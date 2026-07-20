mod api_json;
mod auth;
mod events;
mod host_error;
mod listener;
mod logs;
mod sessions;
mod setup;

use crate::contract::{
    ApiError, ApiErrorCategory, ApiErrorCode, CapabilitiesResponse, EffectiveLimits,
    HostDesktopSessionsResponse, HostStatusResponse, LiveResponse, RequestId, effective_limits,
};
use auth::{AuthorizedRequest, REQUEST_ID_HEADER};
use axum::Router;
use axum::extract::{Extension, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use listener::{ConnectionActivity, ConnectionContext, LimitedTcpListener};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use satelle_core::SatelleError;
use satelle_host::{DaemonRuntimeCapabilities, HostService};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const DEFAULT_MAX_CONNECTIONS: usize = 128;
const HOST_IDENTITY_HEADER: &str = "satelle-host-identity";
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_RATE_KEYS: usize = 4096;
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonServerConfig {
    bind_addr: SocketAddr,
    max_connections: usize,
    shutdown_grace: Duration,
    idle_timeout: Option<Duration>,
    trusted_proxies: Arc<[TrustedProxy]>,
}

impl DaemonServerConfig {
    pub fn loopback(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
            idle_timeout: None,
            trusted_proxies: Arc::from([]),
        }
    }

    pub const fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    pub const fn with_shutdown_grace(mut self, shutdown_grace: Duration) -> Self {
        self.shutdown_grace = shutdown_grace;
        self
    }

    pub const fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = Some(idle_timeout);
        self
    }

    /// Trusts forwarded client addresses only when the transport peer matches
    /// one of these Host-owned exact addresses or CIDR ranges.
    pub fn with_trusted_proxies(
        mut self,
        trusted_proxies: impl IntoIterator<Item = TrustedProxy>,
    ) -> Self {
        self.trusted_proxies = trusted_proxies.into_iter().collect();
        self
    }
}

/// One Host-owned proxy address or CIDR range allowed to supply forwarded
/// client identity. The empty default keeps all proxy headers untrusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix_len: u8,
}

impl TrustedProxy {
    pub const fn exact(address: IpAddr) -> Self {
        Self {
            network: address,
            prefix_len: match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                masked_v4(network, self.prefix_len) == masked_v4(address, self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                masked_v6(network, self.prefix_len) == masked_v6(address, self.prefix_len)
            }
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
        }
    }
}

fn masked_v4(address: std::net::Ipv4Addr, prefix_len: u8) -> u32 {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    u32::from(address) & mask
}

fn masked_v6(address: std::net::Ipv6Addr, prefix_len: u8) -> u128 {
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    u128::from(address) & mask
}

impl From<IpAddr> for TrustedProxy {
    fn from(address: IpAddr) -> Self {
        Self::exact(address)
    }
}

impl FromStr for TrustedProxy {
    type Err = TrustedProxyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_len) = match value.split_once('/') {
            Some((address, prefix_len)) => (address, Some(prefix_len)),
            None => (value, None),
        };
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| TrustedProxyParseError::InvalidAddress)?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = prefix_len
            .map(str::parse::<u8>)
            .transpose()
            .map_err(|_| TrustedProxyParseError::InvalidPrefix)?
            .unwrap_or(maximum);
        if prefix_len > maximum {
            return Err(TrustedProxyParseError::InvalidPrefix);
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TrustedProxyParseError {
    #[error("the trusted proxy address is not a valid IP address")]
    InvalidAddress,
    #[error("the trusted proxy CIDR prefix is invalid for its address family")]
    InvalidPrefix,
}

/// Fully validated Host-side TLS configuration. Construction validates every
/// supplied chain link, rejects certificates outside their validity windows,
/// and proves that the private key matches before a network listener is opened.
#[derive(Clone)]
pub struct DaemonTlsConfig(Arc<rustls::ServerConfig>);

impl fmt::Debug for DaemonTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonTlsConfig")
            .finish_non_exhaustive()
    }
}

impl DaemonTlsConfig {
    pub fn from_pem(
        certificate_chain_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<Self, DaemonTlsConfigError> {
        let certificates = CertificateDer::pem_slice_iter(certificate_chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?;
        if certificates.is_empty() {
            return Err(DaemonTlsConfigError::InvalidCertificateChain);
        }
        let parsed_certificates = certificates
            .iter()
            .map(|certificate_der| {
                let (remaining, certificate) =
                    x509_parser::parse_x509_certificate(certificate_der.as_ref())
                        .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?;
                if !remaining.is_empty() {
                    return Err(DaemonTlsConfigError::InvalidCertificateChain);
                }
                Ok(certificate)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let now = x509_parser::time::ASN1Time::now();
        for certificate in &parsed_certificates {
            let has_unsupported_critical_extension = certificate.extensions().iter().any(|ext| {
                ext.critical
                    && matches!(
                        ext.parsed_extension(),
                        x509_parser::extensions::ParsedExtension::UnsupportedExtension { .. }
                            | x509_parser::extensions::ParsedExtension::ParseError { .. }
                            | x509_parser::extensions::ParsedExtension::Unparsed
                    )
            });
            if has_unsupported_critical_extension {
                return Err(DaemonTlsConfigError::InvalidCertificateChain);
            }
            // This startup validator supports only unconstrained chains. A
            // constrained CA must fail closed until the full RFC 5280 name
            // constraint algorithm is part of this pre-bind validation path.
            if certificate
                .name_constraints()
                .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
                .is_some()
            {
                return Err(DaemonTlsConfigError::InvalidCertificateChain);
            }
            let validity = certificate.validity();
            if validity.not_after <= now {
                return Err(DaemonTlsConfigError::CertificateExpired);
            }
            if validity.not_before > now {
                return Err(DaemonTlsConfigError::CertificateNotYetValid);
            }
        }
        let leaf = &parsed_certificates[0];
        let leaf_is_ca = leaf
            .basic_constraints()
            .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
            .is_some_and(|constraints| constraints.value.ca);
        let leaf_has_server_name = leaf
            .subject_alternative_name()
            .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
            .is_some_and(|names| {
                names.value.general_names.iter().any(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => {
                        let validation_name = name.strip_prefix("*.").unwrap_or(name);
                        matches!(
                            ServerName::try_from(validation_name.to_owned()),
                            Ok(ServerName::DnsName(_))
                        )
                    }
                    x509_parser::extensions::GeneralName::IPAddress(address) => {
                        matches!(address.len(), 4 | 16)
                    }
                    _ => false,
                })
            });
        let leaf_allows_signing = leaf
            .key_usage()
            .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
            .is_none_or(|usage| usage.value.digital_signature());
        let leaf_allows_server_auth = leaf
            .extended_key_usage()
            .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
            .is_none_or(|usage| usage.value.any || usage.value.server_auth);
        if leaf_is_ca || !leaf_has_server_name || !leaf_allows_signing || !leaf_allows_server_auth {
            return Err(DaemonTlsConfigError::InvalidCertificateChain);
        }
        for (link_index, chain_link) in parsed_certificates.windows(2).enumerate() {
            let certificate = &chain_link[0];
            let issuer = &chain_link[1];
            let issuer_constraints = issuer
                .basic_constraints()
                .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
                .ok_or(DaemonTlsConfigError::InvalidCertificateChain)?;
            let issuer_can_sign = issuer
                .key_usage()
                .map_err(|_| DaemonTlsConfigError::InvalidCertificateChain)?
                .is_none_or(|usage| usage.value.key_cert_sign());
            let issuer_index = link_index + 1;
            let subordinate_ca_count = parsed_certificates[1..issuer_index]
                .iter()
                .filter(|subordinate| subordinate.subject() != subordinate.issuer())
                .count();
            let path_length_exceeded = issuer_constraints
                .value
                .path_len_constraint
                .is_some_and(|limit| subordinate_ca_count > limit as usize);
            if certificate.issuer() != issuer.subject()
                || !issuer_constraints.value.ca
                || !issuer_can_sign
                || path_length_exceeded
                || certificate
                    .verify_signature(Some(issuer.public_key()))
                    .is_err()
            {
                return Err(DaemonTlsConfigError::InvalidCertificateChain);
            }
        }
        let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
            .map_err(|_| DaemonTlsConfigError::InvalidPrivateKey)?;
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|error| match error {
                rustls::Error::InconsistentKeys(_) => DaemonTlsConfigError::CertificateKeyMismatch,
                _ => DaemonTlsConfigError::InvalidCertificateChain,
            })?;
        Ok(Self(Arc::new(server)))
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum DaemonTlsConfigError {
    #[error("the TLS certificate chain is empty or malformed")]
    InvalidCertificateChain,
    #[error("the TLS certificate has expired")]
    CertificateExpired,
    #[error("the TLS certificate is not valid yet")]
    CertificateNotYetValid,
    #[error("the TLS private key is empty or malformed")]
    InvalidPrivateKey,
    #[error("the TLS certificate and private key do not match")]
    CertificateKeyMismatch,
}

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum DaemonTlsReloadError {
    #[error("the replacement Host Daemon TLS configuration is invalid: {0}")]
    InvalidConfiguration(#[source] DaemonTlsConfigError),
    #[error("the Host Daemon listener is not configured for TLS")]
    TlsNotConfigured,
    #[error("the Host Daemon listener stopped before TLS reload completed")]
    ListenerStopped,
}

/// Cloneable control handle for replacing the TLS configuration used by
/// future Host Daemon handshakes while the server task owns the listener.
#[derive(Clone)]
pub struct DaemonTlsReloader(watch::Sender<Arc<rustls::ServerConfig>>);

impl DaemonTlsReloader {
    pub fn reload(&self, tls: DaemonTlsConfig) -> Result<(), DaemonTlsReloadError> {
        self.0
            .send(tls.0)
            .map_err(|_| DaemonTlsReloadError::ListenerStopped)
    }

    pub fn reload_from_pem(
        &self,
        certificate_chain_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<(), DaemonTlsReloadError> {
        let tls = DaemonTlsConfig::from_pem(certificate_chain_pem, private_key_pem)
            .map_err(DaemonTlsReloadError::InvalidConfiguration)?;
        self.reload(tls)
    }
}

pub struct DaemonServer {
    local_addr: SocketAddr,
    shutdown: Option<watch::Sender<bool>>,
    task: Option<JoinHandle<Result<(), std::io::Error>>>,
    shutdown_grace: Duration,
    shutdown_service: HostService,
    tls_reloader: Option<DaemonTlsReloader>,
}

#[derive(Clone, Debug)]
/// A cloneable signal for gracefully stopping a running Host listener.
pub struct DaemonShutdownHandle(watch::Sender<bool>);

impl DaemonShutdownHandle {
    /// Requests graceful shutdown without taking ownership of the server.
    pub fn request_shutdown(&self) {
        let _ = self.0.send(true);
    }
}

impl DaemonServer {
    pub async fn bind(
        service: HostService,
        config: DaemonServerConfig,
    ) -> Result<Self, DaemonServerError> {
        Self::bind_inner(service, config, None).await
    }

    /// Binds a Host listener using a fully validated TLS configuration.
    pub async fn bind_tls(
        service: HostService,
        config: DaemonServerConfig,
        tls: DaemonTlsConfig,
    ) -> Result<Self, DaemonServerError> {
        Self::bind_inner(service, config, Some(tls)).await
    }

    async fn bind_inner(
        service: HostService,
        config: DaemonServerConfig,
        tls: Option<DaemonTlsConfig>,
    ) -> Result<Self, DaemonServerError> {
        if service.uses_ssh_bootstrap_authentication() && !config.bind_addr.ip().is_loopback() {
            return Err(DaemonServerError::SshBootstrapNonLoopbackBind);
        }
        if !config.bind_addr.ip().is_loopback() && tls.is_none() {
            return Err(DaemonServerError::NonLoopbackPlaintextBind);
        }
        if config.max_connections == 0 {
            return Err(DaemonServerError::InvalidConnectionLimit);
        }
        if config.shutdown_grace.is_zero() {
            return Err(DaemonServerError::InvalidShutdownGrace);
        }
        if config.idle_timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(DaemonServerError::InvalidIdleTimeout);
        }
        let initialized = service
            .initialize_daemon()
            .map_err(DaemonServerError::HostInitializationFailed)?;
        let capabilities = service
            .daemon_runtime_capabilities()
            .map_err(DaemonServerError::HostInitializationFailed)?;
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .map_err(DaemonServerError::BindFailed)?;
        let local_addr = listener
            .local_addr()
            .map_err(DaemonServerError::BindFailed)?;
        let shutdown_service = service.clone();
        let limits = effective_limits(config.max_connections);
        let (shutdown, mut receiver) = watch::channel(false);
        let state = Arc::new(DaemonState {
            service: Arc::new(service),
            host_identity: initialized.host_identity().to_string(),
            started_at: OffsetDateTime::now_utc(),
            capabilities,
            limits,
            trusted_proxies: Arc::clone(&config.trusted_proxies),
            failed_auth_limit: FailedAuthLimiter::new(limits.failed_auth_attempts_per_minute()),
            authenticated_limit: FixedWindowLimiter::new(
                limits.authenticated_requests_per_minute(),
            ),
            control_limit: FixedWindowLimiter::new(limits.control_requests_per_minute()),
            websocket_inbound_limit: FixedWindowLimiter::new(
                limits.websocket_inbound_messages_per_minute(),
            ),
            websocket_connections: events::ConnectionRegistry::new(
                limits.websocket_connections_per_principal(),
            ),
            setup_issuances: Mutex::new(HashMap::new()),
            setup_mutations: Mutex::new(HashMap::new()),
            shutdown: shutdown.clone(),
        });
        let router = router(Arc::clone(&state));
        let (listener, tls_reloader) = match tls {
            Some(tls) => {
                let (tls_reload, tls_config) = watch::channel(tls.0);
                (
                    LimitedTcpListener::with_tls(listener, config.max_connections, tls_config),
                    Some(DaemonTlsReloader(tls_reload)),
                )
            }
            None => (
                LimitedTcpListener::new(listener, config.max_connections),
                None,
            ),
        };
        let connection_activity = listener.activity();
        let idle_service = Arc::clone(&state.service);
        let idle_timeout = config.idle_timeout;
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<ConnectionContext>(),
            )
            .with_graceful_shutdown(async move {
                tokio::select! {
                    () = wait_for_shutdown(&mut receiver) => {}
                    () = wait_for_idle(idle_service, connection_activity, idle_timeout) => {}
                }
            })
            .await
        });
        Ok(Self {
            local_addr,
            shutdown: Some(shutdown),
            task: Some(task),
            shutdown_grace: config.shutdown_grace,
            shutdown_service,
            tls_reloader,
        })
    }

    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Validates and atomically installs TLS material for future handshakes.
    /// Existing connections and the last valid configuration remain untouched
    /// when validation fails.
    pub fn reload_tls_from_pem(
        &self,
        certificate_chain_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<(), DaemonTlsReloadError> {
        self.tls_reloader
            .as_ref()
            .ok_or(DaemonTlsReloadError::TlsNotConfigured)?
            .reload_from_pem(certificate_chain_pem, private_key_pem)
    }

    pub fn tls_reloader(&self) -> Option<DaemonTlsReloader> {
        self.tls_reloader.clone()
    }

    /// Returns a handle that can request graceful shutdown from another task.
    pub fn shutdown_handle(&self) -> DaemonShutdownHandle {
        DaemonShutdownHandle(
            self.shutdown
                .as_ref()
                .expect("a running daemon retains its shutdown sender")
                .clone(),
        )
    }

    pub async fn wait(mut self) -> Result<(), DaemonServerError> {
        let mut task = self.task.take().expect("server task is present");
        let mut shutdown = self
            .shutdown
            .as_ref()
            .expect("a running daemon retains its shutdown sender")
            .subscribe();
        let task_result = tokio::select! {
            result = &mut task => result,
            () = wait_for_shutdown(&mut shutdown) => {
                match tokio::time::timeout(self.shutdown_grace, &mut task).await {
                    Ok(result) => result,
                    Err(_) => {
                        task.abort();
                        let _ = task.await;
                        return Err(DaemonServerError::ShutdownTimedOut);
                    }
                }
            }
        };
        let result = match task_result {
            Ok(Ok(())) => self.wait_for_workers().await,
            Ok(Err(error)) => Err(DaemonServerError::ServeFailed(error)),
            Err(error) => Err(DaemonServerError::TaskFailed(error)),
        };
        self.shutdown.take();
        result
    }

    pub async fn shutdown(mut self) -> Result<(), DaemonServerError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
        self.finish_bounded().await
    }

    async fn finish_bounded(&mut self) -> Result<(), DaemonServerError> {
        let mut task = self.task.take().expect("server task is present");
        match tokio::time::timeout(self.shutdown_grace, &mut task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => return Err(DaemonServerError::ServeFailed(error)),
            Ok(Err(error)) => return Err(DaemonServerError::TaskFailed(error)),
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err(DaemonServerError::ShutdownTimedOut);
            }
        }
        self.wait_for_workers().await
    }

    async fn wait_for_workers(&self) -> Result<(), DaemonServerError> {
        let deadline = tokio::time::Instant::now() + self.shutdown_grace;
        loop {
            let service = self.shutdown_service.clone();
            match tokio::task::spawn_blocking(move || service.daemon_workers_idle()).await {
                Ok(Ok(true)) => return Ok(()),
                Ok(Ok(false)) => {}
                Ok(Err(_)) | Err(_) => return Err(DaemonServerError::HostShutdownFailed),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DaemonServerError::ShutdownTimedOut);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn wait_for_shutdown(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

async fn wait_for_idle(
    service: Arc<HostService>,
    connections: ConnectionActivity,
    idle_timeout: Option<Duration>,
) {
    let Some(idle_timeout) = idle_timeout else {
        std::future::pending::<()>().await;
        return;
    };
    let poll_interval = idle_timeout.min(Duration::from_secs(1));
    let mut observed_generation = None;
    let mut idle_since = None;

    loop {
        let activity_service = Arc::clone(&service);
        let host_activity =
            tokio::task::spawn_blocking(move || activity_service.daemon_activity_snapshot()).await;
        let (connected_clients, connection_generation) = connections.snapshot();
        let now = tokio::time::Instant::now();

        match host_activity {
            Ok(Ok(host_activity)) => {
                let generation = (host_activity.generation(), connection_generation);
                if observed_generation != Some(generation) {
                    observed_generation = Some(generation);
                    idle_since = None;
                }

                if host_activity.is_idle() && connected_clients == 0 {
                    let started = idle_since.get_or_insert(now);
                    if now.duration_since(*started) >= idle_timeout {
                        return;
                    }
                } else {
                    idle_since = None;
                }
            }
            Ok(Err(_)) | Err(_) => idle_since = None,
        }

        tokio::time::sleep(poll_interval).await;
    }
}

impl fmt::Debug for DaemonServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonServer")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
    }
}

#[derive(Debug)]
pub enum DaemonServerError {
    SshBootstrapNonLoopbackBind,
    NonLoopbackPlaintextBind,
    InvalidConnectionLimit,
    InvalidShutdownGrace,
    InvalidIdleTimeout,
    HostInitializationFailed(SatelleError),
    BindFailed(std::io::Error),
    ServeFailed(std::io::Error),
    TaskFailed(tokio::task::JoinError),
    ShutdownTimedOut,
    HostShutdownFailed,
}

impl DaemonServerError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SshBootstrapNonLoopbackBind => "ssh-bootstrap-non-loopback-bind",
            Self::NonLoopbackPlaintextBind => "non-loopback-plaintext-bind",
            Self::InvalidConnectionLimit => "invalid-connection-limit",
            Self::InvalidShutdownGrace => "invalid-shutdown-grace",
            Self::InvalidIdleTimeout => "invalid-idle-timeout",
            Self::HostInitializationFailed(error) => error.code.as_str(),
            Self::BindFailed(_) => "bind-failed",
            Self::ServeFailed(_) => "serve-failed",
            Self::TaskFailed(_) => "server-task-failed",
            Self::ShutdownTimedOut => "shutdown-timeout",
            Self::HostShutdownFailed => "host-shutdown-failed",
        }
    }

    pub const fn host_error(&self) -> Option<&SatelleError> {
        match self {
            Self::HostInitializationFailed(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Display for DaemonServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SshBootstrapNonLoopbackBind => {
                "SSH bootstrap authentication is restricted to a loopback listener"
            }
            Self::NonLoopbackPlaintextBind => {
                "plaintext Host Daemon transport must bind to a loopback address"
            }
            Self::InvalidConnectionLimit => "the Host Daemon connection limit must be positive",
            Self::InvalidShutdownGrace => "the Host Daemon shutdown grace period must be positive",
            Self::InvalidIdleTimeout => "the Host Daemon idle timeout must be positive",
            Self::HostInitializationFailed(_) => {
                "the Host Daemon could not initialize its authoritative state"
            }
            Self::BindFailed(_) => "the Host Daemon could not bind its listener",
            Self::ServeFailed(_) => "the Host Daemon listener failed",
            Self::TaskFailed(_) => "the Host Daemon server task failed",
            Self::ShutdownTimedOut => {
                "the Host Daemon exceeded its graceful HTTP shutdown deadline"
            }
            Self::HostShutdownFailed => "the Host Daemon could not finalize its execution workers",
        })
    }
}

impl std::error::Error for DaemonServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HostInitializationFailed(error) => Some(error),
            Self::BindFailed(error) | Self::ServeFailed(error) => Some(error),
            Self::TaskFailed(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct DaemonState {
    service: Arc<HostService>,
    host_identity: String,
    started_at: OffsetDateTime,
    capabilities: DaemonRuntimeCapabilities,
    limits: EffectiveLimits,
    trusted_proxies: Arc<[TrustedProxy]>,
    failed_auth_limit: FailedAuthLimiter,
    authenticated_limit: FixedWindowLimiter<String>,
    control_limit: FixedWindowLimiter<String>,
    websocket_inbound_limit: FixedWindowLimiter<String>,
    websocket_connections: Arc<events::ConnectionRegistry>,
    setup_issuances: Mutex<HashMap<(String, String), setup::SetupTokenIssuance>>,
    // SSH bootstrap principals are process-local, so their replay window is
    // exactly this daemon lifetime. Keep successful setup mutations here and
    // bind each operation/key pair to one token target.
    setup_mutations: Mutex<
        HashMap<(String, setup::SetupTokenMutationOperation, String), setup::SetupTokenMutation>,
    >,
    shutdown: watch::Sender<bool>,
}

fn router(state: Arc<DaemonState>) -> Router {
    let capacity_state = Arc::clone(&state);
    let live_route = Router::new()
        .route("/v1/live", get(live).fallback(live_method_not_allowed))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::reject_public_bearer_carriers,
        ));
    let bodyless_read_routes = Router::new()
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/setup/api-token/current", get(setup::confirm_api_token))
        .route("/v1/host/status", get(host_status))
        .route("/v1/host/desktop-sessions", get(host_desktop_sessions))
        .route("/v1/sessions/{session_id}", get(sessions::get_session))
        .route("/v1/events", get(events::get_events))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_empty_read,
        ));
    let logs_route = Router::new()
        .route("/v1/logs", get(logs::get_logs))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_query_read,
        ));
    let read_routes =
        bodyless_read_routes
            .merge(logs_route)
            .route_layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                auth::require_read,
            ));
    let setup_routes = Router::new()
        .route("/v1/setup/api-token", post(setup::issue_api_token))
        .route(
            "/v1/setup/api-token/{token_id}/activate",
            post(setup::activate_api_token),
        )
        .route(
            "/v1/setup/api-token/{token_id}/abort",
            post(setup::abort_api_token),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_empty_setup_mutation,
        ));
    let control_routes = Router::new()
        .route("/v1/sessions", post(sessions::create_session))
        .route(
            "/v1/sessions/{session_id}/turns",
            post(sessions::create_turn),
        )
        .route(
            "/v1/sessions/{session_id}/stop",
            post(sessions::stop_session),
        )
        .merge(setup_routes)
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::require_control,
        ));
    let protected = read_routes
        .merge(control_routes)
        .method_not_allowed_fallback(protected_method_not_allowed)
        .fallback(protected_not_found)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            auth::authorize,
        ));
    Router::new()
        .merge(live_route)
        .merge(protected)
        .with_state(state)
        .layer(middleware::from_fn_with_state(
            capacity_state,
            listener::enforce_capacity,
        ))
}

async fn live(headers: HeaderMap) -> Response {
    json_response(
        StatusCode::OK,
        &LiveResponse::new(),
        request_id_or_new(&headers),
    )
}

async fn live_method_not_allowed(headers: HeaderMap) -> Response {
    api_error_response(
        request_id_or_new(&headers),
        None,
        ApiFailure {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: ApiErrorCode::MethodNotAllowed,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "the requested method is not supported by the liveness route",
            details: None,
        },
    )
}

async fn capabilities(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let response = CapabilitiesResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        state.capabilities.codex_runtime(),
        state.capabilities.native_computer_use(),
        state.capabilities.provider_computer_use(),
        state.limits,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

async fn host_status(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let status = match tokio::task::spawn_blocking(move || service.daemon_runtime_status()).await {
        Ok(Ok(status)) => status,
        Ok(Err(_)) | Err(_) => {
            return api_error_response(
                authorized.request_id().clone(),
                Some(state.host_identity.clone()),
                ApiFailure {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: ApiErrorCode::InternalError,
                    category: ApiErrorCategory::Internal,
                    retryable: false,
                    message: "the Host Daemon could not read authoritative status",
                    details: None,
                },
            );
        }
    };
    let response = HostStatusResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        state.started_at,
        status.session_count(),
        status.active_turn_count(),
        status.recovery_pending_turn_count(),
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

async fn host_desktop_sessions(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let sessions =
        match tokio::task::spawn_blocking(move || service.daemon_desktop_sessions()).await {
            Ok(Ok(sessions)) => sessions,
            Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
            Err(_) => return host_error::task_failure(&state, &authorized),
        };
    let response = HostDesktopSessionsResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        sessions,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

async fn protected_not_found(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::NOT_FOUND,
            code: ApiErrorCode::RouteNotFound,
            category: ApiErrorCategory::NotFound,
            retryable: false,
            message: "the requested Host Daemon route does not exist",
            details: None,
        },
    )
}

async fn protected_method_not_allowed(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: ApiErrorCode::MethodNotAllowed,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "the requested method is not supported by this Host Daemon route",
            details: None,
        },
    )
}

pub(super) struct ApiFailure {
    pub(super) status: StatusCode,
    pub(super) code: ApiErrorCode,
    pub(super) category: ApiErrorCategory,
    pub(super) retryable: bool,
    pub(super) message: &'static str,
    pub(super) details: Option<Value>,
}

pub(super) fn api_error_response(
    request_id: RequestId,
    host_identity: Option<String>,
    failure: ApiFailure,
) -> Response {
    let fallback_request_id = request_id.clone();
    let fallback_host_identity = host_identity.clone();
    json_response_with_context(
        failure.status,
        &ApiError::new(
            request_id,
            host_identity,
            failure.code,
            failure.category,
            failure.retryable,
            failure.message,
            failure.details,
        ),
        fallback_request_id,
        fallback_host_identity,
    )
}

fn json_response(status: StatusCode, value: &impl Serialize, request_id: RequestId) -> Response {
    json_response_with_context(status, value, request_id, None)
}

pub(super) fn authenticated_json_response(
    status: StatusCode,
    value: &impl Serialize,
    request_id: &RequestId,
    host_identity: &str,
) -> Response {
    json_response_with_context(
        status,
        value,
        request_id.clone(),
        Some(host_identity.to_string()),
    )
}

fn json_response_with_context(
    status: StatusCode,
    value: &impl Serialize,
    request_id: RequestId,
    host_identity: Option<String>,
) -> Response {
    let response_host_identity = host_identity.clone();
    let (status, body) = match serde_json::to_vec(value) {
        Ok(body) => (status, body),
        Err(_) => {
            let fallback = ApiError::new(
                request_id.clone(),
                host_identity,
                ApiErrorCode::InternalError,
                ApiErrorCategory::Internal,
                false,
                "the Host Daemon could not encode its response",
                None,
            );
            let body = serde_json::to_vec(&fallback)
                .expect("the closed fallback ApiError contract must serialize");
            (StatusCode::INTERNAL_SERVER_ERROR, body)
        }
    };
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    security_headers(with_response_context(
        response,
        &request_id,
        response_host_identity.as_deref(),
    ))
}

pub(super) fn with_response_context(
    mut response: Response,
    request_id: &RequestId,
    host_identity: Option<&str>,
) -> Response {
    let response_request_id = HeaderValue::try_from(request_id.as_str())
        .expect("a canonical UUIDv7 is always a valid HTTP header value");
    tracing::debug!(
        request_id = %request_id,
        status = response.status().as_u16(),
        "Host Daemon HTTP response completed"
    );
    response
        .headers_mut()
        .insert(REQUEST_ID_HEADER, response_request_id);
    if let Some(host_identity) = host_identity {
        let response_host_identity = HeaderValue::try_from(host_identity)
            .expect("a stored Host Identity is always a valid HTTP header value");
        response
            .headers_mut()
            .insert(HOST_IDENTITY_HEADER, response_host_identity);
    }
    response
}

pub(super) fn security_headers(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(super) fn header_request_id(headers: &HeaderMap) -> Option<RequestId> {
    let mut values = headers.get_all(REQUEST_ID_HEADER).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    RequestId::parse(value).ok()
}

pub(super) fn request_id_or_new(headers: &HeaderMap) -> RequestId {
    header_request_id(headers).unwrap_or_default()
}

struct RateWindow {
    started_at: Instant,
    count: usize,
}

impl RateWindow {
    fn is_active(&self, now: Instant) -> bool {
        now.duration_since(self.started_at) < RATE_WINDOW
    }

    fn retry_after(&self, now: Instant) -> Duration {
        RATE_WINDOW.saturating_sub(now.saturating_duration_since(self.started_at))
    }
}

struct FixedWindowLimiter<K> {
    limit: usize,
    entries: Mutex<HashMap<K, RateWindow>>,
}

impl<K> FixedWindowLimiter<K>
where
    K: Eq + Hash,
{
    fn new(limit: usize) -> Self {
        Self {
            limit,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `None` when the request is admitted and the remaining window
    /// when it is limited. Keeping the duration in the limiter prevents HTTP
    /// and WebSocket callers from reconstructing timing from policy constants.
    fn admit(&self, key: K) -> Option<Duration> {
        self.admit_at(key, Instant::now())
    }

    fn admit_at(&self, key: K, now: Instant) -> Option<Duration> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, window| window.is_active(now));
        if !entries.contains_key(&key) && entries.len() >= MAX_RATE_KEYS {
            return entries.values().map(|window| window.retry_after(now)).min();
        }
        let window = entries.entry(key).or_insert(RateWindow {
            started_at: now,
            count: 0,
        });
        if window.count >= self.limit {
            Some(window.retry_after(now))
        } else {
            window.count += 1;
            None
        }
    }
}

struct FailedAuthLimiter {
    limit: usize,
    entries: Mutex<HashMap<IpAddr, RateWindow>>,
}

impl FailedAuthLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn retry_after(&self, source: IpAddr) -> Option<Duration> {
        self.retry_after_at(source, Instant::now())
    }

    fn retry_after_at(&self, source: IpAddr, now: Instant) -> Option<Duration> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, window| window.is_active(now));
        entries
            .get(&source)
            .filter(|window| window.count >= self.limit)
            .map(|window| window.retry_after(now))
    }

    fn record_failure(&self, source: IpAddr) {
        self.record_failure_at(source, Instant::now());
    }

    fn record_failure_at(&self, source: IpAddr, now: Instant) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, window| window.is_active(now));
        if !entries.contains_key(&source) && entries.len() >= MAX_RATE_KEYS {
            return;
        }
        entries
            .entry(source)
            .and_modify(|window| window.count = window.count.saturating_add(1))
            .or_insert(RateWindow {
                started_at: now,
                count: 1,
            });
    }
}

fn retry_after_ms(duration: Duration) -> u64 {
    let rounded_millis =
        duration.as_millis() + u128::from(!duration.subsec_nanos().is_multiple_of(1_000_000));
    u64::try_from(rounded_millis).expect("the one-minute rate window fits in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct SerializationFailure;

    impl Serialize for SerializationFailure {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("forced serialization failure"))
        }
    }

    #[tokio::test]
    async fn serialization_failure_still_returns_the_typed_error_contract() {
        let request_id = RequestId::new();
        let response = json_response_with_context(
            StatusCode::OK,
            &SerializationFailure,
            request_id.clone(),
            Some("host-test".to_string()),
        );
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 16_384)
            .await
            .expect("read typed fallback body");
        let error: ApiError = serde_json::from_slice(&body).expect("decode typed fallback");
        assert_eq!(error.code(), ApiErrorCode::InternalError);
        assert_eq!(error.request_id(), &request_id);
        assert_eq!(error.host_identity(), Some("host-test"));
    }

    #[test]
    fn fixed_window_reports_remaining_time_and_reopens_at_expiry() {
        let limiter = FixedWindowLimiter::new(1);
        let started_at = Instant::now();

        assert_eq!(limiter.admit_at("principal", started_at), None);
        assert_eq!(
            limiter.admit_at("principal", started_at + Duration::from_millis(125),),
            Some(RATE_WINDOW - Duration::from_millis(125))
        );
        assert_eq!(
            limiter.admit_at("principal", started_at + RATE_WINDOW),
            None
        );
    }

    #[test]
    fn failed_auth_window_reports_remaining_time_and_expires() {
        let limiter = FailedAuthLimiter::new(10);
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let started_at = Instant::now();
        for _ in 0..10 {
            limiter.record_failure_at(source, started_at);
        }

        assert_eq!(
            limiter.retry_after_at(source, started_at + Duration::from_millis(250)),
            Some(RATE_WINDOW - Duration::from_millis(250))
        );
        assert_eq!(
            limiter.retry_after_at(source, started_at + RATE_WINDOW),
            None
        );
    }

    #[test]
    fn full_key_table_reports_the_earliest_window_expiry() {
        let limiter = FixedWindowLimiter::new(1);
        let started_at = Instant::now();
        for key in 0..MAX_RATE_KEYS {
            assert_eq!(limiter.admit_at(key, started_at), None);
        }

        assert_eq!(
            limiter.admit_at(MAX_RATE_KEYS, started_at + Duration::from_secs(1)),
            Some(RATE_WINDOW - Duration::from_secs(1))
        );
        assert_eq!(
            limiter.admit_at(MAX_RATE_KEYS, started_at + RATE_WINDOW),
            None
        );
    }

    #[test]
    fn retry_metadata_rounds_up_to_the_next_millisecond() {
        assert_eq!(retry_after_ms(Duration::from_nanos(1)), 1);
        assert_eq!(retry_after_ms(Duration::from_micros(1_001)), 2);
        assert_eq!(retry_after_ms(Duration::from_millis(60_000)), 60_000);
    }
}
