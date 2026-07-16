use crate::{CliFailure, SelectedHost, failure};
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    ApiTokenSource, DaemonPathOverrides, DirectHostBinding, DoctorOptions, DoctorReport, ErrorCode,
    HostSessionsReport, HostSessionsSchemaVersion, LOCAL_DEMO_HOST, SatelleError, SatelleEvent,
    SessionId, SetupReport, SshHostBinding, StopResult, TransportKind, TurnId,
    read_owner_only_secret_file, read_trusted_ca_bundle_file,
};
use satelle_host::{
    ApiBearerToken, DaemonLogPage, HostService, HostStatus, LogCursor, LogPageQuery,
    admission_request_timeout,
};
use satelle_transport::{
    ApiError, ApiErrorCode, DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError,
    TurnRequest,
};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const SSH_DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[path = "direct-attached.rs"]
mod direct_attached;
#[path = "ssh-bootstrap.rs"]
mod ssh_bootstrap;
#[path = "ssh-tunnel.rs"]
mod ssh_tunnel;

use ssh_bootstrap::SshBootstrapProcess;
use ssh_tunnel::SshTunnel;

pub(crate) fn probe_tailscale_serve(alias: &str, destination: &str) -> Result<(), SatelleError> {
    ssh_bootstrap::probe_tailscale_serve(destination)
        .map_err(|error| map_tailscale_serve_error(alias, error))
}

pub(crate) fn apply_tailscale_serve(alias: &str, destination: &str) -> Result<(), SatelleError> {
    ssh_bootstrap::apply_tailscale_serve(destination)
        .map_err(|error| map_tailscale_serve_error(alias, error))
}

fn map_tailscale_serve_error(alias: &str, error: ssh_bootstrap::SshBootstrapError) -> SatelleError {
    if matches!(
        error,
        ssh_bootstrap::SshBootstrapError::HostKeyVerificationRequired
    ) {
        SatelleError::ssh_host_key_verification_required(alias)
    } else {
        SatelleError {
            code: ErrorCode::RemoteExecution,
            message: format!("remote Tailscale Serve setup failed for host '{alias}'"),
            recovery_command: Some(format!(
                "verify system OpenSSH access, then run satelle doctor --host {alias} --scope transport --json"
            )),
            source_detail: None,
            details: std::collections::BTreeMap::from([(
                "host".to_string(),
                serde_json::Value::String(alias.to_string()),
            )]),
        }
    }
}

#[cfg(feature = "test-support")]
const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

pub(crate) struct AttachedTurnOutcome {
    pub(crate) session: PublicSession,
    pub(crate) turn_id: TurnId,
    pub(crate) provider_smoke: Option<serde_json::Value>,
}

/// The command surface is intentionally exhaustive. A new transport operation
/// must be implemented or explicitly rejected by every backend.
pub(crate) trait TransportClient {
    fn setup(
        &self,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError>;
    fn doctor(
        &self,
        scope: Option<&str>,
        options: DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError>;
    fn host_status(&self) -> Result<HostStatus, SatelleError>;
    fn host_sessions(&self, no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError>;
    fn run(
        &self,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure>;
    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError>;
    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure>;
    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError>;
    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError>;
    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError>;
    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError>;
}

struct LocalTransport {
    alias: String,
    service: HostService,
}

impl LocalTransport {
    fn new(alias: String, service: HostService) -> Self {
        Self { alias, service }
    }
}

impl TransportClient for LocalTransport {
    fn setup(
        &self,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        self.service.setup(
            &self.alias,
            dry_run,
            setup_mode,
            setup_components,
            daemon_path_overrides,
        )
    }

    fn doctor(
        &self,
        scope: Option<&str>,
        options: DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        self.service
            .doctor_with_provider_intent(&self.alias, scope, options, provider_intent)
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        self.service.host_status()
    }

    fn host_sessions(&self, no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        self.service.host_sessions(&self.alias, no_bootstrap)
    }

    fn run(
        &self,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let intent = local_turn_intent(request).map_err(TurnAdmissionFailure::not_admitted)?;
        let outcome = self.service.run(&self.alias, &intent)?;
        let turn_id = outcome
            .session
            .turns()
            .last()
            .expect("an admitted local run always contains its target Turn")
            .turn_id()
            .clone();
        let mut provider_smoke = None;
        for event in outcome.events {
            if event.event_type() == satelle_core::EventType::ProviderSmoke {
                provider_smoke = Some(event.data().clone());
            }
            on_event(event).map_err(|error| {
                TurnAdmissionFailure::admitted(error, outcome.session.clone(), turn_id.clone())
            })?;
        }
        Ok(AttachedTurnOutcome {
            session: outcome.session,
            turn_id,
            provider_smoke,
        })
    }

    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError> {
        self.service
            .run_detached(&self.alias, &local_turn_intent(request)?)
    }

    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let intent = local_turn_intent(request).map_err(TurnAdmissionFailure::not_admitted)?;
        let outcome = self.service.steer(session_id, &intent)?;
        let turn_id = outcome
            .session
            .turns()
            .last()
            .expect("an admitted local steer always contains its target Turn")
            .turn_id()
            .clone();
        let mut provider_smoke = None;
        for event in outcome.events {
            if event.event_type() == satelle_core::EventType::ProviderSmoke {
                provider_smoke = Some(event.data().clone());
            }
            on_event(event).map_err(|error| {
                TurnAdmissionFailure::admitted(error, outcome.session.clone(), turn_id.clone())
            })?;
        }
        Ok(AttachedTurnOutcome {
            session: outcome.session,
            turn_id,
            provider_smoke,
        })
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError> {
        self.service
            .steer_detached(session_id, &local_turn_intent(request)?)
    }

    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.service.status(session_id)
    }

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.service.stop(session_id)
    }

    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        if self.alias != LOCAL_DEMO_HOST {
            return Err(SatelleError::host_not_found(self.alias.clone()));
        }
        self.service.daemon_log_page(query)
    }
}

fn local_turn_intent(request: &TurnRequest) -> Result<satelle_host::TurnIntent, SatelleError> {
    satelle_host::TurnIntent::new(request.prompt(), request.execution_mode())
        .and_then(|intent| {
            intent.with_provider_intent(
                request.model().map(str::to_string),
                request.provider().map(str::to_string),
                request.experimental_provider_computer_use(),
                request.refresh_provider_smoke_test(),
            )
        })
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))
}

struct DirectTransport {
    alias: String,
    mode: &'static str,
    client: Arc<DaemonClient>,
    event_client: DaemonEventClient,
    event_runtime: tokio::runtime::Runtime,
    // Fields drop in declaration order, so the tunnel outlives both clients.
    _tunnel: Option<SshTunnel>,
    // A bootstrapped daemon remains attached to this owned SSH child until all
    // tunneled clients have been dropped.
    _bootstrap: Option<SshBootstrapProcess>,
}

impl DirectTransport {
    fn unsupported(&self, operation: &str) -> SatelleError {
        SatelleError::not_implemented(format!(
            "{} transport for host '{}' does not yet support {operation}",
            self.mode, self.alias
        ))
    }

    fn idempotency_key() -> String {
        Uuid::now_v7().hyphenated().to_string()
    }

    pub(super) fn run_event_error(&self, error: DaemonEventError) -> SatelleError {
        if self.mode == "direct" {
            direct_run_event_error(&self.alias, error)
        } else {
            direct_event_error(&self.alias, error)
        }
    }

    pub(super) fn run_admission_error(
        &self,
    ) -> fn(&str, DaemonClientError) -> TurnAdmissionFailure {
        if self.mode == "direct" {
            direct_run_admission_error
        } else {
            direct_admission_error
        }
    }

    fn run_transport_error(&self, error: DaemonClientError) -> SatelleError {
        if self.mode == "direct" {
            direct_run_transport_error(&self.alias, error)
        } else {
            direct_transport_error(&self.alias, error)
        }
    }
}
impl TransportClient for DirectTransport {
    fn setup(
        &self,
        _dry_run: bool,
        _setup_mode: String,
        _setup_components: Vec<String>,
        _daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        Err(self.unsupported("setup"))
    }

    fn doctor(
        &self,
        _scope: Option<&str>,
        _options: DoctorOptions,
        _provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        Err(self.unsupported("doctor"))
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        let response = self
            .client
            .host_status()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(HostStatus {
            running: true,
            mode: self.mode.to_string(),
            sessions: response.session_count(),
        })
    }

    fn host_sessions(&self, _no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        // The desktop-session envelope intentionally excludes the daemon version.
        // Read the canonical capabilities envelope instead of reporting the CLI version.
        let capabilities = self
            .client
            .capabilities()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        let desktop_sessions = self
            .client
            .desktop_sessions()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(HostSessionsReport {
            schema_version: HostSessionsSchemaVersion::V1,
            host: self.alias.clone(),
            connection_mode: self.mode.to_string(),
            bootstrapped: false,
            bootstrap_actions: Vec::new(),
            host_daemon_version: capabilities.daemon_version().to_string(),
            sessions: desktop_sessions.sessions().to_vec(),
        })
    }

    fn run(
        &self,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        self.event_runtime
            .block_on(self.run_attached(request, on_event))
    }

    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError> {
        self.client
            .create_session(request, &Self::idempotency_key())
            .map(|response| response.session().clone())
            .map_err(|error| self.run_transport_error(error))
    }

    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        self.event_runtime
            .block_on(self.steer_attached(session_id, request, on_event))
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError> {
        self.client
            .create_turn(session_id, request, &Self::idempotency_key())
            .map(|response| response.session().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.client
            .read_session(session_id)
            .map(|response| response.session().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.client
            .stop_session(session_id, &Self::idempotency_key())
            .map(|response| response.result().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        self.client
            .logs(query)
            .map(|response| response.page().clone())
            .map_err(|error| direct_logs_error(&self.alias, error))
    }
}

fn direct_transport(host: &SelectedHost) -> Result<DirectTransport, SatelleError> {
    let binding = DirectHostBinding::from_host_config(&host.config)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ApiTokenSource::File { path } = binding.api_token();
    let raw_token = read_owner_only_secret_file(path)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let http_token = ApiBearerToken::parse(raw_token.as_str())
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let event_token = ApiBearerToken::parse(raw_token.as_str())
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ca_bundle = binding
        .ca_bundle()
        .map(read_trusted_ca_bundle_file)
        .transpose()
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ca_bundle = ca_bundle.as_deref().map(str::as_bytes);
    let client = Arc::new(
        DaemonClient::https(&binding, http_token, ca_bundle)
            .map_err(|error| direct_transport_error(&host.alias, error))?
            .with_admission_timeout(admission_request_timeout(&host.config)),
    );
    let event_client = DaemonEventClient::wss(&binding, event_token, ca_bundle)
        .map_err(|error| direct_event_error(&host.alias, error))?;
    let event_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    Ok(DirectTransport {
        alias: host.alias.clone(),
        mode: "direct",
        client,
        event_client,
        event_runtime,
        _tunnel: None,
        _bootstrap: None,
    })
}

fn ssh_transport(
    host: &SelectedHost,
    bootstrap_if_unreachable: bool,
) -> Result<DirectTransport, SatelleError> {
    let admission_timeout = admission_request_timeout(&host.config);
    let binding = if bootstrap_if_unreachable {
        SshHostBinding::from_host_config_for_bootstrap(&host.config)
    } else {
        SshHostBinding::from_host_config(&host.config)
    }
    .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let durable_tokens = match binding.api_token() {
        Some(ApiTokenSource::File { path }) => {
            let raw_token = read_owner_only_secret_file(path)
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            let http_token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            let event_token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            Some((http_token, event_token))
        }
        None => None,
    };
    let tunnel = SshTunnel::open(binding.destination()).map_err(|error| match error {
        ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
            SatelleError::ssh_host_key_verification_required(&host.alias)
        }
        _ => SatelleError::host_unreachable(&host.alias),
    })?;
    let expected_host_identity = binding.expected_host_identity().to_string();
    let (client, event_client, bootstrap) = match durable_tokens {
        Some((http_token, event_token)) => {
            let durable_client = Arc::new(
                DaemonClient::loopback_with_timeout(
                    tunnel.local_addr(),
                    http_token,
                    &expected_host_identity,
                    SSH_DAEMON_REQUEST_TIMEOUT,
                )
                .map_err(|error| direct_transport_error(&host.alias, error))?
                .with_admission_timeout(admission_timeout),
            );
            match durable_client.capabilities() {
                Ok(_) => {
                    let event_client = DaemonEventClient::loopback(
                        tunnel.local_addr(),
                        event_token,
                        expected_host_identity.clone(),
                    )
                    .map_err(|error| direct_event_error(&host.alias, error))?;
                    (durable_client, event_client, None)
                }
                Err(DaemonClientError::Transport(error))
                    if error.is_connect() && bootstrap_if_unreachable =>
                {
                    let (client, event_client, bootstrap) = bootstrap_ssh_clients(
                        &host.alias,
                        binding.destination(),
                        tunnel.local_addr(),
                        &expected_host_identity,
                        admission_timeout,
                        &host.config,
                    )?;
                    (client, event_client, Some(bootstrap))
                }
                Err(error) => return Err(direct_transport_error(&host.alias, error)),
            }
        }
        None => {
            let (client, event_client, bootstrap) = bootstrap_ssh_clients(
                &host.alias,
                binding.destination(),
                tunnel.local_addr(),
                &expected_host_identity,
                admission_timeout,
                &host.config,
            )?;
            (client, event_client, Some(bootstrap))
        }
    };
    let event_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    Ok(DirectTransport {
        alias: host.alias.clone(),
        mode: "ssh",
        client,
        event_client,
        event_runtime,
        _tunnel: Some(tunnel),
        _bootstrap: bootstrap,
    })
}

fn bootstrap_ssh_clients(
    alias: &str,
    destination: &str,
    tunnel_addr: std::net::SocketAddr,
    expected_host_identity: &str,
    admission_timeout: Duration,
    host_config: &satelle_core::HostConfig,
) -> Result<(Arc<DaemonClient>, DaemonEventClient, SshBootstrapProcess), SatelleError> {
    let bootstrap_token =
        ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(alias))?;
    let raw_bootstrap_token = bootstrap_token.expose();
    let bootstrap = SshBootstrapProcess::launch(destination, &bootstrap_token, host_config)
        .map_err(|error| match error {
            ssh_bootstrap::SshBootstrapError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(alias)
            }
            _ => SatelleError::host_unreachable(alias),
        })?;
    let http_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let event_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let client = Arc::new(
        DaemonClient::loopback_with_timeout(
            tunnel_addr,
            http_token,
            expected_host_identity,
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(alias, error))?
        .with_admission_timeout(admission_timeout),
    );
    client
        .capabilities()
        .map_err(|error| direct_transport_error(alias, error))?;
    let event_client =
        DaemonEventClient::loopback(tunnel_addr, event_token, expected_host_identity)
            .map_err(|error| direct_event_error(alias, error))?;
    Ok((client, event_client, bootstrap))
}

fn direct_event_error(host: &str, error: DaemonEventError) -> SatelleError {
    match error {
        DaemonEventError::Handshake { error, .. } => api_code_error(host, error.code()),
        DaemonEventError::HostIdentityMismatch => SatelleError::host_identity_mismatch(host),
        DaemonEventError::CertificateUntrusted(_) => SatelleError::certificate_untrusted(host),
        DaemonEventError::CertificateHostnameMismatch(_) => {
            SatelleError::certificate_hostname_mismatch(host)
        }
        DaemonEventError::CertificateExpired(_) => SatelleError::certificate_expired(host),
        DaemonEventError::TlsVersionUnsupported(_) => SatelleError::tls_version_unsupported(host),
        DaemonEventError::TlsHandshake(_) => SatelleError::tls_handshake_failed(host),
        DaemonEventError::InvalidHeader
        | DaemonEventError::InvalidCaBundle
        | DaemonEventError::EmptyCaBundle
        | DaemonEventError::TlsConfiguration(_) => {
            SatelleError::config_error(error.to_string(), None)
        }
        DaemonEventError::Closed {
            control: Some(control),
            ..
        } => api_code_error(host, control.code()),
        DaemonEventError::HandshakeTimeout
        | DaemonEventError::StreamIdleTimeout
        | DaemonEventError::AdmissionEventBufferOverflow
        | DaemonEventError::Connect(_)
        | DaemonEventError::Transport(_)
        | DaemonEventError::Closed { control: None, .. }
        | DaemonEventError::Disconnected => SatelleError::host_unreachable(host),
        DaemonEventError::NonLoopbackPlaintextEndpoint
        | DaemonEventError::InvalidSubscriptions
        | DaemonEventError::InvalidHandshakeResponse
        | DaemonEventError::Encode(_)
        | DaemonEventError::InvalidControl(_)
        | DaemonEventError::InvalidEvent(_)
        | DaemonEventError::ControlWithoutClose(_)
        | DaemonEventError::CloseContractMismatch { .. }
        | DaemonEventError::RequestIdMismatch
        | DaemonEventError::SubscriptionMismatch
        | DaemonEventError::SequenceDidNotAdvance
        | DaemonEventError::UnexpectedFrame => {
            SatelleError::remote_api_error(host, "invalid-daemon-response")
        }
    }
}

// A direct run requires its daemon to be reachable before admission begins.
// Keep this context-specific so steer and post-admission stream loss retain
// the broader host-unreachable contract.
fn direct_run_event_error(host: &str, error: DaemonEventError) -> SatelleError {
    // A typed server control remains authoritative even when its close reason
    // also describes a recoverable connection loss, such as a slow consumer.
    if matches!(
        &error,
        DaemonEventError::Closed {
            control: Some(_),
            ..
        }
    ) {
        return direct_event_error(host, error);
    }
    if error.is_recoverable_disconnect() {
        SatelleError::direct_daemon_unreachable(host)
    } else {
        direct_event_error(host, error)
    }
}

fn direct_transport_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Api { error, .. } => map_api_error(host, &error),
        DaemonClientError::ResponseHostIdentityMismatch => {
            SatelleError::host_identity_mismatch(host)
        }
        DaemonClientError::CertificateUntrusted(_) => SatelleError::certificate_untrusted(host),
        DaemonClientError::CertificateHostnameMismatch(_) => {
            SatelleError::certificate_hostname_mismatch(host)
        }
        DaemonClientError::CertificateExpired(_) => SatelleError::certificate_expired(host),
        DaemonClientError::TlsVersionUnsupported(_) => SatelleError::tls_version_unsupported(host),
        DaemonClientError::TlsHandshake(_) => SatelleError::tls_handshake_failed(host),
        DaemonClientError::Transport(_) => SatelleError::host_unreachable(host),
        DaemonClientError::InvalidHostIdentityHeader
        | DaemonClientError::InvalidCaBundle(_)
        | DaemonClientError::EmptyCaBundle => SatelleError::config_error(error.to_string(), None),
        DaemonClientError::NonLoopbackPlaintextEndpoint
        | DaemonClientError::InvalidTokenHeader
        | DaemonClientError::InvalidIdempotencyKeyHeader
        | DaemonClientError::InvalidResponse(_)
        | DaemonClientError::UnexpectedSuccessStatus { .. }
        | DaemonClientError::ResponseRequestIdMismatch => {
            SatelleError::remote_api_error(host, "invalid-daemon-response")
        }
    }
}

fn direct_run_transport_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Transport(error) if error.is_connect() => {
            SatelleError::direct_daemon_unreachable(host)
        }
        error => direct_transport_error(host, error),
    }
}

fn direct_logs_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Api { error, .. } if error.code() == ApiErrorCode::InvalidRequest => {
            SatelleError::invalid_usage("the Host rejected the logs query")
        }
        error => direct_transport_error(host, error),
    }
}

// Cursor expiry is the one API failure whose details are required to resume
// safely. Validate that recovery boundary at the transport boundary instead
// of collapsing it into the generic remote API error used for other codes.
fn map_api_error(host: &str, error: &ApiError) -> SatelleError {
    if error.code() != ApiErrorCode::LogsCursorExpired {
        return api_code_error(host, error.code());
    }

    let Some(details) = error.details().and_then(serde_json::Value::as_object) else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    let earliest_available_cursor = match details.get("earliest_available_cursor") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(cursor)) => match LogCursor::parse(cursor) {
            Ok(cursor) => Some(cursor),
            Err(_) => return SatelleError::remote_api_error(host, "invalid-daemon-response"),
        },
        _ => return SatelleError::remote_api_error(host, "invalid-daemon-response"),
    };
    let Some(resume_cursor) = details
        .get("resume_cursor")
        .and_then(serde_json::Value::as_str)
        .and_then(|cursor| LogCursor::parse(cursor).ok())
    else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    if earliest_available_cursor.is_some_and(|earliest| earliest <= resume_cursor) {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    }

    SatelleError::logs_cursor_expired(
        earliest_available_cursor.map(|cursor| cursor.to_string()),
        resume_cursor.to_string(),
    )
}

fn direct_admission_error(host: &str, error: DaemonClientError) -> TurnAdmissionFailure {
    // Only failures enforced before the daemon calls Host admission are
    // definitive. Runtime, storage, and internal API errors can occur after
    // the Turn commits and carry no durable handles in this protocol version.
    let definitively_not_admitted = matches!(
        &error,
        DaemonClientError::NonLoopbackPlaintextEndpoint
            | DaemonClientError::InvalidTokenHeader
            | DaemonClientError::InvalidHostIdentityHeader
            | DaemonClientError::InvalidIdempotencyKeyHeader
            | DaemonClientError::InvalidCaBundle(_)
            | DaemonClientError::EmptyCaBundle
            | DaemonClientError::CertificateUntrusted(_)
            | DaemonClientError::CertificateHostnameMismatch(_)
            | DaemonClientError::CertificateExpired(_)
            | DaemonClientError::TlsVersionUnsupported(_)
            | DaemonClientError::TlsHandshake(_)
    ) || matches!(
        &error,
        DaemonClientError::Api { error, .. }
            if api_error_is_definitively_not_admitted(error.code())
    );
    let error = direct_transport_error(host, error);
    if definitively_not_admitted {
        TurnAdmissionFailure::not_admitted(error)
    } else {
        TurnAdmissionFailure::admission_unknown(error)
    }
}

fn direct_run_admission_error(host: &str, error: DaemonClientError) -> TurnAdmissionFailure {
    // reqwest connect failures happen before the create-session request can
    // reach the daemon, so this run is definitively not admitted. Every later
    // transport phase retains the generic admission-unknown classification.
    if matches!(&error, DaemonClientError::Transport(error) if error.is_connect()) {
        return TurnAdmissionFailure::not_admitted(SatelleError::direct_daemon_unreachable(host));
    }
    direct_admission_error(host, error)
}

fn api_error_is_definitively_not_admitted(code: ApiErrorCode) -> bool {
    matches!(
        code,
        ApiErrorCode::AuthenticationFailed
            | ApiErrorCode::AuthorizationInsufficientScope
            | ApiErrorCode::HostIdentityMismatch
            | ApiErrorCode::InvalidRequest
            | ApiErrorCode::UnsupportedSchema
            | ApiErrorCode::UnsupportedContentType
            | ApiErrorCode::PayloadTooLarge
            | ApiErrorCode::IdempotencyKeyConflict
            | ApiErrorCode::SessionNotFound
            | ApiErrorCode::HostBusy
            | ApiErrorCode::IncompatibleProtocol
            | ApiErrorCode::IncompatibleControlPlane
            | ApiErrorCode::ComputerUseNotReady
            | ApiErrorCode::NativeReadinessTimeout
            | ApiErrorCode::ProviderSmokeTestTimeout
            | ApiErrorCode::UnsupportedProviderComputerUse
            | ApiErrorCode::CapacityExceeded
            | ApiErrorCode::RateLimited
            | ApiErrorCode::RouteNotFound
            | ApiErrorCode::MethodNotAllowed
    )
}

fn api_code_error(host: &str, code: ApiErrorCode) -> SatelleError {
    match code {
        ApiErrorCode::AuthenticationFailed => SatelleError::authentication_failed(host),
        ApiErrorCode::AuthorizationInsufficientScope => {
            SatelleError::authorization_insufficient_scope(host)
        }
        ApiErrorCode::HostIdentityMismatch => SatelleError::host_identity_mismatch(host),
        ApiErrorCode::HostUnreachable => SatelleError::host_unreachable(host),
        ApiErrorCode::NativeReadinessTimeout => SatelleError::native_readiness_timeout(),
        ApiErrorCode::ProviderSmokeTestTimeout => SatelleError::provider_smoke_test_timeout(),
        ApiErrorCode::UnsupportedProviderComputerUse => {
            SatelleError::unsupported_provider_computer_use()
        }
        code => SatelleError::remote_api_error(host, code.as_str()),
    }
}

fn local_host_service(host_config: &satelle_core::HostConfig) -> Result<HostService, CliFailure> {
    #[cfg(feature = "test-support")]
    match std::env::var(TEST_SUPPORT_ADAPTER_ENV) {
        Ok(value) if value == "fake" => {
            return HostService::local_demo_for_tests().map_err(failure);
        }
        Ok(value) if value == "pending" => {
            return HostService::pending_local_demo_for_tests().map_err(failure);
        }
        Ok(value) if value == "failing" => {
            return HostService::failing_local_demo_for_tests().map_err(failure);
        }
        Ok(_) => {
            return Err(failure(SatelleError::invalid_usage(
                "SATELLE_TEST_SUPPORT_ADAPTER must be exactly 'fake', 'pending', 'failing', or unset",
            )));
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(failure(SatelleError::invalid_usage(
                "SATELLE_TEST_SUPPORT_ADAPTER must contain valid UTF-8",
            )));
        }
        Err(std::env::VarError::NotPresent) => {}
    }

    Ok(HostService::production_for_host(host_config))
}

pub(crate) fn transport_for(host: &SelectedHost) -> Result<Box<dyn TransportClient>, CliFailure> {
    transport_for_with_ssh_bootstrap(host, false)
}

pub(crate) fn transport_for_with_ssh_bootstrap(
    host: &SelectedHost,
    bootstrap_if_unreachable: bool,
) -> Result<Box<dyn TransportClient>, CliFailure> {
    match host.config.transport {
        TransportKind::Local => local_host_service(&host.config)
            .map(|service| Box::new(LocalTransport::new(host.alias.clone(), service)) as _),
        TransportKind::Direct => direct_transport(host)
            .map(|transport| Box::new(transport) as _)
            .map_err(failure),
        TransportKind::Ssh => ssh_transport(host, bootstrap_if_unreachable)
            .map(|transport| Box::new(transport) as _)
            .map_err(failure),
    }
}

pub(crate) fn discover_direct_host_identity(host: &SelectedHost) -> Result<String, SatelleError> {
    if host.config.transport != TransportKind::Direct {
        return Err(SatelleError::invalid_usage(
            "host trust currently requires a direct HTTPS Host Binding",
        ));
    }
    let mut probe_config = host.config.clone();
    probe_config.expected_host_id = Some(format!("trust-probe-{}", Uuid::now_v7()));
    let binding = DirectHostBinding::from_host_config(&probe_config)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ApiTokenSource::File { path } = binding.api_token();
    let raw_token = read_owner_only_secret_file(path)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let token = ApiBearerToken::parse(raw_token.as_str())
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ca_bundle = binding
        .ca_bundle()
        .map(read_trusted_ca_bundle_file)
        .transpose()
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let client = DaemonClient::https(&binding, token, ca_bundle.as_deref().map(str::as_bytes))
        .map_err(|error| direct_transport_error(&host.alias, error))?;
    client
        .discover_host_identity()
        .map_err(|error| direct_transport_error(&host.alias, error))
}

#[cfg(all(test, feature = "test-support"))]
#[path = "transport-tests.rs"]
mod tests;
