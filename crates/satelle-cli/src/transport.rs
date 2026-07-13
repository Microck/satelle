use crate::output::OutputFormat;
use crate::{CliFailure, SelectedHost, failure};
use satelle_core::{
    ApiTokenSource, DaemonPathOverrides, DirectHostBinding, DoctorReport, HostSessionsReport,
    LogEntry, SatelleError, SessionId, SessionRecord, SetupReport, StopResult, TransportKind,
    read_owner_only_secret_file, read_trusted_ca_bundle_file,
};
use satelle_host::{ApiBearerToken, HostService, HostStatus, TurnOutcome};
use satelle_transport::{ApiErrorCode, DaemonClient, DaemonClientError, TurnRequest};

#[cfg(feature = "test-support")]
const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

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
    fn doctor(&self, scope: Option<&str>, refresh: bool) -> Result<DoctorReport, SatelleError>;
    fn host_status(&self) -> Result<HostStatus, SatelleError>;
    fn host_sessions(&self, no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError>;
    fn run(&self, request: &TurnRequest) -> Result<TurnOutcome, SatelleError>;
    fn run_detached(&self, request: &TurnRequest) -> Result<SessionRecord, SatelleError>;
    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<TurnOutcome, SatelleError>;
    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<SessionRecord, SatelleError>;
    fn status(&self, session_id: &SessionId) -> Result<SessionRecord, SatelleError>;
    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError>;
    fn logs(&self) -> Result<Vec<LogEntry>, SatelleError>;
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

    fn doctor(&self, scope: Option<&str>, refresh: bool) -> Result<DoctorReport, SatelleError> {
        self.service.doctor(&self.alias, scope, refresh)
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        self.service.host_status()
    }

    fn host_sessions(&self, no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        self.service.host_sessions(&self.alias, no_bootstrap)
    }

    fn run(&self, request: &TurnRequest) -> Result<TurnOutcome, SatelleError> {
        self.service
            .run(&self.alias, request.prompt(), request.execution_mode())
    }

    fn run_detached(&self, request: &TurnRequest) -> Result<SessionRecord, SatelleError> {
        self.service
            .run_detached(&self.alias, request.prompt(), request.execution_mode())
    }

    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<TurnOutcome, SatelleError> {
        self.service
            .steer(session_id, request.prompt(), request.execution_mode())
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<SessionRecord, SatelleError> {
        self.service
            .steer_detached(session_id, request.prompt(), request.execution_mode())
    }

    fn status(&self, session_id: &SessionId) -> Result<SessionRecord, SatelleError> {
        self.service.status(session_id)
    }

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.service.stop(session_id)
    }

    fn logs(&self) -> Result<Vec<LogEntry>, SatelleError> {
        self.service.logs(&self.alias)
    }
}

struct DirectTransport {
    alias: String,
    client: DaemonClient,
}

impl DirectTransport {
    fn unsupported(&self, operation: &str) -> SatelleError {
        SatelleError::not_implemented(format!(
            "direct transport for host '{}' does not yet support {operation}",
            self.alias
        ))
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

    fn doctor(&self, _scope: Option<&str>, _refresh: bool) -> Result<DoctorReport, SatelleError> {
        Err(self.unsupported("doctor"))
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        let response = self
            .client
            .host_status()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(HostStatus {
            running: true,
            mode: "direct".to_string(),
            sessions: response.session_count(),
        })
    }

    fn host_sessions(&self, _no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        Err(self.unsupported("host sessions"))
    }

    fn run(&self, _request: &TurnRequest) -> Result<TurnOutcome, SatelleError> {
        Err(self.unsupported("run"))
    }

    fn run_detached(&self, _request: &TurnRequest) -> Result<SessionRecord, SatelleError> {
        Err(self.unsupported("detached run"))
    }

    fn steer(
        &self,
        _session_id: &SessionId,
        _request: &TurnRequest,
    ) -> Result<TurnOutcome, SatelleError> {
        Err(self.unsupported("steer"))
    }

    fn steer_detached(
        &self,
        _session_id: &SessionId,
        _request: &TurnRequest,
    ) -> Result<SessionRecord, SatelleError> {
        Err(self.unsupported("detached steer"))
    }

    fn status(&self, _session_id: &SessionId) -> Result<SessionRecord, SatelleError> {
        Err(self.unsupported("session status"))
    }

    fn stop(&self, _session_id: &SessionId) -> Result<StopResult, SatelleError> {
        Err(self.unsupported("stop"))
    }

    fn logs(&self) -> Result<Vec<LogEntry>, SatelleError> {
        Err(self.unsupported("logs"))
    }
}

fn direct_transport(host: &SelectedHost) -> Result<DirectTransport, SatelleError> {
    let binding = DirectHostBinding::from_host_config(&host.config)
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
    Ok(DirectTransport {
        alias: host.alias.clone(),
        client,
    })
}

fn direct_transport_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Api { error, .. } => match error.code() {
            ApiErrorCode::AuthenticationFailed => SatelleError::authentication_failed(host),
            ApiErrorCode::AuthorizationInsufficientScope => {
                SatelleError::authorization_insufficient_scope(host)
            }
            ApiErrorCode::HostIdentityMismatch => SatelleError::host_identity_mismatch(host),
            code => SatelleError::remote_api_error(host, code.as_str()),
        },
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

fn local_host_service(_output: OutputFormat) -> Result<HostService, CliFailure> {
    #[cfg(feature = "test-support")]
    let json = _output.is_json();
    #[cfg(feature = "test-support")]
    match std::env::var(TEST_SUPPORT_ADAPTER_ENV) {
        Ok(value) if value == "fake" => {
            return HostService::local_demo_for_tests().map_err(|error| failure(error, json));
        }
        Ok(_) => {
            return Err(failure(
                SatelleError::invalid_usage(
                    "SATELLE_TEST_SUPPORT_ADAPTER must be exactly 'fake' or unset",
                ),
                json,
            ));
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(failure(
                SatelleError::invalid_usage(
                    "SATELLE_TEST_SUPPORT_ADAPTER must contain valid UTF-8",
                ),
                json,
            ));
        }
        Err(std::env::VarError::NotPresent) => {}
    }

    Ok(HostService::production())
}

pub(crate) fn transport_for(
    host: &SelectedHost,
    output: OutputFormat,
) -> Result<Box<dyn TransportClient>, CliFailure> {
    match host.config.transport {
        TransportKind::Local => local_host_service(output)
            .map(|service| Box::new(LocalTransport::new(host.alias.clone(), service)) as _),
        TransportKind::Direct => direct_transport(host)
            .map(|transport| Box::new(transport) as _)
            .map_err(|error| failure(error, output.is_json())),
        TransportKind::Ssh => Err(failure(
            SatelleError::host_unreachable(&host.alias),
            output.is_json(),
        )),
    }
}
