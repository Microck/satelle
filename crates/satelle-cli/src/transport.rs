use crate::output::OutputFormat;
use crate::{CliFailure, SelectedHost, failure};
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    ApiTokenSource, DaemonPathOverrides, DirectHostBinding, DoctorReport, HostSessionsReport,
    LogEntry, SatelleError, SatelleEvent, SessionId, SetupReport, StopResult, TransportKind,
    TurnId, read_owner_only_secret_file, read_trusted_ca_bundle_file,
};
use satelle_host::{ApiBearerToken, HostService, HostStatus};
use satelle_transport::{
    ApiErrorCode, DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError, TurnRequest,
};
use std::sync::Arc;
use uuid::Uuid;

#[path = "direct-attached.rs"]
mod direct_attached;

#[cfg(feature = "test-support")]
const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

pub(crate) struct AttachedTurnOutcome {
    pub(crate) session: PublicSession,
    pub(crate) turn_id: TurnId,
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
    fn doctor(&self, scope: Option<&str>, refresh: bool) -> Result<DoctorReport, SatelleError>;
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

    fn run(
        &self,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let outcome = self
            .service
            .run(&self.alias, request.prompt(), request.execution_mode())?;
        let turn_id = outcome
            .session
            .turns()
            .last()
            .expect("an admitted local run always contains its target Turn")
            .turn_id()
            .clone();
        for event in outcome.events {
            on_event(event).map_err(|error| {
                TurnAdmissionFailure::admitted(error, outcome.session.clone(), turn_id.clone())
            })?;
        }
        Ok(AttachedTurnOutcome {
            session: outcome.session,
            turn_id,
        })
    }

    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError> {
        self.service
            .run_detached(&self.alias, request.prompt(), request.execution_mode())
    }

    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let outcome = self
            .service
            .steer(session_id, request.prompt(), request.execution_mode())?;
        let turn_id = outcome
            .session
            .turns()
            .last()
            .expect("an admitted local steer always contains its target Turn")
            .turn_id()
            .clone();
        for event in outcome.events {
            on_event(event).map_err(|error| {
                TurnAdmissionFailure::admitted(error, outcome.session.clone(), turn_id.clone())
            })?;
        }
        Ok(AttachedTurnOutcome {
            session: outcome.session,
            turn_id,
        })
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError> {
        self.service
            .steer_detached(session_id, request.prompt(), request.execution_mode())
    }

    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
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
    client: Arc<DaemonClient>,
    event_client: DaemonEventClient,
    event_runtime: tokio::runtime::Runtime,
}

impl DirectTransport {
    fn unsupported(&self, operation: &str) -> SatelleError {
        SatelleError::not_implemented(format!(
            "direct transport for host '{}' does not yet support {operation}",
            self.alias
        ))
    }

    fn idempotency_key() -> String {
        Uuid::now_v7().hyphenated().to_string()
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
            .map_err(|error| direct_transport_error(&self.alias, error))
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
            .map_err(|error| direct_transport_error(&host.alias, error))?,
    );
    let event_client = DaemonEventClient::wss(&binding, event_token, ca_bundle)
        .map_err(|error| direct_event_error(&host.alias, error))?;
    let event_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    Ok(DirectTransport {
        alias: host.alias.clone(),
        client,
        event_client,
        event_runtime,
    })
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

fn direct_transport_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Api { error, .. } => api_code_error(host, error.code()),
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
        code => SatelleError::remote_api_error(host, code.as_str()),
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

#[cfg(all(test, feature = "test-support"))]
#[path = "transport-tests.rs"]
mod tests;
