use super::*;
use satelle_core::session::{TurnAdmissionPhase, TurnState};
use satelle_core::{ErrorCode, EventSource, EventSubject, EventType, SatelleEventBody};
use satelle_host::{
    ApiScopes, LogCursor, LogPageQuery, LogSeverity, LogSource, test_support::TestStateDir,
};
use satelle_transport::{DaemonServer, DaemonServerConfig};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::error::ProtocolError;

#[path = "transport-reconnect-tests.rs"]
mod reconnect;

fn register_client_tokens(
    service: &HostService,
    principal: &str,
) -> (ApiBearerToken, ApiBearerToken) {
    let generated = ApiBearerToken::generate().expect("generate API token");
    let exposed = generated.expose();
    let registry_token = ApiBearerToken::parse(exposed.as_str()).expect("parse registry token");
    let http_token = ApiBearerToken::parse(exposed.as_str()).expect("parse HTTP token");
    let event_token = ApiBearerToken::parse(exposed.as_str()).expect("parse event token");
    service
        .register_api_token(&registry_token, principal, ApiScopes::CONTROL, None)
        .expect("register API token");
    (http_token, event_token)
}

fn cursor_expiry_api_error(
    earliest_available_cursor: serde_json::Value,
    resume_cursor: &str,
) -> satelle_transport::ApiError {
    serde_json::from_value(serde_json::json!({
        "schema_version": "satelle.error.v1",
        "request_id": satelle_transport::RequestId::new().to_string(),
        "host_identity": "host-direct-test",
        "code": "logs-cursor-expired",
        "category": "not_found",
        "retryable": false,
        "message": "the Log Cursor is older than retained Host history",
        "details": {
            "earliest_available_cursor": earliest_available_cursor,
            "resume_cursor": resume_cursor,
        },
        "docs_url": null,
        "suggested_commands": []
    }))
    .expect("deserialize cursor-expiry API response")
}

struct DirectFixture {
    service: HostService,
    host_identity: String,
    address: SocketAddr,
    server: Option<DaemonServer>,
    server_runtime: tokio::runtime::Runtime,
    transport: Option<DirectTransport>,
    _state: TestStateDir,
}

impl DirectFixture {
    fn start() -> Self {
        let state = TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic Host service");
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let (http_token, event_token) =
            register_client_tokens(&service, "principal-cli-direct-test");
        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("construct daemon runtime");
        let server = server_runtime
            .block_on(DaemonServer::bind(
                service.clone(),
                DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            ))
            .expect("bind loopback daemon");
        let address = server.local_addr();
        let client = DaemonClient::loopback(address, http_token, &host_identity)
            .expect("construct loopback HTTP client");
        let event_client = DaemonEventClient::loopback(address, event_token, &host_identity)
            .expect("construct loopback event client");
        let event_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("construct event runtime");
        Self {
            service,
            host_identity,
            address,
            server: Some(server),
            server_runtime,
            transport: Some(DirectTransport {
                alias: "direct-test".to_string(),
                mode: "direct",
                client: Arc::new(client),
                event_client,
                event_runtime,
                _tunnel: None,
            }),
            _state: state,
        }
    }

    fn transport(&self) -> &DirectTransport {
        self.transport
            .as_ref()
            .expect("fixture transport is present")
    }
}

impl Drop for DirectFixture {
    fn drop(&mut self) {
        drop(self.transport.take());
        if let Some(server) = self.server.take() {
            let shutdown = self.server_runtime.block_on(server.shutdown());
            if !std::thread::panicking() {
                shutdown.expect("shut down loopback daemon");
            }
        }
    }
}

#[test]
fn attached_run_reports_direct_daemon_unreachable_after_wss_subscription_succeeds() {
    let mut fixture = DirectFixture::start();
    let subscribed_stream = fixture
        .transport()
        .event_runtime
        .block_on(
            fixture
                .transport()
                .event_client
                .connect_events(vec![satelle_transport::EventSubscription::Host]),
        )
        .expect("prove the WSS Host subscription is reachable");
    let closed_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve a closed HTTP endpoint");
    let closed_address = closed_listener
        .local_addr()
        .expect("read the closed HTTP endpoint");
    drop(closed_listener);

    let disconnected_token = ApiBearerToken::generate().expect("generate disconnected token");
    let disconnected_client =
        DaemonClient::loopback(closed_address, disconnected_token, &fixture.host_identity)
            .expect("construct disconnected HTTP client");
    fixture
        .transport
        .as_mut()
        .expect("fixture transport is present")
        .client = Arc::new(disconnected_client);

    let failure = match fixture
        .transport()
        .run(&TurnRequest::new("must not be admitted"), &mut |_| {
            panic!("an unadmitted run must not emit events")
        }) {
        Ok(_) => panic!("the disconnected HTTP client must fail run admission"),
        Err(failure) => failure,
    };

    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::DirectDaemonUnreachable);
    assert!(failure.durable_handles().is_none());
    drop(subscribed_stream);
}

#[test]
fn direct_host_sessions_read_daemon_metadata_without_bootstrap() {
    let fixture = DirectFixture::start();
    let local = fixture
        .service
        .host_sessions(LOCAL_DEMO_HOST, true)
        .expect("read local Host desktop sessions");

    let direct = fixture
        .transport()
        .host_sessions(true)
        .expect("read desktop sessions through direct transport");

    assert_eq!(direct.schema_version, HostSessionsSchemaVersion::V1);
    assert_eq!(direct.host, "direct-test");
    assert_eq!(direct.connection_mode, "direct");
    assert!(!direct.bootstrapped);
    assert!(direct.bootstrap_actions.is_empty());
    assert_eq!(direct.host_daemon_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(direct.sessions, local.sessions);
}

#[test]
fn local_and_direct_logs_return_the_same_authoritative_page() {
    let fixture = DirectFixture::start();
    let appended = fixture
        .service
        .append_daemon_log_for_tests(
            time::OffsetDateTime::now_utc(),
            LogSource::Storage,
            LogSeverity::Warning,
        )
        .expect("append a canonical Host log");
    let query = LogPageQuery::tail(1)
        .expect("construct canonical tail query")
        .with_sources([LogSource::Storage])
        .with_minimum_severity(LogSeverity::Warning);
    let local = LocalTransport::new("local-demo".to_string(), fixture.service.clone());

    let local_page = local
        .logs(&query)
        .expect("read logs through local transport");
    let direct_page = fixture
        .transport()
        .logs(&query)
        .expect("read logs through direct transport");

    assert_eq!(direct_page, local_page);
    assert_eq!(direct_page.entries().len(), 1);
    assert_eq!(direct_page.entries()[0].cursor(), appended);
    assert_eq!(direct_page.entries()[0].source(), LogSource::Storage);
    assert_eq!(direct_page.entries()[0].severity(), LogSeverity::Warning);
}

#[test]
fn local_logs_reject_a_non_local_demo_alias_before_reading_the_shared_store() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let local = LocalTransport::new("other-local".to_string(), service);
    let query = LogPageQuery::tail(1).expect("construct canonical tail query");

    let error = local
        .logs(&query)
        .expect_err("a non-local-demo alias must not read the shared local Host store");

    assert_eq!(error.code, ErrorCode::HostNotFound);
    assert_eq!(error.message, "host 'other-local' is not configured");
    assert_eq!(error.exit_code(), 66);
}

#[test]
fn local_and_direct_logs_report_cursor_ahead_as_invalid_usage() {
    let fixture = DirectFixture::start();
    let future_cursor = LogCursor::parse("slc1_7fffffffffffffff")
        .expect("the maximum supported Log Cursor is valid");
    let query =
        LogPageQuery::forward(Some(future_cursor), 1).expect("construct future-cursor query");
    let local = LocalTransport::new("local-demo".to_string(), fixture.service.clone());

    let local_error = local
        .logs(&query)
        .expect_err("local transport must reject a cursor above its high-water mark");
    let direct_error = fixture
        .transport()
        .logs(&query)
        .expect_err("direct transport must reject a cursor above its high-water mark");

    assert_eq!(local_error.code, ErrorCode::InvalidUsage);
    assert_eq!(direct_error.code, local_error.code);
    assert_eq!(direct_error.exit_code(), 64);
}

#[test]
fn direct_logs_preserve_typed_cursor_expiry_details() {
    let earliest = "slc1_0000000000000002";
    let resume = "slc1_0000000000000001";
    let api_error = cursor_expiry_api_error(serde_json::json!(earliest), resume);

    let error = direct_logs_error(
        "direct-test",
        DaemonClientError::Api {
            status: 410_u16.try_into().expect("410 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );

    assert_eq!(error.code, ErrorCode::LogsCursorExpired);
    assert_eq!(
        error.details.get("earliest_available_cursor"),
        Some(&serde_json::json!(earliest))
    );
    assert_eq!(
        error.details.get("resume_cursor"),
        Some(&serde_json::json!(resume))
    );

    let api_error = cursor_expiry_api_error(serde_json::Value::Null, resume);
    let error = direct_logs_error(
        "direct-test",
        DaemonClientError::Api {
            status: 410_u16.try_into().expect("410 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );
    assert_eq!(error.code, ErrorCode::LogsCursorExpired);
    assert_eq!(
        error.details.get("earliest_available_cursor"),
        Some(&serde_json::Value::Null)
    );
}

#[test]
fn direct_logs_reject_contradictory_cursor_expiry_details() {
    let resume = "slc1_0000000000000002";
    let api_error = cursor_expiry_api_error(serde_json::json!(resume), resume);

    let error = direct_logs_error(
        "direct-test",
        DaemonClientError::Api {
            status: 410_u16.try_into().expect("410 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );

    assert_eq!(error.code, ErrorCode::RemoteExecution);
    assert_eq!(
        error.details.get("remote_code"),
        Some(&serde_json::json!("invalid-daemon-response"))
    );
}

#[test]
fn direct_attached_run_and_steer_follow_committed_host_events() {
    let fixture = DirectFixture::start();
    let mut run_events = Vec::new();
    let run_outcome = fixture
        .transport()
        .run(&TurnRequest::new("first turn"), &mut |event| {
            run_events.push(event);
            Ok(())
        })
        .expect("run attached Turn");
    let run = &run_outcome.session;
    assert_eq!(
        run_events
            .iter()
            .map(SatelleEvent::event_type)
            .collect::<Vec<_>>(),
        [
            EventType::TurnStarted,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert_eq!(
        run.turns().last().map(|turn| turn.state()),
        Some(TurnState::Completed)
    );
    assert_eq!(
        run.turns().last().map(|turn| turn.turn_id()),
        Some(&run_outcome.turn_id)
    );
    let admitted_failure = TurnAdmissionFailure::admitted(
        SatelleError::host_unreachable("direct-test"),
        run.clone(),
        run_outcome.turn_id.clone(),
    );
    assert_eq!(admitted_failure.phase(), TurnAdmissionPhase::Admitted);
    assert_eq!(
        admitted_failure.durable_handles(),
        Some((run.session_id(), &run_outcome.turn_id))
    );
    let reconciled = fixture
        .transport()
        .reconciled_terminal_event(
            run,
            run.turns().last().expect("run retains its Turn").turn_id(),
        )
        .expect("construct reconciled terminal event");
    assert_eq!(reconciled.source(), EventSource::Cli);
    assert_eq!(reconciled.event_type(), EventType::TurnCompleted);
    assert_eq!(reconciled.session_id(), Some(run.session_id()));
    let run_turn = run.turns().last().expect("run retains its Turn");
    let contradictory = SatelleEventBody::new(
        EventType::TurnFailed,
        EventSource::HostDaemon,
        run_turn.updated_at(),
        "direct-test",
        Some(EventSubject::Turn {
            session_id: run.session_id().clone(),
            turn_id: run_turn.turn_id().clone(),
            session_state_revision: run.session_state_revision(),
            turn_state_revision: run_turn.turn_state_revision(),
        }),
        "contradictory terminal fixture",
        serde_json::json!({}),
    )
    .and_then(|body| body.with_seq(1))
    .expect("construct contradictory event");
    assert!(
        fixture
            .transport()
            .validate_terminal_event(&contradictory, run, run_turn.turn_id())
            .is_err()
    );

    let mut steer_events = Vec::new();
    let steer_outcome = fixture
        .transport()
        .steer(
            run.session_id(),
            &TurnRequest::new("follow-up turn"),
            &mut |event| {
                steer_events.push(event);
                Ok(())
            },
        )
        .expect("steer attached Turn");
    let steer = &steer_outcome.session;
    assert_eq!(steer.turns().len(), 2);
    assert_eq!(
        steer.turns().last().map(|turn| turn.turn_id()),
        Some(&steer_outcome.turn_id)
    );
    assert_eq!(
        steer_events
            .iter()
            .map(SatelleEvent::event_type)
            .collect::<Vec<_>>(),
        [
            EventType::TurnStarted,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert!(steer_events.iter().all(|event| {
        event.session_id() == Some(steer.session_id())
            && event.turn_id() == steer.turns().last().map(|turn| turn.turn_id())
    }));
    let reconciled_first_turn = fixture
        .transport()
        .event_runtime
        .block_on(fixture.transport().reconcile(
            run.session_id(),
            run_turn.turn_id(),
            Some(run_turn.turn_state_revision()),
        ))
        .expect("reconcile the first Turn after a follow-up advanced the Session revision");
    assert!(reconciled_first_turn.is_some());
}

#[test]
fn mutation_idempotency_keys_are_fresh_uuid_v7_values() {
    let first = DirectTransport::idempotency_key();
    let second = DirectTransport::idempotency_key();
    assert_ne!(first, second);
    assert_eq!(
        Uuid::parse_str(&first)
            .expect("parse first idempotency key")
            .get_version_num(),
        7
    );
    assert_eq!(
        Uuid::parse_str(&second)
            .expect("parse second idempotency key")
            .get_version_num(),
        7
    );
}

#[test]
fn only_connection_loss_and_transient_http_outage_enter_retry_paths() {
    assert!(direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::HandshakeTimeout
    ));
    assert!(direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::Disconnected
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::SequenceDidNotAdvance
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::HostIdentityMismatch
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::SubscriptionMismatch
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::UnexpectedFrame
    ));
    assert!(direct_attached::reconciliation_error_allows_retry(
        &SatelleError::host_unreachable("direct-test")
    ));
    assert!(!direct_attached::reconciliation_error_allows_retry(
        &SatelleError::remote_api_error("direct-test", "invalid-daemon-response")
    ));
    assert_eq!(
        direct_event_error("direct-test", DaemonEventError::HandshakeTimeout).code,
        ErrorCode::HostUnreachable
    );
    assert_eq!(
        direct_run_event_error("direct-test", DaemonEventError::HandshakeTimeout).code,
        ErrorCode::DirectDaemonUnreachable
    );
    assert_eq!(
        direct_run_event_error("direct-test", DaemonEventError::HostIdentityMismatch).code,
        ErrorCode::HostIdentityMismatch,
        "run-specific reachability mapping must preserve trust failures"
    );
    assert_eq!(
        direct_run_event_error(
            "direct-test",
            DaemonEventError::Transport(WebSocketError::Protocol(ProtocolError::WrongHttpMethod)),
        )
        .code,
        ErrorCode::HostUnreachable,
        "run-specific reachability mapping must preserve generic protocol-failure handling"
    );
}

#[test]
fn direct_run_preserves_typed_recoverable_close_errors() {
    let control = serde_json::from_value(serde_json::json!({
        "schema_version": "satelle.ws.control.v1",
        "type": "error",
        "request_id": satelle_transport::RequestId::new(),
        "host_identity": "host-direct-test",
        "reason": "slow-consumer",
        "code": "capacity-exceeded",
        "category": "capacity",
        "retryable": false,
        "message": "the WebSocket subscriber could not keep up with live events",
        "details": null,
        "docs_url": null,
        "suggested_commands": []
    }))
    .expect("deserialize valid slow-consumer control error");

    assert_eq!(
        direct_run_event_error(
            "direct-test",
            DaemonEventError::Closed {
                control: Some(Box::new(control)),
                code: 1008,
                reason: satelle_transport::WsCloseReason::SlowConsumer,
            },
        )
        .code,
        ErrorCode::RemoteExecution,
        "typed close controls must remain authoritative during direct run admission"
    );
}

#[test]
fn admission_failures_preserve_definitive_and_ambiguous_phases() {
    for code in [
        ApiErrorCode::AuthenticationFailed,
        ApiErrorCode::AuthorizationInsufficientScope,
        ApiErrorCode::HostIdentityMismatch,
        ApiErrorCode::InvalidRequest,
        ApiErrorCode::UnsupportedSchema,
        ApiErrorCode::UnsupportedContentType,
        ApiErrorCode::PayloadTooLarge,
        ApiErrorCode::IdempotencyKeyConflict,
        ApiErrorCode::SessionNotFound,
        ApiErrorCode::HostBusy,
        ApiErrorCode::IncompatibleProtocol,
        ApiErrorCode::IncompatibleControlPlane,
        ApiErrorCode::ComputerUseNotReady,
        ApiErrorCode::CapacityExceeded,
        ApiErrorCode::RateLimited,
        ApiErrorCode::RouteNotFound,
        ApiErrorCode::MethodNotAllowed,
    ] {
        assert!(api_error_is_definitively_not_admitted(code), "{code:?}");
    }
    for code in [
        ApiErrorCode::LogsCursorExpired,
        ApiErrorCode::HostUnreachable,
        ApiErrorCode::StoreInUse,
        ApiErrorCode::StateConflict,
        ApiErrorCode::StopNotConfirmed,
        ApiErrorCode::StorageBusy,
        ApiErrorCode::StorageIntegrityFailed,
        ApiErrorCode::RemoteExecutionFailed,
        ApiErrorCode::InternalError,
    ] {
        assert!(!api_error_is_definitively_not_admitted(code), "{code:?}");
    }

    let rejected = direct_admission_error("direct-test", DaemonClientError::InvalidTokenHeader);
    assert_eq!(rejected.phase(), TurnAdmissionPhase::NotAdmitted);
    assert!(rejected.durable_handles().is_none());
    let run_rejected =
        direct_run_admission_error("direct-test", DaemonClientError::InvalidTokenHeader);
    assert_eq!(run_rejected.phase(), rejected.phase());
    assert_eq!(run_rejected.error().code, rejected.error().code);

    let ambiguous =
        direct_admission_error("direct-test", DaemonClientError::ResponseRequestIdMismatch);
    assert_eq!(ambiguous.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert!(ambiguous.durable_handles().is_none());
    let run_ambiguous =
        direct_run_admission_error("direct-test", DaemonClientError::ResponseRequestIdMismatch);
    assert_eq!(run_ambiguous.phase(), ambiguous.phase());
    assert_eq!(run_ambiguous.error().code, ambiguous.error().code);

    let api_error: satelle_transport::ApiError = serde_json::from_value(serde_json::json!({
        "schema_version": "satelle.error.v1",
        "request_id": satelle_transport::RequestId::new().to_string(),
        "host_identity": "host-direct-test",
        "code": "host-unreachable",
        "category": "remote_execution",
        "retryable": true,
        "message": "the configured execution runtime is unreachable",
        "details": null,
        "docs_url": null,
        "suggested_commands": []
    }))
    .expect("deserialize representative daemon API failure");
    let api_failure = direct_admission_error(
        "direct-test",
        DaemonClientError::Api {
            status: 503_u16.try_into().expect("503 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );
    assert_eq!(api_failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert!(api_failure.durable_handles().is_none());
}
