#[path = "http/desktop-sessions.rs"]
mod desktop_sessions;
#[path = "http/events.rs"]
mod events;
#[path = "http/logs.rs"]
mod logs;
#[path = "http/protocol.rs"]
mod protocol;
#[path = "http/raw-wire.rs"]
mod raw_wire;
#[path = "http/sessions.rs"]
mod sessions;

use reqwest::StatusCode;
use satelle_core::ErrorCode;
use satelle_host::{ApiBearerToken, ApiScopes, HostService, test_support::TestStateDir};
use satelle_transport::{
    ApiError, CapabilitiesResponse, DaemonClient, DaemonClientError, DaemonServer,
    DaemonServerConfig, HostDesktopSessionsResponse, HostStatusResponse, LiveResponse,
    LogsPageResponse, RequestId,
};
use serde_json::Value;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const EXPECTED_OPERATIONS: [&str; 10] = [
    "live",
    "capabilities",
    "host_status",
    "host_desktop_sessions",
    "session_create",
    "turn_create",
    "session_read",
    "session_stop",
    "logs_read",
    "events_read",
];

struct RunningServer {
    _state: TestStateDir,
    service: HostService,
    server: DaemonServer,
    token: ApiBearerToken,
    host_identity: String,
}

impl RunningServer {
    async fn start(scopes: ApiScopes) -> Self {
        let state = TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic Host service");
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let token = ApiBearerToken::generate().expect("generate API token");
        service
            .register_api_token(&token, "principal-http-test", scopes, None)
            .expect("register API token");
        let server = DaemonServer::bind(
            service.clone(),
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        )
        .await
        .expect("bind daemon server");
        Self {
            _state: state,
            service,
            server,
            token,
            host_identity,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.server.local_addr(), path)
    }

    fn request(&self, path: &str) -> reqwest::RequestBuilder {
        self.protected_request(reqwest::Method::GET, path)
    }

    fn mutation(&self, path: &str, idempotency_key: &str) -> reqwest::RequestBuilder {
        self.protected_request(reqwest::Method::POST, path)
            .header("Idempotency-Key", idempotency_key)
            .header("Satelle-Protocol-Version", "1")
    }

    fn protected_request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let token = self.token.expose();
        reqwest::Client::new()
            .request(method, self.url(path))
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Satelle-Expected-Host-Identity", &self.host_identity)
            .header("Satelle-Request-Id", RequestId::new().to_string())
    }
}

fn bearer(token: &ApiBearerToken) -> String {
    let exposed = token.expose();
    format!("Bearer {}", exposed.as_str())
}

async fn assert_rate_limited(
    response: reqwest::Response,
    expected_host_identity: Option<&str>,
) -> u64 {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let error = response
        .json::<Value>()
        .await
        .expect("decode typed rate-limit response");
    assert_eq!(error["code"], "rate-limited");
    assert_eq!(error["category"], "rate_limit");
    assert_eq!(error["retryable"], true);
    assert_eq!(
        error["host_identity"],
        expected_host_identity.map_or(Value::Null, |value| Value::String(value.to_string()))
    );
    error["details"]["retry_after_ms"]
        .as_u64()
        .expect("known fixed-window timing must be reported")
}

#[tokio::test]
async fn liveness_is_exact_and_reveals_no_protected_metadata() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let generated_response = reqwest::get(running.url("/v1/live"))
        .await
        .expect("request liveness without a caller correlation ID");
    RequestId::parse(
        generated_response.headers()["satelle-request-id"]
            .to_str()
            .expect("generated request ID is ASCII"),
    )
    .expect("liveness generates a canonical UUIDv7 correlation ID");

    let request_id = RequestId::new();
    let response = reqwest::Client::new()
        .get(running.url("/v1/live"))
        .header("Satelle-Request-Id", request_id.to_string())
        .send()
        .await
        .expect("request liveness");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["satelle-request-id"],
        request_id.as_str()
    );
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let bytes = response.bytes().await.expect("read liveness body");
    let value: Value = serde_json::from_slice(&bytes).expect("parse liveness JSON");
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": "satelle.live.v1",
            "alive": true
        })
    );
    let parsed: LiveResponse = serde_json::from_slice(&bytes).expect("decode live contract");
    assert!(parsed.alive());
    assert!(!String::from_utf8_lossy(&bytes).contains(&running.host_identity));
}

#[tokio::test]
async fn liveness_method_rejections_are_correlated() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let request_id = RequestId::new();
    let response = reqwest::Client::new()
        .post(running.url("/v1/live"))
        .header("Satelle-Request-Id", request_id.to_string())
        .send()
        .await
        .expect("request an unsupported liveness method");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers()["satelle-request-id"],
        request_id.as_str()
    );
    let error: ApiError = response.json().await.expect("decode liveness method error");
    assert_eq!(error.code().as_str(), "method-not-allowed");
    assert_eq!(error.request_id(), &request_id);
    assert_eq!(error.host_identity(), None);
}

#[tokio::test]
async fn protected_reads_authenticate_before_host_pinning() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let request_id = RequestId::new();
    let client = reqwest::Client::new();

    let missing = client
        .get(running.url("/v1/host/status"))
        .header("Satelle-Request-Id", request_id.to_string())
        .send()
        .await
        .expect("request without token");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let missing_error: ApiError = missing.json().await.expect("decode missing-token error");
    assert_eq!(missing_error.code().as_str(), "authentication-failed");
    assert_eq!(missing_error.request_id(), &request_id);
    assert_eq!(missing_error.host_identity(), None);

    let malformed = client
        .get(running.url("/v1/host/status"))
        .header("Authorization", "Bearer not-a-token")
        .header("Satelle-Expected-Host-Identity", "attacker-observation")
        .header("Satelle-Request-Id", request_id.to_string())
        .send()
        .await
        .expect("request malformed token");
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);
    let malformed_error: ApiError = malformed
        .json()
        .await
        .expect("decode malformed-token error");
    assert_eq!(malformed_error.code().as_str(), "authentication-failed");
    assert_eq!(malformed_error.host_identity(), None);

    let exposed = running.token.expose();
    let mismatch = client
        .get(running.url("/v1/host/status"))
        .header("Authorization", format!("Bearer {}", exposed.as_str()))
        .header("Satelle-Expected-Host-Identity", "host-wrong")
        .header("Satelle-Request-Id", request_id.to_string())
        .send()
        .await
        .expect("request mismatched identity");
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let mismatch_error: ApiError = mismatch.json().await.expect("decode identity error");
    assert_eq!(mismatch_error.code().as_str(), "host-identity-mismatch");
    assert_eq!(
        mismatch_error.host_identity(),
        Some(running.host_identity.as_str())
    );

    let generated = client
        .get(running.url("/v1/host/status"))
        .header("Authorization", format!("Bearer {}", exposed.as_str()))
        .header("Satelle-Expected-Host-Identity", &running.host_identity)
        .send()
        .await
        .expect("request status without a caller correlation ID");
    assert_eq!(generated.status(), StatusCode::OK);
    let generated_header = RequestId::parse(
        generated.headers()["satelle-request-id"]
            .to_str()
            .expect("generated request ID is ASCII"),
    )
    .expect("authenticated response generates a canonical UUIDv7 request ID");
    let generated_status: HostStatusResponse = generated
        .json()
        .await
        .expect("decode generated-correlation status");
    assert_eq!(generated_status.request_id(), &generated_header);

    let malformed_id = client
        .get(running.url("/v1/host/status"))
        .header("Authorization", format!("Bearer {}", exposed.as_str()))
        .header("Satelle-Expected-Host-Identity", &running.host_identity)
        .header("Satelle-Request-Id", "not-a-uuidv7")
        .send()
        .await
        .expect("request status with a malformed correlation ID");
    assert_eq!(malformed_id.status(), StatusCode::BAD_REQUEST);
    let malformed_id_error: ApiError = malformed_id
        .json()
        .await
        .expect("decode malformed request ID error");
    assert_eq!(malformed_id_error.code().as_str(), "invalid-request");

    let accepted = running
        .request("/v1/host/status")
        .send()
        .await
        .expect("request status");
    assert_eq!(accepted.status(), StatusCode::OK);
    let status: HostStatusResponse = accepted.json().await.expect("decode status");
    assert_eq!(status.host_identity(), running.host_identity);
    assert_eq!(status.session_count(), 0);
}

#[tokio::test]
async fn daemon_client_preserves_the_typed_host_identity_mismatch() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let address = running.server.local_addr();
    let token = {
        let exposed = running.token.expose();
        ApiBearerToken::parse(exposed.as_str()).expect("copy test token into the pinned client")
    };
    let error = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, token, "host-intentionally-wrong")?.host_status()
    })
    .await
    .expect("join wrong-identity request")
    .expect_err("the server must reject a mismatched Host pin");
    match error {
        DaemonClientError::Api { status, error } => {
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(error.code().as_str(), "host-identity-mismatch");
            assert_eq!(error.host_identity(), Some(running.host_identity.as_str()));
        }
        other => panic!("expected the typed Host mismatch, got {other:?}"),
    }
}

#[derive(Clone, Copy)]
enum ClientProtocolViolation {
    SuccessStatus,
    RequestId,
    HostIdentity,
}

#[tokio::test]
async fn daemon_client_rejects_success_envelope_protocol_violations() {
    use axum::Json;
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::get;

    for violation in [
        ClientProtocolViolation::SuccessStatus,
        ClientProtocolViolation::RequestId,
        ClientProtocolViolation::HostIdentity,
    ] {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind protocol fixture");
        let address = listener
            .local_addr()
            .expect("read protocol fixture address");
        let app = Router::new().route(
            "/v1/host/status",
            get(move |headers: HeaderMap| async move {
                let request_id = headers
                    .get("satelle-request-id")
                    .and_then(|value| value.to_str().ok())
                    .expect("client sends a request ID");
                let response_id = match violation {
                    ClientProtocolViolation::RequestId => RequestId::new().to_string(),
                    _ => request_id.to_string(),
                };
                let host_identity = match violation {
                    ClientProtocolViolation::HostIdentity => "host-other",
                    _ => "host-expected",
                };
                let status = match violation {
                    ClientProtocolViolation::SuccessStatus => StatusCode::ACCEPTED,
                    _ => StatusCode::OK,
                };
                (
                    status,
                    Json(serde_json::json!({
                        "schema_version": "satelle.host.status.v1",
                        "request_id": response_id,
                        "host_identity": host_identity,
                        "daemon_version": "0.1.0",
                        "started_at": "2024-01-01T00:00:00Z",
                        "process_mode": "foreground",
                        "session_count": 0,
                        "active_turn_count": 0,
                        "recovery_pending_turn_count": 0
                    })),
                )
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let token = ApiBearerToken::generate().expect("generate protocol-fixture token");
        let error = tokio::task::spawn_blocking(move || {
            DaemonClient::loopback(address, token, "host-expected")?.host_status()
        })
        .await
        .expect("join protocol-fixture request")
        .expect_err("the client must reject the malformed success contract");
        server.abort();
        let _ = server.await;

        match violation {
            ClientProtocolViolation::SuccessStatus => assert!(matches!(
                error,
                DaemonClientError::UnexpectedSuccessStatus {
                    expected: StatusCode::OK,
                    actual: StatusCode::ACCEPTED
                }
            )),
            ClientProtocolViolation::RequestId => assert!(matches!(
                error,
                DaemonClientError::ResponseRequestIdMismatch
            )),
            ClientProtocolViolation::HostIdentity => assert!(matches!(
                error,
                DaemonClientError::ResponseHostIdentityMismatch
            )),
        }
    }
}

#[tokio::test]
async fn daemon_client_rejects_authenticated_errors_without_the_pinned_host_identity() {
    use axum::Json;
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::get;

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind protocol fixture");
    let address = listener
        .local_addr()
        .expect("read protocol fixture address");
    let app = Router::new().route(
        "/v1/host/status",
        get(|headers: HeaderMap| async move {
            let request_id = headers
                .get("satelle-request-id")
                .and_then(|value| value.to_str().ok())
                .expect("client sends a request ID");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "schema_version": "satelle.error.v1",
                    "request_id": request_id,
                    "host_identity": null,
                    "code": "session-not-found",
                    "category": "not_found",
                    "retryable": false,
                    "message": "fixture error",
                    "details": null,
                    "docs_url": null,
                    "suggested_commands": []
                })),
            )
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let token = ApiBearerToken::generate().expect("generate protocol-fixture token");
    let error = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, token, "host-expected")?.host_status()
    })
    .await
    .expect("join protocol-fixture request")
    .expect_err("an authenticated error without Host Identity must be rejected");
    server.abort();
    let _ = server.await;

    assert!(matches!(
        error,
        DaemonClientError::ResponseHostIdentityMismatch
    ));
}

#[tokio::test]
async fn daemon_client_preserves_identity_free_authentication_failures() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let address = running.server.local_addr();
    let expected_host_identity = running.host_identity.clone();
    let unknown = ApiBearerToken::generate().expect("generate unregistered token");
    let error = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, unknown, expected_host_identity)?.host_status()
    })
    .await
    .expect("join authentication request")
    .expect_err("the unregistered token must fail authentication");

    match error {
        DaemonClientError::Api { status, error } => {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(error.code().as_str(), "authentication-failed");
            assert_eq!(error.host_identity(), None);
        }
        other => panic!("expected the typed authentication failure, got {other:?}"),
    }
}

#[tokio::test]
async fn capabilities_are_truthful_and_unknown_routes_are_typed() {
    let running = RunningServer::start(ApiScopes::ADMIN).await;
    let response = running
        .request("/v1/capabilities")
        .send()
        .await
        .expect("request capabilities");
    assert_eq!(response.status(), StatusCode::OK);
    let capabilities: CapabilitiesResponse = response.json().await.expect("decode capabilities");
    assert_eq!(capabilities.host_identity(), running.host_identity);
    assert_eq!(capabilities.operations(), EXPECTED_OPERATIONS);
    assert_eq!(capabilities.limits().attachment_count(), 0);
    assert_eq!(
        capabilities.limits().websocket_connections_per_principal(),
        4
    );
    assert_eq!(capabilities.limits().websocket_message_bytes(), 65_536);
    assert_eq!(
        capabilities
            .limits()
            .websocket_subscriptions_per_connection(),
        16
    );
    assert_eq!(
        capabilities
            .limits()
            .websocket_inbound_messages_per_minute(),
        120
    );
    assert_eq!(
        capabilities.limits().websocket_outbound_queue_messages(),
        256
    );
    assert_eq!(capabilities.limits().websocket_ping_interval_ms(), 15_000);
    assert_eq!(capabilities.limits().websocket_idle_timeout_ms(), 45_000);

    let unknown = running
        .request("/v1/not-a-route")
        .send()
        .await
        .expect("request absent route");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let error: ApiError = unknown.json().await.expect("decode not-found error");
    assert_eq!(error.code().as_str(), "route-not-found");
    assert_eq!(error.host_identity(), Some(running.host_identity.as_str()));
}

#[tokio::test]
async fn plaintext_non_loopback_bind_is_rejected_before_listening() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let error = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
    )
    .await
    .expect_err("non-loopback plaintext bind must fail");
    assert_eq!(error.code(), "non-loopback-plaintext-bind");
}

#[tokio::test]
async fn second_daemon_reports_store_in_use_before_accepting_requests() {
    let state = TestStateDir::new().expect("temporary state directory");
    let first_service =
        HostService::local_demo_for_tests_at(state.path()).expect("construct first Host service");
    let first_server = DaemonServer::bind(
        first_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind first daemon");
    let second_service =
        HostService::local_demo_for_tests_at(state.path()).expect("construct second Host service");

    let error = DaemonServer::bind(
        second_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect_err("the second daemon must fail before serving");

    assert_eq!(error.code(), "store-in-use");
    assert_eq!(
        error
            .host_error()
            .expect("retain the typed Host initialization failure")
            .code,
        ErrorCode::StoreInUse
    );
    first_server.shutdown().await.expect("stop first daemon");
}

#[tokio::test]
async fn unknown_expired_and_revoked_tokens_have_one_failure_contract() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let unknown = ApiBearerToken::generate().expect("generate unknown token");
    let expired = ApiBearerToken::generate().expect("generate expiring token");
    running
        .service
        .register_api_token(
            &expired,
            "principal-expired",
            ApiScopes::READ,
            Some(time::OffsetDateTime::now_utc() + time::Duration::milliseconds(50)),
        )
        .expect("register expiring token");
    let revoked = ApiBearerToken::generate().expect("generate revoked token");
    running
        .service
        .register_api_token(&revoked, "principal-revoked", ApiScopes::READ, None)
        .expect("register revocable token");
    running
        .service
        .revoke_api_token(revoked.token_id())
        .expect("revoke token");
    tokio::time::sleep(Duration::from_millis(75)).await;

    let request_id = RequestId::new();
    let client = reqwest::Client::new();
    let mut failures = Vec::new();
    for token in [&unknown, &expired, &revoked] {
        let response = client
            .get(running.url("/v1/host/status"))
            .header("Authorization", bearer(token))
            .header("Satelle-Expected-Host-Identity", &running.host_identity)
            .header("Satelle-Request-Id", request_id.to_string())
            .send()
            .await
            .expect("request rejected credential");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        failures.push(response.json::<Value>().await.expect("decode auth failure"));
    }
    assert!(failures.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(failures[0]["code"], "authentication-failed");
    assert_eq!(failures[0]["host_identity"], Value::Null);
}

#[tokio::test]
async fn tokens_outside_authorization_and_read_request_bodies_are_rejected() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let exposed = running.token.expose();
    let client = reqwest::Client::new();

    let query_only = client
        .get(running.url(&format!("/v1/host/status?token={}", exposed.as_str())))
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .send()
        .await
        .expect("request query token");
    assert_eq!(query_only.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        query_only
            .json::<ApiError>()
            .await
            .expect("decode query-token rejection")
            .code()
            .as_str(),
        "authentication-failed"
    );

    for request in [
        running
            .request("/v1/host/status?mode=verbose")
            .header("Cookie", format!("satelle_token={}", exposed.as_str())),
        running
            .request("/v1/host/status")
            .body(format!("token={}", exposed.as_str())),
    ] {
        let response = request.send().await.expect("request forbidden placement");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response
            .bytes()
            .await
            .expect("read forbidden-placement body");
        assert!(
            !body
                .windows(exposed.len())
                .any(|window| window == exposed.as_bytes())
        );
    }
}

#[tokio::test]
async fn failed_authentication_limit_uses_the_real_peer_address() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let client = reqwest::Client::new();
    let mut limited_response = None;
    for attempt in 1..=11 {
        let response = client
            .get(running.url("/v1/host/status"))
            .header("Satelle-Request-Id", RequestId::new().to_string())
            .send()
            .await
            .expect("request missing token");
        let expected = if attempt <= 10 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(response.status(), expected);
        if attempt == 11 {
            limited_response = Some(response);
        }
    }
    let retry_after_ms = assert_rate_limited(
        limited_response.expect("the eleventh attempt must be rate limited"),
        None,
    )
    .await;
    assert!((1..60_000).contains(&retry_after_ms));
}

#[tokio::test]
async fn authenticated_request_limit_reports_the_remaining_window() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let client = reqwest::Client::new();
    let authorization = bearer(&running.token);
    for attempt in 1..=601 {
        let response = client
            .get(running.url("/v1/host/status"))
            .header("Authorization", &authorization)
            .header("Satelle-Expected-Host-Identity", &running.host_identity)
            .header("Satelle-Request-Id", RequestId::new().to_string())
            .send()
            .await
            .expect("request authenticated rate limit");
        if attempt <= 600 {
            assert_eq!(response.status(), StatusCode::OK);
            response
                .bytes()
                .await
                .expect("drain successful read response");
        } else {
            let retry_after_ms = assert_rate_limited(response, Some(&running.host_identity)).await;
            assert!((1..60_000).contains(&retry_after_ms));
        }
    }
}

#[tokio::test]
async fn control_routes_limit_control_and_admin_principals() {
    for (scope_name, scopes) in [("control", ApiScopes::CONTROL), ("admin", ApiScopes::ADMIN)] {
        let running = RunningServer::start(scopes).await;
        for attempt in 1..=121 {
            let response = running
                .mutation("/v1/sessions", "control-rate-limit-probe")
                .send()
                .await
                .expect("request control rate limit");
            if attempt <= 120 {
                assert_eq!(
                    response.status(),
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "{scope_name} request {attempt} was limited too early"
                );
                response
                    .bytes()
                    .await
                    .expect("drain rejected mutation response");
            } else {
                let retry_after_ms =
                    assert_rate_limited(response, Some(&running.host_identity)).await;
                assert!((1..60_000).contains(&retry_after_ms));
            }
        }
    }
}

#[tokio::test]
async fn advertised_connection_limit_is_enforced_by_the_listener() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let token = ApiBearerToken::generate().expect("generate API token");
    service
        .register_api_token(&token, "principal-limit", ApiScopes::READ, None)
        .expect("register API token");
    let server = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_max_connections(1),
    )
    .await
    .expect("bind limited server");
    let mut held = TcpStream::connect(server.local_addr())
        .await
        .expect("open held connection");
    held.write_all(b"GET /v1/live HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write partial request");
    tokio::time::sleep(Duration::from_millis(25)).await;

    let blocked_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(100))
        .build()
        .expect("build bounded client");
    let blocked = blocked_client
        .get(format!("http://{}/v1/live", server.local_addr()))
        .send()
        .await;
    assert!(
        blocked.is_err(),
        "a second connection must wait for capacity"
    );
    drop(held);

    let address = server.local_addr();
    let expected_identity = initialized.host_identity().to_string();
    let live = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, token, expected_identity)?.live()
    })
    .await
    .expect("join blocking client")
    .expect("request after releasing capacity");
    assert!(live.alive());
}

#[tokio::test]
async fn read_control_and_admin_scopes_all_authorize_read_routes() {
    for (name, scopes) in [
        ("read", ApiScopes::READ),
        ("control", ApiScopes::CONTROL),
        ("admin", ApiScopes::ADMIN),
    ] {
        let running = RunningServer::start(scopes).await;
        let response = running
            .request("/v1/capabilities")
            .send()
            .await
            .unwrap_or_else(|error| panic!("{name} scope request failed: {error}"));
        assert_eq!(response.status(), StatusCode::OK, "scope={name}");
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }
}
