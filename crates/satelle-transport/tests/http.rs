#[path = "http/conformance.rs"]
mod conformance;
#[path = "http/desktop-sessions.rs"]
mod desktop_sessions;
#[path = "http/event-client.rs"]
mod event_client;
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
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use satelle_core::session::TurnExecutionMode;
use satelle_core::{
    ApiRateLimits, ApiTokenSource, DirectHostBinding, ErrorCode, SatelleConfig, TransportKind,
};
use satelle_host::{
    ApiBearerToken, ApiScopes, HostService, MutationAuthority, TurnIntent,
    test_support::TestStateDir,
};
use satelle_transport::{
    ApiError, ApiErrorCode, CapabilitiesResponse, DURABLE_SETUP_PENDING_TTL, DaemonClient,
    DaemonClientError, DaemonEventClient, DaemonServer, DaemonServerConfig, DaemonTlsConfig,
    DaemonTlsConfigError, DaemonTlsReloadError, DurableTokenActivationResponse,
    DurableTokenIssuanceResponse, EventSubscription, HostDesktopSessionsResponse,
    HostStatusResponse, LiveResponse, LogsPageResponse, RequestId, TrustedProxy,
};
use serde_json::Value;
use std::cell::RefCell;
use std::fmt::Write as _;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tracing::field::{Field, Visit};
use tracing::metadata::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const EXPECTED_OPERATIONS: [&str; 14] = [
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
    "setup_api_token_current",
    "setup_api_token_issue",
    "setup_api_token_activate",
    "setup_api_token_abort",
];

const BLOCKING_SPAN_ATTRIBUTE_MARKER: &str = "trace-blocking-span-attribute-connected";
const BLOCKING_SPAN_RECORD_MARKER: &str = "trace-blocking-span-record-connected";
const BLOCKING_EVENT_MARKER: &str = "trace-blocking-event-connected";
const TEST_INFRASTRUCTURE_DEADLOCK_LIMIT: Duration = Duration::from_secs(30);
static TRACE_CAPTURE_LOCK: Mutex<()> = Mutex::new(());

struct RunningServer {
    _state: TestStateDir,
    service: HostService,
    server: DaemonServer,
    token: ApiBearerToken,
    host_identity: String,
}

fn trusted_test_proxy_ranges() -> [TrustedProxy; 5] {
    // Some CI and sandbox networks transparently route loopback HTTP through
    // the machine's private address. These explicit ranges cover either real
    // peer while keeping the documentation-origin ranges untrusted.
    [
        "127.0.0.0/8".parse().expect("parse loopback proxy range"),
        "10.0.0.0/8".parse().expect("parse private proxy range"),
        "172.16.0.0/12".parse().expect("parse private proxy range"),
        "192.168.0.0/16".parse().expect("parse private proxy range"),
        "::1/128".parse().expect("parse IPv6 loopback proxy range"),
    ]
}

impl RunningServer {
    async fn start(scopes: ApiScopes) -> Self {
        Self::start_with_config(
            scopes,
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        )
        .await
    }

    async fn start_with_config(scopes: ApiScopes, config: DaemonServerConfig) -> Self {
        let state = TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic Host service");
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let token = ApiBearerToken::generate().expect("generate API token");
        service
            .register_api_token(&token, "principal-http-test", scopes, None)
            .expect("register API token");
        let server = DaemonServer::bind(service.clone(), config)
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
            .header("Satelle-Protocol-Version", "4")
    }

    fn mutation_with_request_id(
        &self,
        path: &str,
        idempotency_key: &str,
        request_id: &RequestId,
    ) -> reqwest::RequestBuilder {
        self.protected_request_with_request_id(reqwest::Method::POST, path, request_id)
            .header("Idempotency-Key", idempotency_key)
            .header("Satelle-Protocol-Version", "4")
    }

    fn protected_request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.protected_request_with_request_id(method, path, &RequestId::new())
    }

    fn protected_request_with_request_id(
        &self,
        method: reqwest::Method,
        path: &str,
        request_id: &RequestId,
    ) -> reqwest::RequestBuilder {
        let token = self.token.expose();
        reqwest::Client::new()
            .request(method, self.url(path))
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Satelle-Expected-Host-Identity", &self.host_identity)
            .header("Satelle-Request-Id", request_id.as_str())
    }
}

/// Runs one real server test under a scoped tracing Dispatch. Tokio's runtime
/// hooks propagate that Dispatch to the single blocking thread used by Host
/// admission without changing the process-global subscriber.
fn run_with_trace_capture<F, Fut>(test: F)
where
    F: FnOnce(TraceCapture) -> Fut,
    Fut: Future<Output = ()>,
{
    // Tracing callsite interest is process-global even when each Dispatch is
    // thread-local. Keep the two capture tests from rebuilding that cache at
    // the same time while retaining scoped, non-global subscribers.
    let _capture_lock = TRACE_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let trace_capture = TraceCapture::default();
    let dispatch = trace_capture.dispatch();
    let _server_guard = tracing::dispatcher::set_default(&dispatch);
    let blocking_dispatch = dispatch.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .on_thread_start(move || install_runtime_thread_dispatch(&blocking_dispatch))
        .on_thread_stop(clear_runtime_thread_dispatch)
        .build()
        .expect("build traced Host runtime");
    runtime.block_on(test(trace_capture));
}

thread_local! {
    static RUNTIME_TRACE_GUARD: RefCell<Option<tracing::dispatcher::DefaultGuard>> =
        const { RefCell::new(None) };
}

fn install_runtime_thread_dispatch(dispatch: &tracing::Dispatch) {
    RUNTIME_TRACE_GUARD.with(|guard| {
        let mut guard = guard.borrow_mut();
        assert!(
            guard.is_none(),
            "runtime tracing dispatch is already installed"
        );
        *guard = Some(tracing::dispatcher::set_default(dispatch));
    });
    let span = tracing::trace_span!(
        target: "satelle_transport::test",
        "Host blocking trace capture connected",
        initial_marker = BLOCKING_SPAN_ATTRIBUTE_MARKER,
        later_marker = tracing::field::Empty,
    );
    span.record("later_marker", BLOCKING_SPAN_RECORD_MARKER);
    tracing::trace!(
        target: "satelle_transport::test",
        marker = BLOCKING_EVENT_MARKER,
        "Host blocking trace event connected"
    );
}

fn clear_runtime_thread_dispatch() {
    RUNTIME_TRACE_GUARD.with(|guard| {
        guard.borrow_mut().take();
    });
}

#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

impl TraceCapture {
    fn dispatch(&self) -> tracing::Dispatch {
        tracing::Dispatch::new(TraceCaptureSubscriber {
            capture: self.clone(),
            next_span_id: AtomicU64::new(1),
        })
    }

    fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn append(&self, event: &[u8]) {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend_from_slice(event);
    }
}

fn assert_captured_host_admission_dispatch(traces: &[u8]) {
    let traces = String::from_utf8_lossy(traces);
    for marker in [
        BLOCKING_SPAN_ATTRIBUTE_MARKER,
        BLOCKING_SPAN_RECORD_MARKER,
        BLOCKING_EVENT_MARKER,
    ] {
        assert!(
            traces.contains(marker),
            "tracing sink did not observe blocking-thread marker {marker}"
        );
    }
}

struct TraceCaptureSubscriber {
    capture: TraceCapture,
    next_span_id: AtomicU64,
}

impl Subscriber for TraceCaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::TRACE)
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = Id::from_u64(self.next_span_id.fetch_add(1, Ordering::Relaxed));
        let mut rendered = format!(
            "SPAN {} {} {} ",
            attributes.metadata().level(),
            attributes.metadata().target(),
            attributes.metadata().name()
        );
        attributes.record(&mut TraceFieldVisitor(&mut rendered));
        rendered.push('\n');
        self.capture.append(rendered.as_bytes());
        id
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut rendered = format!("SPAN_RECORD {span:?} ");
        values.record(&mut TraceFieldVisitor(&mut rendered));
        rendered.push('\n');
        self.capture.append(rendered.as_bytes());
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let mut rendered = format!(
            "{} {} {} ",
            metadata.level(),
            metadata.target(),
            metadata.name()
        );
        event.record(&mut TraceFieldVisitor(&mut rendered));
        rendered.push('\n');
        self.capture.append(rendered.as_bytes());
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

struct TraceFieldVisitor<'a>(&'a mut String);

impl Visit for TraceFieldVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

fn bearer(token: &ApiBearerToken) -> String {
    let exposed = token.expose();
    format!("Bearer {}", exposed.as_str())
}

fn setup_mutation_request(
    client: &reqwest::Client,
    address: SocketAddr,
    token: &ApiBearerToken,
    host_identity: &str,
    path: &str,
    idempotency_key: &str,
) -> reqwest::RequestBuilder {
    client
        .post(format!("http://{address}{path}"))
        .header("Authorization", bearer(token))
        .header("Satelle-Expected-Host-Identity", host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .header("Idempotency-Key", idempotency_key)
        .header("Satelle-Protocol-Version", "4")
}

fn replacement_token(token_id: &str) -> ApiBearerToken {
    ApiBearerToken::parse(&format!("satelle_v1.{token_id}.{}", "A".repeat(43)))
        .expect("construct replacement token with a fixed test secret")
}

async fn request_status_over_established_tls(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    authorization: &str,
    host_identity: &str,
) {
    tokio::time::timeout(
        Duration::from_secs(2),
        request_status_over_established_tls_inner(stream, authorization, host_identity),
    )
    .await
    .expect("established TLS request and response must remain bounded");
}

async fn request_status_over_established_tls_inner(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    authorization: &str,
    host_identity: &str,
) {
    let request = format!(
        "GET /v1/host/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nSatelle-Expected-Host-Identity: {host_identity}\r\nSatelle-Request-Id: {}\r\nConnection: keep-alive\r\n\r\n",
        RequestId::new()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write Host status request on established TLS connection");
    stream
        .flush()
        .await
        .expect("flush Host status request on established TLS connection");

    let mut response = Vec::new();
    let header_end = loop {
        if let Some(offset) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
        assert!(
            response.len() < 16 * 1024,
            "HTTP response headers are bounded"
        );
        let mut chunk = [0_u8; 1024];
        let count = stream
            .read(&mut chunk)
            .await
            .expect("read Host status response headers");
        assert_ne!(count, 0, "established TLS connection closed unexpectedly");
        response.extend_from_slice(&chunk[..count]);
    };
    let headers = std::str::from_utf8(&response[..header_end])
        .expect("Host status response headers are UTF-8");
    assert!(
        headers.starts_with("HTTP/1.1 200 "),
        "response was {headers}"
    );
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .expect("Host status response includes Content-Length");
    let response_end = header_end + content_length;
    while response.len() < response_end {
        let mut chunk = [0_u8; 1024];
        let count = stream
            .read(&mut chunk)
            .await
            .expect("read Host status response body");
        assert_ne!(count, 0, "Host status response body was truncated");
        response.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(
        response.len(),
        response_end,
        "one request must consume exactly one response"
    );
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
async fn idle_server_waits_for_timeout_and_connected_clients() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let idle_timeout = Duration::from_millis(80);
    let server = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_idle_timeout(idle_timeout),
    )
    .await
    .expect("bind idle server");
    let address = server.local_addr();
    let mut waiting = Box::pin(server.wait());

    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut waiting)
            .await
            .is_err(),
        "server wait must remain pending before the idle timeout"
    );

    let client = TcpStream::connect(address)
        .await
        .expect("connect idle client");
    assert!(
        tokio::time::timeout(idle_timeout + Duration::from_millis(40), &mut waiting)
            .await
            .is_err(),
        "a connected client must prevent idle shutdown"
    );

    drop(client);
    tokio::time::timeout(idle_timeout + Duration::from_millis(150), waiting)
        .await
        .expect("server should exit after the client disconnects and timeout elapses")
        .expect("idle shutdown should be graceful");
}

#[tokio::test]
async fn retained_idle_session_does_not_prevent_idle_shutdown() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    service.initialize_daemon().expect("initialize Host state");
    let token = ApiBearerToken::generate().expect("generate API token");
    let principal = service
        .register_api_token(&token, "principal-idle-session", ApiScopes::CONTROL, None)
        .expect("register API principal");
    let intent = TurnIntent::new("finish before idle shutdown", TurnExecutionMode::Standard)
        .expect("construct Turn intent");
    let authority = MutationAuthority::new(principal, "idle-session-request")
        .expect("construct mutation authority");
    service.admit_run(&intent, &authority).expect("admit Turn");
    while !service
        .daemon_workers_idle()
        .expect("inspect daemon workers")
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let status = service
        .daemon_runtime_status()
        .expect("read retained Session status");
    assert_eq!(status.session_count(), 1);
    assert_eq!(status.active_turn_count(), 0);

    let server = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_idle_timeout(Duration::from_millis(50)),
    )
    .await
    .expect("bind idle server with retained Session");

    tokio::time::timeout(Duration::from_millis(250), server.wait())
        .await
        .expect("retained idle Session must not keep the daemon alive")
        .expect("idle shutdown should be graceful");
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

    let bodyless_json_response = reqwest::Client::new()
        .get(running.url("/v1/live"))
        .header("Content-Type", "application/json")
        .send()
        .await
        .expect("request liveness with a default JSON content type");
    assert_eq!(bodyless_json_response.status(), StatusCode::OK);

    let token = running.token.expose();
    let deeply_encoded_token = (0..32).fold(token.to_string(), |encoded, _| {
        encoded.replace('%', "%25").replace('.', "%2E")
    });
    let excessively_encoded_value =
        (0..32).fold("%41".to_string(), |encoded, _| encoded.replace('%', "%25"));
    for request in [
        reqwest::Client::new().get(running.url(&format!("/v1/live?token={}", token.as_str()))),
        reqwest::Client::new()
            .get(running.url("/v1/live"))
            .header("Cookie", format!("token={}", token.as_str())),
        reqwest::Client::new()
            .get(running.url("/v1/live"))
            .header("Content-Type", "application/json")
            .body(format!(r#"{{"token":"{}"}}"#, token.as_str())),
        reqwest::Client::new()
            .get(running.url("/v1/live"))
            .header("Content-Type", "text/plain")
            .body(format!("token={}", token.as_str())),
        reqwest::Client::new()
            .get(running.url("/v1/live"))
            .body(format!("token={}", token.as_str())),
        reqwest::Client::new().get(running.url(&format!("/v1/live?token={deeply_encoded_token}"))),
        reqwest::Client::new()
            .get(running.url(&format!("/v1/live?value={excessively_encoded_value}"))),
    ] {
        let response = request
            .send()
            .await
            .expect("request liveness with a disallowed token carrier");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: ApiError = response.json().await.expect("decode carrier rejection");
        assert_eq!(error.code().as_str(), "invalid-request");
        assert_eq!(error.host_identity(), None);
    }
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

    let malformed_body = reqwest::Client::new()
        .post(running.url("/v1/live"))
        .header("Satelle-Request-Id", request_id.to_string())
        .header("Content-Type", "application/json")
        .body("{")
        .send()
        .await
        .expect("request unsupported liveness method with malformed JSON");
    assert_eq!(malformed_body.status(), StatusCode::METHOD_NOT_ALLOWED);
    let error: ApiError = malformed_body
        .json()
        .await
        .expect("decode malformed-body method rejection");
    assert_eq!(error.code().as_str(), "method-not-allowed");
    assert_eq!(error.request_id(), &request_id);
}

#[tokio::test]
async fn liveness_rejects_bearer_token_in_headerless_http2_body() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("build HTTP/2 client");
    let token = running.token.expose();
    let body = format!("token={}", token.as_str()).into_bytes();
    let body = reqwest::Body::wrap_stream(futures_util::stream::once(async move {
        Ok::<_, std::io::Error>(body)
    }));
    let mut request = client
        .get(running.url("/v1/live"))
        .body(body)
        .build()
        .expect("build headerless HTTP/2 liveness request");
    request
        .headers_mut()
        .remove(reqwest::header::CONTENT_LENGTH);

    let response = client
        .execute(request)
        .await
        .expect("request liveness with an HTTP/2 body");

    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: ApiError = response.json().await.expect("decode carrier rejection");
    assert_eq!(error.code().as_str(), "invalid-request");
    assert_eq!(error.host_identity(), None);
}

#[tokio::test]
async fn liveness_stalled_http2_body_has_a_read_deadline() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("build HTTP/2 client");
    let stalled_body = reqwest::Body::wrap_stream(futures_util::stream::pending::<
        Result<Vec<u8>, std::io::Error>,
    >());

    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client
            .get(running.url("/v1/live"))
            .body(stalled_body)
            .send(),
    )
    .await
    .expect("public body read must have a deadline")
    .expect("receive typed liveness timeout");

    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    let error: ApiError = response.json().await.expect("decode body-read timeout");
    assert_eq!(error.code().as_str(), "invalid-request");
    assert_eq!(error.host_identity(), None);

    let live = client
        .get(running.url("/v1/live"))
        .send()
        .await
        .expect("request liveness after the stalled stream is released");
    assert_eq!(live.status(), StatusCode::OK);
}

#[tokio::test]
async fn host_identity_mismatch_does_not_reflect_bearer_token_carriers() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let token = running.token.expose();
    let canonical = token.as_str().to_string();
    let encoded = canonical.replace('.', "%2E");

    for expected_identity in [&canonical, &encoded] {
        let response = reqwest::Client::new()
            .get(running.url("/v1/host/status"))
            .header("Authorization", format!("Bearer {canonical}"))
            .header("Satelle-Expected-Host-Identity", expected_identity)
            .header("Satelle-Request-Id", RequestId::new().to_string())
            .send()
            .await
            .expect("request mismatched identity containing a bearer carrier");
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = response.bytes().await.expect("read mismatch response");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(&canonical));
        assert!(!text.contains(expected_identity));
        let error: ApiError = serde_json::from_slice(&bytes).expect("decode identity mismatch");
        assert_eq!(error.code().as_str(), "host-identity-mismatch");
        assert!(
            error
                .details()
                .and_then(|details| details.get("expected_host_identity"))
                .is_none()
        );
    }
}

#[tokio::test]
async fn protected_read_rejects_bearer_token_in_headerless_http2_body() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("build HTTP/2 client");
    let token = running.token.expose();
    let canonical = token.as_str().to_string();
    let body = format!(r#"{{"token":"{canonical}"}}"#).into_bytes();
    let body = reqwest::Body::wrap_stream(futures_util::stream::once(async move {
        Ok::<_, std::io::Error>(body)
    }));

    let response = client
        .get(running.url("/v1/host/status"))
        .header("Authorization", format!("Bearer {canonical}"))
        .header("Satelle-Expected-Host-Identity", &running.host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("request protected read with an HTTP/2 body");

    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response.bytes().await.expect("read body rejection");
    assert!(!String::from_utf8_lossy(&bytes).contains(&canonical));
    let error: ApiError = serde_json::from_slice(&bytes).expect("decode body rejection");
    assert_eq!(error.code().as_str(), "invalid-request");
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
async fn bearer_tokens_outside_authorization_are_rejected() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let exposed = running.token.expose();
    let token = exposed.as_str();
    let encoded_token = token.replace('.', "%2E");
    let double_encoded_token = token.replace('.', "%252E");
    let mut non_utf8_cookie = vec![0x80, b';', b' '];
    non_utf8_cookie.extend_from_slice(format!("api_token={token}").as_bytes());
    let requests = [
        running.request(&format!("/v1/logs?cursor={token}")),
        running.request(&format!("/v1/logs?cursor={encoded_token}")),
        running.request(&format!("/v1/logs?cursor={double_encoded_token}")),
        running.request(&format!("/v1/{token}")),
        running
            .request("/v1/host/status")
            .header("Cookie", format!("api_token={token}")),
        running
            .request("/v1/host/status")
            .header("X-Api-Token", token),
        running.request("/v1/host/status").header(
            "Cookie",
            reqwest::header::HeaderValue::from_bytes(&non_utf8_cookie)
                .expect("obs-text is a valid raw header value"),
        ),
        running
            .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66ec1")
            .json(&satelle_transport::TurnRequest::new(format!(
                "do not accept {token} from JSON"
            ))),
        running
            .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66ec2")
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"schema_version":"satelle.api.v2","prompt":"{token}","prompt":"safe","execution_mode":"standard"}}"#
            )),
    ];

    for request in requests {
        let response = request.send().await.expect("send disallowed token carrier");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: ApiError = response.json().await.expect("decode carrier rejection");
        assert_eq!(error.code().as_str(), "invalid-request");
    }
}

#[tokio::test]
async fn authenticated_identity_probe_returns_only_the_observed_host_identity() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let address = running.server.local_addr();
    let token = ApiBearerToken::parse(running.token.expose().as_str())
        .expect("copy the registered token for the client");
    let observed = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, token, "trust-probe-candidate")?.discover_host_identity()
    })
    .await
    .expect("join authenticated identity probe")
    .expect("discover authenticated Host Identity");

    assert_eq!(observed, running.host_identity);
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
    let capabilities_json: serde_json::Value =
        response.json().await.expect("decode capabilities JSON");
    assert_eq!(
        capabilities_json["schema_version"],
        "satelle.capabilities.v2"
    );
    let mut obsolete_v1 = capabilities_json.clone();
    obsolete_v1["schema_version"] = serde_json::json!("satelle.capabilities.v1");
    assert!(serde_json::from_value::<CapabilitiesResponse>(obsolete_v1).is_err());
    let capabilities: CapabilitiesResponse =
        serde_json::from_value(capabilities_json).expect("decode typed capabilities");
    assert_eq!(capabilities.host_identity(), running.host_identity);
    assert_eq!(capabilities.operations(), EXPECTED_OPERATIONS);
    assert_eq!(capabilities.limits().json_body_bytes(), 1_048_576);
    assert_eq!(capabilities.limits().http_connections(), 128);
    assert_eq!(capabilities.limits().operation_concurrency(), 1);
    assert_eq!(capabilities.limits().attachment_count(), 0);
    assert_eq!(capabilities.limits().attachment_bytes_each(), 0);
    assert_eq!(capabilities.limits().attachment_bytes_total(), 0);
    assert_eq!(capabilities.limits().failed_auth_attempts_per_minute(), 10);
    assert_eq!(
        capabilities.limits().authenticated_requests_per_minute(),
        600
    );
    assert_eq!(capabilities.limits().control_requests_per_minute(), 120);
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
async fn custom_api_rate_limits_are_advertised_and_enforced() {
    let limit = |value| NonZeroUsize::new(value).expect("test rate limit is nonzero");
    let advertised = ApiRateLimits::new(limit(2), limit(3), limit(4), limit(5));
    let running = RunningServer::start_with_config(
        ApiScopes::ADMIN,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_api_rate_limits(advertised),
    )
    .await;
    let capabilities = running
        .request("/v1/capabilities")
        .send()
        .await
        .expect("request custom capabilities")
        .json::<CapabilitiesResponse>()
        .await
        .expect("decode custom capabilities");
    assert_eq!(capabilities.limits().failed_auth_attempts_per_minute(), 2);
    assert_eq!(capabilities.limits().authenticated_requests_per_minute(), 3);
    assert_eq!(capabilities.limits().control_requests_per_minute(), 4);
    assert_eq!(
        capabilities
            .limits()
            .websocket_inbound_messages_per_minute(),
        5
    );

    for attempt in 1..=3 {
        let response = running
            .request("/v1/host/status")
            .send()
            .await
            .expect("request custom authenticated limit");
        if attempt <= 2 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_rate_limited(response, Some(&running.host_identity)).await;
        }
    }

    let failed_auth = RunningServer::start_with_config(
        ApiScopes::READ,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_api_rate_limits(advertised),
    )
    .await;
    let client = reqwest::Client::new();
    for attempt in 1..=3 {
        let response = client
            .get(failed_auth.url("/v1/host/status"))
            .header("Satelle-Request-Id", RequestId::new().to_string())
            .send()
            .await
            .expect("request custom failed-authentication limit");
        if attempt <= 2 {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        } else {
            assert_rate_limited(response, None).await;
        }
    }

    let control_limits = ApiRateLimits::new(limit(10), limit(10), limit(2), limit(10));
    let control = RunningServer::start_with_config(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_api_rate_limits(control_limits),
    )
    .await;
    for attempt in 1..=3 {
        let response = control
            .mutation("/v1/sessions", "custom-control-rate-limit")
            .send()
            .await
            .expect("request custom control limit");
        if attempt <= 2 {
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        } else {
            assert_rate_limited(response, Some(&control.host_identity)).await;
        }
    }
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
async fn ssh_bootstrap_authentication_rejects_non_loopback_tls_before_listening() {
    let token = ApiBearerToken::generate().expect("generate bootstrap token");
    let host_config = SatelleConfig::defaults()
        .hosts
        .remove(satelle_core::LOCAL_DEMO_HOST)
        .expect("built-in Host config exists");
    let service = HostService::production_for_ssh_bootstrap(
        &token,
        ApiScopes::READ,
        time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        &host_config,
    );
    let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate direct transport certificate");
    let tls = DaemonTlsConfig::from_pem(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
    )
    .expect("build validated TLS configuration");

    let error = DaemonServer::bind_tls(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        tls,
    )
    .await
    .expect_err("bootstrap authentication must never reach a non-loopback listener");

    assert_eq!(error.code(), "ssh-bootstrap-non-loopback-bind");
}

#[tokio::test]
async fn setup_token_mutations_reject_bodies_before_changing_token_state() {
    let state = TestStateDir::new().expect("temporary state directory");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        );
    let host_identity = service
        .initialize_daemon()
        .expect("initialize Host state")
        .host_identity()
        .to_string();
    let server = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind bootstrap server");
    let address = server.local_addr();
    let client = reqwest::Client::new();

    let invalid_issue = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        "/v1/setup/api-token",
        "bodyless-issue",
    )
    .header("Content-Type", "text/plain")
    .body("unsupported payload")
    .send()
    .await
    .expect("issue with an unsupported body");
    assert_eq!(invalid_issue.status(), StatusCode::BAD_REQUEST);

    // Reusing the key must still produce the one-time secret. If the rejected
    // request had issued a token, this replay would omit it.
    let issue = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        "/v1/setup/api-token",
        "bodyless-issue",
    )
    .send()
    .await
    .expect("issue without a body");
    assert_eq!(issue.status(), StatusCode::CREATED);
    let issuance: DurableTokenIssuanceResponse =
        issue.json().await.expect("decode setup token issuance");
    let activate_token_id = issuance.token_id().to_string();
    assert!(issuance.into_bearer_token().is_some());

    let oversized_activate = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        &format!("/v1/setup/api-token/{activate_token_id}/activate"),
        "bodyless-activate",
    )
    .body(vec![b'x'; 1_048_577])
    .send()
    .await
    .expect("activate with an oversized body");
    assert_eq!(oversized_activate.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let activate = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        &format!("/v1/setup/api-token/{activate_token_id}/activate"),
        "bodyless-activate",
    )
    .send()
    .await
    .expect("activate without a body after rejection");
    assert_eq!(activate.status(), StatusCode::OK);
    let activated: DurableTokenActivationResponse =
        activate.json().await.expect("decode activation response");
    assert!(activated.active());

    let abort_candidate = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        "/v1/setup/api-token",
        "bodyless-abort-candidate",
    )
    .send()
    .await
    .expect("issue token for abort rejection");
    assert_eq!(abort_candidate.status(), StatusCode::CREATED);
    let abort_candidate: DurableTokenIssuanceResponse = abort_candidate
        .json()
        .await
        .expect("decode abort candidate issuance");
    let abort_token_id = abort_candidate.token_id().to_string();

    let exposed = bootstrap_token.expose();
    let invalid_abort = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        &format!("/v1/setup/api-token/{abort_token_id}/abort"),
        "bodyless-abort",
    )
    .body(format!("token={}", exposed.as_str()))
    .send()
    .await
    .expect("abort with a bearer token body");
    assert_eq!(invalid_abort.status(), StatusCode::BAD_REQUEST);
    let rejection = invalid_abort
        .bytes()
        .await
        .expect("read bearer carrier rejection");
    assert!(!String::from_utf8_lossy(&rejection).contains(exposed.as_str()));

    // Activation proves the rejected abort left the pending token intact.
    let activate_after_abort_rejection = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        &format!("/v1/setup/api-token/{abort_token_id}/activate"),
        "activate-after-bodyless-abort",
    )
    .send()
    .await
    .expect("activate after rejected abort");
    assert_eq!(activate_after_abort_rejection.status(), StatusCode::OK);

    let second_abort_candidate = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        "/v1/setup/api-token",
        "bodyless-abort-retry-candidate",
    )
    .send()
    .await
    .expect("issue a second abort candidate");
    assert_eq!(second_abort_candidate.status(), StatusCode::CREATED);
    let second_abort_candidate: DurableTokenIssuanceResponse = second_abort_candidate
        .json()
        .await
        .expect("decode second abort candidate issuance");
    let second_abort_token_id = second_abort_candidate.token_id().to_string();
    let abort_after_rejection = setup_mutation_request(
        &client,
        address,
        &bootstrap_token,
        &host_identity,
        &format!("/v1/setup/api-token/{second_abort_token_id}/abort"),
        "bodyless-abort",
    )
    .send()
    .await
    .expect("reuse the idempotency key after rejected abort");
    assert_eq!(abort_after_rejection.status(), StatusCode::OK);
    let aborted: DurableTokenActivationResponse = abort_after_rejection
        .json()
        .await
        .expect("decode successful abort after rejection");
    assert!(!aborted.active());
    assert_eq!(aborted.token_id(), second_abort_token_id);

    server.shutdown().await.expect("stop bootstrap server");
}

#[tokio::test]
async fn ssh_bootstrap_issues_and_activates_one_durable_restart_credential() {
    let state = TestStateDir::new().expect("temporary state directory");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        );
    let ordinary_control_token = ApiBearerToken::generate().expect("generate ordinary token");
    service
        .register_api_token(
            &ordinary_control_token,
            "ordinary-control",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register ordinary control token");
    let host_identity = service
        .initialize_daemon()
        .expect("initialize Host state")
        .host_identity()
        .to_string();
    let server = DaemonServer::bind(
        service.clone(),
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind bootstrap server");
    let first_address = server.local_addr();
    let first_identity = host_identity.clone();
    let restart_durable_token = tokio::task::spawn_blocking(move || {
        let bootstrap_client =
            DaemonClient::loopback(first_address, bootstrap_token, first_identity.clone())
                .expect("construct bootstrap client");
        let aborted_issuance = bootstrap_client
            .issue_durable_setup_token("issue-aborted-setup-token")
            .expect("issue token to abort");
        let aborted_token_id = aborted_issuance.token_id().to_string();
        let aborted_raw_token = aborted_issuance
            .into_bearer_token()
            .expect("first aborted issuance carries the secret");
        let aborted_token =
            ApiBearerToken::parse(aborted_raw_token.as_str()).expect("parse token to abort");
        let aborted = bootstrap_client
            .abort_durable_setup_token(&aborted_token_id, "abort-setup-token")
            .expect("abort setup token");
        assert!(!aborted.active());
        assert_eq!(aborted.token_id(), aborted_token_id);
        let replayed_abort = bootstrap_client
            .abort_durable_setup_token(&aborted_token_id, "abort-setup-token")
            .expect("same-key abort replay returns the committed response");
        assert!(!replayed_abort.active());
        assert_eq!(replayed_abort.token_id(), aborted_token_id);

        let conflicting_abort = bootstrap_client
            .issue_durable_setup_token("issue-conflicting-abort-token")
            .expect("issue another token for abort key binding");
        let conflicting_abort_token_id = conflicting_abort.token_id().to_string();
        let abort_key_error = bootstrap_client
            .abort_durable_setup_token(&conflicting_abort_token_id, "abort-setup-token")
            .expect_err("an abort key cannot be reused for another token");
        assert!(matches!(
            abort_key_error,
            DaemonClientError::Api { status, error }
                if status == StatusCode::CONFLICT
                    && error.code() == ApiErrorCode::IdempotencyKeyConflict
        ));
        bootstrap_client
            .abort_durable_setup_token(
                &conflicting_abort_token_id,
                "abort-conflicting-token-cleanup",
            )
            .expect("abort the second pending token with its own key");
        bootstrap_client
            .activate_durable_setup_token(&aborted_token_id, "activate-aborted-setup-token")
            .expect_err("aborted setup token must not be activatable");
        let aborted_client =
            DaemonClient::loopback(first_address, aborted_token, first_identity.clone())
                .expect("construct aborted client");
        assert!(aborted_client.capabilities().is_err());

        let issued_after = time::OffsetDateTime::now_utc();
        let issuance = bootstrap_client
            .issue_durable_setup_token("issue-durable-setup-token")
            .expect("issue pending durable token");
        let pending_expires_at = time::OffsetDateTime::parse(
            issuance.pending_expires_at(),
            &time::format_description::well_known::Rfc3339,
        )
        .expect("pending expiry is RFC3339 UTC");
        assert!(pending_expires_at > issued_after);
        assert!(
            pending_expires_at <= issued_after + DURABLE_SETUP_PENDING_TTL + time::Duration::SECOND
        );
        let token_id = issuance.token_id().to_string();
        let replayed_issuance = bootstrap_client
            .issue_durable_setup_token("issue-durable-setup-token")
            .expect("replay issuance with the same idempotency key");
        assert_eq!(replayed_issuance.token_id(), token_id);
        assert_eq!(
            replayed_issuance.pending_expires_at(),
            issuance.pending_expires_at()
        );
        assert!(
            replayed_issuance.into_bearer_token().is_none(),
            "an idempotent replay must never re-expose the one-time secret"
        );
        let raw_token = issuance
            .into_bearer_token()
            .expect("first durable issuance carries the secret");
        let pending_token =
            ApiBearerToken::parse(raw_token.as_str()).expect("parse pending durable token");
        let first_durable_token =
            ApiBearerToken::parse(raw_token.as_str()).expect("parse issued durable token");
        let restart_durable_token =
            ApiBearerToken::parse(raw_token.as_str()).expect("parse restart durable token");
        let pending_client =
            DaemonClient::loopback(first_address, pending_token, first_identity.clone())
                .expect("construct pending client");
        let pending_error = pending_client
            .capabilities()
            .expect_err("pending token must not authenticate");
        assert!(matches!(
            pending_error,
            DaemonClientError::Api {
                status: StatusCode::UNAUTHORIZED,
                ..
            }
        ));
        let activated = bootstrap_client
            .activate_durable_setup_token(&token_id, "activate-durable-setup-token")
            .expect("activate durable token");
        assert!(activated.active());
        assert_eq!(activated.token_id(), token_id);
        let replayed_activation = bootstrap_client
            .activate_durable_setup_token(&token_id, "activate-durable-setup-token")
            .expect("same-key activation replay returns the committed response");
        assert!(replayed_activation.active());
        assert_eq!(replayed_activation.token_id(), token_id);

        let conflicting_activation = bootstrap_client
            .issue_durable_setup_token("issue-conflicting-activation-token")
            .expect("issue another token for activation key binding");
        let conflicting_activation_token_id = conflicting_activation.token_id().to_string();
        let activation_key_error = bootstrap_client
            .activate_durable_setup_token(
                &conflicting_activation_token_id,
                "activate-durable-setup-token",
            )
            .expect_err("an activation key cannot be reused for another token");
        assert!(matches!(
            activation_key_error,
            DaemonClientError::Api { status, error }
                if status == StatusCode::CONFLICT
                    && error.code() == ApiErrorCode::IdempotencyKeyConflict
        ));
        bootstrap_client
            .abort_durable_setup_token(
                &conflicting_activation_token_id,
                "abort-conflicting-activation-token",
            )
            .expect("abort the second pending token after the conflict");

        let durable_client =
            DaemonClient::loopback(first_address, first_durable_token, first_identity.clone())
                .expect("construct durable client");
        durable_client
            .capabilities()
            .expect("activated token authenticates");
        let confirmation = durable_client
            .confirm_durable_setup_token()
            .expect("Host confirms setup provenance and exact scope");
        assert_eq!(confirmation.token_id(), token_id);
        assert!(confirmation.setup_active());
        assert!(confirmation.control_scoped());
        let ordinary_client = DaemonClient::loopback(
            first_address,
            ordinary_control_token,
            first_identity.clone(),
        )
        .expect("construct ordinary control client");
        let ordinary_error = ordinary_client
            .confirm_durable_setup_token()
            .expect_err("ordinary control token is not setup-issued");
        assert!(matches!(
            ordinary_error,
            DaemonClientError::Api {
                status: StatusCode::FORBIDDEN,
                ..
            }
        ));
        let error = durable_client
            .issue_durable_setup_token("durable-principal-setup-attempt")
            .expect_err("durable principal cannot mint another setup token");
        assert!(matches!(
            error,
            DaemonClientError::Api {
                status: StatusCode::FORBIDDEN,
                ..
            }
        ));
        restart_durable_token
    })
    .await
    .expect("join bootstrap client operations");
    server.shutdown().await.expect("stop bootstrap server");
    drop(service);

    let restarted_service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct restarted Host service");
    let restarted_server = DaemonServer::bind(
        restarted_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind restarted server");
    let restarted_address = restarted_server.local_addr();
    tokio::task::spawn_blocking(move || {
        let restart_token_id = restart_durable_token.token_id().to_string();
        let restarted_client =
            DaemonClient::loopback(restarted_address, restart_durable_token, host_identity)
                .expect("construct restarted durable client");
        restarted_client
            .capabilities()
            .expect("durable token authenticates after restart");
        let confirmation = restarted_client
            .confirm_durable_setup_token()
            .expect("setup provenance survives Host restart");
        assert_eq!(confirmation.token_id(), restart_token_id);
    })
    .await
    .expect("join restarted client operation");
    restarted_server
        .shutdown()
        .await
        .expect("stop restarted server");
}

#[tokio::test]
async fn authenticated_https_is_served_by_a_non_loopback_tls_listener() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let host_identity = initialized.host_identity().to_string();
    let token = ApiBearerToken::generate().expect("generate API token");
    service
        .register_api_token(&token, "principal-https-test", ApiScopes::READ, None)
        .expect("register API token");
    let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate direct transport certificate");
    let tls = DaemonTlsConfig::from_pem(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
    )
    .expect("build validated TLS configuration");
    let server = DaemonServer::bind_tls(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
        tls,
    )
    .await
    .expect("bind non-loopback TLS daemon");
    let certificate = reqwest::Certificate::from_pem(certified.cert.pem().as_bytes())
        .expect("parse test trust root");
    let client = reqwest::Client::builder()
        .tls_certs_only([certificate])
        .build()
        .expect("build HTTPS client");
    let exposed = token.expose();
    let response = client
        .get(format!(
            "https://localhost:{}/v1/host/status",
            server.local_addr().port()
        ))
        .header("Authorization", format!("Bearer {}", exposed.as_str()))
        .header("Satelle-Expected-Host-Identity", &host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .send()
        .await
        .expect("request authenticated Host status over TLS");

    assert_eq!(response.status(), StatusCode::OK);

    let mut host_config = SatelleConfig::defaults()
        .hosts
        .remove("local-demo")
        .expect("default local Host config");
    host_config.transport = TransportKind::Direct;
    host_config.address = Some(format!("https://localhost:{}", server.local_addr().port()));
    host_config.expected_host_id = Some(host_identity);
    host_config.api_token = Some(ApiTokenSource::File {
        path: std::env::temp_dir().join("satelle-https-server-test.token"),
    });
    let binding =
        DirectHostBinding::from_host_config(&host_config).expect("construct direct Host Binding");
    let event_token = ApiBearerToken::parse(exposed.as_str()).expect("copy API token for WSS");
    let event_client =
        DaemonEventClient::wss(&binding, event_token, Some(certified.cert.pem().as_bytes()))
            .expect("construct WSS client");
    let event_stream = event_client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("connect authenticated WSS event stream");
    drop(event_stream);
    server.shutdown().await.expect("stop TLS daemon");
}

#[tokio::test]
async fn tls_reload_replaces_only_fully_validated_configuration() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let host_identity = service
        .initialize_daemon()
        .expect("initialize Host state")
        .host_identity()
        .to_string();
    let token = ApiBearerToken::generate().expect("generate API token");
    service
        .register_api_token(&token, "principal-tls-reload", ApiScopes::READ, None)
        .expect("register API token");
    let initial = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate initial certificate");
    let replacement = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate replacement certificate");
    let tls = DaemonTlsConfig::from_pem(
        initial.cert.pem().as_bytes(),
        initial.signing_key.serialize_pem().as_bytes(),
    )
    .expect("validate initial TLS configuration");
    let server = DaemonServer::bind_tls(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        tls,
    )
    .await
    .expect("bind reloadable TLS daemon");
    let url = format!(
        "https://localhost:{}/v1/host/status",
        server.local_addr().port()
    );
    let authorization = format!("Bearer {}", token.expose().as_str());
    let mut initial_roots = RootCertStore::empty();
    initial_roots
        .add(initial.cert.der().clone())
        .expect("trust initial certificate");
    let initial_tls = rustls::ClientConfig::builder()
        .with_root_certificates(initial_roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(initial_tls));
    let socket = TcpStream::connect(server.local_addr())
        .await
        .expect("connect initial TLS socket");
    let mut established = connector
        .connect(
            ServerName::try_from("localhost").expect("valid test server name"),
            socket,
        )
        .await
        .expect("establish initial TLS connection");
    request_status_over_established_tls(&mut established, &authorization, &host_identity).await;

    assert_eq!(
        server
            .reload_tls_from_pem(
                replacement.cert.pem().as_bytes(),
                initial.signing_key.serialize_pem().as_bytes(),
            )
            .expect_err("a mismatched replacement must fail"),
        DaemonTlsReloadError::InvalidConfiguration(DaemonTlsConfigError::CertificateKeyMismatch)
    );
    let retained_client = reqwest::Client::builder()
        .tls_certs_only([
            reqwest::Certificate::from_pem(initial.cert.pem().as_bytes())
                .expect("parse retained trust root"),
        ])
        .build()
        .expect("build retained HTTPS client");
    let retained_response = retained_client
        .get(&url)
        .header("Authorization", &authorization)
        .header("Satelle-Expected-Host-Identity", &host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .send()
        .await
        .expect("request after rejected TLS reload");
    assert_eq!(retained_response.status(), StatusCode::OK);
    request_status_over_established_tls(&mut established, &authorization, &host_identity).await;

    server
        .reload_tls_from_pem(
            replacement.cert.pem().as_bytes(),
            replacement.signing_key.serialize_pem().as_bytes(),
        )
        .expect("install replacement TLS configuration");
    request_status_over_established_tls(&mut established, &authorization, &host_identity).await;
    let replacement_client = reqwest::Client::builder()
        .tls_certs_only([
            reqwest::Certificate::from_pem(replacement.cert.pem().as_bytes())
                .expect("parse replacement trust root"),
        ])
        .build()
        .expect("build replacement HTTPS client");
    let replacement_response = replacement_client
        .get(&url)
        .header("Authorization", authorization)
        .header("Satelle-Expected-Host-Identity", host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .send()
        .await
        .expect("request with replacement certificate");
    assert_eq!(replacement_response.status(), StatusCode::OK);

    server.shutdown().await.expect("stop TLS daemon");
}

#[tokio::test]
async fn tls_reload_on_plaintext_server_fails_before_pem_validation() {
    let running = RunningServer::start(ApiScopes::READ).await;

    assert_eq!(
        running
            .server
            .reload_tls_from_pem(b"invalid certificate", b"invalid private key")
            .expect_err("a plaintext listener cannot reload TLS"),
        DaemonTlsReloadError::TlsNotConfigured
    );

    running
        .server
        .shutdown()
        .await
        .expect("stop plaintext daemon");
}

#[tokio::test]
async fn an_idle_tls_handshake_does_not_block_other_clients() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let host_identity = service
        .initialize_daemon()
        .expect("initialize Host state")
        .host_identity()
        .to_string();
    let token = ApiBearerToken::generate().expect("generate API token");
    service
        .register_api_token(&token, "principal-concurrent-tls", ApiScopes::READ, None)
        .expect("register API token");
    let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate direct transport certificate");
    let tls = DaemonTlsConfig::from_pem(
        certified.cert.pem().as_bytes(),
        certified.signing_key.serialize_pem().as_bytes(),
    )
    .expect("build validated TLS configuration");
    let server = DaemonServer::bind_tls(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        tls,
    )
    .await
    .expect("bind TLS daemon");
    let _idle_handshake = TcpStream::connect(server.local_addr())
        .await
        .expect("open idle pre-handshake socket");
    let certificate = reqwest::Certificate::from_pem(certified.cert.pem().as_bytes())
        .expect("parse test trust root");
    let client = reqwest::Client::builder()
        .tls_certs_only([certificate])
        .build()
        .expect("build HTTPS client");
    let exposed = token.expose();
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        client
            .get(format!(
                "https://localhost:{}/v1/host/status",
                server.local_addr().port()
            ))
            .header("Authorization", format!("Bearer {}", exposed.as_str()))
            .header("Satelle-Expected-Host-Identity", host_identity)
            .header("Satelle-Request-Id", RequestId::new().to_string())
            .send(),
    )
    .await
    .expect("idle TLS peer must not block a later client")
    .expect("request authenticated Host status over TLS");

    assert_eq!(response.status(), StatusCode::OK);
    server.shutdown().await.expect("stop TLS daemon");
}

#[test]
fn tls_configuration_rejects_expired_certificates_and_mismatched_keys() {
    let mut expired_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("certificate params");
    expired_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    expired_params.not_after = rcgen::date_time_ymd(2020, 1, 2);
    let expired_key = rcgen::KeyPair::generate().expect("generate expired certificate key");
    let expired = expired_params
        .self_signed(&expired_key)
        .expect("generate expired certificate");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            expired.pem().as_bytes(),
            expired_key.serialize_pem().as_bytes()
        )
        .expect_err("expired certificate must fail before bind"),
        DaemonTlsConfigError::CertificateExpired
    );

    let mut expired_issuer_params =
        rcgen::CertificateParams::new(Vec::new()).expect("issuer certificate params");
    expired_issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    expired_issuer_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    expired_issuer_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    expired_issuer_params.not_after = rcgen::date_time_ymd(2020, 1, 2);
    let expired_issuer_key = rcgen::KeyPair::generate().expect("generate expired issuer key");
    let expired_issuer = expired_issuer_params
        .self_signed(&expired_issuer_key)
        .expect("generate expired issuer certificate");
    let issuer = rcgen::Issuer::new(expired_issuer_params, expired_issuer_key);
    let leaf_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("leaf params");
    let leaf_key = rcgen::KeyPair::generate().expect("generate valid leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("generate valid leaf certificate");
    let chain = format!("{}{}", leaf.pem(), expired_issuer.pem());
    assert_eq!(
        DaemonTlsConfig::from_pem(chain.as_bytes(), leaf_key.serialize_pem().as_bytes())
            .expect_err("expired intermediate must fail before bind"),
        DaemonTlsConfigError::CertificateExpired
    );

    let mut signer_params =
        rcgen::CertificateParams::new(Vec::new()).expect("signer certificate params");
    signer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    signer_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let signer_key = rcgen::KeyPair::generate().expect("generate signer key");
    let signer = rcgen::Issuer::new(signer_params, signer_key);
    let leaf_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("leaf params");
    let leaf_key = rcgen::KeyPair::generate().expect("generate leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &signer)
        .expect("generate signed leaf certificate");
    let mut unrelated_params =
        rcgen::CertificateParams::new(Vec::new()).expect("unrelated issuer params");
    unrelated_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    unrelated_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let unrelated_key = rcgen::KeyPair::generate().expect("generate unrelated issuer key");
    let unrelated = unrelated_params
        .self_signed(&unrelated_key)
        .expect("generate unrelated issuer certificate");
    let chain = format!("{}{}", leaf.pem(), unrelated.pem());
    assert_eq!(
        DaemonTlsConfig::from_pem(chain.as_bytes(), leaf_key.serialize_pem().as_bytes())
            .expect_err("unrelated intermediate must fail before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let mut root_params =
        rcgen::CertificateParams::new(Vec::new()).expect("constrained root params");
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    root_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "constrained root");
    root_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let root_key = rcgen::KeyPair::generate().expect("generate constrained root key");
    let root = root_params
        .self_signed(&root_key)
        .expect("generate constrained root certificate");
    let root_issuer = rcgen::Issuer::new(root_params, root_key);
    let mut intermediate_params =
        rcgen::CertificateParams::new(Vec::new()).expect("intermediate params");
    intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    intermediate_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "subordinate intermediate");
    intermediate_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let intermediate_key = rcgen::KeyPair::generate().expect("generate intermediate key");
    let intermediate = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .expect("generate intermediate certificate");
    let intermediate_issuer = rcgen::Issuer::new(intermediate_params, intermediate_key);
    let leaf_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("leaf params");
    let leaf_key = rcgen::KeyPair::generate().expect("generate path-length leaf key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &intermediate_issuer)
        .expect("generate path-length leaf certificate");
    let chain = format!("{}{}{}", leaf.pem(), intermediate.pem(), root.pem());
    assert_eq!(
        DaemonTlsConfig::from_pem(chain.as_bytes(), leaf_key.serialize_pem().as_bytes())
            .expect_err("exceeded path-length constraint must fail before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let mut constrained_issuer_params =
        rcgen::CertificateParams::new(Vec::new()).expect("name-constrained issuer params");
    constrained_issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    constrained_issuer_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    constrained_issuer_params.name_constraints = Some(rcgen::NameConstraints {
        permitted_subtrees: vec![rcgen::GeneralSubtree::DnsName("example.com".to_string())],
        excluded_subtrees: Vec::new(),
    });
    let constrained_issuer_key =
        rcgen::KeyPair::generate().expect("generate name-constrained issuer key");
    let constrained_issuer_certificate = constrained_issuer_params
        .self_signed(&constrained_issuer_key)
        .expect("generate name-constrained issuer certificate");
    let constrained_issuer = rcgen::Issuer::new(constrained_issuer_params, constrained_issuer_key);
    let constrained_leaf_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("constrained leaf params");
    let constrained_leaf_key = rcgen::KeyPair::generate().expect("generate constrained leaf key");
    let constrained_leaf = constrained_leaf_params
        .signed_by(&constrained_leaf_key, &constrained_issuer)
        .expect("generate constrained leaf certificate");
    let constrained_chain = format!(
        "{}{}",
        constrained_leaf.pem(),
        constrained_issuer_certificate.pem()
    );
    assert_eq!(
        DaemonTlsConfig::from_pem(
            constrained_chain.as_bytes(),
            constrained_leaf_key.serialize_pem().as_bytes()
        )
        .expect_err("name-constrained chain must fail closed before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let nameless_params = rcgen::CertificateParams::new(Vec::new()).expect("nameless leaf params");
    let nameless_key = rcgen::KeyPair::generate().expect("generate nameless leaf key");
    let nameless_leaf = nameless_params
        .self_signed(&nameless_key)
        .expect("generate leaf without subject alternative names");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            nameless_leaf.pem().as_bytes(),
            nameless_key.serialize_pem().as_bytes()
        )
        .expect_err("leaf without a DNS or IP subject alternative name must fail before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let mut unsupported_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("unsupported leaf params");
    let mut unsupported_extension =
        rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 55_555, 1], vec![0x05, 0x00]);
    unsupported_extension.set_criticality(true);
    unsupported_params
        .custom_extensions
        .push(unsupported_extension);
    let unsupported_key = rcgen::KeyPair::generate().expect("generate unsupported leaf key");
    let unsupported_leaf = unsupported_params
        .self_signed(&unsupported_key)
        .expect("generate leaf with an unsupported critical extension");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            unsupported_leaf.pem().as_bytes(),
            unsupported_key.serialize_pem().as_bytes()
        )
        .expect_err("unsupported critical certificate extension must fail before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let mut ca_leaf_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("CA leaf params");
    ca_leaf_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_leaf_params.key_usages.extend([
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ]);
    let ca_leaf_key = rcgen::KeyPair::generate().expect("generate CA leaf key");
    let ca_leaf = ca_leaf_params
        .self_signed(&ca_leaf_key)
        .expect("generate CA leaf certificate");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            ca_leaf.pem().as_bytes(),
            ca_leaf_key.serialize_pem().as_bytes()
        )
        .expect_err("CA certificate must not be accepted as the server leaf"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let mut client_only_params =
        rcgen::CertificateParams::new(["localhost".to_string()]).expect("client-only leaf params");
    client_only_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    let client_only_key = rcgen::KeyPair::generate().expect("generate client-only key");
    let client_only = client_only_params
        .self_signed(&client_only_key)
        .expect("generate client-only certificate");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            client_only.pem().as_bytes(),
            client_only_key.serialize_pem().as_bytes()
        )
        .expect_err("client-only certificate must fail before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let mut signing_only_params = rcgen::CertificateParams::new(["localhost".to_string()])
        .expect("certificate-signing-only leaf params");
    signing_only_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let signing_only_key = rcgen::KeyPair::generate().expect("generate signing-only key");
    let signing_only = signing_only_params
        .self_signed(&signing_only_key)
        .expect("generate certificate-signing-only leaf");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            signing_only.pem().as_bytes(),
            signing_only_key.serialize_pem().as_bytes()
        )
        .expect_err("certificate-signing-only leaf must fail before bind"),
        DaemonTlsConfigError::InvalidCertificateChain
    );

    let certificate = rcgen::generate_simple_self_signed(["localhost".to_string()])
        .expect("generate certificate");
    let unrelated_key = rcgen::KeyPair::generate().expect("generate unrelated key");
    assert_eq!(
        DaemonTlsConfig::from_pem(
            certificate.cert.pem().as_bytes(),
            unrelated_key.serialize_pem().as_bytes()
        )
        .expect_err("certificate and key mismatch must fail before bind"),
        DaemonTlsConfigError::CertificateKeyMismatch
    );
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
async fn shutdown_handle_releases_the_store_for_the_next_daemon() {
    let state = TestStateDir::new().expect("temporary state directory");
    let first_service =
        HostService::local_demo_for_tests_at(state.path()).expect("construct first Host service");
    let first_server = DaemonServer::bind(
        first_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind first daemon");

    first_server.shutdown_handle().request_shutdown();
    first_server
        .wait()
        .await
        .expect("graceful shutdown releases the store");

    let second_service =
        HostService::local_demo_for_tests_at(state.path()).expect("construct second Host service");
    let second_server = DaemonServer::bind(
        second_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("the next daemon acquires the released store");
    second_server.shutdown().await.expect("stop second daemon");
}

#[tokio::test]
async fn shutdown_handle_bounds_a_stalled_connection_and_releases_the_store() {
    let state = TestStateDir::new().expect("temporary state directory");
    let state_path = state.path().to_path_buf();
    let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
    let (cancel_setup, setup_cancelled) = tokio::sync::oneshot::channel();
    let (cancel_watchdog, watchdog_cancelled) = std::sync::mpsc::sync_channel(1);
    // Keep the causal readiness handoff free of the 50 ms product contract.
    // This watchdog only cancels a wedged test setup so a broken fixture fails
    // instead of hanging the suite forever.
    let setup_watchdog = std::thread::spawn(move || {
        if matches!(
            watchdog_cancelled.recv_timeout(TEST_INFRASTRUCTURE_DEADLOCK_LIMIT),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            let _ = cancel_setup.send(());
        }
    });
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build owner runtime");
        let service = HostService::local_demo_for_tests_at(&state_path)
            .expect("construct first Host service");
        let server = runtime.block_on(async {
            tokio::select! {
                server = DaemonServer::bind(
                service,
                DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .with_shutdown_grace(Duration::from_millis(50)),
                ) => server.map(Some),
                _ = setup_cancelled => Ok(None),
            }
        });
        let Some(server) = server.expect("bind first daemon") else {
            return;
        };
        if ready_sender
            .send((server.local_addr(), server.shutdown_handle()))
            .is_err()
        {
            return;
        }
        let error = runtime
            .block_on(server.wait())
            .expect_err("stalled connection exceeds the shutdown grace");
        assert_eq!(error.code(), "shutdown-timeout");
        // The CLI daemon owns one runtime for its process. Dropping that runtime
        // contains any connection tasks Axum retained after bounded shutdown.
        drop(runtime);
    });
    // Startup is not part of the shutdown deadline under test. Wait for the
    // owner handoff so slow scheduling cannot strand its runtime and store;
    // setup failures still disconnect the channel and fail this receive.
    let readiness = ready_receiver.await;
    let _ = cancel_watchdog.send(());
    setup_watchdog
        .join()
        .expect("test infrastructure watchdog exits");
    let (first_addr, shutdown) = match readiness {
        Ok(readiness) => readiness,
        Err(_) => {
            owner
                .join()
                .expect("daemon owner exits after setup cancellation");
            panic!(
                "daemon setup failed or exceeded the test infrastructure deadlock limit before the 50 ms shutdown contract started"
            );
        }
    };
    let mut stalled = TcpStream::connect(first_addr)
        .await
        .expect("open stalled connection");
    stalled
        .write_all(b"GET /v1/live HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .expect("write incomplete request");
    tokio::time::sleep(Duration::from_millis(100)).await;

    shutdown.request_shutdown();
    tokio::task::spawn_blocking(move || owner.join())
        .await
        .expect("join owner task")
        .expect("owner thread exits after bounded shutdown");

    let second_service =
        HostService::local_demo_for_tests_at(state.path()).expect("construct second Host service");
    let second_server = DaemonServer::bind(
        second_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("the next daemon acquires the boundedly released store");
    second_server.shutdown().await.expect("stop second daemon");
}

#[tokio::test]
async fn rejected_token_states_have_one_failure_contract() {
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

    let rotated = ApiBearerToken::generate().expect("generate rotatable token");
    running
        .service
        .register_api_token(&rotated, "principal-rotated", ApiScopes::READ, None)
        .expect("register rotatable token");
    running
        .service
        .rotate_api_token(&replacement_token(rotated.token_id()), 1)
        .expect("rotate token");

    let read_token = ApiBearerToken::generate().expect("generate read token");
    running
        .service
        .register_api_token(&read_token, "principal-read", ApiScopes::READ, None)
        .expect("register read token");
    let wrong_read_secret = replacement_token(read_token.token_id());

    let control_token = ApiBearerToken::generate().expect("generate control token");
    running
        .service
        .register_api_token(
            &control_token,
            "principal-control",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register control token");
    let wrong_control_secret = replacement_token(control_token.token_id());
    tokio::time::sleep(Duration::from_millis(75)).await;

    let request_id = RequestId::new();
    let client = reqwest::Client::new();
    let mut failures = Vec::new();
    for token in [
        &unknown,
        &expired,
        &revoked,
        &rotated,
        &wrong_read_secret,
        &wrong_control_secret,
    ] {
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
            .header("Forwarded", format!("for=192.0.2.{attempt}"))
            .header("X-Forwarded-For", format!("198.51.100.{attempt}"))
            .header("X-Real-IP", format!("203.0.113.{attempt}"))
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
async fn trusted_proxy_headers_use_the_nearest_untrusted_hop_for_auth_limits() {
    let running = RunningServer::start_with_config(
        ApiScopes::READ,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_trusted_proxies(trusted_test_proxy_ranges()),
    )
    .await;
    // These requests must reach the listener directly. A developer's ambient
    // HTTP proxy would otherwise become the real transport peer and correctly
    // make the synthetic loopback proxy chain untrusted.
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build direct HTTP client");

    for attempt in 0..10 {
        let request = client
            .get(running.url("/v1/host/status"))
            .header("Satelle-Request-Id", RequestId::new().to_string());
        let request = if attempt % 2 == 0 {
            request.header(
                "Forwarded",
                "for=203.0.113.99, for=198.51.100.40, for=127.0.0.2",
            )
        } else {
            request.header("X-Forwarded-For", "203.0.113.99, 198.51.100.40, 127.0.0.2")
        };
        let response = request.send().await.expect("send proxied auth failure");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // A different origin through the same trusted proxy chain has an
    // independent budget. If Satelle keyed the limiter by either trusted
    // proxy hop, this authenticated read would already be rate limited.
    let token = running.token.expose();
    let successful = client
        .get(running.url("/v1/host/status"))
        .header("Authorization", format!("Bearer {}", token.as_str()))
        .header("Satelle-Expected-Host-Identity", &running.host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .header("X-Forwarded-For", "203.0.113.99, 198.51.100.41, 127.0.0.2")
        .send()
        .await
        .expect("send independent proxied request");
    let successful_status = successful.status();
    let successful_body = successful.text().await.expect("read proxied response");
    assert_eq!(
        successful_status,
        StatusCode::OK,
        "unexpected proxied response: {successful_body}"
    );

    let limited = client
        .get(running.url("/v1/host/status"))
        .header("Satelle-Request-Id", RequestId::new().to_string())
        .header("X-Forwarded-For", "203.0.113.99, 198.51.100.40, 127.0.0.2")
        .send()
        .await
        .expect("send exhausted proxied request");
    assert_rate_limited(limited, None).await;
}

#[tokio::test]
async fn conflicting_forwarded_header_families_fall_back_to_the_transport_peer() {
    let running = RunningServer::start_with_config(
        ApiScopes::READ,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_trusted_proxies(trusted_test_proxy_ranges()),
    )
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build direct HTTP client");

    for attempt in 1..=11 {
        let response = client
            .get(running.url("/v1/host/status"))
            .header("Satelle-Request-Id", RequestId::new().to_string())
            .header("Forwarded", format!("for=192.0.2.{attempt}"))
            .header("X-Forwarded-For", format!("198.51.100.{attempt}"))
            .send()
            .await
            .expect("send conflicting forwarded identity");
        if attempt <= 10 {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        } else {
            assert_rate_limited(response, None).await;
        }
    }
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
async fn advertised_connection_limit_returns_a_typed_capacity_error() {
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
    held.write_all(b"GET /v1/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write held keep-alive request");
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut response = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let count = held
                .read(&mut chunk)
                .await
                .expect("read held keep-alive response");
            assert_ne!(count, 0, "held keep-alive connection closed unexpectedly");
            response.extend_from_slice(&chunk[..count]);
            if response
                .windows(b"\"alive\":true".len())
                .any(|window| window == b"\"alive\":true")
            {
                break;
            }
        }
    })
    .await
    .expect("held request must establish the capacity-owning connection");

    let overloaded_request_id = RequestId::new();
    let overloaded_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("build bounded client");
    let overloaded = overloaded_client
        .get(format!("http://{}/v1/live", server.local_addr()))
        .header("Satelle-Request-Id", overloaded_request_id.to_string())
        .send()
        .await
        .expect("receive typed connection-capacity response");
    assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        overloaded.headers()["satelle-request-id"],
        overloaded_request_id.as_str()
    );
    assert_eq!(overloaded.headers()["connection"], "close");
    let error = overloaded
        .json::<Value>()
        .await
        .expect("decode typed connection-capacity response");
    assert_eq!(error["code"], "capacity-exceeded");
    assert_eq!(error["category"], "capacity");
    assert_eq!(error["retryable"], true);
    assert_eq!(error["host_identity"], Value::Null);

    let pinned_token = {
        let exposed = token.expose();
        ApiBearerToken::parse(exposed.as_str()).expect("copy token for pinned capacity request")
    };
    let pinned_address = server.local_addr();
    let pinned_identity = initialized.host_identity().to_string();
    let pinned_error = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(pinned_address, pinned_token, pinned_identity)
            .expect("construct pinned capacity client")
            .capabilities()
            .expect_err("pinned client must receive the capacity rejection")
    })
    .await
    .expect("join pinned capacity client");
    match pinned_error {
        DaemonClientError::Api { status, error } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(error.code().as_str(), "capacity-exceeded");
            assert_eq!(error.host_identity(), Some(initialized.host_identity()));
        }
        other => panic!("expected typed pinned capacity error, got {other:?}"),
    }
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
