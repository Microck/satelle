use super::*;
use satelle_test_contract::assert_privacy_canaries_absent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn chunked_oversize_body_returns_typed_413_without_admission() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let authorization = bearer(&running.token);
    let payload_bytes = 1_048_577;
    let head = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 3\r\nIdempotency-Key: raw-chunked-limit\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{payload_bytes:x}\r\n",
        running.host_identity,
        RequestId::new(),
    );
    let mut request = Vec::with_capacity(head.len() + payload_bytes + 16);
    request.extend_from_slice(head.as_bytes());
    request.resize(request.len() + payload_bytes, b'x');
    request.extend_from_slice(b"\r\n0\r\n\r\n");

    let response = raw_request(running.server.local_addr(), &request).await;
    assert_raw_api_error(&response, 413, "payload-too-large");
    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read session count")
            .session_count(),
        0
    );
}

#[test]
fn chunked_non_empty_attachments_return_typed_413_without_admission() {
    run_with_trace_capture(chunked_attachment_limit_and_log_privacy);
}

async fn chunked_attachment_limit_and_log_privacy(trace_capture: TraceCapture) {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let authorization = bearer(&running.token);
    let body_canary = "PRIVATE_CHUNKED_BODY_CANARY";
    let attachment_name = "PRIVATE_CHUNKED_ATTACHMENT_NAME_CANARY";
    let attachment_bytes = "PRIVATE_CHUNKED_ATTACHMENT_BYTES_CANARY";
    let body = format!(
        r#"{{"schema_version":"satelle.api.v2","prompt":7,"execution_mode":"standard","body_canary":"{body_canary}","attachments":[{{"name":"{attachment_name}","content":"{attachment_bytes}"}}]}}"#
    );
    let body = body.as_bytes();
    let split = body.len() / 2;
    let request_id = RequestId::new();
    let request_head = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 3\r\nIdempotency-Key: attachment-limit-chunked\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{split:x}\r\n",
        running.host_identity, request_id,
    );
    let mut request = request_head.into_bytes();
    request.extend_from_slice(&body[..split]);
    request.extend_from_slice(format!("\r\n{:x}\r\n", body.len() - split).as_bytes());
    request.extend_from_slice(&body[split..]);
    request.extend_from_slice(b"\r\n0\r\n\r\n");

    let response = raw_request(running.server.local_addr(), &request).await;
    assert_raw_attachment_limit_error(&response, &running.host_identity);
    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read session count")
            .session_count(),
        0
    );
    let traces = trace_capture.bytes();
    assert_captured_host_admission_dispatch(&traces);
    assert_privacy_canaries_absent(
        "Host Daemon tracing sink after chunked request",
        &traces,
        &[
            body_canary,
            attachment_name,
            attachment_bytes,
            authorization
                .strip_prefix("Bearer ")
                .expect("raw-wire Authorization fixture uses Bearer authentication"),
            authorization.as_str(),
        ],
    );

    // The public Host log page remains separate durable audit evidence.
    assert_raw_returned_host_logs_exclude(
        &running,
        &[
            body_canary,
            attachment_name,
            attachment_bytes,
            authorization
                .strip_prefix("Bearer ")
                .expect("raw-wire Authorization fixture uses Bearer authentication"),
            authorization.as_str(),
        ],
    )
    .await;
}

#[tokio::test]
async fn duplicate_singleton_headers_fail_closed_without_admission() {
    duplicate_header_case(DuplicateHeader::Authorization, 401, "authentication-failed").await;
    duplicate_header_case(DuplicateHeader::IdempotencyKey, 400, "invalid-request").await;
    duplicate_header_case(
        DuplicateHeader::ContentType,
        415,
        "unsupported-content-type",
    )
    .await;
}

#[tokio::test]
async fn bearer_tokens_in_http_trailers_are_rejected_without_admission() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let token = running.token.expose();
    let live_request = format!(
        "GET /v1/live HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Api-Token\r\nConnection: close\r\n\r\n2\r\n{{}}\r\n0\r\nX-Api-Token: {}\r\n\r\n",
        token.as_str()
    );
    let response = raw_request(running.server.local_addr(), live_request.as_bytes()).await;
    assert_raw_api_error(&response, 400, "invalid-request");

    let body =
        br#"{"schema_version":"satelle.api.v2","prompt":"safe","execution_mode":"standard"}"#;
    let mutation_request = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 3\r\nIdempotency-Key: trailer-carrier\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-Api-Token\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\nX-Api-Token: {}\r\n\r\n",
        bearer(&running.token),
        running.host_identity,
        RequestId::new(),
        body.len(),
        String::from_utf8_lossy(body),
        token.as_str(),
    );
    let response = raw_request(running.server.local_addr(), mutation_request.as_bytes()).await;
    assert_raw_api_error(&response, 400, "invalid-request");
    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read session count")
            .session_count(),
        0
    );
}

#[tokio::test]
async fn stalled_upload_cannot_hold_daemon_shutdown_open_forever() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let token = ApiBearerToken::generate().expect("generate API token");
    service
        .register_api_token(&token, "principal-shutdown", ApiScopes::CONTROL, None)
        .expect("register API token");
    let server = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_shutdown_grace(Duration::from_millis(50)),
    )
    .await
    .expect("bind daemon server");
    let address = server.local_addr();
    let mut held = TcpStream::connect(address)
        .await
        .expect("open stalled request connection");
    let partial = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 3\r\nIdempotency-Key: stalled-shutdown\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{",
        bearer(&token),
        initialized.host_identity(),
        RequestId::new(),
    );
    held.write_all(partial.as_bytes())
        .await
        .expect("write partial request");
    tokio::time::sleep(Duration::from_millis(20)).await;

    let error = tokio::time::timeout(Duration::from_secs(1), server.shutdown())
        .await
        .expect("shutdown must be bounded")
        .expect_err("stalled request must exhaust the graceful deadline");
    assert_eq!(error.code(), "shutdown-timeout");
    assert!(TcpStream::connect(address).await.is_err());
    drop(held);
}

pub(super) async fn raw_request(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect raw HTTP client");
    stream.write_all(request).await.expect("write raw request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read raw response");
    response
}

#[derive(Clone, Copy, Debug)]
enum DuplicateHeader {
    Authorization,
    IdempotencyKey,
    ContentType,
}

async fn duplicate_header_case(header: DuplicateHeader, status: u16, code: &str) {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let authorization = bearer(&running.token);
    let body = br#"{"schema_version":"satelle.api.v2","prompt":"PRIVATE_RAW_HEADER_CANARY","execution_mode":"standard"}"#;
    let duplicated = match header {
        DuplicateHeader::Authorization => format!(
            "Authorization: {authorization}\r\nAuthorization: {authorization}\r\nIdempotency-Key: duplicate-auth\r\nContent-Type: application/json\r\n"
        ),
        DuplicateHeader::IdempotencyKey => format!(
            "Authorization: {authorization}\r\nIdempotency-Key: first-key\r\nIdempotency-Key: second-key\r\nContent-Type: application/json\r\n"
        ),
        DuplicateHeader::ContentType => format!(
            "Authorization: {authorization}\r\nIdempotency-Key: duplicate-content-type\r\nContent-Type: application/json\r\nContent-Type: application/json\r\n"
        ),
    };
    let mut request = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 3\r\nContent-Length: {}\r\n{duplicated}Connection: close\r\n\r\n",
        running.host_identity,
        RequestId::new(),
        body.len(),
    )
    .into_bytes();
    request.extend_from_slice(body);
    let response = raw_request(running.server.local_addr(), &request).await;
    let session_count = running
        .service
        .initialize_daemon()
        .expect("read session count")
        .session_count();
    assert!(
        !response.is_empty(),
        "duplicate {header:?} header closed without HTTP"
    );
    assert_raw_api_error(&response, status, code);
    assert_eq!(session_count, 0);
}

pub(super) fn assert_raw_api_error(response: &[u8], status: u16, code: &str) {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("raw response has header terminator");
    let headers = String::from_utf8_lossy(&response[..separator]);
    assert!(
        headers.starts_with(&format!("HTTP/1.1 {status} ")),
        "{headers}"
    );
    let body: ApiError =
        serde_json::from_slice(&response[separator + 4..]).expect("decode raw API error");
    assert_eq!(body.code().as_str(), code);
}

fn assert_raw_attachment_limit_error(response: &[u8], host_identity: &str) {
    assert_raw_api_error(response, 413, "payload-too-large");
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("raw response has header terminator");
    let body: Value =
        serde_json::from_slice(&response[separator + 4..]).expect("decode raw attachment error");
    assert_eq!(body["schema_version"], "satelle.error.v1");
    assert_eq!(body["host_identity"], host_identity);
    assert_eq!(body["code"], "payload-too-large");
    assert_eq!(body["category"], "capacity");
    assert_eq!(body["retryable"], false);
    assert_eq!(
        body["message"],
        "the request exceeds the advertised attachment limit"
    );
    assert_eq!(body["details"], Value::Null);
    assert_eq!(body["docs_url"], Value::Null);
    assert_eq!(body["suggested_commands"], serde_json::json!([]));
}

async fn assert_raw_returned_host_logs_exclude(running: &RunningServer, canaries: &[&str]) {
    let response = running
        .request("/v1/logs?mode=tail&limit=200&minimum_severity=info")
        .send()
        .await
        .expect("read Host logs after raw-wire request");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .bytes()
        .await
        .expect("read Host log page after raw-wire request");
    assert_privacy_canaries_absent(
        "returned Host logs after raw-wire request",
        &bytes,
        canaries,
    );
}
