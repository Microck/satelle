use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn chunked_oversize_body_returns_typed_413_without_admission() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let authorization = bearer(&running.token);
    let payload_bytes = 1_048_577;
    let head = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 2\r\nIdempotency-Key: raw-chunked-limit\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{payload_bytes:x}\r\n",
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
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 2\r\nIdempotency-Key: stalled-shutdown\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{",
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
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version: 2\r\nContent-Length: {}\r\n{duplicated}Connection: close\r\n\r\n",
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
