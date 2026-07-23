use super::*;
use reqwest::Method;
use satelle_transport::{StopRequest, TurnRequest};

#[tokio::test]
async fn protocol_version_gate_is_exact_sanitized_and_precedes_mutation_work() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let session_id = satelle_core::SessionId::new();

    let missing = mutation_without_protocol(&running, "/v1/sessions", "protocol-missing")
        .json(&TurnRequest::new("PRIVATE_PROTOCOL_MISSING_CANARY"))
        .send()
        .await
        .expect("send missing protocol version");
    assert_protocol_error(&running, missing, "missing", None).await;

    for (token, key) in [
        ("01", "protocol-leading-zero"),
        ("+1", "protocol-signed"),
        (
            "PRIVATE_PROTOCOL_HEADER_CANARY",
            "protocol-opaque-malformed",
        ),
    ] {
        let malformed = mutation_without_protocol(&running, "/v1/sessions", key)
            .header("Satelle-Protocol-Version", token)
            .json(&TurnRequest::new("PRIVATE_PROTOCOL_MALFORMED_CANARY"))
            .send()
            .await
            .expect("send malformed protocol version");
        assert_protocol_error(&running, malformed, "malformed", None).await;
    }

    let mut duplicate_request = running
        .mutation("/v1/sessions", "protocol-duplicate-lines")
        .json(&TurnRequest::new("PRIVATE_PROTOCOL_DUPLICATE_CANARY"))
        .build()
        .expect("build duplicate protocol request");
    duplicate_request.headers_mut().append(
        reqwest::header::HeaderName::from_static("satelle-protocol-version"),
        reqwest::header::HeaderValue::from_static("5"),
    );
    let duplicate_lines = reqwest::Client::new()
        .execute(duplicate_request)
        .await
        .expect("send duplicate protocol field lines");
    assert_protocol_error(&running, duplicate_lines, "duplicate", None).await;

    let coalesced_duplicate =
        mutation_without_protocol(&running, "/v1/sessions", "protocol-duplicate-coalesced")
            .header("Satelle-Protocol-Version", "5, 5")
            .json(&TurnRequest::new("PRIVATE_PROTOCOL_COALESCED_CANARY"))
            .send()
            .await
            .expect("send coalesced duplicate protocol version");
    assert_protocol_error(&running, coalesced_duplicate, "duplicate", None).await;

    for token in [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "65535",
        "65536",
        "99999999999999999999",
    ] {
        let unsupported = mutation_without_protocol(&running, "/v1/sessions", "protocol-boundary")
            .header("Satelle-Protocol-Version", token)
            .json(&TurnRequest::new("PRIVATE_PROTOCOL_BOUNDARY_CANARY"))
            .send()
            .await
            .expect("send canonical unsupported protocol version");
        assert_protocol_error(&running, unsupported, "unsupported", Some(token)).await;
    }

    // HTTP optional whitespace is removed by the parser before HeaderMap is
    // exposed. Send this case at the wire layer because reqwest deliberately
    // prevents callers from constructing padded header values.
    let whitespace_request = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nSatelle-Expected-Host-Identity: {}\r\nSatelle-Request-Id: {}\r\nSatelle-Protocol-Version:   6 \r\nIdempotency-Key:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        bearer(&running.token),
        running.host_identity,
        RequestId::new(),
    );
    let whitespace =
        super::raw_wire::raw_request(running.server.local_addr(), whitespace_request.as_bytes())
            .await;
    super::raw_wire::assert_raw_api_error(&whitespace, 400, "invalid-request");

    for (path, body, key) in [
        (
            "/v1/sessions?PRIVATE_PROTOCOL_QUERY_CANARY=1".to_string(),
            serde_json::json!({"PRIVATE_PROTOCOL_BODY_CANARY": true}),
            "protocol-create-unsupported",
        ),
        (
            format!("/v1/sessions/{session_id}/turns"),
            serde_json::to_value(TurnRequest::new("PRIVATE_PROTOCOL_TURN_CANARY")).unwrap(),
            "protocol-turn-unsupported",
        ),
        (
            format!("/v1/sessions/{session_id}/stop"),
            serde_json::to_value(StopRequest::new()).unwrap(),
            "protocol-stop-unsupported",
        ),
    ] {
        let unsupported = mutation_without_protocol(&running, &path, key)
            .header("Satelle-Protocol-Version", "1")
            .header("Cookie", "PRIVATE_PROTOCOL_COOKIE_CANARY=1")
            .json(&body)
            .send()
            .await
            .expect("send unsupported protocol version");
        assert_protocol_error(&running, unsupported, "unsupported", Some("1")).await;
    }

    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read side-effect count")
            .session_count(),
        0,
        "protocol rejection must happen before Host mutation"
    );
}

#[tokio::test]
async fn capabilities_handshake_rejects_old_and_missing_clients() {
    let running = RunningServer::start(ApiScopes::READ).await;

    let missing = running
        .protected_request(Method::GET, "/v1/capabilities")
        .send()
        .await
        .expect("send capabilities request without protocol version");
    assert_protocol_error(&running, missing, "missing", None).await;

    let old = running
        .protected_request(Method::GET, "/v1/capabilities")
        .header("Satelle-Protocol-Version", "5")
        .send()
        .await
        .expect("send capabilities request with old protocol version");
    assert_protocol_error(&running, old, "unsupported", Some("5")).await;

    let current = running
        .protected_request(Method::GET, "/v1/capabilities")
        .header("Satelle-Protocol-Version", "6")
        .send()
        .await
        .expect("send capabilities request with current protocol version");
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(current.headers()["satelle-protocol-version"], "6");
}

#[tokio::test]
async fn control_scope_is_checked_before_protocol_compatibility() {
    let read_only = RunningServer::start(ApiScopes::READ).await;
    let response = mutation_without_protocol(&read_only, "/v1/sessions", "scope-ordering")
        .json(&TurnRequest::new("PRIVATE_SCOPE_ORDERING_CANARY"))
        .send()
        .await
        .expect("send read-only mutation without protocol version");
    super::sessions::assert_api_error(
        response,
        StatusCode::FORBIDDEN,
        "authorization-insufficient-scope",
    )
    .await;
}

fn mutation_without_protocol(
    running: &RunningServer,
    path: &str,
    idempotency_key: &str,
) -> reqwest::RequestBuilder {
    running
        .protected_request(Method::POST, path)
        .header("Idempotency-Key", idempotency_key)
}

async fn assert_protocol_error(
    running: &RunningServer,
    response: reqwest::Response,
    reason: &str,
    received_version: Option<&str>,
) {
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["satelle-host-identity"],
        running.host_identity
    );
    let request_id = response.headers()["satelle-request-id"]
        .to_str()
        .expect("response request ID is ASCII")
        .to_string();
    let body = response.bytes().await.expect("read protocol error");
    let value: Value = serde_json::from_slice(&body).expect("decode protocol error");
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": "satelle.error.v1",
            "request_id": request_id,
            "host_identity": running.host_identity,
            "code": "incompatible-protocol",
            "category": "compatibility",
            "retryable": false,
            "message": "the CLI and Host Daemon protocol versions are incompatible",
            "details": {
                "daemon_version": env!("CARGO_PKG_VERSION"),
                "reason": reason,
                "supported_versions": ["6"],
                "received_version": received_version,
            },
            "docs_url": null,
            "suggested_commands": [],
        })
    );
    assert!(!String::from_utf8_lossy(&body).contains("PRIVATE_PROTOCOL_"));
}
