use super::*;

#[tokio::test]
async fn desktop_sessions_are_a_flat_authenticated_read_contract() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let response = running
        .request("/v1/host/desktop-sessions")
        .send()
        .await
        .expect("request desktop sessions");
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response.headers()["satelle-request-id"]
        .to_str()
        .expect("response request ID is ASCII")
        .to_string();
    RequestId::parse(&request_id).expect("response request ID is canonical UUIDv7");
    assert_eq!(
        response.headers()["satelle-host-identity"],
        running.host_identity
    );
    assert_eq!(response.headers()["cache-control"], "no-store");

    let bytes = response.bytes().await.expect("read desktop sessions");
    let value: Value = serde_json::from_slice(&bytes).expect("parse desktop sessions JSON");
    assert_eq!(
        value
            .as_object()
            .expect("desktop sessions envelope")
            .keys()
            .collect::<Vec<_>>(),
        ["host_identity", "request_id", "schema_version", "sessions"]
    );
    assert_eq!(value["schema_version"], "satelle.host.desktop-sessions.v1");
    assert_eq!(value["request_id"], request_id);
    assert_eq!(value["host_identity"], running.host_identity);
    assert_eq!(
        value["sessions"].as_array().expect("session array").len(),
        1
    );

    let contract: HostDesktopSessionsResponse =
        serde_json::from_slice(&bytes).expect("decode desktop sessions contract");
    assert_eq!(contract.request_id().as_str(), request_id);
    assert_eq!(contract.host_identity(), running.host_identity);
    assert_eq!(contract.sessions()[0].session_id, "local-demo-console");
    assert!(contract.sessions()[0].selected_by_current_config);
}

#[tokio::test]
async fn desktop_sessions_reject_non_read_shapes_and_insufficient_scope() {
    let running = RunningServer::start(ApiScopes::READ).await;
    for request in [
        running.request("/v1/host/desktop-sessions?bootstrap=true"),
        running
            .request("/v1/host/desktop-sessions")
            .header("Cookie", "bootstrap=true"),
    ] {
        let response = request.send().await.expect("send invalid read shape");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: ApiError = response.json().await.expect("decode invalid read error");
        assert_eq!(error.code().as_str(), "invalid-request");
    }

    let wrong_method = running
        .protected_request(reqwest::Method::POST, "/v1/host/desktop-sessions")
        .send()
        .await
        .expect("send wrong method");
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

    let diagnostics_only = RunningServer::start(ApiScopes::DIAGNOSTICS_SENSITIVE).await;
    let forbidden = diagnostics_only
        .request("/v1/host/desktop-sessions")
        .send()
        .await
        .expect("request sessions without read scope");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let error: ApiError = forbidden.json().await.expect("decode scope error");
    assert_eq!(error.code().as_str(), "authorization-insufficient-scope");
}

#[tokio::test]
async fn daemon_client_reads_desktop_sessions_with_identity_pinning() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let address = running.server.local_addr();
    let expected_host_identity = running.host_identity.clone();
    let token = {
        let exposed = running.token.expose();
        ApiBearerToken::parse(exposed.as_str()).expect("copy test token into blocking client")
    };

    let response = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, token, expected_host_identity)?.desktop_sessions()
    })
    .await
    .expect("join desktop-session client request")
    .expect("read desktop sessions through DaemonClient");
    assert_eq!(response.sessions().len(), 1);
    assert_eq!(response.sessions()[0].session_id, "local-demo-console");
}
