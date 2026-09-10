use super::*;

#[tokio::test]
async fn setup_history_requires_authenticated_read_and_returns_only_summary_fields() {
    const PRIVATE: &str = "PRIVATE_HTTP_SETUP_HISTORY";
    const PATH: &str = "/v1/diagnostics/setup-history";
    let running = RunningServer::start(ApiScopes::READ).await;
    let now = time::OffsetDateTime::now_utc();
    let plan = SetupRunPlan::new(
        PRIVATE,
        SetupOperationKind::Setup,
        None,
        now,
        vec![SetupActionPlan::new(PRIVATE, PRIVATE, true).unwrap()],
    )
    .unwrap();
    let mut operation = running.service.begin_setup_run(&plan).unwrap();
    running
        .service
        .skip_setup_action(
            &operation,
            PRIVATE,
            satelle_host::SetupActionSkipReason::NotRequired,
            now,
        )
        .unwrap();
    running
        .service
        .finish_setup_run(&mut operation, now)
        .unwrap();

    let unauthenticated = reqwest::Client::new()
        .get(running.url(PATH))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let response = running.request(PATH).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response.headers()["satelle-request-id"]
        .to_str()
        .unwrap()
        .to_string();
    let bytes = response.bytes().await.unwrap();
    satelle_test_contract::assert_privacy_canaries_absent("setup history HTTP", &bytes, &[PRIVATE]);
    let wire: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(wire["schema_version"], "satelle.setup-history.v1");
    assert_eq!(wire["request_id"], request_id);
    assert_eq!(wire["host_identity"], running.host_identity);
    assert_eq!(wire["history"]["truncated"], false);
    assert_eq!(wire["history"]["runs"][0]["actions"]["skipped"], 1);
    assert_eq!(wire["history"]["runs"][0]["status"], "completed");

    let nonempty = running
        .request(PATH)
        .body("unexpected body")
        .send()
        .await
        .unwrap();
    assert_eq!(nonempty.status(), StatusCode::BAD_REQUEST);
    let address = running.server.local_addr();
    let token = ApiBearerToken::parse(&running.token.expose()).unwrap();
    let identity = running.host_identity.clone();
    let history = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(address, token, identity)
            .unwrap()
            .setup_history()
            .unwrap()
            .into_history()
    })
    .await
    .unwrap();
    assert_eq!(history.runs.len(), 1);
    assert_eq!(history.runs[0].actions.skipped, 1);
    running.server.shutdown().await.unwrap();
}
