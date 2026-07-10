use super::*;
use reqwest::Method;
use satelle_core::StopResultOutcome;
use satelle_core::session::SessionActivity;
use satelle_transport::{SessionResponse, StopRequest, StopResponse, TurnRequest};

const CREATE_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f01";
const STEER_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f02";
const STOP_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f03";
const SECOND_CREATE_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f04";
const CROSS_SESSION_TURN_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f05";

#[tokio::test]
async fn session_routes_complete_the_durable_reconnect_journey() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let prompt = "PRIVATE_HTTP_CREATE_PROMPT_CANARY";
    let create = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new(prompt))
        .send()
        .await
        .expect("create Session");
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let create_bytes = create.bytes().await.expect("read create response");
    let create_json: Value = serde_json::from_slice(&create_bytes).expect("parse create JSON");
    assert_eq!(create_json["schema_version"], "satelle.session.v1");
    assert!(create_json.get("session").is_none());
    assert!(create_json.get("session_id").is_some());
    assert!(!String::from_utf8_lossy(&create_bytes).contains(prompt));
    assert!(!String::from_utf8_lossy(&create_bytes).contains("local-demo"));
    let created: SessionResponse =
        serde_json::from_slice(&create_bytes).expect("decode create contract");
    assert_eq!(created.host_identity(), running.host_identity);
    assert_eq!(created.session().turns().len(), 1);
    let session_id = created.session().session_id().clone();

    let terminal = wait_until_idle(&running, session_id.as_str()).await;
    assert_eq!(terminal.session().session_id(), &session_id);
    assert!(terminal.session().turns()[0].state().is_terminal());

    // A fresh HTTP connection reads the durable Session without any state
    // carried by the request that created it.
    let reconnected: SessionResponse = running
        .request(&format!("/v1/sessions/{session_id}"))
        .send()
        .await
        .expect("read Session through fresh connection")
        .json()
        .await
        .expect("decode Session read");
    assert_eq!(reconnected.session(), terminal.session());

    let steer_prompt = "PRIVATE_HTTP_STEER_PROMPT_CANARY";
    let steer = running
        .mutation(&format!("/v1/sessions/{session_id}/turns"), STEER_KEY)
        .json(&TurnRequest::new(steer_prompt))
        .send()
        .await
        .expect("create follow-up Turn");
    assert_eq!(steer.status(), StatusCode::ACCEPTED);
    let steer_bytes = steer.bytes().await.expect("read steer response");
    assert!(!String::from_utf8_lossy(&steer_bytes).contains(steer_prompt));
    let steered: SessionResponse =
        serde_json::from_slice(&steer_bytes).expect("decode steer contract");
    assert_eq!(steered.session().session_id(), &session_id);
    assert_eq!(steered.session().turns().len(), 2);
    wait_until_idle(&running, session_id.as_str()).await;

    let stop = running
        .mutation(&format!("/v1/sessions/{session_id}/stop"), STOP_KEY)
        .json(&StopRequest::new())
        .send()
        .await
        .expect("stop latest Turn");
    assert_eq!(stop.status(), StatusCode::OK);
    let stopped: StopResponse = stop.json().await.expect("decode stop contract");
    assert_eq!(stopped.host_identity(), running.host_identity);
    assert_eq!(stopped.result().session_id(), &session_id);
    assert_eq!(
        stopped.result().outcome(),
        StopResultOutcome::AlreadyTerminal
    );
}

#[tokio::test]
async fn mutation_replays_preserve_operation_boundaries_and_reject_digest_drift() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let request = TurnRequest::new("PRIVATE_REPLAY_PROMPT_CANARY");
    let first: SessionResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&request)
        .send()
        .await
        .expect("create Session")
        .json()
        .await
        .expect("decode first admission");
    let session_id = first.session().session_id().clone();
    wait_until_idle(&running, session_id.as_str()).await;

    let replay: SessionResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&request)
        .send()
        .await
        .expect("replay create")
        .json()
        .await
        .expect("decode replay");
    assert_eq!(replay.session().session_id(), &session_id);
    assert_eq!(replay.session().turns().len(), 1);

    let changed_prompt = "PRIVATE_CHANGED_REPLAY_PROMPT_CANARY";
    let conflict = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new(changed_prompt))
        .send()
        .await
        .expect("send conflicting replay");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_bytes = conflict.bytes().await.expect("read conflict body");
    let error: ApiError = serde_json::from_slice(&conflict_bytes).expect("decode conflict");
    assert_eq!(error.code().as_str(), "idempotency-key-conflict");
    assert!(!String::from_utf8_lossy(&conflict_bytes).contains(changed_prompt));

    // The original create replay stays at its one-Turn operation boundary even
    // after a later follow-up mutates the current Session.
    running
        .mutation(&format!("/v1/sessions/{session_id}/turns"), STEER_KEY)
        .json(&TurnRequest::new("PRIVATE_LATER_TURN_CANARY"))
        .send()
        .await
        .expect("admit later Turn")
        .error_for_status()
        .expect("later Turn accepted");
    wait_until_idle(&running, session_id.as_str()).await;
    let boundary_replay: SessionResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&request)
        .send()
        .await
        .expect("replay original create after steer")
        .json()
        .await
        .expect("decode boundary replay");
    assert_eq!(boundary_replay.session().turns().len(), 1);
}

#[tokio::test]
async fn simultaneous_identical_mutations_all_replay_one_atomic_admission() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let authorization = bearer(&running.token);
    let address = running.server.local_addr();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let client = reqwest::Client::new();
        let authorization = authorization.clone();
        let host_identity = running.host_identity.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let response = protected_at(
                &client,
                Method::POST,
                address,
                "/v1/sessions",
                &authorization,
                &host_identity,
            )
            .header("Idempotency-Key", "simultaneous-create-key")
            .json(&TurnRequest::new("PRIVATE_SIMULTANEOUS_REPLAY_CANARY"))
            .send()
            .await
            .expect("send simultaneous mutation");
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            response
                .json::<SessionResponse>()
                .await
                .expect("decode simultaneous admission")
        }));
    }

    let mut session_ids = Vec::new();
    for task in tasks {
        session_ids.push(
            task.await
                .expect("join simultaneous mutation")
                .session()
                .session_id()
                .clone(),
        );
    }
    assert!(session_ids.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read atomic admission count")
            .session_count(),
        1
    );
}

#[tokio::test]
async fn turn_idempotency_digest_binds_the_path_session_target() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let first: SessionResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new("PRIVATE_FIRST_SESSION_CANARY"))
        .send()
        .await
        .expect("create first Session")
        .json()
        .await
        .expect("decode first Session");
    wait_until_idle(&running, first.session().session_id().as_str()).await;
    let second: SessionResponse = running
        .mutation("/v1/sessions", SECOND_CREATE_KEY)
        .json(&TurnRequest::new("PRIVATE_SECOND_SESSION_CANARY"))
        .send()
        .await
        .expect("create second Session")
        .json()
        .await
        .expect("decode second Session");
    wait_until_idle(&running, second.session().session_id().as_str()).await;

    let shared_request = TurnRequest::new("PRIVATE_CROSS_TARGET_TURN_CANARY");
    let first_target = running
        .mutation(
            &format!("/v1/sessions/{}/turns", first.session().session_id()),
            CROSS_SESSION_TURN_KEY,
        )
        .json(&shared_request)
        .send()
        .await
        .expect("admit first target");
    assert_eq!(first_target.status(), StatusCode::ACCEPTED);
    wait_until_idle(&running, first.session().session_id().as_str()).await;

    let conflicting_target = running
        .mutation(
            &format!("/v1/sessions/{}/turns", second.session().session_id()),
            CROSS_SESSION_TURN_KEY,
        )
        .json(&shared_request)
        .send()
        .await
        .expect("send changed target");
    assert_api_error(
        conflicting_target,
        StatusCode::CONFLICT,
        "idempotency-key-conflict",
    )
    .await;

    let untouched: SessionResponse = running
        .request(&format!("/v1/sessions/{}", second.session().session_id()))
        .send()
        .await
        .expect("read untouched Session")
        .json()
        .await
        .expect("decode untouched Session");
    assert_eq!(untouched.session().turns().len(), 1);
}

#[tokio::test]
async fn stop_idempotency_digest_binds_the_path_session_target() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let first: SessionResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new("PRIVATE_FIRST_STOP_TARGET_CANARY"))
        .send()
        .await
        .expect("create first stop target")
        .json()
        .await
        .expect("decode first stop target");
    wait_until_idle(&running, first.session().session_id().as_str()).await;
    let second: SessionResponse = running
        .mutation("/v1/sessions", SECOND_CREATE_KEY)
        .json(&TurnRequest::new("PRIVATE_SECOND_STOP_TARGET_CANARY"))
        .send()
        .await
        .expect("create second stop target")
        .json()
        .await
        .expect("decode second stop target");
    wait_until_idle(&running, second.session().session_id().as_str()).await;

    let shared_key = "cross-session-stop-key";
    let first_stop = running
        .mutation(
            &format!("/v1/sessions/{}/stop", first.session().session_id()),
            shared_key,
        )
        .json(&StopRequest::new())
        .send()
        .await
        .expect("stop first target");
    assert_eq!(first_stop.status(), StatusCode::OK);

    let second_stop = running
        .mutation(
            &format!("/v1/sessions/{}/stop", second.session().session_id()),
            shared_key,
        )
        .json(&StopRequest::new())
        .send()
        .await
        .expect("stop changed target");
    assert_api_error(
        second_stop,
        StatusCode::CONFLICT,
        "idempotency-key-conflict",
    )
    .await;
}

#[tokio::test]
async fn replay_and_session_read_survive_a_real_daemon_restart() {
    let state = TestStateDir::new().expect("temporary state directory");
    let first_service =
        HostService::local_demo_for_tests_at(state.path()).expect("construct first Host service");
    let initialized = first_service
        .initialize_daemon()
        .expect("initialize first daemon");
    let host_identity = initialized.host_identity().to_string();
    let token = ApiBearerToken::generate().expect("generate API token");
    first_service
        .register_api_token(&token, "principal-restart-test", ApiScopes::CONTROL, None)
        .expect("register restart token");
    let authorization = bearer(&token);
    let first_server = DaemonServer::bind(
        first_service.clone(),
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind first daemon");
    let client = reqwest::Client::new();
    let request = TurnRequest::new("PRIVATE_RESTART_REPLAY_CANARY");
    let first: SessionResponse = protected_at(
        &client,
        Method::POST,
        first_server.local_addr(),
        "/v1/sessions",
        &authorization,
        &host_identity,
    )
    .header("Idempotency-Key", CREATE_KEY)
    .json(&request)
    .send()
    .await
    .expect("create before restart")
    .json()
    .await
    .expect("decode pre-restart create");
    let session_id = first.session().session_id().clone();
    wait_until_idle_at(
        &client,
        first_server.local_addr(),
        session_id.as_str(),
        &authorization,
        &host_identity,
    )
    .await;
    first_server.shutdown().await.expect("stop first daemon");
    drop(first_service);

    let second_service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct restarted Host service");
    let restarted = second_service
        .initialize_daemon()
        .expect("initialize restarted daemon");
    assert_eq!(restarted.host_identity(), host_identity);
    let second_server = DaemonServer::bind(
        second_service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind restarted daemon");

    let replay: SessionResponse = protected_at(
        &client,
        Method::POST,
        second_server.local_addr(),
        "/v1/sessions",
        &authorization,
        &host_identity,
    )
    .header("Idempotency-Key", CREATE_KEY)
    .json(&request)
    .send()
    .await
    .expect("replay after restart")
    .json()
    .await
    .expect("decode restarted replay");
    assert_eq!(replay.session().session_id(), &session_id);
    assert_eq!(replay.session().turns().len(), 1);

    let read: SessionResponse = protected_at(
        &client,
        Method::GET,
        second_server.local_addr(),
        &format!("/v1/sessions/{session_id}"),
        &authorization,
        &host_identity,
    )
    .send()
    .await
    .expect("read after restart")
    .json()
    .await
    .expect("decode restarted read");
    assert_eq!(read.session().session_id(), &session_id);
    second_server
        .shutdown()
        .await
        .expect("stop restarted daemon");
}

#[tokio::test]
async fn daemon_client_drives_the_complete_session_control_contract() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let address = running.server.local_addr();
    let host_identity = running.host_identity.clone();
    let token = {
        let exposed = running.token.expose();
        ApiBearerToken::parse(exposed.as_str()).expect("copy test token into the blocking client")
    };

    tokio::task::spawn_blocking(move || {
        let client = DaemonClient::loopback(address, token, host_identity)
            .expect("construct pinned daemon client");
        let created = client
            .create_session(
                &TurnRequest::new("PRIVATE_DAEMON_CLIENT_CREATE_CANARY"),
                CREATE_KEY,
            )
            .expect("create Session through DaemonClient");
        let session_id = created.session().session_id().clone();

        let conflict = client
            .create_session(
                &TurnRequest::new("PRIVATE_DAEMON_CLIENT_CHANGED_CANARY"),
                CREATE_KEY,
            )
            .expect_err("changed body must conflict with the retained idempotency key");
        match conflict {
            DaemonClientError::Api { status, error } => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(error.code().as_str(), "idempotency-key-conflict");
            }
            other => panic!("expected a typed API conflict, got {other:?}"),
        }
        wait_until_idle_with_client(&client, &session_id);

        let steered = client
            .create_turn(
                &session_id,
                &TurnRequest::new("PRIVATE_DAEMON_CLIENT_STEER_CANARY"),
                STEER_KEY,
            )
            .expect("create follow-up Turn through DaemonClient");
        assert_eq!(steered.session().session_id(), &session_id);
        assert_eq!(steered.session().turns().len(), 2);
        wait_until_idle_with_client(&client, &session_id);

        let stopped = client
            .stop_session(&session_id, STOP_KEY)
            .expect("stop Session through DaemonClient");
        assert_eq!(stopped.result().session_id(), &session_id);
        assert_eq!(
            stopped.result().outcome(),
            StopResultOutcome::AlreadyTerminal
        );
    })
    .await
    .expect("join DaemonClient journey");
}

#[tokio::test]
async fn mutation_validation_fails_before_execution_with_typed_errors() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;

    let missing_key = running
        .protected_request(Method::POST, "/v1/sessions")
        .json(&TurnRequest::new("PRIVATE_MISSING_KEY_CANARY"))
        .send()
        .await
        .expect("send missing-key request");
    assert_api_error(missing_key, StatusCode::BAD_REQUEST, "invalid-request").await;

    let wrong_schema = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&serde_json::json!({
            "schema_version": "satelle.api.v2",
            "prompt": "PRIVATE_WRONG_SCHEMA_CANARY"
        }))
        .send()
        .await
        .expect("send wrong schema");
    assert_api_error(wrong_schema, StatusCode::BAD_REQUEST, "unsupported-schema").await;

    let unknown_field = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&serde_json::json!({
            "schema_version": "satelle.api.v1",
            "prompt": "PRIVATE_UNKNOWN_FIELD_CANARY",
            "attachments": []
        }))
        .send()
        .await
        .expect("send unknown field");
    assert_api_error(unknown_field, StatusCode::BAD_REQUEST, "invalid-request").await;

    let wrong_content_type = running
        .mutation("/v1/sessions", CREATE_KEY)
        .header("Content-Type", "text/plain")
        .body(r#"{"schema_version":"satelle.api.v1","prompt":"private"}"#)
        .send()
        .await
        .expect("send wrong content type");
    assert_api_error(
        wrong_content_type,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported-content-type",
    )
    .await;

    let duplicate_prompt = running
        .mutation("/v1/sessions", "duplicate-json-field-key")
        .header("Content-Type", "application/json")
        .body(r#"{"schema_version":"satelle.api.v1","prompt":"first","prompt":"second"}"#)
        .send()
        .await
        .expect("send duplicate JSON field");
    assert_api_error(duplicate_prompt, StatusCode::BAD_REQUEST, "invalid-request").await;

    let empty_prompt = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new(""))
        .send()
        .await
        .expect("send empty prompt");
    assert_api_error(empty_prompt, StatusCode::BAD_REQUEST, "invalid-request").await;

    let malformed_path = running
        .mutation("/v1/sessions/not-a-session/turns", STEER_KEY)
        .json(&TurnRequest::new("PRIVATE_BAD_PATH_CANARY"))
        .send()
        .await
        .expect("send malformed path");
    assert_api_error(malformed_path, StatusCode::BAD_REQUEST, "invalid-request").await;

    let oversized = running
        .mutation("/v1/sessions", CREATE_KEY)
        .header("Content-Type", "application/json")
        .body(vec![b'x'; 1_048_577])
        .send()
        .await
        .expect("send oversized body");
    assert_api_error(
        oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload-too-large",
    )
    .await;

    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read side-effect count")
            .session_count(),
        0
    );
}

#[tokio::test]
async fn mutation_scope_and_method_failures_remain_typed() {
    let read_only = RunningServer::start(ApiScopes::READ).await;
    let forbidden = read_only
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new("PRIVATE_SCOPE_CANARY"))
        .send()
        .await
        .expect("send read-only mutation");
    assert_api_error(
        forbidden,
        StatusCode::FORBIDDEN,
        "authorization-insufficient-scope",
    )
    .await;

    let method = read_only
        .protected_request(Method::PUT, "/v1/sessions")
        .send()
        .await
        .expect("send unsupported method");
    assert_api_error(method, StatusCode::METHOD_NOT_ALLOWED, "method-not-allowed").await;
}

fn wait_until_idle_with_client(client: &DaemonClient, session_id: &satelle_core::SessionId) {
    for _ in 0..100 {
        let response = client
            .read_session(session_id)
            .expect("poll Session through DaemonClient");
        if matches!(response.session().activity(), SessionActivity::Idle) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("Session did not become idle within the blocking-client test deadline")
}

async fn wait_until_idle(running: &RunningServer, session_id: &str) -> SessionResponse {
    for _ in 0..100 {
        let response: SessionResponse = running
            .request(&format!("/v1/sessions/{session_id}"))
            .send()
            .await
            .expect("poll Session")
            .json()
            .await
            .expect("decode polled Session");
        if matches!(response.session().activity(), SessionActivity::Idle) {
            return response;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("Session did not become idle within the test deadline")
}

async fn wait_until_idle_at(
    client: &reqwest::Client,
    address: SocketAddr,
    session_id: &str,
    authorization: &str,
    host_identity: &str,
) -> SessionResponse {
    for _ in 0..100 {
        let response: SessionResponse = protected_at(
            client,
            Method::GET,
            address,
            &format!("/v1/sessions/{session_id}"),
            authorization,
            host_identity,
        )
        .send()
        .await
        .expect("poll restarted Session")
        .json()
        .await
        .expect("decode restarted Session");
        if matches!(response.session().activity(), SessionActivity::Idle) {
            return response;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("Session did not become idle within the restart test deadline")
}

fn protected_at(
    client: &reqwest::Client,
    method: Method,
    address: SocketAddr,
    path: &str,
    authorization: &str,
    host_identity: &str,
) -> reqwest::RequestBuilder {
    client
        .request(method, format!("http://{address}{path}"))
        .header("Authorization", authorization)
        .header("Satelle-Expected-Host-Identity", host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string())
}

async fn assert_api_error(response: reqwest::Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let error: ApiError = response.json().await.expect("decode API error");
    assert_eq!(error.code().as_str(), code);
}
