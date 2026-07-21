use super::*;
use reqwest::Method;
use satelle_core::StopResultOutcome;
use satelle_core::session::{SessionActivity, TurnExecutionMode};
use satelle_test_contract::assert_privacy_canaries_absent;
use satelle_transport::{
    AdmissionCancellationOutcome, AdmissionCancellationResponse, SessionResponse, StopRequest,
    StopResponse, TurnRequest,
};

const CREATE_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f01";
const STEER_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f02";
const STOP_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f03";
const SECOND_CREATE_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f04";
const CROSS_SESSION_TURN_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f05";
const STALE_STOP_KEY: &str = "01890a5d-ac96-7b7c-8f89-37c3d0a66f06";

#[tokio::test]
async fn existing_admission_routes_return_exact_committed_handles_when_cancel_arrives_late() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let run_request = TurnRequest::new("PRIVATE_LATE_RUN_CANCELLATION_CANARY");
    let created: SessionResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&run_request)
        .send()
        .await
        .expect("create Session")
        .json()
        .await
        .expect("decode Session");
    let session_id = created.session().session_id().clone();
    let run_turn_id = created.session().turns()[0].turn_id().clone();

    let cancelled_run: AdmissionCancellationResponse = running
        .mutation("/v1/sessions", CREATE_KEY)
        .header("Satelle-Admission-Action", "cancel")
        .json(&run_request)
        .send()
        .await
        .expect("cancel committed run admission")
        .json()
        .await
        .expect("decode run cancellation");
    assert_eq!(
        cancelled_run.outcome(),
        AdmissionCancellationOutcome::Admitted
    );
    assert_eq!(cancelled_run.session_id(), Some(&session_id));
    assert_eq!(cancelled_run.turn_id(), Some(&run_turn_id));

    wait_until_idle(&running, session_id.as_str()).await;
    let steer_request = TurnRequest::new("PRIVATE_LATE_STEER_CANCELLATION_CANARY");
    let steered: SessionResponse = running
        .mutation(&format!("/v1/sessions/{session_id}/turns"), STEER_KEY)
        .json(&steer_request)
        .send()
        .await
        .expect("create follow-up Turn")
        .json()
        .await
        .expect("decode follow-up Turn");
    let steer_turn_id = steered
        .session()
        .turns()
        .last()
        .expect("steer response contains its target Turn")
        .turn_id()
        .clone();

    let cancelled_steer: AdmissionCancellationResponse = running
        .mutation(&format!("/v1/sessions/{session_id}/turns"), STEER_KEY)
        .header("Satelle-Admission-Action", "cancel")
        .json(&steer_request)
        .send()
        .await
        .expect("cancel committed steer admission")
        .json()
        .await
        .expect("decode steer cancellation");
    assert_eq!(
        cancelled_steer.outcome(),
        AdmissionCancellationOutcome::Admitted
    );
    assert_eq!(cancelled_steer.session_id(), Some(&session_id));
    assert_eq!(cancelled_steer.turn_id(), Some(&steer_turn_id));
}

#[tokio::test]
async fn admission_action_is_an_exact_optional_singleton_and_absence_preserves_admission_wire() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let request = TurnRequest::new("PRIVATE_ADMISSION_ACTION_VALIDATION_CANARY");
    let invalid = running
        .mutation("/v1/sessions", CREATE_KEY)
        .header("Satelle-Admission-Action", "Cancel")
        .json(&request)
        .send()
        .await
        .expect("send invalid admission action");
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let error: ApiError = invalid.json().await.expect("decode invalid action error");
    assert_eq!(error.code().as_str(), "invalid-request");
    assert_eq!(
        running
            .service
            .initialize_daemon()
            .expect("read state after invalid action")
            .session_count(),
        0
    );

    let admitted = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&request)
        .send()
        .await
        .expect("admit without the optional action header");
    assert_eq!(admitted.status(), StatusCode::ACCEPTED);
    let body = admitted.bytes().await.expect("read admission response");
    let json: Value = serde_json::from_slice(&body).expect("parse admission response");
    assert_eq!(json["schema_version"], "satelle.session.v1");
    assert!(json.get("outcome").is_none());
    serde_json::from_slice::<SessionResponse>(&body).expect("decode legacy admission response");
}

#[tokio::test]
async fn session_routes_complete_the_durable_reconnect_journey() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let secret = "PRIVATE_HTTP_CREATE_SECRET_CANARY";
    let prompt_canary = "PRIVATE_HTTP_CREATE_PROMPT_CANARY";
    let prompt = format!("{prompt_canary} secret={secret}");
    let create = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new(&prompt))
        .send()
        .await
        .expect("create Session");
    assert_eq!(create.status(), StatusCode::ACCEPTED);
    let create_bytes = create.bytes().await.expect("read create response");
    let create_json: Value = serde_json::from_slice(&create_bytes).expect("parse create JSON");
    assert_eq!(create_json["schema_version"], "satelle.session.v1");
    assert!(create_json.get("session").is_none());
    assert!(create_json.get("session_id").is_some());
    assert_privacy_canaries_absent(
        "HTTP create Session response",
        &create_bytes,
        &[prompt_canary, secret],
    );
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

    let steer_secret = "PRIVATE_HTTP_STEER_SECRET_CANARY";
    let steer_prompt_canary = "PRIVATE_HTTP_STEER_PROMPT_CANARY";
    let steer_prompt = format!("{steer_prompt_canary} secret={steer_secret}");
    let steer = running
        .mutation(&format!("/v1/sessions/{session_id}/turns"), STEER_KEY)
        .json(&TurnRequest::new(&steer_prompt))
        .send()
        .await
        .expect("create follow-up Turn");
    assert_eq!(steer.status(), StatusCode::ACCEPTED);
    let steer_bytes = steer.bytes().await.expect("read steer response");
    assert_privacy_canaries_absent(
        "HTTP steer Session response",
        &steer_bytes,
        &[steer_prompt_canary, steer_secret],
    );
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

    let changed_secret = "PRIVATE_CHANGED_REPLAY_SECRET_CANARY";
    let changed_prompt_canary = "PRIVATE_CHANGED_REPLAY_PROMPT_CANARY";
    let changed_prompt = format!("{changed_prompt_canary} secret={changed_secret}");
    let conflict = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&TurnRequest::new(&changed_prompt))
        .send()
        .await
        .expect("send conflicting replay");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_bytes = conflict.bytes().await.expect("read conflict body");
    let error: ApiError = serde_json::from_slice(&conflict_bytes).expect("decode conflict");
    assert_eq!(error.code().as_str(), "idempotency-key-conflict");
    assert_privacy_canaries_absent(
        "HTTP idempotency conflict response",
        &conflict_bytes,
        &[changed_prompt_canary, changed_secret],
    );

    let mode_conflict = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(
            &TurnRequest::new("PRIVATE_REPLAY_PROMPT_CANARY")
                .with_execution_mode(TurnExecutionMode::Yolo),
        )
        .send()
        .await
        .expect("send changed-mode replay");
    assert_eq!(mode_conflict.status(), StatusCode::CONFLICT);
    let error: ApiError = mode_conflict
        .json()
        .await
        .expect("decode changed-mode conflict");
    assert_eq!(error.code().as_str(), "idempotency-key-conflict");

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
        let original_turn_id = created.session().turns()[0].turn_id().clone();

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

        let stale = client
            .stop_session_for_turn(&session_id, &original_turn_id, STALE_STOP_KEY)
            .expect_err("stale expected Turn must not retarget the newer Turn");
        match stale {
            DaemonClientError::Api { status, error } => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(error.code(), satelle_transport::ApiErrorCode::StateConflict);
            }
            other => panic!("expected stale-Turn conflict, got {other:?}"),
        }
        let latest_turn_id = steered
            .session()
            .turns()
            .last()
            .expect("steered Session has latest Turn")
            .turn_id()
            .clone();
        let stopped = client
            .stop_session_for_turn(&session_id, &latest_turn_id, STOP_KEY)
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
        .header("Satelle-Protocol-Version", "4")
        .json(&TurnRequest::new("PRIVATE_MISSING_KEY_CANARY"))
        .send()
        .await
        .expect("send missing-key request");
    assert_api_error(missing_key, StatusCode::BAD_REQUEST, "invalid-request").await;

    let wrong_schema = running
        .mutation("/v1/sessions", CREATE_KEY)
        .json(&serde_json::json!({
            "schema_version": "satelle.api.v1",
            "prompt": "PRIVATE_WRONG_SCHEMA_CANARY",
            "execution_mode": "standard"
        }))
        .send()
        .await
        .expect("send wrong schema");
    assert_api_error(wrong_schema, StatusCode::BAD_REQUEST, "unsupported-schema").await;

    let wrong_content_type = running
        .mutation("/v1/sessions", CREATE_KEY)
        .header("Content-Type", "text/plain")
        .body(
            r#"{"schema_version":"satelle.api.v2","prompt":"private","execution_mode":"standard"}"#,
        )
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
        .body(r#"{"schema_version":"satelle.api.v2","prompt":"first","prompt":"second","execution_mode":"standard"}"#)
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

    let invalid_model = running
        .mutation("/v1/sessions", "invalid-model-key")
        .json(&TurnRequest::new("private").with_provider_intent(
            Some(" ".to_owned()),
            None,
            false,
            false,
        ))
        .send()
        .await
        .expect("send invalid model override");
    assert_api_error_message(
        invalid_model,
        StatusCode::BAD_REQUEST,
        "invalid-request",
        "model override is invalid",
    )
    .await;

    let invalid_provider = running
        .mutation("/v1/sessions", "invalid-provider-key")
        .json(&TurnRequest::new("private").with_provider_intent(
            None,
            Some(" ".to_owned()),
            false,
            false,
        ))
        .send()
        .await
        .expect("send invalid provider override");
    assert_api_error_message(
        invalid_provider,
        StatusCode::BAD_REQUEST,
        "invalid-request",
        "provider override is invalid",
    )
    .await;

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
async fn fixed_size_attachments_precede_turn_request_deserialization() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let response = running
        .mutation("/v1/sessions", "attachment-limit-fixed-size")
        .json(&serde_json::json!({
            "schema_version": "satelle.api.v2",
            "prompt": "PRIVATE_ATTACHMENT_LIMIT_CANARY",
            "attachments": [{"name": "private.txt", "content": "private"}]
        }))
        .send()
        .await
        .expect("send fixed-size attachment request");

    assert_attachment_limit_error(response, &running.host_identity).await;
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
async fn attachment_limit_preserves_decoder_error_precedence() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let oversized = format!(
        r#"{{"schema_version":"satelle.api.v2","prompt":"PRIVATE_OVERSIZED_ATTACHMENT_CANARY","execution_mode":"standard","attachments":[{{"name":"private.txt"}}],"padding":"{}"}}"#,
        "x".repeat(1_048_576)
    );
    let cases = [
        (
            "wrong-schema",
            r#"{"schema_version":"satelle.api.v1","prompt":"PRIVATE_SCHEMA_ATTACHMENT_CANARY","execution_mode":"standard","attachments":[{"name":"private.txt"}]}"#.to_string(),
            UNSUPPORTED_SCHEMA_ERROR,
        ),
        (
            "duplicate-json-key",
            r#"{"schema_version":"satelle.api.v2","prompt":"PRIVATE_DUPLICATE_ATTACHMENT_CANARY","prompt":"duplicate","execution_mode":"standard","attachments":[{"name":"private.txt"}]}"#.to_string(),
            INVALID_JSON_ERROR,
        ),
        ("oversized-body", oversized, JSON_BODY_LIMIT_ERROR),
    ];

    for (name, body, expected) in cases {
        let response = running
            .mutation(
                "/v1/sessions",
                &format!("attachment-limit-precedence-{name}"),
            )
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap_or_else(|error| panic!("send {name} precedence request: {error}"));
        assert_exact_api_error(response, &running.host_identity, expected).await;
    }

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
async fn empty_and_non_array_attachments_remain_operation_contract_errors() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    for (name, attachments) in [
        ("empty-array", serde_json::json!([])),
        ("null", Value::Null),
        ("object", serde_json::json!({"name": "private.txt"})),
        ("string", serde_json::json!("private")),
    ] {
        let response = running
            .mutation(
                "/v1/sessions",
                &format!("attachment-operation-contract-{name}"),
            )
            .json(&serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "PRIVATE_ATTACHMENT_SHAPE_CANARY",
                "execution_mode": "standard",
                "attachments": attachments
            }))
            .send()
            .await
            .unwrap_or_else(|error| panic!("send {name} attachment request: {error}"));
        assert_exact_api_error(response, &running.host_identity, OPERATION_CONTRACT_ERROR).await;
    }

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
async fn create_turn_attachments_precede_deserialization_without_admission() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let created: SessionResponse = running
        .mutation("/v1/sessions", "attachment-limit-create-turn-session")
        .json(&TurnRequest::new("PRIVATE_ATTACHMENT_BASE_TURN_CANARY"))
        .send()
        .await
        .expect("create attachment-limit Session")
        .json()
        .await
        .expect("decode attachment-limit Session");
    let session_id = created.session().session_id().clone();
    let before = wait_until_idle(&running, session_id.as_str()).await;
    assert_eq!(before.session().turns().len(), 1);

    let response = running
        .mutation(
            &format!("/v1/sessions/{session_id}/turns"),
            "attachment-limit-create-turn",
        )
        .json(&serde_json::json!({
            "schema_version": "satelle.api.v2",
            "prompt": "PRIVATE_REJECTED_ATTACHMENT_TURN_CANARY",
            "attachments": [{"name": "private.txt", "content": "private"}]
        }))
        .send()
        .await
        .expect("send attachment follow-up Turn");
    assert_attachment_limit_error(response, &running.host_identity).await;

    let after: SessionResponse = running
        .request(&format!("/v1/sessions/{session_id}"))
        .send()
        .await
        .expect("read Session after rejected attachment Turn")
        .json()
        .await
        .expect("decode Session after rejected attachment Turn");
    assert_eq!(after.session(), before.session());
    assert_eq!(after.session().turns().len(), 1);
}

#[tokio::test]
async fn controller_only_fields_fail_before_create_session_admission_and_digest() {
    for field in ["attach", "detach"] {
        let running = RunningServer::start(ApiScopes::CONTROL).await;
        let idempotency_key = format!("controller-only-create-{field}");
        let rejected = running
            .mutation("/v1/sessions", &idempotency_key)
            .json(&turn_request_with_controller_field(
                field,
                "PRIVATE_CONTROLLER_ONLY_CREATE_REJECTED_CANARY",
            ))
            .send()
            .await
            .unwrap_or_else(|error| panic!("send rejected {field} create: {error}"));
        assert_exact_api_error(rejected, &running.host_identity, OPERATION_CONTRACT_ERROR).await;
        assert_eq!(
            running
                .service
                .initialize_daemon()
                .expect("read rejected create Session count")
                .session_count(),
            0,
            "Controller-only {field} reached create-session admission"
        );

        // Reusing the rejected request's key for the canonical payload proves
        // the rejected field never reached idempotency digest persistence.
        let accepted = running
            .mutation("/v1/sessions", &idempotency_key)
            .json(&TurnRequest::new(format!(
                "PRIVATE_CONTROLLER_ONLY_CREATE_ACCEPTED_{field}_CANARY"
            )))
            .send()
            .await
            .unwrap_or_else(|error| panic!("send canonical create after {field}: {error}"));
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let accepted: SessionResponse = accepted
            .json()
            .await
            .unwrap_or_else(|error| panic!("decode canonical create after {field}: {error}"));
        assert_eq!(accepted.session().turns().len(), 1);
        wait_until_idle(&running, accepted.session().session_id().as_str()).await;
    }
}

#[tokio::test]
async fn controller_only_fields_fail_before_create_turn_admission_and_digest() {
    for field in ["attach", "detach"] {
        let running = RunningServer::start(ApiScopes::CONTROL).await;
        let created: SessionResponse = running
            .mutation(
                "/v1/sessions",
                &format!("controller-only-turn-session-{field}"),
            )
            .json(&TurnRequest::new(format!(
                "PRIVATE_CONTROLLER_ONLY_TURN_BASE_{field}_CANARY"
            )))
            .send()
            .await
            .unwrap_or_else(|error| panic!("create {field} Turn baseline: {error}"))
            .json()
            .await
            .unwrap_or_else(|error| panic!("decode {field} Turn baseline: {error}"));
        let session_id = created.session().session_id().clone();
        let before = wait_until_idle(&running, session_id.as_str()).await;
        assert_eq!(before.session().turns().len(), 1);

        let idempotency_key = format!("controller-only-turn-{field}");
        let rejected = running
            .mutation(
                &format!("/v1/sessions/{session_id}/turns"),
                &idempotency_key,
            )
            .json(&turn_request_with_controller_field(
                field,
                "PRIVATE_CONTROLLER_ONLY_TURN_REJECTED_CANARY",
            ))
            .send()
            .await
            .unwrap_or_else(|error| panic!("send rejected {field} Turn: {error}"));
        assert_exact_api_error(rejected, &running.host_identity, OPERATION_CONTRACT_ERROR).await;

        let after_rejection: SessionResponse = running
            .request(&format!("/v1/sessions/{session_id}"))
            .send()
            .await
            .unwrap_or_else(|error| panic!("read Session after rejected {field} Turn: {error}"))
            .json()
            .await
            .unwrap_or_else(|error| panic!("decode Session after rejected {field} Turn: {error}"));
        assert_eq!(after_rejection.session(), before.session());
        assert_eq!(after_rejection.session().turns().len(), 1);

        // The same key remains available because ApiJson rejected the
        // Controller-only field before Host admission and digest persistence.
        let accepted = running
            .mutation(
                &format!("/v1/sessions/{session_id}/turns"),
                &idempotency_key,
            )
            .json(&TurnRequest::new(format!(
                "PRIVATE_CONTROLLER_ONLY_TURN_ACCEPTED_{field}_CANARY"
            )))
            .send()
            .await
            .unwrap_or_else(|error| panic!("send canonical Turn after {field}: {error}"));
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let accepted: SessionResponse = accepted
            .json()
            .await
            .unwrap_or_else(|error| panic!("decode canonical Turn after {field}: {error}"));
        assert_eq!(accepted.session().turns().len(), 2);
        wait_until_idle(&running, session_id.as_str()).await;
    }
}

#[test]
fn accepted_and_rejected_request_material_never_reaches_transport_or_durable_logs() {
    run_with_trace_capture(request_material_log_privacy);
}

async fn request_material_log_privacy(trace_capture: TraceCapture) {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let accepted_prompt = "PRIVATE_ACCEPTED_LOG_PROMPT_CANARY";
    let accepted_secret = "PRIVATE_ACCEPTED_LOG_SECRET_CANARY";
    let accepted_request_id = RequestId::new();
    let accepted = running
        .mutation_with_request_id(
            "/v1/sessions",
            "request-log-privacy-accepted",
            &accepted_request_id,
        )
        .json(&TurnRequest::new(format!(
            "{accepted_prompt} secret={accepted_secret}"
        )))
        .send()
        .await
        .expect("send accepted request-log privacy fixture");
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let accepted: SessionResponse = accepted
        .json()
        .await
        .expect("decode accepted request-log privacy fixture");
    wait_until_idle(&running, accepted.session().session_id().as_str()).await;

    let rejected_prompt = "PRIVATE_REJECTED_LOG_PROMPT_CANARY";
    let rejected_body = "PRIVATE_REJECTED_LOG_BODY_CANARY";
    let attachment_name = "PRIVATE_REJECTED_LOG_ATTACHMENT_NAME_CANARY";
    let attachment_bytes = "PRIVATE_REJECTED_LOG_ATTACHMENT_BYTES_CANARY";
    let rejected_request_id = RequestId::new();
    let rejected = running
        .mutation_with_request_id(
            "/v1/sessions",
            "request-log-privacy-rejected",
            &rejected_request_id,
        )
        .json(&serde_json::json!({
            "schema_version": "satelle.api.v2",
            "prompt": rejected_prompt,
            "execution_mode": "standard",
            "body_canary": rejected_body,
            "attachments": [{
                "name": attachment_name,
                "content": attachment_bytes
            }]
        }))
        .send()
        .await
        .expect("send rejected request-log privacy fixture");
    assert_attachment_limit_error(rejected, &running.host_identity).await;

    let exposed_token = running.token.expose();
    let raw_token = exposed_token.as_str().to_string();
    let authorization = format!("Bearer {raw_token}");
    let traces = trace_capture.bytes();
    assert_captured_host_admission_dispatch(&traces);
    assert_privacy_canaries_absent(
        "Host Daemon tracing sink",
        &traces,
        &[
            accepted_prompt,
            accepted_secret,
            rejected_prompt,
            rejected_body,
            attachment_name,
            attachment_bytes,
            raw_token.as_str(),
            authorization.as_str(),
        ],
    );

    // The public Host log page is a separate closed, durable audit surface.
    assert_returned_host_logs_exclude(
        &running,
        &[
            accepted_prompt,
            accepted_secret,
            rejected_prompt,
            rejected_body,
            attachment_name,
            attachment_bytes,
            raw_token.as_str(),
            authorization.as_str(),
        ],
    )
    .await;
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
    let is_mutation = method == Method::POST;
    let request = client
        .request(method, format!("http://{address}{path}"))
        .header("Authorization", authorization)
        .header("Satelle-Expected-Host-Identity", host_identity)
        .header("Satelle-Request-Id", RequestId::new().to_string());
    if is_mutation {
        request.header("Satelle-Protocol-Version", "4")
    } else {
        request
    }
}

pub(super) async fn assert_api_error(response: reqwest::Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let error: ApiError = response.json().await.expect("decode API error");
    assert_eq!(error.code().as_str(), code);
}

async fn assert_api_error_message(
    response: reqwest::Response,
    status: StatusCode,
    code: &str,
    message: &str,
) {
    assert_eq!(response.status(), status);
    let error: serde_json::Value = response.json().await.expect("decode API error");
    assert_eq!(error["code"], code);
    assert_eq!(error["message"], message);
}

async fn assert_attachment_limit_error(response: reqwest::Response, host_identity: &str) {
    assert_exact_api_error(response, host_identity, ATTACHMENT_LIMIT_ERROR).await;
}

fn turn_request_with_controller_field(field: &str, prompt: &str) -> Value {
    let mut request = serde_json::json!({
        "schema_version": "satelle.api.v2",
        "prompt": prompt,
        "execution_mode": "standard"
    });
    request
        .as_object_mut()
        .expect("Turn request fixture is an object")
        .insert(field.to_string(), serde_json::json!(true));
    request
}

async fn assert_returned_host_logs_exclude(running: &RunningServer, canaries: &[&str]) {
    let response = running
        .request("/v1/logs?mode=tail&limit=200&minimum_severity=info")
        .send()
        .await
        .expect("read Host logs after canary-bearing requests");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response
        .bytes()
        .await
        .expect("read Host log page after canary-bearing requests");
    assert_privacy_canaries_absent("returned Host logs", &bytes, canaries);
}

#[derive(Clone, Copy)]
struct ExpectedApiError {
    status: StatusCode,
    code: &'static str,
    category: &'static str,
    retryable: bool,
    message: &'static str,
}

const ATTACHMENT_LIMIT_ERROR: ExpectedApiError = ExpectedApiError {
    status: StatusCode::PAYLOAD_TOO_LARGE,
    code: "payload-too-large",
    category: "capacity",
    retryable: false,
    message: "the request exceeds the advertised attachment limit",
};

const JSON_BODY_LIMIT_ERROR: ExpectedApiError = ExpectedApiError {
    status: StatusCode::PAYLOAD_TOO_LARGE,
    code: "payload-too-large",
    category: "capacity",
    retryable: false,
    message: "the request body exceeds the advertised JSON body limit",
};

const UNSUPPORTED_SCHEMA_ERROR: ExpectedApiError = ExpectedApiError {
    status: StatusCode::BAD_REQUEST,
    code: "unsupported-schema",
    category: "invalid_request",
    retryable: false,
    message: "the request schema_version is unsupported",
};

const INVALID_JSON_ERROR: ExpectedApiError = ExpectedApiError {
    status: StatusCode::BAD_REQUEST,
    code: "invalid-request",
    category: "invalid_request",
    retryable: false,
    message: "the request body must be valid JSON",
};

const OPERATION_CONTRACT_ERROR: ExpectedApiError = ExpectedApiError {
    status: StatusCode::BAD_REQUEST,
    code: "invalid-request",
    category: "invalid_request",
    retryable: false,
    message: "the request body does not match the operation contract",
};

async fn assert_exact_api_error(
    response: reqwest::Response,
    host_identity: &str,
    expected: ExpectedApiError,
) {
    assert_eq!(response.status(), expected.status);
    assert_eq!(
        response.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    let error: Value = response.json().await.expect("decode exact API error");
    serde_json::from_value::<ApiError>(error.clone()).expect("decode closed API error contract");
    assert_eq!(error["schema_version"], "satelle.error.v1");
    assert_eq!(error["host_identity"], host_identity);
    assert_eq!(error["code"], expected.code);
    assert_eq!(error["category"], expected.category);
    assert_eq!(error["retryable"], expected.retryable);
    assert_eq!(error["message"], expected.message);
    assert_eq!(error["details"], Value::Null);
    assert_eq!(error["docs_url"], Value::Null);
    assert_eq!(error["suggested_commands"], serde_json::json!([]));
}
