use super::*;
use satelle_transport::{
    NativeReadinessInvalidationRequest, NativeReadinessInvalidationResponse,
    SetupVerificationRequest, SetupVerificationResponse,
};

const VERIFY_PATH: &str = "/v1/setup/verify";
const INVALIDATE_PATH: &str = "/v1/setup/readiness/native/invalidate";

fn verification_request() -> SetupVerificationRequest {
    SetupVerificationRequest::new(None, None, false, false, false)
        .expect("construct setup verification request")
}

fn invalidation_request() -> NativeReadinessInvalidationRequest {
    NativeReadinessInvalidationRequest::new(None, None, false, false, false)
        .expect("construct native invalidation request")
}

#[tokio::test]
async fn setup_readiness_mutations_require_authenticated_control_scope() {
    let control = RunningServer::start(ApiScopes::CONTROL).await;
    for (path, body) in [
        (
            VERIFY_PATH,
            serde_json::to_value(verification_request()).unwrap(),
        ),
        (
            INVALIDATE_PATH,
            serde_json::to_value(invalidation_request()).unwrap(),
        ),
    ] {
        let unauthenticated = reqwest::Client::new()
            .post(control.url(path))
            .header("Content-Type", "application/json")
            .header("Satelle-Protocol-Version", "13")
            .header("Satelle-Expected-Host-Identity", &control.host_identity)
            .header("Satelle-Request-Id", RequestId::new().as_str())
            .header("Idempotency-Key", "setup-readiness-unauthenticated")
            .json(&body)
            .send()
            .await
            .expect("send unauthenticated setup readiness request");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    }

    let read_only = RunningServer::start(ApiScopes::READ).await;
    for (path, body, key) in [
        (
            VERIFY_PATH,
            serde_json::to_value(verification_request()).unwrap(),
            "setup-verification-read-only",
        ),
        (
            INVALIDATE_PATH,
            serde_json::to_value(invalidation_request()).unwrap(),
            "native-invalidation-read-only",
        ),
    ] {
        let forbidden = read_only
            .mutation(path, key)
            .json(&body)
            .send()
            .await
            .expect("send setup readiness request without control scope");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn setup_readiness_requests_reject_empty_unknown_and_unpaired_shapes() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let empty_invalidation = running
        .mutation(INVALIDATE_PATH, "native-invalidation-empty")
        .header("Content-Type", "application/json")
        .send()
        .await
        .expect("send empty invalidation request");
    assert_eq!(empty_invalidation.status(), StatusCode::BAD_REQUEST);

    for (path, key, body) in [
        (
            VERIFY_PATH,
            "setup-verification-unknown",
            serde_json::json!({
                "schema_version": "satelle.setup-verification.v1",
                "model_from_project": false,
                "provider_from_project": false,
                "experimental_provider_computer_use": false,
                "cache_key": "caller-controlled"
            }),
        ),
        (
            INVALIDATE_PATH,
            "native-invalidation-unpaired",
            serde_json::json!({
                "schema_version": "satelle.native-readiness-invalidation.v2",
                "scope": "intent",
                "model_alias": "vision",
                "model_from_project": false,
                "provider_from_project": false,
                "experimental_provider_computer_use": false
            }),
        ),
    ] {
        let response = running
            .mutation(path, key)
            .json(&body)
            .send()
            .await
            .expect("send invalid setup readiness request");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn native_invalidation_replays_and_conflicts_on_intent_fields() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let request_id = RequestId::new();
    let first = running
        .mutation_with_request_id(INVALIDATE_PATH, "native-invalidation-replay", &request_id)
        .json(&invalidation_request())
        .send()
        .await
        .expect("send native invalidation");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["satelle-request-id"], request_id.as_str());
    assert_eq!(
        first.headers()["satelle-host-identity"],
        running.host_identity
    );
    let body = first
        .json::<serde_json::Value>()
        .await
        .expect("decode native invalidation response");
    assert_eq!(body["request_id"], request_id.as_str());
    assert_eq!(body["host_identity"], running.host_identity);
    let first: NativeReadinessInvalidationResponse =
        serde_json::from_value(body).expect("decode typed native invalidation response");

    let replay = running
        .mutation(INVALIDATE_PATH, "native-invalidation-replay")
        .json(&invalidation_request())
        .send()
        .await
        .expect("replay native invalidation");
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        replay
            .json::<NativeReadinessInvalidationResponse>()
            .await
            .expect("decode native invalidation replay")
            .deleted(),
        first.deleted()
    );

    let conflict = running
        .mutation(INVALIDATE_PATH, "native-invalidation-replay")
        .json(
            &NativeReadinessInvalidationRequest::new(None, None, false, false, true)
                .expect("construct conflicting invalidation"),
        )
        .send()
        .await
        .expect("send conflicting native invalidation");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let scope_conflict = running
        .mutation(INVALIDATE_PATH, "native-invalidation-replay")
        .json(&NativeReadinessInvalidationRequest::host())
        .send()
        .await
        .expect("send conflicting host-wide native invalidation");
    assert_eq!(scope_conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn setup_verification_replay_digest_covers_every_behavior_field() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let request_id = RequestId::new();
    let first = running
        .mutation_with_request_id(VERIFY_PATH, "setup-verification-digest", &request_id)
        .json(&verification_request())
        .send()
        .await
        .expect("send setup verification");
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["satelle-request-id"], request_id.as_str());
    assert_eq!(
        first.headers()["satelle-host-identity"],
        running.host_identity
    );
    let body = first
        .json::<serde_json::Value>()
        .await
        .expect("decode setup verification response");
    assert_eq!(body["request_id"], request_id.as_str());
    assert_eq!(body["host_identity"], running.host_identity);
    let _: SetupVerificationResponse =
        serde_json::from_value(body).expect("decode typed setup verification response");

    let replay = running
        .mutation(VERIFY_PATH, "setup-verification-digest")
        .json(&verification_request())
        .send()
        .await
        .expect("replay setup verification");
    assert_eq!(replay.status(), StatusCode::OK);

    for conflicting in [
        SetupVerificationRequest::new(
            Some("vision".to_string()),
            Some("open_ai".to_string()),
            false,
            false,
            false,
        )
        .unwrap(),
        SetupVerificationRequest::new(None, None, true, false, false).unwrap(),
        SetupVerificationRequest::new(None, None, false, true, false).unwrap(),
        SetupVerificationRequest::new(None, None, false, false, true).unwrap(),
    ] {
        let conflict = running
            .mutation(VERIFY_PATH, "setup-verification-digest")
            .json(&conflicting)
            .send()
            .await
            .expect("send conflicting setup verification");
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
    }
}

#[tokio::test]
async fn setup_verification_uses_the_client_admission_timeout() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let token = ApiBearerToken::generate().expect("generate setup verification client token");
    running
        .service
        .register_api_token(
            &token,
            "setup-verification-client",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register setup verification client token");
    let address = running.server.local_addr();
    let host_identity = running.host_identity.clone();

    let error = tokio::task::spawn_blocking(move || {
        let client = DaemonClient::loopback(address, token, host_identity)?
            .with_admission_timeout(Duration::from_nanos(1));
        client.verify_setup(&verification_request(), "setup-verification-client-timeout")
    })
    .await
    .expect("join setup verification client")
    .expect_err("the admission deadline must bound setup verification");
    assert!(matches!(
        error,
        DaemonClientError::Transport(ref source) if source.is_timeout()
    ));
}
