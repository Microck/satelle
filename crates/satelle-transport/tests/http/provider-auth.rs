use super::*;
use satelle_core::{
    ProviderAuthValidationMode, ProviderBindingAuthorization, ProviderBindingSource,
    ProviderSecretSource,
};
use satelle_transport::{
    ProviderBindingAuthorizationRequest, ProviderBindingAuthorizationResponse,
    ProviderBindingDeletionResponse, ProviderDescriptorValidationRequest,
    ProviderDescriptorValidationResponse,
};

const VALIDATION_PATH: &str = "/v1/setup/provider-bindings/open_ai/vision/validate";
const AUTHORIZATION_PATH: &str = "/v1/setup/provider-bindings/open_ai/vision";

#[tokio::test]
async fn provider_binding_validation_requires_setup_or_control_authority() {
    let request = ProviderDescriptorValidationRequest::new(ProviderAuthValidationMode::Cached);

    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let unauthenticated = reqwest::Client::new()
        .post(control.url(VALIDATION_PATH))
        .header("Content-Type", "application/json")
        .header("Satelle-Protocol-Version", "8")
        .header("Satelle-Expected-Host-Identity", &control.host_identity)
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .header("Idempotency-Key", "provider-auth-unauthenticated")
        .json(&request)
        .send()
        .await
        .expect("send unauthenticated validation");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let read_only = RunningServer::start(ApiScopes::READ).await;
    let forbidden = read_only
        .mutation(VALIDATION_PATH, "provider-auth-read-only")
        .json(&request)
        .send()
        .await
        .expect("send validation without control authority");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bootstrap_admin_authorizes_and_control_validates_the_exact_path_aliases() {
    let state = TestStateDir::new().expect("create provider authorization state");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("create provider authorization service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        );
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let authorization = ProviderBindingAuthorizationRequest::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai"),
    );

    let authorized = reqwest::Client::new()
        .put(running.url(AUTHORIZATION_PATH))
        .header("Authorization", bearer(&bootstrap_token))
        .header("Satelle-Expected-Host-Identity", &running.host_identity)
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .header("Satelle-Protocol-Version", "8")
        .header("Idempotency-Key", "provider-authorization-admin")
        .json(&authorization)
        .send()
        .await
        .expect("send authorization as bootstrap admin");
    assert_eq!(authorized.status(), StatusCode::OK);
    let authorized = authorized
        .json::<ProviderBindingAuthorizationResponse>()
        .await
        .expect("decode provider authorization response");
    assert_eq!(authorized.binding().requested_model_alias(), "vision");
    assert_eq!(authorized.binding().requested_provider_alias(), "open_ai");
    assert_eq!(authorized.binding().model(), "gpt-5.6");
    assert_eq!(authorized.binding().model_provider(), "openai");
    assert_eq!(
        authorized.binding().source(),
        ProviderBindingSource::UserConfig
    );

    let validation = ProviderDescriptorValidationRequest::new(ProviderAuthValidationMode::Cached);
    let validated = running
        .mutation(VALIDATION_PATH, "provider-validation-control")
        .json(&validation)
        .send()
        .await
        .expect("send validation as control principal");
    assert_eq!(validated.status(), StatusCode::OK);
    let validated = validated
        .json::<ProviderDescriptorValidationResponse>()
        .await
        .expect("decode provider validation response");
    assert_eq!(
        validated.resolved_binding().requested_model_alias(),
        "vision"
    );
    assert_eq!(
        validated.resolved_binding().requested_provider_alias(),
        "open_ai"
    );
    assert_eq!(validated.resolved_binding().model(), "gpt-5.6");
    assert_eq!(validated.resolved_binding().model_provider(), "openai");
    assert_eq!(
        validated.resolved_binding().source(),
        ProviderBindingSource::UserConfig
    );
}

#[tokio::test]
async fn validation_rejects_descriptor_material_and_control_cannot_authorize() {
    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let raw_secret = "PRIVATE_PROVIDER_DESCRIPTOR_RAW_SECRET_CANARY";
    let descriptor = control
        .mutation(VALIDATION_PATH, "provider-validation-descriptor")
        .json(&serde_json::json!({
            "schema_version": "satelle.provider-binding-validation.v3",
            "mode": "cached",
            "endpoint": "https://attacker.example",
            "raw_secret": raw_secret
        }))
        .send()
        .await
        .expect("send descriptor-bearing validation");
    assert_eq!(descriptor.status(), StatusCode::BAD_REQUEST);
    let response_bytes = descriptor
        .bytes()
        .await
        .expect("read rejected descriptor response");
    assert!(
        !String::from_utf8_lossy(&response_bytes).contains(raw_secret),
        "rejected raw provider secret must not appear in response bytes"
    );

    let authorization = ProviderBindingAuthorizationRequest::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai"),
    );
    let forbidden = control
        .protected_request(reqwest::Method::PUT, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-authorization-control")
        .header("Satelle-Protocol-Version", "8")
        .json(&authorization)
        .send()
        .await
        .expect("send authorization as control principal");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}

fn bootstrap_mutation(
    running: &RunningServer,
    token: &ApiBearerToken,
    method: reqwest::Method,
    path: &str,
    idempotency_key: &str,
) -> reqwest::RequestBuilder {
    reqwest::Client::new()
        .request(method, running.url(path))
        .header("Authorization", bearer(token))
        .header("Satelle-Expected-Host-Identity", &running.host_identity)
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .header("Satelle-Protocol-Version", "8")
        .header("Idempotency-Key", idempotency_key)
}

async fn stop_provider_auth_server(running: RunningServer) -> TestStateDir {
    let RunningServer {
        _state,
        service,
        server,
        ..
    } = running;
    server
        .shutdown()
        .await
        .expect("shut down provider auth server");
    drop(service);
    _state
}

fn bootstrap_service(state: &TestStateDir, token: &ApiBearerToken) -> HostService {
    HostService::local_demo_for_tests_at(state.path())
        .expect("reopen provider authorization service")
        .with_ssh_bootstrap_auth_for_tests(
            token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        )
}

#[tokio::test]
async fn provider_binding_mutations_require_bootstrap_admin() {
    let authorization = ProviderBindingAuthorizationRequest::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai"),
    );

    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let forbidden_delete = control
        .protected_request(reqwest::Method::DELETE, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-delete-control")
        .header("Satelle-Protocol-Version", "8")
        .send()
        .await
        .expect("send deletion as control principal");
    assert_eq!(forbidden_delete.status(), StatusCode::FORBIDDEN);

    let ordinary_admin = RunningServer::start(ApiScopes::ADMIN).await;
    let forbidden_authorization = ordinary_admin
        .protected_request(reqwest::Method::PUT, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-authorization-ordinary-admin")
        .header("Satelle-Protocol-Version", "8")
        .json(&authorization)
        .send()
        .await
        .expect("send authorization as ordinary admin principal");
    assert_eq!(forbidden_authorization.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn provider_binding_mutation_replay_and_conflict_survive_restart() {
    let state = TestStateDir::new().expect("create provider mutation state");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = bootstrap_service(&state, &bootstrap_token);
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let initial = ProviderBindingAuthorizationRequest::new(ProviderBindingAuthorization::new(
        "vision", "open_ai", "gpt-5.6", "openai",
    ));
    let replacement = ProviderBindingAuthorizationRequest::new(ProviderBindingAuthorization::new(
        "vision",
        "open_ai",
        "gpt-5.6-mini",
        "openai",
    ));

    let authorize = || {
        bootstrap_mutation(
            &running,
            &bootstrap_token,
            reqwest::Method::PUT,
            AUTHORIZATION_PATH,
            "provider-authorization-durable",
        )
        .json(&initial)
    };
    let first = authorize()
        .send()
        .await
        .expect("send initial authorization");
    assert_eq!(first.status(), StatusCode::OK);
    let replay = authorize()
        .send()
        .await
        .expect("replay initial authorization");
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = replay
        .json::<ProviderBindingAuthorizationResponse>()
        .await
        .expect("decode authorization replay");
    assert_eq!(replay.binding().model(), "gpt-5.6");

    let conflict = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authorization-durable",
    )
    .json(&replacement)
    .send()
    .await
    .expect("send conflicting authorization");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let deleted = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::DELETE,
        AUTHORIZATION_PATH,
        "provider-deletion-durable",
    )
    .send()
    .await
    .expect("delete authorized binding");
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(
        deleted
            .json::<ProviderBindingDeletionResponse>()
            .await
            .expect("decode deletion result")
            .deleted()
    );
    let deletion_replay = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::DELETE,
        AUTHORIZATION_PATH,
        "provider-deletion-durable",
    )
    .send()
    .await
    .expect("replay deletion");
    assert!(
        deletion_replay
            .json::<ProviderBindingDeletionResponse>()
            .await
            .expect("decode deletion replay")
            .deleted()
    );

    let state = stop_provider_auth_server(running).await;
    let service = bootstrap_service(&state, &bootstrap_token);
    let restarted = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let authorization_replay = bootstrap_mutation(
        &restarted,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authorization-durable",
    )
    .json(&initial)
    .send()
    .await
    .expect("replay authorization after restart");
    assert_eq!(authorization_replay.status(), StatusCode::OK);
    let deletion_replay = bootstrap_mutation(
        &restarted,
        &bootstrap_token,
        reqwest::Method::DELETE,
        AUTHORIZATION_PATH,
        "provider-deletion-durable",
    )
    .send()
    .await
    .expect("replay deletion after restart");
    assert!(
        deletion_replay
            .json::<ProviderBindingDeletionResponse>()
            .await
            .expect("decode restarted deletion replay")
            .deleted()
    );
}

#[tokio::test]
async fn authorization_is_checked_before_the_durable_mutation_claim() {
    let state = TestStateDir::new().expect("create provider authority state");
    let token = ApiBearerToken::generate().expect("generate shared token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("create provider authority service");
    service
        .initialize_daemon()
        .expect("initialize provider authority service");
    service
        .register_api_token(&token, "shared-provider-principal", ApiScopes::ADMIN, None)
        .expect("register ordinary admin token");
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let initial = ProviderBindingAuthorizationRequest::new(ProviderBindingAuthorization::new(
        "vision",
        "open_ai",
        "gpt-forbidden",
        "openai",
    ));
    let rejected_before_protocol = running
        .protected_request(reqwest::Method::PUT, AUTHORIZATION_PATH)
        .body("{")
        .send()
        .await
        .expect("reject ordinary admin before protocol and body processing");
    assert_eq!(rejected_before_protocol.status(), StatusCode::FORBIDDEN);
    let rejected_before_body = running
        .protected_request(reqwest::Method::PUT, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-authority-before-body")
        .header("Satelle-Protocol-Version", "8")
        .body("{")
        .send()
        .await
        .expect("reject ordinary admin before body processing");
    assert_eq!(rejected_before_body.status(), StatusCode::FORBIDDEN);
    let forbidden = bootstrap_mutation(
        &running,
        &token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authority-before-claim",
    )
    .json(&initial)
    .send()
    .await
    .expect("send forbidden ordinary admin authorization");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let state = stop_provider_auth_server(running).await;
    let service = bootstrap_service(&state, &token);
    let restarted = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let authorized = ProviderBindingAuthorizationRequest::new(ProviderBindingAuthorization::new(
        "vision",
        "open_ai",
        "gpt-authorized",
        "openai",
    ));
    let response = bootstrap_mutation(
        &restarted,
        &token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authority-before-claim",
    )
    .json(&authorized)
    .send()
    .await
    .expect("send authorized bootstrap mutation with reused key");
    assert_eq!(response.status(), StatusCode::OK);
    let response = response
        .json::<ProviderBindingAuthorizationResponse>()
        .await
        .expect("decode authorized binding");
    assert_eq!(response.binding().model(), "gpt-authorized");
}

fn collect_state_bytes(path: &std::path::Path, bytes: &mut Vec<u8>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("read Host state directory") {
            collect_state_bytes(&entry.expect("read Host state entry").path(), bytes);
        }
    } else if path.is_file() {
        bytes.extend(std::fs::read(path).expect("read Host state file"));
    }
}

#[tokio::test]
async fn binding_mutations_do_not_resolve_secret_or_contact_provider_endpoint() {
    let state = TestStateDir::new().expect("create provider privacy state");
    let state_path = state.path().to_path_buf();
    let secret_directory = TestStateDir::new().expect("create isolated provider secret directory");
    let secret_path = secret_directory.path().join("provider-token");
    let secret_canary = "PRIVATE_PROVIDER_MUTATION_SECRET_CANARY";
    std::fs::write(&secret_path, secret_canary).expect("write provider secret canary");
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind attacker provider listener");
    let endpoint = format!("https://{}/provider", listener.local_addr().unwrap());
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = bootstrap_service(&state, &bootstrap_token);
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let authorization = ProviderBindingAuthorizationRequest::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-private", "openai")
            .with_endpoint(endpoint)
            .with_auth_source(ProviderSecretSource::File { path: secret_path })
            .with_experimental_provider_computer_use(true),
    );

    let authorized = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-private-authorization",
    )
    .json(&authorization)
    .send()
    .await
    .expect("authorize private provider binding");
    assert_eq!(authorized.status(), StatusCode::OK);
    let authorized_bytes = authorized
        .bytes()
        .await
        .expect("read authorization response");
    assert!(!String::from_utf8_lossy(&authorized_bytes).contains(secret_canary));

    let deleted = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::DELETE,
        AUTHORIZATION_PATH,
        "provider-private-deletion",
    )
    .send()
    .await
    .expect("delete private provider binding");
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted_bytes = deleted.bytes().await.expect("read deletion response");
    assert!(!String::from_utf8_lossy(&deleted_bytes).contains(secret_canary));

    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "binding mutations must not connect to the provider endpoint"
    );

    let logs = running
        .request("/v1/logs")
        .send()
        .await
        .expect("read Host logs");
    let log_bytes = logs.bytes().await.expect("read Host log bytes");
    assert!(!String::from_utf8_lossy(&log_bytes).contains(secret_canary));

    let mut state_bytes = Vec::new();
    collect_state_bytes(&state_path, &mut state_bytes);
    assert!(
        !String::from_utf8_lossy(&state_bytes).contains(secret_canary),
        "resolved provider secret bytes must not enter durable Host state"
    );
}

#[tokio::test]
async fn failed_provider_binding_authorization_replays_after_recovery_and_restart() {
    let state = TestStateDir::new().expect("create failed provider mutation state");
    let state_path = state.path().to_path_buf();
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = bootstrap_service(&state, &bootstrap_token);
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let connection =
        rusqlite::Connection::open(state_path.join("satelle.sqlite3")).expect("open Host SQLite");
    connection
        .execute_batch(
            "CREATE TRIGGER fail_provider_binding_authorization
             BEFORE INSERT ON authorized_provider_bindings
             BEGIN
                 SELECT RAISE(ABORT, 'forced-provider-binding-failure');
             END;",
        )
        .expect("install deterministic provider mutation failure");
    let initial = ProviderBindingAuthorizationRequest::new(ProviderBindingAuthorization::new(
        "vision",
        "open_ai",
        "gpt-failed",
        "openai",
    ));
    let replacement = ProviderBindingAuthorizationRequest::new(ProviderBindingAuthorization::new(
        "vision",
        "open_ai",
        "gpt-changed",
        "openai",
    ));

    let failed = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authorization-failed",
    )
    .json(&initial)
    .send()
    .await
    .expect("send deterministically failed authorization");
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    connection
        .execute_batch("DROP TRIGGER fail_provider_binding_authorization;")
        .expect("remove deterministic provider mutation failure");

    let replay = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authorization-failed",
    )
    .json(&initial)
    .send()
    .await
    .expect("replay failed authorization after recovery");
    assert_eq!(replay.status(), StatusCode::SERVICE_UNAVAILABLE);

    drop(connection);
    let state = stop_provider_auth_server(running).await;
    let service = bootstrap_service(&state, &bootstrap_token);
    let restarted = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let restarted_replay = bootstrap_mutation(
        &restarted,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authorization-failed",
    )
    .json(&initial)
    .send()
    .await
    .expect("replay failed authorization after restart");
    assert_eq!(restarted_replay.status(), StatusCode::SERVICE_UNAVAILABLE);
    let conflict = bootstrap_mutation(
        &restarted,
        &bootstrap_token,
        reqwest::Method::PUT,
        AUTHORIZATION_PATH,
        "provider-authorization-failed",
    )
    .json(&replacement)
    .send()
    .await
    .expect("send conflicting payload after failed replay");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}
