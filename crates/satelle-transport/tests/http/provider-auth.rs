use super::*;
use satelle_core::{
    ProviderAuthValidationMode, ProviderBindingAuthorization, ProviderBindingSource,
    ProviderSecretSource,
};
use satelle_transport::{
    ProviderBindingAuthorizationRequest, ProviderBindingAuthorizationResponse,
    ProviderBindingDeletionResponse, ProviderDescriptorValidationRequest,
    ProviderDescriptorValidationResponse, ProviderSecretProvisioningMetadata,
};
use zeroize::Zeroizing;

const VALIDATION_PATH: &str = "/v1/setup/provider-bindings/open_ai/vision/validate";
const AUTHORIZATION_PATH: &str = "/v1/setup/provider-bindings/open_ai/vision";
const PROVIDER_SECRET_PATH: &str = "/v1/setup/provider-secret";
const PROVIDER_SECRET_PREVIEW_PATH: &str = "/v1/setup/provider-secret/preview";
const PROVIDER_SECRET_METADATA_HEADER: &str = "Satelle-Provider-Secret-Metadata";
const PROVIDER_SECRET_COMPLETED_OUTCOME: &str = "v1.provider_secret_provisioning.completed";

fn provider_secret_metadata(overwrite_authorized: bool) -> ProviderSecretProvisioningMetadata {
    ProviderSecretProvisioningMetadata::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai"),
        overwrite_authorized,
    )
}

fn provider_secret_file_metadata(path: std::path::PathBuf) -> ProviderSecretProvisioningMetadata {
    ProviderSecretProvisioningMetadata::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai")
            .with_auth_source(ProviderSecretSource::File { path }),
        false,
    )
}

fn copy_provider_secret_client_token(token: &ApiBearerToken) -> ApiBearerToken {
    let exposed = token.expose();
    ApiBearerToken::parse(exposed.as_str()).expect("copy provider secret client token")
}

fn provider_secret_client(
    address: SocketAddr,
    token: ApiBearerToken,
    host_identity: String,
) -> DaemonClient {
    DaemonClient::loopback(address, token, host_identity).expect("construct provider secret client")
}

#[tokio::test]
async fn provider_secret_preview_replays_without_consuming_upload_capacity() {
    let limit = NonZeroUsize::new(256).expect("test rate limit is nonzero");
    let admin = RunningServer::start_with_config(
        ApiScopes::ADMIN,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_api_rate_limits(ApiRateLimits::new(limit, limit, limit, limit)),
    )
    .await;
    let secret_directory = TestStateDir::new().expect("create provider secret directory");
    let metadata = provider_secret_file_metadata(secret_directory.path().join("provider-token"));
    let idempotency_key = "provider-secret-preview-replay";
    let mut original = None;

    // A broken implementation allocates one grant per retry and rejects the
    // 129th request at the pending-upload cap.
    for _ in 0..129 {
        let response = admin
            .mutation(PROVIDER_SECRET_PREVIEW_PATH, idempotency_key)
            .json(&metadata)
            .send()
            .await
            .expect("send replayed provider secret preview");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response
            .json::<serde_json::Value>()
            .await
            .expect("decode provider secret preview");
        body.as_object_mut()
            .expect("preview response is an object")
            .remove("request_id");
        if let Some(original) = &original {
            assert_eq!(&body, original);
        } else {
            original = Some(body);
        }
    }

    let conflicting = ProviderSecretProvisioningMetadata::new(
        metadata.authorization().clone(),
        !metadata.overwrite_authorized(),
    );
    let response = admin
        .mutation(PROVIDER_SECRET_PREVIEW_PATH, idempotency_key)
        .json(&conflicting)
        .send()
        .await
        .expect("send conflicting provider secret preview");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error = response
        .json::<serde_json::Value>()
        .await
        .expect("decode preview idempotency conflict");
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some("idempotency-key-conflict")
    );

    let response = admin
        .mutation(
            PROVIDER_SECRET_PREVIEW_PATH,
            "provider-secret-preview-fresh",
        )
        .json(&metadata)
        .send()
        .await
        .expect("send fresh provider secret preview");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "same-key retries must not exhaust pending upload capacity"
    );
}

#[derive(Debug, Eq, PartialEq)]
struct ProviderSecretPersistenceState {
    journal_rows: i64,
    status: String,
    durable_outcome: String,
    result_json: String,
}

impl ProviderSecretPersistenceState {
    fn assert_completed(&self) {
        assert_eq!(self.journal_rows, 0);
        assert_eq!(self.status, "terminal");
        assert_eq!(self.durable_outcome, PROVIDER_SECRET_COMPLETED_OUTCOME);
        assert!(!self.result_json.is_empty());
    }
}

fn provider_secret_persistence_state(
    state_path: &std::path::Path,
    idempotency_key: &str,
) -> ProviderSecretPersistenceState {
    let connection =
        rusqlite::Connection::open(state_path.join("satelle.sqlite3")).expect("open Host SQLite");
    let journal_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_secret_provisioning_journal",
            [],
            |row| row.get(0),
        )
        .expect("count provider secret journal rows");
    let (status, durable_outcome, result_json) = connection
        .query_row(
            "SELECT status, durable_outcome, result_json
             FROM idempotency_records
             WHERE operation = 'provider_secret_provisioning'
               AND idempotency_key = ?1",
            [idempotency_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("load completed provider secret idempotency record");
    ProviderSecretPersistenceState {
        journal_rows,
        status,
        durable_outcome,
        result_json,
    }
}

#[tokio::test]
async fn exact_prepared_provider_secret_replays_but_a_fresh_reseal_conflicts() {
    let state = TestStateDir::new().expect("create provider secret state");
    let service = HostService::local_demo_with_readiness_for_tests_at(state.path())
        .expect("create provider secret service");
    let admin = RunningServer::start_with_service(
        ApiScopes::ADMIN,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let secret_directory = TestStateDir::new().expect("create provider secret directory");
    let secret_path = secret_directory.path().join("provider-token");
    let state_path = admin._state.path().to_path_buf();
    let client_address = admin.server.local_addr();
    let client_token = copy_provider_secret_client_token(&admin.token);
    let client_host_identity = admin.host_identity.clone();

    tokio::task::spawn_blocking(move || {
        let client = provider_secret_client(client_address, client_token, client_host_identity);
        let metadata = provider_secret_file_metadata(secret_path.clone());
        let idempotency_key = "provider-secret-exact-envelope";
        let preview = client
            .preview_provider_secret_provisioning(&metadata, idempotency_key)
            .expect("preview provider secret provisioning");
        let prepared = client
            .prepare_provider_secret_provisioning(
                &preview,
                &metadata,
                Zeroizing::new(b"PRIVATE_PREPARED_PROVIDER_SECRET".to_vec()),
                idempotency_key,
            )
            .expect("prepare provider secret envelope");
        let resealed = client
            .prepare_provider_secret_provisioning(
                &preview,
                &metadata,
                Zeroizing::new(b"PRIVATE_PREPARED_PROVIDER_SECRET".to_vec()),
                idempotency_key,
            )
            .expect("freshly reseal identical logical inputs");

        // Commit the operation, then discard the response to model a caller
        // that cannot tell whether the Host applied the request.
        client
            .send_prepared_provider_secret_provisioning(&prepared)
            .expect("commit provider secret before losing the response");
        let persistence_after_commit =
            provider_secret_persistence_state(&state_path, idempotency_key);
        persistence_after_commit.assert_completed();

        client
            .send_prepared_provider_secret_provisioning(&prepared)
            .expect("replay the exact prepared envelope");
        assert_eq!(
            provider_secret_persistence_state(&state_path, idempotency_key),
            persistence_after_commit
        );

        let conflict = client
            .send_prepared_provider_secret_provisioning(&resealed)
            .expect_err("fresh ciphertext must conflict with the committed envelope");
        assert!(matches!(
            conflict,
            DaemonClientError::Api { status, error }
                if status == StatusCode::CONFLICT
                    && error.code() == ApiErrorCode::IdempotencyKeyConflict
        ));
        assert_eq!(
            provider_secret_persistence_state(&state_path, idempotency_key),
            persistence_after_commit
        );
        assert_eq!(
            std::fs::read_to_string(secret_path).expect("read provisioned secret"),
            "PRIVATE_PREPARED_PROVIDER_SECRET"
        );
    })
    .await
    .expect("join prepared provider secret replay test");
}

#[tokio::test]
async fn prepared_provider_secret_survives_send_error_and_replays_after_restart() {
    let state = TestStateDir::new().expect("create durable provider secret state");
    let state_path = state.path().to_path_buf();
    let secret_directory = TestStateDir::new().expect("create durable secret directory");
    let secret_path = secret_directory.path().join("provider-token");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = ready_bootstrap_service(&state, &bootstrap_token);
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let live_client_address = running.server.local_addr();
    let live_client_token = copy_provider_secret_client_token(&bootstrap_token);
    let live_client_host_identity = running.host_identity.clone();
    let unavailable_listener =
        std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("reserve unavailable address");
    let unavailable_address = unavailable_listener.local_addr().expect("read address");
    drop(unavailable_listener);
    let unavailable_token = copy_provider_secret_client_token(&bootstrap_token);
    let unavailable_host_identity = running.host_identity.clone();
    let first_secret_path = secret_path.clone();
    let first_state_path = state_path.clone();

    let (prepared, persistence_after_commit) = tokio::task::spawn_blocking(move || {
        let live_client = provider_secret_client(
            live_client_address,
            live_client_token,
            live_client_host_identity,
        );
        let unavailable_client = provider_secret_client(
            unavailable_address,
            unavailable_token,
            unavailable_host_identity,
        );
        let metadata = provider_secret_file_metadata(first_secret_path);
        let idempotency_key = "provider-secret-durable-envelope";
        let preview = live_client
            .preview_provider_secret_provisioning(&metadata, idempotency_key)
            .expect("preview durable provisioning");
        let prepared = live_client
            .prepare_provider_secret_provisioning(
                &preview,
                &metadata,
                Zeroizing::new(b"PRIVATE_DURABLE_PROVIDER_SECRET".to_vec()),
                idempotency_key,
            )
            .expect("prepare durable envelope");

        unavailable_client
            .send_prepared_provider_secret_provisioning(&prepared)
            .expect_err("unavailable daemon must reject the send");
        live_client
            .send_prepared_provider_secret_provisioning(&prepared)
            .expect("the same handle remains sendable after failure");
        let persistence = provider_secret_persistence_state(&first_state_path, idempotency_key);
        persistence.assert_completed();
        (prepared, persistence)
    })
    .await
    .expect("join initial provider secret send");

    let state = stop_provider_auth_server(running).await;
    let service = ready_bootstrap_service(&state, &bootstrap_token);
    let restarted = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let restarted_client_address = restarted.server.local_addr();
    let restarted_client_token = copy_provider_secret_client_token(&bootstrap_token);
    let restarted_client_host_identity = restarted.host_identity.clone();

    tokio::task::spawn_blocking(move || {
        let restarted_client = provider_secret_client(
            restarted_client_address,
            restarted_client_token,
            restarted_client_host_identity,
        );
        restarted_client
            .send_prepared_provider_secret_provisioning(&prepared)
            .expect("replay exact envelope after Host restart");
        assert_eq!(
            provider_secret_persistence_state(&state_path, "provider-secret-durable-envelope"),
            persistence_after_commit
        );
        assert_eq!(
            std::fs::read_to_string(secret_path).expect("read durable provider secret"),
            "PRIVATE_DURABLE_PROVIDER_SECRET"
        );
    })
    .await
    .expect("join restarted provider secret replay");
}

#[tokio::test]
async fn provider_secret_provisioning_requires_admin_mutation_authority_before_body_dispatch() {
    let metadata =
        serde_json::to_string(&provider_secret_metadata(false)).expect("encode metadata");
    let secret_canary = "PRIVATE_PROVIDER_SECRET_AUTHORITY_CANARY";

    let read_only = RunningServer::start(ApiScopes::READ).await;
    let forbidden = read_only
        .mutation(PROVIDER_SECRET_PATH, "provider-secret-read-only")
        .header(
            "Content-Type",
            "application/vnd.satelle.provider-secret-upload+json",
        )
        .header(PROVIDER_SECRET_METADATA_HEADER, &metadata)
        .body(secret_canary)
        .send()
        .await
        .expect("send provider secret without admin authority");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let bytes = forbidden.bytes().await.expect("read forbidden response");
    assert!(!String::from_utf8_lossy(&bytes).contains(secret_canary));

    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let forbidden = control
        .mutation(PROVIDER_SECRET_PATH, "provider-secret-control")
        .header(
            "Content-Type",
            "application/vnd.satelle.provider-secret-upload+json",
        )
        .header(PROVIDER_SECRET_METADATA_HEADER, metadata)
        .body(secret_canary)
        .send()
        .await
        .expect("send provider secret with control-only authority");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let bytes = forbidden.bytes().await.expect("read forbidden response");
    assert!(!String::from_utf8_lossy(&bytes).contains(secret_canary));
}

#[tokio::test]
async fn provider_secret_preview_rejects_missing_file_source_without_side_effects() {
    let admin = RunningServer::start(ApiScopes::ADMIN).await;
    let raw_token = admin.token.expose();
    let host_identity = admin.host_identity.clone();
    let state = stop_provider_auth_server(admin).await;
    let metadata = provider_secret_metadata(false);
    let mut durable_before = Vec::new();
    collect_state_bytes(state.path(), &mut durable_before);

    let token =
        ApiBearerToken::parse(raw_token.as_str()).expect("restore the registered admin token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("reopen the provider preview Host service");
    let server = DaemonServer::bind(
        service.clone(),
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("restart the provider preview server");
    let admin = RunningServer {
        _state: state,
        service,
        server,
        token,
        host_identity,
    };

    let mut normalized = Vec::new();
    let mut request_ids = Vec::new();
    for _ in 0..2 {
        let response = admin
            .mutation(
                PROVIDER_SECRET_PREVIEW_PATH,
                "provider-secret-missing-file-source",
            )
            .json(&metadata)
            .send()
            .await
            .expect("send provider secret preview without a File source");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let mut body = response
            .json::<serde_json::Value>()
            .await
            .expect("decode provider secret preview failure");
        assert_eq!(
            body.pointer("/code").and_then(serde_json::Value::as_str),
            Some("provider-secret-source-required")
        );
        assert!(body.get("upload_id").is_none());
        assert!(body.get("recipient_public_key").is_none());
        request_ids.push(
            body.get("request_id")
                .and_then(serde_json::Value::as_str)
                .expect("failure includes its fresh request ID")
                .to_string(),
        );
        body.as_object_mut()
            .expect("API error is a JSON object")
            .remove("request_id");
        normalized.push(body);
    }
    assert_ne!(request_ids[0], request_ids[1]);
    assert_eq!(normalized[0], normalized[1]);

    let state = stop_provider_auth_server(admin).await;
    let mut durable_after = Vec::new();
    collect_state_bytes(state.path(), &mut durable_after);
    assert_eq!(durable_before, durable_after);
    assert!(!state_contains_provider_secret_sibling(state.path()));
}

fn state_contains_provider_secret_sibling(path: &std::path::Path) -> bool {
    std::fs::read_dir(path)
        .expect("read Host state directory")
        .filter_map(Result::ok)
        .any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                state_contains_provider_secret_sibling(&path)
            } else {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".staged.") || name.contains(".backup.")
            }
        })
}

#[tokio::test]
async fn provider_binding_validation_requires_setup_or_control_authority() {
    let request =
        ProviderDescriptorValidationRequest::new(ProviderAuthValidationMode::Cached, false, false);

    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let unauthenticated = reqwest::Client::new()
        .post(control.url(VALIDATION_PATH))
        .header("Content-Type", "application/json")
        .header("Satelle-Protocol-Version", "14")
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
        .header("Satelle-Protocol-Version", "14")
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

    let validation =
        ProviderDescriptorValidationRequest::new(ProviderAuthValidationMode::Cached, false, false);
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
async fn ssh_bootstrap_read_cannot_validate_provider_bindings() {
    let state = TestStateDir::new().expect("create bootstrap read state");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("create bootstrap read service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::READ,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        );
    let running = RunningServer::start_with_service(
        ApiScopes::CONTROL,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        service,
    )
    .await;
    let validation =
        ProviderDescriptorValidationRequest::new(ProviderAuthValidationMode::Cached, false, false);
    let forbidden = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::POST,
        VALIDATION_PATH,
        "provider-validation-bootstrap-read",
    )
    .json(&validation)
    .send()
    .await
    .expect("send validation as bootstrap read principal");

    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn validation_rejects_descriptor_material_and_control_cannot_authorize() {
    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let raw_secret = "PRIVATE_PROVIDER_DESCRIPTOR_RAW_SECRET_CANARY";
    let descriptor = control
        .mutation(VALIDATION_PATH, "provider-validation-descriptor")
        .json(&serde_json::json!({
            "schema_version": "satelle.provider-binding-validation.v5",
            "model_from_project": false,
            "provider_from_project": false,
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
        .header("Satelle-Protocol-Version", "14")
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
        .header("Satelle-Protocol-Version", "14")
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

fn ready_bootstrap_service(state: &TestStateDir, token: &ApiBearerToken) -> HostService {
    HostService::local_demo_with_readiness_for_tests_at(state.path())
        .expect("reopen provider secret service")
        .with_ssh_bootstrap_auth_for_tests(
            token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        )
}

#[tokio::test]
async fn provider_binding_mutations_require_admin() {
    let authorization = ProviderBindingAuthorizationRequest::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai"),
    );

    let control = RunningServer::start(ApiScopes::CONTROL).await;
    let forbidden_delete = control
        .protected_request(reqwest::Method::DELETE, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-delete-control")
        .header("Satelle-Protocol-Version", "14")
        .send()
        .await
        .expect("send deletion as control principal");
    assert_eq!(forbidden_delete.status(), StatusCode::FORBIDDEN);
    assert!(
        forbidden_delete
            .text()
            .await
            .expect("decode admin scope rejection")
            .contains("the API Principal does not have admin scope")
    );

    let ordinary_admin = RunningServer::start(ApiScopes::ADMIN).await;
    let authorized = ordinary_admin
        .protected_request(reqwest::Method::PUT, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-authorization-ordinary-admin")
        .header("Satelle-Protocol-Version", "14")
        .json(&authorization)
        .send()
        .await
        .expect("send authorization as ordinary admin principal");
    assert_eq!(authorized.status(), StatusCode::OK);

    let rejected_body = ordinary_admin
        .protected_request(reqwest::Method::DELETE, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-delete-body")
        .header("Satelle-Protocol-Version", "14")
        .json(&serde_json::json!({"unexpected": true}))
        .send()
        .await
        .expect("send deletion with an unsupported body");
    assert_eq!(rejected_body.status(), StatusCode::BAD_REQUEST);

    let rejected_oversized_body = ordinary_admin
        .protected_request(reqwest::Method::DELETE, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-delete-oversized-body")
        .header("Satelle-Protocol-Version", "14")
        .body(vec![b'x'; 2 * 1024 * 1024])
        .send()
        .await
        .expect("send deletion with an oversized body");
    assert_eq!(
        rejected_oversized_body.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );

    let deleted = ordinary_admin
        .protected_request(reqwest::Method::DELETE, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-delete-body")
        .header("Satelle-Protocol-Version", "14")
        .send()
        .await
        .expect("reuse the rejected body idempotency key");
    assert_eq!(deleted.status(), StatusCode::OK);

    let absent = ordinary_admin
        .protected_request(reqwest::Method::DELETE, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-delete-oversized-body")
        .header("Satelle-Protocol-Version", "14")
        .send()
        .await
        .expect("reuse the rejected oversized-body idempotency key");
    assert_eq!(absent.status(), StatusCode::OK);
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

    let path_conflict = bootstrap_mutation(
        &running,
        &bootstrap_token,
        reqwest::Method::PUT,
        "/v1/setup/provider-bindings/open_ai/other-model",
        "provider-authorization-durable",
    )
    .json(&initial)
    .send()
    .await
    .expect("send the same authorization to a different resource path");
    assert_eq!(path_conflict.status(), StatusCode::CONFLICT);

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
        .register_api_token(
            &token,
            "shared-provider-principal",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register ordinary control token");
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
        .expect("reject control authority before protocol and body processing");
    assert_eq!(rejected_before_protocol.status(), StatusCode::FORBIDDEN);
    let rejected_before_body = running
        .protected_request(reqwest::Method::PUT, AUTHORIZATION_PATH)
        .header("Idempotency-Key", "provider-authority-before-body")
        .header("Satelle-Protocol-Version", "14")
        .body("{")
        .send()
        .await
        .expect("reject control authority before body processing");
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
    .expect("send forbidden control authorization");
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
        let mut entries = std::fs::read_dir(path)
            .expect("read Host state directory")
            .map(|entry| entry.expect("read Host state entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for entry in entries {
            collect_state_bytes(&entry, bytes);
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

    let RunningServer {
        _state,
        service,
        server,
        ..
    } = running;
    server
        .shutdown()
        .await
        .expect("stop provider privacy daemon");
    drop(service);

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
