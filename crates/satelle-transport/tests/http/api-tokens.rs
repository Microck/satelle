use super::*;
use serde_json::json;

#[tokio::test]
async fn concurrent_token_retries_expose_one_secret_and_keys_are_scoped_to_principals() {
    let running = RunningServer::start(ApiScopes::ADMIN).await;
    let body = json!({ "schema_version": "satelle.api-token.issue.v1", "scopes": ["read"] });
    let first = running
        .mutation("/v1/api-tokens", "shared-key")
        .json(&body)
        .send();
    let second = running
        .mutation("/v1/api-tokens", "shared-key")
        .json(&body)
        .send();
    let (first, second) = tokio::join!(first, second);
    let mut issued_id = None;
    let mut replayed_id = None;
    for response in [first.unwrap(), second.unwrap()] {
        let status = response.status();
        let response: Value = response.json().await.unwrap();
        match status {
            StatusCode::CREATED => {
                assert!(issued_id.is_none(), "only one request receives a secret");
                assert!(response["bearer_token"].is_string());
                issued_id = Some(response["token_id"].clone());
            }
            StatusCode::CONFLICT => {
                assert_eq!(response["code"], "token-secret-not-replayable");
                replayed_id = Some(response["details"]["token"]["token_id"].clone());
            }
            _ => panic!("unexpected token response: {status}"),
        }
    }
    assert!(issued_id.is_some());
    assert_eq!(issued_id, replayed_id);
    let another_admin = ApiBearerToken::generate().unwrap();
    running
        .service
        .register_api_token(&another_admin, "another-admin", ApiScopes::ADMIN, None)
        .unwrap();
    let response = setup_mutation_request(
        &reqwest::Client::new(),
        running.server.local_addr(),
        &another_admin,
        &running.host_identity,
        "/v1/api-tokens",
        "shared-key",
    )
    .json(&body)
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let response: Value = response.json().await.unwrap();
    assert_ne!(Some(response["token_id"].clone()), issued_id);
    running.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn admin_token_lifecycle_returns_secrets_once_and_invalidates_old_credentials() {
    let running = RunningServer::start(ApiScopes::ADMIN).await;
    let client = reqwest::Client::new();
    // The ordinary fixture already sets its admin Authorization header. Build
    // requests for issued credentials directly so each carries one token.
    let token_status = |secret: &str| {
        client
            .get(running.url("/v1/host/status"))
            .header("Authorization", format!("Bearer {secret}"))
            .header("Satelle-Expected-Host-Identity", &running.host_identity)
    };
    let issue_body = json!({ "schema_version": "satelle.api-token.issue.v1", "scopes": ["read"] });
    let response = running
        .mutation("/v1/api-tokens", "issue")
        .json(&issue_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let issued: Value = response.json().await.unwrap();
    assert_eq!(issued["schema_version"], "satelle.api-token.v1");
    let original = issued["bearer_token"].as_str().unwrap();
    let token_id = issued["token_id"].as_str().unwrap();
    assert_eq!(
        token_status(original).send().await.unwrap().status(),
        StatusCode::OK
    );
    let duplicate = running
        .mutation("/v1/api-tokens", "issue")
        .json(&issue_body)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    let duplicate: Value = duplicate.json().await.unwrap();
    assert_eq!(duplicate["code"], "token-secret-not-replayable");
    assert_eq!(duplicate["details"]["token"]["token_id"], token_id);
    assert!(!duplicate.to_string().contains(original));
    let rotate_path = format!("/v1/api-tokens/{token_id}/rotate");
    let rotate_body = json!({ "schema_version": "satelle.api-token.rotate.v1", "expected_credential_revision": 1 });
    let rotated = running
        .mutation(&rotate_path, "rotate")
        .json(&rotate_body)
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
    assert_eq!(rotated.headers()["cache-control"], "no-store");
    let rotated: Value = rotated.json().await.unwrap();
    assert_eq!(rotated["token_id"], issued["token_id"]);
    assert_eq!(rotated["principal_ref"], issued["principal_ref"]);
    assert_eq!(rotated["scopes"], issued["scopes"]);
    assert_eq!(rotated["credential_revision"], 2);
    let replacement = rotated["bearer_token"].as_str().unwrap();
    assert_ne!(replacement, original);
    for (secret, expected) in [
        (original, StatusCode::UNAUTHORIZED),
        (replacement, StatusCode::OK),
    ] {
        let status = token_status(secret).send().await.unwrap();
        assert_eq!(status.status(), expected);
    }
    let duplicate = running
        .mutation(&rotate_path, "rotate")
        .json(&rotate_body)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    let duplicate: Value = duplicate.json().await.unwrap();
    assert_eq!(duplicate["code"], "token-secret-not-replayable");
    assert!(!duplicate.to_string().contains(replacement));
    let stale = running
        .mutation(&rotate_path, "stale")
        .json(&rotate_body)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(
        stale.json::<Value>().await.unwrap()["code"],
        "api-token-state-conflict"
    );
    let revoke_path = format!("/v1/api-tokens/{token_id}/revoke");
    let revoke_body = json!({ "schema_version": "satelle.api-token.revoke.v1", "expected_credential_revision": 2 });
    for _ in 0..2 {
        let revoked = running
            .mutation(&revoke_path, "revoke")
            .json(&revoke_body)
            .send()
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::OK);
        let revoked: Value = revoked.json().await.unwrap();
        assert!(revoked["bearer_token"].is_null());
        assert!(revoked["revoked_at"].is_string());
    }
    let revoked = token_status(replacement).send().await.unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        running
            .request("/v1/host/status")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    running.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn token_management_requires_admin_scope_and_validates_expiry() {
    for scopes in [
        ApiScopes::READ,
        ApiScopes::CONTROL,
        ApiScopes::DIAGNOSTICS_SENSITIVE,
    ] {
        let running = RunningServer::start(scopes).await;
        let response = running
            .mutation("/v1/api-tokens", "denied")
            .json(&json!({
                "schema_version": "satelle.api-token.issue.v1", "scopes": ["admin"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.json::<Value>().await.unwrap()["code"],
            "authorization-insufficient-scope"
        );
        running.server.shutdown().await.unwrap();
    }
    let running = RunningServer::start(ApiScopes::ADMIN).await;
    for (key, scopes, expiry) in [
        ("empty", json!([]), Value::Null),
        ("unknown", json!(["superuser"]), Value::Null),
        ("expired", json!(["read"]), json!("2020-01-01T00:00:00Z")),
        (
            "offset",
            json!(["read"]),
            json!("2030-01-01T01:00:00+01:00"),
        ),
    ] {
        let response = running.mutation("/v1/api-tokens", key).json(&json!({
            "schema_version": "satelle.api-token.issue.v1", "scopes": scopes, "expires_at": expiry
        })).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    running.server.shutdown().await.unwrap();
}
