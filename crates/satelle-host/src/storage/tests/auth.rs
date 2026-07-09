use super::*;
use crate::ApiScopes;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const TOKEN_ID: &str = "token-01890a5d-ac96-7b7c-8f89-37c3d0a66e31";
const PRINCIPAL_ID: &str = "principal-01890a5d-ac96-7b7c-8f89-37c3d0a66e32";
const PAYLOAD_CANARY: &[u8] = b"PRIVATE_CANONICAL_PROMPT_PAYLOAD_CANARY";

#[test]
fn daemon_identity_and_idempotency_hmac_survive_restart() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, recovery) = Storage::open(state.path()).expect("open new storage");
    assert!(recovery.is_empty());

    let first_identity = storage.host_identity().expect("load Host Identity");
    let first_digest = storage
        .digest_idempotency_payload(PAYLOAD_CANARY)
        .expect("digest canonical payload");
    assert_eq!(first_digest.key_version(), 1);
    assert_eq!(first_digest.hex().len(), 64);
    drop(storage);

    let (storage, recovery) = Storage::open(state.path()).expect("reopen storage");
    assert!(recovery.is_empty());
    assert_eq!(
        first_identity,
        storage.host_identity().expect("reload Host Identity")
    );
    assert_eq!(
        first_digest,
        storage
            .digest_idempotency_payload(PAYLOAD_CANARY)
            .expect("recompute canonical digest")
    );

    storage.checkpoint_for_test();
    let database = fs::read(state.path().join("satelle.sqlite3")).expect("read test database");
    assert!(!contains_bytes(&database, PAYLOAD_CANARY));
}

#[test]
fn missing_sensitive_singletons_fail_closed_on_reopen() {
    for table in ["daemon_identity", "idempotency_hmac_keys"] {
        let state = TempDir::new().expect("temporary state directory");
        let (storage, _) = Storage::open(state.path()).expect("open storage");
        storage
            .connection
            .execute(&format!("DELETE FROM {table}"), [])
            .expect("remove singleton for corruption test");
        drop(storage);

        let error = match Storage::open(state.path()) {
            Ok(_) => panic!("missing singleton must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), StorageErrorKind::InvalidStoredState);
    }
}

#[test]
fn retired_hmac_keys_remain_usable_for_replay_digests() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let first = storage
        .digest_idempotency_payload(PAYLOAD_CANARY)
        .expect("digest with initial key");

    assert_eq!(
        storage
            .rotate_idempotency_hmac_key(OffsetDateTime::now_utc() + time::Duration::seconds(1),)
            .expect("rotate HMAC key"),
        2
    );
    let active = storage
        .digest_idempotency_payload(PAYLOAD_CANARY)
        .expect("digest with active key");
    let replay = storage
        .digest_idempotency_payload_with_key(PAYLOAD_CANARY, first.key_version())
        .expect("digest with retained key");

    assert_eq!(active.key_version(), 2);
    assert_ne!(active, first);
    assert_eq!(replay, first);
}

#[test]
fn token_authentication_persists_only_the_canonical_verifier() {
    let state = TempDir::new().expect("temporary state directory");
    let registered_token = token(TOKEN_ID, 0x2a);
    let exposed = registered_token.expose();
    let expected_verifier = registered_token.verifier();
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .register_api_token(
            ApiTokenRegistration::new(
                &registered_token,
                PRINCIPAL_ID,
                1,
                ApiScopes::READ | ApiScopes::CONTROL,
                None,
                at(1),
            )
            .expect("valid token registration"),
        )
        .expect("register token verifier");

    let stored: Vec<u8> = storage
        .connection
        .query_row(
            "SELECT verifier FROM api_tokens WHERE token_id = ?1",
            [TOKEN_ID],
            |row| row.get(0),
        )
        .expect("read stored verifier");
    assert_eq!(stored, expected_verifier.as_bytes());
    let principal = storage
        .authenticate_api_token(&registered_token, at(2))
        .expect("authenticate token")
        .expect("token should match");
    assert_eq!(principal.token_id(), TOKEN_ID);
    assert_eq!(principal.principal_ref(), PRINCIPAL_ID);
    assert_eq!(principal.credential_revision(), 1);
    assert!(principal.scopes().allows(ApiScopes::READ));
    assert!(principal.scopes().allows(ApiScopes::CONTROL));
    assert!(!principal.scopes().allows(ApiScopes::ADMIN));
    assert_eq!(principal.expires_at(), None);

    let wrong_secret = token(TOKEN_ID, 0x5a);
    assert!(
        storage
            .authenticate_api_token(&wrong_secret, at(2))
            .expect("reject wrong verifier")
            .is_none()
    );
    drop(storage);

    let (storage, _) = Storage::open(state.path()).expect("reopen storage");
    assert!(
        storage
            .authenticate_api_token(&registered_token, at(3))
            .expect("authenticate after restart")
            .is_some()
    );
    storage.checkpoint_for_test();
    let database = fs::read(state.path().join("satelle.sqlite3")).expect("read test database");
    assert!(!contains_bytes(&database, exposed.as_bytes()));
    assert!(!contains_bytes(&database, &[0x2a; 32]));
}

#[test]
fn token_rotation_is_atomic_and_invalidates_the_previous_secret() {
    let state = TempDir::new().expect("temporary state directory");
    let original = token(TOKEN_ID, 0x2a);
    let replacement = token(TOKEN_ID, 0x3b);
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .register_api_token(
            ApiTokenRegistration::new(
                &original,
                PRINCIPAL_ID,
                1,
                ApiScopes::ADMIN,
                Some(at(10)),
                at(1),
            )
            .expect("valid token registration"),
        )
        .expect("register token");
    let original_principal = storage
        .authenticate_api_token(&original, at(1))
        .expect("authenticate original token")
        .expect("original token is active");

    let rotated = storage
        .rotate_api_token(&replacement, 1, at(2))
        .expect("rotate token");
    assert_eq!(rotated.credential_revision(), 2);
    assert_eq!(rotated.expires_at(), Some(at(10)));
    assert!(rotated.scopes().allows(ApiScopes::READ));
    assert!(
        !storage
            .api_principal_is_active(&original_principal, at(3))
            .expect("check rotated principal")
    );
    assert!(
        storage
            .api_principal_is_active(&rotated, at(3))
            .expect("check replacement principal")
    );
    assert!(
        storage
            .authenticate_api_token(&original, at(3))
            .expect("old token lookup")
            .is_none()
    );
    assert_eq!(
        storage
            .authenticate_api_token(&replacement, at(3))
            .expect("new token lookup")
            .expect("new token authenticates")
            .credential_revision(),
        2
    );
    assert_eq!(
        storage
            .rotate_api_token(&original, 1, at(4))
            .expect_err("stale rotation must fail")
            .kind(),
        StorageErrorKind::StateConflict
    );
}

#[test]
fn expired_revoked_and_unknown_tokens_share_the_absent_result() {
    let state = TempDir::new().expect("temporary state directory");
    let registered = token(TOKEN_ID, 0x2a);
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .register_api_token(
            ApiTokenRegistration::new(
                &registered,
                PRINCIPAL_ID,
                1,
                ApiScopes::READ,
                Some(at(3)),
                at(1),
            )
            .expect("valid expiring registration"),
        )
        .expect("register token verifier");

    assert!(
        storage
            .authenticate_api_token(&registered, at(2))
            .expect("authenticate before expiry")
            .is_some()
    );
    assert!(
        storage
            .authenticate_api_token(&registered, at(3))
            .expect("reject at expiry")
            .is_none()
    );

    storage
        .revoke_api_token(TOKEN_ID, at(2))
        .expect("revoke token");
    assert!(
        storage
            .authenticate_api_token(&registered, at(2))
            .expect("reject revoked token")
            .is_none()
    );
    assert!(
        storage
            .authenticate_api_token(
                &token("token-01890a5d-ac96-7b7c-8f89-37c3d0a66e99", 0x7b),
                at(2),
            )
            .expect("reject unknown token")
            .is_none()
    );
}

fn token(token_id: &str, secret_byte: u8) -> ApiBearerToken {
    let encoded = URL_SAFE_NO_PAD.encode([secret_byte; 32]);
    ApiBearerToken::parse(&format!("satelle_v1.{token_id}.{encoded}"))
        .expect("fixed test token is valid")
}
