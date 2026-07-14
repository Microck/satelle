use super::*;
use crate::{EvidenceError, ProviderSmokeEvidence, ReadinessEvidence};

#[test]
fn operational_evidence_schema_is_migrated_atomically_to_version_two() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let connection = storage.connection_for_test();

    assert_eq!(2_i64, pragma_integer(connection, "user_version"));
    let versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(vec![1_i64, 2_i64], versions);
    for table in ["readiness_successes", "provider_smoke_successes"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing operational evidence table {table}");
    }
}

#[test]
fn version_one_store_upgrades_without_replacing_existing_state() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let expected_host = storage.host_identity().unwrap();
    storage
        .connection_for_test()
        .execute_batch(
            "DROP TABLE provider_smoke_successes;
             DROP TABLE readiness_successes;
             DELETE FROM schema_migrations WHERE version = 2;
             PRAGMA user_version = 1;",
        )
        .unwrap();
    drop(storage);

    let (storage, _) = Storage::open(state.path()).expect("upgrade version one store");
    assert_eq!(expected_host, storage.host_identity().unwrap());
    assert_eq!(
        2_i64,
        pragma_integer(storage.connection_for_test(), "user_version")
    );
}

#[test]
fn logically_corrupt_version_one_store_is_rejected_before_migration() {
    assert_version_one_corruption_rejected_before_migration(
        "DELETE FROM control_leases;",
        StorageErrorKind::IntegrityCheckFailed,
    );
}

#[test]
fn corrupt_sensitive_version_one_state_is_rejected_before_migration() {
    assert_version_one_corruption_rejected_before_migration(
        "UPDATE idempotency_hmac_keys SET created_at = 'not-a-time' WHERE retired_at IS NULL;",
        StorageErrorKind::InvalidStoredState,
    );
}

fn assert_version_one_corruption_rejected_before_migration(
    corruption_sql: &str,
    expected_error: StorageErrorKind,
) {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    storage
        .begin_session(
            &session,
            &admission(
                IdempotentOperation::Run,
                "run-before-migration",
                "request-before-migration",
                at(0),
            ),
        )
        .expect("admit an active Turn");
    storage
        .connection_for_test()
        .execute_batch(corruption_sql)
        .expect("corrupt version one state");
    storage
        .connection_for_test()
        .execute_batch(
            "DROP TABLE provider_smoke_successes;
             DROP TABLE readiness_successes;
             DELETE FROM schema_migrations WHERE version = 2;
             PRAGMA user_version = 1;",
        )
        .expect("create a logically corrupt version one store");
    drop(storage);

    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("a corrupt version one store must fail before migration"),
        Err(error) => error,
    };
    assert_eq!(expected_error, error.kind());

    let connection = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    assert_eq!(1_i64, pragma_integer(&connection, "user_version"));
    let applied_versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(vec![1_i64], applied_versions);
    for table in ["readiness_successes", "provider_smoke_successes"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !exists,
            "migration created {table} before rejecting corruption"
        );
    }
}

#[test]
fn failed_migration_rolls_back_partial_schema_and_preserves_existing_state() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let expected_host = storage.host_identity().unwrap();
    storage
        .connection_for_test()
        .execute_batch(
            "DROP TABLE provider_smoke_successes;
             DROP TABLE readiness_successes;
             DELETE FROM schema_migrations WHERE version = 2;
             PRAGMA user_version = 1;
             CREATE TABLE migration_sentinel (value TEXT NOT NULL) STRICT;
             INSERT INTO migration_sentinel (value) VALUES ('preserve-me');
             CREATE TRIGGER fail_migration_two_history
             BEFORE INSERT ON schema_migrations
             WHEN NEW.version = 2
             BEGIN
                 SELECT RAISE(ABORT, 'forced migration failure');
             END;",
        )
        .unwrap();
    drop(storage);

    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("a failed migration must not expose a partially migrated store"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::MigrationFailed, error.kind());

    let connection = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    assert_eq!(1_i64, pragma_integer(&connection, "user_version"));
    let applied_versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(vec![1_i64], applied_versions);
    for table in ["readiness_successes", "provider_smoke_successes"] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!exists, "partial migration table {table} must roll back");
    }
    let sentinel: String = connection
        .query_row("SELECT value FROM migration_sentinel", [], |row| row.get(0))
        .unwrap();
    assert_eq!("preserve-me", sentinel);
    let stored_host: String = connection
        .query_row("SELECT host_identity_ref FROM daemon_identity", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(expected_host.to_string(), stored_host);
}

#[test]
fn readiness_and_provider_results_round_trip_without_raw_evidence() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let observed_at = at(1);
    // Fixed-width integer timestamps must preserve a valid subsecond window.
    // Variable-width RFC3339 text would compare these two instants backward.
    let expires_at = observed_at + time::Duration::milliseconds(100);
    let desktop = DesktopBindingRef::new("desktop-binding-1").unwrap();
    let policy = ExecutionPolicy::new(
        EffectiveModelRef::new("computer-use-preview").unwrap(),
        ProviderBindingRef::new("openai").unwrap(),
        DesktopTarget::new(desktop.clone()),
        ApprovalPolicy::OnRequest,
        SandboxPolicy::WorkspaceWrite,
        TimeoutPolicy::bounded_seconds(120).unwrap(),
        ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Enabled),
    );
    let readiness = ReadinessEvidence::new(
        "readiness-1",
        "0.144.0",
        "1.0.0",
        Some("plugin-1.0.0"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        observed_at,
        expires_at,
    )
    .unwrap();
    let provider = ProviderSmokeEvidence::new(
        "provider-smoke-1",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        observed_at,
        expires_at,
    )
    .unwrap();
    storage
        .store_preflight_successes(
            "codex-native-computer-use",
            &desktop,
            &policy,
            &readiness,
            Some(&provider),
        )
        .expect("store preflight results atomically");
    storage
        .store_preflight_successes(
            "codex-native-computer-use",
            &desktop,
            &policy,
            &readiness,
            Some(&provider),
        )
        .expect("replaying identical evidence is idempotent");

    let second_readiness = ReadinessEvidence::new(
        "readiness-2",
        "0.144.0",
        "1.0.0",
        Some("plugin-1.0.0"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        observed_at,
        expires_at,
    )
    .unwrap();
    let conflicting_provider = ProviderSmokeEvidence::new(
        "provider-smoke-1",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        observed_at,
        expires_at + time::Duration::minutes(1),
    )
    .unwrap();
    let error = storage
        .store_preflight_successes(
            "codex-native-computer-use",
            &desktop,
            &policy,
            &second_readiness,
            Some(&conflicting_provider),
        )
        .expect_err("a conflicting provider result must roll back its readiness insert");
    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    let readiness_count: i64 = storage
        .connection_for_test()
        .query_row("SELECT count(*) FROM readiness_successes", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(1, readiness_count);
    let provider_count: i64 = storage
        .connection_for_test()
        .query_row("SELECT count(*) FROM provider_smoke_successes", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(1, provider_count);
    storage.checkpoint_for_test();
    let bytes = fs::read(state.path().join(DATABASE_FILE_NAME)).unwrap();
    assert!(!contains_bytes(&bytes, b"raw stdout"));
    assert!(!contains_bytes(&bytes, b"raw stderr"));
}

#[test]
fn operational_fingerprints_reject_non_digest_values() {
    let error = ReadinessEvidence::new(
        "readiness-1",
        "0.144.0",
        "1.0.0",
        Some("plugin-1.0.0"),
        "raw-provider-secret",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        at(1),
        at(2),
    )
    .expect_err("fingerprints must be fixed-size lowercase digests");
    assert_eq!(EvidenceError::InvalidFingerprint, error);
}
