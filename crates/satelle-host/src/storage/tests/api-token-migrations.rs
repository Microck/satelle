use super::*;

fn version_sixteen_store_with_pending_journal(state: &TempDir) {
    let (storage, _) = Storage::open(state.path()).unwrap();
    let connection = storage.connection_for_test();
    let host_identity = storage.host_identity().unwrap();
    connection
        .execute(
            "INSERT INTO idempotency_records (
            principal_ref, operation, idempotency_key, operation_id,
            request_digest, digest_schema_version, hmac_key_version,
            status, durable_outcome, created_at, expires_at
         ) VALUES ('principal-migration', 'provider_secret_provisioning', 'key-migration',
                   'operation-migration', ?1, 1, 1, 'in_progress',
                   'v1.provider_secret_provisioning.pending',
                   '2026-09-10T00:00:00Z', '2026-09-11T00:00:00Z')",
            ["a".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            r#"INSERT INTO provider_secret_provisioning_journal (
            operation_id, host_identity_ref, desktop_binding_ref, provider_probe_ref,
            requested_model_alias, requested_provider_alias, model, model_provider,
            auth_source_json, experimental_provider_computer_use,
            allow_project_selection, destination_path, staged_path,
            candidate_binding_digest, candidate_secret_hmac, phase, created_at, updated_at
         ) VALUES ('operation-migration', ?1, 'desktop-migration', 'probe-migration',
                   'model-alias', 'provider-alias', 'model', 'provider',
                   '{"kind":"file","path":"/private/provider.key"}', 1, 0,
                   '/private/provider.key', '/private/provider.key.staged', ?2, ?3, 'planned',
                   '2026-09-10T00:00:00Z', '2026-09-10T00:00:00Z')"#,
            params![host_identity.as_str(), "b".repeat(64), "c".repeat(64)],
        )
        .unwrap();
    // Recreate the actual predecessor CHECK constraints with a populated child
    // table. Merely changing user_version would not exercise the rebuild.
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    let predecessor = include_str!("../0013_provider_secret_provisioning.sql")
        .split("CREATE TABLE provider_secret_provisioning_journal (")
        .next()
        .unwrap();
    connection.execute_batch(predecessor).unwrap();
    connection
        .execute("DELETE FROM schema_migrations WHERE version = 17", [])
        .unwrap();
    connection.pragma_update(None, "user_version", 16).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
}

#[test]
fn token_migration_preserves_pending_provider_journal_and_foreign_key_enforcement() {
    let state = TempDir::new().unwrap();
    version_sixteen_store_with_pending_journal(&state);
    let storage = Storage::open_without_restart_recovery(state.path()).unwrap();
    let connection = storage.connection_for_test();
    let journal: (String, String, String) = connection
        .query_row(
            "SELECT journal.operation_id, journal.phase, replay.durable_outcome
         FROM provider_secret_provisioning_journal journal
         JOIN idempotency_records replay ON replay.operation_id = journal.operation_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        journal,
        (
            "operation-migration".into(),
            "planned".into(),
            "v1.provider_secret_provisioning.pending".into()
        )
    );
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1);
    assert!(connection.execute("UPDATE provider_secret_provisioning_journal SET host_identity_ref = 'missing-host'", []).is_err());
    let mut violations = connection.prepare("PRAGMA foreign_key_check").unwrap();
    assert!(violations.query([]).unwrap().next().unwrap().is_none());
}

#[test]
fn token_migration_rolls_back_before_committing_invalid_foreign_keys() {
    let state = TempDir::new().unwrap();
    version_sixteen_store_with_pending_journal(&state);
    let path = state.path().join("satelle.sqlite3");
    {
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(
            "CREATE TRIGGER corrupt_token_migration AFTER INSERT ON schema_migrations
             WHEN NEW.version = 17
             BEGIN UPDATE provider_secret_provisioning_journal SET host_identity_ref = 'missing-host'; END;"
        ).unwrap();
    }
    let error = match Storage::open_without_restart_recovery(state.path()) {
        Ok(_) => panic!("the invalid migration must fail before commit"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), StorageErrorKind::IntegrityCheckFailed);
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 16);
    let recorded: i64 = connection
        .query_row(
            "SELECT count(*) FROM schema_migrations WHERE version = 17",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(recorded, 0);
    let invalid: i64 = connection.query_row("SELECT count(*) FROM provider_secret_provisioning_journal WHERE host_identity_ref = 'missing-host'", [], |row| row.get(0)).unwrap();
    assert_eq!(invalid, 0);
}
