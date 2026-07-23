use super::*;
use crate::runtime::NativeProbeResult;
use crate::storage::{
    LeaseOwner, MaintenanceLeaseCapability, SetupActionPlan, SetupOperationKind, SetupRunPlan,
    SetupRunStatus,
};
use crate::{
    EvidenceError, ProviderSmokeEvidence, ProviderSmokeFailureEvidence, ProviderSmokeResult,
    ReadinessCacheKey, ReadinessEvidence,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn begin_maintenance(
    storage: &mut Storage,
    operation_id: &str,
    desktop_binding: Option<&str>,
    acquired_at: OffsetDateTime,
) -> MaintenanceLeaseCapability {
    let plan = SetupRunPlan::new(
        operation_id,
        SetupOperationKind::Repair,
        desktop_binding.map(|binding| DesktopBindingRef::new(binding).unwrap()),
        acquired_at,
        vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
    )
    .unwrap();
    storage
        .begin_setup_run(&plan, lease_owner(operation_id, acquired_at))
        .expect("setup admission atomically acquires maintenance ownership")
}

#[test]
fn operational_evidence_schema_is_migrated_atomically_to_version_eleven() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let connection = storage.connection_for_test();

    assert_eq!(11_i64, pragma_integer(connection, "user_version"));
    let versions = connection
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| row.get::<_, i64>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        vec![
            1_i64, 2_i64, 3_i64, 4_i64, 5_i64, 6_i64, 7_i64, 8_i64, 9_i64, 10_i64, 11_i64,
        ],
        versions
    );
    for table in [
        "sessions",
        "turns",
        "native_readiness_results",
        "provider_smoke_results",
        "setup_runs",
        "setup_actions",
        "logs",
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing operational evidence table {table}");
    }
    assert!(migration_backups(state.path()).is_empty());
}

#[test]
fn version_ten_operation_rows_upgrade_without_data_loss_or_foreign_key_damage() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open current storage");
    let operation_id = "preserved-setup";
    let plan = SetupRunPlan::new(
        operation_id,
        SetupOperationKind::Setup,
        None,
        at(1),
        vec![SetupActionPlan::new("preserved-action", "Preserve action", false).unwrap()],
    )
    .unwrap();
    let _capability = storage
        .begin_setup_run(&plan, lease_owner(operation_id, at(1)))
        .expect("persist a version ten setup ledger");
    storage
        .connection_for_test()
        .execute(
            "INSERT INTO idempotency_records (
                principal_ref, operation, idempotency_key, operation_id,
                request_digest, digest_schema_version, hmac_key_version,
                status, durable_outcome, created_at, expires_at
             ) VALUES ('preserved-principal', 'run', 'preserved-key',
                       'preserved-operation', ?1, 1, 1, 'in_progress',
                       'v1.turn.starting', ?2, ?3)",
            params![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                at(1).format(&Rfc3339).unwrap(),
                at(2).format(&Rfc3339).unwrap(),
            ],
        )
        .expect("persist a version ten idempotency record");
    storage
        .connection_for_test()
        .execute("DELETE FROM schema_migrations WHERE version = 11", [])
        .expect("remove version eleven history");
    storage
        .connection_for_test()
        .pragma_update(None, "user_version", 10)
        .expect("mark version ten source schema");
    drop(storage);

    let upgraded = Storage::open_without_restart_recovery(state.path())
        .expect("upgrade populated version ten storage");
    let connection = upgraded.connection_for_test();
    assert_eq!(11_i64, pragma_integer(connection, "user_version"));
    assert_eq!(
        ("run".to_string(), "in_progress".to_string()),
        connection
            .query_row(
                "SELECT operation, status FROM idempotency_records
                 WHERE principal_ref = 'preserved-principal'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load migrated idempotency record")
    );
    assert_eq!(
        (
            "setup".to_string(),
            "preserved-action".to_string(),
            "planned".to_string(),
        ),
        connection
            .query_row(
                "SELECT setup_runs.operation_kind, setup_actions.action_id,
                        setup_actions.status
                 FROM setup_runs
                 JOIN setup_actions ON setup_actions.run_id = setup_runs.run_id
                 WHERE setup_runs.run_id = ?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load migrated setup ledger")
    );
    let foreign_key_violations = connection
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare foreign-key check")
        .query_map([], |_| Ok(()))
        .expect("run foreign-key check")
        .count();
    assert_eq!(0, foreign_key_violations);
}

#[test]
fn durable_operation_vocabularies_are_closed_over_pr04_mutations() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let connection = storage.connection_for_test();
    let idempotent_operations = [
        (IdempotentOperation::Run, "run"),
        (IdempotentOperation::Steer, "steer"),
        (IdempotentOperation::Stop, "stop"),
        (IdempotentOperation::Setup, "setup"),
        (IdempotentOperation::Repair, "repair"),
        (IdempotentOperation::HostUpdate, "host_update"),
        (IdempotentOperation::StorageMigration, "storage_migration"),
        (
            IdempotentOperation::DestructiveMaintenance,
            "destructive_maintenance",
        ),
    ];
    for (operation, token) in idempotent_operations {
        assert_eq!(
            token,
            crate::storage::codec::idempotent_operation_token(operation)
        );
        connection
            .execute(
                "INSERT INTO idempotency_records (
                    principal_ref, operation, idempotency_key, operation_id,
                    request_digest, digest_schema_version, hmac_key_version,
                    status, durable_outcome, created_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, 'in_progress',
                           'v1.turn.starting', ?6, ?7)",
                params![
                    format!("principal-{token}"),
                    token,
                    format!("key-{token}"),
                    format!("operation-{token}"),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    at(1).format(&Rfc3339).unwrap(),
                    at(2).format(&Rfc3339).unwrap(),
                ],
            )
            .unwrap_or_else(|error| panic!("persist {token}: {error}"));
    }
    assert!(
        connection
            .execute(
                "INSERT INTO idempotency_records (
                    principal_ref, operation, idempotency_key, operation_id,
                    request_digest, digest_schema_version, hmac_key_version,
                    status, durable_outcome, created_at, expires_at
                 ) VALUES ('principal-unknown', 'unknown', 'key-unknown',
                           'operation-unknown', ?1, 1, 1, 'in_progress',
                           'v1.turn.starting', ?2, ?3)",
                params![
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    at(1).format(&Rfc3339).unwrap(),
                    at(2).format(&Rfc3339).unwrap(),
                ],
            )
            .is_err()
    );

    for (kind, token) in [
        (SetupOperationKind::Setup, "setup"),
        (SetupOperationKind::Repair, "repair"),
        (SetupOperationKind::HostUpdate, "host_update"),
        (SetupOperationKind::StorageMigration, "storage_migration"),
        (SetupOperationKind::ServiceStop, "service_stop"),
        (SetupOperationKind::ServiceRestart, "service_restart"),
    ] {
        let state = TempDir::new().expect("maintenance state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open maintenance storage");
        let operation_id = format!("maintenance-{token}");
        let plan = SetupRunPlan::new(
            &operation_id,
            kind,
            None,
            at(1),
            vec![SetupActionPlan::new("mutate", "Mutate host state", false).unwrap()],
        )
        .unwrap();
        let capability = storage
            .begin_setup_run(&plan, lease_owner(&operation_id, at(1)))
            .expect("acquire Maintenance Lease before mutation");
        let stored = storage
            .load_setup_run(&operation_id)
            .unwrap()
            .expect("load durable maintenance run");
        assert_eq!(kind, stored.operation_kind());
        assert_eq!(
            (token.to_string(), 1_i64, "planned".to_string()),
            storage
                .connection_for_test()
                .query_row(
                    "SELECT operation_kind,
                            (SELECT count(*) FROM maintenance_leases
                             WHERE operation_id = setup_runs.run_id),
                            (SELECT status FROM setup_actions
                             WHERE setup_actions.run_id = setup_runs.run_id)
                     FROM setup_runs WHERE run_id = ?1",
                    [&operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap()
        );
        storage
            .start_setup_action(&capability, "mutate", at(2))
            .expect("the acquired capability authorizes the first mutation");
        assert!(
            storage
                .connection_for_test()
                .execute(
                    "UPDATE setup_runs SET operation_kind = 'unknown' WHERE run_id = ?1",
                    [&operation_id],
                )
                .is_err()
        );
    }
}

#[test]
fn newer_schema_history_is_rejected_without_downgrade() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open current storage");
    storage
        .connection_for_test()
        .execute(
            "INSERT INTO schema_migrations (version, checksum, applied_at)
             VALUES (12, ?1, '2026-07-21T00:00:00Z')",
            ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )
        .expect("insert future migration");
    storage
        .connection_for_test()
        .pragma_update(None, "user_version", 12)
        .expect("mark future schema");
    drop(storage);

    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("future schema must not be downgraded"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), StorageErrorKind::MigrationIntegrity);
    let connection = Connection::open(state.path().join(DATABASE_FILE_NAME))
        .expect("future database remains readable");
    assert_eq!(pragma_integer(&connection, "user_version"), 12);
}

#[test]
fn version_seven_api_tokens_upgrade_to_explicit_active_state() {
    let state = TempDir::new().expect("temporary state directory");
    let existing_token = crate::ApiBearerToken::generate().expect("generate existing token");
    let existing_token_id = existing_token.token_id().to_string();
    let (mut storage, _) = Storage::open(state.path()).expect("open current storage");
    storage
        .register_api_token(
            ApiTokenRegistration::new(
                &existing_token,
                "existing-principal",
                1,
                crate::ApiScopes::CONTROL,
                None,
                at(1),
            )
            .expect("construct existing token registration"),
        )
        .expect("register existing token");
    storage
        .connection_for_test()
        .execute_batch(
            "DROP TABLE admission_cancellations;
             DROP INDEX one_session_per_upstream_goal_ref;
             ALTER TABLE sessions DROP COLUMN display_name;
             ALTER TABLE session_private_refs DROP COLUMN upstream_goal_ref;
             ALTER TABLE api_tokens DROP COLUMN token_state;
             DELETE FROM schema_migrations WHERE version IN (8, 9, 10, 11);
             PRAGMA user_version = 7;",
        )
        .expect("recreate the version seven token schema");
    drop(storage);

    let (storage, _) = Storage::open(state.path()).expect("upgrade version seven storage");
    assert_eq!(
        11_i64,
        pragma_integer(storage.connection_for_test(), "user_version")
    );
    let token_state: String = storage
        .connection_for_test()
        .query_row(
            "SELECT token_state FROM api_tokens WHERE token_id = ?1",
            [&existing_token_id],
            |row| row.get(0),
        )
        .expect("read migrated token state");
    assert_eq!("active", token_state);
    assert!(
        storage
            .authenticate_api_token(&existing_token, at(2))
            .expect("authenticate migrated token")
            .is_some()
    );
}

#[test]
fn native_probe_control_lease_has_a_discriminated_durable_owner() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let host = storage.host_identity().unwrap();
    let connection = storage.connection_for_test();
    let acquired_at = "2026-07-16T00:00:00Z";

    connection
        .execute(
            "INSERT INTO control_leases (
                host_identity_ref, desktop_binding_ref, operation_id,
                owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                acquired_at, heartbeat_at, lease_state, owner_kind, native_probe_ref
             ) VALUES (?1, 'desktop-native', 'probe-operation', 1, 'process-start',
                       'boot-id', ?2, ?2, 'active', 'native_probe', 'native-private-ref')",
            rusqlite::params![host.as_str(), acquired_at],
        )
        .expect("native probe lease");

    let owner = connection
        .query_row(
            "SELECT owner_kind, session_id, turn_id, provider_probe_ref, native_probe_ref
             FROM control_leases WHERE desktop_binding_ref = 'desktop-native'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (
            "native_probe".to_string(),
            None,
            None,
            None,
            "native-private-ref".to_string()
        ),
        owner
    );
}

#[test]
fn provider_probe_control_lease_has_a_discriminated_durable_owner() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let host = storage.host_identity().unwrap();
    let connection = storage.connection_for_test();
    let acquired_at = "2026-07-16T00:00:00Z";

    connection
        .execute(
            "INSERT INTO control_leases (
                host_identity_ref, desktop_binding_ref, operation_id,
                owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                acquired_at, heartbeat_at, lease_state, owner_kind, provider_probe_ref
             ) VALUES (?1, 'desktop-provider', 'probe-operation', 1, 'process-start',
                       'boot-id', ?2, ?2, 'active', 'provider_probe', 'probe-private-ref')",
            rusqlite::params![host.as_str(), acquired_at],
        )
        .expect("provider probe lease");

    let owner = connection
        .query_row(
            "SELECT owner_kind, session_id, turn_id, provider_probe_ref
             FROM control_leases WHERE desktop_binding_ref = 'desktop-provider'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (
            "provider_probe".to_string(),
            None,
            None,
            "probe-private-ref".to_string()
        ),
        owner
    );

    let invalid = connection.execute(
        "INSERT INTO control_leases (
            host_identity_ref, desktop_binding_ref, operation_id,
            owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
            acquired_at, heartbeat_at, lease_state, owner_kind, provider_probe_ref, session_id
         ) VALUES (?1, 'desktop-invalid', 'probe-invalid', 1, 'process-start', 'boot-id',
                   ?2, ?2, 'active', 'provider_probe', 'probe-invalid-ref', 'session-invalid')",
        rusqlite::params![host.as_str(), acquired_at],
    );
    assert!(
        invalid.is_err(),
        "mixed owner fields must violate the schema"
    );
}

#[test]
fn maintenance_lease_conflicts_with_control_and_blocks_other_admission() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(1));
    storage
        .begin_session(
            &session,
            &admission(
                IdempotentOperation::Run,
                "maintenance-conflict",
                "maintenance-conflict-request",
                at(1),
            ),
        )
        .expect("admit the existing Turn");

    let error = storage
        .begin_setup_run(
            &SetupRunPlan::new(
                "maintenance-operation",
                SetupOperationKind::Repair,
                None,
                at(2),
                vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
            )
            .unwrap(),
            lease_owner("maintenance-operation", at(2)),
        )
        .expect_err("maintenance cannot overlap an existing Control Lease");
    assert_eq!(StorageErrorKind::LeaseConflict, error.kind());

    storage
        .commit_lifecycle(
            &session_id(SESSION_1),
            &turn_id(TURN_1),
            ExpectedRevisions::new(
                SessionStateRevision::initial(),
                TurnStateRevision::initial(),
            ),
            TurnTransition::Completed,
            at(3),
        )
        .expect("release the existing Control Lease");
    let _capability = begin_maintenance(&mut storage, "maintenance-operation", None, at(4));

    let competing = storage
        .begin_setup_run(
            &SetupRunPlan::new(
                "competing-maintenance",
                SetupOperationKind::Repair,
                None,
                at(5),
                vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
            )
            .unwrap(),
            lease_owner("competing-maintenance", at(5)),
        )
        .expect_err("a second maintenance operation must be blocked");
    assert_eq!(StorageErrorKind::LeaseConflict, competing.kind());

    let blocked_session = initial_session(&storage, SESSION_2, TURN_2, at(5));
    let blocked_turn = storage
        .begin_session(
            &blocked_session,
            &admission(
                IdempotentOperation::Run,
                "blocked-by-maintenance",
                "blocked-by-maintenance-request",
                at(5),
            ),
        )
        .expect_err("maintenance must block Turn admission");
    assert_eq!(StorageErrorKind::LeaseConflict, blocked_turn.kind());
}

#[test]
fn maintenance_postcheck_sublease_is_atomic_and_blocks_other_work() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let capability = begin_maintenance(
        &mut storage,
        "maintenance-postcheck",
        Some("maintenance-desktop"),
        at(1),
    );
    let key = readiness_key("maintenance-desktop");
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();

    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_postcheck_control_insert
             BEFORE INSERT ON control_leases
             WHEN NEW.operation_id = 'maintenance-postcheck'
             BEGIN SELECT RAISE(ABORT, 'forced postcheck acquisition failure'); END;",
        )
        .unwrap();
    storage
        .begin_maintenance_postcheck(
            &key,
            "maintenance-postcheck-probe",
            "repair-runtime",
            &capability,
        )
        .expect_err("a failed postcheck sublease insert must roll back the transaction");
    assert_eq!(
        (1_i64, 0_i64),
        storage
            .connection_for_test()
            .query_row(
                "SELECT (SELECT count(*) FROM maintenance_leases),
                        (SELECT count(*) FROM control_leases)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    );
    storage
        .connection_for_test()
        .execute_batch("DROP TRIGGER fail_postcheck_control_insert;")
        .unwrap();

    storage
        .begin_maintenance_postcheck(
            &key,
            "maintenance-postcheck-probe",
            "repair-runtime",
            &capability,
        )
        .expect("atomically acquire the postcheck Control sublease");

    let leases = storage
        .connection_for_test()
        .query_row(
            "SELECT maintenance_leases.operation_id, control_leases.operation_id,
                    control_leases.owner_kind, control_leases.native_probe_ref
             FROM maintenance_leases
             JOIN control_leases USING (host_identity_ref)",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .expect("read the atomic lease pair");
    assert_eq!(
        (
            "maintenance-postcheck".to_string(),
            "maintenance-postcheck".to_string(),
            "native_probe".to_string(),
            "maintenance-postcheck-probe".to_string(),
        ),
        leases
    );

    let blocked_session = initial_session(&storage, SESSION_1, TURN_1, at(2));
    let blocked_turn = storage
        .begin_session(
            &blocked_session,
            &admission(
                IdempotentOperation::Run,
                "blocked-by-maintenance-postcheck",
                "blocked-by-maintenance-postcheck-request",
                at(2),
            ),
        )
        .expect_err("a Turn must not overlap the maintenance postcheck");
    assert_eq!(StorageErrorKind::LeaseConflict, blocked_turn.kind());

    let ordinary_probe = storage
        .begin_native_probe(
            &key,
            "ordinary-probe",
            &lease_owner("ordinary-probe", at(2)),
        )
        .expect_err("an ordinary probe must not overlap maintenance postcheck");
    assert_eq!(StorageErrorKind::LeaseConflict, ordinary_probe.kind());
    let competing = storage
        .begin_setup_run(
            &SetupRunPlan::new(
                "other-maintenance",
                SetupOperationKind::Repair,
                None,
                at(2),
                vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
            )
            .unwrap(),
            lease_owner("other-maintenance", at(2)),
        )
        .expect_err("other maintenance must not overlap the postcheck");
    assert_eq!(StorageErrorKind::LeaseConflict, competing.kind());
}

#[test]
fn every_exact_owner_field_and_state_guards_postcheck_acquisition() {
    for (column, wrong_value) in [
        ("operation_id", "different-operation"),
        ("owner_process_id", "424242"),
        ("owner_process_start_ref", "different-process-start"),
        ("owner_boot_identity_ref", "different-boot"),
        ("acquired_at", "1970-01-01T00:00:09Z"),
        ("lease_state", "recovery_pending"),
    ] {
        let state = TempDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let operation_id = format!("postcheck-field-{column}");
        let capability = begin_maintenance(
            &mut storage,
            &operation_id,
            Some("postcheck-field-desktop"),
            at(1),
        );
        storage
            .start_setup_action(&capability, "repair-runtime", at(2))
            .unwrap();
        let key = readiness_key("postcheck-field-desktop");
        let original = replace_lease_field(&storage, "maintenance_leases", column, wrong_value);
        assert_eq!(
            StorageErrorKind::LeaseConflict,
            storage
                .begin_maintenance_postcheck(
                    &key,
                    "owner-field-probe",
                    "repair-runtime",
                    &capability,
                )
                .expect_err("one changed owner field must reject sublease acquisition")
                .kind(),
            "postcheck acquisition predicate omitted {column}"
        );
        replace_lease_field(&storage, "maintenance_leases", column, &original);
    }
}

#[test]
fn each_owner_field_in_each_table_guards_paired_finalization_and_recovery() {
    for table in ["maintenance_leases", "control_leases"] {
        for (column, wrong_value) in [
            ("operation_id", "different-operation"),
            ("owner_process_id", "424242"),
            ("owner_process_start_ref", "different-process-start"),
            ("owner_boot_identity_ref", "different-boot"),
            ("acquired_at", "1970-01-01T00:00:09Z"),
            ("lease_state", "recovery_pending"),
        ] {
            let finalization_state = TempDir::new().expect("finalization state directory");
            let (mut finalization, _) =
                Storage::open(finalization_state.path()).expect("open finalization storage");
            let finalization_id = format!("finalize-{table}-{column}");
            let (capability, key, verified) =
                begin_passed_postcheck(&mut finalization, &finalization_id);
            replace_lease_field(&finalization, table, column, wrong_value);
            let before = paired_maintenance_snapshot(&finalization, &finalization_id);
            assert_eq!(
                StorageErrorKind::LeaseConflict,
                finalization
                    .finish_maintenance_postcheck(
                        &capability,
                        "owner-field-probe",
                        "repair-runtime",
                        &key,
                        &verified,
                    )
                    .expect_err("one changed pair member must reject finalization")
                    .kind(),
                "finalization accepted changed {table}.{column}"
            );
            assert_eq!(
                before,
                paired_maintenance_snapshot(&finalization, &finalization_id),
                "rejected finalization changed durable state for {table}.{column}"
            );

            let recovery_state = TempDir::new().expect("recovery state directory");
            let (mut recovery, _) =
                Storage::open(recovery_state.path()).expect("open recovery storage");
            let recovery_id = format!("recover-{table}-{column}");
            let (recovery_capability, _key, _verified) =
                begin_passed_postcheck(&mut recovery, &recovery_id);
            replace_lease_field(&recovery, table, column, wrong_value);
            let before = paired_maintenance_snapshot(&recovery, &recovery_id);
            assert_eq!(
                StorageErrorKind::StateConflict,
                recovery
                    .retain_lease_recovery(recovery_capability.lease_owner())
                    .expect_err("one changed pair member must reject recovery retention")
                    .kind(),
                "recovery accepted changed {table}.{column}"
            );
            assert_eq!(
                before,
                paired_maintenance_snapshot(&recovery, &recovery_id),
                "rejected recovery changed durable state for {table}.{column}"
            );
        }
    }
}

#[test]
fn each_postcheck_delete_failure_rolls_back_readiness_ledger_and_both_leases() {
    for table in ["control_leases", "maintenance_leases"] {
        let state = TempDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let operation_id = format!("delete-boundary-{table}");
        let capability = begin_maintenance(
            &mut storage,
            &operation_id,
            Some("delete-boundary-desktop"),
            at(1),
        );
        storage
            .start_setup_action(&capability, "repair-runtime", at(2))
            .unwrap();
        let key = readiness_key("delete-boundary-desktop");
        storage
            .begin_maintenance_postcheck(
                &key,
                "delete-boundary-probe",
                "repair-runtime",
                &capability,
            )
            .unwrap();
        let evidence = key
            .evidence("delete-boundary-result", at(3), at(10))
            .unwrap();
        let (verified, _) =
            crate::runtime::verify_maintenance_postcheck(NativeProbeResult::Passed(evidence), None);
        storage
            .connection_for_test()
            .execute_batch(&format!(
                "CREATE TRIGGER fail_delete BEFORE DELETE ON {table}
                 BEGIN SELECT RAISE(ABORT, 'forced delete failure'); END;"
            ))
            .unwrap();
        storage
            .finish_maintenance_postcheck(
                &capability,
                "delete-boundary-probe",
                "repair-runtime",
                &key,
                &verified,
            )
            .expect_err("either delete failure must roll back the entire finalization");
        let run = storage.load_setup_run(&operation_id).unwrap().unwrap();
        assert_eq!(
            SetupRunStatus::Running,
            run.status(),
            "failed delete of {table}"
        );
        assert_eq!(
            crate::storage::SetupActionStatus::Started,
            run.actions()[0].status(),
            "failed delete of {table}"
        );
        let readiness: i64 = storage
            .connection_for_test()
            .query_row("SELECT count(*) FROM native_readiness_results", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(0, readiness, "failed delete of {table}");
        let leases: i64 = storage
            .connection_for_test()
            .query_row(
                "SELECT (SELECT count(*) FROM maintenance_leases)
                      + (SELECT count(*) FROM control_leases)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(2, leases, "failed delete of {table}");
    }
}

fn replace_lease_field(storage: &Storage, table: &str, column: &str, value: &str) -> String {
    let original = storage
        .connection_for_test()
        .query_row(
            &format!("SELECT CAST({column} AS TEXT) FROM {table}"),
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    storage
        .connection_for_test()
        .execute(&format!("UPDATE {table} SET {column} = ?1"), [value])
        .unwrap();
    original
}

fn begin_passed_postcheck(
    storage: &mut Storage,
    operation_id: &str,
) -> (
    MaintenanceLeaseCapability,
    ReadinessCacheKey,
    crate::runtime::VerifiedMaintenancePostcheck,
) {
    let capability = begin_maintenance(storage, operation_id, Some("owner-field-desktop"), at(1));
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();
    let key = readiness_key("owner-field-desktop");
    storage
        .begin_maintenance_postcheck(&key, "owner-field-probe", "repair-runtime", &capability)
        .unwrap();
    let evidence = key.evidence("owner-field-result", at(3), at(10)).unwrap();
    let (verified, terminal_error) =
        crate::runtime::verify_maintenance_postcheck(NativeProbeResult::Passed(evidence), None);
    assert!(terminal_error.is_none());
    (capability, key, verified)
}

fn paired_maintenance_snapshot(storage: &Storage, operation_id: &str) -> String {
    storage
        .connection_for_test()
        .query_row(
            "SELECT printf(
                '%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q',
                setup_runs.status, setup_runs.finished_at,
                setup_actions.status, setup_actions.finished_at,
                setup_actions.error_code, setup_actions.recovery_hint,
                maintenance.operation_id, maintenance.owner_process_id,
                maintenance.owner_process_start_ref, maintenance.owner_boot_identity_ref,
                maintenance.acquired_at, maintenance.heartbeat_at, maintenance.lease_state,
                control.operation_id, control.owner_process_id,
                control.owner_process_start_ref, control.owner_boot_identity_ref,
                control.acquired_at, control.heartbeat_at, control.lease_state,
                (SELECT count(*) FROM native_readiness_results)
             )
             FROM setup_runs
             JOIN setup_actions USING (run_id)
             JOIN maintenance_leases AS maintenance USING (host_identity_ref)
             LEFT JOIN control_leases AS control USING (host_identity_ref)
             WHERE setup_runs.run_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn heartbeat_refresh_rejects_each_individually_wrong_owner_field_and_state() {
    for field in [
        "operation_id",
        "owner_process_id",
        "owner_process_start_ref",
        "owner_boot_identity_ref",
        "acquired_at",
        "lease_state",
    ] {
        let state = TempDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let operation_id = format!("heartbeat-field-{field}");
        let capability = begin_maintenance(&mut storage, &operation_id, None, at(1));
        let owner = capability.lease_owner();
        let wrong_owner = LeaseOwner::new(
            if field == "operation_id" {
                "different-operation"
            } else {
                owner.operation_id.as_str()
            },
            if field == "owner_process_id" {
                owner.process_id + 1
            } else {
                owner.process_id
            },
            if field == "owner_process_start_ref" {
                "different-process-start"
            } else {
                owner.process_start_ref.as_str()
            },
            if field == "owner_boot_identity_ref" {
                "different-boot"
            } else {
                owner.boot_identity_ref.as_str()
            },
            if field == "acquired_at" {
                at(9)
            } else {
                owner.acquired_at
            },
        )
        .unwrap();
        if field == "lease_state" {
            storage
                .connection_for_test()
                .execute(
                    "UPDATE maintenance_leases SET lease_state = 'recovery_pending'",
                    [],
                )
                .unwrap();
        }
        if field == "lease_state" {
            assert_eq!(
                StorageErrorKind::StateConflict,
                storage
                    .refresh_lease_heartbeat(&wrong_owner, at(2))
                    .expect_err("an exact owner cannot refresh recovery ownership")
                    .kind()
            );
        } else {
            assert_eq!(
                0,
                storage
                    .refresh_lease_heartbeat(&wrong_owner, at(2))
                    .unwrap(),
                "heartbeat predicate omitted {field}"
            );
            assert_eq!(
                1,
                storage
                    .refresh_lease_heartbeat(capability.lease_owner(), at(2))
                    .unwrap(),
                "the exact operation owner refreshes its one maintenance row"
            );
        }
    }
}

#[test]
fn paired_heartbeat_refresh_updates_both_rows_or_rolls_back() {
    for table in ["maintenance_leases", "control_leases"] {
        for (column, wrong_value) in [
            ("operation_id", "different-operation"),
            ("owner_process_id", "424242"),
            ("owner_process_start_ref", "different-process-start"),
            ("owner_boot_identity_ref", "different-boot"),
            ("acquired_at", "1970-01-01T00:00:09Z"),
            ("lease_state", "recovery_pending"),
        ] {
            let state = TempDir::new().expect("temporary state directory");
            let (mut storage, _) = Storage::open(state.path()).expect("open storage");
            let operation_id = format!("heartbeat-pair-{table}-{column}");
            let (capability, _key, _verified) = begin_passed_postcheck(&mut storage, &operation_id);
            replace_lease_field(&storage, table, column, wrong_value);
            let before = paired_maintenance_snapshot(&storage, &operation_id);

            assert_eq!(
                StorageErrorKind::StateConflict,
                storage
                    .refresh_lease_heartbeat(capability.lease_owner(), at(2))
                    .expect_err("one mismatched pair member must reject the whole refresh")
                    .kind(),
                "heartbeat refresh accepted changed {table}.{column}"
            );
            assert_eq!(
                before,
                paired_maintenance_snapshot(&storage, &operation_id),
                "rejected heartbeat refresh changed {table}.{column}"
            );
        }
    }

    let state = TempDir::new().expect("successful pair state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let operation_id = "heartbeat-pair-success";
    let (capability, _key, _verified) = begin_passed_postcheck(&mut storage, operation_id);
    assert_eq!(
        2,
        storage
            .refresh_lease_heartbeat(capability.lease_owner(), at(2))
            .expect("the exact paired owner refreshes both leases")
    );
    let expected_heartbeat = at(2).format(&Rfc3339).unwrap();
    for table in ["maintenance_leases", "control_leases"] {
        assert_eq!(
            1_i64,
            storage
                .connection_for_test()
                .query_row(
                    &format!(
                        "SELECT count(*) FROM {table}\n\
                         WHERE operation_id = ?1 AND heartbeat_at = ?2"
                    ),
                    params![operation_id, expected_heartbeat],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            "the successful refresh omitted {table}"
        );
    }
}

#[test]
fn thirty_second_staleness_never_releases_or_weakens_lease_exclusion() {
    let control_state = TempDir::new().expect("control state directory");
    let (mut control, _) = Storage::open(control_state.path()).expect("open control storage");
    let first = initial_session(&control, SESSION_1, TURN_1, at(0));
    control
        .begin_session(
            &first,
            &admission(IdempotentOperation::Run, "stale-control", TURN_1, at(0)),
        )
        .expect("acquire Control Lease");
    let control_heartbeat: String = control
        .connection_for_test()
        .query_row("SELECT heartbeat_at FROM control_leases", [], |row| {
            row.get(0)
        })
        .unwrap();
    for observed_at in [at(29), at(30)] {
        assert_eq!(
            LeaseFreshness::Fresh,
            crate::storage::operational::classify_lease_freshness(&control_heartbeat, observed_at)
                .unwrap()
        );
    }
    assert_eq!(
        LeaseFreshness::Stale,
        crate::storage::operational::classify_lease_freshness(&control_heartbeat, at(31)).unwrap()
    );
    let competing = initial_session(&control, SESSION_2, TURN_2, at(31));
    assert_eq!(
        StorageErrorKind::LeaseConflict,
        control
            .begin_session(
                &competing,
                &admission(
                    IdempotentOperation::Run,
                    "stale-control-contender",
                    TURN_2,
                    at(31),
                ),
            )
            .expect_err("stale Control ownership still blocks admission")
            .kind()
    );
    assert_eq!(
        1_i64,
        control
            .connection_for_test()
            .query_row("SELECT count(*) FROM control_leases", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    );

    let maintenance_state = TempDir::new().expect("maintenance state directory");
    let (mut maintenance, _) =
        Storage::open(maintenance_state.path()).expect("open maintenance storage");
    let capability = begin_maintenance(&mut maintenance, "stale-maintenance", None, at(0));
    let maintenance_heartbeat: String = maintenance
        .connection_for_test()
        .query_row("SELECT heartbeat_at FROM maintenance_leases", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        LeaseFreshness::Fresh,
        crate::storage::operational::classify_lease_freshness(&maintenance_heartbeat, at(30),)
            .unwrap()
    );
    assert_eq!(
        LeaseFreshness::Stale,
        crate::storage::operational::classify_lease_freshness(&maintenance_heartbeat, at(31),)
            .unwrap()
    );
    let competing_plan = SetupRunPlan::new(
        "stale-maintenance-contender",
        SetupOperationKind::ServiceRestart,
        None,
        at(31),
        vec![SetupActionPlan::new("restart", "Restart service", false).unwrap()],
    )
    .unwrap();
    assert_eq!(
        StorageErrorKind::LeaseConflict,
        maintenance
            .begin_setup_run(
                &competing_plan,
                lease_owner("stale-maintenance-contender", at(31)),
            )
            .expect_err("stale Maintenance ownership still blocks mutation")
            .kind()
    );
    assert_eq!(
        capability.operation_id(),
        maintenance
            .connection_for_test()
            .query_row("SELECT operation_id FROM maintenance_leases", [], |row| row
                .get::<_, String>(0),)
            .unwrap()
    );
}

#[test]
fn maintenance_postcheck_finalization_commits_readiness_ledger_and_release_atomically() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let operation_id = "maintenance-final-postcheck";
    let plan = SetupRunPlan::new(
        operation_id,
        SetupOperationKind::Repair,
        Some(DesktopBindingRef::new("maintenance-desktop").unwrap()),
        at(1),
        vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
    )
    .unwrap();
    let capability = storage
        .begin_setup_run(&plan, lease_owner(operation_id, at(1)))
        .unwrap();
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();
    let key = readiness_key("maintenance-desktop");
    storage
        .begin_maintenance_postcheck(
            &key,
            "maintenance-final-probe",
            "repair-runtime",
            &capability,
        )
        .unwrap();
    let evidence = key
        .evidence("maintenance-readiness", at(4), at(10))
        .unwrap();
    let (verified, terminal_error) =
        crate::runtime::verify_maintenance_postcheck(NativeProbeResult::Passed(evidence), None);
    assert!(terminal_error.is_none());

    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_maintenance_finalization
             BEFORE UPDATE OF status ON setup_runs
             WHEN OLD.run_id = 'maintenance-final-postcheck' AND NEW.status != 'running'
             BEGIN SELECT RAISE(ABORT, 'forced finalization failure'); END;",
        )
        .unwrap();
    storage
        .finish_maintenance_postcheck(
            &capability,
            "maintenance-final-probe",
            "repair-runtime",
            &key,
            &verified,
        )
        .expect_err("a failed final ledger commit must roll back readiness and both releases");
    assert_eq!(
        SetupRunStatus::Running,
        storage
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .status()
    );
    assert_eq!(
        crate::storage::SetupActionStatus::Started,
        storage
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .actions()[0]
            .status()
    );
    assert_eq!(
        2_i64,
        storage
            .connection_for_test()
            .query_row(
                "SELECT (SELECT count(*) FROM maintenance_leases)
                      + (SELECT count(*) FROM control_leases)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    );
    assert_eq!(
        0_i64,
        storage
            .connection_for_test()
            .query_row("SELECT count(*) FROM native_readiness_results", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    );

    storage
        .connection_for_test()
        .execute_batch("DROP TRIGGER fail_maintenance_finalization;")
        .unwrap();
    assert_eq!(
        SetupRunStatus::Completed,
        storage
            .finish_maintenance_postcheck(
                &capability,
                "maintenance-final-probe",
                "repair-runtime",
                &key,
                &verified,
            )
            .expect("commit readiness, final ledger state, and both releases")
            .expect("passed postcheck is terminal")
    );
    let host_identity = storage.host_identity().unwrap();
    let readiness_identity: (String, String, String, String, String, Option<String>) = storage
        .connection_for_test()
        .query_row(
            "SELECT result_id, host_identity_ref, desktop_binding_ref,
                    adapter_ref, status, failure_reason
             FROM native_readiness_results",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("successful finalization commits one readiness identity");
    assert_eq!(
        (
            "maintenance-readiness".to_string(),
            host_identity.to_string(),
            "maintenance-desktop".to_string(),
            "codex-native-computer-use".to_string(),
            "passed".to_string(),
            None,
        ),
        readiness_identity
    );
    let readiness_evidence: (String, String, Option<String>, String, String, i64, i64) = storage
        .connection_for_test()
        .query_row(
            "SELECT codex_version, native_runtime_version, plugin_version,
                    os_permission_fingerprint, app_approval_fingerprint,
                    observed_at, expires_at
             FROM native_readiness_results",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .expect("successful finalization commits exact readiness evidence");
    assert_eq!(
        (
            "0.144.0".to_string(),
            "1.0.0".to_string(),
            None,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            i64::try_from(at(4).unix_timestamp_nanos()).unwrap(),
            i64::try_from(at(10).unix_timestamp_nanos()).unwrap(),
        ),
        readiness_evidence
    );
    assert_eq!(
        0_i64,
        storage
            .connection_for_test()
            .query_row(
                "SELECT (SELECT count(*) FROM maintenance_leases)
                      + (SELECT count(*) FROM control_leases)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    );
}

#[test]
fn failed_maintenance_postcheck_commits_failure_ledger_and_release_atomically() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let operation_id = "maintenance-failed-postcheck";
    let capability = begin_maintenance(
        &mut storage,
        operation_id,
        Some("failed-maintenance-desktop"),
        at(1),
    );
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();
    let key = readiness_key("failed-maintenance-desktop");
    storage
        .begin_maintenance_postcheck(
            &key,
            "failed-maintenance-probe",
            "repair-runtime",
            &capability,
        )
        .unwrap();
    let evidence = key
        .evidence("maintenance-readiness", at(4), at(10))
        .unwrap();
    let (verified, terminal_error) = crate::runtime::verify_maintenance_postcheck(
        NativeProbeResult::Failed {
            evidence,
            reason: "readiness postcondition failed",
            error: satelle_core::SatelleError::computer_use_not_ready(),
            dispatch_possible: false,
        },
        None,
    );
    assert!(terminal_error.is_some());

    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_failed_maintenance_finalization
             BEFORE UPDATE OF status ON setup_runs
             WHEN OLD.run_id = 'maintenance-failed-postcheck' AND NEW.status != 'running'
             BEGIN SELECT RAISE(ABORT, 'forced failed-postcheck finalization failure'); END;",
        )
        .unwrap();
    storage
        .finish_maintenance_postcheck(
            &capability,
            "failed-maintenance-probe",
            "repair-runtime",
            &key,
            &verified,
        )
        .expect_err("failed ledger commit rolls back failed readiness and both releases");
    assert_eq!(
        2_i64,
        storage
            .connection_for_test()
            .query_row(
                "SELECT (SELECT count(*) FROM maintenance_leases)
                      + (SELECT count(*) FROM control_leases)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    );
    assert_eq!(
        0_i64,
        storage
            .connection_for_test()
            .query_row("SELECT count(*) FROM native_readiness_results", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    );
    assert_eq!(
        crate::storage::SetupActionStatus::Started,
        storage
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .actions()[0]
            .status()
    );
    storage
        .connection_for_test()
        .execute_batch("DROP TRIGGER fail_failed_maintenance_finalization;")
        .unwrap();

    assert_eq!(
        Some(SetupRunStatus::Failed),
        storage
            .finish_maintenance_postcheck(
                &capability,
                "failed-maintenance-probe",
                "repair-runtime",
                &key,
                &verified,
            )
            .expect("known failure commits ledger, readiness, and releases")
    );
    let (status, failure_reason): (String, Option<String>) = storage
        .connection_for_test()
        .query_row(
            "SELECT status, failure_reason FROM native_readiness_results
             WHERE desktop_binding_ref = 'failed-maintenance-desktop'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!("failed", status);
    assert_eq!(
        Some("readiness postcondition failed".to_string()),
        failure_reason
    );
    assert_eq!(
        0_i64,
        storage
            .connection_for_test()
            .query_row(
                "SELECT (SELECT count(*) FROM maintenance_leases)
                      + (SELECT count(*) FROM control_leases)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    );
}

#[test]
fn unknown_maintenance_postcheck_preserves_both_leases_for_reconciliation() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let operation_id = "maintenance-unknown-postcheck";
    let capability = begin_maintenance(
        &mut storage,
        operation_id,
        Some("unknown-maintenance-desktop"),
        at(1),
    );
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();
    let key = readiness_key("unknown-maintenance-desktop");
    storage
        .begin_maintenance_postcheck(
            &key,
            "unknown-maintenance-probe",
            "repair-runtime",
            &capability,
        )
        .unwrap();
    let (verified, terminal_error) = crate::runtime::verify_maintenance_postcheck(
        NativeProbeResult::UncachedFailure(satelle_core::SatelleError::computer_use_not_ready()),
        None,
    );
    assert!(terminal_error.is_some());

    assert_eq!(
        None,
        storage
            .finish_maintenance_postcheck(
                &capability,
                "unknown-maintenance-probe",
                "repair-runtime",
                &key,
                &verified,
            )
            .expect("unknown postcheck is durably retained")
    );
    assert_eq!(
        SetupRunStatus::OutcomeUnknown,
        storage
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .status()
    );
    let lease_states = storage
        .connection_for_test()
        .prepare(
            "SELECT lease_state FROM maintenance_leases
             UNION ALL SELECT lease_state FROM control_leases ORDER BY lease_state",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(vec!["recovery_pending", "recovery_pending"], lease_states);
}

fn lease_owner(operation_id: &str, acquired_at: OffsetDateTime) -> LeaseOwner {
    LeaseOwner::new(
        operation_id,
        std::process::id(),
        "process-start-maintenance",
        "boot-identity-maintenance",
        acquired_at,
    )
    .unwrap()
}

fn readiness_key(desktop_binding: &str) -> ReadinessCacheKey {
    let desktop = DesktopBindingRef::new(desktop_binding).unwrap();
    let policy = ExecutionPolicy::new(
        EffectiveModelRef::new("computer-use-preview").unwrap(),
        ProviderBindingRef::new("openai").unwrap(),
        DesktopTarget::new(desktop.clone()),
        ApprovalPolicy::OnRequest,
        SandboxPolicy::WorkspaceWrite,
        TimeoutPolicy::bounded_seconds(120).unwrap(),
        ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Enabled),
    );
    ReadinessCacheKey::new(
        "codex-native-computer-use",
        desktop,
        policy,
        "0.144.0",
        "1.0.0",
        None::<String>,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap()
}

#[test]
fn version_one_store_upgrades_without_replacing_existing_state() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");
    let expected_host = storage.host_identity().unwrap();
    storage
        .connection_for_test()
        .execute_batch(
            "DROP TABLE admission_cancellations;
             DROP TABLE setup_actions;
             DROP TABLE setup_runs;
             DROP TABLE native_readiness_results;
             DROP TABLE provider_smoke_results;
             DROP INDEX one_session_per_upstream_goal_ref;
             ALTER TABLE sessions DROP COLUMN display_name;
             ALTER TABLE session_private_refs DROP COLUMN upstream_goal_ref;
             ALTER TABLE api_tokens DROP COLUMN token_state;
             DELETE FROM schema_migrations WHERE version IN (2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
             PRAGMA user_version = 1;",
        )
        .unwrap();
    drop(storage);

    let (storage, _) = Storage::open(state.path()).expect("upgrade version one storage");
    assert_eq!(expected_host, storage.host_identity().unwrap());
    assert_eq!(
        11_i64,
        pragma_integer(storage.connection_for_test(), "user_version")
    );

    let backups = migration_backups(state.path());
    assert_eq!(1, backups.len());
    let backup_path = &backups[0];
    let backup_name = backup_path.file_name().unwrap().to_str().unwrap();
    let manifest_bytes = fs::read(format!("{}.json", backup_path.display())).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(1, manifest["manifest_version"]);
    assert_eq!(backup_name, manifest["backup_file"]);
    assert_eq!(1, manifest["source_schema_version"]);
    assert_eq!(env!("CARGO_PKG_VERSION"), manifest["satelle_version"]);
    assert_eq!(
        "sqlite3",
        manifest["restore_compatibility"]["database_format"]
    );
    assert_eq!(1, manifest["restore_compatibility"]["schema_version"]);
    assert_eq!(
        true,
        manifest["restore_compatibility"]["explicit_restore_required"]
    );
    assert_eq!(
        file_digest(backup_path),
        manifest["source_database_digest"].as_str().unwrap()
    );
    assert!(
        !String::from_utf8(manifest_bytes)
            .unwrap()
            .contains(expected_host.as_str())
    );
    let backup =
        Connection::open_with_flags(backup_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    assert_eq!(1, pragma_integer(&backup, "user_version"));
    assert_eq!(
        "ok",
        backup
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap()
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
            "DROP TABLE admission_cancellations;
             DROP TABLE setup_actions;
             DROP TABLE setup_runs;
             DROP TABLE native_readiness_results;
             DROP TABLE provider_smoke_results;
             DROP INDEX one_session_per_upstream_goal_ref;
             ALTER TABLE sessions DROP COLUMN display_name;
             ALTER TABLE session_private_refs DROP COLUMN upstream_goal_ref;
             ALTER TABLE api_tokens DROP COLUMN token_state;
             DELETE FROM schema_migrations WHERE version IN (2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
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
    for table in [
        "readiness_successes",
        "native_readiness_results",
        "provider_smoke_successes",
        "provider_smoke_results",
        "setup_runs",
        "setup_actions",
    ] {
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
            "DROP TABLE admission_cancellations;
             DROP TABLE setup_actions;
             DROP TABLE setup_runs;
             DROP TABLE native_readiness_results;
             DROP TABLE provider_smoke_results;
             DROP INDEX one_session_per_upstream_goal_ref;
             ALTER TABLE sessions DROP COLUMN display_name;
             ALTER TABLE session_private_refs DROP COLUMN upstream_goal_ref;
             ALTER TABLE api_tokens DROP COLUMN token_state;
             DELETE FROM schema_migrations WHERE version IN (2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
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

    let first_backups = migration_backups(state.path());
    assert_eq!(1, first_backups.len());
    let first_backup = first_backups[0].clone();
    let first_backup_bytes = fs::read(&first_backup).unwrap();
    let first_manifest_path = PathBuf::from(format!("{}.json", first_backup.display()));
    let first_manifest_bytes = fs::read(&first_manifest_path).unwrap();

    let repeated_error = match Storage::open(state.path()) {
        Ok(_) => panic!("the forced migration failure must remain reproducible"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::MigrationFailed, repeated_error.kind());
    assert_eq!(first_backup_bytes, fs::read(&first_backup).unwrap());
    assert_eq!(
        first_manifest_bytes,
        fs::read(&first_manifest_path).unwrap()
    );
    assert_eq!(2, migration_backups(state.path()).len());

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
    for table in [
        "readiness_successes",
        "native_readiness_results",
        "provider_smoke_successes",
        "provider_smoke_results",
        "setup_runs",
        "setup_actions",
    ] {
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

fn migration_backups(state_root: &Path) -> Vec<PathBuf> {
    let mut backups = fs::read_dir(state_root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("satelle.sqlite3.migration-v") && name.ends_with(".backup")
                })
        })
        .collect::<Vec<_>>();
    backups.sort();
    backups
}

fn file_digest(path: &Path) -> String {
    let digest = Sha256::digest(fs::read(path).unwrap());
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
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
    let cache_key = ReadinessCacheKey::new(
        "codex-native-computer-use",
        desktop.clone(),
        policy.clone(),
        "0.144.0",
        "1.0.0",
        Some("plugin-1.0.0"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let provider = ProviderSmokeEvidence::new(
        "provider-smoke-1",
        cache_key.provider_config_fingerprint(),
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
    assert_eq!(
        Some(readiness.clone()),
        storage
            .load_reusable_readiness(&cache_key, observed_at)
            .expect("matching success is reusable before expiry")
    );
    assert!(
        storage
            .load_reusable_readiness(&cache_key, expires_at)
            .expect("expiry lookup")
            .is_none()
    );
    assert_eq!(
        Some(ProviderSmokeResult::Passed(
            provider
                .clone()
                .with_source(crate::ProviderSmokeSource::Cache),
        )),
        storage
            .load_reusable_provider_smoke(&cache_key, observed_at)
            .expect("matching provider smoke is reusable before expiry")
    );
    assert!(
        storage
            .load_reusable_provider_smoke(&cache_key, expires_at)
            .expect("provider expiry lookup")
            .is_none()
    );

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
        cache_key.provider_config_fingerprint(),
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
    storage
        .store_preflight_failure(&cache_key, &second_readiness, "action_not_observed")
        .expect("store terminal native readiness failure");

    let failure_observed_at = observed_at + time::Duration::seconds(1);
    let failure_expires_at = failure_observed_at + time::Duration::minutes(10);
    let failure_readiness = cache_key
        .evidence(
            "readiness-provider-failure",
            failure_observed_at,
            failure_expires_at,
        )
        .unwrap();
    let provider_failure = ProviderSmokeFailureEvidence::new(
        "provider-smoke-failure-1",
        cache_key.provider_config_fingerprint(),
        satelle_core::ErrorCode::UnsupportedProviderComputerUse,
        "provider_smoke_provider_rejected",
        failure_observed_at,
        failure_expires_at,
    )
    .unwrap();
    storage
        .store_provider_smoke_failure(&cache_key, &failure_readiness, &provider_failure)
        .expect("store normalized provider failure");
    assert_eq!(
        Some(ProviderSmokeResult::Failed(
            provider_failure
                .clone()
                .with_source(crate::ProviderSmokeSource::Cache),
        )),
        storage
            .load_reusable_provider_smoke(&cache_key, failure_observed_at)
            .expect("matching provider failure is reusable before expiry")
    );
    assert!(
        storage
            .load_reusable_provider_smoke(&cache_key, failure_expires_at)
            .expect("provider failure expiry lookup")
            .is_none()
    );
    let readiness_count: i64 = storage
        .connection_for_test()
        .query_row("SELECT count(*) FROM native_readiness_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(3, readiness_count);
    let statuses = storage
        .connection_for_test()
        .prepare("SELECT status FROM native_readiness_results ORDER BY result_id")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(vec!["passed", "failed", "passed"], statuses);
    let provider_count: i64 = storage
        .connection_for_test()
        .query_row("SELECT count(*) FROM provider_smoke_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(1, provider_count);
    let provider_statuses = storage
        .connection_for_test()
        .prepare("SELECT status FROM provider_smoke_results ORDER BY result_id")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(vec!["failed"], provider_statuses);
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
