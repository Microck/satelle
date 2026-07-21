use super::*;
use crate::storage::{DurableAdmissionState, DurableCancellationOutcome, StorageErrorKind};

#[test]
fn cancellation_tombstones_replay_conflict_block_and_prune() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let created_at = at(1);
    let identity = idempotency(IdempotentOperation::Run, "cancelled-run", created_at);

    assert!(matches!(
        storage
            .record_admission_cancellation(
                IdempotentOperation::Run,
                &identity,
                None,
                DurableCancellationOutcome::Cancelled,
                created_at,
            )
            .expect("record cancellation"),
        DurableAdmissionState::Cancelled
    ));
    assert!(matches!(
        storage
            .resolve_admission_operation(
                IdempotentOperation::Run,
                &identity,
                None,
                created_at + time::Duration::hours(1),
            )
            .expect("replay cancellation"),
        DurableAdmissionState::Cancelled
    ));

    let conflicting = IdempotencyInput::new(
        "principal-1",
        IdempotentOperation::Run,
        "cancelled-run",
        "operation-cancelled-run",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        1,
        1,
        created_at,
        created_at + IDEMPOTENCY_RETENTION,
    )
    .expect("construct conflicting identity");
    let conflict = match storage.resolve_admission_operation(
        IdempotentOperation::Run,
        &conflicting,
        None,
        created_at + time::Duration::hours(1),
    ) {
        Ok(_) => panic!("digest drift must conflict"),
        Err(error) => error,
    };
    assert_eq!(conflict.kind(), StorageErrorKind::IdempotencyConflict);

    let session = initial_session(&storage, SESSION_1, TURN_1, created_at);
    assert_eq!(
        storage
            .begin_session(
                &session,
                &admission(
                    IdempotentOperation::Run,
                    "cancelled-run",
                    "cancelled-request",
                    created_at,
                ),
            )
            .expect_err("unexpired tombstone must block admission")
            .kind(),
        StorageErrorKind::AdmissionCancelled
    );

    storage
        .prune_expired_session_metadata(created_at + IDEMPOTENCY_RETENTION)
        .expect("prune exact expiry boundary");
    assert!(matches!(
        storage
            .resolve_admission_operation(
                IdempotentOperation::Run,
                &identity,
                None,
                created_at + IDEMPOTENCY_RETENTION,
            )
            .expect("resolve after expiry"),
        DurableAdmissionState::Missing
    ));
}

#[test]
fn recovery_pending_tombstones_survive_retention_pruning_and_restart() {
    let state = TempDir::new().expect("temporary state directory");
    let created_at = at(1);
    let observed_at = created_at + IDEMPOTENCY_RETENTION + time::Duration::days(30);
    let identity = idempotency(IdempotentOperation::Run, "recovery-pending-run", created_at);
    {
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        assert!(matches!(
            storage
                .record_admission_cancellation(
                    IdempotentOperation::Run,
                    &identity,
                    None,
                    DurableCancellationOutcome::RecoveryPending,
                    created_at,
                )
                .expect("record ambiguous cancellation"),
            DurableAdmissionState::RecoveryPending
        ));
        storage
            .prune_expired_session_metadata(observed_at)
            .expect("prune metadata well past the idempotency window");
        assert!(matches!(
            storage
                .resolve_admission_operation(
                    IdempotentOperation::Run,
                    &identity,
                    None,
                    observed_at,
                )
                .expect("resolve retained ambiguity after pruning"),
            DurableAdmissionState::RecoveryPending
        ));
    }

    let (storage, _) = Storage::open(state.path()).expect("restart storage");
    assert!(matches!(
        storage
            .resolve_admission_operation(
                IdempotentOperation::Run,
                &identity,
                None,
                observed_at + time::Duration::days(30),
            )
            .expect("resolve retained ambiguity after restart"),
        DurableAdmissionState::RecoveryPending
    ));
}

#[test]
fn recovery_pending_atomically_upgrades_and_never_downgrades() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let created_at = at(1);
    let identity = idempotency(
        IdempotentOperation::Run,
        "monotonic-cancellation",
        created_at,
    );

    assert!(matches!(
        storage
            .record_admission_cancellation(
                IdempotentOperation::Run,
                &identity,
                None,
                DurableCancellationOutcome::Cancelled,
                created_at,
            )
            .expect("record cancellation-first tombstone"),
        DurableAdmissionState::Cancelled
    ));
    assert!(matches!(
        storage
            .record_admission_cancellation(
                IdempotentOperation::Run,
                &identity,
                None,
                DurableCancellationOutcome::RecoveryPending,
                created_at,
            )
            .expect("upgrade ambiguous active admission"),
        DurableAdmissionState::RecoveryPending
    ));
    assert!(matches!(
        storage
            .record_admission_cancellation(
                IdempotentOperation::Run,
                &identity,
                None,
                DurableCancellationOutcome::Cancelled,
                created_at,
            )
            .expect("repeat confirmed cancellation without reconciliation authority"),
        DurableAdmissionState::RecoveryPending
    ));
}

#[test]
fn reconciled_cancellation_receives_a_fresh_retention_window() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let created_at = at(1);
    let reconciled_at = created_at + IDEMPOTENCY_RETENTION + time::Duration::days(30);
    let identity = idempotency(
        IdempotentOperation::Run,
        "fresh-reconciled-retention",
        created_at,
    );

    assert!(matches!(
        storage
            .record_admission_cancellation(
                IdempotentOperation::Run,
                &identity,
                None,
                DurableCancellationOutcome::RecoveryPending,
                created_at,
            )
            .expect("record unresolved cancellation"),
        DurableAdmissionState::RecoveryPending
    ));
    assert!(matches!(
        storage
            .reconcile_admission_cancellation(
                IdempotentOperation::Run,
                &identity,
                None,
                DurableCancellationOutcome::Cancelled,
                reconciled_at,
            )
            .expect("explicitly reconcile the cancellation"),
        DurableAdmissionState::Cancelled
    ));

    let (stored_created_at, stored_expires_at): (String, String) = storage
        .connection_for_test()
        .query_row(
            "SELECT created_at, expires_at FROM admission_cancellations
             WHERE principal_ref = ?1 AND operation = 'run' AND idempotency_key = ?2",
            rusqlite::params![identity.principal_ref.as_str(), identity.key.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read refreshed cancellation retention");
    assert_eq!(
        parse_time(&stored_created_at).expect("parse refreshed creation time"),
        reconciled_at
    );
    assert_eq!(
        parse_time(&stored_expires_at).expect("parse refreshed expiry"),
        reconciled_at + IDEMPOTENCY_RETENTION
    );
    assert!(matches!(
        storage
            .resolve_admission_operation(
                IdempotentOperation::Run,
                &identity,
                None,
                reconciled_at + IDEMPOTENCY_RETENTION - time::Duration::nanoseconds(1),
            )
            .expect("replay immediately before refreshed expiry"),
        DurableAdmissionState::Cancelled
    ));
    assert!(matches!(
        storage
            .resolve_admission_operation(
                IdempotentOperation::Run,
                &identity,
                None,
                reconciled_at + IDEMPOTENCY_RETENTION,
            )
            .expect("resolve exact refreshed expiry boundary"),
        DurableAdmissionState::Missing
    ));
}

#[test]
fn committed_admission_wins_a_late_cancellation_record() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let created_at = at(1);
    let context = admission(
        IdempotentOperation::Run,
        "committed-before-cancel",
        "committed-request",
        created_at,
    );
    let session = initial_session(&storage, SESSION_1, TURN_1, created_at);
    storage
        .begin_session(&session, &context)
        .expect("commit admission");

    assert!(matches!(
        storage
            .record_admission_cancellation(
                IdempotentOperation::Run,
                context.idempotency(),
                None,
                DurableCancellationOutcome::RecoveryPending,
                created_at,
            )
            .expect("resolve late cancellation"),
        DurableAdmissionState::Admitted(_)
    ));
}

#[test]
fn expired_cancelled_tombstone_does_not_pin_a_retired_hmac_key_on_reuse() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let observed_at = OffsetDateTime::now_utc();
    let expired_at = observed_at - time::Duration::seconds(1);
    let created_at = expired_at - IDEMPOTENCY_RETENTION;
    let first_digest = storage
        .digest_idempotency_payload(b"first cancelled payload")
        .expect("digest cancelled payload with initial key");
    let first = IdempotencyInput::new(
        "principal-hmac-reuse",
        IdempotentOperation::Run,
        "reused-after-expiry",
        "expired-cancellation-operation",
        first_digest.hex(),
        1,
        first_digest.key_version(),
        created_at,
        expired_at,
    )
    .expect("construct expired cancellation identity");
    storage
        .record_admission_cancellation(
            IdempotentOperation::Run,
            &first,
            None,
            DurableCancellationOutcome::Cancelled,
            created_at,
        )
        .expect("record cancellation under initial HMAC key");

    assert_eq!(
        storage
            .rotate_idempotency_hmac_key(observed_at)
            .expect("rotate HMAC key"),
        2
    );
    assert_eq!(
        storage
            .idempotency_hmac_key_version(
                "principal-hmac-reuse",
                IdempotentOperation::Run,
                "reused-after-expiry",
            )
            .expect("look up reusable key"),
        None,
        "an expired cancelled tombstone must not select its retired key"
    );

    let fresh_digest = storage
        .digest_idempotency_payload(b"fresh payload after expiry")
        .expect("digest fresh payload with active key");
    assert_eq!(fresh_digest.key_version(), 2);
    let fresh = IdempotencyInput::new(
        "principal-hmac-reuse",
        IdempotentOperation::Run,
        "reused-after-expiry",
        "fresh-cancellation-operation",
        fresh_digest.hex(),
        1,
        fresh_digest.key_version(),
        observed_at,
        observed_at + IDEMPOTENCY_RETENTION,
    )
    .expect("construct fresh cancellation identity");
    storage
        .record_admission_cancellation(
            IdempotentOperation::Run,
            &fresh,
            None,
            DurableCancellationOutcome::Cancelled,
            observed_at,
        )
        .expect("replace expired cancellation with active-key identity");

    let (stored_version, stored_expiry): (i64, String) = storage
        .connection_for_test()
        .query_row(
            "SELECT hmac_key_version, expires_at FROM admission_cancellations
             WHERE principal_ref = 'principal-hmac-reuse'
               AND operation = 'run'
               AND idempotency_key = 'reused-after-expiry'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read replacement cancellation");
    assert_eq!(stored_version, 2);
    assert_eq!(
        parse_time(&stored_expiry).expect("parse replacement expiry"),
        observed_at + IDEMPOTENCY_RETENTION
    );
    let retired_references: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM admission_cancellations WHERE hmac_key_version = 1",
            [],
            |row| row.get(0),
        )
        .expect("count retired-key cancellation references");
    assert_eq!(
        retired_references, 0,
        "fresh reuse must not extend retention of the retired-key tombstone"
    );
}
