use super::*;
use crate::{LogCursor, LogPageQuery, LogSubject};

const SESSION_RETENTION: time::Duration = time::Duration::days(7);

fn terminal_session(
    storage: &mut Storage,
    session: &str,
    turn: &str,
    started_at: OffsetDateTime,
    terminal_at: OffsetDateTime,
) -> Session {
    terminal_session_with_transition(
        storage,
        session,
        turn,
        started_at,
        terminal_at,
        TurnTransition::Completed,
    )
}

fn terminal_session_with_transition(
    storage: &mut Storage,
    session: &str,
    turn: &str,
    started_at: OffsetDateTime,
    terminal_at: OffsetDateTime,
    transition: TurnTransition,
) -> Session {
    let initial = initial_session(storage, session, turn, started_at);
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &initial,
            &admission(IdempotentOperation::Run, turn, turn, started_at),
        )
        .expect("admit Session")
    else {
        panic!("new Session admission must execute");
    };
    storage
        .commit_lifecycle(
            session.id(),
            &turn_id(turn),
            revisions(&session, turn),
            transition,
            terminal_at,
        )
        .expect("make Session terminal")
}

fn stopped_session(
    storage: &mut Storage,
    session: &str,
    turn: &str,
    started_at: OffsetDateTime,
    terminal_at: OffsetDateTime,
) -> Session {
    let initial = initial_session(storage, session, turn, started_at);
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &initial,
            &admission(IdempotentOperation::Run, turn, turn, started_at),
        )
        .expect("admit Session")
    else {
        panic!("new Session admission must execute");
    };
    let claim = match storage
        .begin_stop(
            session.id(),
            &turn_id(turn),
            &idempotency(IdempotentOperation::Stop, "retention-stop", terminal_at),
        )
        .expect("claim Session stop")
    {
        BeginStopOutcome::Observe(claim) => claim,
        BeginStopOutcome::Complete(_) => panic!("new stop must require observation"),
    };
    storage
        .confirm_stop(
            claim,
            StopObservation::UpstreamInactiveConfirmed,
            terminal_at,
        )
        .expect("confirm Session stop")
        .session()
        .clone()
}

fn table_rows_for_session(storage: &Storage, table: &str, session: &SessionId) -> i64 {
    storage
        .connection_for_test()
        .query_row(
            &format!("SELECT count(*) FROM {table} WHERE session_id = ?1"),
            [session.as_str()],
            |row| row.get(0),
        )
        .expect("count Session-owned rows")
}

#[test]
fn terminal_session_expires_only_after_the_exact_seven_day_boundary() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let terminal_at = at(1);
    let session = terminal_session(&mut storage, SESSION_1, TURN_1, at(0), terminal_at);

    storage
        .prune_expired_session_metadata(terminal_at + SESSION_RETENTION)
        .expect("maintain retention at the exact boundary");
    assert!(storage.load_session(session.id()).unwrap().is_some());

    storage
        .prune_expired_session_metadata(
            terminal_at + SESSION_RETENTION + time::Duration::nanoseconds(1),
        )
        .expect("maintain retention after the boundary");
    assert!(storage.load_session(session.id()).unwrap().is_none());
}

#[test]
fn retention_age_starts_when_the_latest_follow_up_becomes_terminal() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let first_terminal_at = at(1);
    let first = terminal_session(&mut storage, SESSION_1, TURN_1, at(0), first_terminal_at);
    let follow_up_started_at = first_terminal_at + time::Duration::days(8);
    let follow_up_idempotency = admission(
        IdempotentOperation::Steer,
        "follow-up-retention",
        "follow-up-retention",
        follow_up_started_at,
    );
    let AdmissionOutcome::Execute {
        session: follow_up, ..
    } = storage
        .begin_follow_up(
            first.id(),
            first.session_state_revision(),
            turn_id(TURN_2),
            policy(),
            follow_up_started_at,
            &follow_up_idempotency,
        )
        .expect("admit follow-up")
    else {
        panic!("new follow-up admission must execute");
    };
    let latest_terminal_at = follow_up_started_at + time::Duration::seconds(1);
    let terminal = storage
        .commit_lifecycle(
            follow_up.id(),
            &turn_id(TURN_2),
            revisions(&follow_up, TURN_2),
            TurnTransition::Completed,
            latest_terminal_at,
        )
        .expect("complete follow-up");

    storage
        .prune_expired_session_metadata(latest_terminal_at + SESSION_RETENTION)
        .expect("maintain retention at the latest Turn boundary");
    assert!(storage.load_session(terminal.id()).unwrap().is_some());

    storage
        .prune_expired_session_metadata(
            latest_terminal_at + SESSION_RETENTION + time::Duration::nanoseconds(1),
        )
        .expect("maintain retention after the latest Turn boundary");
    assert!(storage.load_session(terminal.id()).unwrap().is_none());
}

#[test]
fn every_terminal_turn_state_is_eligible_for_retention() {
    for (terminal_state, transition) in [
        ("completed", TurnTransition::Completed),
        ("blocked", TurnTransition::Blocked),
        ("failed", TurnTransition::Failed),
    ] {
        let state = TempDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let terminal_at = at(1);
        let session = terminal_session_with_transition(
            &mut storage,
            SESSION_1,
            TURN_1,
            at(0),
            terminal_at,
            transition,
        );

        storage
            .prune_expired_session_metadata(
                terminal_at + SESSION_RETENTION + time::Duration::nanoseconds(1),
            )
            .expect("prune terminal Session metadata");

        assert_eq!(
            0,
            table_rows_for_session(&storage, "sessions", session.id()),
            "{terminal_state}"
        );
    }

    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let terminal_at = at(1);
    let stopped = stopped_session(&mut storage, SESSION_1, TURN_1, at(0), terminal_at);
    storage
        .prune_expired_session_metadata(
            terminal_at + SESSION_RETENTION + time::Duration::nanoseconds(1),
        )
        .expect("prune stopped Session metadata");
    assert_eq!(
        0,
        table_rows_for_session(&storage, "sessions", stopped.id()),
        "stopped"
    );
}

#[test]
fn an_older_nonterminal_turn_blocks_session_deletion_without_a_control_lease() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let first = terminal_session(&mut storage, SESSION_1, TURN_1, at(0), at(1));
    let AdmissionOutcome::Execute {
        session: follow_up, ..
    } = storage
        .begin_follow_up(
            first.id(),
            first.session_state_revision(),
            turn_id(TURN_2),
            policy(),
            at(2),
            &admission(
                IdempotentOperation::Steer,
                "nonterminal-retention",
                "nonterminal-retention",
                at(2),
            ),
        )
        .expect("admit follow-up")
    else {
        panic!("new follow-up admission must execute");
    };
    let latest = storage
        .commit_lifecycle(
            follow_up.id(),
            &turn_id(TURN_2),
            revisions(&follow_up, TURN_2),
            TurnTransition::Completed,
            at(3),
        )
        .expect("complete latest Turn");
    // Hydration rejects an older active Turn, but the SQLite contract permits
    // this shape. Retention must preserve the evidence instead of deleting it.
    storage
        .connection_for_test()
        .execute(
            "UPDATE turns
             SET state = 'running', terminal_at = NULL, safe_summary = NULL
             WHERE turn_id = ?1",
            [TURN_1],
        )
        .expect("inject older nonterminal Turn");

    storage
        .prune_expired_session_metadata(at(3) + time::Duration::days(30))
        .expect("maintain retention around a nonterminal Turn");

    assert_eq!(1, table_rows_for_session(&storage, "sessions", latest.id()));
    assert_eq!(
        "running",
        storage
            .connection_for_test()
            .query_row(
                "SELECT state FROM turns WHERE turn_id = ?1",
                [TURN_1],
                |row| row.get::<_, String>(0),
            )
            .expect("load preserved nonterminal state")
    );
    assert_eq!(
        0,
        table_rows_for_session(&storage, "control_leases", latest.id())
    );
}

#[test]
fn a_control_lease_blocks_terminal_session_deletion() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let terminal_at = at(1);
    let session = terminal_session(&mut storage, SESSION_1, TURN_1, at(0), terminal_at);
    let lease_at = terminal_at.format(&Rfc3339).unwrap();
    let host_identity = storage.host_identity().unwrap();
    storage
        .connection_for_test()
        .execute(
            "INSERT INTO control_leases (
                 host_identity_ref, desktop_binding_ref, operation_id,
                 owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                 acquired_at, heartbeat_at, lease_state, session_id, turn_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active', ?8, ?9)",
            params![
                host_identity.as_str(),
                "desktop-binding-1",
                "retention-lease",
                i64::from(std::process::id()),
                "process-start-retention",
                "boot-retention",
                lease_at,
                session.id().as_str(),
                TURN_1,
            ],
        )
        .expect("inject terminal Session control lease");

    storage
        .prune_expired_session_metadata(terminal_at + time::Duration::days(30))
        .expect("maintain retention around a control lease");

    assert_eq!(
        1,
        table_rows_for_session(&storage, "sessions", session.id())
    );
    assert_eq!(
        1,
        table_rows_for_session(&storage, "control_leases", session.id())
    );
}

#[test]
fn unexpired_idempotency_record_blocks_session_deletion() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let terminal_at = at(1);
    let session = terminal_session(&mut storage, SESSION_1, TURN_1, at(0), terminal_at);
    let observed_at = terminal_at + time::Duration::days(30);
    storage
        .connection_for_test()
        .execute(
            "UPDATE idempotency_records SET expires_at = ?1 WHERE session_id = ?2",
            params![
                (observed_at + time::Duration::hours(1))
                    .format(&Rfc3339)
                    .unwrap(),
                session.id().as_str()
            ],
        )
        .expect("extend the durable replay fixture");
    let last_cursor: i64 = storage
        .connection_for_test()
        .query_row("SELECT max(log_cursor) FROM logs", [], |row| row.get(0))
        .expect("read the last retained cursor");

    storage
        .prune_expired_session_metadata(observed_at)
        .expect("maintain retention around an unexpired replay");

    assert!(storage.load_session(session.id()).unwrap().is_some());
    assert_eq!(0, table_rows_for_session(&storage, "logs", session.id()));
    assert_eq!(
        1,
        table_rows_for_session(&storage, "idempotency_records", session.id())
    );
    let expired_through: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT expired_through_cursor FROM log_retention_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("read the expired cursor high-water mark");
    assert_eq!(last_cursor, expired_through);
}

#[test]
fn expired_pending_stop_does_not_preserve_a_terminal_session() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let started_at = at(0);
    let stop_at = at(1);
    let terminal_at = at(2);
    let initial = initial_session(&storage, SESSION_1, TURN_1, started_at);
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &initial,
            &admission(IdempotentOperation::Run, TURN_1, TURN_1, started_at),
        )
        .expect("admit Session")
    else {
        panic!("new Session admission must execute");
    };
    assert!(matches!(
        storage
            .begin_stop(
                session.id(),
                &turn_id(TURN_1),
                &idempotency(IdempotentOperation::Stop, "pending-stop", stop_at),
            )
            .expect("claim Session stop"),
        BeginStopOutcome::Observe(_)
    ));
    let terminal = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            terminal_at,
        )
        .expect("complete the Turn after stop observation is interrupted");
    assert!(
        terminal
            .turn(&turn_id(TURN_1))
            .expect("terminal Session retains its Turn")
            .state()
            .is_terminal()
    );
    assert_eq!(
        0,
        table_rows_for_session(&storage, "control_leases", session.id())
    );

    storage
        .prune_expired_session_metadata(terminal_at + time::Duration::days(30))
        .expect("prune terminal Session with an expired pending stop");

    assert!(storage.load_session(session.id()).unwrap().is_none());
    assert_eq!(
        0,
        table_rows_for_session(&storage, "idempotency_records", session.id())
    );
}

#[test]
fn retention_without_due_work_does_not_request_sqlite_write_ownership() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .connection_for_test()
        .busy_timeout(std::time::Duration::from_millis(1))
        .unwrap();
    let blocker = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    storage
        .prune_expired_session_metadata(time::OffsetDateTime::now_utc())
        .expect("a read-only no-work check must not contend for write ownership");

    blocker.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn due_retention_work_still_requests_sqlite_write_ownership() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .connection_for_test()
        .busy_timeout(std::time::Duration::from_millis(1))
        .unwrap();
    let observed_at = time::OffsetDateTime::now_utc();
    let session = terminal_session(
        &mut storage,
        SESSION_1,
        TURN_1,
        observed_at - time::Duration::days(8) - time::Duration::seconds(1),
        observed_at - time::Duration::days(8),
    );
    let blocker = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    let error = storage
        .prune_expired_session_metadata(observed_at)
        .expect_err("due cleanup must acquire write ownership");
    assert_eq!(StorageErrorKind::Busy, error.kind());
    assert!(storage.load_session(session.id()).unwrap().is_some());

    blocker.execute_batch("ROLLBACK").unwrap();
    storage
        .prune_expired_session_metadata(observed_at)
        .expect("cleanup must succeed after write ownership is available");
    assert!(storage.load_session(session.id()).unwrap().is_none());
}

#[test]
fn expiring_the_session_that_owns_all_logs_preserves_the_cursor_high_water() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let observed_at = time::OffsetDateTime::now_utc();
    let session = terminal_session(
        &mut storage,
        SESSION_1,
        TURN_1,
        observed_at - time::Duration::days(8) - time::Duration::seconds(1),
        observed_at - time::Duration::days(8),
    );
    let delivered_cursor: i64 = storage
        .connection_for_test()
        .query_row("SELECT max(log_cursor) FROM logs", [], |row| row.get(0))
        .expect("load delivered cursor");

    storage
        .prune_expired_session_metadata(observed_at)
        .expect("prune expired log prefix and Session");

    assert!(storage.load_session(session.id()).unwrap().is_none());
    let delivered_cursor = u64::try_from(delivered_cursor).unwrap();
    let page = storage
        .log_page(
            &LogPageQuery::forward(Some(LogCursor::from_position(delivered_cursor)), 10)
                .expect("valid delivered cursor query"),
        )
        .expect("a delivered cursor must not become cursor-ahead");
    assert!(page.entries().is_empty());
    assert_eq!(delivered_cursor, page.next_cursor().position());
}

#[test]
fn monotonic_clamped_logs_delay_session_cleanup_until_the_logs_expire() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let observed_at = time::OffsetDateTime::now_utc();
    storage
        .append_safe_log(
            &SafeLogRecord::new(
                observed_at,
                LogSource::Storage,
                LogSeverity::Info,
                LogEvent::StoreOpened,
                LogSubject::Host,
            )
            .expect("build current host log"),
        )
        .expect("establish the monotonic log clock");
    let session = terminal_session(
        &mut storage,
        SESSION_1,
        TURN_1,
        observed_at - time::Duration::days(8) - time::Duration::seconds(1),
        observed_at - time::Duration::days(8),
    );

    storage
        .prune_expired_session_metadata(observed_at)
        .expect("maintain retention with young clamped logs");

    assert!(storage.load_session(session.id()).unwrap().is_some());
    assert!(table_rows_for_session(&storage, "logs", session.id()) > 0);
    let oldest_session_log: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT min(recorded_at_unix_nanos) FROM logs WHERE session_id = ?1",
            [session.id().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(oldest_session_log >= i64::try_from(observed_at.unix_timestamp_nanos()).unwrap());
}

#[test]
fn canonical_log_prefix_expiry_removes_the_now_logless_session_and_dependencies() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let observed_at = time::OffsetDateTime::now_utc();
    let session = terminal_session(
        &mut storage,
        SESSION_1,
        TURN_1,
        observed_at - time::Duration::days(8) - time::Duration::seconds(1),
        observed_at - time::Duration::days(8),
    );
    let last_cursor: i64 = storage
        .connection_for_test()
        .query_row("SELECT max(log_cursor) FROM logs", [], |row| row.get(0))
        .unwrap();

    storage
        .prune_expired_session_metadata(observed_at)
        .expect("expire logs and Session in one transaction");

    for table in ["sessions", "turns", "idempotency_records", "logs"] {
        assert_eq!(
            0,
            table_rows_for_session(&storage, table, session.id()),
            "{table}"
        );
    }
    let private_session_rows: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM session_private_refs WHERE session_id = ?1",
            [session.id().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let private_turn_rows: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM turn_private_refs WHERE turn_id = ?1",
            [TURN_1],
            |row| row.get(0),
        )
        .unwrap();
    let policy_rows: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM turn_policies WHERE turn_id = ?1",
            [TURN_1],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        (0, 0, 0),
        (private_session_rows, private_turn_rows, policy_rows)
    );
    let expired_through: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT expired_through_cursor FROM log_retention_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last_cursor, expired_through);
}

#[test]
fn cleanup_failure_rolls_back_every_dependency_deletion() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = terminal_session(&mut storage, SESSION_1, TURN_1, at(0), at(1));
    storage
        .connection_for_test()
        .execute_batch(&format!(
            "CREATE TRIGGER fail_session_retention BEFORE DELETE ON sessions
             WHEN OLD.session_id = '{}'
             BEGIN
                 SELECT RAISE(ABORT, 'forced retention failure');
             END;",
            session.id().as_str()
        ))
        .expect("install retention failure fixture");
    let before = ["sessions", "turns", "idempotency_records", "logs"]
        .map(|table| table_rows_for_session(&storage, table, session.id()));
    let expired_through_before: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT expired_through_cursor FROM log_retention_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();

    storage
        .prune_expired_session_metadata(at(1) + time::Duration::days(8))
        .expect_err("cleanup must surface an atomic failure");

    let after = ["sessions", "turns", "idempotency_records", "logs"]
        .map(|table| table_rows_for_session(&storage, table, session.id()));
    assert_eq!(before, after);
    let expired_through_after: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT expired_through_cursor FROM log_retention_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expired_through_before, expired_through_after);
}
