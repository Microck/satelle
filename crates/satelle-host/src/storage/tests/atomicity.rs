use super::*;

#[test]
fn admission_and_its_canonical_log_commit_atomically() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER reject_session_log \
             BEFORE INSERT ON logs \
             WHEN NEW.event_kind = 'session_started' \
             BEGIN SELECT RAISE(ABORT, 'reject test log'); END;",
        )
        .expect("install deterministic log failure");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));

    let error = storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect_err("a rejected canonical log must reject admission");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    assert_eq!(0, storage.snapshot().unwrap().session_count());
    for table in ["control_leases", "idempotency_records", "logs"] {
        let count: i64 = storage
            .connection_for_test()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(0, count, "{table} retained a partial admission");
    }
}

#[test]
fn confirmed_stop_and_its_canonical_log_commit_atomically() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .unwrap()
    else {
        panic!("new Session admission must execute");
    };
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .unwrap();
    let stop_idempotency = idempotency(IdempotentOperation::Stop, "stop-1", at(2));
    let BeginStopOutcome::Observe(claim) = storage
        .begin_stop(running.id(), &turn_id(TURN_1), &stop_idempotency)
        .unwrap()
    else {
        panic!("new stop request must observe the active Turn");
    };
    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER reject_stop_log \
             BEFORE INSERT ON logs \
             WHEN NEW.event_kind = 'stop_confirmed' \
             BEGIN SELECT RAISE(ABORT, 'reject test log'); END;",
        )
        .expect("install deterministic stop-log failure");

    let error = storage
        .confirm_stop(claim, StopObservation::UpstreamInactiveConfirmed, at(3))
        .expect_err("a rejected canonical log must reject the stop commit");

    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    let restored = storage
        .load_session(running.id())
        .unwrap()
        .expect("Session remains stored");
    assert_eq!(
        TurnState::Running,
        restored.turn(&turn_id(TURN_1)).unwrap().state()
    );
    let lease_count: i64 = storage
        .connection_for_test()
        .query_row("SELECT count(*) FROM control_leases", [], |row| row.get(0))
        .unwrap();
    assert_eq!(1, lease_count);
    let stop_status: String = storage
        .connection_for_test()
        .query_row(
            "SELECT status FROM idempotency_records WHERE operation = 'stop'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!("in_progress", stop_status);
}

#[test]
fn lifecycle_transitions_emit_one_canonical_log_in_their_transaction() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit Session")
    else {
        panic!("new Session must execute");
    };
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .expect("commit running");
    let completed = storage
        .commit_lifecycle(
            running.id(),
            &turn_id(TURN_1),
            revisions(&running, TURN_1),
            TurnTransition::Completed,
            at(2),
        )
        .expect("commit completed");

    let logs = storage.logs_after(None, 10).expect("load canonical logs");
    assert_eq!(3, logs.len());
    assert_eq!(LogEvent::SessionStarted, logs[0].record().event());
    for (log, expected_session_revision, expected_turn_revision) in [
        (
            &logs[1],
            running.session_state_revision(),
            running
                .turn(&turn_id(TURN_1))
                .unwrap()
                .turn_state_revision(),
        ),
        (
            &logs[2],
            completed.session_state_revision(),
            completed
                .turn(&turn_id(TURN_1))
                .unwrap()
                .turn_state_revision(),
        ),
    ] {
        assert_eq!(LogEvent::TurnStateCommitted, log.record().event());
        let crate::LogSubject::Turn {
            session_state_revision,
            turn_state_revision,
            ..
        } = log.record().subject()
        else {
            panic!("lifecycle log must have a Turn subject");
        };
        assert_eq!(expected_session_revision, *session_state_revision);
        assert_eq!(expected_turn_revision, *turn_state_revision);
    }
}

#[test]
fn lifecycle_transition_rolls_back_when_its_canonical_log_is_rejected() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit Session")
    else {
        panic!("new Session must execute");
    };
    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER reject_lifecycle_log \
             BEFORE INSERT ON logs \
             WHEN NEW.event_kind = 'turn_state_committed' \
             BEGIN SELECT RAISE(ABORT, 'reject test log'); END;",
        )
        .expect("install deterministic lifecycle-log failure");

    let error = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .expect_err("rejected canonical log must reject lifecycle commit");
    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    let restored = storage
        .load_session(session.id())
        .expect("load Session")
        .expect("stored Session");
    assert_eq!(session.snapshot(), restored.snapshot());
    assert_eq!(1, storage.logs_after(None, 10).unwrap().len());
}

#[test]
fn restart_recovery_transition_and_log_commit_atomically() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit Session")
    else {
        panic!("new Session must execute");
    };
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .expect("commit running");
    drop(storage);

    let (storage, recovery) = Storage::open(state.path()).expect("reopen for recovery");
    assert_eq!(1, recovery.len());
    let logs = storage.logs_after(None, 10).expect("load recovery log");
    assert_eq!(
        LogEvent::RestartRecoveryPending,
        logs.last().unwrap().record().event()
    );
    drop(storage);

    let connection = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    connection
        .execute_batch(
            "UPDATE turns SET state = 'running', turn_state_revision = '0000000000000002'; \
             UPDATE sessions SET session_state_revision = '0000000000000002'; \
             UPDATE control_leases SET lease_state = 'active';",
        )
        .expect("restore active lifecycle state");
    connection
        .execute(
            "UPDATE idempotency_records \
             SET status = 'in_progress', durable_outcome = 'v1.turn.running', \
                 completed_at = NULL, result_session_state_revision = NULL, \
                 result_session_updated_at = NULL \
             WHERE operation = 'run' AND turn_id = ?1",
            [TURN_1],
        )
        .expect("restore the original operation idempotency state");
    connection
        .execute_batch(
            "CREATE TRIGGER reject_recovery_log \
             BEFORE INSERT ON logs \
             WHEN NEW.event_kind = 'restart_recovery_pending' \
             BEGIN SELECT RAISE(ABORT, 'reject test log'); END;",
        )
        .expect("reject the next recovery log");
    drop(connection);

    let error = match Storage::open(state.path()) {
        Ok(_) => panic!("rejected recovery log must reject recovery transition"),
        Err(error) => error,
    };
    assert_eq!(StorageErrorKind::OperationFailed, error.kind());
    let connection = Connection::open(state.path().join(DATABASE_FILE_NAME)).unwrap();
    let state_token: String = connection
        .query_row(
            "SELECT state FROM turns WHERE turn_id = ?1",
            [TURN_1],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!("running", state_token);
    let idempotency_state: (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = connection
        .query_row(
            "SELECT status, durable_outcome, completed_at, \
                        result_session_state_revision, result_session_updated_at \
                 FROM idempotency_records \
                 WHERE operation = 'run' AND turn_id = ?1",
            [TURN_1],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("read rolled-back idempotency state");
    assert_eq!(
        (
            "in_progress".to_string(),
            "v1.turn.running".to_string(),
            None,
            None,
            None,
        ),
        idempotency_state
    );
    let recovery_log_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM logs WHERE event_kind = 'restart_recovery_pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(1, recovery_log_count);
    assert_eq!(running.id().as_str(), SESSION_1);
}
