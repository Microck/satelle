use super::*;

#[test]
fn terminal_session_round_trips_with_follow_up_and_exact_snapshot() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, recovery) = Storage::open(state.path()).expect("open storage");
    assert!(recovery.is_empty());
    let mut session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let run = admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0));

    let admitted = storage
        .begin_session(&session, &run)
        .expect("admit initial Session");
    let AdmissionOutcome::Execute {
        session: admitted,
        recovery_subject,
    } = admitted
    else {
        panic!("new Session admission must execute");
    };
    assert_eq!(session.snapshot(), admitted.snapshot());
    assert_eq!(session.id(), recovery_subject.session_id());
    assert_eq!(1, storage.snapshot().unwrap().session_count());

    session = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            ExpectedRevisions::new(
                SessionStateRevision::initial(),
                TurnStateRevision::initial(),
            ),
            TurnTransition::Running,
            at(1),
        )
        .expect("commit running");
    record_upstream_refs(
        &mut storage,
        session.id(),
        &turn_id(TURN_1),
        "thread-private-1",
        "turn-private-1",
    );
    session = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            at(2),
        )
        .expect("commit completion");

    let steer = admission(
        IdempotentOperation::Steer,
        "steer-1",
        "request-steer-1",
        at(3),
    );
    let follow_up = storage
        .begin_follow_up(
            session.id(),
            session.session_state_revision(),
            turn_id(TURN_2),
            policy(),
            at(3),
            &steer,
        )
        .expect("admit follow-up");
    let AdmissionOutcome::Execute {
        session: follow_up, ..
    } = follow_up
    else {
        panic!("new follow-up admission must execute");
    };
    session = follow_up;
    record_upstream_refs(
        &mut storage,
        session.id(),
        &turn_id(TURN_2),
        "thread-private-1",
        "turn-private-2",
    );
    session = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_2),
            revisions(&session, TURN_2),
            TurnTransition::Completed,
            at(4),
        )
        .expect("complete follow-up");
    let expected = session.snapshot();
    drop(storage);

    let (storage, recovery) = Storage::open(state.path()).expect("reopen storage");
    assert!(recovery.is_empty());
    let restored = storage
        .load_session(&session_id(SESSION_1))
        .expect("load Session")
        .expect("stored Session");
    assert_eq!(expected, restored.snapshot());
}

#[test]
fn upstream_reference_observation_is_lifecycle_neutral_idempotent_and_conflict_safe() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let context = admission(
        IdempotentOperation::Run,
        "run-reference-observation",
        "request-reference-observation",
        at(0),
    );
    let AdmissionOutcome::Execute {
        session: admitted, ..
    } = storage
        .begin_session(&session, &context)
        .expect("admit initial Session")
    else {
        panic!("new Session admission must execute");
    };
    let before = admitted.snapshot();
    let logs_before = storage
        .logs_after(None, 100)
        .expect("read logs before reference observation")
        .len();

    let thread_ref = ObservedUpstreamRef::thread("thread-private-1").unwrap();
    let turn_ref = ObservedUpstreamRef::turn("turn-private-1").unwrap();
    storage
        .record_upstream_ref(admitted.id(), &turn_id(TURN_1), &thread_ref)
        .expect("persist the first observed thread reference");
    storage
        .record_upstream_ref(admitted.id(), &turn_id(TURN_1), &turn_ref)
        .expect("persist the first observed Turn reference");
    storage
        .record_upstream_ref(admitted.id(), &turn_id(TURN_1), &thread_ref)
        .expect("recording the same thread reference must be idempotent");
    storage
        .record_upstream_ref(admitted.id(), &turn_id(TURN_1), &turn_ref)
        .expect("recording the same Turn reference must be idempotent");

    let conflicting_thread = storage
        .record_upstream_ref(
            admitted.id(),
            &turn_id(TURN_1),
            &ObservedUpstreamRef::thread("thread-private-conflict").unwrap(),
        )
        .expect_err("a different thread reference must fail closed");
    assert_eq!(
        StorageErrorKind::PrivateReferenceConflict,
        conflicting_thread.kind()
    );

    let conflicting_turn = storage
        .record_upstream_ref(
            admitted.id(),
            &turn_id(TURN_1),
            &ObservedUpstreamRef::turn("turn-private-conflict").unwrap(),
        )
        .expect_err("a different Turn reference must fail closed");
    assert_eq!(
        StorageErrorKind::PrivateReferenceConflict,
        conflicting_turn.kind()
    );

    let restored = storage
        .load_session(admitted.id())
        .expect("load Session after reference observation")
        .expect("stored Session");
    assert_eq!(before, restored.snapshot());
    assert_eq!(
        logs_before,
        storage
            .logs_after(None, 100)
            .expect("read logs after reference observation")
            .len()
    );
    let refs = storage
        .recovery_subject(admitted.id(), &turn_id(TURN_1))
        .expect("reload the final reference-bearing subject");
    let expected_thread_ref = PrivateUpstreamRef::new("thread-private-1").unwrap();
    let expected_turn_ref = PrivateUpstreamRef::new("turn-private-1").unwrap();
    assert_eq!(Some(&expected_thread_ref), refs.upstream_thread_ref());
    assert_eq!(Some(&expected_turn_ref), refs.upstream_turn_ref());
    assert!(matches!(
        storage
            .begin_session(&session, &context)
            .expect("idempotency outcome must remain readable"),
        AdmissionOutcome::InProgress(_)
    ));

    let competing = initial_session(&storage, SESSION_2, TURN_3, at(1));
    let lease_error = storage
        .begin_session(
            &competing,
            &admission(
                IdempotentOperation::Run,
                "run-reference-competitor",
                "request-reference-competitor",
                at(1),
            ),
        )
        .expect_err("reference persistence must retain Control Lease ownership");
    assert_eq!(StorageErrorKind::LeaseConflict, lease_error.kind());
}

#[test]
fn upstream_reference_rejects_a_valid_turn_owned_by_another_session() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let first = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session: first, .. } = storage
        .begin_session(
            &first,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit the first Session")
    else {
        panic!("new Session admission must execute");
    };
    let first = storage
        .commit_lifecycle(
            first.id(),
            &turn_id(TURN_1),
            revisions(&first, TURN_1),
            TurnTransition::Completed,
            at(1),
        )
        .expect("complete the first Session and release its lease");
    let second = initial_session(&storage, SESSION_2, TURN_2, at(2));
    let AdmissionOutcome::Execute {
        session: second, ..
    } = storage
        .begin_session(
            &second,
            &admission(IdempotentOperation::Run, "run-2", "request-run-2", at(2)),
        )
        .expect("admit the second Session")
    else {
        panic!("new Session admission must execute");
    };

    let error = storage
        .record_upstream_ref(
            first.id(),
            &turn_id(TURN_2),
            &ObservedUpstreamRef::thread("thread-cross-session").unwrap(),
        )
        .expect_err("a Turn owned by another Session must be rejected");
    assert_eq!(StorageErrorKind::InvalidStoredState, error.kind());
    assert!(
        storage
            .recovery_subject(first.id(), &turn_id(TURN_1))
            .expect("reload the first subject")
            .upstream_thread_ref()
            .is_none()
    );
    assert!(
        storage
            .recovery_subject(second.id(), &turn_id(TURN_2))
            .expect("reload the second subject")
            .upstream_thread_ref()
            .is_none()
    );
}

#[test]
fn upstream_references_cannot_alias_distinct_sessions_or_turns() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let first = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session: first, .. } = storage
        .begin_session(
            &first,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit the first Session")
    else {
        panic!("new Session admission must execute");
    };
    record_upstream_refs(
        &mut storage,
        first.id(),
        &turn_id(TURN_1),
        "thread-private-shared",
        "turn-private-shared",
    );
    storage
        .commit_lifecycle(
            first.id(),
            &turn_id(TURN_1),
            revisions(&first, TURN_1),
            TurnTransition::Completed,
            at(1),
        )
        .expect("complete the first Session and release its lease");

    let second = initial_session(&storage, SESSION_2, TURN_2, at(2));
    let AdmissionOutcome::Execute {
        session: second, ..
    } = storage
        .begin_session(
            &second,
            &admission(IdempotentOperation::Run, "run-2", "request-run-2", at(2)),
        )
        .expect("admit the second Session")
    else {
        panic!("new Session admission must execute");
    };

    let thread_error = storage
        .record_upstream_ref(
            second.id(),
            &turn_id(TURN_2),
            &ObservedUpstreamRef::thread("thread-private-shared").unwrap(),
        )
        .expect_err("one upstream thread must not belong to two Sessions");
    assert_eq!(
        StorageErrorKind::PrivateReferenceConflict,
        thread_error.kind()
    );

    let turn_error = storage
        .record_upstream_ref(
            second.id(),
            &turn_id(TURN_2),
            &ObservedUpstreamRef::turn("turn-private-shared").unwrap(),
        )
        .expect_err("one upstream Turn must not belong to two Satelle Turns");
    assert_eq!(
        StorageErrorKind::PrivateReferenceConflict,
        turn_error.kind()
    );

    let second_refs = storage
        .recovery_subject(second.id(), &turn_id(TURN_2))
        .expect("reload the second subject");
    assert!(second_refs.upstream_thread_ref().is_none());
    assert!(second_refs.upstream_turn_ref().is_none());
}

#[test]
fn restart_marks_active_turn_recovery_pending_and_retains_lease() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .unwrap();
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .unwrap();
    record_upstream_refs(
        &mut storage,
        running.id(),
        &turn_id(TURN_1),
        "thread-private-1",
        "turn-private-1",
    );
    drop(storage);

    let (mut storage, recovery) = Storage::open(state.path()).expect("restart storage");
    assert_eq!(1, recovery.len());
    assert_eq!(running.id(), recovery[0].session_id());
    assert_eq!(&turn_id(TURN_1), recovery[0].turn_id());
    assert_eq!(
        &storage.host_identity().expect("load Host Identity"),
        recovery[0].host_identity()
    );
    assert_eq!(
        &PrivateRequestToken::new("request-run-1").unwrap(),
        recovery[0].request_token()
    );
    assert!(recovery[0].upstream_thread_ref().is_some());
    assert!(recovery[0].upstream_turn_ref().is_some());
    let restored = storage
        .load_session(running.id())
        .unwrap()
        .expect("stored Session");
    assert!(matches!(
        restored.activity(),
        SessionActivity::RecoveryPending { .. }
    ));
    assert_eq!(3, restored.session_state_revision().get());
    assert_eq!(
        revisions(&restored, TURN_1),
        recovery[0].expected_revisions()
    );

    let competing = initial_session(&storage, SESSION_2, TURN_3, at(2));
    let error = storage
        .begin_session(
            &competing,
            &admission(IdempotentOperation::Run, "run-2", "request-run-2", at(2)),
        )
        .expect_err("retained lease blocks competing admission");
    assert_eq!(StorageErrorKind::LeaseConflict, error.kind());
    assert_eq!(Some(running.id()), error.conflicting_session_id());
}

#[test]
fn replay_only_open_preserves_running_state_before_external_admission() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let run = admission(
        IdempotentOperation::Run,
        "run-replay-only",
        "request-replay-only",
        at(0),
    );
    storage.begin_session(&session, &run).unwrap();
    storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .unwrap();

    let persisted_state = |connection: &rusqlite::Connection| {
        let lifecycle = connection
            .query_row(
                "SELECT sessions.session_state_revision, turns.turn_state_revision, turns.state, control_leases.lease_state \
                 FROM sessions JOIN turns USING (session_id) JOIN control_leases USING (session_id, turn_id) \
                 WHERE sessions.session_id = ?1",
                [SESSION_1],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .unwrap();
        let idempotency = connection
            .query_row(
                "SELECT status, durable_outcome FROM idempotency_records \
                 WHERE operation = 'run' AND idempotency_key = 'run-replay-only'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        let recovery_logs = connection
            .query_row(
                "SELECT count(*) FROM logs WHERE event_kind = 'restart_recovery_pending'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        (lifecycle, idempotency, recovery_logs)
    };
    let before = persisted_state(&storage.connection);
    assert_eq!(before.0.2, "running");
    assert_eq!(before.0.3, "active");
    assert_eq!(
        before.1,
        ("in_progress".to_string(), "v1.turn.running".to_string())
    );
    assert_eq!(before.2, 0);
    drop(storage);

    let storage = Storage::open_without_restart_recovery(state.path())
        .expect("replay-only open should validate without lifecycle mutation");
    let replay = storage
        .replay_admission_if_present(IdempotentOperation::Run, run.idempotency(), None)
        .expect("read the durable replay")
        .expect("the committed admission must be replayable");
    assert_eq!(replay.session_id(), session.id());
    assert_eq!(replay.turn_id(), &turn_id(TURN_1));
    assert_eq!(persisted_state(&storage.connection), before);
}

#[test]
fn begin_stop_claims_before_observation_and_confirmed_stop_releases_lease() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .unwrap();
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .unwrap();
    record_upstream_refs(
        &mut storage,
        running.id(),
        &turn_id(TURN_1),
        "thread-private-1",
        "turn-private-1",
    );
    let stop_idempotency = idempotency(IdempotentOperation::Stop, "stop-1", at(2));

    let claim = match storage
        .begin_stop(running.id(), &turn_id(TURN_1), &stop_idempotency)
        .expect("claim stop")
    {
        BeginStopOutcome::Observe(claim) => {
            assert_eq!(running.id(), claim.recovery_subject().session_id());
            claim
        }
        BeginStopOutcome::Complete(_) => {
            panic!("a newly claimed active Turn requires one observation")
        }
    };
    let replay_claim = match storage
        .begin_stop(running.id(), &turn_id(TURN_1), &stop_idempotency)
        .expect("pending stop replay")
    {
        BeginStopOutcome::Observe(claim) => claim,
        BeginStopOutcome::Complete(_) => {
            panic!("a pending stop replay must resume the existing observation")
        }
    };
    assert_eq!(running.id(), replay_claim.recovery_subject().session_id());
    let stopped = storage
        .confirm_stop(claim, StopObservation::UpstreamInactiveConfirmed, at(3))
        .expect("commit confirmed stop");
    assert_eq!(
        &StopCommitOutcome::Stopped(TurnState::Running),
        stopped.outcome()
    );
    assert!(!stopped.session().is_active());

    let replay = storage
        .begin_stop(stopped.session().id(), &turn_id(TURN_1), &stop_idempotency)
        .expect("replay stop");
    let BeginStopOutcome::Complete(replay) = replay else {
        panic!("terminal idempotency replay must not request adapter work");
    };
    assert_eq!(
        &StopCommitOutcome::Stopped(TurnState::Running),
        replay.outcome()
    );

    storage
        .begin_follow_up(
            stopped.session().id(),
            stopped.session().session_state_revision(),
            turn_id(TURN_2),
            policy(),
            at(4),
            &admission(
                IdempotentOperation::Steer,
                "steer-1",
                "request-steer-1",
                at(4),
            ),
        )
        .expect("released lease permits follow-up");
}

#[test]
fn pending_stop_blocks_a_later_nonterminal_execution_commit() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute {
        session: starting, ..
    } = storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit initial Session")
    else {
        panic!("new Session admission must execute");
    };
    let claim = match storage
        .begin_stop(
            starting.id(),
            &turn_id(TURN_1),
            &idempotency(IdempotentOperation::Stop, "stop-1", at(1)),
        )
        .expect("claim stop while the Turn is starting")
    {
        BeginStopOutcome::Observe(claim) => claim,
        BeginStopOutcome::Complete(_) => {
            panic!("a new stop must own the observation claim")
        }
    };

    let error = storage
        .commit_lifecycle(
            starting.id(),
            &turn_id(TURN_1),
            revisions(&starting, TURN_1),
            TurnTransition::Running,
            at(2),
        )
        .expect_err("a pending stop must block a later Running commit");
    assert_eq!(StorageErrorKind::StateConflict, error.kind());

    let stopped = storage
        .confirm_stop(claim, StopObservation::UpstreamInactiveConfirmed, at(2))
        .expect("the stop claim should remain commit-able");
    assert_eq!(
        &StopCommitOutcome::Stopped(TurnState::Starting),
        stopped.outcome()
    );
}

#[test]
fn stale_turn_revision_does_not_rewrite_the_winning_session_state() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let initial = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute {
        session: starting, ..
    } = storage
        .begin_session(
            &initial,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit initial Session")
    else {
        panic!("new Session admission must execute");
    };
    let running = storage
        .commit_lifecycle(
            starting.id(),
            &turn_id(TURN_1),
            revisions(&starting, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .expect("commit the winning Running transition");

    let stale = ExpectedRevisions::new(
        running.session_state_revision(),
        TurnStateRevision::initial(),
    );
    let error = storage
        .commit_lifecycle(
            running.id(),
            &turn_id(TURN_1),
            stale,
            TurnTransition::Completed,
            at(2),
        )
        .expect_err("the stale Turn revision must lose");

    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    let stored = storage
        .load_session(running.id())
        .expect("reload the winning state")
        .expect("winning Session remains stored");
    assert_eq!(running.snapshot(), stored.snapshot());
}

#[test]
fn lifecycle_completion_wins_a_stop_race_without_redeleting_its_lease() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    storage
        .begin_session(
            &session,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .unwrap();
    let running = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Running,
            at(1),
        )
        .unwrap();
    record_upstream_refs(
        &mut storage,
        running.id(),
        &turn_id(TURN_1),
        "thread-private-1",
        "turn-private-1",
    );
    let stop_idempotency = idempotency(IdempotentOperation::Stop, "stop-1", at(2));
    let BeginStopOutcome::Observe(claim) = storage
        .begin_stop(running.id(), &turn_id(TURN_1), &stop_idempotency)
        .unwrap()
    else {
        panic!("running Turn requires a stop observation");
    };
    let completed = storage
        .commit_lifecycle(
            running.id(),
            &turn_id(TURN_1),
            revisions(&running, TURN_1),
            TurnTransition::Completed,
            at(3),
        )
        .expect("completion wins the terminal commit");

    let stop = storage
        .confirm_stop(claim, StopObservation::UpstreamInactiveConfirmed, at(4))
        .expect("stop observes the winning terminal state");
    assert_eq!(
        &StopCommitOutcome::AlreadyTerminal(TerminalTurnState::Completed),
        stop.outcome()
    );
    assert_eq!(completed.snapshot(), stop.session().snapshot());
}

#[test]
fn admission_replays_the_same_request_and_rejects_a_changed_digest() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let context = admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0));
    let AdmissionOutcome::Execute { session, .. } =
        storage.begin_session(&session, &context).unwrap()
    else {
        panic!("a newly admitted request must execute exactly once");
    };

    let replay = storage
        .begin_session(&session, &context)
        .expect("matching request replays");
    let AdmissionOutcome::InProgress(replayed) = replay else {
        panic!("an in-progress replay must return its durable handles");
    };
    assert_eq!(session.snapshot(), replayed.snapshot());
    assert_eq!(1, storage.snapshot().unwrap().session_count());

    let completed = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            at(1),
        )
        .expect("complete the admitted request");
    let terminal_replay = storage
        .begin_session(&session, &context)
        .expect("terminal request replays from durable state");
    let AdmissionOutcome::Complete(replayed) = terminal_replay else {
        panic!("a terminal replay must not request adapter work or recovery");
    };
    assert_eq!(completed.snapshot(), replayed.snapshot());

    let mut conflicting = context.clone();
    conflicting.idempotency.request_digest =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let error = storage
        .begin_session(&session, &conflicting)
        .expect_err("changed digest conflicts");
    assert_eq!(StorageErrorKind::IdempotencyConflict, error.kind());
    assert_eq!(1, storage.snapshot().unwrap().session_count());
}

#[test]
fn run_replay_uses_stored_handles_and_the_original_terminal_snapshot() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let original = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let run = admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0));
    let AdmissionOutcome::Execute { session, .. } =
        storage.begin_session(&original, &run).expect("admit run")
    else {
        panic!("new run must execute");
    };
    let completed_run = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            at(1),
        )
        .expect("complete run");

    let steer = admission(
        IdempotentOperation::Steer,
        "steer-1",
        "request-steer-1",
        at(2),
    );
    let AdmissionOutcome::Execute {
        session: followed_up,
        ..
    } = storage
        .begin_follow_up(
            completed_run.id(),
            completed_run.session_state_revision(),
            turn_id(TURN_2),
            policy(),
            at(2),
            &steer,
        )
        .expect("admit later follow-up")
    else {
        panic!("new follow-up must execute");
    };
    storage
        .commit_lifecycle(
            followed_up.id(),
            &turn_id(TURN_2),
            revisions(&followed_up, TURN_2),
            TurnTransition::Completed,
            at(3),
        )
        .expect("complete later follow-up");

    // Session and Turn identifiers are server-generated proposal values. A
    // retry is identified by its idempotency identity and digest, so the
    // durable handles and original operation snapshot must win.
    let fresh_proposal = initial_session(&storage, SESSION_2, TURN_3, at(4));
    let AdmissionOutcome::Complete(replayed) = storage
        .begin_session(&fresh_proposal, &run)
        .expect("replay run with regenerated handles")
    else {
        panic!("terminal run replay must return its durable result");
    };
    assert_eq!(completed_run.snapshot(), replayed.snapshot());
}

#[test]
fn steer_replay_uses_its_stored_turn_handle() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let original = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute { session, .. } = storage
        .begin_session(
            &original,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit run")
    else {
        panic!("new run must execute");
    };
    let completed_run = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            at(1),
        )
        .expect("complete run");
    let steer = admission(
        IdempotentOperation::Steer,
        "steer-1",
        "request-steer-1",
        at(2),
    );
    let AdmissionOutcome::Execute {
        session: followed_up,
        ..
    } = storage
        .begin_follow_up(
            completed_run.id(),
            completed_run.session_state_revision(),
            turn_id(TURN_2),
            policy(),
            at(2),
            &steer,
        )
        .expect("admit follow-up")
    else {
        panic!("new follow-up must execute");
    };
    let completed_steer = storage
        .commit_lifecycle(
            followed_up.id(),
            &turn_id(TURN_2),
            revisions(&followed_up, TURN_2),
            TurnTransition::Completed,
            at(3),
        )
        .expect("complete follow-up");

    let AdmissionOutcome::Complete(replayed) = storage
        .begin_follow_up(
            completed_run.id(),
            completed_run.session_state_revision(),
            turn_id(TURN_3),
            policy(),
            at(4),
            &steer,
        )
        .expect("replay steer with a regenerated Turn handle")
    else {
        panic!("terminal steer replay must return its durable result");
    };
    assert_eq!(completed_steer.snapshot(), replayed.snapshot());
}

#[test]
fn in_progress_steer_replay_wins_before_active_turn_rejection() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let initial = initial_session(&storage, SESSION_1, TURN_1, at(0));
    let AdmissionOutcome::Execute {
        session: starting, ..
    } = storage
        .begin_session(
            &initial,
            &admission(IdempotentOperation::Run, "run-1", "request-run-1", at(0)),
        )
        .expect("admit run")
    else {
        panic!("new run must execute");
    };
    let completed = storage
        .commit_lifecycle(
            starting.id(),
            &turn_id(TURN_1),
            revisions(&starting, TURN_1),
            TurnTransition::Completed,
            at(1),
        )
        .expect("complete run");
    let steer = admission(
        IdempotentOperation::Steer,
        "steer-active-replay",
        "request-steer-active-replay",
        at(2),
    );
    let AdmissionOutcome::Execute {
        session: active, ..
    } = storage
        .begin_follow_up(
            completed.id(),
            completed.session_state_revision(),
            turn_id(TURN_2),
            policy(),
            at(2),
            &steer,
        )
        .expect("admit follow-up")
    else {
        panic!("new follow-up must execute");
    };

    let AdmissionOutcome::InProgress(replayed) = storage
        .begin_follow_up(
            completed.id(),
            completed.session_state_revision(),
            turn_id(TURN_3),
            policy(),
            at(3),
            &steer,
        )
        .expect("same-key active follow-up must replay")
    else {
        panic!("active same-key follow-up must not report HostBusy");
    };
    assert_eq!(active.snapshot(), replayed.snapshot());
}
