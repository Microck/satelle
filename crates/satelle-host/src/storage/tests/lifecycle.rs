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
    assert_eq!(1, storage.session_count().unwrap());

    session = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            ExpectedRevisions::new(
                SessionStateRevision::initial(),
                TurnStateRevision::initial(),
            ),
            TurnTransition::Running,
            Some(&observed_refs("thread-private-1", "turn-private-1")),
            at(1),
        )
        .expect("commit running");
    session = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            None,
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
    session = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_2),
            revisions(&session, TURN_2),
            TurnTransition::Completed,
            Some(&observed_refs("thread-private-1", "turn-private-2")),
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
            Some(&observed_refs("thread-private-1", "turn-private-1")),
            at(1),
        )
        .unwrap();
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
            Some(&observed_refs("thread-private-1", "turn-private-1")),
            at(1),
        )
        .unwrap();
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
        .confirm_stop(
            claim,
            StopObservation::UpstreamInactiveConfirmed,
            None,
            at(3),
        )
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
            None,
            at(2),
        )
        .expect_err("a pending stop must block a later Running commit");
    assert_eq!(StorageErrorKind::StateConflict, error.kind());

    let stopped = storage
        .confirm_stop(
            claim,
            StopObservation::UpstreamInactiveConfirmed,
            None,
            at(2),
        )
        .expect("the stop claim should remain commit-able");
    assert_eq!(
        &StopCommitOutcome::Stopped(TurnState::Starting),
        stopped.outcome()
    );
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
            Some(&observed_refs("thread-private-1", "turn-private-1")),
            at(1),
        )
        .unwrap();
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
            None,
            at(3),
        )
        .expect("completion wins the terminal commit");

    let stop = storage
        .confirm_stop(
            claim,
            StopObservation::UpstreamInactiveConfirmed,
            None,
            at(4),
        )
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
    assert_eq!(1, storage.session_count().unwrap());

    let completed = storage
        .commit_lifecycle(
            session.id(),
            &turn_id(TURN_1),
            revisions(&session, TURN_1),
            TurnTransition::Completed,
            None,
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
    assert_eq!(1, storage.session_count().unwrap());
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
