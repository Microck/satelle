use super::*;

#[test]
fn stable_run_replay_skips_repeated_adapter_preflight() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let preflight_calls = Arc::new(AtomicUsize::new(0));
    let execute_calls = Arc::new(AtomicUsize::new(0));
    let adapter = PreflightCountingAdapter {
        preflight_calls: Arc::clone(&preflight_calls),
        execute_calls: Arc::clone(&execute_calls),
    };
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter);
    let identity = RequestIdentity::new("stable-preflight-key", STABLE_DIGEST);

    runtime
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_PREFLIGHT_REPLAY",
            identity.clone(),
        ))
        .expect("first request should execute");
    runtime
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_PREFLIGHT_REPLAY",
            identity,
        ))
        .expect("stable retry should replay");

    assert_eq!(preflight_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn stable_run_replay_after_restart_skips_adapter_preflight() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let state_root = state.path().to_path_buf();
    let identity = RequestIdentity::new("stable-restart-key", STABLE_DIGEST);
    let initial = RuntimeHandle::new(
        Ok(state_root.clone()),
        PreflightCountingAdapter {
            preflight_calls: Arc::new(AtomicUsize::new(0)),
            execute_calls: Arc::new(AtomicUsize::new(0)),
        },
    );
    let first = initial
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_RESTART_REPLAY",
            identity.clone(),
        ))
        .expect("the original request should complete");
    drop(initial);

    let preflight_calls = Arc::new(AtomicUsize::new(0));
    let execute_calls = Arc::new(AtomicUsize::new(0));
    let restarted = RuntimeHandle::new(
        Ok(state_root),
        PreflightCountingAdapter {
            preflight_calls: Arc::clone(&preflight_calls),
            execute_calls: Arc::clone(&execute_calls),
        },
    );
    let replay = restarted
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_RESTART_REPLAY",
            identity,
        ))
        .expect("the restarted runtime should return the durable result");

    assert_eq!(replay.session.session_id, first.session.session_id);
    assert_eq!(preflight_calls.load(Ordering::SeqCst), 0);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_attached_run_returns_in_progress_handles_without_waiting_for_execution() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = SubjectBlockingAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let identity = RequestIdentity::new("stable-in-progress-key", STABLE_DIGEST);
    let first_runtime = runtime.clone();
    let first_identity = identity.clone();
    let first = std::thread::spawn(move || {
        first_runtime.run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_IN_PROGRESS_REPLAY",
            first_identity,
        ))
    });
    let session_id = adapter
        .session_receiver
        .lock()
        .expect("subject receiver lock should not be poisoned")
        .recv_timeout(WAIT_LIMIT)
        .expect("the original execution should expose its durable Session");

    let duplicate_runtime = runtime.clone();
    let (duplicate_sender, duplicate_receiver) = mpsc::sync_channel(1);
    let duplicate = std::thread::spawn(move || {
        let outcome = duplicate_runtime.run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_IN_PROGRESS_REPLAY",
            identity,
        ));
        duplicate_sender
            .send(outcome)
            .expect("duplicate result receiver should remain connected");
    });

    let replay = match duplicate_receiver.recv_timeout(WAIT_LIMIT) {
        Ok(outcome) => outcome.expect("the duplicate should return durable in-progress handles"),
        Err(error) => {
            adapter.execute_release.signal();
            first
                .join()
                .expect("original request should not panic")
                .ok();
            duplicate
                .join()
                .expect("duplicate request should not panic");
            panic!("the duplicate waited for adapter execution to finish: {error}");
        }
    };
    assert_eq!(replay.session.session_id, session_id);
    assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 1);

    adapter.execute_release.signal();
    first
        .join()
        .expect("original request should not panic")
        .expect("original request should complete");
    duplicate
        .join()
        .expect("duplicate request should not panic");
}

#[test]
fn stable_steer_replays_while_a_later_turn_is_active() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = BlockOnThirdExecutionAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "PRIVATE_INITIAL"))
        .expect("initial run should complete")
        .session
        .session_id;
    let identity = RequestIdentity::new("stable-active-steer", STABLE_DIGEST);
    let original = runtime
        .steer(SteerCommand::attached_with_identity(
            session_id.clone(),
            "PRIVATE_ORIGINAL_STEER",
            identity.clone(),
        ))
        .expect("original steer should complete");

    runtime
        .steer(SteerCommand::detached(
            session_id.clone(),
            "PRIVATE_LATER_ACTIVE_STEER",
        ))
        .expect("later steer should be admitted");
    assert!(
        adapter.blocked_started.wait_for(WAIT_LIMIT),
        "later execution should become active"
    );

    let replay = runtime
        .steer(SteerCommand::attached_with_identity(
            session_id,
            "PRIVATE_ORIGINAL_STEER",
            identity,
        ))
        .expect("stable retry should replay despite the later active Turn");
    assert_eq!(replay.session.turns, original.session.turns);
    assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 3);

    adapter.blocked_release.signal();
    runtime
        .wait_for_background()
        .expect("later detached worker should finish");
}

#[test]
fn proven_running_restart_work_is_restored_and_keeps_admission_blocked() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let state_root = state.path().to_path_buf();
    let interrupted = RuntimeHandle::new(Ok(state_root.clone()), FailFirstAdapter::default());
    let session = interrupted
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_RUNNING_RECOVERY",
        ))
        .expect("interrupted work should be admitted")
        .session;
    interrupted
        .wait_for_background()
        .expect("interrupted worker should finish");
    drop(interrupted);

    let restarted = RuntimeHandle::new(Ok(state_root), RunningRecoveryAdapter);
    let error = restarted
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_CONFLICTING_ADMISSION",
        ))
        .expect_err("a proven-running Turn must retain the Control Lease");

    assert_eq!(error.code, ErrorCode::HostBusy);
    let status = restarted
        .status(session.session_id.clone())
        .expect("restored running Session should remain readable");
    assert_eq!(status.status, satelle_core::TurnStatus::Started);
    assert_eq!(
        restarted
            .startup_state()
            .expect("reconciled running work should clear startup recovery"),
        RuntimeStartupState::Ready
    );
    restarted
        .stop(StopCommand::new(session.session_id))
        .expect("test cleanup should stop the restored Turn");
}

#[test]
fn stop_during_recovery_observation_does_not_resurrect_the_subject() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let state_root = state.path().to_path_buf();
    let interrupted = RuntimeHandle::new(Ok(state_root.clone()), FailFirstAdapter::default());
    let session = interrupted
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_RECOVERY_STOP_RACE",
        ))
        .expect("interrupted work should be admitted")
        .session;
    interrupted
        .wait_for_background()
        .expect("interrupted worker should finish");
    drop(interrupted);

    let adapter = BlockingRecoveryAdapter::default();
    let restarted = RuntimeHandle::new(Ok(state_root), adapter.clone());
    let admission_runtime = restarted.clone();
    let admission = std::thread::spawn(move || {
        admission_runtime.run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_AFTER_CONCURRENT_STOP",
        ))
    });
    assert!(
        adapter.recovery_started.wait_for(WAIT_LIMIT),
        "admission should begin recovery observation"
    );

    let stopped = restarted
        .stop(StopCommand::new(session.session_id.clone()))
        .expect("explicit stop should resolve the observed recovery subject");
    assert_eq!(stopped.current_state(), TurnState::Stopped);
    adapter.recovery_release.signal();

    let new_outcome = admission
        .join()
        .expect("admission thread should not panic")
        .expect("resolved recovery should allow the waiting admission");
    assert_eq!(
        new_outcome.session.status,
        satelle_core::TurnStatus::Completed
    );
    assert_eq!(
        restarted
            .startup_state()
            .expect("concurrent stop must clear recovery state"),
        RuntimeStartupState::Ready
    );
}

#[test]
fn attached_execution_losing_to_stop_returns_the_durable_stopped_state() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = SubjectBlockingAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let run_runtime = runtime.clone();
    let attached = std::thread::spawn(move || {
        run_runtime.run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_ATTACHED_STOP_RACE",
        ))
    });
    let session_id = adapter
        .session_receiver
        .lock()
        .expect("subject receiver lock should not be poisoned")
        .recv_timeout(WAIT_LIMIT)
        .expect("adapter should expose the admitted Session");

    runtime
        .stop(StopCommand::new(session_id))
        .expect("stop should win the terminal compare-and-swap");
    adapter.execute_release.signal();
    let outcome = attached
        .join()
        .expect("attached execution thread should not panic")
        .expect("the losing execution should return durable terminal state");

    assert_eq!(outcome.session.status, satelle_core::TurnStatus::Stopped);
    assert!(
        outcome
            .events
            .iter()
            .all(|event| event.event_type() != EventType::TurnCompleted),
        "a losing completion must not be reported as committed"
    );
}

#[test]
fn cancellation_confirmed_worker_exit_does_not_block_new_turn_admission() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = BlockingExecutionAndStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_LINGERING_LOCAL_WORKER",
        ))
        .expect("the original detached Turn should be admitted")
        .session
        .session_id;
    assert!(
        adapter.execute_started.wait_for(WAIT_LIMIT),
        "the original local worker should start"
    );

    let stop_runtime = runtime.clone();
    let stop_session_id = session_id.clone();
    let (stop_sender, stop_receiver) = mpsc::sync_channel(1);
    let stop_worker = std::thread::spawn(move || {
        stop_sender
            .send(stop_runtime.stop(StopCommand::new(stop_session_id)))
            .expect("stop receiver should remain connected");
    });
    assert!(
        adapter.stop_started.wait_for(WAIT_LIMIT),
        "stop observation should start"
    );
    adapter.stop_release.signal();
    stop_receiver
        .recv_timeout(WAIT_LIMIT)
        .expect("stop should finish")
        .expect("confirmed stop should win");
    stop_worker.join().expect("stop worker should not panic");

    let admitted = runtime
        .steer(SteerCommand::detached(
            session_id.clone(),
            "PRIVATE_AFTER_CONFIRMED_CANCELLATION",
        ))
        .expect("a cancellation-confirmed worker must not become a second admission authority");
    assert_eq!(admitted.session.status, satelle_core::TurnStatus::Started);
    assert_eq!(admitted.session.turns.len(), 2);

    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("both detached workers should finish");
    let recovered = runtime
        .steer(SteerCommand::attached(
            session_id,
            "PRIVATE_AFTER_WORKER_REAP",
        ))
        .expect("a later Turn should execute after the worker slot is reaped");
    assert_eq!(
        recovered.session.status,
        satelle_core::TurnStatus::Completed
    );
}

#[test]
fn stop_proven_still_active_is_not_queued_for_running_to_running_recovery() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = StillActiveStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_STILL_ACTIVE_STOP",
        ))
        .expect("detached Turn should be admitted")
        .session
        .session_id;
    assert!(
        adapter.execute_started.wait_for(WAIT_LIMIT),
        "adapter execution should start"
    );

    let stop_error = runtime
        .stop(StopCommand::new(session_id))
        .expect_err("known-active stop observation should report not confirmed");
    assert_eq!(stop_error.code, ErrorCode::RemoteExecution);
    assert_eq!(stop_error.details["ownership"], "active");
    let error = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_CONFLICTING_AFTER_STILL_ACTIVE",
        ))
        .expect_err("the retained Control Lease should block new admission");
    assert_eq!(error.code, ErrorCode::HostBusy);
    assert_eq!(adapter.recovery_calls.load(Ordering::SeqCst), 0);

    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the original worker should finish");
}

#[test]
fn preflight_and_execution_use_the_same_adapter_instance() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = CloneDistinguishingAdapter {
        instance: 1,
        preflight_instance: Arc::new(AtomicUsize::new(0)),
    };
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter);

    let outcome = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_SINGLE_ADAPTER_INSTANCE",
        ))
        .expect("one adapter instance should own preflight and execution");
    assert_eq!(outcome.session.status, satelle_core::TurnStatus::Completed);
}

#[test]
fn pending_stop_retry_resumes_observation_and_then_replays() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = FailFirstStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(LOCAL_DEMO_HOST, "PRIVATE_STOP_RETRY"))
        .expect("detached Turn should be admitted")
        .session
        .session_id;
    assert!(
        adapter.execute_started.wait_for(WAIT_LIMIT),
        "adapter execution should start"
    );
    let identity = RequestIdentity::new("stable-stop-resume", STABLE_DIGEST);

    runtime
        .stop(StopCommand::with_identity(
            session_id.clone(),
            identity.clone(),
        ))
        .expect_err("the first stop observation should fail");
    let stopped = runtime
        .stop(StopCommand::with_identity(
            session_id.clone(),
            identity.clone(),
        ))
        .expect("the same key should resume and confirm stop");
    let replay = runtime
        .stop(StopCommand::with_identity(session_id, identity))
        .expect("the completed stop should replay without observation");

    assert_eq!(stopped.current_state(), TurnState::Stopped);
    assert_eq!(replay.current_state(), TurnState::Stopped);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 2);
    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the stopped execution worker should finish");
}

#[test]
fn pending_stop_retry_completes_after_the_turn_terminalizes() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let adapter = FailFirstStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_STOP_TERMINAL_RETRY",
        ))
        .expect("detached Turn should be admitted")
        .session
        .session_id;
    assert!(
        adapter.execute_started.wait_for(WAIT_LIMIT),
        "adapter execution should start"
    );
    let identity = RequestIdentity::new("stable-stop-terminal", STABLE_DIGEST);
    runtime
        .stop(StopCommand::with_identity(
            session_id.clone(),
            identity.clone(),
        ))
        .expect_err("the first stop observation should fail");

    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the original execution should complete");
    let replay = runtime
        .stop(StopCommand::with_identity(session_id, identity))
        .expect("terminal Turn should complete the pending stop idempotency");

    assert_eq!(replay.current_state(), TurnState::Completed);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn stop_winning_before_running_skips_adapter_execution_and_returns_stopped() {
    let state = tempfile::tempdir().expect("temporary state directory should exist");
    let execute_calls = Arc::new(AtomicUsize::new(0));
    let runtime = RuntimeHandle::new(
        Ok(state.path().to_path_buf()),
        PreflightCountingAdapter {
            preflight_calls: Arc::new(AtomicUsize::new(0)),
            execute_calls: Arc::clone(&execute_calls),
        },
    );
    let engine = runtime.engine().expect("open runtime storage");
    let readiness = FakeComputerUseAdapter
        .preflight(LOCAL_DEMO_HOST)
        .expect("fake adapter should be ready");
    let session_id = satelle_core::SessionId::new();
    let turn_id = satelle_core::TurnId::new();
    let started_at = time::OffsetDateTime::now_utc();
    let host_identity = engine
        .host_identity()
        .expect("load canonical Host Identity");
    let session = super::super::model::initial_session(
        session_id.clone(),
        turn_id,
        host_identity,
        &readiness,
        started_at,
    )
    .expect("build the initial Session");
    let identity = RequestIdentity::new("starting-stop-race", STABLE_DIGEST);
    let context = super::super::model::admission(
        crate::storage::IdempotentOperation::Run,
        started_at,
        &identity,
        &engine.process_identity,
    )
    .expect("build admission context");
    let crate::storage::AdmissionOutcome::Execute {
        session,
        recovery_subject,
    } = engine
        .lock_storage()
        .expect("lock runtime storage")
        .begin_session(&session, &context)
        .expect("admit the Starting Turn")
    else {
        panic!("new admission must execute");
    };
    let plan = super::super::worker::ExecutionPlan {
        host: LOCAL_DEMO_HOST.to_string(),
        prompt: "PRIVATE_STOP_BEFORE_RUNNING".to_string(),
        work: super::super::worker::TurnWork {
            session,
            subject: recovery_subject,
        },
    };

    runtime
        .stop(StopCommand::new(session_id))
        .expect("stop should terminalize the Starting Turn");
    let outcome = engine
        .execute(plan)
        .expect("the execution path should return the durable stop winner");

    assert_eq!(outcome.session.status, satelle_core::TurnStatus::Stopped);
    assert!(outcome.events.is_empty());
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);
}

#[derive(Clone)]
struct PreflightCountingAdapter {
    preflight_calls: Arc<AtomicUsize>,
    execute_calls: Arc<AtomicUsize>,
}

impl ComputerUseAdapter for PreflightCountingAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Default)]
struct BlockOnThirdExecutionAdapter {
    execute_calls: Arc<AtomicUsize>,
    blocked_started: Latch,
    blocked_release: Latch,
}

impl ComputerUseAdapter for BlockOnThirdExecutionAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        let call = self.execute_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == 3 {
            self.blocked_started.signal();
            self.blocked_release.wait();
        }
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Copy)]
struct RunningRecoveryAdapter;

impl ComputerUseAdapter for RunningRecoveryAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        _subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(RecoveryObservation::Running)
    }
}

#[derive(Clone)]
struct SubjectBlockingAdapter {
    session_sender: mpsc::SyncSender<satelle_core::SessionId>,
    session_receiver: Arc<Mutex<mpsc::Receiver<satelle_core::SessionId>>>,
    execute_release: Latch,
    execute_calls: Arc<AtomicUsize>,
}

impl Default for SubjectBlockingAdapter {
    fn default() -> Self {
        let (session_sender, session_receiver) = mpsc::sync_channel(1);
        Self {
            session_sender,
            session_receiver: Arc::new(Mutex::new(session_receiver)),
            execute_release: Latch::default(),
            execute_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ComputerUseAdapter for SubjectBlockingAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        self.session_sender
            .send(request.subject().session_id().clone())
            .map_err(|_| SatelleError::not_implemented("subject receiver disconnected"))?;
        self.execute_release.wait();
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        _subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Default)]
struct StillActiveStopAdapter {
    execute_started: Latch,
    execute_release: Latch,
    recovery_calls: Arc<AtomicUsize>,
}

struct CloneDistinguishingAdapter {
    instance: usize,
    preflight_instance: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct FailFirstStopAdapter {
    execute_started: Latch,
    execute_release: Latch,
    stop_calls: Arc<AtomicUsize>,
}

impl ComputerUseAdapter for FailFirstStopAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        self.execute_started.signal();
        self.execute_release.wait();
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        if self.stop_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(SatelleError::not_implemented(
                "deterministic stop observation interruption",
            ));
        }
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

impl Clone for CloneDistinguishingAdapter {
    fn clone(&self) -> Self {
        Self {
            instance: self.instance + 1,
            preflight_instance: Arc::clone(&self.preflight_instance),
        }
    }
}

impl ComputerUseAdapter for CloneDistinguishingAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        self.preflight_instance
            .store(self.instance, Ordering::SeqCst);
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        if self.preflight_instance.load(Ordering::SeqCst) != self.instance {
            return Err(SatelleError::not_implemented(
                "preflight and execution used different adapter instances",
            ));
        }
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

impl ComputerUseAdapter for StillActiveStopAdapter {
    fn preflight(&self, host: &str) -> Result<super::super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::super::ExecuteRequest<'_>,
    ) -> Result<super::super::ExecuteResult, SatelleError> {
        self.execute_started.signal();
        self.execute_release.wait();
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        _subject: super::super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        Ok(StopObservation::UpstreamStillActive)
    }

    fn observe_recovery(
        &self,
        _subject: super::super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        Ok(RecoveryObservation::Running)
    }
}
