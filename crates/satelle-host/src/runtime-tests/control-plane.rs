use super::*;
use crate::{AdapterReadiness, AdapterSubject, ExecuteRequest, ExecuteResult};

#[test]
fn control_plane_admission_blocks_run_and_steer_before_preflight_or_state_mutation() {
    let run_state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let run_adapter = RejectingAdmissionAdapter::new(ControlPlaneOperation::Run);
    let run_runtime = RuntimeHandle::new(Ok(run_state.path().to_path_buf()), run_adapter.clone());

    let error = run_runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_REJECTED_RUN",
        ))
        .expect_err("run must fail before adapter preflight");
    assert_eq!(error.error().code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(run_adapter.preflight_calls.load(Ordering::SeqCst), 0);
    assert_eq!(run_adapter.execute_calls.load(Ordering::SeqCst), 0);
    assert_eq!(run_runtime.snapshot().unwrap().session_count(), 0);

    let steer_state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let steer_adapter = RejectingAdmissionAdapter::new(ControlPlaneOperation::Steer);
    let steer_runtime =
        RuntimeHandle::new(Ok(steer_state.path().to_path_buf()), steer_adapter.clone());
    let session_id = steer_runtime
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "PRIVATE_INITIAL_RUN"))
        .expect("unrelated run admission should remain available")
        .session
        .session_id()
        .clone();

    let error = steer_runtime
        .steer(SteerCommand::attached(
            session_id.clone(),
            "PRIVATE_REJECTED_STEER",
        ))
        .expect_err("steer must fail before adapter preflight");
    assert_eq!(error.error().code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(steer_adapter.preflight_calls.load(Ordering::SeqCst), 1);
    assert_eq!(steer_adapter.execute_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        steer_runtime.status(session_id).unwrap().turns().len(),
        1,
        "rejected steer must not append a Turn"
    );
}

#[test]
fn rejected_run_does_not_reconcile_or_mutate_pending_recovery() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let interrupted =
        RuntimeHandle::new(Ok(state.path().to_path_buf()), FailFirstAdapter::default());
    let session_id = interrupted
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_PENDING_RECOVERY_BEFORE_REJECTION",
        ))
        .expect("detached work should be durably admitted")
        .session
        .session_id()
        .clone();
    interrupted
        .wait_for_background()
        .expect("the interrupted worker should finish");
    let database_path = state.path().join("satelle.sqlite3");
    let durable_state = || {
        let connection = rusqlite::Connection::open(&database_path)
            .expect("open the authoritative store for read-only assertions");
        connection
            .query_row(
                "SELECT sessions.session_state_revision, turns.turn_state_revision, turns.state, \
                        control_leases.lease_state, idempotency_records.status, \
                        idempotency_records.durable_outcome, \
                        (SELECT count(*) FROM logs WHERE event_kind = 'restart_recovery_pending') \
                 FROM sessions JOIN turns USING (session_id) \
                 JOIN control_leases USING (session_id, turn_id) \
                 JOIN idempotency_records USING (session_id, turn_id) \
                 WHERE sessions.session_id = ?1 AND idempotency_records.operation = 'run'",
                [session_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .unwrap()
    };
    let before = durable_state();
    drop(interrupted);

    let adapter = RejectingAdmissionAdapter::new(ControlPlaneOperation::Run);
    let restarted = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let error = restarted
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_REJECTED_BEFORE_RECOVERY",
        ))
        .expect_err("run admission must fail before recovery observation");

    assert_eq!(error.error().code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(adapter.recovery_calls.load(Ordering::SeqCst), 0);
    assert_eq!(durable_state(), before);
}

#[test]
fn active_stop_admission_fails_before_any_stop_mutation_but_terminal_stop_stays_local() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = RejectingActiveStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_ACTIVE_STOP_ADMISSION",
        ))
        .expect("detached run should be durably admitted")
        .session
        .session_id()
        .clone();
    assert!(
        adapter.execute_started.wait_for(WAIT_LIMIT),
        "execution should remain active during the stop attempt"
    );
    let before = runtime.status(session_id.clone()).unwrap();
    let connection = rusqlite::Connection::open(state.path().join("satelle.sqlite3"))
        .expect("open authoritative store for read-only assertions");
    let count = |table: &str| -> i64 {
        connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    let idempotency_before = count("idempotency_records");
    let logs_before = count("logs");

    let error = runtime
        .stop(StopCommand::new(session_id.clone()))
        .expect_err("active stop must require cancellation capability");
    assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(adapter.stop_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.stop_observation_calls.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.status(session_id).unwrap(), before);
    assert_eq!(count("idempotency_records"), idempotency_before);
    assert_eq!(count("logs"), logs_before);

    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("blocked execution should finish after release");

    let terminal_state =
        crate::TestStateDir::new().expect("temporary state directory should exist");
    let terminal_adapter = RejectingAdmissionAdapter::new(ControlPlaneOperation::Stop);
    let terminal_runtime =
        RuntimeHandle::new(Ok(terminal_state.path().to_path_buf()), terminal_adapter);
    let terminal_session = terminal_runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_TERMINAL_STOP",
        ))
        .expect("run should reach a terminal state")
        .session
        .session_id()
        .clone();
    let stopped = terminal_runtime
        .stop(StopCommand::new(terminal_session))
        .expect("already-terminal stop must not contact Codex");
    assert_eq!(stopped.outcome().as_str(), "already_terminal");
}

#[test]
fn completed_stop_replay_stays_local_while_a_later_turn_is_active() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = FailFirstAdapter::replay_sensitive();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session = runtime
        .run(RunCommand::detached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_INTERRUPTED",
            RequestIdentity::new("stable-interrupted-run", STABLE_DIGEST),
        ))
        .expect("detached work should be durably admitted")
        .session;
    runtime
        .wait_for_background()
        .expect("the deterministic failed worker should finish");

    let stop_identity = RequestIdentity::new("stable-stop-key", STABLE_DIGEST);
    let first_stop = runtime
        .stop(StopCommand::with_identity(
            session.session_id().clone(),
            stop_identity.clone(),
        ))
        .expect("the interrupted first Turn should stop");
    let original_turn_id = first_stop.turn_id().clone();
    runtime
        .steer(SteerCommand::detached(
            session.session_id().clone(),
            "PRIVATE_LATER_FOLLOW_UP",
        ))
        .expect("a later follow-up should be admitted");
    assert!(
        adapter.follow_up_started.wait_for(WAIT_LIMIT),
        "the later follow-up should remain active during replay"
    );

    let replay = runtime
        .stop(StopCommand::with_identity(
            session.session_id().clone(),
            stop_identity,
        ))
        .expect("the completed stop retry should remain local");

    assert_eq!(replay.turn_id(), &original_turn_id);
    assert_eq!(replay.previous_state(), first_stop.previous_state());
    assert_eq!(replay.current_state(), first_stop.current_state());
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.stop_admission_calls.load(Ordering::SeqCst), 1);
    adapter.follow_up_release.signal();
    runtime
        .wait_for_background()
        .expect("the later follow-up should finish after release");
}

#[test]
fn pending_stop_replay_rechecks_admission_before_observing_upstream_state() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = PendingStopAdmissionAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_PENDING_STOP_REPLAY",
        ))
        .expect("detached work should be admitted")
        .session
        .session_id()
        .clone();
    runtime
        .wait_for_background()
        .expect("the interrupted worker should finish");
    let identity = RequestIdentity::new("pending-stop-key", STABLE_DIGEST);

    let first = runtime
        .stop(StopCommand::with_identity(
            session_id.clone(),
            identity.clone(),
        ))
        .expect_err("the first observation should leave a pending stop");
    assert_eq!(first.code, ErrorCode::NotImplemented);
    assert_eq!(adapter.stop_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.stop_observation_calls.load(Ordering::SeqCst), 1);

    let replay = runtime
        .stop(StopCommand::with_identity(session_id, identity))
        .expect_err("pending stop replay must recheck control-plane admission");
    assert_eq!(replay.code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(adapter.stop_admission_calls.load(Ordering::SeqCst), 2);
    assert_eq!(adapter.stop_observation_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_stop_replay_finishes_locally_after_its_turn_terminalizes() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = PendingStopAdmissionAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session_id = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_PENDING_THEN_TERMINAL_STOP",
        ))
        .expect("detached work should be admitted")
        .session
        .session_id()
        .clone();
    runtime
        .wait_for_background()
        .expect("the interrupted worker should finish");
    let original_turn_id = runtime.status(session_id.clone()).unwrap().turns()[0]
        .turn_id()
        .clone();
    let identity = RequestIdentity::new("pending-terminal-stop-key", STABLE_DIGEST);

    let first = runtime
        .stop(StopCommand::with_identity(
            session_id.clone(),
            identity.clone(),
        ))
        .expect_err("the first observation should leave a pending stop");
    assert_eq!(first.code, ErrorCode::NotImplemented);

    runtime
        .steer(SteerCommand::detached(
            session_id.clone(),
            "PRIVATE_ACTIVE_FOLLOW_UP_AFTER_RECOVERY",
        ))
        .expect("recovery should terminalize the original Turn and admit a follow-up");
    assert!(
        adapter.follow_up_started.wait_for(WAIT_LIMIT),
        "the later follow-up should remain active during stop replay"
    );

    let replay = runtime
        .stop(StopCommand::with_identity(session_id, identity))
        .expect("the terminal original Turn should complete its pending stop locally");

    assert_eq!(replay.turn_id(), &original_turn_id);
    assert_eq!(replay.outcome().as_str(), "already_terminal");
    assert_eq!(adapter.stop_admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(adapter.stop_observation_calls.load(Ordering::SeqCst), 1);
    adapter.follow_up_release.signal();
    runtime
        .wait_for_background()
        .expect("the later follow-up should finish after release");
}

#[derive(Clone)]
pub(super) struct CountingAdapter {
    inner: FakeComputerUseAdapter,
    execute_calls: Arc<AtomicUsize>,
    admission_calls: Arc<AtomicUsize>,
}

impl CountingAdapter {
    pub(super) fn new(execute_calls: Arc<AtomicUsize>, admission_calls: Arc<AtomicUsize>) -> Self {
        Self {
            inner: FakeComputerUseAdapter,
            execute_calls,
            admission_calls,
        }
    }
}

impl ComputerUseAdapter for CountingAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        self.admission_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.admit_operation(operation)
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.inner.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        self.inner.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        self.inner.observe_recovery(subject)
    }
}

#[derive(Clone)]
struct RejectingAdmissionAdapter {
    rejected: ControlPlaneOperation,
    preflight_calls: Arc<AtomicUsize>,
    execute_calls: Arc<AtomicUsize>,
    recovery_calls: Arc<AtomicUsize>,
}

impl RejectingAdmissionAdapter {
    fn new(rejected: ControlPlaneOperation) -> Self {
        Self {
            rejected,
            preflight_calls: Arc::new(AtomicUsize::new(0)),
            execute_calls: Arc::new(AtomicUsize::new(0)),
            recovery_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ComputerUseAdapter for RejectingAdmissionAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        if operation != self.rejected {
            return Ok(());
        }
        let details = IncompatibleControlPlaneDetails::new(
            operation,
            ControlPlaneFailureReason::HandshakeUnavailable,
            &[],
        )
        .expect("closed test admission details must be valid");
        Err(SatelleError::incompatible_control_plane(details))
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        Ok(RecoveryObservation::Completed)
    }
}

#[derive(Clone, Default)]
struct RejectingActiveStopAdapter {
    execute_started: Latch,
    execute_release: Latch,
    stop_admission_calls: Arc<AtomicUsize>,
    stop_observation_calls: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct PendingStopAdmissionAdapter {
    execute_calls: Arc<AtomicUsize>,
    stop_admission_calls: Arc<AtomicUsize>,
    stop_observation_calls: Arc<AtomicUsize>,
    follow_up_started: Latch,
    follow_up_release: Latch,
}

impl ComputerUseAdapter for PendingStopAdmissionAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        if operation != ControlPlaneOperation::Stop {
            return Ok(());
        }
        let call = self.stop_admission_calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Ok(());
        }
        let details = IncompatibleControlPlaneDetails::new(
            operation,
            ControlPlaneFailureReason::HandshakeUnavailable,
            &[],
        )
        .expect("closed test admission details must be valid");
        Err(SatelleError::incompatible_control_plane(details))
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        let call = self.execute_calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Err(SatelleError::not_implemented(
                "deterministic adapter interruption",
            ));
        }
        self.follow_up_started.signal();
        self.follow_up_release.wait();
        FakeComputerUseAdapter.execute(_request)
    }

    fn observe_stop(&self, _subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        self.stop_observation_calls.fetch_add(1, Ordering::SeqCst);
        Err(SatelleError::not_implemented(
            "deterministic stop observation interruption",
        ))
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(RecoveryObservation::Completed)
    }
}

impl ComputerUseAdapter for RejectingActiveStopAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        if operation != ControlPlaneOperation::Stop {
            return Ok(());
        }
        self.stop_admission_calls.fetch_add(1, Ordering::SeqCst);
        let details = IncompatibleControlPlaneDetails::new(
            operation,
            ControlPlaneFailureReason::RequiredCapabilityMissing,
            &[satelle_core::ControlPlaneCapability::Cancellation],
        )
        .expect("closed test admission details must be valid");
        Err(SatelleError::incompatible_control_plane(details))
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.execute_started.signal();
        self.execute_release.wait();
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        self.stop_observation_calls.fetch_add(1, Ordering::SeqCst);
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}
