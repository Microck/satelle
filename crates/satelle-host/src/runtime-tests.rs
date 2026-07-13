use self::control_plane::CountingAdapter;
use super::adapter::BlockedComputerUseAdapter;
use super::{
    ComputerUseAdapter, LogQuery, RecoveryObservation, RequestIdentity, RunCommand, RuntimeHandle,
    RuntimeStartupState, SteerCommand, StopCommand,
};
use crate::storage::PrivateUpstreamRef;
use crate::test_runtime::FakeComputerUseAdapter;
use satelle_core::session::{SafeSummary, StopObservation, TurnState, TurnTransition};
use satelle_core::{
    ControlPlaneFailureReason, ControlPlaneOperation, ErrorCode, EventType,
    IncompatibleControlPlaneDetails, LOCAL_DEMO_HOST, SatelleError,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

const WAIT_LIMIT: Duration = Duration::from_secs(2);
const STABLE_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PRIVATE_UPSTREAM_THREAD_REF: &str = "PRIVATE_UPSTREAM_THREAD_REFERENCE_CANARY";
const PRIVATE_UPSTREAM_TURN_REF: &str = "PRIVATE_UPSTREAM_TURN_REFERENCE_CANARY";

#[test]
fn adapter_types_are_erased_at_the_runtime_handle_boundary() {
    let fake = RuntimeHandle::new(
        Err(SatelleError::invalid_usage("unused fake state root")),
        FakeComputerUseAdapter,
    );
    let blocked = RuntimeHandle::new(
        Err(SatelleError::invalid_usage("unused blocked state root")),
        BlockedComputerUseAdapter::new(SatelleError::computer_use_not_ready()),
    );

    let handles: Vec<RuntimeHandle> = vec![fake, blocked];

    assert_eq!(handles.len(), 2);
}

#[test]
fn blocked_preflight_opens_authoritative_state_without_admitting_work() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(
        Ok(state.path().to_path_buf()),
        BlockedComputerUseAdapter::new(SatelleError::computer_use_not_ready()),
    );

    let error = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_PREFLIGHT_CANARY",
        ))
        .expect_err("blocked preflight must reject execution");

    assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
    assert!(state.path().join("satelle.sqlite3").exists());
    assert!(state.path().join("satelle.sqlite3.lock").exists());
    assert_eq!(
        runtime
            .snapshot()
            .expect("blocked readiness must leave authoritative state readable")
            .session_count(),
        0,
    );
}

#[test]
fn retrying_a_stable_run_identity_does_not_repeat_adapter_execution() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let execute_calls = Arc::new(AtomicUsize::new(0));
    let admission_calls = Arc::new(AtomicUsize::new(0));
    let adapter = CountingAdapter::new(Arc::clone(&execute_calls), Arc::clone(&admission_calls));
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter);
    let identity = RequestIdentity::new("stable-run-key", STABLE_DIGEST);

    let first = runtime
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_RETRY_CANARY",
            identity.clone(),
        ))
        .expect("first request should execute");
    let replay = runtime
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_RETRY_CANARY",
            identity,
        ))
        .expect("stable retry should return the durable result");

    assert_eq!(first.session.session_id, replay.session.session_id);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    drop(runtime);

    let connection = rusqlite::Connection::open(state.path().join("satelle.sqlite3"))
        .expect("open released authoritative store");
    for table in ["readiness_successes", "provider_smoke_successes"] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(1, count, "stable replay must not duplicate {table}");
    }
}

#[test]
fn retrying_a_stable_steer_identity_does_not_repeat_adapter_execution() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let execute_calls = Arc::new(AtomicUsize::new(0));
    let admission_calls = Arc::new(AtomicUsize::new(0));
    let adapter = CountingAdapter::new(Arc::clone(&execute_calls), Arc::clone(&admission_calls));
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter);
    let session_id = runtime
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "PRIVATE_INITIAL"))
        .expect("initial run should complete")
        .session
        .session_id;
    let identity = RequestIdentity::new("stable-steer-key", STABLE_DIGEST);

    let first = runtime
        .steer(SteerCommand::attached_with_identity(
            session_id.clone(),
            "PRIVATE_FOLLOW_UP",
            identity.clone(),
        ))
        .expect("first steer should execute");
    let replay = runtime
        .steer(SteerCommand::attached_with_identity(
            session_id,
            "PRIVATE_FOLLOW_UP",
            identity,
        ))
        .expect("stable steer retry should replay its durable result");

    assert_eq!(first.session.turns, replay.session.turns);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 2);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn reads_and_stop_remain_available_during_slow_execution_and_stop_observation() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = BlockingExecutionAndStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_BLOCKING_EXECUTION",
        ))
        .expect("detached work should be admitted")
        .session;
    assert!(
        adapter.execute_started.wait_for(WAIT_LIMIT),
        "the detached worker should invoke the adapter"
    );

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let read_runtime = runtime.clone();
    let read_session_id = session.session_id.clone();
    let execute_read = std::thread::spawn(move || {
        let read_result = read_runtime.status(read_session_id).and_then(|status| {
            let count = read_runtime.snapshot()?.session_count();
            Ok((status, count))
        });
        read_sender
            .send(read_result)
            .expect("read receiver should remain connected");
    });
    let (running_status, count) = match read_receiver.recv_timeout(WAIT_LIMIT) {
        Ok(result) => result.expect("reads should succeed during adapter execution"),
        Err(error) => {
            adapter.release_all();
            panic!("reads were serialized behind adapter execution: {error}");
        }
    };
    execute_read.join().expect("read worker should finish");
    assert_eq!(running_status.status, satelle_core::TurnStatus::Started);
    assert_eq!(count, 1);

    let (stop_sender, stop_receiver) = mpsc::sync_channel(1);
    let stop_runtime = runtime.clone();
    let stop_session_id = session.session_id.clone();
    let stop_worker = std::thread::spawn(move || {
        let stop = stop_runtime.stop(StopCommand::with_identity(
            stop_session_id,
            RequestIdentity::new("blocking-stop", STABLE_DIGEST),
        ));
        stop_sender
            .send(stop)
            .expect("stop receiver should remain connected");
    });
    if !adapter.stop_started.wait_for(WAIT_LIMIT) {
        adapter.release_all();
        panic!("stop could not reach observation while execution was blocked");
    }

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let read_runtime = runtime.clone();
    let read_session_id = session.session_id.clone();
    let stop_read = std::thread::spawn(move || {
        let read_result = read_runtime.status(read_session_id).and_then(|status| {
            let logs = read_runtime.logs(LogQuery::for_host(LOCAL_DEMO_HOST))?;
            Ok((status, logs))
        });
        read_sender
            .send(read_result)
            .expect("read receiver should remain connected");
    });
    let (_status, logs) = match read_receiver.recv_timeout(WAIT_LIMIT) {
        Ok(result) => result.expect("reads should succeed during stop observation"),
        Err(error) => {
            adapter.release_all();
            panic!("reads were serialized behind stop observation: {error}");
        }
    };
    stop_read.join().expect("read worker should finish");
    assert!(!logs.is_empty());

    adapter.stop_release.signal();
    let stopped = stop_receiver
        .recv_timeout(WAIT_LIMIT)
        .expect("stop should finish after observation is released")
        .expect("confirmed stop should succeed");
    stop_worker.join().expect("stop worker should finish");
    assert_eq!(stopped.current_state(), TurnState::Stopped);

    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the losing execution worker should finish");
    let final_status = runtime
        .status(session.session_id)
        .expect("the terminal stop compare-and-swap should win");
    assert_eq!(final_status.status, satelle_core::TurnStatus::Stopped);
}

#[test]
fn adapter_persists_upstream_refs_before_waiting_and_stop_keeps_them_durable() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ReferencePersistingAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_REFERENCE_PERSISTENCE_PROMPT",
        ))
        .expect("detached work should be admitted")
        .session;
    let turn_id = session
        .latest_turn()
        .expect("admitted Session must contain its starting Turn")
        .turn_id
        .clone();
    if !adapter.references_recorded.wait_for(WAIT_LIMIT) {
        adapter.execute_release.signal();
        panic!("the adapter did not durably record its upstream references");
    }

    let engine = runtime.engine().expect("runtime engine should be open");
    let expected_thread_ref = PrivateUpstreamRef::new(PRIVATE_UPSTREAM_THREAD_REF)
        .expect("the thread canary must be a valid private reference");
    let expected_turn_ref = PrivateUpstreamRef::new(PRIVATE_UPSTREAM_TURN_REF)
        .expect("the Turn canary must be a valid private reference");
    let durable_subject = engine
        .lock_storage()
        .expect("lock runtime storage")
        .recovery_subject(&session.session_id, &turn_id)
        .expect("reload durable adapter subject");
    assert_eq!(
        durable_subject.upstream_thread_ref(),
        Some(&expected_thread_ref)
    );
    assert_eq!(
        durable_subject.upstream_turn_ref(),
        Some(&expected_turn_ref)
    );
    let public_session = runtime
        .status_public(&session.session_id)
        .expect("read public Session while execution is waiting");
    let logs = runtime
        .logs(LogQuery::for_host(LOCAL_DEMO_HOST))
        .expect("read safe logs while execution is waiting");
    let public_json = serde_json::to_string(&(public_session, logs))
        .expect("serialize public state and safe logs");
    assert!(!public_json.contains(PRIVATE_UPSTREAM_THREAD_REF));
    assert!(!public_json.contains(PRIVATE_UPSTREAM_TURN_REF));

    let stopped = runtime
        .stop(StopCommand::new(session.session_id.clone()))
        .expect("stop observation should consume the durable references");
    assert_eq!(stopped.current_state(), TurnState::Stopped);
    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the losing execution worker should finish");

    let final_status = runtime
        .status(session.session_id.clone())
        .expect("the confirmed stop should remain terminal");
    assert_eq!(final_status.status, satelle_core::TurnStatus::Stopped);
    let final_subject = engine
        .lock_storage()
        .expect("lock runtime storage after stop")
        .recovery_subject(&session.session_id, &turn_id)
        .expect("reload durable adapter subject after stop");
    assert_eq!(
        final_subject.upstream_thread_ref(),
        Some(&expected_thread_ref)
    );
    assert_eq!(final_subject.upstream_turn_ref(), Some(&expected_turn_ref));
}

#[test]
fn adapter_receives_committed_policy_and_resumes_the_private_thread_reference() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = BoundaryInspectingAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());

    let session_id = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_INITIAL_POLICY_PROMPT",
        ))
        .expect("initial Turn should execute through the adapter boundary")
        .session
        .session_id;
    runtime
        .steer(SteerCommand::attached(
            session_id,
            "PRIVATE_FOLLOW_UP_POLICY_PROMPT",
        ))
        .expect("follow-up Turn should reuse the persisted private thread reference");

    assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn yolo_turn_commits_never_and_danger_full_access_before_adapter_execution() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = BoundaryInspectingAdapter {
        expected_mode: satelle_core::session::TurnExecutionMode::Yolo,
        ..BoundaryInspectingAdapter::default()
    };
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());

    runtime
        .run(
            RunCommand::attached(LOCAL_DEMO_HOST, "PRIVATE_YOLO_POLICY_PROMPT")
                .with_execution_mode(satelle_core::session::TurnExecutionMode::Yolo),
        )
        .expect("YOLO Turn should execute through the committed policy boundary");

    assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn read_paths_open_storage_without_computer_use_preflight() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let state_root = state.path().to_path_buf();
    let seeded = RuntimeHandle::new(Ok(state_root.clone()), FakeComputerUseAdapter);
    let session = seeded
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "PRIVATE_SEED"))
        .expect("seed run should complete")
        .session;
    drop(seeded);

    let blocked = RuntimeHandle::new(
        Ok(state_root),
        BlockedComputerUseAdapter::new(SatelleError::computer_use_not_ready()),
    );
    let status = blocked
        .status(session.session_id)
        .expect("status should not require adapter readiness");
    let logs = blocked
        .logs(LogQuery::for_host(LOCAL_DEMO_HOST))
        .expect("logs should not require adapter readiness");
    let count = blocked
        .snapshot()
        .expect("runtime snapshot should not require adapter readiness")
        .session_count();

    assert_eq!(status.status, satelle_core::TurnStatus::Completed);
    assert!(!logs.is_empty());
    assert_eq!(count, 1);
}

#[test]
fn detached_adapter_error_enters_recovery_without_a_restart() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FailFirstAdapter::default());
    let session = runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_UNKNOWN_EXECUTION",
        ))
        .expect("detached work should be durably admitted")
        .session;
    runtime
        .wait_for_background()
        .expect("the failed detached worker should be reaped");

    assert_eq!(
        runtime
            .startup_state()
            .expect("unknown execution should be queued for reconciliation"),
        RuntimeStartupState::RecoveryRequired
    );
    let status = runtime
        .status(session.session_id.clone())
        .expect("the recovering Session should remain readable");
    assert_eq!(status.status, satelle_core::TurnStatus::Started);

    runtime
        .stop(StopCommand::new(session.session_id))
        .expect("confirmed stop should resolve the queued recovery subject");
    assert_eq!(
        runtime
            .startup_state()
            .expect("confirmed stop should clear recovery"),
        RuntimeStartupState::Ready
    );
}

#[test]
fn restart_recovery_commits_adapter_proven_blocked_and_failed_outcomes() {
    for (observation, expected_status) in [
        (
            RecoveryObservation::Blocked,
            satelle_core::TurnStatus::Blocked,
        ),
        (
            RecoveryObservation::Failed,
            satelle_core::TurnStatus::Failed,
        ),
    ] {
        let state = crate::TestStateDir::new().expect("temporary state directory should exist");
        let state_root = state.path().to_path_buf();
        let interrupted = RuntimeHandle::new(Ok(state_root.clone()), FailFirstAdapter::default());
        let old_session = interrupted
            .run(RunCommand::detached(
                LOCAL_DEMO_HOST,
                "PRIVATE_TERMINAL_RECOVERY",
            ))
            .expect("interrupted work should be admitted")
            .session;
        interrupted
            .wait_for_background()
            .expect("the interrupted worker should finish");
        drop(interrupted);

        let restarted = RuntimeHandle::new(Ok(state_root), TerminalRecoveryAdapter { observation });
        restarted
            .run(RunCommand::attached(
                LOCAL_DEMO_HOST,
                "PRIVATE_AFTER_TERMINAL_RECOVERY",
            ))
            .expect("terminal recovery should release admission");
        let recovered_session_id = old_session.session_id;
        let recovered = restarted
            .status(recovered_session_id.clone())
            .expect("the recovered Session should remain readable");
        assert_eq!(recovered.status, expected_status);
        if observation == RecoveryObservation::Failed {
            let public = restarted
                .status_public(&recovered_session_id)
                .expect("read recovered public Session");
            assert_eq!(
                public.turns().last().unwrap().safe_summary(),
                Some(&SafeSummary::DaemonRestartRecoveryFailed)
            );
        }
    }
}

#[test]
fn new_admission_reconciles_restart_work_without_blocking_reads() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let state_root = state.path().to_path_buf();
    let interrupted = RuntimeHandle::new(Ok(state_root.clone()), FailFirstAdapter::default());
    let old_session = interrupted
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_RECOVERY_SUBJECT",
        ))
        .expect("interrupted work should be admitted")
        .session;
    interrupted
        .wait_for_background()
        .expect("the interrupted worker should finish");
    let before_recovery = interrupted
        .status(old_session.session_id.clone())
        .expect("interrupted status should be readable");
    drop(interrupted);

    let adapter = BlockingRecoveryAdapter::default();
    let restarted = RuntimeHandle::new(Ok(state_root), adapter.clone());
    let run_runtime = restarted.clone();
    let (run_sender, run_receiver) = mpsc::sync_channel(1);
    let run_worker = std::thread::spawn(move || {
        let outcome = run_runtime.run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_AFTER_RECOVERY",
        ));
        run_sender
            .send(outcome)
            .expect("run receiver should remain connected");
    });
    if !adapter.recovery_started.wait_for(WAIT_LIMIT) {
        adapter.recovery_release.signal();
        panic!("new admission did not attempt restart reconciliation");
    }

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let read_runtime = restarted.clone();
    let read_session_id = old_session.session_id.clone();
    let read_worker = std::thread::spawn(move || {
        let result = read_runtime.status(read_session_id).and_then(|status| {
            let logs = read_runtime.logs(LogQuery::for_host(LOCAL_DEMO_HOST))?;
            Ok((status, logs.len()))
        });
        read_sender
            .send(result)
            .expect("read receiver should remain connected");
    });
    let (recovering_status, log_count) = match read_receiver.recv_timeout(WAIT_LIMIT) {
        Ok(result) => result.expect("reads should succeed during recovery observation"),
        Err(error) => {
            adapter.recovery_release.signal();
            panic!("reads were serialized behind recovery observation: {error}");
        }
    };
    read_worker.join().expect("read worker should finish");
    assert_eq!(recovering_status.status, satelle_core::TurnStatus::Started);
    assert!(log_count > 0);

    adapter.recovery_release.signal();
    let new_outcome = run_receiver
        .recv_timeout(WAIT_LIMIT)
        .expect("admission should continue after recovery")
        .expect("recovery and new execution should succeed");
    run_worker.join().expect("run worker should finish");
    let recovered = restarted
        .status(old_session.session_id)
        .expect("recovered Session should remain readable");

    assert_eq!(recovered.status, satelle_core::TurnStatus::Completed);
    assert!(recovered.updated_at >= before_recovery.updated_at);
    assert_eq!(
        new_outcome.session.status,
        satelle_core::TurnStatus::Completed
    );
    assert_eq!(adapter.recovery_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        restarted
            .startup_state()
            .expect("successful reconciliation should clear startup recovery"),
        RuntimeStartupState::Ready
    );
}

#[test]
fn unknown_restart_work_blocks_new_admission_until_stop_resolves_it() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let state_root = state.path().to_path_buf();
    let interrupted = RuntimeHandle::new(Ok(state_root.clone()), FailFirstAdapter::default());
    let session = interrupted
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_UNKNOWN_RECOVERY",
        ))
        .expect("interrupted work should be admitted")
        .session;
    interrupted
        .wait_for_background()
        .expect("the interrupted worker should finish");
    drop(interrupted);

    let restarted = RuntimeHandle::new(Ok(state_root), FakeComputerUseAdapter);
    let error = restarted
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_MUST_NOT_ADMIT",
        ))
        .expect_err("unknown recovery must block new admission");
    assert_eq!(error.code, ErrorCode::HostBusy);
    assert_eq!(error.details["reason"], "outcome_unknown");
    assert_eq!(
        error.recovery_command,
        Some(format!("satelle status {} --json", session.session_id))
    );
    assert_eq!(
        restarted
            .startup_state()
            .expect("unknown work should remain in recovery"),
        RuntimeStartupState::RecoveryRequired
    );

    let stopped = restarted
        .stop(StopCommand::new(session.session_id.clone()))
        .expect("explicit stop should resolve unknown restart work");
    assert_eq!(stopped.previous_state(), TurnState::RecoveryPending);
    assert_eq!(stopped.current_state(), TurnState::Stopped);
    assert_eq!(
        restarted
            .startup_state()
            .expect("resolved startup should be ready"),
        RuntimeStartupState::Ready
    );
}

#[derive(Clone, Default)]
struct FailFirstAdapter {
    execute_calls: Arc<AtomicUsize>,
    stop_calls: Arc<AtomicUsize>,
    stop_admission_calls: Arc<AtomicUsize>,
    reject_replayed_stop: bool,
    follow_up_started: Latch,
    follow_up_release: Latch,
}

impl FailFirstAdapter {
    fn replay_sensitive() -> Self {
        Self {
            reject_replayed_stop: true,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy)]
struct TerminalRecoveryAdapter {
    observation: RecoveryObservation,
}

impl super::ComputerUseAdapter for TerminalRecoveryAdapter {
    fn preflight(&self, host: &str) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        _subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(self.observation)
    }
}

impl super::ComputerUseAdapter for FailFirstAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        if operation != ControlPlaneOperation::Stop {
            return FakeComputerUseAdapter.admit_operation(operation);
        }
        let call = self.stop_admission_calls.fetch_add(1, Ordering::SeqCst);
        if !self.reject_replayed_stop || call == 0 {
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

    fn preflight(&self, host: &str) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        let call = self.execute_calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Err(SatelleError::not_implemented(
                "deterministic adapter interruption",
            ));
        }
        if self.reject_replayed_stop && call == 1 {
            self.follow_up_started.signal();
            self.follow_up_release.wait();
        }
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Default)]
struct BlockingExecutionAndStopAdapter {
    execute_started: Latch,
    execute_release: Latch,
    stop_started: Latch,
    stop_release: Latch,
}

#[derive(Clone, Default)]
struct ReferencePersistingAdapter {
    references_recorded: Latch,
    execute_release: Latch,
}

#[derive(Clone, Default)]
struct BoundaryInspectingAdapter {
    execute_calls: Arc<AtomicUsize>,
    expected_policy: Arc<Mutex<Option<satelle_core::session::ExecutionPolicy>>>,
    expected_mode: satelle_core::session::TurnExecutionMode,
}

impl super::ComputerUseAdapter for BoundaryInspectingAdapter {
    fn preflight(&self, host: &str) -> Result<super::AdapterReadiness, SatelleError> {
        let readiness = FakeComputerUseAdapter.preflight(host)?;
        *self
            .expected_policy
            .lock()
            .expect("the policy expectation lock should not be poisoned") = Some(
            readiness
                .execution_policy()
                .for_turn_mode(self.expected_mode),
        );
        Ok(readiness)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        let call = self.execute_calls.fetch_add(1, Ordering::SeqCst);
        let expected_policy = self
            .expected_policy
            .lock()
            .expect("the policy expectation lock should not be poisoned");
        assert_eq!(
            request.execution_policy(),
            expected_policy.as_ref().unwrap()
        );
        assert_eq!(request.execution_mode(), self.expected_mode);
        match call {
            0 => {
                assert_eq!(request.upstream_thread_ref(), None);
                request.persist_upstream_thread_ref(PRIVATE_UPSTREAM_THREAD_REF)?;
                request.persist_upstream_turn_ref("PRIVATE_INITIAL_TURN_REFERENCE")?;
            }
            1 => {
                assert_eq!(
                    request.upstream_thread_ref(),
                    Some(PRIVATE_UPSTREAM_THREAD_REF)
                );
                request.persist_upstream_turn_ref("PRIVATE_FOLLOW_UP_TURN_REFERENCE")?;
            }
            _ => panic!("the boundary test scheduled an unexpected extra execution"),
        }
        Ok(super::ExecuteResult::new(
            TurnTransition::Completed,
            Vec::new(),
        ))
    }

    fn observe_stop(
        &self,
        _subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        _subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(RecoveryObservation::Unknown)
    }
}

impl super::ComputerUseAdapter for ReferencePersistingAdapter {
    fn preflight(&self, host: &str) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        request.persist_upstream_thread_ref(PRIVATE_UPSTREAM_THREAD_REF)?;
        request.persist_upstream_turn_ref(PRIVATE_UPSTREAM_TURN_REF)?;
        self.references_recorded.signal();
        self.execute_release.wait();
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        if !subject.has_upstream_references() {
            return Err(SatelleError::computer_use_not_ready());
        }
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

impl BlockingExecutionAndStopAdapter {
    fn release_all(&self) {
        self.execute_release.signal();
        self.stop_release.signal();
    }
}

impl super::ComputerUseAdapter for BlockingExecutionAndStopAdapter {
    fn preflight(&self, host: &str) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        self.execute_started.signal();
        self.execute_release.wait();
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        _subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        self.stop_started.signal();
        self.stop_release.wait();
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Default)]
struct BlockingRecoveryAdapter {
    recovery_started: Latch,
    recovery_release: Latch,
    recovery_calls: Arc<AtomicUsize>,
}

impl super::ComputerUseAdapter for BlockingRecoveryAdapter {
    fn preflight(&self, host: &str) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        _subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        self.recovery_started.signal();
        self.recovery_release.wait();
        Ok(RecoveryObservation::Completed)
    }
}

#[derive(Clone, Default)]
struct Latch {
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl Latch {
    fn signal(&self) {
        let (lock, changed) = &*self.state;
        let mut signaled = lock.lock().expect("test latch lock should not be poisoned");
        *signaled = true;
        changed.notify_all();
    }

    fn wait(&self) {
        let (lock, changed) = &*self.state;
        let signaled = lock.lock().expect("test latch lock should not be poisoned");
        let _signaled = changed
            .wait_while(signaled, |signaled| !*signaled)
            .expect("test latch lock should not be poisoned");
    }

    fn wait_for(&self, timeout: Duration) -> bool {
        let (lock, changed) = &*self.state;
        let signaled = lock.lock().expect("test latch lock should not be poisoned");
        let (signaled, _wait) = changed
            .wait_timeout_while(signaled, timeout, |signaled| !*signaled)
            .expect("test latch lock should not be poisoned");
        *signaled
    }
}

#[path = "runtime-tests/control-plane.rs"]
mod control_plane;

#[path = "runtime-tests/review-regressions.rs"]
mod review_regressions;
