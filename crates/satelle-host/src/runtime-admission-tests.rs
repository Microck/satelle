use super::control_plane::CountingAdapter;
use super::*;
use crate::{AdapterReadiness, AdapterSubject, ExecuteRequest, ExecuteResult};

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

    assert_eq!(first.session, replay.session);
    assert_eq!(
        first.session.session_state_revision(),
        replay.session.session_state_revision()
    );
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    drop(runtime);

    let connection = rusqlite::Connection::open(state.path().join("satelle.sqlite3"))
        .expect("open released authoritative store");
    for table in ["native_readiness_results", "provider_smoke_successes"] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(1, count, "stable replay must not duplicate {table}");
    }
}

#[test]
fn precommit_rejection_replays_a_concurrently_committed_matching_run() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = RacingAdmissionAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let identity = RequestIdentity::new("race-run", STABLE_DIGEST);
    let racing_runtime = runtime.clone();
    let racing_identity = identity.clone();
    let racing_request = std::thread::spawn(move || {
        racing_runtime.run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_MATCHING_RACE",
            racing_identity,
        ))
    });
    assert!(
        adapter.rejection_started.wait_for(WAIT_LIMIT),
        "the racing request must reach precommit admission"
    );

    let committed = runtime
        .run(RunCommand::attached_with_identity(
            LOCAL_DEMO_HOST,
            "PRIVATE_MATCHING_RACE",
            identity,
        ))
        .expect("the concurrent matching request should commit");
    adapter.rejection_release.signal();
    let replayed = racing_request
        .join()
        .expect("the racing request thread should finish")
        .expect("precommit rejection must replay the committed matching request");

    assert_eq!(replayed.session, committed.session);
    assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 1);
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
        .session_id()
        .clone();
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

    assert_eq!(first.session.turns(), replay.session.turns());
    assert_eq!(
        latest_turn(&first.session).turn_state_revision(),
        latest_turn(&replay.session).turn_state_revision()
    );
    assert_eq!(execute_calls.load(Ordering::SeqCst), 2);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 2);
}

#[derive(Clone, Default)]
struct RacingAdmissionAdapter {
    admission_calls: Arc<AtomicUsize>,
    execute_calls: Arc<AtomicUsize>,
    rejection_started: Latch,
    rejection_release: Latch,
}

impl super::ComputerUseAdapter for RacingAdmissionAdapter {
    fn admit_operation(&self, _operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        if self.admission_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.rejection_started.signal();
            self.rejection_release.wait();
            return Err(SatelleError::computer_use_not_ready());
        }
        Ok(())
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
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
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}
