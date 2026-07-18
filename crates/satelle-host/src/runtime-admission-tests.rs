use super::control_plane::CountingAdapter;
use super::*;
use crate::runtime::adapter::{NativeProbeResult, ReadinessProbeDriver};
use crate::{AdapterReadiness, AdapterSubject, ExecuteRequest, ExecuteResult};

#[test]
fn detached_execution_inherits_the_scheduling_dispatch() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let marker_seen = Arc::new(AtomicBool::new(false));
    let dispatch = tracing::Dispatch::new(DetachedExecutionMarkerSubscriber {
        marker_seen: Arc::clone(&marker_seen),
    });
    let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter);

    runtime
        .run(RunCommand::detached(
            LOCAL_DEMO_HOST,
            "PRIVATE_DETACHED_DISPATCH_CANARY",
        ))
        .expect("detached work should be admitted");
    runtime
        .wait_for_background()
        .expect("detached worker should finish before the marker assertion");

    assert!(
        marker_seen.load(Ordering::Acquire),
        "the real local adapter marker must use the scheduling thread's effective Dispatch"
    );
}

struct DetachedExecutionMarkerSubscriber {
    marker_seen: Arc<AtomicBool>,
}

impl tracing::Subscriber for DetachedExecutionMarkerSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut DetachedExecutionMarkerVisitor {
            marker_seen: &self.marker_seen,
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

struct DetachedExecutionMarkerVisitor<'a> {
    marker_seen: &'a AtomicBool,
}

impl tracing::field::Visit for DetachedExecutionMarkerVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "marker" && value == crate::test_runtime::DETACHED_EXECUTION_TRACE_MARKER
        {
            self.marker_seen.store(true, Ordering::Release);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

#[test]
fn host_service_maintenance_authority_blocks_turns_and_finalizes_atomically() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let service = crate::HostService::local_demo_for_tests_at(state.path()).unwrap();
    let operation_id = "runtime-maintenance-finalization";
    let plan = crate::storage::SetupRunPlan::new(
        operation_id,
        crate::storage::SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::UNIX_EPOCH,
        vec![
            crate::storage::SetupActionPlan::new("repair-runtime", "Repair runtime", false)
                .unwrap(),
        ],
    )
    .unwrap();
    let mut operation = service.begin_setup_run(&plan).unwrap();

    let error = service
        .runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_MAINTENANCE_CONFLICT",
        ))
        .expect_err("maintenance ownership must block prompt Turn admission");
    assert_eq!(
        satelle_core::session::TurnAdmissionPhase::NotAdmitted,
        error.phase()
    );
    service
        .start_setup_action(
            &operation,
            "repair-runtime",
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .unwrap();
    service
        .complete_setup_action_after_verified_postcondition(
            &operation,
            "repair-runtime",
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(2),
        )
        .unwrap();

    assert_eq!(
        crate::storage::SetupRunStatus::Completed,
        service
            .finish_setup_run(
                &mut operation,
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(3),
            )
            .expect("runtime finalization must commit ledger state and lease release")
    );
    service
        .start_setup_action(
            &operation,
            "repair-runtime",
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(4),
        )
        .expect_err("a consumed operation handle cannot authorize another mutation");
    service
        .runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_AFTER_MAINTENANCE",
        ))
        .expect("atomic finalization must release maintenance ownership");
}

#[test]
fn host_service_rejects_an_operation_handle_from_another_exact_owner() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let other_state = crate::TestStateDir::new().expect("second state directory should exist");
    let service = crate::HostService::local_demo_for_tests_at(state.path()).unwrap();
    let other_service = crate::HostService::local_demo_for_tests_at(other_state.path()).unwrap();
    let plan = crate::storage::SetupRunPlan::new(
        "runtime-owned-maintenance",
        crate::storage::SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::UNIX_EPOCH,
        vec![
            crate::storage::SetupActionPlan::new("repair-runtime", "Repair runtime", false)
                .unwrap(),
        ],
    )
    .unwrap();
    let other_plan = crate::storage::SetupRunPlan::new(
        "other-runtime-maintenance",
        crate::storage::SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::UNIX_EPOCH,
        vec![
            crate::storage::SetupActionPlan::new("repair-runtime", "Repair runtime", false)
                .unwrap(),
        ],
    )
    .unwrap();
    let operation = service.begin_setup_run(&plan).unwrap();
    let other_operation = other_service.begin_setup_run(&other_plan).unwrap();

    service
        .start_setup_action(
            &other_operation,
            "repair-runtime",
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .expect_err("an opaque handle from another exact owner has no authority");

    drop(other_operation);
    drop(operation);
}

#[test]
fn host_service_postcheck_finalizes_pass_failure_and_unknown_through_live_authority() {
    assert_host_postcheck_outcome("passed", MaintenanceProbeFixture::Passed);
    assert_host_postcheck_outcome(
        "failed",
        MaintenanceProbeFixture::Failed("runtime postcheck failed"),
    );
    assert_host_postcheck_outcome("unknown", MaintenanceProbeFixture::Unknown);
}

fn assert_host_postcheck_outcome(suffix: &str, fixture: MaintenanceProbeFixture) {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let service =
        crate::HostService::local_demo_with_readiness_driver_for_tests_at(state.path(), fixture)
            .unwrap();
    let operation_id = format!("runtime-postcheck-{suffix}");
    let desktop_binding =
        satelle_core::session::DesktopBindingRef::new(format!("desktop-postcheck-{suffix}"))
            .unwrap();
    let policy = satelle_core::session::ExecutionPolicy::new(
        satelle_core::session::EffectiveModelRef::new("computer-use-preview").unwrap(),
        satelle_core::session::ProviderBindingRef::new("openai").unwrap(),
        satelle_core::session::DesktopTarget::new(desktop_binding.clone()),
        satelle_core::session::ApprovalPolicy::OnRequest,
        satelle_core::session::SandboxPolicy::WorkspaceWrite,
        satelle_core::session::TimeoutPolicy::bounded_seconds(120).unwrap(),
        satelle_core::session::ExperimentalFeatureChoices::new(
            satelle_core::session::FeatureChoice::Enabled,
            satelle_core::session::FeatureChoice::Enabled,
        ),
    );
    let key = crate::ReadinessCacheKey::new(
        "codex-native-computer-use",
        desktop_binding,
        policy,
        "0.144.0",
        "1.0.0",
        None::<String>,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .unwrap();
    let plan = crate::storage::SetupRunPlan::new(
        operation_id.clone(),
        crate::storage::SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::UNIX_EPOCH,
        vec![
            crate::storage::SetupActionPlan::new("repair-runtime", "Repair runtime", false)
                .unwrap(),
        ],
    )
    .unwrap();
    let mut operation = service.begin_setup_run(&plan).unwrap();
    service
        .start_setup_action(
            &operation,
            "repair-runtime",
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .unwrap();
    let observed = service.run_maintenance_postcheck(&mut operation, &key, "repair-runtime");
    let stored = service.load_setup_run(&operation_id).unwrap().unwrap();
    match suffix {
        "passed" => {
            assert_eq!(crate::storage::SetupRunStatus::Completed, observed.unwrap());
            assert_eq!(crate::storage::SetupRunStatus::Completed, stored.status());
        }
        "failed" => {
            assert_eq!(
                satelle_core::ErrorCode::ComputerUseNotReady,
                observed.unwrap_err().code
            );
            assert_eq!(crate::storage::SetupRunStatus::Failed, stored.status());
        }
        "unknown" => {
            assert_eq!(
                satelle_core::ErrorCode::ComputerUseNotReady,
                observed.unwrap_err().code
            );
            assert_eq!(
                crate::storage::SetupRunStatus::OutcomeUnknown,
                stored.status()
            );
        }
        _ => unreachable!(),
    }
    if suffix != "unknown" {
        service
            .runtime
            .run(RunCommand::attached(
                LOCAL_DEMO_HOST,
                "PRIVATE_AFTER_POSTCHECK",
            ))
            .expect("known postcheck result must release both leases");
    } else {
        service
            .runtime
            .run(RunCommand::attached(
                LOCAL_DEMO_HOST,
                "PRIVATE_UNKNOWN_POSTCHECK",
            ))
            .expect_err("unknown postcheck result must retain both leases");
    }
}

#[test]
fn lost_maintenance_guard_is_recovery_pending_and_stale_authority_is_rejected() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let service = crate::HostService::local_demo_for_tests_at(state.path()).unwrap();
    let plan = crate::storage::SetupRunPlan::new(
        "lost-maintenance-worker",
        crate::storage::SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::UNIX_EPOCH,
        vec![
            crate::storage::SetupActionPlan::new("repair-runtime", "Repair runtime", false)
                .unwrap(),
        ],
    )
    .unwrap();
    let operation = service.begin_setup_run(&plan).unwrap();
    drop(operation);

    let stored = service.load_setup_run(plan.run_id()).unwrap().unwrap();
    assert_eq!(
        crate::storage::SetupRunStatus::OutcomeUnknown,
        stored.status()
    );

    let conflict = service
        .runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_RECOVERY_PENDING",
        ))
        .expect_err("ambiguous maintenance loss must remain fail-closed");
    assert_eq!(
        satelle_core::session::TurnAdmissionPhase::NotAdmitted,
        conflict.phase()
    );
}

#[test]
fn host_service_reconciles_restart_postconditions_and_unknown_remains_blocking() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let service = crate::HostService::local_demo_for_tests_at(state.path()).unwrap();
    let plan = crate::storage::SetupRunPlan::new(
        "restart-maintenance",
        crate::storage::SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::UNIX_EPOCH,
        vec![
            crate::storage::SetupActionPlan::new("repair-runtime", "Repair runtime", false)
                .unwrap(),
        ],
    )
    .unwrap();
    let operation = service.begin_setup_run(&plan).unwrap();
    service
        .start_setup_action(
            &operation,
            "repair-runtime",
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .unwrap();
    drop(operation);
    drop(service);

    let restarted = crate::HostService::local_demo_for_tests_at(state.path()).unwrap();
    let mut unknown = FixedSetupObserver::unknown();
    restarted
        .reconcile_setup_maintenance(&mut unknown)
        .expect_err("observer failure must preserve restart ownership");
    restarted
        .runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_UNKNOWN_RECOVERY",
        ))
        .expect_err("unknown reconciliation must remain fail-closed");

    let mut satisfied = FixedSetupObserver::satisfied();
    assert_eq!(
        Some(crate::storage::SetupRunStatus::Completed),
        restarted
            .reconcile_setup_maintenance(&mut satisfied)
            .expect("verified postconditions atomically commit and release")
    );
    restarted
        .runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_AFTER_RECOVERY",
        ))
        .expect("verified restart reconciliation unblocks admission");
}

enum MaintenanceProbeFixture {
    Passed,
    Failed(&'static str),
    Unknown,
}

impl ReadinessProbeDriver for MaintenanceProbeFixture {
    fn run_native_probe(
        &self,
        key: &crate::ReadinessCacheKey,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> NativeProbeResult {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(2);
        match self {
            Self::Passed => NativeProbeResult::Passed(
                key.evidence(
                    "runtime-postcheck-passed",
                    observed_at,
                    observed_at + time::Duration::minutes(5),
                )
                .unwrap(),
            ),
            Self::Failed(reason) => NativeProbeResult::Failed {
                evidence: key
                    .evidence(
                        "runtime-postcheck-failed",
                        observed_at,
                        observed_at + time::Duration::minutes(5),
                    )
                    .unwrap(),
                reason: *reason,
                error: SatelleError::computer_use_not_ready(),
            },
            Self::Unknown => {
                NativeProbeResult::UncachedFailure(SatelleError::computer_use_not_ready())
            }
        }
    }

    fn preflight_terminal_with_provider_probe(
        &self,
        _host: &str,
        _cached: Option<crate::ReadinessEvidence>,
        _cached_provider: Option<crate::ProviderSmokeResult>,
        _provider_intent: &crate::ProviderComputerUseIntent,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        unreachable!("maintenance fixture is only an operation postcheck observer")
    }

    fn observe_readiness_probe(
        &self,
        _subject: &crate::storage::ProbeRecoverySubject,
    ) -> RecoveryObservation {
        RecoveryObservation::Unknown
    }
}

struct FixedSetupObserver {
    result: Result<bool, SatelleError>,
}

impl FixedSetupObserver {
    fn unknown() -> Self {
        Self {
            result: Err(SatelleError::computer_use_not_ready()),
        }
    }

    fn satisfied() -> Self {
        Self { result: Ok(true) }
    }
}

impl crate::SetupPostconditionObserver for FixedSetupObserver {
    fn observe(&mut self, action: &crate::SetupActionRecord) -> Result<bool, SatelleError> {
        assert_eq!("repair-runtime", action.action_id());
        match &self.result {
            Ok(satisfied) => Ok(*satisfied),
            Err(_) => Err(SatelleError::computer_use_not_ready()),
        }
    }
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
    for table in ["native_readiness_results", "provider_smoke_results"] {
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
