use super::adapter::{BlockedComputerUseAdapter, NativeProbeResult, ReadinessProbeDriver};
use super::{
    AdapterPreflight, AdapterReadiness, ComputerUseAdapter, ExecuteRequest, ExecuteResult,
    LogPageQuery, ProviderComputerUseIntent, ProviderSmokeFailureEvidence, ReadinessCacheKey,
    ReadinessEvidence, RecoveryObservation, RequestIdentity, RunCommand, RuntimeHandle,
    RuntimeStartupState, SteerCommand, StopCommand,
};
use crate::storage::{LeaseOwner, PrivateUpstreamRef, ProbeRecoverySubject};
use crate::test_runtime::FakeComputerUseAdapter;
use crate::{AttachmentUpload, attachment::verify_uploads};
use base64::Engine as _;
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, PublicSession, PublicTurn,
    SafeSummary, SandboxPolicy, StopObservation, TimeoutPolicy, TurnState, TurnTransition,
};
use satelle_core::{
    ControlPlaneFailureReason, ControlPlaneOperation, ErrorCode, EventType,
    IncompatibleControlPlaneDetails, LOCAL_DEMO_HOST, SatelleError,
};
use satelle_test_contract::assert_privacy_canaries_absent;
use sha2::Digest as _;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

const WAIT_LIMIT: Duration = Duration::from_secs(2);
const DEADLOCK_GUARD_LIMIT: Duration = Duration::from_secs(30);
const STABLE_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PRIVATE_UPSTREAM_THREAD_REF: &str = "PRIVATE_UPSTREAM_THREAD_REFERENCE_CANARY";
const PRIVATE_UPSTREAM_TURN_REF: &str = "PRIVATE_UPSTREAM_TURN_REFERENCE_CANARY";
const PRIVATE_UPSTREAM_GOAL_REF: &str = "PRIVATE_UPSTREAM_GOAL_REFERENCE_CANARY";

fn latest_turn(session: &PublicSession) -> &PublicTurn {
    session
        .turns()
        .last()
        .expect("a public Session must contain Turn history")
}

fn latest_turn_state(session: &PublicSession) -> TurnState {
    latest_turn(session).state()
}

fn verified_png() -> Vec<crate::attachment::VerifiedImageAttachment> {
    let bytes = b"\x89PNG\r\n\x1a\nPRIVATE_RUNTIME_ATTACHMENT_CANARY";
    let digest = sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    verify_uploads(vec![AttachmentUpload::new(
        "image/png",
        bytes.len() as u64,
        digest,
        base64::engine::general_purpose::STANDARD.encode(bytes),
    )])
    .expect("verify the runtime image fixture")
}

fn staged_file_count(state_root: &std::path::Path) -> usize {
    std::fs::read_dir(state_root.join("attachments"))
        .expect("read attachment staging directory")
        .count()
}

#[test]
fn commit_gate_rejection_drops_staged_attachments() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter);
    let engine = runtime.engine().expect("runtime engine should open");
    let readiness = FakeComputerUseAdapter
        .preflight(LOCAL_DEMO_HOST, &ProviderComputerUseIntent::host_default())
        .expect("fake adapter preflight");
    let cancellation = super::AdmissionCancellation::new();
    cancellation.request();

    let error = engine
        .run(
            RunCommand::attached(LOCAL_DEMO_HOST, "PRIVATE_REJECTED_IMAGE")
                .with_cancellation(cancellation)
                .with_attachments(verified_png()),
            readiness,
        )
        .expect_err("the commit gate should reject requested cancellation");

    assert_eq!(error.code, ErrorCode::Interrupted);
    assert_eq!(staged_file_count(state.path()), 0);
    assert_eq!(runtime.snapshot().unwrap().session_count(), 0);
}

#[test]
fn detached_completion_keeps_then_removes_staged_attachments() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = BlockingExecutionAndStopAdapter::default();
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());

    runtime
        .run(
            RunCommand::detached(LOCAL_DEMO_HOST, "PRIVATE_DETACHED_IMAGE")
                .with_attachments(verified_png()),
        )
        .expect("detached image Turn should be admitted");
    adapter.execute_started.wait();
    assert_eq!(staged_file_count(state.path()), 1);
    adapter.execute_release.signal();
    runtime.wait_for_background().expect("worker should finish");
    assert_eq!(staged_file_count(state.path()), 0);
}

#[test]
fn runtime_mirrors_only_committed_normalized_log_entries() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter);
    let cursor = runtime
        .append_log_for_tests(
            time::OffsetDateTime::now_utc(),
            crate::LogSource::Storage,
            crate::LogSeverity::Info,
        )
        .expect("commit authoritative log entry");

    let operator_log = std::fs::read_to_string(state.path().join("logs/satelle-host.log"))
        .expect("read runtime-owned operator log mirror");
    assert!(operator_log.contains(&format!("cursor={cursor}")));
    assert!(operator_log.contains("event=store_opened subject=host"));
    assert!(operator_log.contains("message=\"opened Host state store\""));
}

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

    assert_eq!(error.error().code, ErrorCode::ComputerUseNotReady);
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
fn provider_smoke_preflight_event_reports_safe_live_provenance() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter);

    let outcome = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_PROVIDER_PROVENANCE_CANARY",
        ))
        .expect("fake provider preflight and Turn should succeed");
    let provider = outcome
        .events
        .first()
        .expect("provider preflight should be the first attached event");

    assert_eq!(provider.seq(), 1);
    assert_eq!(provider.event_type(), EventType::ProviderSmoke);
    assert_eq!(provider.data()["status"], "passed");
    assert_eq!(provider.data()["source"], "live");
    assert!(provider.data()["observed_at"].is_string());
    assert!(provider.data()["expires_at"].is_string());
    assert!(provider.data()["age_ms"].is_u64());
    assert!(provider.data().get("provider_config_fingerprint").is_none());
    assert_eq!(outcome.events[1].seq(), 2);
}

#[test]
fn unknown_provider_probe_ownership_blocks_probe_and_prompt_until_terminal_reconciliation() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::new([
        RecoveryObservation::Running,
        RecoveryObservation::Running,
        RecoveryObservation::Completed,
    ]);
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter,
    );
    let provider_intent = ProviderComputerUseIntent::new(None, None, true, true);

    let first = runtime
        .refresh_provider_smoke(LOCAL_DEMO_HOST, &provider_intent)
        .expect_err("unknown cancellation must fail the provider probe");
    assert_eq!(first.code, ErrorCode::ProviderSmokeTestTimeout);
    let engine = runtime.engine().expect("runtime engine should be open");
    let storage = engine.lock_storage().unwrap();
    let status: String = storage
        .connection_for_test()
        .query_row("SELECT status FROM provider_smoke_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    let lease = storage
        .connection_for_test()
        .query_row(
            "SELECT lease_state, upstream_thread_ref, upstream_turn_ref
             FROM control_leases WHERE owner_kind = 'provider_probe'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .unwrap();
    drop(storage);
    assert_eq!("outcome_unknown", status);
    assert_eq!("recovery_pending", lease.0);
    assert_eq!(PRIVATE_UPSTREAM_THREAD_REF, lease.1);
    assert_eq!(PRIVATE_UPSTREAM_TURN_REF, lease.2);

    let prompt_error = runtime
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "blocked-prompt"))
        .expect_err("a running recovered probe must block prompt admission");
    assert_eq!(
        prompt_error.error().details["reason"],
        "provider_probe_recovery_pending"
    );
    let probe_error = runtime
        .refresh_provider_smoke(LOCAL_DEMO_HOST, &provider_intent)
        .expect_err("a running recovered probe must block another probe");
    assert_eq!(
        probe_error.details["reason"],
        "provider_probe_recovery_pending"
    );

    runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "prompt-after-terminal-reconciliation",
        ))
        .expect("terminal upstream observation should release the probe lease");
    let remaining: i64 = engine
        .lock_storage()
        .unwrap()
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM control_leases WHERE owner_kind = 'provider_probe'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(0, remaining);
}

#[test]
fn active_provider_probe_blocks_without_external_reconciliation() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::new([]);
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter.clone(),
    );
    let engine = runtime.engine().expect("runtime engine should be open");
    let now = time::OffsetDateTime::now_utc();
    let owner = LeaseOwner::new("active-probe", 1, "process-start", "boot-id", now).unwrap();
    engine
        .lock_storage()
        .unwrap()
        .begin_provider_probe(
            &ProviderProbeRecoveryAdapter::key(),
            "active-provider-probe",
            &owner,
        )
        .unwrap();

    let error = runtime
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "conflicting-prompt"))
        .expect_err("an active provider probe owns the desktop");
    assert_eq!(
        error.error().details["reason"],
        "provider_probe_recovery_pending"
    );
    assert_eq!(0, adapter.observation_calls.load(Ordering::SeqCst));
}

#[test]
fn provider_probe_failure_before_dispatch_releases_control() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::new([]).with_provider_dispatch_possible(false);
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter,
    );
    let provider_intent = ProviderComputerUseIntent::new(None, None, true, true);

    runtime
        .refresh_provider_smoke(LOCAL_DEMO_HOST, &provider_intent)
        .expect_err("synthetic pre-dispatch provider failure must fail the probe");

    let engine = runtime.engine().expect("runtime engine should be open");
    let storage = engine.lock_storage().unwrap();
    let status: String = storage
        .connection_for_test()
        .query_row("SELECT status FROM provider_smoke_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    let leases: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM control_leases WHERE owner_kind = 'provider_probe'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!("timed_out", status);
    assert_eq!(0, leases);
}

#[test]
fn native_probe_ordinary_failure_preserves_only_possible_dispatch() {
    for (behavior, expected_status, expected_leases) in [
        (
            NativeProbeBehavior::FailedBeforeDispatch,
            "timed_out",
            0_i64,
        ),
        (
            NativeProbeBehavior::FailedAfterDispatch,
            "outcome_unknown",
            1_i64,
        ),
    ] {
        let state = crate::TestStateDir::new().expect("temporary state directory should exist");
        let adapter = ProviderProbeRecoveryAdapter::with_native_results([], [behavior]);
        let runtime = RuntimeHandle::new_with_readiness_probe_driver(
            Ok(state.path().to_path_buf()),
            adapter.clone(),
            adapter,
        );

        runtime
            .run(RunCommand::attached(
                LOCAL_DEMO_HOST,
                "classify ordinary native probe failure",
            ))
            .expect_err("synthetic native probe failure must block admission");

        let engine = runtime.engine().expect("runtime engine should be open");
        let storage = engine.lock_storage().unwrap();
        let status: String = storage
            .connection_for_test()
            .query_row("SELECT status FROM native_readiness_results", [], |row| {
                row.get(0)
            })
            .unwrap();
        let leases: i64 = storage
            .connection_for_test()
            .query_row(
                "SELECT count(*) FROM control_leases WHERE owner_kind = 'native_probe'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expected_status, status);
        assert_eq!(expected_leases, leases);
    }
}

#[test]
fn confirmed_native_probe_timeout_is_terminal_and_releases_control() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::with_native_results(
        [],
        [
            NativeProbeBehavior::TimedOutConfirmed,
            NativeProbeBehavior::Passed,
        ],
    );
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter,
    );

    let error = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "blocked-by-native-timeout",
        ))
        .expect_err("the prompt must not execute after a native readiness timeout");
    assert_eq!(error.error().code, ErrorCode::NativeReadinessTimeout);
    assert_eq!(
        error.error().details["native_readiness_cancellation"],
        "confirmed"
    );
    let engine = runtime.engine().expect("runtime engine should be open");
    let storage = engine.lock_storage().unwrap();
    let status: String = storage
        .connection_for_test()
        .query_row("SELECT status FROM native_readiness_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    let leases: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM control_leases WHERE owner_kind = 'native_probe'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(storage);
    assert_eq!("timed_out", status);
    assert_eq!(0, leases);

    runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "prompt-after-confirmed-timeout",
        ))
        .expect("confirmed cancellation must allow a later native probe and prompt");
}

#[test]
fn native_probe_timeout_without_terminal_evidence_retains_recovery() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::with_native_results(
        [],
        [NativeProbeBehavior::TimedOutWithoutCancellationDetail],
    );
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter,
    );

    let error = runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "native-timeout-without-cancellation-detail",
        ))
        .expect_err("a dispatched timeout without terminal evidence must fail closed");
    assert_eq!(error.error().code, ErrorCode::NativeReadinessTimeout);
    assert!(
        !error
            .error()
            .details
            .contains_key("native_readiness_cancellation")
    );

    let engine = runtime.engine().expect("runtime engine should be open");
    let storage = engine.lock_storage().unwrap();
    let status: String = storage
        .connection_for_test()
        .query_row("SELECT status FROM native_readiness_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    let leases: i64 = storage
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM control_leases WHERE owner_kind = 'native_probe'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!("outcome_unknown", status);
    assert_eq!(1, leases);
}

#[test]
fn unknown_native_probe_timeout_blocks_until_terminal_reconciliation() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::with_native_results(
        [
            RecoveryObservation::Running,
            RecoveryObservation::Running,
            RecoveryObservation::Completed,
        ],
        [
            NativeProbeBehavior::TimedOutUnknown,
            NativeProbeBehavior::Passed,
        ],
    );
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter,
    );

    runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "native-timeout-unknown",
        ))
        .expect_err("unconfirmed cancellation must fail closed");
    let engine = runtime.engine().expect("runtime engine should be open");
    let storage = engine.lock_storage().unwrap();
    let status: String = storage
        .connection_for_test()
        .query_row("SELECT status FROM native_readiness_results", [], |row| {
            row.get(0)
        })
        .unwrap();
    let lease = storage
        .connection_for_test()
        .query_row(
            "SELECT lease_state, upstream_thread_ref, upstream_turn_ref
             FROM control_leases WHERE owner_kind = 'native_probe'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .unwrap();
    drop(storage);
    assert_eq!("outcome_unknown", status);
    assert_eq!("recovery_pending", lease.0);
    assert_eq!(PRIVATE_UPSTREAM_THREAD_REF, lease.1);
    assert_eq!(PRIVATE_UPSTREAM_TURN_REF, lease.2);

    for prompt in ["conflicting-prompt", "conflicting-native-probe"] {
        let error = runtime
            .run(RunCommand::attached(LOCAL_DEMO_HOST, prompt))
            .expect_err("an active upstream probe must retain exclusive control");
        assert_eq!(
            error.error().details["reason"],
            "native_probe_recovery_pending"
        );
    }

    runtime
        .run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "prompt-after-native-reconciliation",
        ))
        .expect("terminal observation must release control before retrying the probe");
    let remaining: i64 = engine
        .lock_storage()
        .unwrap()
        .connection_for_test()
        .query_row(
            "SELECT count(*) FROM control_leases WHERE owner_kind = 'native_probe'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(0, remaining);
}

#[test]
fn active_native_probe_blocks_without_external_reconciliation() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = ProviderProbeRecoveryAdapter::new([]);
    let runtime = RuntimeHandle::new_with_readiness_probe_driver(
        Ok(state.path().to_path_buf()),
        adapter.clone(),
        adapter.clone(),
    );
    let engine = runtime.engine().expect("runtime engine should be open");
    let now = time::OffsetDateTime::now_utc();
    let owner = LeaseOwner::new("active-native-probe", 1, "process-start", "boot-id", now).unwrap();
    engine
        .lock_storage()
        .unwrap()
        .begin_native_probe(
            &ProviderProbeRecoveryAdapter::key(),
            "active-native-probe",
            &owner,
        )
        .unwrap();

    let error = runtime
        .run(RunCommand::attached(LOCAL_DEMO_HOST, "conflicting-prompt"))
        .expect_err("an active native probe owns the desktop");
    assert_eq!(
        error.error().details["reason"],
        "native_probe_recovery_pending"
    );
    assert_eq!(0, adapter.observation_calls.load(Ordering::SeqCst));
}

#[test]
fn reads_and_stop_remain_available_during_slow_execution_and_stop_observation() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let adapter = BlockingExecutionAndStopAdapter::default();
    let deadlock_guard = DeadlockGuard::new([
        adapter.execute_started.clone(),
        adapter.execute_release.clone(),
        adapter.stop_started.clone(),
        adapter.stop_release.clone(),
    ]);
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter.clone());
    let session = runtime
        .run(
            RunCommand::detached(LOCAL_DEMO_HOST, "PRIVATE_BLOCKING_EXECUTION")
                .with_attachments(verified_png()),
        )
        .expect("detached work should be admitted")
        .session;
    adapter.execute_started.wait();
    assert_eq!(staged_file_count(state.path()), 1);

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let read_runtime = runtime.clone();
    let read_session_id = session.session_id().clone();
    let execute_read = std::thread::spawn(move || {
        let result = read_runtime.status(read_session_id).and_then(|status| {
            let count = read_runtime.snapshot()?.session_count();
            Ok((status, count))
        });
        read_sender
            .send(result)
            .expect("read receiver should remain connected");
    });
    let (running_status, count) = read_receiver
        .recv()
        .expect("read worker should publish its result")
        .expect("reads should succeed during adapter execution");
    execute_read.join().expect("read worker should finish");
    assert_eq!(latest_turn_state(&running_status), TurnState::Running);
    assert_eq!(count, 1);

    let (stop_sender, stop_receiver) = mpsc::sync_channel(1);
    let stop_runtime = runtime.clone();
    let stop_session_id = session.session_id().clone();
    let stop_worker = std::thread::spawn(move || {
        let result = stop_runtime.stop(StopCommand::with_identity(
            stop_session_id,
            RequestIdentity::new("blocking-stop", STABLE_DIGEST),
        ));
        stop_sender
            .send(result)
            .expect("stop receiver should remain connected");
    });
    adapter.stop_started.wait();

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let read_runtime = runtime.clone();
    let read_session_id = session.session_id().clone();
    let stop_read = std::thread::spawn(move || {
        let result = read_runtime.status(read_session_id).and_then(|status| {
            let logs = read_runtime.log_page(&LogPageQuery::default())?;
            Ok((status, logs))
        });
        read_sender
            .send(result)
            .expect("read receiver should remain connected");
    });
    let (_status, logs) = read_receiver
        .recv()
        .expect("read worker should publish its result")
        .expect("reads should succeed during stop observation");
    stop_read.join().expect("read worker should finish");
    assert!(!logs.entries().is_empty());

    adapter.stop_release.signal();
    let stopped = stop_receiver
        .recv()
        .expect("stop worker should publish its result")
        .expect("confirmed stop should succeed");
    stop_worker.join().expect("stop worker should finish");
    assert_eq!(stopped.current_state(), TurnState::Stopped);

    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the losing execution worker should finish");
    assert_eq!(staged_file_count(state.path()), 0);
    let final_status = runtime
        .status(session.session_id().clone())
        .expect("the terminal stop compare-and-swap should win");
    assert_eq!(latest_turn_state(&final_status), TurnState::Stopped);
    deadlock_guard.complete();
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
    let turn_id = latest_turn(&session).turn_id().clone();
    if !adapter.references_recorded.wait_for(WAIT_LIMIT) {
        adapter.execute_release.signal();
        panic!("the adapter did not durably record its upstream references");
    }

    let engine = runtime.engine().expect("runtime engine should be open");
    let expected_thread_ref = PrivateUpstreamRef::new(PRIVATE_UPSTREAM_THREAD_REF)
        .expect("the thread canary must be a valid private reference");
    let expected_turn_ref = PrivateUpstreamRef::new(PRIVATE_UPSTREAM_TURN_REF)
        .expect("the Turn canary must be a valid private reference");
    let expected_goal_ref = PrivateUpstreamRef::new(PRIVATE_UPSTREAM_GOAL_REF)
        .expect("the Goal canary must be a valid private reference");
    let durable_subject = engine
        .lock_storage()
        .expect("lock runtime storage")
        .recovery_subject(session.session_id(), &turn_id)
        .expect("reload durable adapter subject");
    assert_eq!(
        durable_subject.upstream_thread_ref(),
        Some(&expected_thread_ref)
    );
    assert_eq!(
        durable_subject.upstream_turn_ref(),
        Some(&expected_turn_ref)
    );
    assert_eq!(
        durable_subject.upstream_goal_ref(),
        Some(&expected_goal_ref)
    );
    let public_session = runtime
        .status(session.session_id().clone())
        .expect("read public Session while execution is waiting");
    let logs = runtime
        .log_page(&LogPageQuery::default())
        .expect("read safe logs while execution is waiting");
    let public_json = serde_json::to_string(&(public_session, logs))
        .expect("serialize public state and safe logs");
    assert_privacy_canaries_absent(
        "Host runtime status and log projection",
        public_json.as_bytes(),
        &[
            PRIVATE_UPSTREAM_THREAD_REF,
            PRIVATE_UPSTREAM_TURN_REF,
            PRIVATE_UPSTREAM_GOAL_REF,
        ],
    );

    let stopped = runtime
        .stop(StopCommand::new(session.session_id().clone()))
        .expect("stop observation should consume the durable references");
    assert_eq!(stopped.current_state(), TurnState::Stopped);
    adapter.execute_release.signal();
    runtime
        .wait_for_background()
        .expect("the losing execution worker should finish");

    let final_status = runtime
        .status(session.session_id().clone())
        .expect("the confirmed stop should remain terminal");
    assert_eq!(latest_turn_state(&final_status), TurnState::Stopped);
    let final_subject = engine
        .lock_storage()
        .expect("lock runtime storage after stop")
        .recovery_subject(session.session_id(), &turn_id)
        .expect("reload durable adapter subject after stop");
    assert_eq!(
        final_subject.upstream_thread_ref(),
        Some(&expected_thread_ref)
    );
    assert_eq!(final_subject.upstream_turn_ref(), Some(&expected_turn_ref));
    assert_eq!(final_subject.upstream_goal_ref(), Some(&expected_goal_ref));
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
        .session_id()
        .clone();
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
        .status(session.session_id().clone())
        .expect("status should not require adapter readiness");
    let logs = blocked
        .log_page(&LogPageQuery::default())
        .expect("logs should not require adapter readiness");
    let count = blocked
        .snapshot()
        .expect("runtime snapshot should not require adapter readiness")
        .session_count();

    assert_eq!(latest_turn_state(&status), TurnState::Completed);
    assert!(!logs.entries().is_empty());
    assert_eq!(count, 1);
}

#[test]
fn detached_adapter_error_enters_recovery_without_a_restart() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FailFirstAdapter::default());
    let session = runtime
        .run(
            RunCommand::detached(LOCAL_DEMO_HOST, "PRIVATE_UNKNOWN_EXECUTION")
                .with_attachments(verified_png()),
        )
        .expect("detached work should be durably admitted")
        .session;
    runtime
        .wait_for_background()
        .expect("the failed detached worker should be reaped");
    assert_eq!(staged_file_count(state.path()), 0);

    assert_eq!(
        runtime
            .startup_state()
            .expect("unknown execution should be queued for reconciliation"),
        RuntimeStartupState::RecoveryRequired
    );
    let status = runtime
        .status(session.session_id().clone())
        .expect("the recovering Session should remain readable");
    assert_eq!(latest_turn_state(&status), TurnState::RecoveryPending);

    runtime
        .stop(StopCommand::new(session.session_id().clone()))
        .expect("confirmed stop should resolve the queued recovery subject");
    assert_eq!(
        runtime
            .startup_state()
            .expect("confirmed stop should clear recovery"),
        RuntimeStartupState::Ready
    );
}

#[test]
fn detached_worker_panic_drops_staged_attachments() {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), PanickingExecutionAdapter);
    let session = runtime
        .run(
            RunCommand::detached(LOCAL_DEMO_HOST, "PRIVATE_PANICKING_IMAGE")
                .with_attachments(verified_png()),
        )
        .expect("panicking detached work should first be admitted")
        .session;

    runtime
        .wait_for_background()
        .expect("the panicking worker should be contained and reaped");

    assert_eq!(staged_file_count(state.path()), 0);
    assert_eq!(
        latest_turn_state(&runtime.status(session.session_id().clone()).unwrap()),
        TurnState::RecoveryPending
    );
}

#[test]
fn restart_recovery_commits_adapter_proven_blocked_and_failed_outcomes() {
    for (observation, expected_state) in [
        (RecoveryObservation::Blocked, TurnState::Blocked),
        (RecoveryObservation::Failed, TurnState::Failed),
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
        let recovered_session_id = old_session.session_id().clone();
        let recovered = restarted
            .status(recovered_session_id.clone())
            .expect("the recovered Session should remain readable");
        assert_eq!(latest_turn_state(&recovered), expected_state);
        if observation == RecoveryObservation::Failed {
            let public = restarted
                .status(recovered_session_id.clone())
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
        .status(old_session.session_id().clone())
        .expect("interrupted status should be readable");
    drop(interrupted);

    let adapter = BlockingRecoveryAdapter::default();
    let deadlock_guard = DeadlockGuard::new([
        adapter.recovery_started.clone(),
        adapter.recovery_release.clone(),
    ]);
    let restarted = RuntimeHandle::new(Ok(state_root), adapter.clone());
    let run_runtime = restarted.clone();
    let (run_sender, run_receiver) = mpsc::sync_channel(1);
    let run_worker = std::thread::spawn(move || {
        let result = run_runtime.run(RunCommand::attached(
            LOCAL_DEMO_HOST,
            "PRIVATE_AFTER_RECOVERY",
        ));
        run_sender
            .send(result)
            .expect("run receiver should remain connected");
    });
    adapter.recovery_started.wait();

    let (read_sender, read_receiver) = mpsc::sync_channel(1);
    let read_runtime = restarted.clone();
    let read_session_id = old_session.session_id().clone();
    let read_worker = std::thread::spawn(move || {
        let result = read_runtime.status(read_session_id).and_then(|status| {
            let logs = read_runtime.log_page(&LogPageQuery::default())?;
            Ok((status, logs.entries().len()))
        });
        read_sender
            .send(result)
            .expect("read receiver should remain connected");
    });
    let (recovering_status, log_count) = read_receiver
        .recv()
        .expect("read worker should publish its result")
        .expect("reads should succeed during recovery observation");
    read_worker.join().expect("read worker should finish");
    assert_eq!(
        latest_turn_state(&recovering_status),
        TurnState::RecoveryPending
    );
    assert!(log_count > 0);

    adapter.recovery_release.signal();
    let new_outcome = run_receiver
        .recv()
        .expect("run worker should publish its result")
        .expect("recovery and new execution should succeed");
    run_worker.join().expect("run worker should finish");
    let recovered = restarted
        .status(old_session.session_id().clone())
        .expect("recovered Session should remain readable");

    assert_eq!(latest_turn_state(&recovered), TurnState::Completed);
    assert!(recovered.updated_at() >= before_recovery.updated_at());
    assert_eq!(
        latest_turn_state(&new_outcome.session),
        TurnState::Completed
    );
    assert_eq!(adapter.recovery_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        restarted
            .startup_state()
            .expect("successful reconciliation should clear startup recovery"),
        RuntimeStartupState::Ready
    );
    deadlock_guard.complete();
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
    assert_eq!(error.error().code, ErrorCode::HostBusy);
    assert_eq!(error.error().details["reason"], "outcome_unknown");
    assert_eq!(
        error.error().recovery_command.as_deref(),
        Some(format!("satelle status {} --json", session.session_id())).as_deref()
    );
    assert_eq!(
        restarted
            .startup_state()
            .expect("unknown work should remain in recovery"),
        RuntimeStartupState::RecoveryRequired
    );

    let stopped = restarted
        .stop(StopCommand::new(session.session_id().clone()))
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

#[derive(Clone, Copy)]
struct PanickingExecutionAdapter;

impl ComputerUseAdapter for PanickingExecutionAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        panic!("PRIVATE_ADAPTER_PANIC_CANARY")
    }

    fn observe_stop(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
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

#[derive(Clone)]
struct ProviderProbeRecoveryAdapter {
    observations: Arc<Mutex<VecDeque<RecoveryObservation>>>,
    observation_calls: Arc<AtomicUsize>,
    native_results: Arc<Mutex<VecDeque<NativeProbeBehavior>>>,
    native_probe_calls: Arc<AtomicUsize>,
    provider_dispatch_possible: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
enum NativeProbeBehavior {
    Passed,
    TimedOutConfirmed,
    TimedOutUnknown,
    TimedOutWithoutCancellationDetail,
    FailedBeforeDispatch,
    FailedAfterDispatch,
}

impl ProviderProbeRecoveryAdapter {
    fn new(observations: impl IntoIterator<Item = RecoveryObservation>) -> Self {
        Self {
            observations: Arc::new(Mutex::new(observations.into_iter().collect())),
            observation_calls: Arc::new(AtomicUsize::new(0)),
            native_results: Arc::new(Mutex::new(VecDeque::new())),
            native_probe_calls: Arc::new(AtomicUsize::new(0)),
            provider_dispatch_possible: Arc::new(AtomicBool::new(true)),
        }
    }

    fn with_native_results(
        observations: impl IntoIterator<Item = RecoveryObservation>,
        results: impl IntoIterator<Item = NativeProbeBehavior>,
    ) -> Self {
        let adapter = Self::new(observations);
        *adapter.native_results.lock().unwrap() = results.into_iter().collect();
        adapter
    }

    fn key() -> ReadinessCacheKey {
        let desktop = DesktopBindingRef::new("provider-probe-desktop").unwrap();
        let policy = ExecutionPolicy::new(
            EffectiveModelRef::new("provider-probe-model").unwrap(),
            ProviderBindingRef::new("provider-probe-binding").unwrap(),
            DesktopTarget::new(desktop.clone()),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Enabled),
        );
        ReadinessCacheKey::new(
            "provider-probe-test",
            desktop,
            policy,
            "codex-test",
            "native-test",
            None::<String>,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap()
    }

    fn readiness_with_id(result_id: impl Into<String>) -> ReadinessEvidence {
        let now = time::OffsetDateTime::now_utc();
        Self::key()
            .evidence(result_id, now, now + time::Duration::minutes(5))
            .unwrap()
    }

    fn readiness() -> ReadinessEvidence {
        Self::readiness_with_id("provider-probe-native-result")
    }

    fn with_provider_dispatch_possible(self, possible: bool) -> Self {
        self.provider_dispatch_possible
            .store(possible, Ordering::SeqCst);
        self
    }
}

impl ComputerUseAdapter for ProviderProbeRecoveryAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn readiness_cache_key(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ReadinessCacheKey>, SatelleError> {
        Ok(Some(Self::key()))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
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
        subject: super::AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

impl ReadinessProbeDriver for ProviderProbeRecoveryAdapter {
    fn run_native_probe(
        &self,
        _key: &ReadinessCacheKey,
        _cancellation: &super::AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> NativeProbeResult {
        let call = self.native_probe_calls.fetch_add(1, Ordering::SeqCst);
        let evidence = Self::readiness_with_id(format!("native-probe-result-{call}"));
        match self
            .native_results
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(NativeProbeBehavior::Passed)
        {
            NativeProbeBehavior::Passed => NativeProbeResult::Passed(evidence),
            behavior => {
                let dispatch_possible = matches!(
                    behavior,
                    NativeProbeBehavior::TimedOutConfirmed
                        | NativeProbeBehavior::TimedOutUnknown
                        | NativeProbeBehavior::TimedOutWithoutCancellationDetail
                        | NativeProbeBehavior::FailedAfterDispatch
                );
                if dispatch_possible {
                    persist_thread_ref(PRIVATE_UPSTREAM_THREAD_REF).unwrap();
                    persist_turn_ref(PRIVATE_UPSTREAM_TURN_REF).unwrap();
                }
                let mut error = SatelleError::native_readiness_timeout();
                error.details.insert(
                    "reason".to_string(),
                    serde_json::Value::String("native_readiness_timed_out".to_string()),
                );
                let cancellation = match behavior {
                    NativeProbeBehavior::TimedOutConfirmed => Some("confirmed"),
                    NativeProbeBehavior::TimedOutUnknown => Some("outcome_unknown"),
                    NativeProbeBehavior::TimedOutWithoutCancellationDetail => None,
                    NativeProbeBehavior::FailedBeforeDispatch
                    | NativeProbeBehavior::FailedAfterDispatch => None,
                    NativeProbeBehavior::Passed => unreachable!(),
                };
                if let Some(cancellation) = cancellation {
                    error.details.insert(
                        "native_readiness_cancellation".to_string(),
                        serde_json::Value::String(cancellation.to_string()),
                    );
                }
                NativeProbeResult::Failed {
                    evidence,
                    reason: "native_readiness_timed_out",
                    error,
                    dispatch_possible,
                }
            }
        }
    }

    fn preflight_terminal_with_provider_probe(
        &self,
        _host: &str,
        _cached: Option<ReadinessEvidence>,
        _cached_provider: Option<super::ProviderSmokeResult>,
        _provider_intent: &ProviderComputerUseIntent,
        _cancellation: &super::AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        let dispatch_possible = self.provider_dispatch_possible.load(Ordering::SeqCst);
        if dispatch_possible {
            persist_thread_ref(PRIVATE_UPSTREAM_THREAD_REF).unwrap();
            persist_turn_ref(PRIVATE_UPSTREAM_TURN_REF).unwrap();
        }
        let key = Self::key();
        let readiness = Self::readiness();
        let now = time::OffsetDateTime::now_utc();
        let failure = ProviderSmokeFailureEvidence::new(
            "provider-probe-outcome-unknown",
            key.provider_config_fingerprint(),
            ErrorCode::ProviderSmokeTestTimeout,
            "provider_smoke_timed_out",
            now,
            now + time::Duration::minutes(10),
        )
        .unwrap();
        let mut error = SatelleError {
            code: ErrorCode::ProviderSmokeTestTimeout,
            message: "provider probe timed out".to_string(),
            recovery_command: None,
            source_detail: None,
            details: std::collections::BTreeMap::new(),
        };
        if dispatch_possible {
            error.details.insert(
                "provider_smoke_cancellation".to_string(),
                serde_json::Value::String("outcome_unknown".to_string()),
            );
        }
        error.details.insert(
            "probe_dispatch_possible".to_string(),
            serde_json::Value::Bool(dispatch_possible),
        );
        AdapterPreflight::ProviderFailed {
            key,
            readiness,
            failure,
            error,
        }
    }

    fn observe_readiness_probe(&self, subject: &ProbeRecoverySubject) -> RecoveryObservation {
        self.observation_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            Some(PRIVATE_UPSTREAM_THREAD_REF),
            subject.upstream_thread_ref()
        );
        assert_eq!(Some(PRIVATE_UPSTREAM_TURN_REF), subject.upstream_turn_ref());
        self.observations
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(RecoveryObservation::Unknown)
    }
}

impl super::ComputerUseAdapter for TerminalRecoveryAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
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

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
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
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<super::AdapterReadiness, SatelleError> {
        let readiness = FakeComputerUseAdapter.preflight(host, provider_intent)?;
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
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(
        &self,
        request: super::ExecuteRequest<'_>,
    ) -> Result<super::ExecuteResult, SatelleError> {
        request.persist_upstream_thread_ref(PRIVATE_UPSTREAM_THREAD_REF)?;
        request.persist_upstream_turn_ref(PRIVATE_UPSTREAM_TURN_REF)?;
        request.persist_upstream_goal_ref(PRIVATE_UPSTREAM_GOAL_REF)?;
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

impl super::ComputerUseAdapter for BlockingExecutionAndStopAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
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
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<super::AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
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

struct DeadlockGuard {
    emergency_releases: Vec<Latch>,
    cancelled: mpsc::SyncSender<()>,
    expired: Arc<AtomicBool>,
    watchdog: Option<std::thread::JoinHandle<()>>,
}

impl DeadlockGuard {
    fn new(emergency_releases: impl IntoIterator<Item = Latch>) -> Self {
        let emergency_releases = emergency_releases.into_iter().collect::<Vec<_>>();
        let watchdog_releases = emergency_releases.clone();
        let expired = Arc::new(AtomicBool::new(false));
        let watchdog_expired = Arc::clone(&expired);
        let (cancelled, cancellation) = mpsc::sync_channel(1);
        // Phase ordering is synchronized without elapsed-time assertions. This
        // watchdog exists only to release intentionally blocked adapters and
        // turn a genuine test deadlock into a bounded failure.
        let watchdog = std::thread::spawn(move || {
            if matches!(
                cancellation.recv_timeout(DEADLOCK_GUARD_LIMIT),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                watchdog_expired.store(true, Ordering::SeqCst);
                for release in watchdog_releases {
                    release.signal();
                }
            }
        });
        Self {
            emergency_releases,
            cancelled,
            expired,
            watchdog: Some(watchdog),
        }
    }

    fn complete(mut self) {
        self.stop_watchdog();
        assert!(
            !self.expired.load(Ordering::SeqCst),
            "test synchronization exceeded the deadlock guard"
        );
    }

    fn stop_watchdog(&mut self) {
        let _ = self.cancelled.send(());
        if let Some(watchdog) = self.watchdog.take() {
            watchdog
                .join()
                .expect("the deadlock watchdog should not panic");
        }
    }

    fn release_all(&self) {
        for release in &self.emergency_releases {
            release.signal();
        }
    }
}

impl Drop for DeadlockGuard {
    fn drop(&mut self) {
        if self.watchdog.is_none() {
            return;
        }
        self.release_all();
        self.stop_watchdog();
    }
}

#[path = "runtime-tests/control-plane.rs"]
mod control_plane;

#[path = "runtime-tests/review-regressions.rs"]
mod review_regressions;

#[path = "runtime-admission-tests.rs"]
mod admission_tests;
