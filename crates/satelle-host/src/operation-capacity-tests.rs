use crate::operation_capacity::{OperationCapacity, OperationOutcome, OperationRequest};
use crate::runtime::{
    AdapterReadiness, AdapterSubject, ComputerUseAdapter, ExecuteRequest, ExecuteResult,
    RecoveryObservation, RequestIdentity, RuntimeHandle,
};
use crate::storage::IdempotentOperation;
use crate::test_runtime::FakeComputerUseAdapter;
use crate::{ApiBearerToken, ApiScopes, HostMode, HostService, MutationAuthority, TurnIntent};
use satelle_core::session::{PublicSession, StopObservation, TurnExecutionMode};
use satelle_core::{ErrorCode, SatelleError};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

const WAIT_LIMIT: Duration = Duration::from_secs(2);

#[test]
fn one_host_global_slot_is_shared_by_clones_and_principals() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let first_authority = authority(&service, "principal-first", "global-first");
    let second_authority = authority(&service, "principal-second", "global-second");

    let leader_service = service.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(&intent("first operation"), &first_authority)
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "the first operation must occupy capacity before the assertion"
    );

    let error = service
        .admit_run(&intent("second operation"), &second_authority)
        .expect_err("another principal must share the occupied Host-global slot");
    assert_capacity_exceeded(&error);

    adapter.preflight_release.signal();
    leader
        .join()
        .expect("leader thread must not panic")
        .expect("leader admission must finish");
    service
        .runtime
        .wait_for_background()
        .expect("leader execution must finish");
}

#[test]
fn identical_concurrent_requests_join_one_execution() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let request_authority = authority(&service, "principal-singleflight", "same-request");

    let leader_service = service.clone();
    let leader_authority = request_authority.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(&intent("singleflight operation"), &leader_authority)
    });
    assert!(adapter.preflight_started.wait_for(WAIT_LIMIT));

    let follower_service = service.clone();
    let follower = std::thread::spawn(move || {
        follower_service.admit_run(&intent("singleflight operation"), &request_authority)
    });

    assert!(
        service
            .operation_capacity
            .wait_for_follower_registration(WAIT_LIMIT),
        "the duplicate must register on the leader's in-flight entry"
    );
    adapter.preflight_release.signal();
    let admitted = leader
        .join()
        .expect("leader thread must not panic")
        .expect("leader admission must finish");
    let replayed = follower
        .join()
        .expect("follower thread must not panic")
        .expect("identical follower must replay the leader admission");
    assert_eq!(admitted, replayed);
    service
        .runtime
        .wait_for_background()
        .expect("single detached execution must finish");
    assert_eq!(adapter.execute_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn identical_follower_receives_the_exact_pre_durable_leader_error() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    adapter.fail_next_preflight.store(true, Ordering::SeqCst);
    let service = service(state.path(), adapter.clone());
    let request_authority = authority(&service, "principal-error", "same-error");

    let leader_service = service.clone();
    let leader_authority = request_authority.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(&intent("shared pre-durable error"), &leader_authority)
    });
    assert!(adapter.preflight_started.wait_for(WAIT_LIMIT));

    let follower_service = service.clone();
    let follower = std::thread::spawn(move || {
        follower_service.admit_run(&intent("shared pre-durable error"), &request_authority)
    });
    assert!(
        service
            .operation_capacity
            .wait_for_follower_registration(WAIT_LIMIT),
        "the duplicate must register before the leader fails"
    );

    adapter.preflight_release.signal();
    let leader_error = leader
        .join()
        .expect("leader thread must not panic")
        .expect_err("leader preflight must fail");
    let follower_error = follower
        .join()
        .expect("follower thread must not panic")
        .expect_err("follower must receive the leader failure");
    assert_same_error(&leader_error, &follower_error);
    assert_eq!(adapter.preflight_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn conflicting_identity_beats_occupied_capacity() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let request_authority = authority(&service, "principal-conflict", "conflicting-request");

    let leader_service = service.clone();
    let leader_authority = request_authority.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(&intent("original payload"), &leader_authority)
    });
    assert!(adapter.preflight_started.wait_for(WAIT_LIMIT));

    let (sender, receiver) = mpsc::sync_channel(1);
    let conflicting_service = service.clone();
    let conflict = std::thread::spawn(move || {
        sender
            .send(conflicting_service.admit_run(&intent("changed payload"), &request_authority))
            .expect("conflict receiver must remain connected");
    });
    let error = match receiver.recv_timeout(WAIT_LIMIT) {
        Ok(result) => result.expect_err("a changed digest must conflict"),
        Err(error) => {
            adapter.preflight_release.signal();
            panic!("a changed digest waited for capacity instead of conflicting: {error}");
        }
    };
    assert_eq!(error.code, ErrorCode::IdempotencyKeyConflict);
    conflict.join().expect("conflict thread must not panic");

    adapter.preflight_release.signal();
    leader
        .join()
        .expect("leader thread must not panic")
        .expect("leader admission must finish");
    service
        .runtime
        .wait_for_background()
        .expect("finish leader");
}

#[test]
fn stale_replay_miss_is_reprobed_after_leader_handoff_and_unrelated_install() {
    let scenario = stale_probe_after_handoff(StaleProbeExpectation::Replay);

    assert_eq!(
        scenario
            .response
            .expect("the second durable probe must recover A's committed response"),
        scenario.expected
    );
    assert_eq!(scenario.probe_count, 2);
}

#[test]
fn stale_conflict_miss_is_reprobed_after_leader_handoff_and_unrelated_install() {
    let scenario = stale_probe_after_handoff(StaleProbeExpectation::Conflict);

    let error = scenario
        .response
        .expect_err("the second durable probe must recover A's committed key conflict");
    assert_eq!(error.code, ErrorCode::IdempotencyKeyConflict);
    assert_eq!(scenario.probe_count, 2);
}

#[test]
fn completed_replay_bypasses_an_unrelated_occupied_slot() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    let service = service(state.path(), adapter.clone());
    let replay_authority = authority(&service, "principal-replay", "completed-replay");
    let original = service
        .admit_run(&intent("completed operation"), &replay_authority)
        .expect("admit replay source");
    service
        .runtime
        .wait_for_background()
        .expect("complete replay source");

    adapter.block_next_preflight();
    let occupant_authority = authority(&service, "principal-occupant", "capacity-occupant");
    let occupant_service = service.clone();
    let occupant = std::thread::spawn(move || {
        occupant_service.admit_run(&intent("occupying operation"), &occupant_authority)
    });
    assert!(adapter.preflight_started.wait_for(WAIT_LIMIT));

    let replayed = service
        .admit_run(&intent("completed operation"), &replay_authority)
        .expect("durable replay must bypass unrelated capacity");
    assert_eq!(original.session_id(), replayed.session_id());

    adapter.preflight_release.signal();
    occupant
        .join()
        .expect("occupant thread must not panic")
        .expect("occupant admission must finish");
    service
        .runtime
        .wait_for_background()
        .expect("finish occupant");
}

#[test]
fn active_run_replay_bypasses_a_new_occupant_after_handoff() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_execution.store(true, Ordering::SeqCst);
    let service = service(state.path(), adapter.clone());
    let active_authority = authority(&service, "principal-handoff", "active-run");
    let active = service
        .admit_run(&intent("blocked detached execution"), &active_authority)
        .expect("detached admission must return after handoff");
    assert!(adapter.execute_started.wait_for(WAIT_LIMIT));

    adapter.block_next_preflight();
    let occupant_authority = authority(&service, "principal-handoff-occupant", "occupant-run");
    let occupant_service = service.clone();
    let occupant = std::thread::spawn(move || {
        occupant_service.admit_run(&intent("new logical operation"), &occupant_authority)
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "an unrelated operation must acquire capacity after execution handoff"
    );

    let replayed = service
        .admit_run(&intent("blocked detached execution"), &active_authority)
        .expect("durable active replay must bypass the unrelated occupied slot");
    assert_same_session_and_turn_handles(&active, &replayed);

    adapter.preflight_release.signal();
    let occupant_error = occupant
        .join()
        .expect("occupant thread must not panic")
        .expect_err("the active Turn's Control Lease must reject the unrelated admission");
    assert_eq!(occupant_error.code, ErrorCode::HostBusy);
    adapter.execute_release.signal();
    service
        .runtime
        .wait_for_background()
        .expect("blocked execution must finish after release");
}

#[test]
fn active_steer_replay_bypasses_a_new_occupant_after_handoff() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    let service = service(state.path(), adapter.clone());
    let run_authority = authority(&service, "principal-steer-seed", "steer-seed");
    let session = service
        .admit_run(&intent("seed steer session"), &run_authority)
        .expect("seed Session");
    service
        .runtime
        .wait_for_background()
        .expect("finish seed Turn");

    adapter.block_execution.store(true, Ordering::SeqCst);
    let steer_authority = authority(&service, "principal-steer-active", "active-steer");
    let active = service
        .admit_steer(
            session.session_id(),
            &intent("blocked steer"),
            &steer_authority,
        )
        .expect("admit detached steer");
    assert!(adapter.execute_started.wait_for(WAIT_LIMIT));

    adapter.block_next_preflight();
    let occupant_authority = authority(&service, "principal-steer-occupant", "steer-occupant");
    let occupant_service = service.clone();
    let occupant = std::thread::spawn(move || {
        occupant_service.admit_run(&intent("occupy during steer"), &occupant_authority)
    });
    assert!(adapter.preflight_started.wait_for(WAIT_LIMIT));

    let replayed = service
        .admit_steer(
            session.session_id(),
            &intent("blocked steer"),
            &steer_authority,
        )
        .expect("durable active steer replay must bypass unrelated capacity");
    assert_same_session_and_turn_handles(&active, &replayed);

    adapter.preflight_release.signal();
    let occupant_error = occupant
        .join()
        .expect("occupant thread must not panic")
        .expect_err("the active steer Turn's Control Lease must reject the unrelated admission");
    assert_eq!(occupant_error.code, ErrorCode::HostBusy);
    adapter.execute_release.signal();
    service
        .runtime
        .wait_for_background()
        .expect("finish executions");
}

#[test]
fn stop_holds_capacity_through_confirmation_and_identical_stop_joins() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_execution.store(true, Ordering::SeqCst);
    adapter.block_stop.store(true, Ordering::SeqCst);
    let service = service(state.path(), adapter.clone());
    let run_authority = authority(&service, "principal-stop", "run-before-stop");
    let session = service
        .admit_run(&intent("active operation"), &run_authority)
        .expect("admit active operation");
    assert!(adapter.execute_started.wait_for(WAIT_LIMIT));
    let stop_authority = authority(&service, "principal-stop-follower", "same-stop");

    let leader_service = service.clone();
    let leader_session = session.session_id().clone();
    let leader_authority = stop_authority.clone();
    let leader =
        std::thread::spawn(move || leader_service.admit_stop(&leader_session, &leader_authority));
    assert!(adapter.stop_started.wait_for(WAIT_LIMIT));

    let unrelated_authority = authority(&service, "principal-stop-capacity", "unrelated-run");
    let error = service
        .admit_run(
            &intent("blocked by stop confirmation"),
            &unrelated_authority,
        )
        .expect_err("stop confirmation must retain the Host-global slot");
    assert_capacity_exceeded(&error);

    let follower_service = service.clone();
    let follower_session = session.session_id().clone();
    let follower =
        std::thread::spawn(move || follower_service.admit_stop(&follower_session, &stop_authority));

    assert!(
        service
            .operation_capacity
            .wait_for_follower_registration(WAIT_LIMIT),
        "the duplicate stop must register before confirmation"
    );
    adapter.stop_release.signal();
    let first = leader
        .join()
        .expect("stop leader thread must not panic")
        .expect("stop leader must commit");
    let second = follower
        .join()
        .expect("stop follower thread must not panic")
        .expect("identical stop follower must replay");
    assert_eq!(first, second);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 1);

    adapter.execute_release.signal();
    service
        .runtime
        .wait_for_background()
        .expect("finish execution");
}

#[test]
fn completed_stop_replays_its_exact_original_response_while_capacity_is_occupied() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    let service = service(state.path(), adapter.clone());
    let run_authority = authority(&service, "principal-stop-replay", "stop-replay-run");
    let session = service
        .admit_run(&intent("stop replay source"), &run_authority)
        .expect("admit stop replay source");
    service
        .runtime
        .wait_for_background()
        .expect("finish source Turn");
    let stop_authority = authority(&service, "principal-stop-replay", "completed-stop");
    let original = service
        .admit_stop(session.session_id(), &stop_authority)
        .expect("commit original stop");

    let steer_authority = authority(&service, "principal-stop-replay", "later-steer");
    let later = service
        .admit_steer(
            session.session_id(),
            &intent("advance Session revision"),
            &steer_authority,
        )
        .expect("admit later Turn");
    assert!(
        later.session_state_revision().get() > original.session_state_revision().get(),
        "the later Turn must advance the Session beyond the stored stop response"
    );
    service
        .runtime
        .wait_for_background()
        .expect("finish later Turn");

    adapter.block_next_preflight();
    let occupant_authority = authority(&service, "principal-stop-occupant", "stop-occupant");
    let occupant_service = service.clone();
    let occupant = std::thread::spawn(move || {
        occupant_service.admit_run(&intent("occupy during stop replay"), &occupant_authority)
    });
    assert!(adapter.preflight_started.wait_for(WAIT_LIMIT));

    let replayed = service
        .admit_stop(session.session_id(), &stop_authority)
        .expect("completed stop replay must bypass occupied capacity");
    assert_eq!(original, replayed);

    adapter.preflight_release.signal();
    occupant
        .join()
        .expect("occupant thread must not panic")
        .expect("occupant admission must finish");
    service
        .runtime
        .wait_for_background()
        .expect("finish occupant");
}

#[test]
fn pending_stop_after_restart_reacquires_capacity() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let first_adapter = ControlledAdapter::default();
    first_adapter.block_execution.store(true, Ordering::SeqCst);
    first_adapter.fail_next_stop.store(true, Ordering::SeqCst);
    let first_service = service(state.path(), first_adapter.clone());
    let run_authority = authority(&first_service, "principal-pending", "pending-run");
    let session = first_service
        .admit_run(&intent("pending stop source"), &run_authority)
        .expect("admit pending stop source");
    assert!(first_adapter.execute_started.wait_for(WAIT_LIMIT));
    let stop_authority = authority(&first_service, "principal-pending-stop", "pending-stop");
    let error = first_service
        .admit_stop(session.session_id(), &stop_authority)
        .expect_err("the first stop observation must leave a pending record");
    assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
    first_adapter.execute_release.signal();
    first_service
        .runtime
        .wait_for_background()
        .expect("source execution must finish before restart");
    drop(first_service);

    let restarted_adapter = ControlledAdapter::default();
    restarted_adapter.block_next_preflight();
    let restarted = service(state.path(), restarted_adapter.clone());
    let occupant_authority = authority(&restarted, "principal-after-restart", "restart-occupant");
    let occupant_service = restarted.clone();
    let occupant = std::thread::spawn(move || {
        occupant_service.admit_run(&intent("restart capacity occupant"), &occupant_authority)
    });
    assert!(restarted_adapter.preflight_started.wait_for(WAIT_LIMIT));

    let error = restarted
        .admit_stop(session.session_id(), &stop_authority)
        .expect_err("a pending stop must reacquire rather than bypass capacity");
    assert_capacity_exceeded(&error);

    restarted_adapter.preflight_release.signal();
    occupant
        .join()
        .expect("restart occupant thread must not panic")
        .expect("restart occupant must finish admission");
    restarted
        .runtime
        .wait_for_background()
        .expect("restart occupant execution must finish");
    let stopped = restarted
        .admit_stop(session.session_id(), &stop_authority)
        .expect("pending stop retry must finalize after reacquiring capacity");
    assert!(stopped.result().current_state().is_terminal());
    assert_eq!(restarted_adapter.stop_calls.load(Ordering::SeqCst), 0);
}

#[derive(Clone, Copy)]
enum StaleProbeExpectation {
    Replay,
    Conflict,
}

struct StaleProbeScenario {
    response: Result<PublicSession, SatelleError>,
    expected: PublicSession,
    probe_count: usize,
}

fn stale_probe_after_handoff(expectation: StaleProbeExpectation) -> StaleProbeScenario {
    let expected = coordinator_result_session();
    let capacity = Arc::new(OperationCapacity::default());
    let durable = Arc::new(AtomicBool::new(false));

    let leader_started = Latch::default();
    let release_leader = Latch::default();
    let leader_capacity = Arc::clone(&capacity);
    let leader_durable = Arc::clone(&durable);
    let leader_expected = expected.clone();
    let leader_started_signal = leader_started.clone();
    let release_leader_wait = release_leader.clone();
    let leader = std::thread::spawn(move || {
        leader_capacity
            .execute(
                operation_request("principal-a", "key-a", DIGEST_A),
                || Ok(None),
                || {
                    leader_started_signal.signal();
                    release_leader_wait.wait();
                    leader_durable.store(true, Ordering::SeqCst);
                    Ok(OperationOutcome::Session(leader_expected))
                },
            )
            .and_then(OperationOutcome::into_session)
    });
    assert!(
        leader_started.wait_for(WAIT_LIMIT),
        "leader A must occupy the coordinator before the stale probe"
    );

    let first_probe_started = Latch::default();
    let release_first_probe = Latch::default();
    let probe_count = Arc::new(AtomicUsize::new(0));
    let duplicate_capacity = Arc::clone(&capacity);
    let duplicate_durable = Arc::clone(&durable);
    let duplicate_expected = expected.clone();
    let duplicate_probe_count = Arc::clone(&probe_count);
    let first_probe_started_signal = first_probe_started.clone();
    let release_first_probe_wait = release_first_probe.clone();
    let duplicate_digest = match expectation {
        StaleProbeExpectation::Replay => DIGEST_A,
        StaleProbeExpectation::Conflict => DIGEST_CONFLICT,
    };
    let duplicate = std::thread::spawn(move || {
        duplicate_capacity
            .execute(
                operation_request("principal-a", "key-a", duplicate_digest),
                || {
                    let probe = duplicate_probe_count.fetch_add(1, Ordering::SeqCst);
                    if probe == 0 {
                        assert!(!duplicate_durable.load(Ordering::SeqCst));
                        first_probe_started_signal.signal();
                        release_first_probe_wait.wait();
                        return Ok(None);
                    }
                    assert!(duplicate_durable.load(Ordering::SeqCst));
                    match expectation {
                        StaleProbeExpectation::Replay => {
                            Ok(Some(OperationOutcome::Session(duplicate_expected.clone())))
                        }
                        StaleProbeExpectation::Conflict => {
                            Err(crate::runtime::idempotency_conflict())
                        }
                    }
                },
                || panic!("a stale probe must recheck durable state instead of becoming a leader"),
            )
            .and_then(OperationOutcome::into_session)
    });
    assert!(
        first_probe_started.wait_for(WAIT_LIMIT),
        "duplicate A's first durable probe must miss while leader A is active"
    );

    release_leader.signal();
    let leader_response = leader
        .join()
        .expect("leader A thread must not panic")
        .expect("leader A must commit before B installs");

    let occupant_started = Latch::default();
    let release_occupant = Latch::default();
    let occupant_capacity = Arc::clone(&capacity);
    let occupant_expected = expected.clone();
    let occupant_started_signal = occupant_started.clone();
    let release_occupant_wait = release_occupant.clone();
    let occupant = std::thread::spawn(move || {
        occupant_capacity
            .execute(
                operation_request("principal-b", "key-b", DIGEST_B),
                || Ok(None),
                || {
                    occupant_started_signal.signal();
                    release_occupant_wait.wait();
                    Ok(OperationOutcome::Session(occupant_expected))
                },
            )
            .and_then(OperationOutcome::into_session)
    });
    assert!(
        occupant_started.wait_for(WAIT_LIMIT),
        "unrelated B must install after leader A clears"
    );

    release_first_probe.signal();
    let response = duplicate.join().expect("duplicate A thread must not panic");
    release_occupant.signal();
    let occupant_response = occupant
        .join()
        .expect("occupant B thread must not panic")
        .expect("occupant B must finish after the stale probe revalidates");

    assert_eq!(leader_response, expected);
    assert_eq!(occupant_response, expected);
    StaleProbeScenario {
        response,
        expected,
        probe_count: probe_count.load(Ordering::SeqCst),
    }
}

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DIGEST_CONFLICT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn operation_request(principal: &str, key: &str, digest: &str) -> OperationRequest {
    let identity = RequestIdentity::authenticated(principal, key, digest, 1, 1);
    OperationRequest::new(IdempotentOperation::Run, &identity)
}

fn coordinator_result_session() -> PublicSession {
    let state = crate::TestStateDir::new().expect("temporary coordinator state directory");
    let service = service(state.path(), ControlledAdapter::default());
    let request_authority = authority(&service, "principal-result", "coordinator-result");
    let session = service
        .admit_run(&intent("coordinator result"), &request_authority)
        .expect("admit coordinator result Session");
    service
        .runtime
        .wait_for_background()
        .expect("finish coordinator result execution");
    session
}

fn service(state_root: &Path, adapter: ControlledAdapter) -> HostService {
    HostService {
        runtime: RuntimeHandle::new(Ok(state_root.to_path_buf()), adapter),
        mode: HostMode::TestFake,
        operation_capacity: Arc::new(OperationCapacity::default()),
    }
}

fn authority(service: &HostService, principal: &str, key: &str) -> MutationAuthority {
    let token = ApiBearerToken::generate().expect("generate API token");
    let principal = service
        .register_api_token(&token, principal, ApiScopes::CONTROL, None)
        .expect("register API principal");
    MutationAuthority::new(principal, key).expect("construct mutation authority")
}

fn intent(prompt: &str) -> TurnIntent {
    TurnIntent::new(prompt, TurnExecutionMode::Standard).expect("construct Turn intent")
}

fn assert_capacity_exceeded(error: &SatelleError) {
    assert_eq!(error.code, ErrorCode::CapacityExceeded);
    assert_eq!(
        error.details.get("resource"),
        Some(&serde_json::json!("operation-concurrency"))
    );
    assert_eq!(error.details.get("limit"), Some(&serde_json::json!(1)));
}

fn assert_same_error(left: &SatelleError, right: &SatelleError) {
    assert_eq!(left.code, right.code);
    assert_eq!(left.message, right.message);
    assert_eq!(left.recovery_command, right.recovery_command);
    assert_eq!(left.source_detail, right.source_detail);
    assert_eq!(left.details, right.details);
}

fn assert_same_session_and_turn_handles(
    left: &satelle_core::session::PublicSession,
    right: &satelle_core::session::PublicSession,
) {
    assert_eq!(left.session_id(), right.session_id());
    assert_eq!(left.turns().len(), right.turns().len());
    for (left_turn, right_turn) in left.turns().iter().zip(right.turns()) {
        assert_eq!(left_turn.turn_id(), right_turn.turn_id());
    }
}

#[derive(Clone, Default)]
struct ControlledAdapter {
    block_preflight: Arc<AtomicBool>,
    fail_next_preflight: Arc<AtomicBool>,
    preflight_calls: Arc<AtomicUsize>,
    preflight_started: Latch,
    preflight_release: Latch,
    block_execution: Arc<AtomicBool>,
    execute_started: Latch,
    execute_release: Latch,
    execute_calls: Arc<AtomicUsize>,
    block_stop: Arc<AtomicBool>,
    fail_next_stop: Arc<AtomicBool>,
    stop_started: Latch,
    stop_release: Latch,
    stop_calls: Arc<AtomicUsize>,
}

impl ControlledAdapter {
    fn block_next_preflight(&self) {
        self.block_preflight.store(true, Ordering::SeqCst);
    }
}

impl ComputerUseAdapter for ControlledAdapter {
    fn preflight(&self, host: &str) -> Result<AdapterReadiness, SatelleError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        if self.block_preflight.swap(false, Ordering::SeqCst) {
            self.preflight_started.signal();
            self.preflight_release.wait();
        }
        if self.fail_next_preflight.swap(false, Ordering::SeqCst) {
            return Err(SatelleError::computer_use_not_ready());
        }
        FakeComputerUseAdapter.preflight(host)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.execute_calls.fetch_add(1, Ordering::SeqCst);
        if self.block_execution.load(Ordering::SeqCst) {
            self.execute_started.signal();
            self.execute_release.wait();
        }
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        self.stop_started.signal();
        if self.fail_next_stop.swap(false, Ordering::SeqCst) {
            return Err(SatelleError::computer_use_not_ready());
        }
        if self.block_stop.load(Ordering::SeqCst) {
            self.stop_release.wait();
        }
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Default)]
struct Latch {
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl Latch {
    fn signal(&self) {
        let (lock, changed) = &*self.state;
        let mut signaled = lock.lock().expect("test latch lock must not be poisoned");
        *signaled = true;
        changed.notify_all();
    }

    fn wait(&self) {
        let (lock, changed) = &*self.state;
        let signaled = lock.lock().expect("test latch lock must not be poisoned");
        let _signaled = changed
            .wait_while(signaled, |signaled| !*signaled)
            .expect("test latch lock must not be poisoned");
    }

    fn wait_for(&self, timeout: Duration) -> bool {
        let (lock, changed) = &*self.state;
        let signaled = lock.lock().expect("test latch lock must not be poisoned");
        let (signaled, _) = changed
            .wait_timeout_while(signaled, timeout, |signaled| !*signaled)
            .expect("test latch lock must not be poisoned");
        *signaled
    }
}
