use crate::operation_capacity::{OperationCapacity, OperationOutcome, OperationRequest};
use crate::runtime::{
    AdapterReadiness, AdapterSubject, AdmissionCancellation, ComputerUseAdapter, ExecuteRequest,
    ExecuteResult, RecoveryObservation, RequestIdentity, RuntimeHandle,
};
use crate::storage::IdempotentOperation;
use crate::test_runtime::FakeComputerUseAdapter;
use crate::{ApiBearerToken, ApiScopes, HostMode, HostService, MutationAuthority, TurnIntent};
use satelle_core::session::{PublicSession, StopObservation, TurnExecutionMode};
use satelle_core::{ControlPlaneOperation, ErrorCode, SatelleError, SessionId, TurnId};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

const WAIT_LIMIT: Duration = Duration::from_secs(2);

#[test]
fn cancellation_registered_before_run_uses_the_same_gate_and_prevents_admission() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = service(state.path(), ControlledAdapter::default());
    let mutation = authority(&service, "interrupt-principal", "cancel-first-run");
    assert!(matches!(
        service
            .cancel_run_admission(&intent("cancel before run registration"), &mutation,)
            .expect("cancellation must return without waiting for admission"),
        crate::AdmissionCancellationResult::Cancelled
    ));
    assert!(
        service
            .operation_capacity
            .activity_snapshot()
            .expect("capacity remains readable")
            .0,
        "cancellation-first registration must not occupy mutation capacity"
    );

    let admission_error = service
        .admit_run(&intent("cancel before run registration"), &mutation)
        .expect_err("the registered cancellation must prevent durable admission");
    assert_eq!(admission_error.code, ErrorCode::Interrupted);
    assert_eq!(
        service
            .daemon_runtime_status()
            .expect("runtime status remains available")
            .session_count(),
        0
    );
}

#[test]
fn durable_cancellations_survive_pressure_restart_and_digest_conflicts() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let host = service(state.path(), ControlledAdapter::default());
    let principal = "durable-cancellation-principal";
    let token = ApiBearerToken::generate().expect("generate API token");
    let principal = host
        .register_api_token(&token, principal, ApiScopes::CONTROL, None)
        .expect("register API principal");
    for index in 0..1_025 {
        let prompt = format!("durable cancellation {index}");
        let mutation = MutationAuthority::new(principal.clone(), format!("durable-cancel-{index}"))
            .expect("construct mutation authority");
        assert!(matches!(
            host.cancel_run_admission(&intent(&prompt), &mutation)
                .expect("persist cancellation tombstone"),
            crate::AdmissionCancellationResult::Cancelled
        ));
    }
    let original = MutationAuthority::new(principal, "durable-cancel-0")
        .expect("construct original mutation authority");
    let conflict = host
        .admit_run(&intent("different durable cancellation digest"), &original)
        .expect_err("same base key with a different digest must conflict");
    assert_eq!(conflict.code, ErrorCode::IdempotencyKeyConflict);
    drop(host);

    let restarted = service(state.path(), ControlledAdapter::default());
    let delayed = restarted
        .admit_run(&intent("durable cancellation 0"), &original)
        .expect_err("oldest unexpired cancellation must survive pressure and restart");
    assert_eq!(delayed.code, ErrorCode::Interrupted);
}

#[test]
fn cancellation_registered_before_steer_prevents_follow_up_admission() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = service(state.path(), ControlledAdapter::default());
    let seed_authority = authority(&service, "interrupt-principal", "cancel-first-steer-seed");
    let session = service
        .admit_run(&intent("seed cancellation-first steer"), &seed_authority)
        .expect("seed Session");
    service
        .runtime
        .wait_for_background()
        .expect("seed Turn completes");
    let initial_turn_count = session.turns().len();

    let mutation = authority(&service, "interrupt-principal", "cancel-first-steer");
    assert!(matches!(
        service
            .cancel_steer_admission(
                session.session_id(),
                &intent("cancel before steer registration"),
                &mutation,
            )
            .expect("cancellation must return without waiting for admission"),
        crate::AdmissionCancellationResult::Cancelled
    ));
    assert!(
        service
            .operation_capacity
            .activity_snapshot()
            .expect("capacity remains readable")
            .0,
        "steer cancellation-first registration must not occupy mutation capacity"
    );

    let admission_error = service
        .admit_steer(
            session.session_id(),
            &intent("cancel before steer registration"),
            &mutation,
        )
        .expect_err("the registered cancellation must prevent follow-up admission");
    assert_eq!(admission_error.code, ErrorCode::Interrupted);
    assert_eq!(
        service
            .runtime
            .status(session.session_id().clone())
            .expect("seed Session remains readable")
            .turns()
            .len(),
        initial_turn_count
    );
}

#[test]
fn expected_turn_stop_never_retargets_a_newer_active_turn() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    let service = service(state.path(), adapter.clone());
    let seed = service
        .admit_run(
            &intent("seed expected-Turn stop"),
            &authority(&service, "expected-turn-principal", "expected-turn-seed"),
        )
        .expect("seed Session");
    let old_turn_id = seed
        .turns()
        .last()
        .expect("seed Session has a Turn")
        .turn_id()
        .clone();
    service
        .runtime
        .wait_for_background()
        .expect("seed Turn completes");

    adapter.block_execution.store(true, Ordering::SeqCst);
    let steered = service
        .admit_steer(
            seed.session_id(),
            &intent("new active Turn"),
            &authority(&service, "expected-turn-principal-2", "expected-turn-steer"),
        )
        .expect("admit newer Turn");
    let new_turn_id = steered
        .turns()
        .last()
        .expect("steered Session has a Turn")
        .turn_id()
        .clone();
    assert!(adapter.execute_started.wait_for(WAIT_LIMIT));

    let error = service
        .stop_expected_turn(seed.session_id(), &old_turn_id)
        .expect_err("stale expected Turn must not retarget");
    assert_eq!(error.code, ErrorCode::StateConflict);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 0);
    let current = service
        .session_status(seed.session_id())
        .expect("read current Session");
    assert!(
        !current
            .turns()
            .iter()
            .find(|turn| turn.turn_id() == &new_turn_id)
            .expect("new Turn remains present")
            .state()
            .is_terminal()
    );
    adapter.execute_release.signal();
    service
        .runtime
        .wait_for_background()
        .expect("new Turn completes");
}

#[test]
fn cancellation_registered_during_preflight_prevents_durable_turn_admission() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let mutation = authority(&service, "interrupt-principal", "interrupt-run");
    let leader_service = service.clone();
    let leader_authority = mutation.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(&intent("cancel before admission"), &leader_authority)
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "the readiness preflight must be active before cancellation"
    );

    let cancellation_service = service.clone();
    let cancellation = std::thread::spawn(move || {
        cancellation_service.cancel_run_admission(&intent("cancel before admission"), &mutation)
    });
    assert!(
        service
            .operation_capacity
            .wait_for_cancellation_request(WAIT_LIMIT),
        "cancellation must request the matching admission before preflight resumes"
    );

    adapter.preflight_release.signal();
    let admission_error = leader
        .join()
        .expect("admission thread must not panic")
        .expect_err("cancellation must win before durable admission");
    assert_eq!(admission_error.code, ErrorCode::Interrupted);
    match cancellation
        .join()
        .expect("cancellation thread must not panic")
        .expect("cancellation must return a typed outcome")
    {
        crate::AdmissionCancellationResult::Cancelled => {}
        crate::AdmissionCancellationResult::RecoveryPending => {
            panic!("pre-dispatch cancellation must not retain recovery ownership")
        }
        crate::AdmissionCancellationResult::Admitted { .. } => {
            panic!("the commit gate must prevent admission")
        }
    }
    assert_eq!(
        service
            .daemon_runtime_status()
            .expect("runtime status remains available")
            .session_count(),
        0
    );
}

#[test]
fn active_cancellation_requests_before_slow_tombstone_persistence() {
    let capacity = Arc::new(OperationCapacity::default());
    let request = operation_request("principal-a", "slow-active-persistence", DIGEST_A);
    let operation_started = Latch::default();
    let operation_release = Latch::default();
    let persistence_started = Latch::default();
    let persistence_release = Latch::default();
    let expected = admission_outcome(coordinator_result_session());

    let operation_capacity = Arc::clone(&capacity);
    let operation_request = request.clone();
    let started_signal = operation_started.clone();
    let operation_release_wait = operation_release.clone();
    let operation_expected = expected.clone();
    let operation = std::thread::spawn(move || {
        operation_capacity.execute_interruptible_durable(
            operation_request,
            AdmissionCancellation::new(),
            || Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
            |outcome| match outcome {
                crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => {
                    Ok(crate::operation_capacity::DurableAdmissionOutcome::Cancelled)
                }
                crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => {
                    Ok(crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending)
                }
                _ => Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
            },
            |cancellation| {
                started_signal.signal();
                operation_release_wait.wait();
                cancellation
                    .with_commit_gate(SessionId::new(), TurnId::new(), || Ok(operation_expected))
            },
        )
    });
    assert!(operation_started.wait_for(WAIT_LIMIT));

    let cancellation_capacity = Arc::clone(&capacity);
    let persistence_started_signal = persistence_started.clone();
    let persistence_release_wait = persistence_release.clone();
    let cancellation = std::thread::spawn(move || {
        let mut persistence_call = 0_u8;
        cancellation_capacity.cancel_durable(
            request,
            || Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
            |outcome| {
                persistence_call += 1;
                if persistence_call == 1 {
                    assert!(matches!(
                        outcome,
                        crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending
                    ));
                    persistence_started_signal.signal();
                    persistence_release_wait.wait();
                }
                Ok(match outcome {
                    crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => {
                        crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending
                    }
                    crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
                    | crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => {
                        crate::operation_capacity::DurableAdmissionOutcome::Cancelled
                    }
                    crate::operation_capacity::AdmissionCancellationOutcome::Admitted { .. } => {
                        unreachable!("the persistence seam receives only cancellation outcomes")
                    }
                })
            },
        )
    });
    assert!(
        persistence_started.wait_for(WAIT_LIMIT),
        "durable persistence must remain blocked after the token is requested"
    );
    assert!(
        capacity.wait_for_cancellation_request(WAIT_LIMIT),
        "the exact active token must be requested before persistence"
    );

    operation_release.signal();
    let operation_error = match operation.join().expect("operation thread must not panic") {
        Ok(_) => panic!("the commit gate must reject the cancelled admission"),
        Err(error) => error,
    };
    assert_eq!(operation_error.code, ErrorCode::Interrupted);
    persistence_release.signal();
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("cancellation must finish after persistence resumes"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));
}

#[test]
fn local_precommit_failure_racing_with_cancellation_is_reconciled_cancelled() {
    let capacity = Arc::new(OperationCapacity::default());
    let request = operation_request("principal-a", "precommit-storage-failure", DIGEST_A);
    let storage_write_started = Latch::default();
    let storage_write_release = Latch::default();

    let operation_capacity = Arc::clone(&capacity);
    let operation_request = request.clone();
    let storage_write_started_signal = storage_write_started.clone();
    let storage_write_release_wait = storage_write_release.clone();
    let operation = std::thread::spawn(move || {
        let wait_capacity = Arc::clone(&operation_capacity);
        operation_capacity.execute_interruptible_durable(
            operation_request,
            AdmissionCancellation::new(),
            || Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
            |outcome| {
                Ok(match outcome {
                    crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => {
                        crate::operation_capacity::DurableAdmissionOutcome::Cancelled
                    }
                    crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => {
                        crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending
                    }
                    _ => crate::operation_capacity::DurableAdmissionOutcome::Missing,
                })
            },
            |cancellation| {
                let result = cancellation.with_commit_gate(
                    SessionId::new(),
                    TurnId::new(),
                    || {
                        storage_write_started_signal.signal();
                        storage_write_release_wait.wait();
                        Err(crate::runtime::integrity_error(
                            "synthetic precommit storage failure",
                        ))
                    },
                );
                assert!(
                    wait_capacity.wait_for_cancellation_request(WAIT_LIMIT),
                    "cancellation must become Requested after the failing commit gate unlocks"
                );
                result
            },
        )
    });
    assert!(
        storage_write_started.wait_for(WAIT_LIMIT),
        "the synthetic storage write must hold the commit gate"
    );

    let cancellation_capacity = Arc::clone(&capacity);
    let cancellation = std::thread::spawn(move || {
        cancellation_capacity.cancel_durable(
            request,
            || Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
            |outcome| {
                Ok(match outcome {
                    crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => {
                        crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending
                    }
                    crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
                    | crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => {
                        crate::operation_capacity::DurableAdmissionOutcome::Cancelled
                    }
                    crate::operation_capacity::AdmissionCancellationOutcome::Admitted { .. } => {
                        unreachable!("the persistence seam receives only cancellation outcomes")
                    }
                })
            },
        )
    });
    storage_write_release.signal();
    assert!(
        operation
            .join()
            .expect("operation thread must not panic")
            .is_err(),
        "the synthetic precommit storage failure must remain the admission result"
    );
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("known local failure must reconcile cancellation"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));
    capacity
        .execute_exclusive(|| Ok(()))
        .expect("known local failure must release Host mutation capacity");
}

#[test]
fn completion_linearizes_before_a_cloned_late_cancellation_request() {
    #[derive(Clone, Copy)]
    enum Completion {
        KnownPrecommitFailure,
        PossibleDispatch,
        Admitted,
    }

    for completion in [
        Completion::KnownPrecommitFailure,
        Completion::PossibleDispatch,
        Completion::Admitted,
    ] {
        let capacity = Arc::new(OperationCapacity::default());
        let request = operation_request(
            "principal-completion-race",
            match completion {
                Completion::KnownPrecommitFailure => "completion-known-failure",
                Completion::PossibleDispatch => "completion-possible-dispatch",
                Completion::Admitted => "completion-admitted",
            },
            DIGEST_A,
        );
        let operation_started = Latch::default();
        let operation_release = Latch::default();
        let durable_state = Arc::new(AtomicUsize::new(0));
        let admitted_session = coordinator_result_session();
        let admitted_turn_id = admitted_session.turns()[0].turn_id().clone();

        capacity.pause_next_cancellation_before_request();
        let operation_capacity = Arc::clone(&capacity);
        let operation_request = request.clone();
        let operation_started_signal = operation_started.clone();
        let operation_release_wait = operation_release.clone();
        let operation_durable_state = Arc::clone(&durable_state);
        let operation_session = admitted_session.clone();
        let operation_turn_id = admitted_turn_id.clone();
        let operation = std::thread::spawn(move || {
            operation_capacity.execute_interruptible_durable(
                operation_request,
                AdmissionCancellation::new(),
                || match operation_durable_state.load(Ordering::SeqCst) {
                    0 => Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
                    1 => Ok(crate::operation_capacity::DurableAdmissionOutcome::Cancelled),
                    2 => Ok(crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending),
                    _ => unreachable!("the synthetic durable state is closed"),
                },
                |outcome| {
                    let state = match outcome {
                        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
                        | crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => 1,
                        crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => 2,
                        crate::operation_capacity::AdmissionCancellationOutcome::Admitted { .. } => {
                            unreachable!("the persistence seam receives only cancellation outcomes")
                        }
                    };
                    operation_durable_state.store(state, Ordering::SeqCst);
                    Ok(match state {
                        1 => crate::operation_capacity::DurableAdmissionOutcome::Cancelled,
                        2 => crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending,
                        _ => unreachable!("the synthetic durable state is closed"),
                    })
                },
                |cancellation| {
                    operation_started_signal.signal();
                    operation_release_wait.wait();
                    match completion {
                        Completion::KnownPrecommitFailure => Err(crate::runtime::integrity_error(
                            "synthetic known precommit failure",
                        )),
                        Completion::PossibleDispatch => {
                            cancellation.finish(
                                crate::runtime::AdmissionCancellationState::RecoveryPending,
                            );
                            Err(crate::runtime::integrity_error(
                                "synthetic possible dispatch failure",
                            ))
                        }
                        Completion::Admitted => {
                            cancellation.with_commit_gate(
                                operation_session.session_id().clone(),
                                operation_turn_id.clone(),
                                || Ok(()),
                            )?;
                            Ok(OperationOutcome::admission(
                                operation_session,
                                operation_turn_id,
                            ))
                        }
                    }
                },
            )
        });
        assert!(operation_started.wait_for(WAIT_LIMIT));

        let cancellation_capacity = Arc::clone(&capacity);
        let cancellation_request = request.clone();
        let cancellation_durable_state = Arc::clone(&durable_state);
        let cancellation = std::thread::spawn(move || {
            cancellation_capacity.cancel_durable(
                cancellation_request,
                || match cancellation_durable_state.load(Ordering::SeqCst) {
                    0 => Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
                    1 => Ok(crate::operation_capacity::DurableAdmissionOutcome::Cancelled),
                    2 => Ok(crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending),
                    _ => unreachable!("the synthetic durable state is closed"),
                },
                |outcome| {
                    let state = match outcome {
                        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
                        | crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => 1,
                        crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => 2,
                        crate::operation_capacity::AdmissionCancellationOutcome::Admitted { .. } => {
                            unreachable!("the persistence seam receives only cancellation outcomes")
                        }
                    };
                    cancellation_durable_state.store(state, Ordering::SeqCst);
                    Ok(match state {
                        1 => crate::operation_capacity::DurableAdmissionOutcome::Cancelled,
                        2 => crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending,
                        _ => unreachable!("the synthetic durable state is closed"),
                    })
                },
            )
        });
        assert!(
            capacity.wait_for_cancellation_before_request(WAIT_LIMIT),
            "the canceller must clone the active entry before completion"
        );

        operation_release.signal();
        let operation_result = operation.join().expect("operation thread must not panic");
        capacity.release_cancellation_before_request();
        let cancellation_result = cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("late cancellation must resolve deterministically");

        match completion {
            Completion::KnownPrecommitFailure => {
                assert!(operation_result.is_err());
                assert!(matches!(
                    cancellation_result,
                    crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
                ));
                assert_eq!(durable_state.load(Ordering::SeqCst), 1);
            }
            Completion::PossibleDispatch => {
                assert!(operation_result.is_err());
                assert!(matches!(
                    cancellation_result,
                    crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending
                ));
                assert_eq!(durable_state.load(Ordering::SeqCst), 2);
            }
            Completion::Admitted => {
                operation_result.expect("the synthetic admission completes");
                match cancellation_result {
                    crate::operation_capacity::AdmissionCancellationOutcome::Admitted {
                        session,
                        turn_id,
                    } => {
                        assert_eq!(session.session_id(), admitted_session.session_id());
                        assert_eq!(turn_id, admitted_turn_id);
                    }
                    _ => panic!("the completed admission must win late cancellation"),
                }
                assert_eq!(durable_state.load(Ordering::SeqCst), 0);
            }
        }
    }
}

#[test]
fn adapter_admission_rejection_racing_with_cancellation_releases_capacity() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_admission_rejection();
    let service = service(state.path(), adapter.clone());
    let mutation = authority(&service, "rejected-principal", "rejected-admission");

    let admission_service = service.clone();
    let admission_authority = mutation.clone();
    let admission = std::thread::spawn(move || {
        admission_service.admit_run(
            &intent("adapter rejects before dispatch"),
            &admission_authority,
        )
    });
    assert!(adapter.admission_started.wait_for(WAIT_LIMIT));

    let cancellation_service = service.clone();
    let cancellation = std::thread::spawn(move || {
        cancellation_service
            .cancel_run_admission(&intent("adapter rejects before dispatch"), &mutation)
    });
    assert!(
        service
            .operation_capacity
            .wait_for_cancellation_request(WAIT_LIMIT)
    );
    adapter.admission_release.signal();

    assert_eq!(
        admission
            .join()
            .expect("admission thread must not panic")
            .expect_err("adapter admission rejection must fail locally")
            .code,
        ErrorCode::ComputerUseNotReady
    );
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("local rejection must reconcile cancellation"),
        crate::AdmissionCancellationResult::Cancelled
    ));
    assert!(
        service
            .operation_capacity
            .activity_snapshot()
            .expect("capacity remains readable")
            .0
    );
    let lease_count: i64 = rusqlite::Connection::open(state.path().join("satelle.sqlite3"))
        .expect("open authoritative store for lease inspection")
        .query_row("SELECT count(*) FROM control_leases", [], |row| row.get(0))
        .expect("count retained leases");
    assert_eq!(
        lease_count, 0,
        "pre-dispatch rejection must retain no lease"
    );
}

#[test]
fn unresolved_operation_cancellation_is_recovery_pending_not_confirmed_cancelled() {
    let capacity = Arc::new(OperationCapacity::default());
    let operation_started = Latch::default();
    let operation_release = Latch::default();
    let operation_capacity = Arc::clone(&capacity);
    let started_signal = operation_started.clone();
    let release_wait = operation_release.clone();
    let operation = std::thread::spawn(move || {
        operation_capacity.execute_interruptible(
            operation_request("principal-a", "ambiguous-cancel", DIGEST_A),
            AdmissionCancellation::new(),
            || Ok(None),
            |cancellation| {
                started_signal.signal();
                release_wait.wait();
                assert!(cancellation.is_requested());
                cancellation.finish(crate::runtime::AdmissionCancellationState::RecoveryPending);
                Err(crate::runtime::integrity_error(
                    "the interrupted operation ended without a terminal cancellation observation",
                ))
            },
        )
    });
    assert!(
        operation_started.wait_for(WAIT_LIMIT),
        "the operation must be active before cancellation"
    );

    let cancellation_capacity = Arc::clone(&capacity);
    let cancellation = std::thread::spawn(move || {
        cancellation_capacity.cancel(
            operation_request("principal-a", "ambiguous-cancel", DIGEST_A),
            || Ok(None),
        )
    });
    assert!(
        capacity.wait_for_cancellation_request(WAIT_LIMIT),
        "cancellation must request the active operation before it terminates"
    );
    operation_release.signal();
    if operation
        .join()
        .expect("operation thread must not panic")
        .is_ok()
    {
        panic!("the synthetic operation must remain ambiguous");
    }
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("ambiguous cancellation returns a typed outcome"),
        crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending
    ));
    assert!(matches!(
        capacity
            .cancel(
                operation_request("principal-a", "ambiguous-cancel", DIGEST_A),
                || Ok(None),
            )
            .expect("the terminal cancellation outcome must replay"),
        crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending
    ));
    capacity
        .execute_exclusive(|| Ok(()))
        .expect("recovery-pending replay must not retain mutation capacity");
}

#[test]
fn cancellation_without_admission_returns_and_reclaims_capacity() {
    let capacity = OperationCapacity::default();
    let request = operation_request("principal-a", "never-admitted", DIGEST_A);

    assert!(matches!(
        capacity
            .cancel(request.clone(), || Ok(None))
            .expect("cancellation-first registration returns immediately"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));
    assert!(
        capacity
            .activity_snapshot()
            .expect("capacity remains readable")
            .0
    );
    capacity
        .execute_exclusive(|| Ok(()))
        .expect("cancellation-first registration must not retain mutation capacity");
    assert!(matches!(
        capacity
            .cancel(request.clone(), || Ok(None))
            .expect("an exact repeated cancellation replays"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));

    let invoked = AtomicBool::new(false);
    let error = match capacity.execute_interruptible(
        request,
        AdmissionCancellation::new(),
        || Ok(None),
        |_| {
            invoked.store(true, Ordering::SeqCst);
            Ok(admission_outcome(coordinator_result_session()))
        },
    ) {
        Ok(_) => panic!("the late admission must remain cancelled"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::Interrupted);
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn admission_failure_before_cancellation_registration_cannot_escape_cancellation() {
    let capacity = Arc::new(OperationCapacity::default());
    let replay_started = Latch::default();
    let replay_release = Latch::default();
    let cancellation_capacity = Arc::clone(&capacity);
    let replay_started_signal = replay_started.clone();
    let replay_release_wait = replay_release.clone();
    let cancellation = std::thread::spawn(move || {
        cancellation_capacity.cancel(
            operation_request("principal-a", "failed-before-register", DIGEST_A),
            || {
                replay_started_signal.signal();
                replay_release_wait.wait();
                Ok(None)
            },
        )
    });
    assert!(
        replay_started.wait_for(WAIT_LIMIT),
        "cancellation must finish its initial capacity probe"
    );

    let failed = capacity.execute(
        operation_request("principal-a", "failed-before-register", DIGEST_A),
        || Ok(None),
        || {
            Err(crate::runtime::integrity_error(
                "synthetic immediate admission failure",
            ))
        },
    );
    assert!(failed.is_err());
    replay_release.signal();
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("cancellation must linearize after the failed admission"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));

    let late = capacity.execute(
        operation_request("principal-a", "failed-before-register", DIGEST_A),
        || Ok(None),
        || Ok(admission_outcome(coordinator_result_session())),
    );
    let error = match late {
        Ok(_) => panic!("the late exact admission must remain cancelled"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::Interrupted);
}

#[test]
fn cancellation_persistence_linearizes_with_late_active_install_and_upgrades_ambiguity() {
    let capacity = Arc::new(OperationCapacity::default());
    let request = operation_request("principal-a", "persist-install-race", DIGEST_A);
    let durable_state = Arc::new(AtomicUsize::new(0));
    let persistence_started = Latch::default();
    let admission_resolved_missing = Latch::default();
    let cancellation_persisted = Latch::default();
    let operation_started = Latch::default();
    let operation_release = Latch::default();

    let cancellation_capacity = Arc::clone(&capacity);
    let cancellation_request = request.clone();
    let cancellation_state = Arc::clone(&durable_state);
    let cancellation_persistence_started = persistence_started.clone();
    let cancellation_admission_resolved = admission_resolved_missing.clone();
    let cancellation_persisted_signal = cancellation_persisted.clone();
    let cancellation_operation_started = operation_started.clone();
    let cancellation = std::thread::spawn(move || {
        cancellation_capacity.cancel_durable(
            cancellation_request,
            || Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing),
            |outcome| match outcome {
                crate::operation_capacity::AdmissionCancellationOutcome::Cancelled => {
                    cancellation_persistence_started.signal();
                    cancellation_admission_resolved.wait();
                    cancellation_state.store(1, Ordering::SeqCst);
                    cancellation_persisted_signal.signal();
                    cancellation_operation_started.wait();
                    Ok(crate::operation_capacity::DurableAdmissionOutcome::Cancelled)
                }
                crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending => {
                    cancellation_state.store(2, Ordering::SeqCst);
                    Ok(crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending)
                }
                crate::operation_capacity::AdmissionCancellationOutcome::ReconciledCancelled => {
                    cancellation_state.store(1, Ordering::SeqCst);
                    Ok(crate::operation_capacity::DurableAdmissionOutcome::Cancelled)
                }
                crate::operation_capacity::AdmissionCancellationOutcome::Admitted { .. } => {
                    unreachable!("the synthetic persistence seam only receives cancellations")
                }
            },
        )
    });
    assert!(
        persistence_started.wait_for(WAIT_LIMIT),
        "cancellation must enter persistence before admission resolves"
    );

    let admission_capacity = Arc::clone(&capacity);
    let admission_state = Arc::clone(&durable_state);
    let admission_resolved_signal = admission_resolved_missing.clone();
    let admission_cancellation_persisted = cancellation_persisted.clone();
    let admission_operation_started = operation_started.clone();
    let admission_operation_release = operation_release.clone();
    let admission = std::thread::spawn(move || {
        admission_capacity.execute_interruptible_durable(
            request,
            AdmissionCancellation::new(),
            || {
                let observed = admission_state.load(Ordering::SeqCst);
                admission_resolved_signal.signal();
                admission_cancellation_persisted.wait();
                assert_eq!(
                    observed, 0,
                    "admission must have resolved Missing before cancellation persisted"
                );
                Ok(crate::operation_capacity::DurableAdmissionOutcome::Missing)
            },
            |_| {
                admission_state.store(2, Ordering::SeqCst);
                Ok(crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending)
            },
            |cancellation| {
                admission_operation_started.signal();
                admission_operation_release.wait();
                cancellation.finish(crate::runtime::AdmissionCancellationState::RecoveryPending);
                Err(crate::runtime::integrity_error(
                    "the possibly dispatched admission remained ambiguous",
                ))
            },
        )
    });

    assert!(
        operation_started.wait_for(WAIT_LIMIT),
        "the admission must install before cancellation rechecks capacity"
    );
    assert!(
        capacity.wait_for_cancellation_request(WAIT_LIMIT),
        "cancellation must find and signal the active admission after persistence"
    );
    operation_release.signal();
    assert!(
        admission
            .join()
            .expect("admission thread must not panic")
            .is_err(),
        "the synthetic active admission must remain ambiguous"
    );
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("cancellation returns a typed outcome"),
        crate::operation_capacity::AdmissionCancellationOutcome::RecoveryPending
    ));
    assert_eq!(
        durable_state.load(Ordering::SeqCst),
        2,
        "the cancellation-first tombstone must atomically upgrade to recovery_pending"
    );
}

#[test]
fn cancellation_ledger_matches_every_operation_identity_dimension() {
    let capacity = OperationCapacity::default();
    let original = operation_request("principal-a", "identity-key", DIGEST_A);
    assert!(matches!(
        capacity
            .cancel(original.clone(), || Ok(None))
            .expect("the original cancellation registers"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));
    assert!(matches!(
        capacity
            .cancel(original.clone(), || Ok(None))
            .expect("the exact cancellation replays"),
        crate::operation_capacity::AdmissionCancellationOutcome::Cancelled
    ));

    for request in [
        operation_request("principal-b", "identity-key", DIGEST_A),
        operation_request("principal-a", "different-key", DIGEST_A),
        operation_request_for(
            IdempotentOperation::Steer,
            "principal-a",
            "identity-key",
            DIGEST_A,
        ),
    ] {
        assert!(
            capacity
                .execute(
                    request,
                    || Ok(None),
                    || Ok(admission_outcome(coordinator_result_session())),
                )
                .is_ok(),
            "a principal, key, or operation mismatch must not consume the cancellation"
        );
    }

    let digest_conflict = capacity.cancel(
        operation_request("principal-a", "identity-key", DIGEST_CONFLICT),
        || Ok(None),
    );
    let error = match digest_conflict {
        Ok(_) => panic!("a changed digest on the same base must conflict"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::IdempotencyKeyConflict);
}

#[test]
fn admission_winning_late_cancellation_clears_the_provisional_recovery_record() {
    let capacity = Arc::new(OperationCapacity::default());
    let committed = Latch::default();
    let release = Latch::default();
    let admitted_session = coordinator_result_session();
    let session_id = admitted_session.session_id().clone();
    let turn_id = admitted_session.turns()[0].turn_id().clone();
    let operation_capacity = Arc::clone(&capacity);
    let operation_session = admitted_session.clone();
    let operation_turn_id = turn_id.clone();
    let committed_signal = committed.clone();
    let release_wait = release.clone();
    let operation = std::thread::spawn(move || {
        operation_capacity.execute_interruptible(
            operation_request("principal-a", "admission-wins", DIGEST_A),
            AdmissionCancellation::new(),
            || Ok(None),
            |cancellation| {
                cancellation
                    .with_commit_gate(session_id, operation_turn_id.clone(), || Ok(()))
                    .expect("the admission commit wins before cancellation");
                committed_signal.signal();
                release_wait.wait();
                Ok(OperationOutcome::admission(
                    operation_session,
                    operation_turn_id,
                ))
            },
        )
    });
    assert!(
        committed.wait_for(WAIT_LIMIT),
        "the admission must commit before cancellation"
    );

    let cancellation_capacity = Arc::clone(&capacity);
    let cancellation_session = admitted_session.clone();
    let cancellation_turn_id = turn_id.clone();
    let cancellation = std::thread::spawn(move || {
        cancellation_capacity.cancel(
            operation_request("principal-a", "admission-wins", DIGEST_A),
            || {
                Ok(Some(OperationOutcome::admission(
                    cancellation_session.clone(),
                    cancellation_turn_id.clone(),
                )))
            },
        )
    });
    assert!(
        capacity.wait_for_follower_registration(WAIT_LIMIT),
        "late cancellation must join the committed admission"
    );
    release.signal();
    operation
        .join()
        .expect("operation thread must not panic")
        .expect("the committed admission succeeds");
    match cancellation
        .join()
        .expect("cancellation thread must not panic")
        .expect("late cancellation returns an admitted outcome")
    {
        crate::operation_capacity::AdmissionCancellationOutcome::Admitted {
            session,
            turn_id: admitted_turn_id,
        } => {
            assert_eq!(session.session_id(), admitted_session.session_id());
            assert_eq!(admitted_turn_id, turn_id);
        }
        _ => panic!("the committed admission must win late cancellation"),
    }

    let replay_session = admitted_session.clone();
    let replay_turn_id = turn_id.clone();
    assert!(
        capacity
            .execute(
                operation_request("principal-a", "admission-wins", DIGEST_A),
                || {
                    Ok(Some(OperationOutcome::admission(
                        replay_session.clone(),
                        replay_turn_id.clone(),
                    )))
                },
                || panic!("the exact admission must replay"),
            )
            .is_ok(),
        "the provisional recovery record must not block exact admission replay"
    );
    assert!(matches!(
        capacity
            .cancel(
                operation_request("principal-a", "admission-wins", DIGEST_A),
                || {
                    Ok(Some(OperationOutcome::admission(
                        admitted_session.clone(),
                        turn_id.clone(),
                    )))
                },
            )
            .expect("repeated cancellation must use durable admitted replay"),
        crate::operation_capacity::AdmissionCancellationOutcome::Admitted { .. }
    ));
}

#[test]
fn cancellation_replay_returns_the_exact_original_turn_handle() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = service(state.path(), ControlledAdapter::default());
    let run_authority = authority(&service, "interrupt-principal", "original-run");
    let original = service
        .admit_run(&intent("original run"), &run_authority)
        .expect("the original run is admitted");
    let original_turn_id = original
        .turns()
        .last()
        .expect("the original run has one Turn")
        .turn_id()
        .clone();
    service
        .runtime
        .wait_for_background()
        .expect("the original run completes");

    let steer_authority = authority(&service, "interrupt-principal", "later-steer");
    let later = service
        .admit_steer(
            original.session_id(),
            &intent("later steer"),
            &steer_authority,
        )
        .expect("a later Turn is admitted");
    assert_ne!(
        later
            .turns()
            .last()
            .expect("the later Session has a target Turn")
            .turn_id(),
        &original_turn_id
    );

    let cancellation = service
        .cancel_run_admission(&intent("original run"), &run_authority)
        .expect("the durable run replay is available");
    match cancellation {
        crate::AdmissionCancellationResult::Admitted { session, turn_id } => {
            assert_eq!(session.session_id(), original.session_id());
            assert_eq!(turn_id, original_turn_id);
        }
        _ => panic!("the committed run must return an admitted cancellation result"),
    }
}

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
fn setup_token_issuance_shares_the_host_global_slot() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let authority = authority(&service, "principal-running", "running-operation");

    let operation_service = service.clone();
    let operation = std::thread::spawn(move || {
        operation_service.admit_run(&intent("occupy setup capacity"), &authority)
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "the run must occupy Host capacity before setup issuance"
    );

    let error = match service.issue_pending_api_token(
        ApiScopes::CONTROL,
        time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
    ) {
        Ok(_) => panic!("setup issuance must share the occupied Host-global slot"),
        Err(error) => error,
    };
    assert_capacity_exceeded(&error);

    adapter.preflight_release.signal();
    operation
        .join()
        .expect("run thread must not panic")
        .expect("run admission must finish");
    service
        .runtime
        .wait_for_background()
        .expect("run execution must finish");
}

#[test]
fn hmac_rotation_waits_for_active_admission_identity_cancellation() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let mutation = authority(&service, "rotation-principal", "rotation-active-run");
    let leader_service = service.clone();
    let leader_mutation = mutation.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(
            &intent("cancel active admission before HMAC rotation"),
            &leader_mutation,
        )
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "the admission must retain its request identity while occupying capacity"
    );

    let cancellation_service = service.clone();
    let cancellation = std::thread::spawn(move || {
        cancellation_service.cancel_run_admission(
            &intent("cancel active admission before HMAC rotation"),
            &mutation,
        )
    });
    assert!(
        service
            .operation_capacity
            .wait_for_cancellation_request(WAIT_LIMIT),
        "cancellation must signal the active identity before rotation"
    );
    let rotation_service = service.clone();
    let rotation = std::thread::spawn(move || rotation_service.rotate_idempotency_hmac_key());
    adapter.preflight_release.signal();
    assert_eq!(
        leader
            .join()
            .expect("admission thread must not panic")
            .expect_err("cancellation must prevent admission")
            .code,
        ErrorCode::Interrupted
    );
    assert!(matches!(
        cancellation
            .join()
            .expect("cancellation thread must not panic")
            .expect("cancellation must return a typed result"),
        crate::AdmissionCancellationResult::Cancelled
    ));
    assert_eq!(
        rotation
            .join()
            .expect("rotation thread must not panic")
            .expect("rotation may proceed after cancellation resolves"),
        2
    );
}

#[test]
fn identical_stop_and_hmac_rotation_preserve_lock_ordering() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_execution.store(true, Ordering::SeqCst);
    adapter.block_stop.store(true, Ordering::SeqCst);
    let service = service(state.path(), adapter.clone());
    let session = service
        .admit_run(
            &intent("active turn for stop rotation"),
            &authority(&service, "stop-rotation-principal", "stop-rotation-run"),
        )
        .expect("admit active turn");
    assert!(adapter.execute_started.wait_for(WAIT_LIMIT));
    let stop_authority = authority(
        &service,
        "stop-rotation-principal",
        "stop-rotation-identity",
    );

    let leader_service = service.clone();
    let leader_session_id = session.session_id().clone();
    let leader_authority = stop_authority.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_stop(&leader_session_id, &leader_authority)
    });
    assert!(adapter.stop_started.wait_for(WAIT_LIMIT));

    let rotation_started = Latch::default();
    let rotation_started_signal = rotation_started.clone();
    let rotation_service = service.clone();
    let rotation = std::thread::spawn(move || {
        rotation_started_signal.signal();
        rotation_service.rotate_idempotency_hmac_key()
    });
    assert!(rotation_started.wait_for(WAIT_LIMIT));

    let follower_service = service.clone();
    let follower_session_id = session.session_id().clone();
    let follower = std::thread::spawn(move || {
        follower_service.admit_stop(&follower_session_id, &stop_authority)
    });

    adapter.stop_release.signal();
    let first = leader
        .join()
        .expect("stop leader thread must not panic")
        .expect("stop leader must finish");
    assert_eq!(
        rotation
            .join()
            .expect("rotation thread must not panic")
            .expect("rotation must wait for the stop read gate before taking capacity"),
        2
    );
    let replayed = follower
        .join()
        .expect("identical stop thread must not panic")
        .expect("identical stop must derive its original request identity");
    assert_eq!(first, replayed);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 1);

    adapter.execute_release.signal();
    service
        .runtime
        .wait_for_background()
        .expect("active execution must finish after stop");
}

#[test]
fn identical_requests_remain_one_identity_across_an_attempted_hmac_rotation() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let mutation = authority(&service, "rotation-principal", "rotation-identical-run");

    let leader_service = service.clone();
    let leader_mutation = mutation.clone();
    let leader = std::thread::spawn(move || {
        leader_service.admit_run(
            &intent("identity held through registration"),
            &leader_mutation,
        )
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "the first request must hold its derived identity through active registration"
    );

    let rotation_started = Latch::default();
    let rotation_started_signal = rotation_started.clone();
    let rotation_service = service.clone();
    let rotation = std::thread::spawn(move || {
        rotation_started_signal.signal();
        rotation_service.rotate_idempotency_hmac_key()
    });
    assert!(
        rotation_started.wait_for(WAIT_LIMIT),
        "rotation must be attempted while the first identity is active"
    );

    let follower_started = Latch::default();
    let follower_started_signal = follower_started.clone();
    let follower_service = service.clone();
    let follower = std::thread::spawn(move || {
        follower_started_signal.signal();
        follower_service.admit_run(&intent("identity held through registration"), &mutation)
    });
    assert!(
        follower_started.wait_for(WAIT_LIMIT),
        "the identical request must attempt derivation across the pending rotation"
    );

    adapter.preflight_release.signal();
    let admitted = leader
        .join()
        .expect("leader thread must not panic")
        .expect("leader admission must finish");
    assert_eq!(
        rotation
            .join()
            .expect("rotation thread must not panic")
            .expect("rotation must complete after identity registration"),
        2
    );
    let replayed = follower
        .join()
        .expect("follower thread must not panic")
        .expect("identical request must preserve its operation identity");
    assert_same_session_and_turn_handles(&admitted, &replayed);
    service
        .runtime
        .wait_for_background()
        .expect("detached execution must finish");
}

#[test]
fn daemon_activity_snapshot_tracks_live_host_operations() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let adapter = ControlledAdapter::default();
    adapter.block_next_preflight();
    let service = service(state.path(), adapter.clone());
    let request_authority = authority(&service, "principal-activity", "activity-request");
    let initial = service
        .daemon_activity_snapshot()
        .expect("read initial daemon activity");
    assert!(initial.is_idle());

    let operation_service = service.clone();
    let operation = std::thread::spawn(move || {
        operation_service.admit_run(&intent("tracked operation"), &request_authority)
    });
    assert!(
        adapter.preflight_started.wait_for(WAIT_LIMIT),
        "the operation must occupy Host capacity before activity is inspected"
    );
    let active = service
        .daemon_activity_snapshot()
        .expect("read active daemon activity");
    assert!(!active.is_idle());
    assert_ne!(active.generation(), initial.generation());

    adapter.preflight_release.signal();
    operation
        .join()
        .expect("operation thread must not panic")
        .expect("operation admission must finish");
    service
        .runtime
        .wait_for_background()
        .expect("operation worker must finish");
    let finished = service
        .daemon_activity_snapshot()
        .expect("read finished daemon activity");
    assert!(finished.is_idle());
    assert_ne!(finished.generation(), active.generation());
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
fn retry_joins_the_published_result_before_capacity_clears() {
    let capacity = Arc::new(OperationCapacity::default());
    capacity.pause_next_result_before_clear();

    let leader_capacity = Arc::clone(&capacity);
    let leader = std::thread::spawn(move || {
        leader_capacity.execute(
            operation_request("principal-a", "key-a", DIGEST_A),
            || Ok(None),
            || {
                Err(crate::runtime::integrity_error(
                    "the authoritative pre-durable failure",
                ))
            },
        )
    });
    assert!(
        capacity.wait_for_result_before_clear(WAIT_LIMIT),
        "the leader must publish its result before releasing capacity"
    );

    let retry_capacity = Arc::clone(&capacity);
    let retry = std::thread::spawn(move || {
        retry_capacity.execute(
            operation_request("principal-a", "key-a", DIGEST_A),
            || Ok(None),
            || panic!("an identical retry must not become a second leader"),
        )
    });
    if !capacity.wait_for_follower_registration(WAIT_LIMIT) {
        capacity.release_result_before_clear();
        let _ = leader.join();
        let _ = retry.join();
        panic!("the retry did not join the published in-flight result");
    }
    capacity.release_result_before_clear();

    let leader_error = match leader.join().expect("leader thread must not panic") {
        Ok(_) => panic!("leader operation must fail"),
        Err(error) => error,
    };
    let retry_error = match retry.join().expect("retry thread must not panic") {
        Ok(_) => panic!("retry must share the leader failure"),
        Err(error) => error,
    };
    assert_same_error(&leader_error, &retry_error);
}

#[test]
fn matching_in_memory_request_wins_over_an_in_progress_durable_replay() {
    let capacity = Arc::new(OperationCapacity::default());
    let durable_starting = coordinator_result_session();
    let leader_started = Latch::default();
    let release_leader = Latch::default();

    let leader_capacity = Arc::clone(&capacity);
    let leader_started_signal = leader_started.clone();
    let release_leader_wait = release_leader.clone();
    let leader = std::thread::spawn(move || {
        leader_capacity.execute(
            operation_request("principal-a", "key-a", DIGEST_A),
            || Ok(None),
            || {
                leader_started_signal.signal();
                release_leader_wait.wait();
                Err(crate::runtime::integrity_error(
                    "the scheduled dispatch failed after durable admission",
                ))
            },
        )
    });
    assert!(
        leader_started.wait_for(WAIT_LIMIT),
        "the leader must remain active after durable admission"
    );

    let replay_calls = Arc::new(AtomicUsize::new(0));
    let follower_capacity = Arc::clone(&capacity);
    let follower_replay_calls = Arc::clone(&replay_calls);
    let follower = std::thread::spawn(move || {
        follower_capacity.execute(
            operation_request("principal-a", "key-a", DIGEST_A),
            || {
                follower_replay_calls.fetch_add(1, Ordering::SeqCst);
                Ok(Some(admission_outcome(durable_starting.clone())))
            },
            || panic!("an identical duplicate must not become a second leader"),
        )
    });

    if !capacity.wait_for_follower_registration(WAIT_LIMIT) {
        release_leader.signal();
        let _ = leader.join();
        let _ = follower.join();
        panic!("the duplicate accepted durable in-progress state instead of joining the leader");
    }
    release_leader.signal();
    let leader_error = match leader.join().expect("leader thread must not panic") {
        Ok(_) => panic!("the leader's post-admission dispatch must fail"),
        Err(error) => error,
    };
    let follower_error = match follower.join().expect("follower thread must not panic") {
        Ok(_) => panic!("the follower must receive the leader's exact failure"),
        Err(error) => error,
    };

    assert_same_error(&leader_error, &follower_error);
    assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
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
                            Ok(Some(admission_outcome(duplicate_expected.clone())))
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
        "duplicate A's first durable probe must start before leader A installs"
    );

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
                    Ok(admission_outcome(leader_expected))
                },
            )
            .and_then(OperationOutcome::into_session)
    });
    assert!(
        leader_started.wait_for(WAIT_LIMIT),
        "leader A must install while duplicate A's first probe is paused"
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
                    Ok(admission_outcome(occupant_expected))
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
    operation_request_for(IdempotentOperation::Run, principal, key, digest)
}

fn operation_request_for(
    operation: IdempotentOperation,
    principal: &str,
    key: &str,
    digest: &str,
) -> OperationRequest {
    let identity = RequestIdentity::authenticated(principal, key, digest, 1, 1);
    OperationRequest::new(operation, &identity)
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
        bootstrap_auth: None,
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
    block_admission_rejection: Arc<AtomicBool>,
    admission_started: Latch,
    admission_release: Latch,
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
    fn block_next_admission_rejection(&self) {
        self.block_admission_rejection.store(true, Ordering::SeqCst);
    }

    fn block_next_preflight(&self) {
        self.block_preflight.store(true, Ordering::SeqCst);
    }
}

impl ComputerUseAdapter for ControlledAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        if self.block_admission_rejection.swap(false, Ordering::SeqCst) {
            self.admission_started.signal();
            self.admission_release.wait();
            return Err(SatelleError::computer_use_not_ready());
        }
        FakeComputerUseAdapter.admit_operation(operation)
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        if self.block_preflight.swap(false, Ordering::SeqCst) {
            self.preflight_started.signal();
            self.preflight_release.wait();
        }
        if self.fail_next_preflight.swap(false, Ordering::SeqCst) {
            return Err(SatelleError::computer_use_not_ready());
        }
        FakeComputerUseAdapter.preflight(host, provider_intent)
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

fn admission_outcome(session: PublicSession) -> OperationOutcome {
    let turn_id = session
        .turns()
        .last()
        .expect("test Session contains a Turn")
        .turn_id()
        .clone();
    OperationOutcome::admission(session, turn_id)
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
