use super::*;
use crate::codex_capabilities::{
    CapabilityMatrix, CodexVersionEvidence, HostPlatform, Phase0CapabilityEvidence,
    REQUIRED_CODEX_VERSION,
};
use base64::Engine as _;
use satelle_core::session::TurnExecutionMode;
use satelle_core::session::{StopObservation, TurnState, TurnTransition};
use satelle_core::{ErrorCode, SatelleError};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

fn turn_intent(prompt: &str) -> TurnIntent {
    TurnIntent::new(prompt, TurnExecutionMode::Standard).expect("valid test Turn intent")
}

#[derive(Clone)]
struct RecordingTurnExtrasAdapter {
    observations: Arc<Mutex<Vec<TurnExtrasObservation>>>,
}

#[derive(Debug, Eq, PartialEq)]
struct TurnExtrasObservation {
    attachments: Vec<AttachmentObservation>,
    timeout_seconds: u32,
}

#[derive(Debug, Eq, PartialEq)]
struct AttachmentObservation {
    path: PathBuf,
    media_type: String,
    size_bytes: usize,
}

#[derive(Clone, Copy)]
struct SecretBoundaryAdapter;

impl ComputerUseAdapter for SecretBoundaryAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        let binding = provider_intent
            .resolved_provider_binding()
            .expect("Host must inject the authoritative provider binding");
        drop(crate::runtime::resolve_provider_child_secret_for_test(
            binding,
        )?);
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
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

#[derive(Clone, Copy)]
struct FailedProviderSmokeAdapter;

impl ComputerUseAdapter for FailedProviderSmokeAdapter {
    fn preflight(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        Err(SatelleError::remote_api_error(
            LOCAL_DEMO_HOST,
            "provider smoke failed",
        ))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
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

impl ComputerUseAdapter for RecordingTurnExtrasAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.observations
            .lock()
            .expect("lock observations")
            .push(TurnExtrasObservation {
                attachments: request
                    .attachments()
                    .iter()
                    .map(|attachment| AttachmentObservation {
                        path: attachment.path().to_path_buf(),
                        media_type: attachment.media_type().to_string(),
                        size_bytes: attachment.bytes().len(),
                    })
                    .collect(),
                timeout_seconds: request.execution_policy().timeout_policy().seconds(),
            });
        Ok(ExecuteResult::new(TurnTransition::Completed, Vec::new()))
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

fn turn_intent_with_extras(prompt: &str, timeout_seconds: u64) -> TurnIntent {
    let bytes = b"\x89PNG\r\n\x1a\n";
    let digest = Sha256::digest(bytes);
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    turn_intent(prompt)
        .with_turn_execution_timeout_ms(Some(timeout_seconds * 1_000))
        .expect("valid Turn timeout")
        .with_attachments(vec![AttachmentUpload::new(
            "image/png",
            u64::try_from(bytes.len()).expect("image size fits u64"),
            sha256,
            base64::engine::general_purpose::STANDARD.encode(bytes),
        )])
        .expect("valid image attachment")
}

#[test]
fn local_host_run_and_steer_forward_attachments_and_host_clamped_timeout() {
    let state = TestStateDir::new().expect("temporary state directory");
    let observations = Arc::new(Mutex::new(Vec::new()));
    let service = HostService {
        runtime: RuntimeHandle::new(
            Ok(state.path().to_path_buf()),
            RecordingTurnExtrasAdapter {
                observations: Arc::clone(&observations),
            },
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    }
    .with_turn_execution_timeout_for_tests(5);

    let session = service
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent_with_extras("local run extras", 3),
        )
        .expect("run local Turn")
        .session;
    service
        .steer(
            session.session_id(),
            &turn_intent_with_extras("local steer extras", 7),
        )
        .expect("steer local Turn");

    let observations = observations.lock().expect("lock observations");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].timeout_seconds, 3);
    assert_eq!(observations[1].timeout_seconds, 5);
    for observation in observations.iter() {
        assert_eq!(observation.attachments.len(), 1);
        let attachment = &observation.attachments[0];
        assert_eq!(attachment.media_type, "image/png");
        assert_eq!(attachment.size_bytes, 8);
        assert!(
            attachment
                .path
                .starts_with(state.path().join("attachments"))
        );
        assert!(
            attachment
                .path
                .file_name()
                .expect("staged image path has a file name")
                .to_string_lossy()
                .starts_with("satelle-image-")
        );
        assert!(
            !attachment.path.exists(),
            "terminal run and steer must both delete staged images"
        );
    }
    assert_ne!(
        observations[0].attachments[0].path, observations[1].attachments[0].path,
        "run and steer must receive separate generated staging names"
    );
}

#[test]
fn unsupported_image_capability_rejects_direct_run_and_steer_before_admission() {
    let state = TestStateDir::new().expect("temporary state directory");
    let observations = Arc::new(Mutex::new(Vec::new()));
    let service = HostService {
        runtime: RuntimeHandle::new(
            Ok(state.path().to_path_buf()),
            RecordingTurnExtrasAdapter {
                observations: Arc::clone(&observations),
            },
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: false,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    let image_intent = turn_intent_with_extras("unsupported image", 3);

    let run_failure = service
        .run(LOCAL_DEMO_HOST, &image_intent)
        .expect_err("attached image run must be rejected");
    assert!(matches!(
        run_failure,
        TurnAdmissionFailure::NotAdmitted(error) if error.code == ErrorCode::InvalidUsage
    ));
    let detached_run_error = service
        .run_detached(LOCAL_DEMO_HOST, &image_intent)
        .expect_err("detached image run must be rejected");
    assert_eq!(detached_run_error.code, ErrorCode::InvalidUsage);
    assert!(
        !state.path().join("attachments").exists(),
        "unsupported images must be rejected before the attachment store opens"
    );
    assert!(observations.lock().expect("lock observations").is_empty());

    let initial = service
        .run(LOCAL_DEMO_HOST, &turn_intent("image-free run"))
        .expect("image-free run remains supported")
        .session;
    let steer_failure = service
        .steer(initial.session_id(), &image_intent)
        .expect_err("attached image steer must be rejected");
    assert!(matches!(
        steer_failure,
        TurnAdmissionFailure::NotAdmitted(error) if error.code == ErrorCode::InvalidUsage
    ));
    let detached_steer_error = service
        .steer_detached(initial.session_id(), &image_intent)
        .expect_err("detached image steer must be rejected");
    assert_eq!(detached_steer_error.code, ErrorCode::InvalidUsage);

    let status = service
        .status(initial.session_id())
        .expect("seed Session remains readable");
    assert_eq!(status.turns().len(), 1);
    assert_eq!(observations.lock().expect("lock observations").len(), 1);
}

#[test]
fn admission_request_timeout_tracks_both_configured_readiness_phases() {
    let mut config = satelle_core::SatelleConfig::defaults()
        .hosts
        .remove(LOCAL_DEMO_HOST)
        .expect("built-in Host config exists");
    assert_eq!(
        admission_request_timeout(&config),
        std::time::Duration::from_secs(250)
    );

    config.timeouts = Some(satelle_core::TimeoutConfig {
        native_readiness: satelle_core::ExplicitDuration::parse("2s"),
        provider_smoke_test: satelle_core::ExplicitDuration::parse("3s"),
        turn_execution: None,
    });
    assert_eq!(
        admission_request_timeout(&config),
        std::time::Duration::from_secs(15)
    );
}

#[test]
fn configured_remote_alias_reaches_execution_and_session_keeps_host_identity() {
    const REMOTE_HOST_ALIAS: &str = "studio-workstation";

    let state = TestStateDir::new().expect("temporary state directory should exist");
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };

    let outcome = service
        .run(
            REMOTE_HOST_ALIAS,
            &turn_intent("exercise configured remote Host routing"),
        )
        .expect("the Host Daemon should accept its validated configured alias");
    assert!(
        outcome
            .events
            .iter()
            .filter(|event| event.event_type() != satelle_core::EventType::ProviderSmoke)
            .all(|event| event.host() == REMOTE_HOST_ALIAS),
        "the configured alias must reach adapter execution events"
    );
    let public_session = outcome.session;
    assert_eq!(
        service
            .status(public_session.session_id())
            .expect("the admitted Session should remain publicly readable"),
        public_session
    );

    // The Controller-local alias selects this daemon, but durable ownership
    // remains bound to the daemon's stable Host Identity.
    drop(service);
    let (storage, _) = crate::storage::Storage::open(state.path())
        .expect("the authoritative Host store should reopen");
    let stored_session = storage
        .load_session(public_session.session_id())
        .expect("the admitted Session should be readable from storage")
        .expect("the admitted Session should be durable");
    assert_eq!(
        stored_session.host_identity(),
        &storage
            .host_identity()
            .expect("the Host Identity should be durable")
    );
    assert_eq!(stored_session.to_public(), public_session);
}

#[test]
fn configured_remote_alias_is_accepted_by_host_diagnostics() {
    const REMOTE_HOST_ALIAS: &str = "studio-workstation";

    let state = TestStateDir::new().expect("temporary state directory should exist");
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    let doctor = service
        .doctor(REMOTE_HOST_ALIAS, None, DoctorOptions::default())
        .expect("doctor should diagnose the already-routed Host alias");
    assert_eq!(doctor.host, REMOTE_HOST_ALIAS);

    let sessions = service
        .host_sessions(REMOTE_HOST_ALIAS, false)
        .expect("desktop Session discovery should accept the routed Host alias");
    assert_eq!(sessions.host, REMOTE_HOST_ALIAS);
    assert_eq!(
        sessions.bootstrap_actions,
        ["direct studio-workstation Host daemon already reachable"]
    );

    let setup = service
        .setup(
            REMOTE_HOST_ALIAS,
            true,
            "full".to_string(),
            Vec::new(),
            DaemonPathOverrides::default(),
        )
        .expect("setup planning should accept the routed Host alias");
    assert_eq!(setup.host, REMOTE_HOST_ALIAS);
}

#[derive(Clone, Copy)]
struct FailingExecutionAdapter;

impl ComputerUseAdapter for FailingExecutionAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        Err(SatelleError::host_unreachable(LOCAL_DEMO_HOST))
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

#[test]
fn unsupported_or_unproven_production_execution_is_blocked_without_state_admission() {
    for (name, evidence, control_plane_admission) in [
        (
            "unsupported-linux-host",
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: HostPlatform::Linux,
                capabilities: CapabilityMatrix::unproven(),
            },
            codex_capabilities::ControlPlaneAdmission::not_applicable(),
        ),
        (
            "supported-windows-host-with-unproven-native-readiness",
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: HostPlatform::Windows,
                capabilities: CapabilityMatrix::unproven(),
            },
            codex_capabilities::ControlPlaneAdmission::not_applicable(),
        ),
    ] {
        let state = TestStateDir::new().expect("temporary state directory should exist");
        let mut production_snapshot = capability_snapshot(evidence, 7);
        production_snapshot.control_plane_admission = control_plane_admission;
        let snapshot = Arc::new(RwLock::new(production_snapshot));
        let adapter = ProductionComputerUseAdapter::new(
            Arc::clone(&snapshot),
            Ok(state.path().join("codex-app-server-work")),
        );
        let service = HostService {
            runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: crate::configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::Production { snapshot },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
        };
        let session_id = SessionId::new();

        let assert_blocked_error = |operation: &str, error: &SatelleError| {
            assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
            assert!(
                error.details.is_empty(),
                "{name} {operation} must remain a native readiness failure"
            );

            let serialized =
                serde_json::to_string(error).expect("closed capability blocker must serialize");
            assert!(!serialized.contains("PRIVATE_PRODUCTION_PROMPT"));
            assert!(!serialized.contains("fake"));
        };

        for (operation, failure) in [
            (
                "run",
                service
                    .run(LOCAL_DEMO_HOST, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("attached run must be blocked"),
            ),
            (
                "steer",
                service
                    .steer(&session_id, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("attached steer must be blocked before session lookup"),
            ),
        ] {
            assert!(matches!(failure, TurnAdmissionFailure::NotAdmitted(_)));
            assert_blocked_error(operation, failure.error());
        }

        for (operation, error) in [
            (
                "run",
                service
                    .run_detached(LOCAL_DEMO_HOST, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("detached run must be blocked"),
            ),
            (
                "steer",
                service
                    .steer_detached(&session_id, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("detached steer must be blocked before session lookup"),
            ),
        ] {
            assert_blocked_error(operation, &error);
        }

        let stop_error = service
            .stop(&session_id)
            .expect_err("stop should remain available without adapter readiness");
        assert_eq!(stop_error.code, ErrorCode::SessionNotFound);

        let status_error = service
            .status(&session_id)
            .expect_err("read-only status should open storage without adapter readiness");
        assert_eq!(status_error.code, ErrorCode::SessionNotFound);

        let runtime_status = service
            .daemon_runtime_status()
            .expect("blocked production execution must leave runtime status readable");
        assert_eq!(
            (
                runtime_status.session_count(),
                runtime_status.active_turn_count(),
                runtime_status.recovery_pending_turn_count(),
            ),
            (0, 0, 0),
            "{name} must not durably admit a Session or Turn"
        );
    }
}

#[test]
fn blocked_control_plane_precedes_capability_and_live_desktop_checks() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let evidence = Phase0CapabilityEvidence {
        codex_version: CodexVersionEvidence::Detected {
            version: REQUIRED_CODEX_VERSION,
        },
        host_platform: HostPlatform::Windows,
        capabilities: CapabilityMatrix::unproven(),
    };
    let mut production_snapshot = capability_snapshot(evidence, 7);
    production_snapshot.control_plane_admission =
        codex_capabilities::ControlPlaneAdmission::unavailable(
            satelle_core::ControlPlaneFailureReason::HandshakeUnavailable,
        );
    let adapter = ProductionComputerUseAdapter::new(
        Arc::new(RwLock::new(production_snapshot)),
        Ok(state.path().join("codex-app-server-work")),
    );
    let intent = turn_intent("PRIVATE_PRODUCTION_PROMPT");

    let error = match adapter.preflight(LOCAL_DEMO_HOST, intent.provider_intent()) {
        Ok(_) => panic!("a blocked control plane must stop before live readiness"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
}

#[test]
fn attached_adapter_failures_return_exact_durable_run_and_steer_handles() {
    let run_state = TestStateDir::new().expect("temporary run state directory should exist");
    let run_service = HostService {
        runtime: RuntimeHandle::new(Ok(run_state.path().to_path_buf()), FailingExecutionAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    let run_failure = run_service
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_FAIL_AFTER_RUN_COMMIT"),
        )
        .expect_err("the deterministic adapter must fail after run admission");
    let (run_failure_session, run_turn_id) = match run_failure {
        TurnAdmissionFailure::Admitted {
            session, turn_id, ..
        } => (*session, turn_id),
        other => panic!("postcommit run failure had the wrong phase: {other:?}"),
    };
    let run_session_id = run_failure_session.session_id().clone();
    let run_status = run_service
        .status(&run_session_id)
        .expect("the admitted run must remain readable");
    let durable_run = run_status
        .turns()
        .last()
        .expect("the admitted run must retain its Turn");
    assert_eq!(durable_run.turn_id(), &run_turn_id);
    assert_eq!(durable_run.state(), TurnState::RecoveryPending);
    assert_eq!(run_failure_session, run_status);

    let steer_state = TestStateDir::new().expect("temporary steer state directory should exist");
    let seeded = HostService {
        runtime: RuntimeHandle::new(Ok(steer_state.path().to_path_buf()), FakeComputerUseAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    let initial = seeded
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_SUCCESSFUL_INITIAL_RUN"),
        )
        .expect("the initial run should complete");
    let steer_session_id = initial.session.session_id().clone();
    drop(seeded);
    let steer_service = HostService {
        runtime: RuntimeHandle::new(
            Ok(steer_state.path().to_path_buf()),
            FailingExecutionAdapter,
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    let steer_failure = steer_service
        .steer(
            &steer_session_id,
            &turn_intent("PRIVATE_FAIL_AFTER_STEER_COMMIT"),
        )
        .expect_err("the deterministic adapter must fail after steer admission");
    let steer_turn_id = match steer_failure {
        TurnAdmissionFailure::Admitted {
            session, turn_id, ..
        } => {
            assert_eq!(session.session_id(), &steer_session_id);
            assert_eq!(session.turns().len(), 2);
            assert_eq!(
                session.turns().last().map(|turn| turn.state()),
                Some(TurnState::RecoveryPending)
            );
            turn_id
        }
        other => panic!("postcommit steer failure had the wrong phase: {other:?}"),
    };
    let steer_status = steer_service
        .status(&steer_session_id)
        .expect("the admitted steer must remain readable");
    assert_eq!(steer_status.turns().len(), 2);
    let durable_steer = steer_status
        .turns()
        .last()
        .expect("the admitted steer must retain its Turn");
    assert_eq!(durable_steer.turn_id(), &steer_turn_id);
    assert_eq!(durable_steer.state(), TurnState::RecoveryPending);
}

#[test]
fn refreshed_production_snapshot_updates_admission_surfaces_but_not_desktop_discovery() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let initial = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Detected {
                version: REQUIRED_CODEX_VERSION,
            },
            host_platform: HostPlatform::Windows,
            capabilities: CapabilityMatrix::unproven(),
        },
        7,
    );
    let snapshot = Arc::new(RwLock::new(initial));
    let adapter = ProductionComputerUseAdapter::new(
        Arc::clone(&snapshot),
        Ok(state.path().join("codex-app-server-work")),
    );
    let shared_snapshot = Arc::clone(&snapshot);
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::Production { snapshot },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    let clone = service.clone();

    let initial_error = service
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_BEFORE_CONTROL_PLANE_REFRESH"),
        )
        .expect_err("the supported snapshot should reach the native execution blocker");
    assert!(matches!(
        initial_error,
        TurnAdmissionFailure::NotAdmitted(_)
    ));
    assert_eq!(initial_error.error().code, ErrorCode::ComputerUseNotReady);
    assert!(
        service
            .daemon_runtime_capabilities()
            .unwrap()
            .codex_runtime()
    );

    let mut refreshed = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Missing,
            host_platform: HostPlatform::Windows,
            capabilities: CapabilityMatrix::unproven(),
        },
        11,
    );
    refreshed.control_plane_admission = codex_capabilities::ControlPlaneAdmission::unavailable(
        satelle_core::ControlPlaneFailureReason::RuntimeMissing,
    );
    replace_production_snapshot(&shared_snapshot, refreshed)
        .expect("doctor refresh should atomically replace the shared snapshot");

    let refreshed_error = clone
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_AFTER_CONTROL_PLANE_REFRESH"),
        )
        .expect_err("the cloned service must use refreshed execution readiness");
    assert!(matches!(
        refreshed_error,
        TurnAdmissionFailure::NotAdmitted(_)
    ));
    assert_eq!(
        refreshed_error.error().code,
        ErrorCode::IncompatibleControlPlane
    );
    assert!(!clone.daemon_runtime_capabilities().unwrap().codex_runtime());
    let sessions = clone
        .host_sessions(LOCAL_DEMO_HOST, false)
        .expect("desktop discovery must remain available for readiness diagnosis");
    assert_eq!(sessions.schema_version, HostSessionsSchemaVersion::V1);
    assert_eq!(sessions.host, LOCAL_DEMO_HOST);
    let doctor = clone
        .doctor(LOCAL_DEMO_HOST, Some("codex"), DoctorOptions::default())
        .expect("non-refresh doctor must read the refreshed snapshot");
    assert!(doctor.findings.iter().any(|finding| {
        finding
            .evidence
            .contains(&"reason=missing_codex_runtime".to_string())
    }));
}

#[test]
fn production_doctor_uses_blocked_probe_results_and_closed_evidence() {
    let snapshot = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Malformed,
            host_platform: HostPlatform::Windows,
            capabilities: CapabilityMatrix::unproven(),
        },
        17,
    );
    let report = production_doctor_report(LOCAL_DEMO_HOST, Some("codex"), &snapshot);
    let serialized = serde_json::to_string(&report).expect("doctor report should serialize");

    assert!(!report.ready);
    assert_eq!(report.duration_ms, 17);
    assert_eq!(report.probe_results[0].duration_ms, 17);
    assert!(
        report
            .probe_results
            .iter()
            .all(|probe| probe.status == "blocked")
    );
    assert!(report.findings.iter().any(|finding| {
        finding
            .evidence
            .contains(&"reason=malformed_codex_version".to_string())
    }));
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.scope == "codex")
    );
    assert!(!serialized.contains("fake"));
    assert!(!serialized.contains("codex-cli"));
}

#[test]
fn production_doctor_identifies_the_missing_private_native_execution_path() {
    let mut capabilities = CapabilityMatrix::unproven();
    capabilities.handshake = codex_capabilities::CapabilityEvidence::new(
        codex_capabilities::EvidenceSurface::Stable,
        codex_capabilities::LiveProofStatus::NotRequired,
    );
    let snapshot = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Detected {
                version: REQUIRED_CODEX_VERSION,
            },
            host_platform: HostPlatform::Windows,
            capabilities,
        },
        19,
    );

    let report = production_doctor_report(LOCAL_DEMO_HOST, Some("computer-use"), &snapshot);
    let finding = report
        .findings
        .iter()
        .find(|finding| {
            finding
                .evidence
                .contains(&"reason=native_execution_path_unavailable".to_string())
        })
        .expect("doctor must identify an absent native path on the private app-server");

    assert_eq!(finding.scope, "computer-use");
    assert_eq!(
        finding.summary,
        "the private Codex app-server exposes no stable native Computer Use path"
    );
    assert_eq!(finding.readiness_impact, "blocked");
    assert!(!report.ready);
}

#[test]
fn production_doctor_filters_requested_scopes_without_relabeling_blockers() {
    let snapshot = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Malformed,
            host_platform: HostPlatform::Linux,
            capabilities: CapabilityMatrix::unproven(),
        },
        23,
    );

    let transport = production_doctor_report(LOCAL_DEMO_HOST, Some("transport"), &snapshot);
    assert!(!transport.ready);
    assert_eq!(transport.scopes, ["transport"]);
    assert_eq!(transport.findings.len(), 1);
    assert_eq!(transport.findings[0].scope, "transport");
    assert_eq!(
        transport.findings[0].evidence,
        ["reason=transport_unavailable"]
    );
    assert_eq!(transport.probe_results[0].duration_ms, 0);

    let provider = production_doctor_report(LOCAL_DEMO_HOST, Some("provider"), &snapshot);
    assert!(!provider.ready);
    assert_eq!(provider.scopes, ["provider"]);
    assert_eq!(provider.findings.len(), 1);
    assert_eq!(provider.findings[0].scope, "provider");

    let config = production_doctor_report(LOCAL_DEMO_HOST, Some("config"), &snapshot);
    assert!(config.ready);
    assert_eq!(config.scopes, ["config"]);
    assert!(config.findings.is_empty());
    assert_eq!(config.probe_results[0].status, "passed");

    let codex = production_doctor_report(LOCAL_DEMO_HOST, Some("codex"), &snapshot);
    assert!(!codex.ready);
    assert!(codex.findings.is_empty());
    assert_eq!(codex.probe_results[0].status, "blocked");
    assert_eq!(codex.probe_results[0].dependency_status, "blocked");

    let computer_use = production_doctor_report(LOCAL_DEMO_HOST, Some("computer-use"), &snapshot);
    assert!(!computer_use.ready);
    assert!(
        computer_use
            .findings
            .iter()
            .all(|finding| finding.scope == "computer-use")
    );
    assert!(!computer_use.findings.iter().any(|finding| {
        finding
            .evidence
            .contains(&"reason=malformed_codex_version".to_string())
    }));

    let all = production_doctor_report(LOCAL_DEMO_HOST, Some("all"), &snapshot);
    assert!(!all.ready);
    assert_eq!(
        all.scopes,
        ["codex", "computer-use", "config", "provider", "transport"]
    );
    assert!(all.findings.iter().all(|finding| finding.scope != "all"));
}

#[test]
fn doctor_provider_refresh_updates_cache_without_admitting_prompt_work() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    service
        .runtime
        .authorize_provider_binding(&satelle_core::ResolvedProviderBinding::from_authorization(
            satelle_core::ProviderBindingAuthorization::new(
                "provider-doctor-model",
                "provider-doctor-binding",
                "provider-doctor-model",
                "provider-doctor-binding",
            )
            .with_auth_source(satelle_core::ProviderSecretSource::Environment {
                variable: "SATELLE_PROVIDER_DOCTOR_TOKEN".to_string(),
            })
            .with_experimental_provider_computer_use(true),
            satelle_core::ProviderBindingSource::UserConfig,
        ))
        .expect("authorize the persisted UserConfig provider binding");
    let intent = ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("provider-doctor-model")
                .expect("valid model"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("provider-doctor-binding")
                .expect("valid provider"),
        ),
        true,
    );

    let report = service
        .doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            Some("provider"),
            DoctorOptions::new(true, Some(std::time::Duration::from_secs(5))),
            &intent,
        )
        .expect("provider doctor refresh should complete");

    assert!(report.ready);
    assert!(report.changed);
    assert_eq!(report.cache_updates, ["provider_smoke"]);
    assert_eq!(report.probe_results.len(), 1);
    assert_eq!(report.probe_results[0].probe_id, "provider.smoke.refresh");
    assert_eq!(report.probe_results[0].cache_status, "refreshed");
    assert!(
        report.findings[0]
            .evidence
            .contains(&"source=refresh".to_string())
    );
    assert_eq!(service.host_status().unwrap().sessions, 0);
}

#[test]
fn production_adapter_accepts_host_authorized_binding_without_resolving_auth() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let host_auth = satelle_core::ProviderSecretSource::Environment {
        variable: "SATELLE_HOST_OWNED_PROVIDER_SECRET_MISSING".to_string(),
    };
    let adapter = ProductionComputerUseAdapter::with_readiness_policy(
        Arc::new(RwLock::new(capability_snapshot(
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Malformed,
                host_platform: HostPlatform::Linux,
                capabilities: CapabilityMatrix::unproven(),
            },
            0,
        ))),
        Ok(state.path().to_path_buf()),
        crate::runtime::ProductionAdapterPolicy {
            native_readiness_timeout: std::time::Duration::from_secs(1),
            native_readiness_ttl: time::Duration::minutes(5),
            provider_smoke_timeout: std::time::Duration::from_secs(1),
            provider_smoke_success_ttl: time::Duration::hours(24),
            provider_smoke_failure_ttl: time::Duration::minutes(10),
            desktop_selection: satelle_core::DesktopSelectionPolicy {
                desktop_user: None,
                preference: None,
                native_selector: None,
            },
        },
    );
    let binding = satelle_core::ResolvedProviderBinding::from_authorization(
        satelle_core::ProviderBindingAuthorization::new(
            "review",
            "openai",
            "host-model",
            "host-provider",
        )
        .with_endpoint("https://host-provider.invalid/v1")
        .with_auth_source(host_auth.clone())
        .with_experimental_provider_computer_use(true),
        satelle_core::ProviderBindingSource::HostOwned,
    );
    let intent = ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("review")
                .expect("valid requested model alias"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("openai")
                .expect("valid requested provider alias"),
        ),
        false,
    )
    .with_resolved_provider_binding(binding);

    let resolved = ComputerUseAdapter::resolve_provider_binding(&adapter, LOCAL_DEMO_HOST, &intent)
        .expect("Host-owned binding resolution must not read its missing secret");

    assert_eq!(
        satelle_core::ProviderBindingSource::HostOwned,
        resolved.source()
    );
    assert_eq!("host-model", resolved.model());
    assert_eq!("host-provider", resolved.model_provider());
    assert_eq!(
        Some("https://host-provider.invalid/v1"),
        resolved.endpoint()
    );
    assert_eq!(Some(&host_auth), resolved.auth_source());
}

#[test]
fn unresolved_host_secret_maps_to_the_typed_public_error_without_descriptor_text() {
    let variable = format!(
        "SATELLE_PROVIDER_AUTH_MISSING_{}",
        uuid::Uuid::now_v7().simple()
    );
    let binding = satelle_core::ResolvedProviderBinding::from_authorization(
        satelle_core::ProviderBindingAuthorization::new(
            "review",
            "openai",
            "host-model",
            "host-provider",
        )
        .with_endpoint("https://host-provider.invalid/v1")
        .with_auth_source(satelle_core::ProviderSecretSource::Environment {
            variable: variable.clone(),
        }),
        satelle_core::ProviderBindingSource::HostOwned,
    );

    let error = crate::runtime::resolve_provider_child_secret_for_test(&binding)
        .expect_err("the missing Host environment secret must fail closed");

    assert_eq!(ErrorCode::ProviderSecretResolutionFailed, error.code);
    assert_eq!(error.details["reason"], "provider_auth_unresolved");
    let encoded = serde_json::to_string(&error).expect("serialize typed error");
    assert!(!encoded.contains(&variable));
}

#[cfg(unix)]
#[test]
fn provider_descriptor_validation_resolves_only_during_target_host_refresh() {
    use std::os::unix::fs::PermissionsExt;

    let state = TestStateDir::new().expect("temporary state directory");
    let secret_directory = tempfile::tempdir().expect("create provider secret directory");
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make provider secret directory owner-only");
    let secret_path = secret_directory.path().join("provider-token");
    let secret_canary = "PRIVATE_PROVIDER_REFRESH_SECRET_CANARY";
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), SecretBoundaryAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    service
        .authorize_provider_binding(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            satelle_core::ProviderBindingAuthorization::new(
                "review",
                "openai",
                "host-model",
                "openai",
            )
            .with_endpoint("http://127.0.0.1:9")
            .with_auth_source(satelle_core::ProviderSecretSource::File {
                path: secret_path.clone(),
            })
            .with_experimental_provider_computer_use(true),
        )
        .expect("authorization stores only the provider descriptor");

    let cached = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            satelle_core::ProviderAuthValidationMode::Cached,
        )
        .expect("cached validation remains observation-only");
    assert_eq!(
        cached.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::ConfiguredDeferred
    );
    assert_eq!(
        cached.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Deferred
    );
    assert!(!secret_path.exists());

    std::fs::write(&secret_path, secret_canary).expect("write provider secret canary");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("make provider secret owner-only");
    let refreshed = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
        )
        .expect("live validation resolves at the target Host");
    assert_eq!(
        refreshed.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::Resolved
    );
    assert_eq!(
        refreshed.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    let public = satelle_core::PublicProviderDescriptorValidation::from(&refreshed);
    let encoded = serde_json::to_string(&public).expect("serialize public validation");
    assert!(!encoded.contains(secret_canary));
    assert!(!encoded.contains(secret_path.to_string_lossy().as_ref()));

    std::fs::remove_file(&secret_path).expect("remove provider secret");
    let unresolved = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
        )
        .expect("live validation reports a closed unresolved outcome");
    assert_eq!(
        unresolved.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret
    );
    assert_eq!(
        unresolved.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    let encoded = serde_json::to_string(&satelle_core::PublicProviderDescriptorValidation::from(
        &unresolved,
    ))
    .expect("serialize unresolved public validation");
    assert!(!encoded.contains(secret_canary));
    assert!(!encoded.contains(secret_path.to_string_lossy().as_ref()));
}

#[cfg(unix)]
#[test]
fn failed_upstream_validation_returns_only_the_closed_smoke_failed_outcome() {
    use std::os::unix::fs::PermissionsExt;

    let state = TestStateDir::new().expect("temporary state directory");
    let secret_directory = tempfile::tempdir().expect("create provider secret directory");
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make provider secret directory owner-only");
    let secret_path = secret_directory.path().join("provider-token");
    std::fs::write(&secret_path, "provider-smoke-token").expect("write provider smoke secret");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("make provider smoke secret owner-only");
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), FailedProviderSmokeAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
    };
    service
        .authorize_provider_binding(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            satelle_core::ProviderBindingAuthorization::new(
                "review",
                "openai",
                "host-model",
                "openai",
            )
            .with_auth_source(satelle_core::ProviderSecretSource::File { path: secret_path }),
        )
        .expect("authorize provider binding before failed smoke");

    let validation = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
        )
        .expect("upstream smoke failure must become a closed validation outcome");
    assert_eq!(
        validation.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed
    );
    assert_eq!(
        validation.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    let public = satelle_core::PublicProviderDescriptorValidation::from(&validation);
    let encoded = serde_json::to_value(public).expect("serialize closed validation");
    assert_eq!(
        encoded["validation"]["outcome"],
        satelle_core::ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed.as_str()
    );
}

#[test]
fn doctor_provider_scope_reports_closed_descriptor_status_without_secret_text() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let variable = format!(
        "SATELLE_DOCTOR_PROVIDER_SECRET_{}",
        uuid::Uuid::now_v7().simple()
    );
    service
        .runtime
        .authorize_provider_binding(&satelle_core::ResolvedProviderBinding::from_authorization(
            satelle_core::ProviderBindingAuthorization::new(
                "review",
                "openai",
                "provider-doctor-model",
                "provider-doctor-binding",
            )
            .with_auth_source(satelle_core::ProviderSecretSource::Environment {
                variable: variable.clone(),
            })
            .with_experimental_provider_computer_use(true),
            satelle_core::ProviderBindingSource::UserConfig,
        ))
        .expect("authorize the persisted UserConfig provider binding");
    let intent = ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("review")
                .expect("valid requested model alias"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("openai")
                .expect("valid requested provider alias"),
        ),
        false,
    );

    let report = service
        .doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            Some("provider"),
            DoctorOptions::new(false, None),
            &intent,
        )
        .expect("read-only provider doctor should classify its descriptor");
    let evidence = report
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        evidence.contains(&"provider_auth_outcome=configured_deferred".to_string()),
        "doctor must report the closed descriptor outcome"
    );
    assert!(
        evidence.contains(&"provider_auth_observation_source=deferred".to_string()),
        "doctor must distinguish deferred descriptor inspection from live resolution"
    );
    assert!(
        !serde_json::to_string(&report)
            .expect("serialize doctor report")
            .contains(&variable),
        "doctor output must not return environment variable names or secret material"
    );
}

fn capability_snapshot(
    evidence: Phase0CapabilityEvidence,
    duration_ms: u64,
) -> ProductionCapabilitySnapshot {
    ProductionCapabilitySnapshot {
        evidence,
        verdict: evaluate_phase0_support(evidence),
        control_plane_admission: codex_capabilities::ControlPlaneAdmission::not_applicable(),
        started_at: "2026-07-09T00:00:00Z".to_string(),
        finished_at: "2026-07-09T00:00:01Z".to_string(),
        duration_ms,
    }
}
