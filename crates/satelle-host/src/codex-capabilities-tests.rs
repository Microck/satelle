use super::*;

const INCOMPLETE_PROOF_STATES: [LiveProofStatus; 3] = [
    LiveProofStatus::NotRequired,
    LiveProofStatus::NotObserved,
    LiveProofStatus::Failed,
];
const NON_STABLE_SURFACES: [EvidenceSurface; 3] = [
    EvidenceSurface::Experimental,
    EvidenceSurface::Undocumented,
    EvidenceSurface::Absent,
];

#[test]
fn exact_candidate_with_complete_proof_supports_macos_and_windows() {
    for platform in [HostPlatform::Macos, HostPlatform::Windows] {
        let verdict = evaluate_phase0_support(fully_proven_evidence(platform));

        assert_eq!(
            verdict,
            Phase0SupportVerdict::Supported {
                codex_version: REQUIRED_CODEX_VERSION,
                host_platform: platform,
            }
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_discovery_skips_the_native_computer_use_control_plane() {
    let evidence = discover_phase0_evidence();

    assert_eq!(evidence.host_platform, HostPlatform::Linux);
    assert_eq!(evidence.codex_version, CodexVersionEvidence::Unavailable);
    assert_eq!(
        evaluate_phase0_support(evidence),
        Phase0SupportVerdict::Blocked {
            blockers: vec![Phase0CapabilityBlocker {
                reason: BlockerReason::UnsupportedHostPlatform,
                capability: RequiredCapability::NativeReadiness,
                codex_version: CodexVersionEvidence::Unavailable,
                host_platform: HostPlatform::Linux,
                observed_surface: EvidenceSurface::Absent,
                live_proof: LiveProofStatus::NotObserved,
            }],
        }
    );
}

#[test]
fn every_other_codex_version_is_blocked_at_the_handshake_gate() {
    for detected_version in [
        CodexVersion::new(0, 143, 9),
        CodexVersion::new(0, 144, 1),
        CodexVersion::new(0, 145, 0),
        CodexVersion::new(1, 0, 0),
    ] {
        let mut evidence = fully_proven_evidence(HostPlatform::Windows);
        evidence.codex_version = CodexVersionEvidence::Detected {
            version: detected_version,
        };

        assert_eq!(
            blockers(evaluate_phase0_support(evidence)),
            vec![Phase0CapabilityBlocker {
                reason: BlockerReason::UnsupportedCodexVersion,
                capability: RequiredCapability::Handshake,
                codex_version: CodexVersionEvidence::Detected {
                    version: detected_version,
                },
                host_platform: HostPlatform::Windows,
                observed_surface: EvidenceSurface::Stable,
                live_proof: LiveProofStatus::NotRequired,
            }]
        );
    }
}

#[test]
fn every_non_host_platform_is_blocked_at_native_readiness() {
    for platform in [HostPlatform::Linux, HostPlatform::Other] {
        let evidence = fully_proven_evidence(platform);

        assert_eq!(
            blockers(evaluate_phase0_support(evidence)),
            vec![Phase0CapabilityBlocker {
                reason: BlockerReason::UnsupportedHostPlatform,
                capability: RequiredCapability::NativeReadiness,
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: platform,
                observed_surface: EvidenceSurface::Stable,
                live_proof: LiveProofStatus::Passed,
            }]
        );
    }
}

#[test]
fn every_required_capability_rejects_every_non_stable_surface() {
    for capability in REQUIRED_CAPABILITIES {
        for surface in NON_STABLE_SURFACES {
            let mut evidence = fully_proven_evidence(HostPlatform::Macos);
            evidence_mut(&mut evidence.capabilities, capability).surface = surface;

            assert_eq!(
                blockers(evaluate_phase0_support(evidence)),
                vec![Phase0CapabilityBlocker {
                    reason: BlockerReason::NonStableSurface,
                    capability,
                    codex_version: CodexVersionEvidence::Detected {
                        version: REQUIRED_CODEX_VERSION,
                    },
                    host_platform: HostPlatform::Macos,
                    observed_surface: surface,
                    live_proof: if capability.requires_live_proof() {
                        LiveProofStatus::Passed
                    } else {
                        LiveProofStatus::NotRequired
                    },
                }],
                "{capability:?} unexpectedly accepted {surface:?} evidence"
            );
        }
    }
}

#[test]
fn every_live_proof_capability_rejects_every_incomplete_proof_state() {
    for capability in REQUIRED_CAPABILITIES
        .into_iter()
        .filter(|capability| capability.requires_live_proof())
    {
        for proof_status in INCOMPLETE_PROOF_STATES {
            let mut evidence = fully_proven_evidence(HostPlatform::Windows);
            evidence_mut(&mut evidence.capabilities, capability).live_proof = proof_status;

            assert_eq!(
                blockers(evaluate_phase0_support(evidence)),
                vec![Phase0CapabilityBlocker {
                    reason: BlockerReason::IncompleteLiveProof,
                    capability,
                    codex_version: CodexVersionEvidence::Detected {
                        version: REQUIRED_CODEX_VERSION,
                    },
                    host_platform: HostPlatform::Windows,
                    observed_surface: EvidenceSurface::Stable,
                    live_proof: proof_status,
                }],
                "{capability:?} unexpectedly accepted {proof_status:?} proof"
            );
        }
    }
}

#[test]
fn version_surface_and_live_proof_blockers_are_reported_together() {
    let mut evidence = fully_proven_evidence(HostPlatform::Windows);
    evidence.codex_version = CodexVersionEvidence::Detected {
        version: CodexVersion::new(0, 145, 0),
    };
    evidence.capabilities.approval_observation.surface = EvidenceSurface::Absent;
    evidence.capabilities.approval_observation.live_proof = LiveProofStatus::NotObserved;

    let blockers = blockers(evaluate_phase0_support(evidence));

    assert_eq!(blockers.len(), 3);
    assert!(
        blockers
            .iter()
            .any(|blocker| { blocker.reason == BlockerReason::UnsupportedCodexVersion })
    );
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker.reason == BlockerReason::NonStableSurface)
    );
    assert!(
        blockers
            .iter()
            .any(|blocker| { blocker.reason == BlockerReason::IncompleteLiveProof })
    );
}

#[test]
fn serialized_blockers_have_a_closed_diagnostic_shape() {
    let mut evidence = fully_proven_evidence(HostPlatform::Linux);
    evidence.capabilities.native_harmless_action.surface = EvidenceSurface::Undocumented;
    evidence.capabilities.native_harmless_action.live_proof = LiveProofStatus::Failed;

    let verdict = evaluate_phase0_support(evidence);
    let serialized = serde_json::to_string(&verdict).expect("verdict must serialize");

    assert!(!serialized.contains("terminal"));
    assert!(!serialized.contains("gui"));
    assert!(!serialized.contains("method"));

    let value = serde_json::to_value(&verdict).expect("verdict must serialize as JSON");
    assert_eq!(value["status"], "blocked");
    let blocker = value["blockers"][0]
        .as_object()
        .expect("blocked verdict must contain typed blocker objects");
    let mut keys: Vec<_> = blocker.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        vec![
            "capability",
            "codex_version",
            "host_platform",
            "live_proof",
            "observed_surface",
            "reason",
        ],
        keys
    );
}

fn fully_proven_evidence(host_platform: HostPlatform) -> Phase0CapabilityEvidence {
    let stable = CapabilityEvidence::new(EvidenceSurface::Stable, LiveProofStatus::NotRequired);
    let proven = CapabilityEvidence::new(EvidenceSurface::Stable, LiveProofStatus::Passed);

    Phase0CapabilityEvidence {
        codex_version: CodexVersionEvidence::Detected {
            version: REQUIRED_CODEX_VERSION,
        },
        host_platform,
        capabilities: CapabilityMatrix {
            handshake: stable,
            session_thread_creation: stable,
            turn_start: stable,
            lifecycle_events: stable,
            approval_observation: proven,
            native_readiness: proven,
            native_harmless_action: proven,
            recovery: proven,
            follow_up_turn: proven,
            detached_turn_ownership: proven,
            interrupt_request: stable,
            confirmed_stop: proven,
        },
    }
}

fn evidence_mut(
    matrix: &mut CapabilityMatrix,
    capability: RequiredCapability,
) -> &mut CapabilityEvidence {
    match capability {
        RequiredCapability::Handshake => &mut matrix.handshake,
        RequiredCapability::SessionThreadCreation => &mut matrix.session_thread_creation,
        RequiredCapability::TurnStart => &mut matrix.turn_start,
        RequiredCapability::LifecycleEvents => &mut matrix.lifecycle_events,
        RequiredCapability::ApprovalObservation => &mut matrix.approval_observation,
        RequiredCapability::NativeReadiness => &mut matrix.native_readiness,
        RequiredCapability::NativeHarmlessAction => &mut matrix.native_harmless_action,
        RequiredCapability::Recovery => &mut matrix.recovery,
        RequiredCapability::FollowUpTurn => &mut matrix.follow_up_turn,
        RequiredCapability::DetachedTurnOwnership => &mut matrix.detached_turn_ownership,
        RequiredCapability::InterruptRequest => &mut matrix.interrupt_request,
        RequiredCapability::ConfirmedStop => &mut matrix.confirmed_stop,
    }
}

fn blockers(verdict: Phase0SupportVerdict) -> Vec<Phase0CapabilityBlocker> {
    match verdict {
        Phase0SupportVerdict::Blocked { blockers } => blockers,
        Phase0SupportVerdict::Supported { .. } => {
            panic!("expected a blocked Phase 0 support verdict")
        }
    }
}

#[test]
fn version_probe_parser_accepts_only_the_canonical_codex_cli_line() {
    let expected = CodexVersionEvidence::Detected {
        version: REQUIRED_CODEX_VERSION,
    };
    assert_eq!(parse_codex_version_output(b"codex-cli 0.144.0\n"), expected);
    assert_eq!(
        parse_codex_version_output(b"codex-cli 0.144.0\r\n"),
        expected
    );

    for malformed in [
        b"codex 0.144.0".as_slice(),
        b" codex-cli 0.144.0".as_slice(),
        b"codex-cli 0.144.0 ".as_slice(),
        b"codex-cli 0.144".as_slice(),
        b"codex-cli 00.144.0".as_slice(),
        b"codex-cli 0.0144.0".as_slice(),
        b"codex-cli 0.144.0-beta.1".as_slice(),
        b"codex-cli 0.144.0\nextra".as_slice(),
        b"codex-cli 0.144.0\n\n".as_slice(),
        b"\xff\xfe".as_slice(),
    ] {
        assert_eq!(
            parse_codex_version_output(malformed),
            CodexVersionEvidence::Malformed
        );
    }

    assert_eq!(
        parse_codex_version_output(&[b'x'; VERSION_OUTPUT_LIMIT as usize]),
        CodexVersionEvidence::Malformed
    );
}

#[test]
fn missing_and_malformed_versions_have_distinct_typed_blockers() {
    for (version, expected_reason) in [
        (
            CodexVersionEvidence::Missing,
            BlockerReason::MissingCodexRuntime,
        ),
        (
            CodexVersionEvidence::Malformed,
            BlockerReason::MalformedCodexVersion,
        ),
        (
            CodexVersionEvidence::Unavailable,
            BlockerReason::CodexVersionUnavailable,
        ),
    ] {
        let mut evidence = fully_proven_evidence(HostPlatform::Windows);
        evidence.codex_version = version;

        let blockers = blockers(evaluate_phase0_support(evidence));
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].reason, expected_reason);
        assert_eq!(blockers[0].codex_version, version);
    }
}

#[test]
fn version_probe_times_out_and_terminates_a_slow_process() {
    let mut command = Command::new(
        std::env::current_exe().expect("the current test executable should be available"),
    );
    command
        .args([
            "--exact",
            "codex_capabilities::tests::slow_version_probe_child",
            "--nocapture",
        ])
        .env("SATELLE_VERSION_PROBE_TEST_CHILD", "slow");
    let started = Instant::now();

    let evidence = probe_codex_version_command(command, Duration::from_millis(50));

    assert_eq!(evidence, CodexVersionEvidence::Unavailable);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the bounded version probe exceeded its termination deadline"
    );
}

#[test]
fn version_probe_terminates_stdout_inheriting_descendants_after_leader_exit() {
    let fixture = super::control_plane_tests::compile_stdio_fixture();
    let mut command = Command::new(fixture.executable());
    command.arg("version-with-descendant");
    let started = Instant::now();

    let evidence = probe_codex_version_command(command, Duration::from_secs(2));

    assert_eq!(
        evidence,
        CodexVersionEvidence::Detected {
            version: REQUIRED_CODEX_VERSION,
        }
    );
    assert!(
        started.elapsed() < Duration::from_millis(2_500),
        "version process-group shutdown waited on a stdout-inheriting descendant"
    );
}

#[cfg(unix)]
#[test]
fn version_probe_deadline_survives_a_group_escaping_pipe_holder() {
    let fixture = super::control_plane_tests::compile_stdio_fixture();
    let mut command = Command::new(fixture.executable());
    command.arg("version-with-escaped-descendant");
    let started = Instant::now();

    let evidence = probe_codex_version_command(command, Duration::from_millis(100));

    assert_eq!(evidence, CodexVersionEvidence::Unavailable);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "an escaped stdout holder exceeded the version probe deadline"
    );
}

#[cfg(unix)]
#[test]
fn cleanup_accepts_only_the_exact_already_reaped_wait_error() {
    let reaped = std::io::Error::from_raw_os_error(rustix::io::Errno::CHILD.raw_os_error());
    let group_gone = std::io::Error::from_raw_os_error(rustix::io::Errno::SRCH.raw_os_error());

    assert!(group_is_reaped(&reaped));
    assert!(!group_is_reaped(&group_gone));
}

#[test]
fn slow_version_probe_child() {
    if std::env::var_os("SATELLE_VERSION_PROBE_TEST_CHILD").as_deref()
        == Some(std::ffi::OsStr::new("slow"))
    {
        thread::sleep(Duration::from_secs(5));
    }
}
