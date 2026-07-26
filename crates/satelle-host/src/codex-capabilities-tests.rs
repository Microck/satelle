use super::*;

const INCOMPLETE_PROOF_STATES: [LiveProofStatus; 3] = [
    LiveProofStatus::NotRequired,
    LiveProofStatus::NotObserved,
    LiveProofStatus::Failed,
];
const NON_STABLE_SURFACES: [EvidenceSurface; 5] = [
    EvidenceSurface::Private,
    EvidenceSurface::Experimental,
    EvidenceSurface::Undocumented,
    EvidenceSurface::Absent,
    EvidenceSurface::Incomplete,
];
const WINDOWS_APP_POLICY_FIXTURE_HOME: &str = "SATELLE_WINDOWS_APP_POLICY_FIXTURE_HOME";
const WINDOWS_APP_POLICY_FIXTURE_COMPILE_TIMEOUT: Duration = Duration::from_secs(30);
const WINDOWS_APP_POLICY_FIXTURE_SOURCE: &str = r##"
use std::io::{BufRead, Read, Write};

fn main() {
    let mode = std::env::args().nth(1).expect("fixture mode");
    let codex_home = std::env::var("SATELLE_WINDOWS_APP_POLICY_FIXTURE_HOME")
        .expect("fixture Codex home");
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    input.read_line(&mut line).expect("read initialize request");
    assert!(line.contains("\"method\":\"initialize\""));

    let mut output = std::io::stdout().lock();
    writeln!(output, "{{\"method\":\"fixture/notification\",\"params\":{{}}}}")
        .expect("write notification");
    writeln!(
        output,
        "{{\"id\":1,\"result\":{{\"userAgent\":\"fixture\",\"codexHome\":\"{}\",\"platformFamily\":\"windows\",\"platformOs\":\"windows\"}}}}",
        json_escape(&codex_home)
    )
    .expect("write initialize response");
    output.flush().expect("flush initialize response");

    line.clear();
    input.read_line(&mut line).expect("read initialized notification");
    assert!(line.contains("\"method\":\"initialized\""));
    line.clear();
    input.read_line(&mut line).expect("read config request");
    assert!(line.contains("\"method\":\"config/read\""));
    if mode == "defaults" {
        assert!(line.contains("\"includeLayers\":false"));
    } else {
        assert!(line.contains("\"includeLayers\":true"));
    }

    let (effective_config, origins, layer_config) = match mode.as_str() {
        "stable" => (
            "{}",
            "{}",
            r#"{"computer_use":{"windows":{"always_allowed_app_ids":["fixture-paint.exe"]}}}"#,
        ),
        "legacy" => ("{}", "{}", "{}"),
        "defaults" => (
            r#"{"model":"gpt-effective","model_provider":"openai-effective"}"#,
            r#"{"model":{"type":"user","file":"PRIVATE_PATH_CANARY"},"model_provider":{"type":"sessionFlags","hash":"PRIVATE_HASH_CANARY"}}"#,
            r#"{"private_flattened_canary":"PRIVATE_LAYER_CANARY"}"#,
        ),
        _ => std::process::exit(2),
    };
    let config_file = std::path::Path::new(&codex_home).join("config.toml");
    writeln!(
        output,
        "{{\"id\":2,\"result\":{{\"config\":{effective_config},\"origins\":{origins},\"layers\":[{{\"name\":{{\"type\":\"user\",\"file\":\"{}\",\"profile\":null}},\"version\":\"fixture\",\"config\":{layer_config},\"disabledReason\":null}}]}}}}",
        json_escape(&config_file.display().to_string()),
    )
    .expect("write config response");
    output.flush().expect("flush config response");

    let mut rest = String::new();
    input.read_to_string(&mut rest).expect("wait for probe shutdown");
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            character if character.is_control() => panic!("control character in fixture path"),
            character => escaped.push(character),
        }
    }
    escaped
}
"##;

struct CompiledWindowsAppPolicyFixture {
    _directory: tempfile::TempDir,
    executable: std::path::PathBuf,
}

fn compile_windows_app_policy_fixture() -> CompiledWindowsAppPolicyFixture {
    let directory = tempfile::tempdir().expect("create Windows app-policy fixture directory");
    let source = directory.path().join("windows-app-policy-fixture.rs");
    std::fs::write(&source, WINDOWS_APP_POLICY_FIXTURE_SOURCE)
        .expect("write Windows app-policy fixture source");
    let executable = directory.path().join(if cfg!(windows) {
        "windows-app-policy-fixture.exe"
    } else {
        "windows-app-policy-fixture"
    });
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiler_stderr_path = directory.path().join("rustc.stderr");
    let compiler_stderr = std::fs::File::create(&compiler_stderr_path)
        .expect("create Windows app-policy compiler stderr fixture");
    let mut compiler_command = Command::new(rustc);
    compiler_command
        .arg(&source)
        .arg("--edition=2024")
        .arg("-o")
        .arg(&executable)
        .stdout(Stdio::null())
        .stderr(Stdio::from(compiler_stderr));
    let mut compiler = compiler_command
        .group_spawn()
        .expect("spawn Windows app-policy fixture compiler");
    let compile_deadline = Instant::now() + WINDOWS_APP_POLICY_FIXTURE_COMPILE_TIMEOUT;
    let output_status = match wait_for_group(&mut compiler, compile_deadline) {
        GroupWaitOutcome::Exited(status) => status,
        GroupWaitOutcome::Deadline => {
            assert!(
                terminate_group(&mut compiler),
                "terminate stalled fixture compiler"
            );
            panic!("Windows app-policy fixture compilation timed out");
        }
        GroupWaitOutcome::Error => {
            let _ = terminate_group(&mut compiler);
            panic!("Windows app-policy fixture compiler wait failed");
        }
    };
    assert!(
        terminate_group(&mut compiler),
        "clean up Windows app-policy fixture compiler"
    );
    let compiler_stderr = std::fs::read_to_string(compiler_stderr_path)
        .expect("read Windows app-policy compiler stderr fixture");
    assert!(
        output_status.success(),
        "Windows app-policy fixture compilation failed: {}",
        compiler_stderr
    );
    CompiledWindowsAppPolicyFixture {
        _directory: directory,
        executable,
    }
}

fn windows_app_policy_fixture_command(
    fixture: &CompiledWindowsAppPolicyFixture,
    mode: &str,
    codex_home: &std::path::Path,
) -> Command {
    let mut command = Command::new(&fixture.executable);
    command
        .arg(mode)
        .env(WINDOWS_APP_POLICY_FIXTURE_HOME, codex_home);
    command
}

fn windows_config_read_result(
    codex_home: &std::path::Path,
    config: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "config": {},
        "origins": {},
        "layers": [{
            "name": {
                "type": "user",
                "file": codex_home.join("config.toml").display().to_string(),
                "profile": null,
            },
            "version": "fixture",
            "config": config,
            "disabledReason": null,
        }]
    })
}

#[test]
fn effective_defaults_probe_keeps_only_the_model_pair_and_closed_origins() {
    let fixture = compile_windows_app_policy_fixture();
    let codex_home = tempfile::tempdir().expect("create deterministic Codex home");
    let defaults = probe_effective_codex_defaults_with(
        windows_app_policy_fixture_command(&fixture, "defaults", codex_home.path()),
        Duration::from_secs(3),
    )
    .expect("read effective Codex defaults");

    assert_eq!(defaults.model(), "gpt-effective");
    assert_eq!(defaults.model_provider(), "openai-effective");
    assert_eq!(defaults.model_origin(), CodexConfigOriginClass::User);
    assert_eq!(
        defaults.model_provider_origin(),
        CodexConfigOriginClass::Session
    );
    let debug = format!("{defaults:?}");
    assert!(!debug.contains("PRIVATE_PATH_CANARY"));
    assert!(!debug.contains("PRIVATE_HASH_CANARY"));
    assert!(!debug.contains("PRIVATE_LAYER_CANARY"));
}

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
fn platform_policy_keeps_controller_support_distinct_from_native_host_support() {
    for (platform, supports_native_computer_use) in [
        (HostPlatform::Macos, true),
        (HostPlatform::Windows, true),
        (HostPlatform::Linux, false),
        (HostPlatform::Other, false),
    ] {
        assert_eq!(
            platform.supports_native_computer_use(),
            supports_native_computer_use,
            "{platform:?} used another platform's native Computer Use policy"
        );
    }
}

#[test]
fn compiled_host_uses_its_own_platform_capability_policy() {
    let expected = if cfg!(target_os = "macos") {
        HostPlatform::Macos
    } else if cfg!(target_os = "windows") {
        HostPlatform::Windows
    } else if cfg!(target_os = "linux") {
        HostPlatform::Linux
    } else {
        HostPlatform::Other
    };

    assert_eq!(HostPlatform::current(), expected);
    assert_eq!(
        HostPlatform::current().supports_native_computer_use(),
        matches!(expected, HostPlatform::Macos | HostPlatform::Windows)
    );
}

#[test]
fn current_windows_app_policy_is_stable_and_does_not_retain_app_ids() {
    let codex_home = tempfile::TempDir::new().expect("create deterministic Codex home");
    std::fs::create_dir(codex_home.path().join("computer-use"))
        .expect("create legacy policy directory");
    std::fs::write(
        codex_home.path().join("computer-use/config.toml"),
        "[apps]\ndenied = [\"sensitive-admin-app.exe\"]\n",
    )
    .expect("write ignored legacy denied list");
    std::fs::write(
        codex_home.path().join("config.toml"),
        concat!(
            "model = \"fixture\"\n",
            "[computer_use.windows]\n",
            "always_allowed_app_ids = [\"fixture-paint.exe\"]\n",
        ),
    )
    .expect("write current Windows app policy");

    let config_result = windows_config_read_result(
        codex_home.path(),
        serde_json::json!({
            "computer_use": {
                "windows": {
                    "always_allowed_app_ids": ["fixture-paint.exe"]
                }
            }
        }),
    );
    let surface = classify_windows_app_policy(codex_home.path(), &config_result);

    assert_eq!(surface, EvidenceSurface::Stable);
    let serialized = serde_json::to_string(&surface).expect("serialize closed evidence surface");
    assert_eq!(serialized, "\"stable\"");
    assert!(!serialized.contains("fixture-paint"));
    assert!(!serialized.contains(&codex_home.path().display().to_string()));
}

#[test]
fn legacy_allow_list_is_private_migration_input() {
    let codex_home = tempfile::TempDir::new().expect("create deterministic Codex home");
    std::fs::create_dir(codex_home.path().join("computer-use"))
        .expect("create legacy policy directory");
    std::fs::write(
        codex_home.path().join("computer-use/config.toml"),
        concat!(
            "[apps]\n",
            "allowed = [\n",
            "  \"fixture-paint.exe\", # a desktop executable id\n",
            "  'Fixture.Package_123!App',\n",
            "]\n",
            "denied = [\"ignored-denied-app.exe\"]\n",
        ),
    )
    .expect("write legacy app policy");

    assert_eq!(
        classify_windows_app_policy(
            codex_home.path(),
            &windows_config_read_result(codex_home.path(), serde_json::json!({})),
        ),
        EvidenceSurface::Private
    );
}

#[test]
fn removed_legacy_denied_list_is_never_an_app_policy_fallback() {
    let codex_home = tempfile::TempDir::new().expect("create deterministic Codex home");
    std::fs::create_dir(codex_home.path().join("computer-use"))
        .expect("create legacy policy directory");
    std::fs::write(
        codex_home.path().join("computer-use/config.toml"),
        "[apps]\ndenied = [\"fixture-calculator.exe\"]\n",
    )
    .expect("write denied-only legacy policy");

    assert_eq!(
        classify_windows_app_policy(
            codex_home.path(),
            &windows_config_read_result(codex_home.path(), serde_json::json!({})),
        ),
        EvidenceSurface::Absent
    );
}

#[test]
fn malformed_current_or_legacy_allow_lists_are_incomplete() {
    let legacy_home = tempfile::TempDir::new().expect("create legacy Codex home");
    std::fs::create_dir(legacy_home.path().join("computer-use"))
        .expect("create legacy policy directory");
    std::fs::write(
        legacy_home.path().join("computer-use/config.toml"),
        "[apps]\nallowed = [\"unterminated.exe\"\n",
    )
    .expect("write malformed legacy policy");

    assert_eq!(
        classify_windows_app_policy(
            legacy_home.path(),
            &windows_config_read_result(legacy_home.path(), serde_json::json!({})),
        ),
        EvidenceSurface::Incomplete
    );

    let current_home = tempfile::TempDir::new().expect("create current Codex home");
    std::fs::write(
        current_home.path().join("config.toml"),
        "[computer_use.windows]\nalways_allowed_app_ids = \"fixture-paint.exe\"\n",
    )
    .expect("write malformed current policy");
    let malformed_result = windows_config_read_result(
        current_home.path(),
        serde_json::json!({
            "computer_use": {
                "windows": {
                    "always_allowed_app_ids": "fixture-paint.exe"
                }
            }
        }),
    );
    assert_eq!(
        classify_windows_app_policy(current_home.path(), &malformed_result),
        EvidenceSurface::Incomplete
    );
}

#[test]
fn missing_current_and_legacy_windows_app_policy_is_absent() {
    let codex_home = tempfile::TempDir::new().expect("create deterministic Codex home");

    assert_eq!(
        classify_windows_app_policy(
            codex_home.path(),
            &windows_config_read_result(codex_home.path(), serde_json::json!({})),
        ),
        EvidenceSurface::Absent
    );
}

#[test]
fn process_probe_resolves_codex_home_before_classifying_legacy_input() {
    let codex_home = tempfile::TempDir::new().expect("create deterministic Codex home");
    std::fs::create_dir(codex_home.path().join("computer-use"))
        .expect("create legacy policy directory");
    std::fs::write(
        codex_home.path().join("computer-use/config.toml"),
        "[apps]\nallowed = [\"fixture-paint.exe\"]\n",
    )
    .expect("write legacy policy fixture");
    let fixture = compile_windows_app_policy_fixture();
    let command = windows_app_policy_fixture_command(&fixture, "legacy", codex_home.path());

    assert_eq!(
        probe_windows_app_policy_with(command, Duration::from_secs(2)),
        EvidenceSurface::Private
    );
}

#[test]
fn a_stable_app_allow_list_does_not_prove_sensitive_action_approval() {
    let codex_home = tempfile::TempDir::new().expect("create deterministic Codex home");
    std::fs::write(
        codex_home.path().join("config.toml"),
        "[computer_use.windows]\nalways_allowed_app_ids = []\n",
    )
    .expect("write empty stable policy");
    let config_result = windows_config_read_result(
        codex_home.path(),
        serde_json::json!({
            "computer_use": {
                "windows": {
                    "always_allowed_app_ids": []
                }
            }
        }),
    );
    let surface = classify_windows_app_policy(codex_home.path(), &config_result);
    let mut evidence = fully_proven_evidence(HostPlatform::Windows);
    evidence.capabilities.approval_observation =
        CapabilityEvidence::new(surface, LiveProofStatus::NotObserved);

    assert_eq!(
        blockers(evaluate_phase0_support(evidence)),
        vec![Phase0CapabilityBlocker {
            reason: BlockerReason::IncompleteLiveProof,
            capability: RequiredCapability::ApprovalObservation,
            codex_version: CodexVersionEvidence::Detected {
                version: REQUIRED_CODEX_VERSION,
            },
            host_platform: HostPlatform::Windows,
            observed_surface: EvidenceSurface::Stable,
            live_proof: LiveProofStatus::NotObserved,
        }]
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_ci_observes_the_native_app_policy_fixture() {
    assert_eq!(HostPlatform::current(), HostPlatform::Windows);
    let codex_home = tempfile::TempDir::new().expect("create Windows Codex home fixture");
    std::fs::write(
        codex_home.path().join("config.toml"),
        "[computer_use.windows]\nalways_allowed_app_ids = [\"mspaint.exe\"]\n",
    )
    .expect("write Windows current app-policy fixture");
    let fixture = compile_windows_app_policy_fixture();
    let command = windows_app_policy_fixture_command(&fixture, "stable", codex_home.path());

    assert_eq!(
        probe_windows_app_policy_with(command, Duration::from_secs(2)),
        EvidenceSurface::Stable
    );
}

#[test]
fn absent_native_surface_reports_the_private_execution_path_blocker() {
    for capability in [
        RequiredCapability::NativeReadiness,
        RequiredCapability::NativeHarmlessAction,
    ] {
        let mut evidence = fully_proven_evidence(HostPlatform::Windows);
        evidence_mut(&mut evidence.capabilities, capability).surface = EvidenceSurface::Absent;

        assert_eq!(
            blockers(evaluate_phase0_support(evidence)),
            vec![Phase0CapabilityBlocker {
                reason: BlockerReason::NativeExecutionPathUnavailable,
                capability,
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: HostPlatform::Windows,
                observed_surface: EvidenceSurface::Absent,
                live_proof: LiveProofStatus::Passed,
            }],
            "{capability:?} did not identify the missing private execution path"
        );
    }
}

#[test]
fn unproven_control_plane_does_not_claim_the_private_native_path_was_queried() {
    let evidence = Phase0CapabilityEvidence {
        codex_version: CodexVersionEvidence::Missing,
        host_platform: HostPlatform::Windows,
        capabilities: CapabilityMatrix::unproven(),
    };

    assert!(
        blockers(evaluate_phase0_support(evidence))
            .iter()
            .all(|blocker| blocker.reason != BlockerReason::NativeExecutionPathUnavailable)
    );
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
                    reason: surface_blocker_reason(evidence.capabilities, capability),
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

#[test]
fn termination_reaps_an_already_exited_empty_process_group() {
    let mut command = Command::new(
        std::env::current_exe().expect("the current test executable should be available"),
    );
    command
        .args(["--exact", "no_test_has_this_name", "--nocapture"])
        .stdout(Stdio::piped());
    let mut child = command.group_spawn().expect("spawn empty process group");
    let mut stdout = child.inner().stdout.take().expect("capture child stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("observe process-group leader exit");

    assert!(
        terminate_group(&mut child),
        "an already-exited empty process group must be proven reaped"
    );
}

#[cfg(unix)]
#[test]
fn leader_reap_respects_an_expired_deadline() {
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
    let mut child = command.group_spawn().expect("spawn live process group");

    assert!(
        !reap_group_leader(&mut child, Instant::now()),
        "leader reaping must not block beyond an expired cleanup deadline"
    );
    assert!(
        terminate_group(&mut child),
        "the live fixture process group must still be cleaned up"
    );
}

#[test]
fn repeated_interrupted_kill_retries_stop_at_the_shared_deadline() {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(500);
    let mut attempts = 0;
    let mut observations = [start, start, deadline].into_iter();

    let error = retry_interrupted_until(
        deadline,
        || {
            attempts += 1;
            Err::<(), _>(std::io::Error::from(ErrorKind::Interrupted))
        },
        || observations.next().unwrap_or(deadline),
    )
    .expect_err("repeated EINTR must stop at the cleanup deadline");

    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(attempts, 2);
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
