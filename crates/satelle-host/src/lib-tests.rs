use super::*;
use crate::codex_capabilities::{
    CapabilityMatrix, CodexVersionEvidence, HostPlatform, Phase0CapabilityEvidence,
    REQUIRED_CODEX_VERSION,
};
use satelle_core::ErrorCode;

#[test]
fn unsupported_or_unproven_production_execution_is_blocked_before_admission() {
    for (name, evidence) in [
        (
            "unsupported-platform",
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: HostPlatform::Linux,
                capabilities: CapabilityMatrix::unproven(),
            },
        ),
        (
            "missing-runtime",
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Missing,
                host_platform: HostPlatform::Windows,
                capabilities: CapabilityMatrix::unproven(),
            },
        ),
    ] {
        let state = TestStateDir::new().expect("temporary state directory should exist");
        let state_path = state.path().join(format!("{name}.json"));
        let snapshot = Arc::new(RwLock::new(capability_snapshot(evidence, 7)));
        let adapter = ProductionComputerUseAdapter::new(
            Arc::clone(&snapshot),
            Ok(state.path().join("codex-app-server-work")),
        );
        let service = HostService {
            runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
            mode: HostMode::Production { snapshot },
        };
        let session_id = SessionId::new();

        for error in [
            service
                .run(
                    LOCAL_DEMO_HOST,
                    "PRIVATE_PRODUCTION_PROMPT",
                    TurnExecutionMode::Standard,
                )
                .expect_err("attached run must be blocked"),
            service
                .run_detached(
                    LOCAL_DEMO_HOST,
                    "PRIVATE_PRODUCTION_PROMPT",
                    TurnExecutionMode::Standard,
                )
                .expect_err("detached run must be blocked"),
            service
                .steer(
                    &session_id,
                    "PRIVATE_PRODUCTION_PROMPT",
                    TurnExecutionMode::Standard,
                )
                .expect_err("attached steer must be blocked before session lookup"),
            service
                .steer_detached(
                    &session_id,
                    "PRIVATE_PRODUCTION_PROMPT",
                    TurnExecutionMode::Standard,
                )
                .expect_err("detached steer must be blocked before session lookup"),
        ] {
            assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
            let serialized =
                serde_json::to_string(&error).expect("closed capability blocker must serialize");
            assert!(!serialized.contains("PRIVATE_PRODUCTION_PROMPT"));
            assert!(!serialized.contains("fake"));
        }

        let stop_error = service
            .stop(&session_id)
            .expect_err("stop should remain available without adapter readiness");
        assert_eq!(stop_error.code, ErrorCode::SessionNotFound);

        let status_error = service
            .status(&session_id)
            .expect_err("read-only status should open storage without adapter readiness");
        assert_eq!(status_error.code, ErrorCode::SessionNotFound);

        assert!(
            !state_path.exists(),
            "blocked production execution must not create {state_path:?}"
        );
    }
}

#[test]
fn refreshed_production_snapshot_updates_admission_surfaces_but_not_desktop_discovery() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let initial = ProductionCapabilitySnapshot {
        verdict: Phase0SupportVerdict::Supported {
            codex_version: REQUIRED_CODEX_VERSION,
            host_platform: HostPlatform::Windows,
        },
        control_plane_admission: codex_capabilities::ControlPlaneAdmission::not_applicable(),
        started_at: "2026-07-09T00:00:00Z".to_string(),
        finished_at: "2026-07-09T00:00:01Z".to_string(),
        duration_ms: 7,
    };
    let snapshot = Arc::new(RwLock::new(initial));
    let adapter = ProductionComputerUseAdapter::new(
        Arc::clone(&snapshot),
        Ok(state.path().join("codex-app-server-work")),
    );
    let shared_snapshot = Arc::clone(&snapshot);
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
        mode: HostMode::Production { snapshot },
    };
    let clone = service.clone();

    let initial_error = service
        .run(
            LOCAL_DEMO_HOST,
            "PRIVATE_BEFORE_CONTROL_PLANE_REFRESH",
            TurnExecutionMode::Standard,
        )
        .expect_err("the supported snapshot should reach the native execution blocker");
    assert_eq!(initial_error.code, ErrorCode::NotImplemented);
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
            "PRIVATE_AFTER_CONTROL_PLANE_REFRESH",
            TurnExecutionMode::Standard,
        )
        .expect_err("the cloned service must use refreshed admission");
    assert_eq!(refreshed_error.code, ErrorCode::IncompatibleControlPlane);
    assert!(!clone.daemon_runtime_capabilities().unwrap().codex_runtime());
    let sessions = clone
        .host_sessions(LOCAL_DEMO_HOST, false)
        .expect("desktop discovery must remain available for readiness diagnosis");
    assert_eq!(sessions.schema_version, HostSessionsSchemaVersion::V1);
    assert_eq!(sessions.host, LOCAL_DEMO_HOST);
    let doctor = clone
        .doctor(LOCAL_DEMO_HOST, Some("codex"), false)
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

fn capability_snapshot(
    evidence: Phase0CapabilityEvidence,
    duration_ms: u64,
) -> ProductionCapabilitySnapshot {
    ProductionCapabilitySnapshot {
        verdict: evaluate_phase0_support(evidence),
        control_plane_admission: codex_capabilities::ControlPlaneAdmission::not_applicable(),
        started_at: "2026-07-09T00:00:00Z".to_string(),
        finished_at: "2026-07-09T00:00:01Z".to_string(),
        duration_ms,
    }
}
