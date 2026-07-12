#[path = "api-auth.rs"]
mod api_auth;
mod codex_capabilities;
mod daemon;
#[path = "live-events.rs"]
mod live_events;
#[path = "log-page.rs"]
mod log_page;
#[path = "process-identity.rs"]
mod process_identity;
mod runtime;
mod storage;
#[cfg(any(test, feature = "test-support"))]
#[path = "test-runtime.rs"]
mod test_runtime;

pub use api_auth::{ApiBearerToken, ApiBearerTokenError, ApiPrincipal, ApiScopes};
use codex_capabilities::{
    BlockerReason, CodexVersionEvidence, Phase0CapabilityBlocker, Phase0SupportVerdict,
    RequiredCapability, discover_phase0, evaluate_phase0_support,
};
pub use daemon::{
    DaemonRuntimeCapabilities, DaemonRuntimeStatus, MutationAuthority, MutationAuthorityError,
    StopAdmission, TurnIntent, TurnIntentError,
};
pub use live_events::{LiveEventReceiveError, LiveEventSubscription};
pub use log_page::{
    DaemonLogEntry, DaemonLogPage, LogCursor, LogCursorError, LogEvent, LogPageMode, LogPageQuery,
    LogPageQueryError, LogSeverity, LogSource, LogSubject,
};
pub use runtime::{
    AdapterReadiness, AdapterSubject, ComputerUseAdapter, EvidenceError, ExecuteRequest,
    ExecuteResult, ProviderSmokeEvidence, ReadinessEvidence, RecoveryObservation,
};
use runtime::{
    BlockedComputerUseAdapter, LogQuery, RunCommand, RuntimeHandle, SteerCommand, StopCommand,
};
use satelle_core::{
    DaemonPathOverrides, DoctorFinding, DoctorFixability, DoctorProbeResult, DoctorReport,
    DoctorSchemaVersion, DoctorSummary, HostSessionsReport, LOCAL_DEMO_HOST, LogEntry,
    SatelleError, SatelleEvent, SessionId, SessionRecord, SetupReadinessSummary, SetupReport,
    SetupSchemaVersion, StopResult, object_value, utc_now,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::Instant;
#[cfg(any(test, feature = "test-support"))]
use test_runtime::FakeComputerUseAdapter;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    pub use crate::storage::TestStateDir;
}

#[cfg(test)]
use test_support::TestStateDir;

#[derive(Clone, Debug)]
pub struct HostService {
    runtime: RuntimeHandle,
    mode: HostMode,
}

#[derive(Clone, Debug)]
enum HostMode {
    Production {
        snapshot: Arc<RwLock<ProductionCapabilitySnapshot>>,
    },
    #[cfg(any(test, feature = "test-support"))]
    TestFake,
}

#[derive(Clone, Debug)]
pub(crate) struct ProductionCapabilitySnapshot {
    verdict: Phase0SupportVerdict,
    control_plane_admission: codex_capabilities::ControlPlaneAdmission,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
}

impl ProductionCapabilitySnapshot {
    fn collect() -> Self {
        let started_at = utc_now();
        let started = Instant::now();
        let discovery = discover_phase0();
        let verdict = evaluate_phase0_support(discovery.evidence);
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        Self {
            verdict,
            control_plane_admission: discovery.control_plane_admission,
            started_at,
            finished_at: utc_now(),
            duration_ms,
        }
    }
}

fn read_production_snapshot(
    snapshot: &RwLock<ProductionCapabilitySnapshot>,
) -> Result<RwLockReadGuard<'_, ProductionCapabilitySnapshot>, SatelleError> {
    snapshot.read().map_err(|_| {
        crate::runtime::integrity_error("the production capability snapshot lock was poisoned")
    })
}

fn replace_production_snapshot(
    snapshot: &RwLock<ProductionCapabilitySnapshot>,
    refreshed: ProductionCapabilitySnapshot,
) -> Result<(), SatelleError> {
    *snapshot.write().map_err(|_| {
        crate::runtime::integrity_error("the production capability snapshot lock was poisoned")
    })? = refreshed;
    Ok(())
}

impl HostService {
    /// Builds the only runtime available in normal and release builds. The
    /// constructor retains only typed, diagnostic-safe capability evidence.
    pub fn production() -> Self {
        let snapshot = Arc::new(RwLock::new(ProductionCapabilitySnapshot::collect()));
        let adapter = BlockedComputerUseAdapter::production(Arc::clone(&snapshot));
        Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), adapter),
            mode: HostMode::Production { snapshot },
        }
    }

    /// The deterministic adapter requires both the compile-time feature and a
    /// separate Satelle-owned CLI opt-in. It is not present in default builds.
    #[cfg(feature = "test-support")]
    pub fn local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), FakeComputerUseAdapter),
            mode: HostMode::TestFake,
        })
    }

    pub fn doctor(
        &self,
        host: &str,
        scope: Option<&str>,
        refresh: bool,
    ) -> Result<DoctorReport, SatelleError> {
        ensure_local_demo(host)?;
        if let Some(scope) = scope
            && ![
                "transport",
                "codex",
                "computer-use",
                "provider",
                "config",
                "all",
            ]
            .contains(&scope)
        {
            return Err(SatelleError::invalid_usage("unsupported doctor scope"));
        }
        match &self.mode {
            HostMode::Production { snapshot } if refresh => {
                let refreshed = ProductionCapabilitySnapshot::collect();
                let report = production_doctor_report(host, scope, &refreshed);
                replace_production_snapshot(snapshot, refreshed)?;
                Ok(report)
            }
            HostMode::Production { snapshot } => Ok(production_doctor_report(
                host,
                scope,
                &*read_production_snapshot(snapshot)?,
            )),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake => self.fake_doctor(host, scope, refresh, &FakeComputerUseAdapter),
        }
    }

    pub fn setup(
        &self,
        host: &str,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        ensure_local_demo(host)?;
        match &self.mode {
            HostMode::Production { .. } => Ok(production_setup_report(
                host,
                dry_run,
                setup_mode,
                setup_components,
                daemon_path_overrides,
            )),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake => self.setup_fake(
                host,
                dry_run,
                setup_mode,
                setup_components,
                daemon_path_overrides,
            ),
        }
    }

    pub fn host_status(&self) -> Result<HostStatus, SatelleError> {
        match &self.mode {
            HostMode::Production { .. } => Ok(HostStatus {
                running: false,
                mode: "production-capability-blocked".to_string(),
                sessions: 0,
            }),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake => {
                let snapshot = self.runtime.reconcile_and_snapshot()?;
                Ok(HostStatus {
                    running: true,
                    mode: "local-demo-in-process".to_string(),
                    sessions: snapshot.session_count(),
                })
            }
        }
    }

    pub fn run(&self, host: &str, prompt: &str) -> Result<TurnOutcome, SatelleError> {
        self.runtime
            .run(RunCommand::attached(host, prompt))
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn run_detached(&self, host: &str, prompt: &str) -> Result<SessionRecord, SatelleError> {
        self.runtime
            .run(RunCommand::detached(host, prompt))
            .map(|outcome| outcome.session)
    }

    pub fn steer(&self, session_id: &SessionId, prompt: &str) -> Result<TurnOutcome, SatelleError> {
        self.runtime
            .steer(SteerCommand::attached(session_id.clone(), prompt))
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn steer_detached(
        &self,
        session_id: &SessionId,
        prompt: &str,
    ) -> Result<SessionRecord, SatelleError> {
        self.runtime
            .steer(SteerCommand::detached(session_id.clone(), prompt))
            .map(|outcome| outcome.session)
    }

    pub fn status(&self, session_id: &SessionId) -> Result<SessionRecord, SatelleError> {
        self.runtime.status(session_id.clone())
    }

    pub fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.runtime.stop(StopCommand::new(session_id.clone()))
    }

    pub fn logs(&self, host: &str) -> Result<Vec<LogEntry>, SatelleError> {
        self.runtime.logs(LogQuery::for_host(host))
    }

    pub fn host_sessions(
        &self,
        _host: &str,
        _no_bootstrap: bool,
    ) -> Result<HostSessionsReport, SatelleError> {
        match &self.mode {
            HostMode::Production { snapshot } => Err(execution_blocker(
                &read_production_snapshot(snapshot)?.verdict,
            )),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake => self.host_sessions_fake(_host, _no_bootstrap),
        }
    }
}
fn execution_blocker(verdict: &Phase0SupportVerdict) -> SatelleError {
    if verdict.is_supported() {
        return SatelleError::not_implemented(
            "native Computer Use execution is not implemented after capability admission",
        );
    }

    SatelleError::computer_use_not_ready()
}

fn production_doctor_report(
    host: &str,
    scope: Option<&str>,
    snapshot: &ProductionCapabilitySnapshot,
) -> DoctorReport {
    let selected_scopes = selected_doctor_scopes(scope);
    let capability_recovery = "satelle doctor --scope computer-use --refresh --json";
    let mut findings = snapshot
        .verdict
        .blockers()
        .iter()
        .filter_map(|blocker| {
            let scope = blocker_scope(blocker);
            selected_scopes
                .contains(&scope)
                .then(|| blocker_finding(scope, blocker, capability_recovery))
        })
        .collect::<Vec<_>>();
    if selected_scopes.contains(&"transport") {
        findings.push(unavailable_scope_finding(
            "transport",
            "transport_unavailable",
            "no production Host transport is available",
            "satelle setup --host local-demo --dry-run --json",
        ));
    }
    if selected_scopes.contains(&"provider") {
        findings.push(unavailable_scope_finding(
            "provider",
            "provider_readiness_not_observed",
            "provider readiness has not been observed through a production Host",
            "satelle setup --host local-demo --component provider-auth --dry-run --json",
        ));
    }
    findings.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.finding_id.cmp(&right.finding_id))
    });

    let probe_results = selected_scopes
        .iter()
        .map(|scope| production_probe_result(scope, &findings, snapshot))
        .collect::<Vec<_>>();
    let ready = probe_results.iter().all(|probe| probe.status == "passed");
    let blocking_findings = findings.len()
        + probe_results
            .iter()
            .filter(|probe| probe.status == "blocked" && probe.finding_ids.is_empty())
            .count();
    let mut recovery_commands = findings
        .iter()
        .filter_map(|finding| finding.recovery_command.clone())
        .collect::<Vec<_>>();
    recovery_commands.sort();
    recovery_commands.dedup();

    DoctorReport {
        schema_version: DoctorSchemaVersion::V1,
        status: if ready { "ready" } else { "blocked" }.to_string(),
        target: host.to_string(),
        host: host.to_string(),
        scopes: selected_scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect(),
        started_at: snapshot.started_at.clone(),
        finished_at: snapshot.finished_at.clone(),
        duration_ms: snapshot.duration_ms,
        summary: DoctorSummary {
            ready,
            blocking_findings,
            repairable_findings: 0,
            informational_findings: 0,
        },
        probe_results,
        ready,
        findings,
        recovery_commands,
        changed: false,
        cache_updates: Vec::new(),
    }
}

fn selected_doctor_scopes(scope: Option<&str>) -> Vec<&'static str> {
    match scope {
        None | Some("all") => vec!["codex", "computer-use", "config", "provider", "transport"],
        Some("codex") => vec!["codex"],
        Some("computer-use") => vec!["computer-use"],
        Some("config") => vec!["config"],
        Some("provider") => vec!["provider"],
        Some("transport") => vec!["transport"],
        Some(_) => Vec::new(),
    }
}

fn blocker_scope(blocker: &Phase0CapabilityBlocker) -> &'static str {
    match blocker.reason {
        BlockerReason::MissingCodexRuntime
        | BlockerReason::MalformedCodexVersion
        | BlockerReason::CodexVersionUnavailable
        | BlockerReason::UnsupportedCodexVersion => "codex",
        BlockerReason::UnsupportedHostPlatform => "computer-use",
        BlockerReason::NonStableSurface | BlockerReason::IncompleteLiveProof => {
            capability_scope(blocker.capability)
        }
    }
}

fn capability_scope(capability: RequiredCapability) -> &'static str {
    match capability {
        RequiredCapability::Handshake
        | RequiredCapability::SessionThreadCreation
        | RequiredCapability::TurnStart
        | RequiredCapability::LifecycleEvents => "codex",
        RequiredCapability::ApprovalObservation
        | RequiredCapability::NativeReadiness
        | RequiredCapability::NativeHarmlessAction
        | RequiredCapability::Recovery
        | RequiredCapability::FollowUpTurn
        | RequiredCapability::DetachedTurnOwnership
        | RequiredCapability::InterruptRequest
        | RequiredCapability::ConfirmedStop => "computer-use",
    }
}

fn unavailable_scope_finding(
    scope: &str,
    reason: &str,
    summary: &str,
    recovery_command: &str,
) -> DoctorFinding {
    DoctorFinding {
        finding_id: format!("production.{scope}.{reason}"),
        scope: scope.to_string(),
        severity: "error".to_string(),
        fixability: DoctorFixability::Blocked,
        readiness_impact: "blocked".to_string(),
        summary: summary.to_string(),
        evidence: vec![format!("reason={reason}")],
        recovery_command: Some(recovery_command.to_string()),
    }
}

fn production_probe_result(
    scope: &str,
    findings: &[DoctorFinding],
    snapshot: &ProductionCapabilitySnapshot,
) -> DoctorProbeResult {
    let finding_ids = findings
        .iter()
        .filter(|finding| finding.scope == scope)
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    let blockers = snapshot.verdict.blockers();
    let computer_use_blocked_by_codex = scope == "computer-use"
        && blockers
            .iter()
            .any(|blocker| blocker_scope(blocker) == "codex");
    // Codex probing is deliberately skipped when native Computer Use cannot
    // run on the host. The unobserved control-plane gate is blocked rather
    // than mislabeled as passed, without inventing a Codex-specific finding.
    let codex_blocked_by_platform = scope == "codex"
        && blockers
            .iter()
            .any(|blocker| blocker.reason == BlockerReason::UnsupportedHostPlatform);
    let dependency_blocked = computer_use_blocked_by_codex || codex_blocked_by_platform;
    let blocked = !finding_ids.is_empty() || dependency_blocked;
    let capability_probe = matches!(scope, "codex" | "computer-use");
    let (started_at, finished_at, duration_ms) = if capability_probe {
        (
            snapshot.started_at.clone(),
            snapshot.finished_at.clone(),
            snapshot.duration_ms,
        )
    } else {
        (
            snapshot.finished_at.clone(),
            snapshot.finished_at.clone(),
            0,
        )
    };

    DoctorProbeResult {
        probe_id: match scope {
            "codex" => "codex.phase0_capability_gate",
            "computer-use" => "computer-use.phase0_capability_gate",
            "config" => "config.selected_host_resolution",
            "provider" => "provider.production_readiness",
            "transport" => "transport.production_availability",
            _ => "unknown.invalid_scope",
        }
        .to_string(),
        scope: scope.to_string(),
        status: if blocked { "blocked" } else { "passed" }.to_string(),
        started_at,
        finished_at,
        duration_ms,
        cache_status: "not_persisted".to_string(),
        dependency_status: if dependency_blocked {
            "blocked"
        } else {
            "satisfied"
        }
        .to_string(),
        finding_ids,
    }
}

fn blocker_finding(
    scope: &str,
    blocker: &Phase0CapabilityBlocker,
    recovery_command: &str,
) -> DoctorFinding {
    DoctorFinding {
        finding_id: format!(
            "phase0.{}.{}",
            blocker.capability.as_str(),
            blocker.reason.as_str()
        ),
        scope: scope.to_string(),
        severity: "error".to_string(),
        fixability: DoctorFixability::Blocked,
        readiness_impact: "blocked".to_string(),
        summary: blocker_summary(blocker).to_string(),
        evidence: vec![
            format!("reason={}", blocker.reason.as_str()),
            format!("capability={}", blocker.capability.as_str()),
            version_evidence(blocker.codex_version),
            format!("host_platform={}", blocker.host_platform.as_str()),
            format!("observed_surface={}", blocker.observed_surface.as_str()),
            format!("live_proof={}", blocker.live_proof.as_str()),
        ],
        recovery_command: Some(recovery_command.to_string()),
    }
}

fn blocker_summary(blocker: &Phase0CapabilityBlocker) -> &'static str {
    use codex_capabilities::BlockerReason;

    match blocker.reason {
        BlockerReason::MissingCodexRuntime => "the Codex runtime was not found",
        BlockerReason::MalformedCodexVersion => "the Codex version response was malformed",
        BlockerReason::CodexVersionUnavailable => "the Codex version probe was unavailable",
        BlockerReason::UnsupportedCodexVersion => "the installed Codex version is unsupported",
        BlockerReason::UnsupportedHostPlatform => {
            "native Computer Use is unsupported on this host platform"
        }
        BlockerReason::NonStableSurface => {
            "a required capability lacks evidence from the stable surface"
        }
        BlockerReason::IncompleteLiveProof => "a required capability lacks passing live-host proof",
    }
}

fn version_evidence(evidence: CodexVersionEvidence) -> String {
    match evidence {
        CodexVersionEvidence::Detected { version } => format!("codex_version={version}"),
        evidence => format!("codex_version_status={}", evidence.status_name()),
    }
}

fn production_setup_report(
    host: &str,
    dry_run: bool,
    setup_mode: String,
    setup_components: Vec<String>,
    daemon_path_overrides: DaemonPathOverrides,
) -> SetupReport {
    let service_persistent = setup_mode == "persistent";
    let service_scope = if service_persistent {
        "user"
    } else {
        "on_demand"
    };
    let daemon_path_overrides = daemon_path_overrides.entries();
    let mut planned_actions = vec![
        "resolve the configured local host".to_string(),
        "report the current standalone Codex admission state".to_string(),
        "keep native Computer Use blocked until stable schema and live-host proof pass".to_string(),
    ];
    planned_actions.extend(daemon_path_overrides.iter().map(|override_entry| {
        format!(
            "map {}={} in Satelle-owned service configuration",
            override_entry.environment_variable, override_entry.value
        )
    }));

    SetupReport {
        schema_version: SetupSchemaVersion::V1,
        host: host.to_string(),
        dry_run,
        status: "planned".to_string(),
        setup_mode,
        service_persistent,
        service_scope: service_scope.to_string(),
        fallback_reason: None,
        setup_components,
        planned_actions,
        applied_actions: Vec::new(),
        required_input: Vec::new(),
        recovery_commands: vec!["satelle doctor --scope computer-use --refresh --json".to_string()],
        readiness_summary: SetupReadinessSummary {
            transport: "not_available".to_string(),
            host_daemon: "not_installed".to_string(),
            codex_runtime: "not_ready".to_string(),
            native_computer_use: "blocked_pending_acceptance".to_string(),
            provider_auth: "not_checked".to_string(),
        },
        daemon_path_overrides,
        mutated: false,
        native_computer_use_readiness: "blocked_pending_acceptance".to_string(),
        next_command: "satelle doctor --scope computer-use --refresh --json".to_string(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostStatus {
    pub running: bool,
    pub mode: String,
    pub sessions: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TurnOutcome {
    pub session: SessionRecord,
    pub events: Vec<SatelleEvent>,
}

fn ensure_local_demo(host: &str) -> Result<(), SatelleError> {
    if host == LOCAL_DEMO_HOST {
        return Ok(());
    }

    Err(SatelleError::not_implemented(format!(
        "host '{host}' is configured, but only local-demo execution is implemented in this MVP skeleton"
    )))
}

pub fn health_route() -> Value {
    object_value([
        ("status", json!("ok")),
        ("service", json!("satelle-host")),
        ("mode", json!("production-capability-gated")),
    ])
}

pub fn readiness_route() -> Value {
    object_value([
        ("ready", json!(false)),
        ("adapter", json!("codex")),
        ("host", json!(LOCAL_DEMO_HOST)),
        ("blocker", json!("computer-use-not-ready")),
    ])
}

#[cfg(test)]
mod tests {
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
            let adapter = BlockedComputerUseAdapter::production(Arc::clone(&snapshot));
            let service = HostService {
                runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
                mode: HostMode::Production { snapshot },
            };
            let session_id = SessionId::new();

            for error in [
                service
                    .run(LOCAL_DEMO_HOST, "PRIVATE_PRODUCTION_PROMPT")
                    .expect_err("attached run must be blocked"),
                service
                    .run_detached(LOCAL_DEMO_HOST, "PRIVATE_PRODUCTION_PROMPT")
                    .expect_err("detached run must be blocked"),
                service
                    .steer(&session_id, "PRIVATE_PRODUCTION_PROMPT")
                    .expect_err("attached steer must be blocked before session lookup"),
                service
                    .steer_detached(&session_id, "PRIVATE_PRODUCTION_PROMPT")
                    .expect_err("detached steer must be blocked before session lookup"),
            ] {
                assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
                let serialized = serde_json::to_string(&error)
                    .expect("closed capability blocker must serialize");
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
    fn refreshed_production_snapshot_updates_every_service_surface_and_clone() {
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
        let adapter = BlockedComputerUseAdapter::production(Arc::clone(&snapshot));
        let shared_snapshot = Arc::clone(&snapshot);
        let service = HostService {
            runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
            mode: HostMode::Production { snapshot },
        };
        let clone = service.clone();

        let initial_error = service
            .run(LOCAL_DEMO_HOST, "PRIVATE_BEFORE_CONTROL_PLANE_REFRESH")
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
            .run(LOCAL_DEMO_HOST, "PRIVATE_AFTER_CONTROL_PLANE_REFRESH")
            .expect_err("the cloned service must use refreshed admission");
        assert_eq!(refreshed_error.code, ErrorCode::IncompatibleControlPlane);
        assert!(!clone.daemon_runtime_capabilities().unwrap().codex_runtime());
        assert_eq!(
            clone
                .host_sessions(LOCAL_DEMO_HOST, false)
                .expect_err("refreshed readiness must block host sessions")
                .code,
            ErrorCode::ComputerUseNotReady
        );
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

        let computer_use =
            production_doctor_report(LOCAL_DEMO_HOST, Some("computer-use"), &snapshot);
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
}
