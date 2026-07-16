#[path = "api-auth.rs"]
mod api_auth;
mod codex_capabilities;
#[path = "codex-session.rs"]
mod codex_session;
mod daemon;
#[path = "desktop-sessions.rs"]
mod desktop_sessions;
#[path = "live-events.rs"]
mod live_events;
#[path = "log-page.rs"]
mod log_page;
#[path = "operation-capacity.rs"]
mod operation_capacity;
#[path = "process-identity.rs"]
mod process_identity;
#[path = "provider-probe.rs"]
mod provider_probe;
mod runtime;
mod storage;
#[cfg(any(test, feature = "test-support"))]
#[path = "test-runtime.rs"]
mod test_runtime;

use api_auth::EphemeralApiAuthenticator;
pub use api_auth::{ApiBearerToken, ApiBearerTokenError, ApiPrincipal, ApiScopes};
use codex_capabilities::{
    BlockerReason, CodexVersionEvidence, Phase0CapabilityBlocker, Phase0SupportVerdict,
    RequiredCapability, discover_phase0, evaluate_phase0_support,
};
pub use daemon::{
    DaemonActivitySnapshot, DaemonRuntimeCapabilities, DaemonRuntimeStatus, MutationAuthority,
    MutationAuthorityError, StopAdmission, TurnIntent, TurnIntentError,
};
pub use live_events::{LiveEventReceiveError, LiveEventSubscription};
pub use log_page::{
    DaemonLogEntry, DaemonLogPage, LogCursor, LogCursorError, LogEvent, LogPageMode, LogPageQuery,
    LogPageQueryError, LogSeverity, LogSource, LogSubject,
};
use operation_capacity::OperationCapacity;
pub use runtime::{
    AdapterPreflight, AdapterReadiness, AdapterSubject, ComputerUseAdapter, EvidenceError,
    ExecuteRequest, ExecuteResult, ProviderComputerUseIntent, ProviderSmokeEvidence,
    ProviderSmokeFailureEvidence, ProviderSmokeResult, ReadinessCacheKey, ReadinessEvidence,
    RecoveryObservation,
};
use runtime::{ProductionComputerUseAdapter, RunCommand, RuntimeHandle, SteerCommand, StopCommand};
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    DaemonPathOverrides, DoctorFinding, DoctorFixability, DoctorOptions, DoctorProbeResult,
    DoctorReport, DoctorSchemaVersion, DoctorSummary, HostConfig, HostSessionsReport,
    HostSessionsSchemaVersion, LOCAL_DEMO_HOST, SatelleError, SatelleEvent, SessionId,
    SetupReadinessSummary, SetupReport, SetupSchemaVersion, StopResult, object_value, utc_now,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::Instant;
#[cfg(any(test, feature = "test-support"))]
use test_runtime::FakeComputerUseAdapter;
#[cfg(feature = "test-support")]
use test_runtime::PendingComputerUseAdapter;

const DEFAULT_NATIVE_READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const DEFAULT_NATIVE_READINESS_TTL: time::Duration = time::Duration::minutes(5);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    pub use crate::storage::TestStateDir;
}

#[cfg(test)]
use test_support::TestStateDir;

#[cfg(test)]
#[path = "operation-capacity-tests.rs"]
mod operation_capacity_tests;

#[derive(Clone, Debug)]
pub struct HostService {
    runtime: RuntimeHandle,
    operation_capacity: Arc<OperationCapacity>,
    mode: HostMode,
    bootstrap_auth: Option<Arc<EphemeralApiAuthenticator>>,
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
    evidence: codex_capabilities::Phase0CapabilityEvidence,
    verdict: Phase0SupportVerdict,
    control_plane_admission: codex_capabilities::ControlPlaneAdmission,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
}

impl ProductionCapabilitySnapshot {
    fn collect(probe_timeout: Option<std::time::Duration>) -> Self {
        let started_at = utc_now();
        let started = Instant::now();
        let discovery = discover_phase0(probe_timeout);
        let verdict = evaluate_phase0_support(discovery.evidence);
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        Self {
            evidence: discovery.evidence,
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
        let config = satelle_core::SatelleConfig::defaults()
            .hosts
            .remove(LOCAL_DEMO_HOST)
            .expect("the built-in local Host config exists");
        Self::production_for_host(&config)
    }

    /// Builds a production Host whose native probe timeout and cache TTL come
    /// from the fully resolved host/profile configuration.
    pub fn production_for_host(config: &HostConfig) -> Self {
        let snapshot = Arc::new(RwLock::new(ProductionCapabilitySnapshot::collect(None)));
        let state_root = satelle_core::state_dir();
        let working_directory = state_root
            .as_ref()
            .map(|path| path.join("codex-app-server-work"))
            .map_err(Clone::clone);
        let timeout = config
            .timeouts
            .as_ref()
            .and_then(|timeouts| timeouts.native_readiness.as_ref())
            .map_or(DEFAULT_NATIVE_READINESS_TIMEOUT, |duration| {
                std::time::Duration::from_millis(duration.milliseconds())
            });
        let ttl = config.native_readiness_cache_ttl.as_ref().map_or(
            DEFAULT_NATIVE_READINESS_TTL,
            |duration| {
                time::Duration::milliseconds(
                    i64::try_from(duration.milliseconds()).unwrap_or(i64::MAX),
                )
            },
        );
        let provider_smoke_timeout = config
            .timeouts
            .as_ref()
            .and_then(|timeouts| timeouts.provider_smoke_test.as_ref())
            .map_or(std::time::Duration::from_secs(120), |duration| {
                std::time::Duration::from_millis(duration.milliseconds())
            });
        let adapter = ProductionComputerUseAdapter::with_readiness_policy(
            Arc::clone(&snapshot),
            working_directory,
            timeout,
            ttl,
            provider_smoke_timeout,
        );
        Self {
            runtime: RuntimeHandle::new(state_root, adapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            mode: HostMode::Production { snapshot },
            bootstrap_auth: None,
        }
    }

    /// Builds an on-demand Host whose only bootstrap credential is held in
    /// process memory and expires independently of durable Host state.
    pub fn production_for_ssh_bootstrap(
        token: &ApiBearerToken,
        expires_at: time::OffsetDateTime,
    ) -> Self {
        let mut service = Self::production();
        service.bootstrap_auth = Some(Arc::new(EphemeralApiAuthenticator::new(
            token,
            ApiScopes::CONTROL,
            expires_at,
        )));
        service
    }

    /// The deterministic adapter requires both the compile-time feature and a
    /// separate Satelle-owned CLI opt-in. It is not present in default builds.
    #[cfg(feature = "test-support")]
    pub fn local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), FakeComputerUseAdapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            mode: HostMode::TestFake,
            bootstrap_auth: None,
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn pending_local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), PendingComputerUseAdapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            mode: HostMode::TestFake,
            bootstrap_auth: None,
        })
    }

    pub fn doctor(
        &self,
        host: &str,
        scope: Option<&str>,
        options: DoctorOptions,
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
            HostMode::Production { snapshot } if options.refresh() => {
                let refreshed = ProductionCapabilitySnapshot::collect(options.probe_timeout());
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
            HostMode::TestFake => self.fake_doctor(host, scope, options, &FakeComputerUseAdapter),
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
        if !dry_run {
            return Err(SatelleError::not_implemented(format!(
                "{setup_mode} setup mutations are not supported by the local Host transport"
            )));
        }
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

    pub fn run(
        &self,
        host: &str,
        intent: &TurnIntent,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        self.runtime
            .run(
                RunCommand::attached(host, intent.prompt())
                    .with_execution_mode(intent.execution_mode())
                    .with_provider_intent(intent.provider_intent().clone()),
            )
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn run_detached(
        &self,
        host: &str,
        intent: &TurnIntent,
    ) -> Result<PublicSession, SatelleError> {
        crate::runtime::admitted_session(
            self.runtime.run(
                RunCommand::detached(host, intent.prompt())
                    .with_execution_mode(intent.execution_mode())
                    .with_provider_intent(intent.provider_intent().clone()),
            ),
        )
    }

    pub fn steer(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        self.runtime
            .steer(
                SteerCommand::attached(session_id.clone(), intent.prompt())
                    .with_execution_mode(intent.execution_mode())
                    .with_provider_intent(intent.provider_intent().clone()),
            )
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn steer_detached(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
    ) -> Result<PublicSession, SatelleError> {
        crate::runtime::admitted_session(
            self.runtime.steer(
                SteerCommand::detached(session_id.clone(), intent.prompt())
                    .with_execution_mode(intent.execution_mode())
                    .with_provider_intent(intent.provider_intent().clone()),
            ),
        )
    }

    pub fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.runtime.status(session_id.clone())
    }

    pub fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.runtime.stop(StopCommand::new(session_id.clone()))
    }

    pub fn host_sessions(
        &self,
        host: &str,
        no_bootstrap: bool,
    ) -> Result<HostSessionsReport, SatelleError> {
        ensure_local_demo(host)?;
        let sessions = self.daemon_desktop_sessions()?;
        let bootstrap_actions = if no_bootstrap {
            Vec::new()
        } else {
            vec!["direct local-demo host daemon already reachable".to_string()]
        };
        Ok(HostSessionsReport {
            schema_version: HostSessionsSchemaVersion::V1,
            host: host.to_string(),
            connection_mode: "direct".to_string(),
            bootstrapped: false,
            bootstrap_actions,
            host_daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            sessions,
        })
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

    // Production capability discovery is currently one combined live probe,
    // so it already satisfies the at-most-one execution promised by
    // --serial-probes. The per-scope results below are static projections of
    // that single snapshot, not additional live work to schedule.
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
        BlockerReason::UnsupportedHostPlatform | BlockerReason::NativeExecutionPathUnavailable => {
            "computer-use"
        }
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
        BlockerReason::NativeExecutionPathUnavailable => {
            "the private Codex app-server exposes no stable native Computer Use path"
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
    pub session: PublicSession,
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
#[path = "lib-tests.rs"]
mod tests;
