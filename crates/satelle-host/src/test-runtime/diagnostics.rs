use super::FakeComputerUseAdapter;
use crate::runtime::ComputerUseAdapter;
use satelle_core::{
    DaemonPathOverrides, DoctorFinding, DoctorFixability, DoctorOptions, DoctorProbeResult,
    DoctorReport, DoctorSchemaVersion, DoctorSummary, SatelleError, SetupReadinessSummary,
    SetupReport, SetupSchemaVersion, utc_now,
};

pub(super) fn doctor(
    host: &str,
    scope: Option<&str>,
    options: DoctorOptions,
    adapter: &FakeComputerUseAdapter,
) -> Result<DoctorReport, SatelleError> {
    let started_at = utc_now();
    let readiness = adapter.preflight(host, &crate::ProviderComputerUseIntent::host_default())?;
    let probes = probe_plan(scope);
    let mut findings = Vec::new();
    let mut probe_results = Vec::new();

    for probe in probes {
        let scope = probe.scope.to_string();
        let probe_started_at = utc_now();
        let finding_id = format!("{}.ready", probe.probe_id);
        findings.push(DoctorFinding {
            finding_id: finding_id.clone(),
            scope: scope.clone(),
            severity: "info".to_string(),
            fixability: DoctorFixability::Informational,
            readiness_impact: "ready".to_string(),
            summary: readiness.message().to_string(),
            evidence: vec![
                format!("adapter={}", readiness.adapter()),
                format!("refresh={}", options.refresh()),
                "transport=local".to_string(),
                format!("dependencies={}", probe.dependencies.join(",")),
            ],
            recovery_command: None,
        });
        probe_results.push(DoctorProbeResult {
            probe_id: probe.probe_id.to_string(),
            scope,
            status: "passed".to_string(),
            started_at: probe_started_at,
            finished_at: utc_now(),
            duration_ms: 0,
            cache_status: if options.refresh() {
                "refreshed"
            } else {
                "not_used"
            }
            .to_string(),
            dependency_status: "satisfied".to_string(),
            finding_ids: vec![finding_id],
        });
    }

    probe_results.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.probe_id.cmp(&right.probe_id))
    });
    findings.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.finding_id.cmp(&right.finding_id))
    });
    let scopes = probe_results
        .iter()
        .map(|probe| probe.scope.clone())
        .collect::<Vec<_>>();
    let recovery_commands = findings
        .iter()
        .filter_map(|finding| finding.recovery_command.clone())
        .collect::<Vec<_>>();

    Ok(DoctorReport {
        schema_version: DoctorSchemaVersion::V1,
        status: if readiness.is_ready() {
            "ready"
        } else {
            "blocked"
        }
        .to_string(),
        target: host.to_string(),
        host: host.to_string(),
        scopes,
        started_at,
        finished_at: utc_now(),
        duration_ms: 0,
        summary: DoctorSummary {
            ready: readiness.is_ready(),
            blocking_findings: 0,
            repairable_findings: 0,
            informational_findings: findings.len(),
        },
        probe_results,
        ready: readiness.is_ready(),
        findings,
        recovery_commands,
        changed: options.refresh(),
        cache_updates: if options.refresh() {
            vec!["local-demo-readiness".to_string()]
        } else {
            Vec::new()
        },
    })
}

pub(super) fn setup(
    host: &str,
    dry_run: bool,
    setup_mode: String,
    setup_components: Vec<String>,
    daemon_path_overrides: DaemonPathOverrides,
) -> SetupReport {
    let service_persistent = setup_mode == "persistent";
    let service_scope = if service_persistent {
        "user".to_string()
    } else {
        "on_demand".to_string()
    };
    let daemon_path_overrides = daemon_path_overrides.entries();
    let mut planned_actions = vec![
        "resolve local-demo host alias".to_string(),
        "use fake computer-use adapter".to_string(),
        "leave live native Computer Use readiness unverified".to_string(),
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
        service_scope,
        fallback_reason: None,
        setup_components,
        planned_actions,
        applied_actions: Vec::new(),
        required_input: Vec::new(),
        recovery_commands: vec!["satelle doctor --scope computer-use --refresh".to_string()],
        readiness_summary: SetupReadinessSummary {
            transport: "ready".to_string(),
            host_daemon: "local_demo_in_process".to_string(),
            codex_runtime: "not_checked".to_string(),
            native_computer_use: "not_verified".to_string(),
            provider_auth: "not_required_for_local_demo".to_string(),
        },
        daemon_path_overrides,
        mutated: false,
        native_computer_use_readiness: "not_verified".to_string(),
        next_command: "satelle doctor --scope computer-use --refresh".to_string(),
    }
}

#[derive(Clone, Copy, Debug)]
struct ProbeDefinition {
    probe_id: &'static str,
    scope: &'static str,
    dependencies: &'static [&'static str],
}

const PROBES: &[ProbeDefinition] = &[
    ProbeDefinition {
        probe_id: "transport.local_demo",
        scope: "transport",
        dependencies: &[],
    },
    ProbeDefinition {
        probe_id: "config.local_demo",
        scope: "config",
        dependencies: &[],
    },
    ProbeDefinition {
        probe_id: "codex.local_demo",
        scope: "codex",
        dependencies: &["transport.local_demo"],
    },
    ProbeDefinition {
        probe_id: "computer-use.local_demo",
        scope: "computer-use",
        dependencies: &["transport.local_demo", "codex.local_demo"],
    },
    ProbeDefinition {
        probe_id: "provider.local_demo",
        scope: "provider",
        dependencies: &["transport.local_demo", "computer-use.local_demo"],
    },
];

fn probe_plan(scope: Option<&str>) -> Vec<ProbeDefinition> {
    if matches!(scope, None | Some("all")) {
        return PROBES.to_vec();
    }

    PROBES
        .iter()
        .copied()
        .filter(|probe| Some(probe.scope) == scope)
        .collect()
}
