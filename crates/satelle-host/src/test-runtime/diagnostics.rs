use super::FakeComputerUseAdapter;
use crate::runtime::ComputerUseAdapter;
use satelle_core::doctor::{DoctorProbeScheduleEvent, DoctorScope, DoctorScopeSelection};
use satelle_core::{
    DaemonPathOverrides, DoctorFinding, DoctorFixability, DoctorOptions, DoctorProbeResult,
    DoctorReport, DoctorSchemaVersion, DoctorSummary, DoctorTransportObservation, SatelleError,
    SetupReadinessSummary, SetupReport, SetupSchemaVersion, utc_now,
};

pub(super) fn doctor(
    host: &str,
    scope_selection: &DoctorScopeSelection,
    transport_observation: &DoctorTransportObservation,
    options: DoctorOptions,
    adapter: &FakeComputerUseAdapter,
) -> Result<DoctorReport, SatelleError> {
    let started_at = utc_now();
    let readiness = adapter.preflight(host, &crate::ProviderComputerUseIntent::host_default())?;
    let probes = probe_plan(scope_selection);
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
    if scope_selection
        .scopes()
        .iter()
        .any(|scope| scope.as_str() == "transport")
        && let Some(finding) = transport_observation.finding()
    {
        findings.retain(|finding| finding.scope != "transport");
        probe_results.retain(|probe| probe.scope != "transport");
        let finding_id = finding.finding_id.clone();
        findings.push(finding.clone());
        probe_results.push(DoctorProbeResult {
            probe_id: "transport.selected".to_string(),
            scope: "transport".to_string(),
            status: if transport_observation.is_ready() {
                "passed"
            } else {
                "blocked"
            }
            .to_string(),
            started_at: started_at.clone(),
            finished_at: utc_now(),
            duration_ms: 0,
            cache_status: "not_persisted".to_string(),
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
    let transport_selected = scope_selection.scopes().contains(&DoctorScope::Transport);
    let ready = readiness.is_ready() && (!transport_selected || transport_observation.is_ready());

    let probe_schedule_events = probe_results
        .iter()
        .flat_map(|probe| {
            [
                DoctorProbeScheduleEvent::Started {
                    probe_id: probe.probe_id.clone(),
                    timestamp: probe.started_at.clone(),
                },
                DoctorProbeScheduleEvent::Finished {
                    probe_id: probe.probe_id.clone(),
                    timestamp: probe.finished_at.clone(),
                },
            ]
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok(DoctorReport {
        schema_version: DoctorSchemaVersion::V1,
        status: if ready { "ready" } else { "blocked" }.to_string(),
        target: host.to_string(),
        host: host.to_string(),
        scopes,
        started_at,
        finished_at: utc_now(),
        duration_ms: 0,
        summary: DoctorSummary {
            ready,
            blocking_findings: findings
                .iter()
                .filter(|finding| finding.readiness_impact == "blocked")
                .count(),
            repairable_findings: 0,
            informational_findings: findings
                .iter()
                .filter(|finding| finding.fixability == DoctorFixability::Informational)
                .count(),
        },
        probe_results,
        probe_schedule_events,
        ready,
        findings,
        recovery_commands,
        changed: options.refresh(),
        cache_updates: if options.refresh() {
            vec!["local-demo-readiness".to_string()]
        } else {
            Vec::new()
        },
        fix_flow: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked_transport_observation() -> DoctorTransportObservation {
        DoctorTransportObservation::blocked(DoctorFinding {
            finding_id: "transport.test.blocked".to_string(),
            scope: "transport".to_string(),
            severity: "error".to_string(),
            fixability: DoctorFixability::Blocked,
            readiness_impact: "blocked".to_string(),
            summary: "the selected transport is blocked".to_string(),
            evidence: Vec::new(),
            recovery_command: Some("repair the selected transport".to_string()),
        })
    }

    #[test]
    fn transport_observation_changes_readiness_only_when_transport_is_selected() {
        let adapter = FakeComputerUseAdapter;
        let blocked_transport = blocked_transport_observation();
        let config_scope = DoctorScopeSelection::parse(&["config".to_string()])
            .expect("config scope should parse");
        let config_report = doctor(
            "local-demo",
            &config_scope,
            &blocked_transport,
            DoctorOptions::default(),
            &adapter,
        )
        .expect("unselected transport evidence must not block config diagnostics");

        assert_eq!(config_report.status, "ready");
        assert!(config_report.summary.ready);
        assert!(config_report.ready);

        let transport_scope = DoctorScopeSelection::parse(&["transport".to_string()])
            .expect("transport scope should parse");
        let transport_report = doctor(
            "local-demo",
            &transport_scope,
            &blocked_transport,
            DoctorOptions::default(),
            &adapter,
        )
        .expect("selected transport evidence should produce a report");

        assert_eq!(transport_report.status, "blocked");
        assert!(!transport_report.summary.ready);
        assert!(!transport_report.ready);
    }
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
    let native_setup_planned = setup_components.iter().any(|component| {
        matches!(
            component.as_str(),
            "all" | "host" | "codex" | "computer-use" | "desktop"
        )
    });
    let applied = native_setup_planned && !dry_run;
    let applied_actions = applied
        .then(|| "configured fake native Computer Use readiness".to_string())
        .into_iter()
        .collect();

    SetupReport {
        schema_version: SetupSchemaVersion::V2,
        host: host.to_string(),
        dry_run,
        status: if applied { "applied" } else { "planned" }.to_string(),
        cancellation_reason: None,
        verification: None,
        setup_mode,
        service_persistent,
        service_scope,
        fallback_reason: None,
        target_platform: None,
        host_artifact: None,
        service_plan: None,
        current_daemon_paths: None,
        planned_daemon_paths: None,
        setup_components,
        planned_actions,
        applied_actions,
        required_input: Vec::new(),
        recovery_commands: vec!["satelle doctor --scope computer-use --refresh".to_string()],
        readiness_summary: SetupReadinessSummary {
            transport: "ready".to_string(),
            host_daemon: "local_demo_in_process".to_string(),
            codex_runtime: "not_checked".to_string(),
            native_computer_use: "not_verified".to_string(),
            provider_auth: "not_required_for_local_demo".to_string(),
        },
        descriptor_configured: false,
        secret_provisioned: false,
        validation_status: "not_required".to_string(),
        provider_smoke_test_status: "not_required".to_string(),
        daemon_path_overrides,
        changed: applied,
        mutated: applied,
        mutation_planned: native_setup_planned,
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

fn probe_plan(scope_selection: &DoctorScopeSelection) -> Vec<ProbeDefinition> {
    PROBES
        .iter()
        .copied()
        .filter(|probe| {
            scope_selection
                .scopes()
                .iter()
                .any(|scope| scope.as_str() == probe.scope)
        })
        .collect()
}
