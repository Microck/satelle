use satelle_core::doctor::{
    DoctorDependentEvidence, DoctorProbe, DoctorProbeCachePolicy, DoctorProbeCompletion,
    DoctorProbeExecutionContext, DoctorProbeLifecycle, DoctorProbeLifecycleEvent,
    DoctorProbeScheduler, DoctorProbeStatus, DoctorScope, DoctorScopeSelection,
};
use satelle_core::{
    DoctorFinding, DoctorFixability, DoctorOptions, DoctorProbeResult, DoctorReport,
    DoctorSchemaVersion, DoctorSummary, DoctorTransportObservation, HostConfig, NetworkConfig,
    TransportKind, utc_now,
};
use satelle_host::{ControllerTransportProbe, ControllerTransportProbeOutcome};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use url::Url;

const MAX_STATUS_BYTES: usize = 1024 * 1024;

pub(super) struct TailscaleDoctorProbe {
    executable: std::path::PathBuf,
    tailnet_name: Option<String>,
    target: Option<String>,
    selected: bool,
}

pub(super) fn transport_doctor_probe(
    scope_selection: &DoctorScopeSelection,
    host: &HostConfig,
) -> TailscaleDoctorProbe {
    transport_doctor_probe_with(scope_selection, host, Path::new("tailscale"))
}

fn transport_doctor_probe_with(
    scope_selection: &DoctorScopeSelection,
    host: &HostConfig,
    executable: &Path,
) -> TailscaleDoctorProbe {
    let Some(NetworkConfig::Tailscale {
        tailnet_name,
        hostname,
    }) = host.network.as_ref()
    else {
        return TailscaleDoctorProbe {
            executable: executable.to_path_buf(),
            tailnet_name: None,
            target: None,
            selected: false,
        };
    };
    let address_target = host
        .address
        .as_deref()
        .and_then(|address| address_host(&host.transport, address));
    TailscaleDoctorProbe {
        executable: executable.to_path_buf(),
        tailnet_name: tailnet_name.clone(),
        target: hostname.clone().or(address_target),
        selected: scope_selection.contains(DoctorScope::Transport),
    }
}

impl ControllerTransportProbe for TailscaleDoctorProbe {
    fn execute(&self, context: &DoctorProbeExecutionContext) -> ControllerTransportProbeOutcome {
        if !self.selected {
            return ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::ready(
                None,
            ));
        }
        self.execute_selected(context)
    }
}

impl TailscaleDoctorProbe {
    fn execute_selected(
        &self,
        context: &DoctorProbeExecutionContext,
    ) -> ControllerTransportProbeOutcome {
        // Tailscale is only a network provider. This path deliberately uses
        // read-only status and ping operations and never changes daemon, ACL, or
        // Serve state.
        let mut diagnosis = match read_status(&self.executable, context) {
            Ok(status) => {
                diagnose_status(status, self.tailnet_name.as_deref(), self.target.as_deref())
            }
            Err(StatusReadError::TimedOut) => {
                return ControllerTransportProbeOutcome::TimedOut(timeout_observation());
            }
            Err(StatusReadError::MissingCli) => Diagnosis::blocked(
                "tailscale_cli_unavailable",
                "the local Tailscale CLI is unavailable; configuration was validated but live checks were skipped",
                vec![
                    "network_provider=tailscale".to_string(),
                    "live_checks=skipped".to_string(),
                ],
                Some("tailscale status --json"),
            ),
            Err(StatusReadError::CommandFailed) => Diagnosis::blocked(
                "tailscale_status_unavailable",
                "the local Tailscale daemon or login state is unavailable",
                vec!["network_provider=tailscale".to_string()],
                Some("tailscale status --json"),
            ),
            Err(StatusReadError::InvalidOutput) => Diagnosis::blocked(
                "tailscale_status_invalid",
                "the local Tailscale status response could not be read safely",
                vec!["network_provider=tailscale".to_string()],
                Some("tailscale status --json"),
            ),
        };
        if diagnosis.ready
            && let Some(target) = diagnosis.ping_target.as_deref()
            && let Err(error) = ping(&self.executable, target, context)
        {
            if error == StatusReadError::TimedOut {
                return ControllerTransportProbeOutcome::TimedOut(timeout_observation());
            }
            diagnosis = Diagnosis::blocked(
                "tailscale_host_unreachable",
                "the configured host is visible but did not answer a Tailscale-layer reachability probe",
                vec![format!("configured_target={target}")],
                Some("tailscale ping --c 1 <host>"),
            );
        }

        let finding = diagnosis.finding;
        ControllerTransportProbeOutcome::Observed(if diagnosis.ready {
            DoctorTransportObservation::ready(Some(finding))
        } else {
            DoctorTransportObservation::blocked(finding)
        })
    }
}

fn is_transport_only_doctor(host: &HostConfig, scope_selection: &DoctorScopeSelection) -> bool {
    scope_selection.scopes() == [DoctorScope::Transport]
        && matches!(host.transport, TransportKind::Direct | TransportKind::Ssh)
        && matches!(host.network, Some(NetworkConfig::Tailscale { .. }))
}

pub(super) struct PreparedTransportOnlyDoctor {
    scheduler: DoctorProbeScheduler,
}

pub(super) fn prepare_transport_only_doctor(
    host: &HostConfig,
    scope_selection: &DoctorScopeSelection,
    options: DoctorOptions,
) -> Result<Option<PreparedTransportOnlyDoctor>, satelle_core::SatelleError> {
    if !is_transport_only_doctor(host, scope_selection) {
        return Ok(None);
    }

    let scheduler = DoctorProbeScheduler::new(vec![DoctorProbe {
        probe_id: "transport.tailscale.local".to_string(),
        scope: DoctorScope::Transport.as_str().to_string(),
        dependencies: Vec::new(),
        resource_locks: Default::default(),
        timeout: options.effective_probe_timeout(),
        cache_policy: DoctorProbeCachePolicy::RefreshWhenRequested,
    }])
    .map_err(|error| satelle_core::SatelleError::invalid_usage(error.to_string()))?;
    Ok(Some(PreparedTransportOnlyDoctor { scheduler }))
}

pub(super) fn execute_transport_only_doctor(
    host_alias: &str,
    scope_selection: &DoctorScopeSelection,
    probe: &TailscaleDoctorProbe,
    mut prepared: PreparedTransportOnlyDoctor,
) -> Result<DoctorReport, satelle_core::SatelleError> {
    debug_assert_eq!(scope_selection.scopes(), [DoctorScope::Transport]);
    let scheduler = &mut prepared.scheduler;
    let definition = scheduler
        .start_ready()
        .into_iter()
        .next()
        .expect("the prepared transport graph has one ready probe");
    let mut lifecycle = DoctorProbeLifecycle::start(
        definition.probe_id.clone(),
        std::time::Instant::now(),
        definition.timeout,
        (definition.timeout / 4).min(std::time::Duration::from_secs(1)),
    )
    .map_err(|error| satelle_core::SatelleError::invalid_usage(error.to_string()))?;
    let context = lifecycle.context();
    let started_at = utc_now();
    let started = std::time::Instant::now();
    let outcome = probe.execute(&context);
    let completed_at = std::time::Instant::now();
    let finished_at = utc_now();
    let duration = completed_at.duration_since(started);
    let probe_completion = match &outcome {
        ControllerTransportProbeOutcome::Observed(observation) => DoctorProbeCompletion::new(
            if observation.is_ready() {
                DoctorProbeStatus::Passed
            } else {
                DoctorProbeStatus::Finding
            },
            DoctorDependentEvidence::Useful,
        ),
        ControllerTransportProbeOutcome::TimedOut(_) => DoctorProbeCompletion::new(
            DoctorProbeStatus::TimedOut,
            DoctorDependentEvidence::NotUseful,
        ),
    };
    let DoctorProbeLifecycleEvent::TerminalAck(completion) = lifecycle
        .poll(completed_at, Some((completed_at, probe_completion)))
        .map_err(|error| satelle_core::SatelleError::invalid_usage(error.to_string()))?
    else {
        unreachable!("the owned transport operation returned a terminal acknowledgment")
    };
    let records = [satelle_core::doctor::DoctorProbeExecutionRecord {
        probe_id: definition.probe_id.clone(),
        status: completion.status,
    }];
    scheduler
        .finish(&definition.probe_id, completion)
        .expect("the acknowledged transport probe is running");
    let projection = project_transport_outcome(&outcome, completion);
    let observation = &projection.observation;
    let findings = observation
        .finding()
        .cloned()
        .into_iter()
        .collect::<Vec<_>>();
    let finding_ids = findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    let recovery_commands = findings
        .iter()
        .filter_map(|finding| finding.recovery_command.clone())
        .collect::<Vec<_>>();
    let ready = projection.ready;
    let status = projection.status;
    let duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);

    Ok(DoctorReport {
        schema_version: DoctorSchemaVersion::V1,
        status: if ready { "ready" } else { "blocked" }.to_string(),
        target: host_alias.to_string(),
        host: host_alias.to_string(),
        scopes: vec![DoctorScope::Transport.as_str().to_string()],
        started_at: started_at.clone(),
        finished_at: finished_at.clone(),
        duration_ms,
        summary: DoctorSummary {
            ready,
            blocking_findings: findings
                .iter()
                .filter(|finding| finding.readiness_impact == "blocked")
                .count(),
            repairable_findings: findings
                .iter()
                .filter(|finding| finding.fixability == DoctorFixability::Repairable)
                .count(),
            informational_findings: findings
                .iter()
                .filter(|finding| finding.fixability == DoctorFixability::Informational)
                .count(),
        },
        probe_results: vec![DoctorProbeResult {
            probe_id: "transport.tailscale.local".to_string(),
            scope: DoctorScope::Transport.as_str().to_string(),
            status: status.to_string(),
            started_at,
            finished_at,
            duration_ms,
            cache_status: "not_persisted".to_string(),
            dependency_status: "satisfied".to_string(),
            finding_ids,
        }],
        probe_completion_order: records
            .iter()
            .map(|record| record.probe_id.clone())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        ready,
        findings,
        recovery_commands,
        changed: false,
        cache_updates: Vec::new(),
    })
}

struct TransportProbeProjection {
    observation: DoctorTransportObservation,
    status: &'static str,
    ready: bool,
}

fn project_transport_outcome(
    outcome: &ControllerTransportProbeOutcome,
    completion: DoctorProbeCompletion,
) -> TransportProbeProjection {
    let observation = match completion.status {
        DoctorProbeStatus::TimedOut => timeout_observation(),
        DoctorProbeStatus::Passed | DoctorProbeStatus::Finding | DoctorProbeStatus::Failed => {
            match outcome {
                ControllerTransportProbeOutcome::Observed(observation)
                | ControllerTransportProbeOutcome::TimedOut(observation) => observation.clone(),
            }
        }
    };
    let status = match completion.status {
        DoctorProbeStatus::Passed => "passed",
        DoctorProbeStatus::Finding => "blocked",
        DoctorProbeStatus::Failed => "failed",
        DoctorProbeStatus::TimedOut => "timed_out",
    };
    TransportProbeProjection {
        ready: completion.status == DoctorProbeStatus::Passed && observation.is_ready(),
        observation,
        status,
    }
}

fn read_status(
    executable: &Path,
    context: &DoctorProbeExecutionContext,
) -> Result<TailscaleStatus, StatusReadError> {
    let stdout = run_bounded(executable, &["status".into(), "--json".into()], context)?;
    serde_json::from_slice(&stdout).map_err(|_| StatusReadError::InvalidOutput)
}

fn ping(
    executable: &Path,
    target: &str,
    context: &DoctorProbeExecutionContext,
) -> Result<(), StatusReadError> {
    let remaining = context.remaining();
    let remaining_ms = remaining.as_millis();
    if context.is_cancelled() || remaining.is_zero() || remaining_ms == 0 {
        return Err(StatusReadError::TimedOut);
    }
    run_bounded(
        executable,
        &[
            "ping".into(),
            "--c".into(),
            "1".into(),
            "--timeout".into(),
            format!("{remaining_ms}ms"),
            target.into(),
        ],
        context,
    )
    .map(|_| ())
}

fn run_bounded(
    executable: &Path,
    args: &[String],
    context: &DoctorProbeExecutionContext,
) -> Result<Vec<u8>, StatusReadError> {
    let mut command = Command::new(executable);
    command.args(args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                StatusReadError::MissingCli
            } else {
                StatusReadError::CommandFailed
            }
        })?;
    let stdout = child.stdout.take().ok_or(StatusReadError::InvalidOutput)?;
    let (reader_sender, reader_receiver) = std::sync::mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((MAX_STATUS_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = reader_sender.send(result);
    });
    let mut status = None;
    let mut stdout = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| StatusReadError::CommandFailed)?;
        }
        if stdout.is_none() {
            match reader_receiver.try_recv() {
                Ok(result) => stdout = Some(result),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(StatusReadError::InvalidOutput);
                }
            }
        }
        if status.is_some() && stdout.is_some() {
            break;
        }
        let remaining = context.remaining();
        if context.is_cancelled() || remaining.is_zero() {
            terminate_process_tree(&mut child, context.cleanup_deadline());
            let _ = reader_receiver.recv_timeout(context.cleanup_remaining());
            return Err(StatusReadError::TimedOut);
        }
        thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
    }
    let status = status.expect("loop exits only with a process status");
    let stdout = stdout
        .expect("loop exits only with stdout")
        .map_err(|_| StatusReadError::InvalidOutput)?;
    if stdout.len() > MAX_STATUS_BYTES {
        return Err(StatusReadError::InvalidOutput);
    }
    if !status.success() {
        return Err(StatusReadError::CommandFailed);
    }
    Ok(stdout)
}

fn terminate_process_tree(child: &mut std::process::Child, cleanup_deadline: std::time::Instant) {
    #[cfg(unix)]
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    #[cfg(windows)]
    let mut tree_killer = Command::new("taskkill")
        .args(["/T", "/F", "/PID", &child.id().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok();
    #[cfg(not(windows))]
    let mut tree_killer: Option<std::process::Child> = None;

    let _ = child.kill();
    loop {
        let child_exited = child.try_wait().map_or(true, |status| status.is_some());
        let tree_killer_exited = tree_killer
            .as_mut()
            .is_none_or(|process| process.try_wait().map_or(true, |status| status.is_some()));
        if child_exited && tree_killer_exited {
            return;
        }
        let remaining = cleanup_deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(remaining.min(std::time::Duration::from_millis(5)));
    }
    let _ = child.kill();
    if let Some(tree_killer) = tree_killer.as_mut() {
        let _ = tree_killer.kill();
    }
}

fn diagnose_status(
    status: TailscaleStatus,
    expected_tailnet: Option<&str>,
    target: Option<&str>,
) -> Diagnosis {
    if status.backend_state.as_deref() != Some("Running") {
        return Diagnosis::blocked(
            "tailscale_not_running",
            "the local Tailscale daemon is not in the Running state",
            vec![format!(
                "backend_state={}",
                status.backend_state.as_deref().unwrap_or("unknown")
            )],
            Some("tailscale status --json"),
        );
    }

    if let Some(expected) = expected_tailnet {
        let observed = status
            .current_tailnet
            .as_ref()
            .and_then(|tailnet| tailnet.name.as_deref());
        if observed.is_none_or(|observed| !names_match(expected, observed)) {
            return Diagnosis::blocked(
                "tailscale_tailnet_mismatch",
                "the active Tailscale tailnet does not match the configured tailnet",
                vec![
                    format!("expected_tailnet={expected}"),
                    format!("observed_tailnet={}", observed.unwrap_or("unknown")),
                ],
                Some("tailscale status --json"),
            );
        }
    }

    let Some(target) = target else {
        return Diagnosis::blocked(
            "tailscale_target_missing",
            "the Tailscale-backed host has no hostname or address to validate",
            vec!["network_provider=tailscale".to_string()],
            Some("satelle config explain --json"),
        );
    };
    let Some(peer) = status
        .peer
        .values()
        .find(|peer| peer.matches_target(target))
    else {
        return Diagnosis::blocked(
            "tailscale_host_not_visible",
            "the configured host is not visible in local Tailscale status",
            vec![format!("configured_target={target}")],
            Some("tailscale status --json"),
        );
    };
    if peer.online != Some(true) {
        return Diagnosis::blocked(
            "tailscale_host_offline",
            "the configured Tailscale host is visible but not online",
            vec![format!("configured_target={target}")],
            Some("tailscale status --json"),
        );
    }

    let mut evidence = vec![
        "network_provider=tailscale".to_string(),
        "backend_state=Running".to_string(),
        format!("configured_target={target}"),
    ];
    if let Some(tailnet) = status
        .current_tailnet
        .as_ref()
        .and_then(|tailnet| tailnet.name.as_deref())
    {
        evidence.push(format!("tailnet={tailnet}"));
    }
    if let Some(dns_name) = peer.dns_name.as_deref() {
        evidence.push(format!(
            "suggested_dns_name={}",
            dns_name.trim_end_matches('.')
        ));
    }
    if !peer.tailscale_ips.is_empty() {
        evidence.push(format!(
            "suggested_tailscale_ips={}",
            peer.tailscale_ips.join(",")
        ));
    }
    let ping_target = peer
        .dns_name
        .as_deref()
        .map(|name| name.trim_end_matches('.').to_string())
        .or_else(|| peer.tailscale_ips.first().cloned())
        .unwrap_or_else(|| target.to_string());
    Diagnosis::ready(evidence, ping_target)
}

fn address_host(transport: &TransportKind, address: &str) -> Option<String> {
    match transport {
        TransportKind::Direct => Url::parse(address).ok()?.host_str().map(str::to_string),
        TransportKind::Ssh => {
            let destination = address.rsplit_once('@').map_or(address, |(_, host)| host);
            if let Some(bracketed) = destination.strip_prefix('[') {
                return bracketed.split_once(']').map(|(host, _)| host.to_string());
            }
            if destination.matches(':').count() == 1 {
                return destination
                    .split_once(':')
                    .map(|(host, _)| host.to_string());
            }
            Some(destination.to_string())
        }
        TransportKind::Local => None,
    }
}

fn names_match(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

// `tailscale status --json` is explicitly version-dependent. Keep every
// consumed field optional and ignore the rest so older and newer CLIs degrade
// to a typed partial diagnostic instead of coupling Satelle to the full shape.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscaleStatus {
    backend_state: Option<String>,
    current_tailnet: Option<CurrentTailnet>,
    #[serde(default)]
    peer: BTreeMap<String, TailscalePeer>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CurrentTailnet {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TailscalePeer {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(default, rename = "TailscaleIPs")]
    tailscale_ips: Vec<String>,
    online: Option<bool>,
}

impl TailscalePeer {
    fn matches_target(&self, target: &str) -> bool {
        self.host_name
            .as_deref()
            .is_some_and(|host| names_match(host, target))
            || self
                .dns_name
                .as_deref()
                .is_some_and(|host| names_match(host, target))
            || self.tailscale_ips.iter().any(|ip| names_match(ip, target))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StatusReadError {
    MissingCli,
    CommandFailed,
    InvalidOutput,
    TimedOut,
}

fn timeout_observation() -> DoctorTransportObservation {
    DoctorTransportObservation::blocked(
        Diagnosis::blocked(
            "tailscale_probe_timed_out",
            "the local Tailscale diagnostic exceeded its Doctor probe deadline",
            vec!["network_provider=tailscale".to_string()],
            Some("satelle doctor --scope transport --json"),
        )
        .finding,
    )
}

struct Diagnosis {
    ready: bool,
    finding: DoctorFinding,
    ping_target: Option<String>,
}

impl Diagnosis {
    fn ready(evidence: Vec<String>, ping_target: String) -> Self {
        Self {
            ready: true,
            finding: DoctorFinding {
                finding_id: "tailscale_host_reachable".to_string(),
                scope: "transport".to_string(),
                severity: "info".to_string(),
                fixability: DoctorFixability::Informational,
                readiness_impact: "ready".to_string(),
                summary: "the configured host is visible and online through Tailscale".to_string(),
                evidence,
                recovery_command: None,
            },
            ping_target: Some(ping_target),
        }
    }

    fn blocked(
        finding_id: &str,
        summary: &str,
        evidence: Vec<String>,
        recovery_command: Option<&str>,
    ) -> Self {
        Self {
            ready: false,
            finding: DoctorFinding {
                finding_id: finding_id.to_string(),
                scope: "transport".to_string(),
                severity: "error".to_string(),
                fixability: DoctorFixability::ManualActionRequired,
                readiness_impact: "blocked".to_string(),
                summary: summary.to_string(),
                evidence,
                recovery_command: recovery_command.map(str::to_string),
            },
            ping_target: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::{AdapterKind, ApiTokenSource};
    use std::path::PathBuf;

    fn transport_only_doctor_report(
        host_alias: &str,
        host: &HostConfig,
        scope_selection: &DoctorScopeSelection,
        probe: &TailscaleDoctorProbe,
        options: DoctorOptions,
    ) -> Result<Option<DoctorReport>, satelle_core::SatelleError> {
        let Some(prepared) = prepare_transport_only_doctor(host, scope_selection, options)? else {
            return Ok(None);
        };
        execute_transport_only_doctor(host_alias, scope_selection, probe, prepared).map(Some)
    }

    #[test]
    fn online_peer_reports_tailscale_address_guidance() {
        let status: TailscaleStatus = serde_json::from_str(
            r#"{
                "BackendState":"Running",
                "CurrentTailnet":{"Name":"example.test"},
                "Peer":{"node-key":{"HostName":"studio","DNSName":"studio.example.test.","TailscaleIPs":["100.64.0.8"],"Online":true}}
            }"#,
        )
        .expect("parse status fixture");

        let diagnosis = diagnose_status(status, Some("example.test"), Some("studio"));

        assert!(diagnosis.ready);
        assert!(
            diagnosis
                .finding
                .evidence
                .contains(&"suggested_dns_name=studio.example.test".to_string())
        );
        assert!(
            diagnosis
                .finding
                .evidence
                .contains(&"suggested_tailscale_ips=100.64.0.8".to_string())
        );
    }

    #[test]
    fn missing_cli_keeps_configuration_evidence_in_a_partial_report() {
        let selection = DoctorScopeSelection::parse(&["transport".to_string()])
            .expect("transport scope should parse");
        let host = tailscale_host();
        let probe = transport_doctor_probe_with(
            &selection,
            &host,
            Path::new("/definitely/missing/tailscale"),
        );
        let report = transport_only_doctor_report(
            "studio",
            &host,
            &selection,
            &probe,
            DoctorOptions::new(false, None).expect("default timeout is valid"),
        )
        .expect("transport scheduler")
        .expect("Tailscale host should produce a transport report");

        assert!(!report.ready);
        let finding = report.findings.first().expect("blocked transport finding");
        assert_eq!(finding.finding_id, "tailscale_cli_unavailable");
        assert_eq!(
            finding.evidence,
            vec![
                "network_provider=tailscale".to_string(),
                "live_checks=skipped".to_string()
            ]
        );
    }

    #[test]
    fn non_transport_scope_does_not_run_the_tailscale_executable() {
        let selection = DoctorScopeSelection::parse(&["config".to_string()])
            .expect("config scope should parse");

        let host = tailscale_host();
        let probe = transport_doctor_probe_with(
            &selection,
            &host,
            Path::new("/definitely/missing/tailscale"),
        );

        assert!(
            transport_only_doctor_report(
                "studio",
                &host,
                &selection,
                &probe,
                DoctorOptions::new(false, None).expect("default timeout is valid"),
            )
            .expect("transport scheduler")
            .is_none()
        );
    }

    fn tailscale_host() -> HostConfig {
        HostConfig {
            provider_bindings: std::collections::BTreeMap::new(),
            experimental_provider_computer_use_by_provider: std::collections::BTreeMap::new(),
            transport: TransportKind::Direct,
            adapter: AdapterKind::Codex,
            address: Some("https://studio.example.test:3001".to_string()),
            network: Some(NetworkConfig::Tailscale {
                tailnet_name: Some("example.test".to_string()),
                hostname: Some("studio".to_string()),
            }),
            timeouts: None,
            native_readiness_cache_ttl: None,
            provider_smoke_success_cache_ttl: None,
            provider_smoke_failure_cache_ttl: None,
            daemon_idle_timeout: None,
            desktop_user: None,
            desktop_session_preference: None,
            desktop_session_native_selector: None,
            daemon_home: None,
            daemon_config_file: None,
            daemon_state_dir: None,
            daemon_cache_dir: None,
            daemon_log_dir: None,
            setup_mode: None,
            experimental_provider_computer_use: None,
            yolo: None,
            allow_project_selection: false,
            expected_host_id: Some("host-studio".to_string()),
            api_token: Some(ApiTokenSource::File {
                path: PathBuf::from("/tmp/token"),
            }),
            ca_bundle: None,
            provider_auth: BTreeMap::new(),
        }
    }

    #[cfg(unix)]
    fn executable_fixture(contents: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("create Tailscale fixture directory");
        let executable = directory.path().join("tailscale-fixture");
        std::fs::write(&executable, contents).expect("write Tailscale fixture");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("make Tailscale fixture executable");
        (directory, executable)
    }

    #[cfg(unix)]
    #[test]
    fn blocking_status_times_out_and_is_killed_and_reaped() {
        let fifo_directory = tempfile::tempdir().expect("create status FIFO directory");
        let fifo = fifo_directory.path().join("status");
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("create status FIFO")
            .success()
            .then_some(())
            .expect("mkfifo succeeds");
        let pid_file = fifo_directory.path().join("pid");
        let script = format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec cat '{}'\n",
            pid_file.display(),
            fifo.display()
        );
        let (_fixture, executable) = executable_fixture(&script);
        let selection =
            DoctorScopeSelection::parse(&["transport".to_string()]).expect("transport scope");
        let host = tailscale_host();
        let probe = transport_doctor_probe_with(&selection, &host, &executable);

        let report = transport_only_doctor_report(
            "studio",
            &host,
            &selection,
            &probe,
            DoctorOptions::new(false, Some(std::time::Duration::from_millis(40)))
                .expect("positive timeout"),
        )
        .expect("transport scheduler")
        .expect("Direct Tailscale transport report");

        assert_eq!(report.probe_results[0].status, "timed_out");
        assert!(report.probe_results[0].duration_ms > 0);
        let pid = std::fs::read_to_string(pid_file).expect("read blocked status pid");
        assert!(
            !Path::new("/proc").join(pid).exists(),
            "timed out status child must be reaped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn escaped_stdout_holder_cannot_extend_the_hard_cleanup_deadline() {
        let script = "#!/bin/sh\nsetsid sh -c 'sleep 1' &\nwhile true; do sleep 1; done\n";
        let (_fixture, executable) = executable_fixture(script);
        let selection =
            DoctorScopeSelection::parse(&["transport".to_string()]).expect("transport scope");
        let host = tailscale_host();
        let probe = transport_doctor_probe_with(&selection, &host, &executable);
        let started = std::time::Instant::now();

        let report = transport_only_doctor_report(
            "studio",
            &host,
            &selection,
            &probe,
            DoctorOptions::new(false, Some(std::time::Duration::from_millis(80)))
                .expect("positive timeout"),
        )
        .expect("transport scheduler")
        .expect("Direct Tailscale transport report");

        assert_eq!(report.probe_results[0].status, "timed_out");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(300),
            "escaped pipe holders must not extend the hard cleanup deadline"
        );
    }

    #[test]
    fn terminal_transport_projection_owns_readiness_and_public_status() {
        let ready =
            ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::ready(None));
        let timed_out = project_transport_outcome(
            &ready,
            DoctorProbeCompletion::new(
                DoctorProbeStatus::TimedOut,
                DoctorDependentEvidence::NotUseful,
            ),
        );
        assert!(!timed_out.ready);
        assert_eq!(timed_out.status, "timed_out");
        assert_eq!(
            timed_out
                .observation
                .finding()
                .expect("timeout finding")
                .finding_id,
            "tailscale_probe_timed_out"
        );

        let blocked =
            ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::blocked(
                Diagnosis::blocked("tailscale_cli_unavailable", "blocked", Vec::new(), None)
                    .finding,
            ));
        let finding = project_transport_outcome(
            &blocked,
            DoctorProbeCompletion::new(DoctorProbeStatus::Finding, DoctorDependentEvidence::Useful),
        );
        assert!(!finding.ready);
        assert_eq!(finding.status, "blocked");
    }

    #[cfg(unix)]
    #[test]
    fn blocking_ping_uses_only_the_remaining_scheduler_budget() {
        let directory = tempfile::tempdir().expect("create ping FIFO directory");
        let fifo = directory.path().join("ping");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("create ping FIFO")
                .success()
        );
        let arguments = directory.path().join("arguments");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = status ]; then\n  printf '%s' \
             '{{\"BackendState\":\"Running\",\"CurrentTailnet\":{{\"Name\":\"example.test\"}},\
             \"Peer\":{{\"node\":{{\"HostName\":\"studio\",\"DNSName\":\"studio.example.test.\",\
             \"TailscaleIPs\":[\"100.64.0.8\"],\"Online\":true}}}}}}'\nelse\n  printf '%s\\n' \"$@\" > '{}'\n  exec cat '{}'\nfi\n",
            arguments.display(),
            fifo.display()
        );
        let (_fixture, executable) = executable_fixture(&script);
        let selection =
            DoctorScopeSelection::parse(&["transport".to_string()]).expect("transport scope");
        let host = tailscale_host();
        let probe = transport_doctor_probe_with(&selection, &host, &executable);

        let report = transport_only_doctor_report(
            "studio",
            &host,
            &selection,
            &probe,
            DoctorOptions::new(false, Some(std::time::Duration::from_millis(500)))
                .expect("positive timeout"),
        )
        .expect("transport scheduler")
        .expect("Direct Tailscale transport report");

        assert_eq!(report.probe_results[0].status, "timed_out");
        let arguments = std::fs::read_to_string(arguments).expect("read ping arguments");
        assert!(arguments.contains("--timeout"));
        assert!(arguments.contains("ms"));
        assert!(!arguments.contains("5s"));
    }

    #[cfg(unix)]
    #[test]
    fn direct_and_ssh_transport_only_reports_publish_live_timing_and_status() {
        for transport in [TransportKind::Direct, TransportKind::Ssh] {
            let fifo_directory = tempfile::tempdir().expect("create timing FIFO directory");
            let fifo = fifo_directory.path().join("status");
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&fifo)
                    .status()
                    .expect("create timing FIFO")
                    .success()
            );
            let script = format!("#!/bin/sh\nexec cat '{}'\n", fifo.display());
            let (_fixture, executable) = executable_fixture(&script);
            let selection =
                DoctorScopeSelection::parse(&["transport".to_string()]).expect("transport scope");
            let mut host = tailscale_host();
            host.transport = transport.clone();
            if transport == TransportKind::Ssh {
                host.address = Some("operator@studio".to_string());
            }
            let probe = transport_doctor_probe_with(&selection, &host, &executable);

            let report = transport_only_doctor_report(
                "studio",
                &host,
                &selection,
                &probe,
                DoctorOptions::new(false, Some(std::time::Duration::from_millis(30)))
                    .expect("positive timeout"),
            )
            .expect("transport scheduler")
            .expect("transport-only report");

            assert_eq!(report.probe_results[0].status, "timed_out");
            assert!(report.duration_ms > 0);
            assert_eq!(report.duration_ms, report.probe_results[0].duration_ms);
            assert_eq!(report.started_at, report.probe_results[0].started_at);
            assert_eq!(report.finished_at, report.probe_results[0].finished_at);
        }
    }
}
