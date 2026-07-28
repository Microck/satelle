use satelle_core::{
    DoctorFinding, DoctorFixability, DoctorTransportObservation, HostConfig, NetworkConfig,
    TransportKind,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use url::Url;

const MAX_STATUS_BYTES: usize = 1024 * 1024;

pub(super) fn transport_doctor_observation(
    host: &HostConfig,
) -> Option<DoctorTransportObservation> {
    transport_doctor_observation_with(host, Path::new("tailscale"))
}

fn transport_doctor_observation_with(
    host: &HostConfig,
    executable: &Path,
) -> Option<DoctorTransportObservation> {
    let NetworkConfig::Tailscale {
        tailnet_name,
        hostname,
    } = host.network.as_ref()?;
    let address_target = host
        .address
        .as_deref()
        .and_then(|address| address_host(&host.transport, address));
    let target = hostname.as_deref().or(address_target.as_deref());

    // Tailscale is only a network provider. This path deliberately uses
    // read-only status and ping operations and never changes daemon, ACL, or
    // Serve state.
    let mut diagnosis = match read_status(executable) {
        Ok(status) => diagnose_status(status, tailnet_name.as_deref(), target),
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
        && ping(executable, target).is_err()
    {
        diagnosis = Diagnosis::blocked(
            "tailscale_host_unreachable",
            "the configured host is visible but did not answer a Tailscale-layer reachability probe",
            vec![format!("configured_target={target}")],
            Some("tailscale ping --c 1 <host>"),
        );
    }

    let finding = diagnosis.finding;
    Some(if diagnosis.ready {
        DoctorTransportObservation::ready(Some(finding))
    } else {
        DoctorTransportObservation::blocked(finding)
    })
}

fn read_status(executable: &Path) -> Result<TailscaleStatus, StatusReadError> {
    let stdout = run_bounded(executable, &["status", "--json"])?;
    serde_json::from_slice(&stdout).map_err(|_| StatusReadError::InvalidOutput)
}

fn ping(executable: &Path, target: &str) -> Result<(), StatusReadError> {
    run_bounded(executable, &["ping", "--c", "1", "--timeout", "5s", target]).map(|_| ())
}

fn run_bounded(executable: &Path, args: &[&str]) -> Result<Vec<u8>, StatusReadError> {
    let mut child = Command::new(executable)
        .args(args)
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
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((MAX_STATUS_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = child.wait().map_err(|_| StatusReadError::CommandFailed)?;
    let stdout = reader
        .join()
        .map_err(|_| StatusReadError::InvalidOutput)?
        .map_err(|_| StatusReadError::InvalidOutput)?;
    if stdout.len() > MAX_STATUS_BYTES {
        return Err(StatusReadError::InvalidOutput);
    }
    if !status.success() {
        return Err(StatusReadError::CommandFailed);
    }
    Ok(stdout)
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
        let observation = transport_doctor_observation_with(
            &tailscale_host(),
            Path::new("/definitely/missing/tailscale"),
        )
        .expect("Tailscale host should produce a transport observation");

        assert!(!observation.is_ready());
        let finding = observation.finding().expect("blocked transport finding");
        assert_eq!(finding.finding_id, "tailscale_cli_unavailable");
        assert_eq!(
            finding.evidence,
            vec![
                "network_provider=tailscale".to_string(),
                "live_checks=skipped".to_string()
            ]
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
}
