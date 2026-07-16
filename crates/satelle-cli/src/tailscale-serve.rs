use crate::transport;
use satelle_core::{
    HostConfig, NetworkConfig, SatelleError, SetupReadinessSummary, SetupReport,
    SetupSchemaVersion, TransportKind,
};

const PLANNED_COMMAND: &str = "tailscale serve --bg --yes --https 443 http://127.0.0.1:3001";

pub(super) fn applies_to(host: &HostConfig) -> bool {
    host.transport == TransportKind::Direct
        && matches!(host.network, Some(NetworkConfig::Tailscale { .. }))
}

pub(super) fn configure(
    host_alias: &str,
    host: &HostConfig,
    dry_run: bool,
    setup_mode: &str,
) -> Result<SetupReport, SatelleError> {
    let destination = destination(host)?;
    // run_setup always completes this read-only preview before it crosses the
    // consent gate. Apply therefore executes only the mutation, without
    // repeating the same remote validation.
    let changed = if dry_run {
        transport::probe_tailscale_serve(host_alias, destination)?;
        false
    } else {
        transport::apply_tailscale_serve(host_alias, destination)?;
        true
    };
    Ok(report(host_alias, setup_mode, dry_run, changed))
}

fn destination(host: &HostConfig) -> Result<&str, SatelleError> {
    if host.transport != TransportKind::Direct {
        return Err(SatelleError::invalid_usage(
            "Tailscale Serve setup requires transport = \"direct\"",
        ));
    }
    let NetworkConfig::Tailscale { hostname, .. } = host.network.as_ref().ok_or_else(|| {
        SatelleError::invalid_usage(
            "Tailscale Serve setup requires [hosts.<alias>.network] provider = \"tailscale\"",
        )
    })?;
    let destination = hostname.as_deref().ok_or_else(|| {
        SatelleError::invalid_usage(
            "Tailscale Serve setup requires network.hostname as the system OpenSSH destination",
        )
    })?;
    if destination.is_empty()
        || destination.starts_with('-')
        || destination.chars().any(char::is_control)
    {
        return Err(SatelleError::invalid_usage(
            "network.hostname is not a safe system OpenSSH destination",
        ));
    }
    Ok(destination)
}

fn report(host_alias: &str, setup_mode: &str, dry_run: bool, changed: bool) -> SetupReport {
    SetupReport {
        schema_version: SetupSchemaVersion::V1,
        host: host_alias.to_string(),
        dry_run,
        status: if dry_run { "planned" } else { "configured" }.to_string(),
        setup_mode: setup_mode.to_string(),
        service_persistent: false,
        service_scope: "remote_user".to_string(),
        fallback_reason: None,
        setup_components: vec!["transport".to_string()],
        planned_actions: vec![format!(
            "run remotely through system OpenSSH: {PLANNED_COMMAND}; preserve unrelated Tailscale Serve handlers"
        )],
        applied_actions: changed
            .then(|| format!("applied remote incremental Serve handler: {PLANNED_COMMAND}"))
            .into_iter()
            .collect(),
        required_input: Vec::new(),
        recovery_commands: vec![format!(
            "satelle doctor --host {host_alias} --scope transport --json"
        )],
        readiness_summary: SetupReadinessSummary {
            transport: if dry_run { "planned" } else { "configured" }.to_string(),
            host_daemon: "not_verified".to_string(),
            codex_runtime: "not_verified".to_string(),
            native_computer_use: "not_verified".to_string(),
            provider_auth: "not_verified".to_string(),
        },
        daemon_path_overrides: Vec::new(),
        mutated: changed,
        native_computer_use_readiness: "not_verified".to_string(),
        next_command: format!("satelle doctor --host {host_alias} --scope transport --json"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::{AdapterKind, ApiTokenSource};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn preview_names_only_the_incremental_tailnet_serve_mutation() {
        let report = report("studio", "on_demand", true, false);
        assert_eq!(report.setup_components, ["transport"]);
        assert!(report.planned_actions[0].contains(PLANNED_COMMAND));
        assert!(!report.planned_actions[0].contains("reset"));
        assert!(!report.planned_actions[0].contains("set-config"));
        assert!(!report.planned_actions[0].contains("funnel"));
        assert!(!report.mutated);
    }

    #[test]
    fn only_tailscale_backed_direct_hosts_select_the_helper() {
        let mut host = tailscale_host();
        assert!(applies_to(&host));
        assert_eq!(destination(&host).unwrap(), "studio.example.ts.net");
        host.transport = TransportKind::Ssh;
        assert!(!applies_to(&host));
    }

    fn tailscale_host() -> HostConfig {
        HostConfig {
            transport: TransportKind::Direct,
            adapter: AdapterKind::Codex,
            address: Some("https://studio.example.ts.net".to_string()),
            network: Some(NetworkConfig::Tailscale {
                tailnet_name: Some("example.ts.net".to_string()),
                hostname: Some("studio.example.ts.net".to_string()),
            }),
            timeouts: None,
            native_readiness_cache_ttl: None,
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
