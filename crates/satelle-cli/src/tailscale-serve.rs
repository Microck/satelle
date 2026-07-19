use crate::transport;
use satelle_core::{
    DaemonPathOverrides, ErrorCode, HostConfig, NetworkConfig, SatelleError, SetupReadinessSummary,
    SetupReport, SetupRequiredInput, SetupSchemaVersion, TransportKind,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use url::{Host, Url};

const PLANNED_COMMAND: &str = "tailscale serve --bg --yes --https 443 http://127.0.0.1:3001";
const SATELLE_HOST_PORT: u16 = 3001;

pub(super) fn applies_to(host: &HostConfig) -> bool {
    host.transport == TransportKind::Direct
        && matches!(host.network, Some(NetworkConfig::Tailscale { .. }))
}

pub(super) fn configure(
    host_alias: &str,
    host: &HostConfig,
    daemon_path_overrides: &DaemonPathOverrides,
    dry_run: bool,
    setup_mode: &str,
) -> Result<SetupReport, SatelleError> {
    let mut operations = SystemServeOperations;
    configure_with_operations(
        host_alias,
        host,
        daemon_path_overrides,
        dry_run,
        setup_mode,
        &mut operations,
    )
}

trait ServeOperations {
    fn probe(
        &mut self,
        host_alias: &str,
        destination: &str,
        daemon_path_overrides: &DaemonPathOverrides,
    ) -> Result<ServeProbe, SatelleError>;
    fn apply(&mut self, host_alias: &str, destination: &str) -> Result<(), SatelleError>;
}

struct SystemServeOperations;

struct ServeProbe {
    status: Vec<u8>,
    services: Vec<u8>,
}

impl ServeOperations for SystemServeOperations {
    fn probe(
        &mut self,
        host_alias: &str,
        destination: &str,
        daemon_path_overrides: &DaemonPathOverrides,
    ) -> Result<ServeProbe, SatelleError> {
        let (status, services) =
            transport::probe_tailscale_serve(host_alias, destination, daemon_path_overrides)?;
        Ok(ServeProbe { status, services })
    }

    fn apply(&mut self, host_alias: &str, destination: &str) -> Result<(), SatelleError> {
        transport::apply_tailscale_serve(host_alias, destination)
    }
}

fn configure_with_operations(
    host_alias: &str,
    host: &HostConfig,
    daemon_path_overrides: &DaemonPathOverrides,
    dry_run: bool,
    setup_mode: &str,
    operations: &mut impl ServeOperations,
) -> Result<SetupReport, SatelleError> {
    let destination = destination(host)?;
    // Preview and apply both inspect live Serve state. The apply-time check
    // avoids relying on a stale pre-consent preview when deciding whether the
    // incremental Serve mutation is safe.
    let probe = operations.probe(host_alias, destination, daemon_path_overrides)?;
    let public_endpoints = parse_public_satelle_funnel_endpoints(&probe.status, &probe.services)
        .map_err(|_| invalid_serve_status(host_alias))?;
    if !public_endpoints.is_empty() {
        return Ok(public_exposure_report(
            host_alias,
            setup_mode,
            dry_run,
            &public_endpoints,
        ));
    }
    let changed = if dry_run {
        false
    } else {
        operations.apply(host_alias, destination)?;
        true
    };
    Ok(report(host_alias, setup_mode, dry_run, changed))
}

fn invalid_serve_status(host_alias: &str) -> SatelleError {
    SatelleError {
        code: ErrorCode::RemoteExecution,
        message: format!(
            "remote Tailscale Serve status for host '{host_alias}' was not valid Serve JSON"
        ),
        recovery_command: Some(format!(
            "verify tailscale serve status --json on host {host_alias}, then rerun satelle setup --host {host_alias} --component transport --dry-run --json"
        )),
        source_detail: None,
        details: BTreeMap::from([("host".to_string(), Value::String(host_alias.to_string()))]),
    }
}

fn parse_public_satelle_funnel_endpoints(
    status: &[u8],
    services: &[u8],
) -> Result<Vec<String>, serde_json::Error> {
    let status: Option<ServeStatus> = serde_json::from_slice(status)?;
    let Some(status) = status else {
        return Ok(Vec::new());
    };
    let mut endpoints = BTreeSet::new();
    status.collect_public_satelle_funnel_endpoints(&mut endpoints);
    let services: ServicesConfig = serde_json::from_slice(services)?;
    let service_ports = services.satelle_inbound_ports();
    status.collect_public_service_endpoints(&service_ports, &mut endpoints);
    Ok(endpoints.into_iter().collect())
}

fn public_exposure_report(
    host_alias: &str,
    setup_mode: &str,
    dry_run: bool,
    public_endpoints: &[String],
) -> SetupReport {
    let warning = format!(
        "WARNING: Tailscale Funnel/public exposure is not allowed for desktop-control access (remote Funnel endpoints route to Satelle: {}); no Serve changes will be applied",
        public_endpoints.join(", ")
    );
    let recovery = "disable Funnel for every endpoint routing to Satelle's 127.0.0.1:3001 listener or its localhost or IPv4-mapped equivalents, then rerun setup";
    let mut report = report(host_alias, setup_mode, dry_run, false);
    report.status = "input_required".to_string();
    report.planned_actions = vec![warning];
    report.required_input = vec![SetupRequiredInput {
        component: "transport".to_string(),
        input_kind: "tailscale_private_exposure_required".to_string(),
        reason: "Satelle requires tailnet-only Tailscale Serve for desktop-control access"
            .to_string(),
        recovery_command: recovery.to_string(),
    }];
    report.recovery_commands = vec![recovery.to_string()];
    report.readiness_summary.transport = "blocked".to_string();
    report.next_command = recovery.to_string();
    report
}

#[derive(Debug, Deserialize)]
struct ServeStatus {
    #[serde(default, rename = "TCP")]
    tcp: BTreeMap<String, ServeTcpHandler>,
    #[serde(default, rename = "Web")]
    web: BTreeMap<String, ServeWeb>,
    #[serde(default, rename = "AllowFunnel")]
    allow_funnel: BTreeMap<String, bool>,
    #[serde(default, rename = "Foreground")]
    foreground: BTreeMap<String, Option<ServeStatus>>,
    #[serde(default, rename = "Services")]
    services: BTreeMap<String, ServeStatus>,
}

impl ServeStatus {
    fn collect_public_satelle_funnel_endpoints(&self, endpoints: &mut BTreeSet<String>) {
        endpoints.extend(
            self.allow_funnel
                .iter()
                .filter(|&(endpoint, allowed)| {
                    *allowed
                        && ((endpoint_port(endpoint) == Some(443)
                            && self.web.contains_key(endpoint))
                            || self.routes_to_satelle(endpoint))
                })
                .map(|(endpoint, _)| endpoint.clone()),
        );
        for foreground in self.foreground.values().flatten() {
            foreground.collect_public_satelle_funnel_endpoints(endpoints);
        }
        for service in self.services.values() {
            service.collect_public_satelle_funnel_endpoints(endpoints);
        }
    }

    fn collect_public_service_endpoints(
        &self,
        service_ports: &BTreeSet<u16>,
        endpoints: &mut BTreeSet<String>,
    ) {
        endpoints.extend(
            self.allow_funnel
                .iter()
                .filter(|&(endpoint, allowed)| {
                    *allowed
                        && endpoint_port(endpoint).is_some_and(|port| service_ports.contains(&port))
                })
                .map(|(endpoint, _)| endpoint.clone()),
        );
        for foreground in self.foreground.values().flatten() {
            foreground.collect_public_service_endpoints(service_ports, endpoints);
        }
        for service in self.services.values() {
            service.collect_public_service_endpoints(service_ports, endpoints);
        }
    }

    fn routes_to_satelle(&self, endpoint: &str) -> bool {
        self.web
            .get(endpoint)
            .is_some_and(ServeWeb::proxies_to_satelle)
            || endpoint
                .rsplit_once(':')
                .and_then(|(_, port)| self.tcp.get(port))
                .is_some_and(ServeTcpHandler::forwards_to_satelle)
            || self
                .services
                .values()
                .any(|service| service.routes_to_satelle(endpoint))
    }
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    endpoint.rsplit_once(':')?.1.parse().ok()
}

#[derive(Debug, Deserialize)]
struct ServicesConfig {
    #[serde(default)]
    services: BTreeMap<String, ServiceConfig>,
}

impl ServicesConfig {
    fn satelle_inbound_ports(&self) -> BTreeSet<u16> {
        self.services
            .values()
            .flat_map(|service| &service.endpoints)
            .filter_map(|(inbound, target)| {
                service_target_to_satelle(target)
                    .then(|| endpoint_port(inbound))
                    .flatten()
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct ServiceConfig {
    #[serde(default)]
    endpoints: BTreeMap<String, String>,
}

fn service_target_to_satelle(target: &str) -> bool {
    let Ok(target) = Url::parse(target) else {
        return false;
    };
    matches!(
        target.scheme(),
        "http" | "https" | "https+insecure" | "tcp" | "tls-terminated-tcp"
    ) && target.port() == Some(SATELLE_HOST_PORT)
        && is_satelle_listener_host(&target)
}

#[derive(Debug, Deserialize)]
struct ServeTcpHandler {
    #[serde(default, rename = "TCPForward")]
    tcp_forward: Option<String>,
}

impl ServeTcpHandler {
    fn forwards_to_satelle(&self) -> bool {
        self.tcp_forward.as_deref().is_some_and(forwards_to_satelle)
    }
}

#[derive(Debug, Deserialize)]
struct ServeWeb {
    #[serde(default, rename = "Handlers")]
    handlers: BTreeMap<String, ServeHandler>,
}

impl ServeWeb {
    fn proxies_to_satelle(&self) -> bool {
        self.handlers
            .values()
            .any(|handler| handler.proxy.as_deref().is_some_and(proxies_to_satelle))
    }
}

#[derive(Debug, Deserialize)]
struct ServeHandler {
    #[serde(default, rename = "Proxy")]
    proxy: Option<String>,
}

fn proxies_to_satelle(proxy: &str) -> bool {
    let expanded;
    let proxy = if proxy.bytes().all(|byte| byte.is_ascii_digit()) {
        expanded = format!("http://localhost:{proxy}");
        expanded.as_str()
    } else if proxy.contains("://") {
        proxy
    } else {
        expanded = format!("http://{proxy}");
        expanded.as_str()
    };
    let Ok(proxy) = Url::parse(proxy) else {
        return false;
    };
    matches!(proxy.scheme(), "http" | "https" | "https+insecure")
        && proxy.port() == Some(SATELLE_HOST_PORT)
        && is_satelle_listener_host(&proxy)
}

fn forwards_to_satelle(target: &str) -> bool {
    // A temporary HTTP scheme gives the URL parser a standards-aware host and
    // port grammar without treating TCPForward as an HTTP configuration.
    let Ok(target) = Url::parse(&format!("http://{target}")) else {
        return false;
    };
    target.port() == Some(SATELLE_HOST_PORT)
        && is_satelle_listener_host(&target)
        && target.path() == "/"
        && target.query().is_none()
        && target.fragment().is_none()
}

fn is_satelle_listener_host(target: &Url) -> bool {
    match target.host() {
        Some(Host::Ipv4(address)) => address == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(address)) => address == Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain == "localhost"
                || (domain.ends_with(".localhost") && domain.len() > ".localhost".len())
                || domain
                    .parse::<IpAddr>()
                    .is_ok_and(is_satelle_listener_address)
        }
        None => false,
    }
}

fn is_satelle_listener_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address == Ipv4Addr::LOCALHOST,
        IpAddr::V6(address) => address == Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
    }
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
    use std::collections::{BTreeMap, VecDeque};
    use std::path::PathBuf;

    const CLEAN_SERVE_STATUS: &[u8] = b"null";
    const CLEAN_SERVICE_CONFIG: &[u8] = br#"{"version":"0.0.1"}"#;
    const PUBLIC_SATELLE_FUNNEL_STATUS: &[u8] = br#"{
        "Web": {
            "studio.example.ts.net:443": {
                "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
            }
        },
        "AllowFunnel": {"studio.example.ts.net:443": true}
    }"#;
    const PUBLIC_SATELLE_FOREGROUND_FUNNEL_STATUS: &[u8] = br#"{
        "Foreground": {
            "session-1": {
                "Web": {
                    "ephemeral.example.ts.net:443": {
                        "Handlers": {"/": {"Proxy": "3001"}}
                    }
                },
                "AllowFunnel": {"ephemeral.example.ts.net:443": true}
            }
        }
    }"#;
    const PUBLIC_SATELLE_SERVICE_FUNNEL_STATUS: &[u8] = br#"{
        "Services": {
            "svc:studio": {
                "TCP": {
                    "8443": {"TCPForward": "127.0.0.1:3001"}
                },
                "Web": {
                    "studio.example.ts.net:443": {
                        "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
                    }
                }
            }
        },
        "AllowFunnel": {
            "studio.example.ts.net:443": true,
            "tcp.example.ts.net:8443": true
        }
    }"#;
    const PUBLIC_OTHER_BACKEND_HTTPS_STATUS: &[u8] = br#"{
        "Web": {
            "studio.example.ts.net:443": {
                "Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}
            }
        },
        "AllowFunnel": {"studio.example.ts.net:443": true}
    }"#;
    const PUBLIC_SERVICE_FUNNEL_STATUS: &[u8] = br#"{
        "AllowFunnel": {"service.example.ts.net:8443": true}
    }"#;
    const PUBLIC_NESTED_SERVICE_FUNNEL_STATUS: &[u8] = br#"{
        "Services": {
            "svc:studio": {
                "AllowFunnel": {"service.example.ts.net:8443": true}
            }
        }
    }"#;
    const SATELLE_SERVICE_CONFIG: &[u8] = br#"{
        "version": "0.0.1",
        "services": {
            "svc:studio": {
                "endpoints": {"tcp:8443": "tcp://127.0.0.1:3001"}
            }
        }
    }"#;

    struct ServeOperationsFixture {
        statuses: VecDeque<&'static [u8]>,
        service_configs: VecDeque<&'static [u8]>,
        calls: Vec<&'static str>,
    }

    impl ServeOperationsFixture {
        fn new(statuses: &[&'static [u8]]) -> Self {
            Self {
                statuses: statuses.iter().copied().collect(),
                service_configs: std::iter::repeat_n(CLEAN_SERVICE_CONFIG, statuses.len())
                    .collect(),
                calls: Vec::new(),
            }
        }

        fn with_service_config(status: &'static [u8], services: &'static [u8]) -> Self {
            Self {
                statuses: VecDeque::from([status]),
                service_configs: VecDeque::from([services]),
                calls: Vec::new(),
            }
        }
    }

    impl ServeOperations for ServeOperationsFixture {
        fn probe(
            &mut self,
            _host_alias: &str,
            _destination: &str,
            _daemon_path_overrides: &DaemonPathOverrides,
        ) -> Result<ServeProbe, SatelleError> {
            self.calls.push("probe");
            Ok(ServeProbe {
                status: self
                    .statuses
                    .pop_front()
                    .expect("Serve fixture must provide one status per probe")
                    .to_vec(),
                services: self
                    .service_configs
                    .pop_front()
                    .expect("Serve fixture must provide one service config per probe")
                    .to_vec(),
            })
        }

        fn apply(&mut self, _host_alias: &str, _destination: &str) -> Result<(), SatelleError> {
            self.calls.push("apply");
            Ok(())
        }
    }

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

    #[test]
    fn serve_status_reports_only_public_satelle_endpoints() {
        let endpoints = parse_public_satelle_funnel_endpoints(
            br#"{
                "TCP": {
                    "2222": {"TCPForward": "127.0.0.1:22"},
                    "8443": {"TCPForward": "[::ffff:127.0.0.1]:3001"},
                    "9443": {"HTTPS": true}
                },
                "Web": {
                    "studio.example.ts.net:443": {
                        "Handlers": {"/": {"Proxy": "http://localhost:3001/v1/sessions"}}
                    },
                    "other.example.ts.net:443": {
                        "Handlers": {"/": {"Proxy": "http://127.0.0.1:7676"}}
                    },
                    "private.example.ts.net:443": {
                        "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
                    }
                },
                "AllowFunnel": {
                    "studio.example.ts.net:443": true,
                    "other.example.ts.net:443": true,
                    "private.example.ts.net:443": false,
                    "ssh.example.ts.net:2222": true,
                    "tcp.example.ts.net:8443": true,
                    "https.example.ts.net:9443": true
                }
            }"#,
            CLEAN_SERVICE_CONFIG,
        )
        .expect("parse Serve status");

        assert_eq!(
            endpoints,
            [
                "other.example.ts.net:443",
                "studio.example.ts.net:443",
                "tcp.example.ts.net:8443"
            ]
        );
    }

    #[test]
    fn serve_status_reports_public_satelle_endpoints_from_foreground_sessions() {
        let endpoints = parse_public_satelle_funnel_endpoints(
            br#"{
                "Foreground": {
                    "session-1": {
                        "Web": {
                            "ephemeral.example.ts.net:443": {
                                "Handlers": {"/": {"Proxy": "http://127.0.0.1:3001"}}
                            }
                        },
                        "AllowFunnel": {"ephemeral.example.ts.net:443": true}
                    }
                }
            }"#,
            CLEAN_SERVICE_CONFIG,
        )
        .expect("parse foreground Serve status");

        assert_eq!(endpoints, ["ephemeral.example.ts.net:443"]);
    }

    #[test]
    fn serve_status_recognizes_all_supported_satelle_proxy_target_forms() {
        for proxy in ["http://127.0.0.1:3001", "localhost:3001", "3001"] {
            let status = format!(
                r#"{{
                    "Web": {{
                        "studio.example.ts.net:443": {{
                            "Handlers": {{"/": {{"Proxy": "{proxy}"}}}}
                        }}
                    }},
                    "AllowFunnel": {{"studio.example.ts.net:443": true}}
                }}"#
            );

            assert_eq!(
                parse_public_satelle_funnel_endpoints(status.as_bytes(), CLEAN_SERVICE_CONFIG)
                    .expect("parse supported Serve proxy target"),
                ["studio.example.ts.net:443"],
                "Proxy target {proxy} must resolve to Satelle"
            );
        }
    }

    #[test]
    fn live_public_funnel_status_returns_input_required_without_apply() {
        let host = tailscale_host();
        let mut operations = ServeOperationsFixture::new(&[PUBLIC_SATELLE_FUNNEL_STATUS]);

        let report = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect("public Funnel status must return a blocking report");

        assert_eq!(report.status, "input_required");
        assert!(!report.mutated);
        assert!(report.applied_actions.is_empty());
        assert_eq!(report.readiness_summary.transport, "blocked");
        assert!(report.planned_actions[0].contains("studio.example.ts.net:443"));
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn live_foreground_funnel_status_returns_input_required_without_apply() {
        let host = tailscale_host();
        let mut operations =
            ServeOperationsFixture::new(&[PUBLIC_SATELLE_FOREGROUND_FUNNEL_STATUS]);

        let report = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect("foreground Funnel status must return a blocking report");

        assert_eq!(report.status, "input_required");
        assert!(!report.mutated);
        assert!(report.applied_actions.is_empty());
        assert_eq!(report.readiness_summary.transport, "blocked");
        assert!(report.planned_actions[0].contains("ephemeral.example.ts.net:443"));
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn daemon_path_override_validation_blocks_serve_before_status_or_apply() {
        struct InvalidWindowsOverrideOperations {
            calls: Vec<&'static str>,
        }

        impl ServeOperations for InvalidWindowsOverrideOperations {
            fn probe(
                &mut self,
                _host_alias: &str,
                _destination: &str,
                daemon_path_overrides: &DaemonPathOverrides,
            ) -> Result<ServeProbe, SatelleError> {
                self.calls.push("probe_platform_and_validate_paths");
                assert_eq!(
                    daemon_path_overrides.state_dir.as_deref(),
                    Some(std::path::Path::new("/srv/satelle/state"))
                );
                Err(SatelleError::daemon_path_override_not_absolute(
                    "--daemon-state-dir",
                    "/srv/satelle/state".to_string(),
                ))
            }

            fn apply(&mut self, _host_alias: &str, _destination: &str) -> Result<(), SatelleError> {
                self.calls.push("apply");
                Ok(())
            }
        }

        let host = tailscale_host();
        let overrides = DaemonPathOverrides {
            state_dir: Some(PathBuf::from("/srv/satelle/state")),
            ..DaemonPathOverrides::default()
        };
        let mut operations = InvalidWindowsOverrideOperations { calls: Vec::new() };

        let error = configure_with_operations(
            "studio",
            &host,
            &overrides,
            false,
            "on_demand",
            &mut operations,
        )
        .expect_err("wrong-platform override must stop Serve setup");

        assert_eq!(error.code, ErrorCode::DaemonPathOverrideNotAbsolute);
        assert_eq!(operations.calls, ["probe_platform_and_validate_paths"]);
    }

    #[test]
    fn live_service_funnel_status_returns_input_required_without_apply() {
        let host = tailscale_host();
        let mut operations = ServeOperationsFixture::new(&[PUBLIC_SATELLE_SERVICE_FUNNEL_STATUS]);

        let report = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect("public VIP Service Funnel status must return a blocking report");

        assert_eq!(report.status, "input_required");
        assert!(!report.mutated);
        assert!(report.applied_actions.is_empty());
        assert_eq!(report.readiness_summary.transport, "blocked");
        assert!(report.planned_actions[0].contains("studio.example.ts.net:443"));
        assert!(report.planned_actions[0].contains("tcp.example.ts.net:8443"));
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn existing_https_funnel_is_blocked_before_satelle_rewrites_its_handler() {
        let host = tailscale_host();
        let mut operations = ServeOperationsFixture::new(&[PUBLIC_OTHER_BACKEND_HTTPS_STATUS]);

        let report = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect("an existing Funnel permit on the planned endpoint must block apply");

        assert_eq!(report.status, "input_required");
        assert!(!report.mutated);
        assert!(report.applied_actions.is_empty());
        assert!(report.planned_actions[0].contains("studio.example.ts.net:443"));
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn service_config_is_checked_when_status_omits_service_routes() {
        let host = tailscale_host();
        let mut operations = ServeOperationsFixture::with_service_config(
            PUBLIC_SERVICE_FUNNEL_STATUS,
            SATELLE_SERVICE_CONFIG,
        );

        let report = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect("public service config must block apply even when status omits its route");

        assert_eq!(report.status, "input_required");
        assert!(!report.mutated);
        assert!(report.applied_actions.is_empty());
        assert!(report.planned_actions[0].contains("service.example.ts.net:8443"));
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn live_nested_service_funnel_status_returns_input_required_without_apply() {
        let host = tailscale_host();
        let mut operations = ServeOperationsFixture::with_service_config(
            PUBLIC_NESTED_SERVICE_FUNNEL_STATUS,
            SATELLE_SERVICE_CONFIG,
        );

        let report = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect("a nested public VIP Service Funnel must block apply");

        assert_eq!(report.status, "input_required");
        assert!(!report.mutated);
        assert!(report.applied_actions.is_empty());
        assert_eq!(report.readiness_summary.transport, "blocked");
        assert!(report.planned_actions[0].contains("service.example.ts.net:8443"));
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn unrelated_service_funnel_on_https_does_not_block_node_serve_setup() {
        let endpoints = parse_public_satelle_funnel_endpoints(
            br#"{"AllowFunnel":{"docs.example.ts.net:443":true}}"#,
            br#"{
                "version":"0.0.1",
                "services":{
                    "svc:docs":{"endpoints":{"tcp:443":"tcp://127.0.0.1:8080"}}
                }
            }"#,
        )
        .expect("parse an unrelated public Service");

        assert!(endpoints.is_empty());
    }

    #[test]
    fn invalid_live_serve_status_fails_closed_without_apply() {
        let host = tailscale_host();
        let mut operations = ServeOperationsFixture::new(&[b"not-json"]);

        let error = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut operations,
        )
        .expect_err("invalid Serve status must prevent remote mutation");

        assert_eq!(error.code, ErrorCode::RemoteExecution);
        assert_eq!(operations.calls, ["probe"]);
    }

    #[test]
    fn apply_occurs_only_after_a_clean_apply_time_recheck() {
        let host = tailscale_host();
        let mut blocked_operations =
            ServeOperationsFixture::new(&[CLEAN_SERVE_STATUS, PUBLIC_SATELLE_FUNNEL_STATUS]);

        let preview = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            true,
            "on_demand",
            &mut blocked_operations,
        )
        .expect("clean preview must be planned");
        assert_eq!(preview.status, "planned");

        let blocked_apply = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut blocked_operations,
        )
        .expect("public apply-time recheck must return a blocking report");
        assert_eq!(blocked_apply.status, "input_required");
        assert_eq!(blocked_operations.calls, ["probe", "probe"]);

        let mut clean_operations =
            ServeOperationsFixture::new(&[CLEAN_SERVE_STATUS, CLEAN_SERVE_STATUS]);
        configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            true,
            "on_demand",
            &mut clean_operations,
        )
        .expect("clean preview must be planned");
        let applied = configure_with_operations(
            "studio",
            &host,
            &DaemonPathOverrides::default(),
            false,
            "on_demand",
            &mut clean_operations,
        )
        .expect("clean apply-time recheck must permit Serve apply");

        assert_eq!(applied.status, "configured");
        assert!(applied.mutated);
        assert_eq!(clean_operations.calls, ["probe", "probe", "apply"]);
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
