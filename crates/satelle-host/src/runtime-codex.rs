use command_group::CommandGroup;
use satelle_core::{
    ControlPlaneCapability, ControlPlaneCapabilitySet, ControlPlaneFailureReason,
    ControlPlaneOperation, IncompatibleControlPlaneDetails, SatelleError,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
#[cfg(not(windows))]
use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA_FILE_LIMIT: u64 = 2 * 1024 * 1024;
const HANDSHAKE_LINE_LIMIT: u64 = 64 * 1024;
const HANDSHAKE_MESSAGE_LIMIT: usize = 64;
const HANDSHAKE_SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
// A cold probe verifies the managed runtime, generates the full app-server
// schema, and completes a live handshake. Windows ARM64 has taken 14.5 seconds
// for this path, so the blocking admission budget must cover the cold case.
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
// Native isolation serializes desktop-app authentication, plugin and MCP
// inventories, Computer Use helper authentication, and the final bridge check.
// The current Windows ARM64 runtime can spend 30 seconds reopening the managed
// Codex home immediately after a native session, even though each warm command
// is fast. Keep one fail-closed deadline over the complete trust decision.
pub(super) const NATIVE_ISOLATION_TIMEOUT: Duration = Duration::from_secs(90);
const INVENTORY_OUTPUT_LIMIT: u64 = 2 * 1024 * 1024;
const COMPUTER_USE_PLUGIN_ID: &str = "computer-use@openai-bundled";
#[cfg(target_os = "macos")]
const MACOS_CODEX_APP_ID: &str = "com.openai.codex";
#[cfg(target_os = "macos")]
const MACOS_CODEX_CLI_ID: &str = "codex";
#[cfg(target_os = "macos")]
const MACOS_CODEX_APP_PATH: &str = "/Applications/ChatGPT.app";
const MACOS_NODE_REPL_ROOT: &str = "/Applications/ChatGPT.app/Contents/Resources/cua_node";
#[cfg(target_os = "macos")]
const MACOS_NATIVE_BRIDGE_LAUNCHER: &str = "__satelle-launch-macos-native-bridge";
#[cfg(target_os = "macos")]
const MACOS_COMPUTER_USE_SERVICE_ID: &str = "com.openai.sky.CUAService";
#[cfg(any(target_os = "macos", all(test, unix)))]
const MACOS_COMPUTER_USE_SERVICE_EXECUTABLE: &str = "SkyComputerUseService";
#[cfg(windows)]
const CODEX_PACKAGE_FAMILY: &str = "OpenAI.Codex_2p2nqsd0c76g0";
#[cfg(windows)]
const CODEX_PACKAGE_NODE_REPL: &str = "app/resources/cua_node/bin/node_repl.exe";
const NATIVE_BRIDGE_FILE_LIMIT: u64 = 64 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MACOS_NATIVE_LAUNCHER_FILE_LIMIT: u64 = 256 * 1024 * 1024;
#[cfg(any(target_os = "macos", all(test, unix)))]
const MACOS_SERVICE_INFO_LIMIT: u64 = 1024 * 1024;
const WINDOWS_LOCKED_BRIDGE_SCRIPT: &str = r#"& { param([string]$bridge,[string]$expected) $ErrorActionPreference='Stop'; if ([string]::IsNullOrEmpty($bridge) -or [string]::IsNullOrEmpty($expected)) { exit 64 }; $stream=$null; $child=$null; try { $stream=[System.IO.File]::Open($bridge,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read); $sha=[System.Security.Cryptography.SHA256]::Create(); try { $actual=([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') } finally { $sha.Dispose() }; if (-not $actual.Equals($expected,[System.StringComparison]::OrdinalIgnoreCase)) { exit 74 }; $start=New-Object System.Diagnostics.ProcessStartInfo; $start.FileName=$bridge; $start.UseShellExecute=$false; $child=[System.Diagnostics.Process]::Start($start); if ($null -eq $child) { exit 74 } } catch { exit 74 } finally { if ($null -ne $stream) { $stream.Dispose() } }; $child.WaitForExit(); exit $child.ExitCode }"#;
static SCHEMA_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const REQUIRED_LIFECYCLE_NOTIFICATIONS: [&str; 5] = [
    "thread/started",
    "turn/started",
    "item/started",
    "item/completed",
    "turn/completed",
];
/// Sanitized result of schema discovery plus a live initialize/initialized
/// exchange over a private stdio child process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlPlaneProbe {
    operations: ControlPlaneCapabilitySet,
    schema_available: bool,
    handshake_completed: bool,
    goal_set: bool,
    image_input: CodexImageInputMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexImageInputMode {
    Unsupported,
    Inline,
    Local,
}

impl ControlPlaneProbe {
    const fn unavailable() -> Self {
        Self {
            operations: ControlPlaneCapabilitySet::EMPTY,
            schema_available: false,
            handshake_completed: false,
            goal_set: false,
            image_input: CodexImageInputMode::Unsupported,
        }
    }

    pub(super) const fn supports(self, capability: ControlPlaneCapability) -> bool {
        self.schema_available && self.handshake_completed && self.operations.contains(capability)
    }

    pub(super) const fn handshake_completed(self) -> bool {
        self.handshake_completed
    }
}

/// Sanitized admission evidence retained by the production adapter. It stores
/// only closed failure reasons and capability bits, never upstream method
/// names, schema bytes, process output, or app-server messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlPlaneAdmission {
    NotApplicable,
    Unavailable(ControlPlaneFailureReason),
    Probed(ControlPlaneProbe),
}

impl ControlPlaneAdmission {
    pub(crate) const fn not_applicable() -> Self {
        Self::NotApplicable
    }

    pub(crate) const fn unavailable(reason: ControlPlaneFailureReason) -> Self {
        Self::Unavailable(reason)
    }

    pub(crate) const fn from_probe(probe: ControlPlaneProbe) -> Self {
        Self::Probed(probe)
    }

    pub(crate) const fn goal_set(self) -> bool {
        matches!(self, Self::Probed(probe) if probe.handshake_completed && probe.goal_set)
    }

    pub(crate) const fn image_input(self) -> CodexImageInputMode {
        match self {
            Self::Probed(probe) if probe.handshake_completed => probe.image_input,
            Self::Probed(_) => CodexImageInputMode::Unsupported,
            Self::NotApplicable | Self::Unavailable(_) => CodexImageInputMode::Unsupported,
        }
    }

    pub(crate) fn admit(self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        let required = operation.required_capabilities();
        let (reason, missing) = match self {
            Self::NotApplicable => return Ok(()),
            Self::Unavailable(reason) => (reason, Vec::new()),
            Self::Probed(probe) if !probe.schema_available => {
                (ControlPlaneFailureReason::SchemaUnavailable, Vec::new())
            }
            Self::Probed(probe) if !probe.handshake_completed => {
                (ControlPlaneFailureReason::HandshakeUnavailable, Vec::new())
            }
            Self::Probed(probe) => {
                let missing = required
                    .iter()
                    .copied()
                    .filter(|capability| !probe.operations.contains(*capability))
                    .collect::<Vec<_>>();
                if missing.is_empty() {
                    return Ok(());
                }
                (
                    ControlPlaneFailureReason::RequiredCapabilityMissing,
                    missing,
                )
            }
        };
        let details = IncompatibleControlPlaneDetails::new(operation, reason, &missing)
            .expect("the closed operation capability matrix is internally consistent");
        Err(SatelleError::incompatible_control_plane(details))
    }
}

impl super::CapabilityMatrix {
    pub(super) fn from_control_plane(probe: ControlPlaneProbe) -> Self {
        let unobserved = super::CapabilityEvidence::new(
            super::EvidenceSurface::Absent,
            super::LiveProofStatus::NotObserved,
        );
        let stable = |capability| {
            super::CapabilityEvidence::new(
                if probe.supports(capability) {
                    super::EvidenceSurface::Stable
                } else {
                    super::EvidenceSurface::Absent
                },
                super::LiveProofStatus::NotRequired,
            )
        };
        let stable_unobserved = |capability| {
            super::CapabilityEvidence::new(
                stable(capability).surface,
                super::LiveProofStatus::NotObserved,
            )
        };
        let handshake = super::CapabilityEvidence::new(
            if probe.handshake_completed() {
                super::EvidenceSurface::Stable
            } else {
                super::EvidenceSurface::Absent
            },
            super::LiveProofStatus::NotRequired,
        );

        Self {
            handshake,
            session_thread_creation: stable(ControlPlaneCapability::SessionCreation),
            turn_start: stable(ControlPlaneCapability::TurnStart),
            lifecycle_events: stable(ControlPlaneCapability::EventObservation),
            approval_observation: unobserved,
            native_readiness: unobserved,
            native_harmless_action: unobserved,
            recovery: if probe.supports(ControlPlaneCapability::Status)
                && probe.supports(ControlPlaneCapability::Steering)
            {
                super::CapabilityEvidence::new(
                    super::EvidenceSurface::Stable,
                    super::LiveProofStatus::NotObserved,
                )
            } else {
                unobserved
            },
            follow_up_turn: stable_unobserved(ControlPlaneCapability::Steering),
            // Detached ownership is a Host Daemon behavior, not a method in
            // the upstream schema. It remains unproven until the live journey.
            detached_turn_ownership: unobserved,
            interrupt_request: stable(ControlPlaneCapability::Cancellation),
            confirmed_stop: if probe.supports(ControlPlaneCapability::Cancellation)
                && probe.supports(ControlPlaneCapability::EventObservation)
            {
                super::CapabilityEvidence::new(
                    super::EvidenceSurface::Stable,
                    super::LiveProofStatus::NotObserved,
                )
            } else {
                unobserved
            },
        }
    }
}

pub(super) fn probe_installed_control_plane(
    runtime: &crate::codex_install::VerifiedCodexRuntime,
    timeout: Option<Duration>,
) -> ControlPlaneProbe {
    let timeout = timeout.unwrap_or(PROBE_TIMEOUT);
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return ControlPlaneProbe::unavailable();
    };
    let Ok([mut mcp_command, mut schema_command, mut app_server_command]) = runtime.commands()
    else {
        return ControlPlaneProbe::unavailable();
    };
    mcp_command = configure_mcp_inventory_command(mcp_command);
    let Ok(mcp_output) = bounded_inventory_command_output(
        mcp_command,
        deadline,
        "mcp_inventory_unavailable",
        "mcp_inventory_failed",
    ) else {
        return ControlPlaneProbe::unavailable();
    };
    let Ok(mcp_server_names) = mcp_server_names_from_json(&mcp_output) else {
        return ControlPlaneProbe::unavailable();
    };
    let schema_command = move |schema_dir: &Path| {
        schema_command
            .args(["app-server", "generate-json-schema", "--out"])
            .arg(schema_dir);
        schema_command
    };
    app_server_command =
        configure_control_plane_probe_command(app_server_command, &mcp_server_names);
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return ControlPlaneProbe::unavailable();
    }
    probe_control_plane_with(schema_command, app_server_command, remaining)
}

pub(super) fn mcp_server_names_from_json(mcp_json: &[u8]) -> Result<Vec<String>, SatelleError> {
    Ok(configured_mcp_servers_from_json(mcp_json)?
        .into_iter()
        .map(|server| server.name)
        .collect())
}

pub(super) fn configure_mcp_inventory_command(mut command: Command) -> Command {
    // Plugin MCP servers are resolved from plugin-relative paths. Re-declaring
    // one as a partial top-level override makes Codex reject the transport
    // before the app-server starts. Inventory only user-configured servers;
    // `features.plugins=false` isolates every plugin-provided server itself.
    command.args([
        "mcp",
        "list",
        "--config",
        "features.plugins=false",
        "--json",
    ]);
    command
}

fn configured_mcp_servers_from_json(
    mcp_json: &[u8],
) -> Result<Vec<ConfiguredMcpServer>, SatelleError> {
    let mut servers = serde_json::from_slice::<Vec<ConfiguredMcpServer>>(mcp_json)
        .map_err(|_| codex_isolation_error("mcp_inventory_malformed"))?;
    if servers
        .iter()
        .any(|server| !isolatable_mcp_name(&server.name))
    {
        return Err(codex_isolation_error("mcp_server_name_not_isolatable"));
    }
    servers.sort_by(|left, right| left.name.cmp(&right.name));
    if servers.windows(2).any(|pair| pair[0].name == pair[1].name) {
        return Err(codex_isolation_error("mcp_inventory_ambiguous"));
    }
    Ok(servers)
}

pub(super) fn configure_control_plane_probe_command(
    mut command: Command,
    mcp_server_names: &[String],
) -> Command {
    command.arg("app-server");
    for server_name in mcp_server_names {
        command.args([
            "--config",
            &format!("mcp_servers.{server_name}.enabled=false"),
        ]);
    }
    command.args([
        "--config",
        "features.apps=false",
        "--config",
        "features.plugins=false",
        "--listen",
        "stdio://",
    ]);
    command
}

pub(crate) fn installed_read_only_app_server_command(
    deadline: Instant,
) -> Result<Command, SatelleError> {
    let runtime = crate::codex_install::admit_managed_codex_for_current_process()?;
    // Build both commands from one post-admission identity verification. The
    // inventory subprocess then consumes the same recovery deadline before
    // the already-verified app-server command can be returned.
    let [mut mcp_command, app_server_command] = runtime.commands()?;
    mcp_command = configure_mcp_inventory_command(mcp_command);
    let mcp_output = bounded_inventory_command_output(
        mcp_command,
        deadline,
        "mcp_inventory_unavailable",
        "mcp_inventory_failed",
    )?;
    let mcp_server_names = mcp_server_names_from_json(&mcp_output)?;
    Ok(configure_control_plane_probe_command(
        app_server_command,
        &mcp_server_names,
    ))
}

pub(crate) fn installed_computer_use_app_server()
-> Result<VerifiedComputerUseAppServer, SatelleError> {
    let runtime = crate::codex_install::admit_managed_codex_for_current_process()?;
    verified_computer_use_app_server(&runtime)
}

pub(crate) fn verified_app_server_command(
    runtime: &crate::codex_install::VerifiedCodexRuntime,
) -> Result<VerifiedComputerUseAppServer, SatelleError> {
    verified_computer_use_app_server(runtime)
}

fn verified_computer_use_app_server(
    runtime: &crate::codex_install::VerifiedCodexRuntime,
) -> Result<VerifiedComputerUseAppServer, SatelleError> {
    let isolation_deadline = Instant::now()
        .checked_add(NATIVE_ISOLATION_TIMEOUT)
        .ok_or_else(|| codex_isolation_error("inventory_deadline_invalid"))?;
    let [plugin_command, mcp_command, app_server_command] =
        computer_use_runtime_commands(runtime, isolation_deadline)?;
    let (mut isolation, trusted_native_bridge_root, isolation_deadline) =
        configured_codex_isolation(
            runtime.codex_home(),
            plugin_command,
            mcp_command,
            isolation_deadline,
        )?;
    // The Windows desktop app creates a new named pipe on every launch and
    // rewrites the interactive user's Codex config with that address. The
    // isolated managed home can therefore retain a retired pipe after an app
    // restart. Refresh only this short-lived, strictly shaped address from the
    // current app-updated config; all executable and code-path trust still comes
    // from the authenticated managed inventory below.
    refresh_windows_native_pipe_binding(
        &mut isolation.native_mcp_binding,
        &isolation.native_mcp_server_name,
    )?;
    let prepared_native_bridge = prepare_native_bridge(
        Path::new(&isolation.native_mcp_binding.command),
        &trusted_native_bridge_root,
        std::env::consts::OS,
        runtime.codex_home(),
        &mut isolation.native_mcp_binding.env,
        isolation_deadline,
    )?;
    isolation.native_mcp_binding.command = prepared_native_bridge.command;
    isolation
        .native_mcp_binding
        .args
        .splice(0..0, prepared_native_bridge.prefix_args);
    let native_action_path = match isolation.planned_native_action_path {
        PlannedNativeComputerUseActionPath::WindowsNodeRepl => {
            NativeComputerUseActionPath::WindowsNodeRepl
        }
        PlannedNativeComputerUseActionPath::MacosNodeRepl => {
            NativeComputerUseActionPath::MacosNodeRepl
        }
    };
    Ok(VerifiedComputerUseAppServer {
        command: configure_app_server_command(
            app_server_command,
            &isolation.disabled_mcp_server_names,
            &isolation.native_mcp_server_name,
            &isolation.native_mcp_binding,
        ),
        native_mcp_server_name: isolation.native_mcp_server_name,
        native_action_path,
        plugin_version: isolation.plugin_version,
        native_runtime_version: prepared_native_bridge.native_runtime_version,
        native_action_evidence: crate::provider_probe::NativeActionEvidence::new(),
        _native_resources: prepared_native_bridge.native_resources,
    })
}

pub(crate) fn configure_app_server_command(
    mut command: Command,
    mcp_server_names: &[String],
    native_mcp_server_name: &str,
    native_mcp_binding: &NativeMcpBinding,
) -> Command {
    // The Host owns this process through private pipes. No socket or public
    // listener exists at the upstream protocol seam.
    // Satelle also owns the available action path. It configures the validated
    // bridge sourced from OpenAI's Computer Use plugin directly, while the
    // plugin loader remains disabled. Bind the validated values on the
    // app-server process and in the canonical MCP child table; Sky reads the
    // explicit child values through nodeRepl.env.
    command.envs(&native_mcp_binding.env);
    command.arg("app-server");
    for server_name in mcp_server_names {
        command.args([
            "--config",
            &format!("mcp_servers.{server_name}.enabled=false"),
        ]);
    }
    for config in native_mcp_config_overrides(native_mcp_server_name, native_mcp_binding) {
        command.args(["--config", &config]);
    }
    // The Windows Computer Use helper creates a nested app-approval
    // elicitation from inside node_repl. Pin both stable Codex features so a
    // user-level feature override cannot remove that approval path from the
    // Host-owned private app-server process.
    command.args([
        "--config",
        "features.auth_elicitation=true",
        "--config",
        "features.tool_call_mcp_elicitation=true",
        "--config",
        "features.apps=false",
        "--config",
        "features.plugins=false",
        "--listen",
        "stdio://",
    ]);
    command
}

fn native_mcp_config_overrides(name: &str, binding: &NativeMcpBinding) -> Vec<String> {
    let args = binding
        .args
        .iter()
        .map(|value| toml::Value::String(value.clone()).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let env = binding
        .env
        .iter()
        .map(|(key, value)| {
            format!(
                "{} = {}",
                toml::Value::String(key.clone()),
                toml::Value::String(value.clone())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    vec![
        format!("mcp_servers.{name}.enabled=true"),
        format!(
            "mcp_servers.{name}.command={}",
            toml::Value::String(binding.command.clone())
        ),
        format!("mcp_servers.{name}.args=[{args}]"),
        format!("mcp_servers.{name}.env={{ {env} }}"),
    ]
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CodexIsolationPlan {
    pub(crate) disabled_mcp_server_names: Vec<String>,
    pub(crate) native_mcp_server_name: String,
    pub(crate) plugin_version: String,
    pub(super) planned_native_action_path: PlannedNativeComputerUseActionPath,
    pub(super) native_mcp_binding: NativeMcpBinding,
}

#[derive(Eq, PartialEq)]
pub(crate) enum NativeComputerUseActionPath {
    WindowsNodeRepl,
    MacosNodeRepl,
}

impl std::fmt::Debug for NativeComputerUseActionPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowsNodeRepl => formatter.write_str("WindowsNodeRepl"),
            Self::MacosNodeRepl => formatter.write_str("MacosNodeRepl"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum PlannedNativeComputerUseActionPath {
    WindowsNodeRepl,
    MacosNodeRepl,
}

pub(crate) struct VerifiedComputerUseAppServer {
    pub(crate) command: Command,
    pub(crate) native_mcp_server_name: String,
    pub(crate) native_action_path: NativeComputerUseActionPath,
    plugin_version: String,
    native_runtime_version: String,
    native_action_evidence: crate::provider_probe::NativeActionEvidence,
    _native_resources: NativeSessionResources,
}

impl VerifiedComputerUseAppServer {
    pub(crate) fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub(crate) fn native_runtime_version(&self) -> &str {
        &self.native_runtime_version
    }

    pub(crate) fn native_action_evidence(&self) -> crate::provider_probe::NativeActionEvidence {
        self.native_action_evidence.clone()
    }
}

impl std::fmt::Debug for VerifiedComputerUseAppServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedComputerUseAppServer")
    }
}

#[cfg(test)]
impl VerifiedComputerUseAppServer {
    pub(crate) fn for_test(command: Command) -> Self {
        Self {
            command,
            native_mcp_server_name: "computer-use".to_owned(),
            native_action_path: NativeComputerUseActionPath::MacosNodeRepl,
            plugin_version: "test-plugin-1".to_owned(),
            native_runtime_version: "cdhash-test-bridge-1".to_owned(),
            native_action_evidence: crate::provider_probe::NativeActionEvidence::new(),
            _native_resources: NativeSessionResources::empty(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct NativeMcpBinding {
    pub(super) command: String,
    pub(super) args: Vec<String>,
    pub(super) env: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct PluginInventory {
    installed: Vec<InstalledPlugin>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstalledPlugin {
    plugin_id: String,
    marketplace_name: String,
    installed: bool,
    enabled: bool,
    #[serde(default)]
    version: Option<String>,
    source: InstalledPluginSource,
}

#[derive(Deserialize)]
struct InstalledPluginSource {
    source: String,
    path: PathBuf,
}

#[derive(Deserialize)]
struct ConfiguredMcpServer {
    name: String,
    transport: ConfiguredMcpTransport,
}

#[derive(Deserialize)]
struct ConfiguredMcpTransport {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Option<BTreeMap<String, String>>,
    #[serde(default)]
    cwd: Option<String>,
}

fn configured_codex_isolation(
    codex_home: &Path,
    mut plugin_command: Command,
    mut mcp_command: Command,
    deadline: Instant,
) -> Result<(CodexIsolationPlan, PathBuf, Instant), SatelleError> {
    plugin_command.args(["plugin", "list", "--available", "--json"]);
    let plugin_output = bounded_inventory_command_output(
        plugin_command,
        deadline,
        "plugin_inventory_unavailable",
        "plugin_inventory_failed",
    )?;

    mcp_command = configure_mcp_inventory_command(mcp_command);
    let mcp_output = bounded_inventory_command_output(
        mcp_command,
        deadline,
        "mcp_inventory_unavailable",
        "mcp_inventory_failed",
    )?;

    let trusted_native_bridge_root = official_native_bridge_root(std::env::consts::OS, codex_home)?;
    let isolation = codex_isolation_plan_from_json(
        &plugin_output,
        &mcp_output,
        std::env::consts::OS,
        codex_home,
        &trusted_native_bridge_root,
    )?;
    #[cfg(target_os = "macos")]
    authenticate_macos_computer_use_service(codex_home, deadline)?;
    Ok((isolation, trusted_native_bridge_root, deadline))
}

fn computer_use_runtime_commands<const COUNT: usize>(
    runtime: &crate::codex_install::VerifiedCodexRuntime,
    deadline: Instant,
) -> Result<[Command; COUNT], SatelleError> {
    #[cfg(target_os = "macos")]
    {
        // The signed macOS Computer Use service authenticates the node_repl
        // process and its Codex ancestor as one desktop release family. A
        // separately installed standalone Codex binary is signed by OpenAI,
        // but the service rejects that mixed ancestry before the first ping.
        let binary = authenticate_macos_codex_app(deadline)?;
        Ok(std::array::from_fn(|_| {
            macos_codex_app_command(&binary, runtime.codex_home())
        }))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = deadline;
        runtime.commands()
    }
}

pub(super) fn bounded_inventory_command_output(
    mut command: Command,
    deadline: Instant,
    unavailable_reason: &'static str,
    failed_reason: &'static str,
) -> Result<Vec<u8>, SatelleError> {
    if Instant::now() >= deadline {
        return Err(codex_isolation_error(unavailable_reason));
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
        .map_err(|_| codex_isolation_error(unavailable_reason))?;
    let Some(stdout) = child.inner().stdout.take() else {
        let _ = super::terminate_group(&mut child);
        return Err(codex_isolation_error(unavailable_reason));
    };
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let output = read_inventory_output(stdout, deadline);
        let _ = sender.send(output);
    });
    // Inventory success belongs to the command leader. Codex may leave
    // background helpers in the Windows job after that leader has emitted
    // complete JSON and exited. Waiting for the full job here consumes the
    // probe deadline; terminate and verify descendants immediately instead.
    let status = super::wait_for_leader(&mut child, deadline);
    let group_stopped = super::terminate_group(&mut child);
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(10));
    let output = receiver.recv_timeout(remaining);
    let reader_stopped = reader.join().is_ok();
    finish_inventory_output(
        status,
        group_stopped && reader_stopped,
        output.ok().and_then(Result::ok),
        unavailable_reason,
        failed_reason,
    )
}

fn finish_inventory_output(
    status: super::GroupWaitOutcome,
    resources_stopped: bool,
    output: Option<Vec<u8>>,
    unavailable_reason: &'static str,
    failed_reason: &'static str,
) -> Result<Vec<u8>, SatelleError> {
    let Some(output) = output.filter(|output| output.len() <= INVENTORY_OUTPUT_LIMIT as usize)
    else {
        return Err(codex_isolation_error(unavailable_reason));
    };
    if !resources_stopped {
        return Err(codex_isolation_error(unavailable_reason));
    }
    match status {
        super::GroupWaitOutcome::Exited(status) if status.success() => Ok(output),
        super::GroupWaitOutcome::Exited(_) => Err(codex_isolation_error(failed_reason)),
        super::GroupWaitOutcome::Deadline | super::GroupWaitOutcome::Error => {
            Err(codex_isolation_error(unavailable_reason))
        }
    }
}

#[cfg(unix)]
fn read_inventory_output(
    stdout: std::process::ChildStdout,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    super::set_nonblocking(&stdout)?;
    let mut output = Vec::new();
    let mut bounded = stdout.take(INVENTORY_OUTPUT_LIMIT + 1);
    loop {
        match bounded.read_to_end(&mut output) {
            Ok(_) => return Ok(output),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                // Codex can leave a group-escaping helper holding stdout after
                // the verified command leader has emitted its one JSON value.
                // Match the Windows pipe reader: complete JSON is the bounded
                // inventory contract, so pipe EOF is not additional evidence.
                if serde_json::from_slice::<Value>(&output).is_ok() {
                    return Ok(output);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
fn read_inventory_output(
    mut stdout: std::process::ChildStdout,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let mut output = Vec::new();
    loop {
        let mut available = 0_u32;
        // Anonymous child pipes are implemented as named pipes on Windows.
        // Peek before each read so the reader never blocks after the deadline
        // or while process-group termination is being reconciled.
        let peeked = unsafe {
            PeekNamedPipe(
                stdout.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if peeked == 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::BrokenPipe {
                Ok(output)
            } else {
                Err(error)
            };
        }
        if available > 0 {
            let remaining = (INVENTORY_OUTPUT_LIMIT + 1)
                .saturating_sub(output.len() as u64)
                .min(u64::from(available));
            if remaining == 0 {
                return Ok(output);
            }
            let start = output.len();
            output.resize(start + remaining as usize, 0);
            stdout.read_exact(&mut output[start..])?;
            // Inventory commands emit exactly one JSON value. A Codex helper
            // can inherit the pipe after the command leader exits, so EOF is
            // not a valid completion requirement on Windows. The caller still
            // requires the verified leader's successful exit status.
            if serde_json::from_slice::<Value>(&output).is_ok() {
                return Ok(output);
            }
            continue;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "inventory pipe read deadline expired",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(all(not(unix), not(windows)))]
fn read_inventory_output(
    stdout: std::process::ChildStdout,
    _deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    stdout
        .take(INVENTORY_OUTPUT_LIMIT + 1)
        .read_to_end(&mut output)
        .map(|_| output)
}

pub(crate) fn codex_isolation_plan_from_json(
    plugin_json: &[u8],
    mcp_json: &[u8],
    platform: &str,
    codex_home: &Path,
    trusted_native_bridge_root: &Path,
) -> Result<CodexIsolationPlan, SatelleError> {
    let inventory = serde_json::from_slice::<PluginInventory>(plugin_json)
        .map_err(|_| codex_isolation_error("plugin_inventory_malformed"))?;
    let mut plugins = inventory
        .installed
        .into_iter()
        .filter(|plugin| plugin.installed)
        .collect::<Vec<_>>();
    if plugins.iter().any(|plugin| {
        plugin.plugin_id.is_empty()
            || !plugin
                .plugin_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'@'))
    }) {
        return Err(codex_isolation_error("plugin_id_not_isolatable"));
    }
    plugins.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    if plugins
        .windows(2)
        .any(|pair| pair[0].plugin_id == pair[1].plugin_id)
    {
        return Err(codex_isolation_error("plugin_inventory_ambiguous"));
    }
    let Some(computer_use) = plugins
        .iter()
        .find(|plugin| plugin.plugin_id == COMPUTER_USE_PLUGIN_ID)
    else {
        return Err(codex_isolation_error("computer_use_plugin_missing"));
    };
    if !matches!(platform, "windows" | "macos") {
        return Err(codex_isolation_error("native_bridge_platform_unsupported"));
    }
    let Some(plugin_version) = computer_use
        .version
        .as_deref()
        .filter(|version| component_version_is_valid(version))
    else {
        return Err(codex_isolation_error("computer_use_plugin_not_ready"));
    };
    if computer_use.marketplace_name != "openai-bundled" || !computer_use.enabled {
        return Err(codex_isolation_error("computer_use_plugin_not_ready"));
    }
    let expected_plugin_root = expected_computer_use_plugin_root(codex_home);
    if computer_use.source.source != "local"
        || !path_is_absolute_for_platform(&computer_use.source.path, platform)
        || !same_path_for_platform(&computer_use.source.path, &expected_plugin_root, platform)
    {
        return Err(codex_isolation_error(
            "computer_use_plugin_source_untrusted",
        ));
    }
    let planned_native_action_path = match platform {
        "windows" => PlannedNativeComputerUseActionPath::WindowsNodeRepl,
        "macos" => PlannedNativeComputerUseActionPath::MacosNodeRepl,
        _ => return Err(codex_isolation_error("native_bridge_platform_unsupported")),
    };

    let servers = configured_mcp_servers_from_json(mcp_json)?;

    let native_mcp_server_name = match platform {
        "windows" => "node_repl",
        "macos" => "node_repl",
        _ => return Err(codex_isolation_error("native_bridge_platform_unsupported")),
    };
    let Some(native_bridge) = servers
        .iter()
        .find(|server| server.name == native_mcp_server_name)
    else {
        return Err(codex_isolation_error("native_bridge_missing"));
    };
    let native_mcp_binding = trusted_native_mcp_binding(
        native_bridge,
        platform,
        trusted_native_bridge_root,
        codex_home,
    )
    .ok_or_else(|| codex_isolation_error("native_bridge_untrusted"))?;

    Ok(CodexIsolationPlan {
        disabled_mcp_server_names: servers
            .into_iter()
            .filter_map(|server| (server.name != native_mcp_server_name).then_some(server.name))
            .collect(),
        native_mcp_server_name: native_mcp_server_name.to_string(),
        plugin_version: plugin_version.to_string(),
        planned_native_action_path,
        native_mcp_binding,
    })
}

fn expected_computer_use_plugin_root(codex_home: &Path) -> PathBuf {
    codex_home
        .join(".tmp")
        .join("bundled-marketplaces")
        .join("openai-bundled")
        .join("plugins")
        .join("computer-use")
}

fn component_version_is_valid(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub(super) fn same_path_for_platform(left: &Path, right: &Path, platform: &str) -> bool {
    match platform {
        "windows" => normalized_windows_drive_path(left)
            .zip(normalized_windows_drive_path(right))
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(&right)),
        "macos" => {
            left.to_string_lossy().replace('\\', "/") == right.to_string_lossy().replace('\\', "/")
        }
        _ => false,
    }
}

pub(super) fn path_is_absolute_for_platform(path: &Path, platform: &str) -> bool {
    let path = path.to_string_lossy();
    match platform {
        "windows" => normalized_windows_drive_path(Path::new(path.as_ref())).is_some(),
        "macos" => path.starts_with('/'),
        _ => false,
    }
}

fn normalized_windows_drive_path(path: &Path) -> Option<String> {
    let path = path.to_string_lossy().replace('\\', "/");
    // `fs::canonicalize` returns a verbatim drive path on Windows, while the
    // Codex inventory reports the same local path without the verbatim prefix.
    // Normalize only that exact drive form. Device and UNC paths remain
    // outside the trusted bundled-plugin boundary.
    let path = path.strip_prefix("//?/").unwrap_or(&path);
    let bytes = path.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/')
        .then(|| path.to_string())
}

fn prepare_native_bridge(
    path: &Path,
    trusted_root: &Path,
    platform: &str,
    codex_home: &Path,
    native_env: &mut BTreeMap<String, String>,
    deadline: Instant,
) -> Result<PreparedNativeBridge, SatelleError> {
    match platform {
        "windows" => {
            let _ = (codex_home, native_env, deadline);
            validate_native_bridge_filesystem(path, trusted_root, platform)?;
            // The inventory path lives in a user-writable runtime cache. The
            // AppX copy authenticates its bytes, while protected PowerShell
            // holds the checked cache file against writes and replacement
            // until Windows has opened the child image.
            let inventory_digest = native_bridge_digest(path)?;
            protected_windows_native_bridge(&inventory_digest)?;
            Ok(PreparedNativeBridge {
                command: windows_powershell_path()?.to_string_lossy().into_owned(),
                prefix_args: windows_locked_bridge_args(path, &inventory_digest),
                native_runtime_version: format!("sha256-{}", hex_digest(&inventory_digest)),
                native_resources: NativeSessionResources::empty(),
            })
        }
        "macos" => {
            validate_native_bridge_filesystem(path, trusted_root, platform)?;
            #[cfg(target_os = "macos")]
            return prepare_macos_native_bridge(path, codex_home, native_env, deadline);
            #[cfg(not(target_os = "macos"))]
            Ok(PreparedNativeBridge {
                // Non-macOS unit tests can inspect the closed launcher
                // contract without starting a platform-native relay.
                command: std::env::current_exe()
                    .map_err(|_| codex_isolation_error("native_bridge_untrusted"))?
                    .to_string_lossy()
                    .into_owned(),
                prefix_args: macos_authenticated_bridge_args(
                    path,
                    "0000000000000000000000000000000000000000",
                    "0000000000000000000000000000000000000000",
                ),
                native_runtime_version: "cdhash-0000000000000000000000000000000000000000"
                    .to_string(),
                native_resources: NativeSessionResources::empty(),
            })
        }
        _ => Err(codex_isolation_error("native_bridge_platform_unsupported")),
    }
}

struct PreparedNativeBridge {
    command: String,
    prefix_args: Vec<String>,
    native_runtime_version: String,
    native_resources: NativeSessionResources,
}

struct NativeSessionResources {
    #[cfg(target_os = "macos")]
    _macos: Option<MacosNativeSessionResources>,
}

impl NativeSessionResources {
    const fn empty() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            _macos: None,
        }
    }
}

#[cfg(target_os = "macos")]
fn prepare_macos_native_bridge(
    bridge: &Path,
    codex_home: &Path,
    _native_env: &mut BTreeMap<String, String>,
    deadline: Instant,
) -> Result<PreparedNativeBridge, SatelleError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let executable = std::env::current_exe()
        .map_err(|_| codex_isolation_error("native_bridge_launcher_untrusted"))?;
    let parent_cdhash = macos_process_cdhash(std::process::id())
        .ok_or_else(|| codex_isolation_error("native_bridge_launcher_untrusted"))?;
    if !macos_process_signature_valid(std::process::id()) {
        return Err(codex_isolation_error("native_bridge_launcher_untrusted"));
    }
    let bridge_cdhash = macos_path_cdhash(bridge)
        .filter(|_| macos_path_matches_openai_signature(bridge, deadline))
        .ok_or_else(|| codex_isolation_error("native_bridge_untrusted"))?;
    // Admission executes three independently signed native components. Bind
    // every executable identity into readiness so a partial Desktop update
    // cannot reuse proof collected for a different app-server or service.
    let codex_binary = validate_macos_codex_app_layout(Path::new(MACOS_CODEX_APP_PATH))?;
    let codex_cdhash = macos_path_cdhash(&codex_binary)
        .ok_or_else(|| codex_isolation_error("codex_app_runtime_untrusted"))?;
    let computer_use_service = validate_macos_computer_use_service_layout(codex_home)?;
    let service_cdhash = macos_path_cdhash(&computer_use_service)
        .ok_or_else(|| codex_isolation_error("computer_use_service_untrusted"))?;

    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| codex_isolation_error("native_bridge_launcher_unavailable"))?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let launcher_directory = PathBuf::from(format!(
        "/tmp/satelle-native-launcher-{}-{nonce}",
        std::process::id()
    ));
    let mut source = File::open(executable)
        .map_err(|_| codex_isolation_error("native_bridge_launcher_untrusted"))?;
    let source_metadata = source
        .metadata()
        .map_err(|_| codex_isolation_error("native_bridge_launcher_untrusted"))?;
    if !source_metadata.is_file() || source_metadata.len() > MACOS_NATIVE_LAUNCHER_FILE_LIMIT {
        return Err(codex_isolation_error("native_bridge_launcher_untrusted"));
    }
    let mut directory = fs::DirBuilder::new();
    directory.mode(0o700);
    directory
        .create(&launcher_directory)
        .map_err(|_| codex_isolation_error("native_bridge_launcher_unavailable"))?;
    let launcher_path = launcher_directory.join("satelle");
    let copy_result = (|| {
        let mut launcher = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&launcher_path)?;
        let copied = std::io::copy(&mut source, &mut launcher)?;
        if copied != source_metadata.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Satelle launcher copy was incomplete",
            ));
        }
        launcher.sync_all()
    })();
    let launcher_is_trusted = copy_result.is_ok()
        && macos_path_cdhash(&launcher_path).as_deref() == Some(parent_cdhash.as_str())
        && macos_path_signature_valid(&launcher_path);
    if !launcher_is_trusted {
        let _ = fs::remove_file(&launcher_path);
        let _ = fs::remove_dir(&launcher_directory);
        return Err(codex_isolation_error("native_bridge_launcher_untrusted"));
    }

    // Keep the official node_repl-to-service connection direct. The service
    // authenticates its peer process, so an intermediary cannot preserve the
    // native identity that the signed helper requires.
    let native_resources = MacosNativeSessionResources::start(launcher_directory.clone());

    Ok(PreparedNativeBridge {
        command: launcher_path.to_string_lossy().into_owned(),
        prefix_args: vec![
            MACOS_NATIVE_BRIDGE_LAUNCHER.to_string(),
            parent_cdhash,
            bridge.to_string_lossy().into_owned(),
            bridge_cdhash.clone(),
        ],
        native_runtime_version: macos_native_runtime_version(
            &bridge_cdhash,
            &codex_cdhash,
            &service_cdhash,
        ),
        native_resources: NativeSessionResources {
            _macos: Some(native_resources),
        },
    })
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_native_runtime_version(
    bridge_cdhash: &str,
    codex_cdhash: &str,
    service_cdhash: &str,
) -> String {
    // The three 40-character CDHashes do not fit the readiness identifier's
    // 128-byte persistence contract when concatenated with labels. Hash the
    // framed tuple so every executable remains bound without truncation.
    let mut digest = Sha256::new();
    digest.update(b"satelle-macos-native-runtime-v1\0");
    for cdhash in [bridge_cdhash, codex_cdhash, service_cdhash] {
        digest.update(cdhash.as_bytes());
        digest.update([0]);
    }
    let digest: [u8; 32] = digest.finalize().into();
    format!("sha256-{}", hex_digest(&digest))
}

#[cfg(target_os = "macos")]
pub(super) struct MacosNativeSessionResources {
    directory: PathBuf,
}

#[cfg(target_os = "macos")]
impl MacosNativeSessionResources {
    pub(super) fn start(directory: PathBuf) -> Self {
        Self { directory }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosNativeSessionResources {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[cfg(target_os = "macos")]
fn macos_process_cdhash(pid: u32) -> Option<String> {
    let output = Command::new("/usr/bin/codesign")
        .args(["-dvvv", &format!("+{pid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("CDHash="))
        .filter(|cdhash| cdhash.len() == 40 && cdhash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn macos_process_signature_valid(pid: u32) -> bool {
    Command::new("/usr/bin/codesign")
        .args(["-v", &format!("+{pid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn macos_path_cdhash(path: &Path) -> Option<String> {
    let output = Command::new("/usr/bin/codesign")
        .arg("-dvvv")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("CDHash="))
        .filter(|cdhash| cdhash.len() == 40 && cdhash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn macos_path_signature_valid(path: &Path) -> bool {
    Command::new("/usr/bin/codesign")
        .arg("-v")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn macos_path_matches_openai_signature(path: &Path, deadline: Instant) -> bool {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args([
            "-v",
            "--strict",
            "-R",
            "=anchor apple generic and certificate leaf[subject.OU] = \"2DC432GLL2\"",
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    run_to_completion(&mut command, deadline)
}

#[cfg(any(not(target_os = "macos"), test))]
pub(super) fn macos_authenticated_bridge_args(
    path: &Path,
    bridge_cdhash: &str,
    launcher_cdhash: &str,
) -> Vec<String> {
    vec![
        "__satelle-launch-macos-native-bridge".to_string(),
        launcher_cdhash.to_string(),
        path.to_string_lossy().into_owned(),
        bridge_cdhash.to_string(),
    ]
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn powershell_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(super) fn windows_locked_bridge_args(path: &Path, digest: &[u8; 32]) -> Vec<String> {
    let bridge = powershell_single_quoted(&path.to_string_lossy());
    let digest = powershell_single_quoted(&hex_digest(digest));
    vec![
        "-NoLogo".to_string(),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        format!("{WINDOWS_LOCKED_BRIDGE_SCRIPT} {bridge} {digest}"),
    ]
}

pub(super) fn native_bridge_digest(path: &Path) -> Result<[u8; 32], SatelleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > NATIVE_BRIDGE_FILE_LIMIT
    {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| codex_isolation_error("native_bridge_untrusted"))?
        .take(NATIVE_BRIDGE_FILE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
    if bytes.len() > NATIVE_BRIDGE_FILE_LIMIT as usize {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }
    Ok(Sha256::digest(bytes).into())
}

#[cfg(windows)]
fn protected_windows_native_bridge(inventory_digest: &[u8; 32]) -> Result<PathBuf, SatelleError> {
    matching_native_bridge_path(
        inventory_digest,
        windows_package_roots(CODEX_PACKAGE_FAMILY)?
            .into_iter()
            .map(|root| root.join(CODEX_PACKAGE_NODE_REPL)),
    )
    .ok_or_else(|| codex_isolation_error("native_bridge_untrusted"))
}

#[cfg(windows)]
pub(super) fn windows_powershell_path() -> Result<PathBuf, SatelleError> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut system_directory = vec![0_u16; 260];
    loop {
        let capacity = u32::try_from(system_directory.len())
            .map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
        let length = unsafe { GetSystemDirectoryW(system_directory.as_mut_ptr(), capacity) };
        if length == 0 {
            return Err(codex_isolation_error("native_bridge_untrusted"));
        }
        if length < capacity {
            system_directory.truncate(length as usize);
            break;
        }
        system_directory.resize(length as usize, 0);
    }
    let powershell = PathBuf::from(std::ffi::OsString::from_wide(&system_directory))
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let metadata = fs::symlink_metadata(&powershell)
        .map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }
    let canonical = fs::canonicalize(&powershell)
        .map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
    if !same_path_for_platform(&canonical, &powershell, "windows") {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }
    Ok(powershell)
}

#[cfg(any(target_os = "macos", all(test, unix)))]
pub(super) fn validate_macos_codex_app_layout(bundle: &Path) -> Result<PathBuf, SatelleError> {
    let canonical_bundle = fs::canonicalize(bundle)
        .map_err(|_| codex_isolation_error("codex_app_runtime_untrusted"))?;
    let bundle_metadata = fs::symlink_metadata(bundle)
        .map_err(|_| codex_isolation_error("codex_app_runtime_untrusted"))?;
    if !bundle_metadata.is_dir()
        || bundle_metadata.file_type().is_symlink()
        || canonical_bundle != bundle
    {
        return Err(codex_isolation_error("codex_app_runtime_untrusted"));
    }
    let executable = bundle.join("Contents").join("Resources").join("codex");
    let executable_metadata = fs::symlink_metadata(&executable)
        .map_err(|_| codex_isolation_error("codex_app_runtime_untrusted"))?;
    let canonical_executable = fs::canonicalize(&executable)
        .map_err(|_| codex_isolation_error("codex_app_runtime_untrusted"))?;
    if !executable_metadata.is_file()
        || executable_metadata.file_type().is_symlink()
        || canonical_executable != canonical_bundle.join("Contents/Resources/codex")
    {
        return Err(codex_isolation_error("codex_app_runtime_untrusted"));
    }
    Ok(canonical_executable)
}

#[cfg(target_os = "macos")]
fn authenticate_macos_codex_app(deadline: Instant) -> Result<PathBuf, SatelleError> {
    let bundle = Path::new(MACOS_CODEX_APP_PATH);
    let binary = validate_macos_codex_app_layout(bundle)?;
    let app_requirement = format!(
        "=identifier \"{MACOS_CODEX_APP_ID}\" and anchor apple generic and certificate leaf[subject.OU] = \"2DC432GLL2\""
    );
    let mut app_signature = Command::new("/usr/bin/codesign");
    app_signature
        .args(["-v", "--strict", "--deep", "-R", &app_requirement])
        .arg(bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let cli_requirement = format!(
        "=identifier \"{MACOS_CODEX_CLI_ID}\" and anchor apple generic and certificate leaf[subject.OU] = \"2DC432GLL2\""
    );
    let mut cli_signature = Command::new("/usr/bin/codesign");
    cli_signature
        .args(["-v", "--strict", "-R", &cli_requirement])
        .arg(&binary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !run_to_completion(&mut app_signature, deadline)
        || !run_to_completion(&mut cli_signature, deadline)
    {
        return Err(codex_isolation_error("codex_app_runtime_untrusted"));
    }
    Ok(binary)
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_codex_app_command(binary: &Path, codex_home: &Path) -> Command {
    let mut command = Command::new(binary);
    command.env("CODEX_HOME", codex_home);
    command
}

#[cfg(any(target_os = "macos", all(test, unix)))]
pub(super) fn validate_macos_computer_use_service_layout(
    codex_home: &Path,
) -> Result<PathBuf, SatelleError> {
    let canonical_home = fs::canonicalize(codex_home)
        .map_err(|_| codex_isolation_error("computer_use_service_untrusted"))?;
    let service_root = codex_home.join("computer-use");
    let bundle = service_root.join("Codex Computer Use.app");
    let contents = bundle.join("Contents");
    let info = contents.join("Info.plist");
    let executable = contents
        .join("MacOS")
        .join(MACOS_COMPUTER_USE_SERVICE_EXECUTABLE);
    for directory in [&service_root, &bundle, &contents, &contents.join("MacOS")] {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| codex_isolation_error("computer_use_service_untrusted"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(codex_isolation_error("computer_use_service_untrusted"));
        }
    }
    for (file, size_limit) in [
        (&info, MACOS_SERVICE_INFO_LIMIT),
        (&executable, NATIVE_BRIDGE_FILE_LIMIT),
    ] {
        let metadata = fs::symlink_metadata(file)
            .map_err(|_| codex_isolation_error("computer_use_service_untrusted"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > size_limit {
            return Err(codex_isolation_error("computer_use_service_untrusted"));
        }
    }
    let expected_bundle = canonical_home
        .join("computer-use")
        .join("Codex Computer Use.app");
    let canonical_bundle = fs::canonicalize(&bundle)
        .map_err(|_| codex_isolation_error("computer_use_service_untrusted"))?;
    let canonical_executable = fs::canonicalize(&executable)
        .map_err(|_| codex_isolation_error("computer_use_service_untrusted"))?;
    if canonical_bundle != expected_bundle
        || canonical_executable
            != expected_bundle
                .join("Contents")
                .join("MacOS")
                .join(MACOS_COMPUTER_USE_SERVICE_EXECUTABLE)
    {
        return Err(codex_isolation_error("computer_use_service_untrusted"));
    }
    Ok(canonical_bundle)
}

#[cfg(target_os = "macos")]
fn authenticate_macos_computer_use_service(
    codex_home: &Path,
    deadline: Instant,
) -> Result<(), SatelleError> {
    let bundle = validate_macos_computer_use_service_layout(codex_home)?;
    let info = bundle.join("Contents").join("Info.plist");
    let mut plist = Command::new("/usr/bin/plutil");
    plist.args(["-convert", "json", "-o", "-"]).arg(&info);
    let output = bounded_inventory_command_output(
        plist,
        deadline,
        "computer_use_service_unavailable",
        "computer_use_service_untrusted",
    )?;
    let metadata = serde_json::from_slice::<Value>(&output)
        .map_err(|_| codex_isolation_error("computer_use_service_untrusted"))?;
    if metadata.get("CFBundleIdentifier").and_then(Value::as_str)
        != Some(MACOS_COMPUTER_USE_SERVICE_ID)
        || !metadata
            .get("CFBundleShortVersionString")
            .and_then(Value::as_str)
            .is_some_and(component_version_is_valid)
        || metadata.get("CFBundleExecutable").and_then(Value::as_str)
            != Some(MACOS_COMPUTER_USE_SERVICE_EXECUTABLE)
    {
        return Err(codex_isolation_error("computer_use_service_untrusted"));
    }
    let requirement = format!(
        "=identifier \"{MACOS_COMPUTER_USE_SERVICE_ID}\" and anchor apple generic and certificate leaf[subject.OU] = \"2DC432GLL2\""
    );
    let mut codesign = Command::new("/usr/bin/codesign");
    codesign
        .args(["-v", "--strict", "--deep", "-R", &requirement])
        .arg(bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !run_to_completion(&mut codesign, deadline) {
        return Err(codex_isolation_error("computer_use_service_untrusted"));
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn windows_powershell_path() -> Result<PathBuf, SatelleError> {
    Err(codex_isolation_error("native_bridge_platform_unsupported"))
}

#[cfg(windows)]
pub(super) fn matching_native_bridge_path(
    inventory_digest: &[u8; 32],
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Option<PathBuf> {
    candidates.into_iter().find(|candidate| {
        native_bridge_digest(candidate).is_ok_and(|digest| digest == *inventory_digest)
    })
}

#[cfg(windows)]
fn windows_package_roots(package_family: &str) -> Result<Vec<PathBuf>, SatelleError> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
    use windows_sys::Win32::Storage::Packaging::Appx::{
        GetPackagesByPackageFamily, GetStagedPackagePathByFullName,
    };

    let package_family = wide_null(package_family);
    let mut package_count = 0_u32;
    let mut names_buffer_length = 0_u32;
    let first_status = unsafe {
        GetPackagesByPackageFamily(
            package_family.as_ptr(),
            &mut package_count,
            std::ptr::null_mut(),
            &mut names_buffer_length,
            std::ptr::null_mut(),
        )
    };
    if first_status != ERROR_INSUFFICIENT_BUFFER || package_count == 0 || names_buffer_length == 0 {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }

    let mut package_names = vec![std::ptr::null_mut(); package_count as usize];
    let mut names_buffer = vec![0_u16; names_buffer_length as usize];
    let status = unsafe {
        GetPackagesByPackageFamily(
            package_family.as_ptr(),
            &mut package_count,
            package_names.as_mut_ptr(),
            &mut names_buffer_length,
            names_buffer.as_mut_ptr(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }

    let mut roots = Vec::new();
    for package_name in package_names.into_iter().take(package_count as usize) {
        let package_name = unsafe { wide_pointer_to_string(package_name) }
            .ok_or_else(|| codex_isolation_error("native_bridge_untrusted"))?;
        if !windows_package_full_name_has_valid_version(&package_name) {
            continue;
        }
        let package_name = wide_null(&package_name);
        let mut path_length = 0_u32;
        let first_status = unsafe {
            GetStagedPackagePathByFullName(
                package_name.as_ptr(),
                &mut path_length,
                std::ptr::null_mut(),
            )
        };
        if first_status != ERROR_INSUFFICIENT_BUFFER || path_length == 0 {
            return Err(codex_isolation_error("native_bridge_untrusted"));
        }
        let mut path = vec![0_u16; path_length as usize];
        let status = unsafe {
            GetStagedPackagePathByFullName(
                package_name.as_ptr(),
                &mut path_length,
                path.as_mut_ptr(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(codex_isolation_error("native_bridge_untrusted"));
        }
        path.truncate(path_length as usize);
        if path.last() == Some(&0) {
            path.pop();
        }
        roots.push(PathBuf::from(std::ffi::OsString::from_wide(&path)));
    }
    if roots.is_empty() {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }
    Ok(roots)
}

#[cfg(any(windows, test))]
pub(super) fn windows_package_full_name_has_valid_version(package_name: &str) -> bool {
    package_name.split('_').nth(1).is_some_and(|version| {
        version.split('.').count() == 4 && component_version_is_valid(version)
    })
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
unsafe fn wide_pointer_to_string(pointer: *const u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let mut length = 0_usize;
    while unsafe { *pointer.add(length) } != 0 {
        length = length.checked_add(1)?;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(pointer, length) }).ok()
}

#[cfg(not(windows))]
fn protected_windows_native_bridge(_inventory_digest: &[u8; 32]) -> Result<PathBuf, SatelleError> {
    Err(codex_isolation_error("native_bridge_platform_unsupported"))
}

fn isolatable_mcp_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(super) fn official_native_bridge_root(
    platform: &str,
    codex_home: &Path,
) -> Result<PathBuf, SatelleError> {
    let root = native_bridge_root_path(platform, codex_home)
        .ok_or_else(|| codex_isolation_error("native_bridge_root_unavailable"))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|_| codex_isolation_error("native_bridge_root_unavailable"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(codex_isolation_error("native_bridge_root_untrusted"));
    }
    let canonical_root = fs::canonicalize(&root)
        .map_err(|_| codex_isolation_error("native_bridge_root_untrusted"))?;
    if platform == "macos" && canonical_root != root {
        return Err(codex_isolation_error("native_bridge_root_untrusted"));
    }
    Ok(canonical_root)
}

pub(super) fn native_bridge_root_path(platform: &str, _codex_home: &Path) -> Option<PathBuf> {
    match platform {
        "windows" => std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|root| {
                root.join("OpenAI")
                    .join("Codex")
                    .join("runtimes")
                    .join("cua_node")
            }),
        // The official macOS node runtime is inside the root-owned Codex
        // application bundle. The mutable Codex home supplies the service
        // app, but it must not define which executable receives authority.
        "macos" => Some(PathBuf::from(MACOS_NODE_REPL_ROOT)),
        _ => None,
    }
}

fn trusted_native_mcp_binding(
    server: &ConfiguredMcpServer,
    platform: &str,
    trusted_root: &Path,
    codex_home: &Path,
) -> Option<NativeMcpBinding> {
    let command = server.transport.command.as_deref()?;
    if server.transport.kind != "stdio" {
        return None;
    }

    match platform {
        "windows" => {
            if !server.transport.args.is_empty()
                || server.transport.cwd.is_some()
                || !trusted_windows_bridge_path(Path::new(command), trusted_root)
            {
                return None;
            }
            let reported_env = server.transport.env.as_ref()?;
            let native_pipe = reported_env.get("SKY_CUA_NATIVE_PIPE")?;
            let native_pipe_directory = reported_env.get("SKY_CUA_NATIVE_PIPE_DIRECTORY")?;
            let build_flavor = reported_env.get("BROWSER_USE_CODEX_APP_BUILD_FLAVOR")?;
            let trusted_code_paths =
                trusted_windows_node_repl_code_paths(reported_env, Path::new(command), codex_home)?;
            if native_pipe != "1" || native_pipe_directory.is_empty() || build_flavor != "prod" {
                return None;
            }
            Some(NativeMcpBinding {
                command: command.to_string(),
                args: server.transport.args.clone(),
                env: BTreeMap::from([
                    (
                        "BROWSER_USE_CODEX_APP_BUILD_FLAVOR".to_string(),
                        build_flavor.clone(),
                    ),
                    (
                        "NODE_REPL_TRUSTED_CODE_PATHS".to_string(),
                        trusted_code_paths,
                    ),
                    ("SKY_CUA_NATIVE_PIPE".to_string(), native_pipe.clone()),
                    (
                        "SKY_CUA_NATIVE_PIPE_DIRECTORY".to_string(),
                        native_pipe_directory.clone(),
                    ),
                ]),
            })
        }
        "macos" => {
            if !server.transport.args.is_empty()
                || server.transport.cwd.is_some()
                || !trusted_macos_node_repl_path(Path::new(command), trusted_root)
            {
                return None;
            }
            let reported_env = server.transport.env.as_ref()?;
            let app_version = reported_env
                .get("BROWSER_USE_CODEX_APP_VERSION")
                .filter(|version| component_version_is_valid(version))?;
            // This digest is a bridge-declared client handshake fingerprint,
            // not Satelle's executable trust anchor. Carry the one exact
            // current value from the verified runtime inventory so official
            // updates can rotate it. The fixed root, signed node_repl binary,
            // exact remaining environment, and live proof retain authority.
            let browser_client_sha256 = reported_env
                .get("NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S")
                .filter(|digest| sha256_is_valid(digest))?;
            let expected_env = trusted_macos_node_repl_env(
                codex_home,
                trusted_root,
                app_version,
                browser_client_sha256,
            );
            if server.transport.env.as_ref() != Some(&expected_env) {
                return None;
            }
            Some(NativeMcpBinding {
                // This function can validate a macOS inventory on another
                // host during release conformance. Keep the admitted macOS
                // command in macOS form instead of applying the host's path
                // separator rules.
                command: format!(
                    "{}/bin/node_repl",
                    trusted_root.to_string_lossy().replace('\\', "/")
                ),
                args: Vec::new(),
                env: expected_env,
            })
        }
        _ => None,
    }
}

fn trusted_macos_node_repl_env(
    codex_home: &Path,
    trusted_root: &Path,
    app_version: &str,
    browser_client_sha256: &str,
) -> BTreeMap<String, String> {
    let codex_home = codex_home.to_string_lossy();
    let trusted_root = trusted_root.to_string_lossy();
    // Release conformance can validate a macOS inventory on Windows. Build
    // the serialized guest path with macOS separators instead of the host's.
    let computer_use_service = format!(
        "{}/computer-use/Codex Computer Use.app",
        codex_home.trim_end_matches('/')
    );
    let node_modules = format!("{trusted_root}/lib/node_modules");
    BTreeMap::from([
        (
            "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS".to_string(),
            "1000".to_string(),
        ),
        (
            "NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S".to_string(),
            browser_client_sha256.to_string(),
        ),
        (
            "BROWSER_USE_CODEX_APP_VERSION".to_string(),
            app_version.to_string(),
        ),
        (
            "NODE_REPL_TRUSTED_CODE_PATHS".to_string(),
            format!("{codex_home}:{node_modules}"),
        ),
        (
            "NODE_REPL_NODE_MODULE_DIRS".to_string(),
            node_modules,
        ),
        (
            "NODE_REPL_NODE_PATH".to_string(),
            format!("{trusted_root}/bin/node"),
        ),
        (
            "BROWSER_USE_AVAILABLE_BACKENDS".to_string(),
            "chrome,iab".to_string(),
        ),
        ("CODEX_HOME".to_string(), codex_home.to_string()),
        (
            "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER".to_string(),
            "Control the in-app browser in conjunction with the Browser Plugin.".to_string(),
        ),
        (
            "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME".to_string(),
            "Control the Chrome browser in conjunction with the Chrome Plugin. Prefer this method of controlling Chrome over alternatives (such as Computer Use) unless the user explicitly mentions an alternative."
                .to_string(),
        ),
        (
            "NODE_REPL_INSTRUCTIONS_USE_CASE_COMPUTER_USE".to_string(),
            "Control desktop apps on macOS through Computer Use.".to_string(),
        ),
        (
            "BROWSER_USE_CODEX_APP_BUILD_FLAVOR".to_string(),
            "prod".to_string(),
        ),
        (
            "CODEX_CLI_PATH".to_string(),
            "/Applications/ChatGPT.app/Contents/Resources/codex".to_string(),
        ),
        ("SKY_CUA_SERVICE_PATH".to_string(), computer_use_service),
    ])
}

fn sha256_is_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn trusted_windows_node_repl_code_paths(
    reported_env: &BTreeMap<String, String>,
    command: &Path,
    codex_home: &Path,
) -> Option<String> {
    let command = normalized_windows_drive_path(command)?;
    const NODE_REPL_SUFFIX: &str = "/node_repl.exe";
    let suffix_start = command.len().checked_sub(NODE_REPL_SUFFIX.len())?;
    if !command
        .get(suffix_start..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(NODE_REPL_SUFFIX))
    {
        return None;
    }
    let runtime_bin = &command[..suffix_start];
    let node_modules = format!("{runtime_bin}/node_modules");
    let reported = reported_env.get("NODE_REPL_TRUSTED_CODE_PATHS")?;
    let paths = reported.split(';').collect::<Vec<_>>();
    if paths.len() != 2
        || !same_path_for_platform(Path::new(paths[0]), codex_home, "windows")
        || !same_path_for_platform(Path::new(paths[1]), Path::new(&node_modules), "windows")
    {
        return None;
    }
    Some(reported.clone())
}

fn trusted_windows_bridge_path(command: &Path, trusted_root: &Path) -> bool {
    let Some(command) = normalized_windows_drive_path(command) else {
        return false;
    };
    let Some(root) = normalized_windows_drive_path(trusted_root) else {
        return false;
    };
    let command = command.to_ascii_lowercase();
    let root = root.trim_end_matches('/').to_ascii_lowercase();
    let trusted_prefix = format!("{root}/");
    let Some(suffix) = command.strip_prefix(&trusted_prefix) else {
        return false;
    };
    let components = suffix.split('/').collect::<Vec<_>>();
    components.len() == 3
        && components[0].len() == 16
        && components[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        && components[1].eq_ignore_ascii_case("bin")
        && components[2].eq_ignore_ascii_case("node_repl.exe")
}

#[cfg(windows)]
fn refresh_windows_native_pipe_binding(
    binding: &mut NativeMcpBinding,
    server_name: &str,
) -> Result<(), SatelleError> {
    let profile = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| codex_isolation_error("native_pipe_inventory_unavailable"))?;
    let config_path = PathBuf::from(profile).join(".codex").join("config.toml");
    let metadata = fs::symlink_metadata(&config_path)
        .map_err(|_| codex_isolation_error("native_pipe_inventory_unavailable"))?;
    if !metadata.is_file() || metadata.len() > SCHEMA_FILE_LIMIT {
        return Err(codex_isolation_error("native_pipe_inventory_untrusted"));
    }
    let config = fs::read_to_string(config_path)
        .map_err(|_| codex_isolation_error("native_pipe_inventory_unavailable"))?;
    refresh_windows_native_pipe_binding_from_config(binding, server_name, &config)
}

#[cfg(not(windows))]
fn refresh_windows_native_pipe_binding(
    _binding: &mut NativeMcpBinding,
    _server_name: &str,
) -> Result<(), SatelleError> {
    Ok(())
}

#[cfg(any(windows, test))]
pub(super) fn refresh_windows_native_pipe_binding_from_config(
    binding: &mut NativeMcpBinding,
    server_name: &str,
    config: &str,
) -> Result<(), SatelleError> {
    let parsed = toml::from_str::<toml::Value>(config)
        .map_err(|_| codex_isolation_error("native_pipe_inventory_untrusted"))?;
    let env = parsed
        .get("mcp_servers")
        .and_then(|servers| servers.get(server_name))
        .and_then(|server| server.get("env"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| codex_isolation_error("native_pipe_inventory_untrusted"))?;
    if env.get("SKY_CUA_NATIVE_PIPE").and_then(toml::Value::as_str) != Some("1")
        || env
            .get("BROWSER_USE_CODEX_APP_BUILD_FLAVOR")
            .and_then(toml::Value::as_str)
            != Some("prod")
    {
        return Err(codex_isolation_error("native_pipe_inventory_untrusted"));
    }
    let pipe = env
        .get("SKY_CUA_NATIVE_PIPE_DIRECTORY")
        .and_then(toml::Value::as_str)
        .filter(|pipe| windows_computer_use_pipe_is_valid(pipe))
        .ok_or_else(|| codex_isolation_error("native_pipe_inventory_untrusted"))?;
    binding.env.insert(
        "SKY_CUA_NATIVE_PIPE_DIRECTORY".to_string(),
        pipe.to_string(),
    );
    Ok(())
}

#[cfg(any(windows, test))]
fn windows_computer_use_pipe_is_valid(pipe: &str) -> bool {
    const PREFIX: &str = r"\\.\pipe\codex-computer-use-";
    let Some(identifier) = pipe.strip_prefix(PREFIX) else {
        return false;
    };
    uuid::Uuid::parse_str(identifier).is_ok_and(|uuid| {
        uuid.hyphenated()
            .to_string()
            .eq_ignore_ascii_case(identifier)
    })
}

fn trusted_macos_node_repl_path(command: &Path, trusted_root: &Path) -> bool {
    let expected = trusted_root.join("bin").join("node_repl");
    same_path_for_platform(command, &expected, "macos")
}

fn validate_native_bridge_filesystem(
    path: &Path,
    trusted_root: &Path,
    platform: &str,
) -> Result<(), SatelleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(codex_isolation_error("native_bridge_untrusted"));
    }
    let canonical_path =
        fs::canonicalize(path).map_err(|_| codex_isolation_error("native_bridge_untrusted"))?;
    let trusted = match platform {
        "windows" => trusted_windows_bridge_path(&canonical_path, trusted_root),
        "macos" => trusted_macos_node_repl_path(&canonical_path, trusted_root),
        _ => false,
    };
    if trusted {
        Ok(())
    } else {
        Err(codex_isolation_error("native_bridge_untrusted"))
    }
}

fn codex_isolation_error(reason: &'static str) -> SatelleError {
    let mut error = SatelleError::computer_use_not_ready();
    error.message = "native Computer Use cannot start because the trusted Codex action path could not be isolated"
        .to_string();
    error
        .details
        .insert("reason".to_string(), Value::String(reason.to_string()));
    error
}

pub(super) fn probe_control_plane_with<F>(
    schema_command: F,
    app_server_command: Command,
    timeout: Duration,
) -> ControlPlaneProbe
where
    F: FnOnce(&Path) -> Command,
{
    probe_control_plane_with_handshake(schema_command, timeout, |schema_dir, deadline| {
        perform_handshake(app_server_command, schema_dir, deadline)
    })
}

fn probe_control_plane_with_handshake<F, H>(
    schema_command: F,
    timeout: Duration,
    handshake: H,
) -> ControlPlaneProbe
where
    F: FnOnce(&Path) -> Command,
    H: FnOnce(&Path, Instant) -> bool,
{
    let deadline = Instant::now() + timeout;
    let Some(schema_dir) = SchemaDirectory::create() else {
        return ControlPlaneProbe::unavailable();
    };
    let mut command = schema_command(schema_dir.path());
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !run_to_completion(&mut command, deadline) {
        return ControlPlaneProbe::unavailable();
    }

    let Some(schema) = StableProtocolSchema::read(schema_dir.path()) else {
        return ControlPlaneProbe::unavailable();
    };
    let operations = schema.operation_capabilities();
    let goal_set = schema.client_requests.declares("thread/goal/set");
    let image_input = if schema.client_requests.declares_user_input("localImage") {
        CodexImageInputMode::Local
    } else if schema.client_requests.declares_user_input("image") {
        CodexImageInputMode::Inline
    } else {
        CodexImageInputMode::Unsupported
    };
    let handshake_declared = schema.client_requests.declares("initialize")
        && schema.client_notifications.declares("initialized");
    let handshake_completed = handshake_declared && handshake(schema_dir.path(), deadline);

    ControlPlaneProbe {
        operations,
        schema_available: true,
        handshake_completed,
        goal_set,
        image_input,
    }
}

struct StableProtocolSchema {
    client_requests: MethodSchema,
    client_notifications: MethodSchema,
    server_notifications: MethodSchema,
}

impl StableProtocolSchema {
    fn read(schema_dir: &Path) -> Option<Self> {
        Some(Self {
            client_requests: MethodSchema::read(&schema_dir.join("ClientRequest.json"))?,
            client_notifications: MethodSchema::read(&schema_dir.join("ClientNotification.json"))?,
            server_notifications: MethodSchema::read(&schema_dir.join("ServerNotification.json"))?,
        })
    }

    fn operation_capabilities(&self) -> ControlPlaneCapabilitySet {
        ControlPlaneCapability::ALL
            .into_iter()
            .filter(|capability| match capability {
                ControlPlaneCapability::SessionCreation => {
                    self.client_requests.declares("thread/start")
                }
                ControlPlaneCapability::TurnStart => self.client_requests.declares("turn/start"),
                ControlPlaneCapability::EventObservation => REQUIRED_LIFECYCLE_NOTIFICATIONS
                    .iter()
                    .all(|method| self.server_notifications.declares(method)),
                // Public Satelle steering starts a follow-up Turn on the same
                // thread. It does not map to upstream in-flight turn/steer.
                ControlPlaneCapability::Steering => {
                    self.client_requests.declares("turn/start")
                        && self.client_requests.declares("thread/resume")
                }
                ControlPlaneCapability::Status => self.client_requests.declares("thread/read"),
                ControlPlaneCapability::Cancellation => {
                    self.client_requests.declares("turn/interrupt")
                }
            })
            .collect()
    }
}

struct MethodSchema(Value);

impl MethodSchema {
    fn read(path: &Path) -> Option<Self> {
        let file = File::open(path).ok()?;
        let mut bytes = Vec::new();
        file.take(SCHEMA_FILE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > SCHEMA_FILE_LIMIT as usize {
            return None;
        }
        serde_json::from_slice(&bytes).ok().map(Self)
    }

    fn declares(&self, expected: &str) -> bool {
        declares_method(&self.0, expected)
    }

    fn declares_user_input(&self, expected: &str) -> bool {
        let Some(request) = request_variant(&self.0, "turn/start") else {
            return false;
        };
        let Some(params) = resolve_schema(&self.0, request.pointer("/properties/params")) else {
            return false;
        };
        let Some(input) = resolve_schema(&self.0, params.pointer("/properties/input/items")) else {
            return false;
        };
        input
            .get("oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| {
                variants.iter().any(|variant| {
                    resolve_schema(&self.0, Some(variant))
                        .and_then(|variant| variant.pointer("/properties/type"))
                        .is_some_and(|kind| schema_string_value(kind, expected))
                })
            })
    }
}

fn request_variant<'a>(root: &'a Value, method: &str) -> Option<&'a Value> {
    root.get("oneOf")?.as_array()?.iter().find(|variant| {
        variant
            .pointer("/properties/method")
            .is_some_and(|kind| schema_string_value(kind, method))
    })
}

fn resolve_schema<'a>(root: &'a Value, value: Option<&'a Value>) -> Option<&'a Value> {
    let value = value?;
    match value.get("$ref").and_then(Value::as_str) {
        Some(reference) => root.pointer(reference.strip_prefix('#')?),
        None => Some(value),
    }
}

fn schema_string_value(value: &Value, expected: &str) -> bool {
    value.get("const").and_then(Value::as_str) == Some(expected)
        || value
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn declares_method(value: &Value, expected: &str) -> bool {
    value
        .get("oneOf")
        .and_then(Value::as_array)
        .is_some_and(|variants| {
            variants.iter().any(|variant| {
                variant
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get("method"))
                    .and_then(Value::as_object)
                    .and_then(|method| method.get("enum"))
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        values.iter().any(|value| value.as_str() == Some(expected))
                    })
            })
        })
}

pub(super) fn perform_handshake(
    mut command: Command,
    working_dir: &Path,
    deadline: Instant,
) -> bool {
    if Instant::now() >= deadline {
        return false;
    }
    let mut child = match command
        .current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(mut stdin) = child.inner().stdin.take() else {
        let _ = super::terminate_group(&mut child);
        return false;
    };
    let Some(stdout) = child.inner().stdout.take() else {
        let _ = super::terminate_group(&mut child);
        return false;
    };

    if !write_initialize_request(&mut stdin) {
        let _ = super::terminate_group(&mut child);
        return false;
    }

    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let result = read_initialize_response(stdout, deadline);
        let _ = sender.send(result);
    });
    let remaining = deadline.saturating_duration_since(Instant::now());
    let accepted = receiver.recv_timeout(remaining).unwrap_or(false);

    let initialized_sent = accepted && write_initialized_notification(&mut stdin);

    let shutdown_deadline = Instant::now()
        + deadline
            .saturating_duration_since(Instant::now())
            .min(HANDSHAKE_SHUTDOWN_GRACE);
    let status = super::wait_for_group(&mut child, shutdown_deadline);
    // The app-server is expected to remain alive after initialization. Always
    // terminate the complete process group or Windows job, including when the
    // leader exited after spawning descendants.
    let group_stopped = super::terminate_group(&mut child);
    drop(stdin);
    // A healthy app-server remains alive while its stdin is open. A status
    // query failure must not be confused with reaching the observation
    // deadline, and an early exit is incompatible even when its status is 0.
    let process_accepted_initialization =
        matches!(status, super::GroupWaitOutcome::Deadline) && group_stopped;
    // Unix readers are nonblocking and enforce the same absolute deadline, so
    // even a group-escaping descendant cannot hold this join open. Windows job
    // containment closes every inherited pipe before a reader is joined.
    #[cfg(unix)]
    let reader_stopped = reader.join().is_ok();
    #[cfg(not(unix))]
    let reader_stopped = group_stopped && reader.join().is_ok();
    initialized_sent && process_accepted_initialization && reader_stopped
}

fn write_initialize_request(writer: &mut impl Write) -> bool {
    write_json_line(
        writer,
        &json!({
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "satelle-host",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {"experimentalApi": false}
            }
        }),
    )
}

fn write_initialized_notification(writer: &mut impl Write) -> bool {
    write_json_line(writer, &json!({"method": "initialized"}))
}

fn write_json_line(writer: &mut impl Write, value: &Value) -> bool {
    serde_json::to_writer(&mut *writer, value).is_ok()
        && writer.write_all(b"\n").is_ok()
        && writer.flush().is_ok()
}

#[cfg(not(windows))]
fn read_initialize_response(stdout: std::process::ChildStdout, deadline: Instant) -> bool {
    #[cfg(unix)]
    if super::set_nonblocking(&stdout).is_err() {
        return false;
    }
    let mut reader = BufReader::new(stdout);

    for _ in 0..HANDSHAKE_MESSAGE_LIMIT {
        let mut line = Vec::new();
        let mut bounded = (&mut reader).take(HANDSHAKE_LINE_LIMIT + 1);
        loop {
            match bounded.read_until(b'\n', &mut line) {
                Ok(0) => return false,
                Ok(_) if line.last() == Some(&b'\n') => break,
                Ok(_) if line.len() > HANDSHAKE_LINE_LIMIT as usize => return false,
                // A nonblocking pipe may yield a valid prefix before the
                // delimiter arrives. Keep accumulating the same bounded line
                // instead of attempting to parse a partial JSON object.
                Ok(_) => {}
                #[cfg(unix)]
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    if line.len() > HANDSHAKE_LINE_LIMIT as usize {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return false,
            }
        }
        if line.len() > HANDSHAKE_LINE_LIMIT as usize {
            return false;
        }
        match classify_initialize_message(&line) {
            InitializeMessage::Accepted => return true,
            InitializeMessage::Notification => continue,
            InitializeMessage::Invalid => return false,
        }
    }
    false
}

#[cfg(windows)]
fn read_initialize_response(mut stdout: std::process::ChildStdout, deadline: Instant) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;

    let mut pending = Vec::new();
    let mut messages = 0_usize;
    while Instant::now() < deadline && messages < HANDSHAKE_MESSAGE_LIMIT {
        let mut available = 0_u32;
        let peeked = unsafe {
            PeekNamedPipe(
                stdout.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if peeked == 0 {
            return false;
        }
        if available == 0 {
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        let remaining = (HANDSHAKE_LINE_LIMIT + 1).saturating_sub(pending.len() as u64);
        if remaining == 0 {
            return false;
        }
        let start = pending.len();
        let read_length = remaining.min(u64::from(available)) as usize;
        pending.resize(start + read_length, 0);
        if stdout.read_exact(&mut pending[start..]).is_err() {
            return false;
        }

        while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=newline).collect::<Vec<_>>();
            messages += 1;
            match classify_initialize_message(&line) {
                InitializeMessage::Accepted => return true,
                InitializeMessage::Notification => {}
                InitializeMessage::Invalid => return false,
            }
            if messages == HANDSHAKE_MESSAGE_LIMIT {
                return false;
            }
        }
        if pending.len() > HANDSHAKE_LINE_LIMIT as usize {
            return false;
        }
    }
    false
}

enum InitializeMessage {
    Accepted,
    Notification,
    Invalid,
}

fn classify_initialize_message(line: &[u8]) -> InitializeMessage {
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        return InitializeMessage::Invalid;
    };
    let Some(object) = message.as_object() else {
        return InitializeMessage::Invalid;
    };
    if object.get("id").and_then(Value::as_u64) == Some(1) {
        return if object
            .get("result")
            .and_then(Value::as_object)
            .is_some_and(|result| {
                ["userAgent", "codexHome", "platformFamily", "platformOs"]
                    .iter()
                    .all(|field| result.get(*field).and_then(Value::as_str).is_some())
            }) {
            InitializeMessage::Accepted
        } else {
            InitializeMessage::Invalid
        };
    }
    // Notifications have no request id. Unknown methods are deliberately
    // normalized to this branch and discarded without side effects.
    if object.get("id").is_none() && object.get("method").and_then(Value::as_str).is_some() {
        InitializeMessage::Notification
    } else {
        InitializeMessage::Invalid
    }
}

fn run_to_completion(command: &mut Command, deadline: Instant) -> bool {
    if Instant::now() >= deadline {
        return false;
    }
    let Ok(mut child) = command.group_spawn() else {
        return false;
    };
    let status = super::wait_for_group(&mut child, deadline);
    let group_stopped = super::terminate_group(&mut child);
    matches!(status, super::GroupWaitOutcome::Exited(status) if status.success()) && group_stopped
}

struct SchemaDirectory(PathBuf);

impl SchemaDirectory {
    fn create() -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let sequence = SCHEMA_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "satelle-codex-schema-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;

            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        builder.create(&path).ok()?;
        Some(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SchemaDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
