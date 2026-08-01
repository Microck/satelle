#[path = "bootstrap-lock.rs"]
mod bootstrap_lock;
#[path = "command-history.rs"]
mod command_history;
mod completions;
#[path = "error-output.rs"]
mod error_output;
#[path = "host-trust.rs"]
mod host_trust;
#[path = "host-update.rs"]
mod host_update;
mod logs;
mod mcp;
mod output;
mod read;
#[path = "self-update.rs"]
mod self_update;
mod tailscale;
#[path = "tailscale-serve.rs"]
mod tailscale_serve;
mod transport;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use completions::{CompletionsCommand, run_completions};
use error_output::{ErrorFormat, parser_error, print_error, process_exit_code};
use host_trust::{
    HostTrustReport, persist_desktop_selection, persist_host_identity,
    persist_provider_auth_descriptor,
};
use logs::{LogsCommand, show_logs};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use output::{EventOutput, OutputArgs, OutputFormat, SessionResultSchemaVersion, StatusReport};
#[cfg(any(windows, test))]
use satelle_core::daemon_service::WindowsServiceConfigV2;
use satelle_core::daemon_service::{
    DaemonServicePlatform, PersistentServiceDecision, SetupModeSelection, SetupModeSource,
};
use satelle_core::doctor::{DoctorScopeSelection, DoctorScopeSelectionError};
use satelle_core::session::{
    EffectiveModelRef, HostIdentityRef, ProviderBindingRef, PublicSession, PublicTurn,
    TurnAdmissionPhase, TurnExecutionMode, TurnState,
};
use satelle_core::{
    BEACON_CORAL, CLI_NAME, DaemonPathOverrides, DesktopSelectionPolicy, DesktopSessionPreference,
    DoctorEventRecord, DoctorEventSchemaVersion, DoctorEventType, DoctorFixability, DoctorOptions,
    DoctorReport, ERROR_RED, ErrorCode, EventSource, EventType, HostConfig, HostSessionsReport,
    LOCAL_DEMO_HOST, MutationCommandFamily, OwnerOnlyDirectory, PRODUCT_NAME, ProfileField,
    ProfileSelectionSource, ProviderSecretSource, RELAY_ROSE, ResolvedConfig, SUCCESS_GREEN,
    SatelleError, SatelleEvent, SatelleEventBody, SecureFileError, SessionId, SetupMode,
    SetupReadinessSummary, SetupReport, SetupRequiredInput, SetupSchemaVersion, SetupVerification,
    TransportKind, load_config, load_config_for_profile, load_config_without_profile,
    load_user_api_rate_limits, open_or_create_owner_only_directory, open_or_create_owner_only_file,
    open_owner_only_directory, read_owner_controlled_config_file,
    read_owner_only_secret_config_file, resolve_desktop_session, resolve_path_set, utc_now,
};
use satelle_host::{
    ApiBearerToken, DoctorExecutionFailure, DoctorExecutionResult, HostService,
    ProviderComputerUseIntent, contains_api_bearer_token,
};
use satelle_transport::{
    DaemonServer, DaemonServerConfig, DaemonServerError, DaemonTlsConfig, DaemonTlsConfigError,
    DaemonTlsReloadError, DaemonTlsReloader, ProviderBindingAuthorization,
    SetupVerificationRequest, TurnRequest,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tailscale::{
    execute_transport_only_doctor, prepare_transport_only_doctor, transport_doctor_probe,
};
use transport::{
    AttachedTurnOutcome, SshBootstrapScope, SshHostDiscovery, authenticated_ssh_bootstrap_user,
    discover_direct_host_identity, discover_ssh_host, transport_for, transport_for_setup,
    transport_for_with_ssh_bootstrap,
};
use uuid::Uuid;

const CONFIG_CHECK_SCHEMA_VERSION: &str = "satelle.config.check.v1";
const CONFIG_EXPLAIN_SCHEMA_VERSION: &str = "satelle.config.explain.v2";
const PATHS_SCHEMA_VERSION: &str = "satelle.paths.v2";
const DEFAULT_HOST_BIND: &str = "127.0.0.1:3001";
const DEFAULT_ON_DEMAND_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SSH_STATE_RELEASE_REQUEST: &str = "ssh-state-release.request";
const SSH_STATE_RELEASE_REQUESTER_LOCK: &str = "ssh-state-release.requester.lock";
const STATE_OWNERSHIP_LOCK: &str = "satelle.sqlite3.lock";
const STATE_RELEASE_TIMEOUT: Duration = Duration::from_secs(20);
const STATE_RELEASE_POLL_INTERVAL: Duration = Duration::from_millis(50);
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "satelle",
    version,
    about = "Satelle remote computer-use bridge",
    long_about = "Satelle sends command uplinks to a visible remote host and returns telemetry from the native computer-use runtime."
)]
struct Cli {
    #[arg(long, global = true, help = "Disable colored human output")]
    no_color: bool,

    #[arg(
        long,
        global = true,
        value_name = "NAME",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        help = "Apply a named user-level configuration profile"
    )]
    profile: Option<String>,

    #[arg(
        long,
        global = true,
        value_enum,
        env = "SATELLE_ERROR_FORMAT",
        value_name = "FORMAT",
        help = "Format diagnostics as human-readable text or JSON"
    )]
    error_format: Option<ErrorFormat>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone)]
struct ConfigContext<'a> {
    flag_profile: Option<&'a str>,
    select_profile: bool,
    profile_source: Option<satelle_core::ProfileSelectionSource>,
    resolved: Arc<OnceLock<Result<ResolvedConfig, SatelleError>>>,
}

#[derive(Debug)]
struct SelectedHost {
    alias: String,
    config: HostConfig,
    from_project: bool,
}

impl From<(String, HostConfig, bool)> for SelectedHost {
    fn from((alias, config, from_project): (String, HostConfig, bool)) -> Self {
        Self {
            alias,
            config,
            from_project,
        }
    }
}

impl From<(String, HostConfig)> for SelectedHost {
    fn from((alias, config): (String, HostConfig)) -> Self {
        Self {
            alias,
            config,
            from_project: false,
        }
    }
}

impl<'a> ConfigContext<'a> {
    fn new(flag_profile: Option<&'a str>) -> Self {
        Self {
            flag_profile,
            select_profile: true,
            profile_source: None,
            resolved: Arc::new(OnceLock::new()),
        }
    }

    fn for_profile(profile: &'a str, source: satelle_core::ProfileSelectionSource) -> Self {
        Self {
            flag_profile: Some(profile),
            select_profile: true,
            profile_source: Some(source),
            resolved: Arc::new(OnceLock::new()),
        }
    }

    fn without_profile() -> Self {
        Self {
            flag_profile: None,
            select_profile: false,
            profile_source: None,
            resolved: Arc::new(OnceLock::new()),
        }
    }

    fn load(&self) -> Result<&ResolvedConfig, CliFailure> {
        let resolved = self.resolved.get_or_init(|| {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            if let Some(source) = self.profile_source {
                load_config_for_profile(
                    &cwd,
                    self.flag_profile
                        .expect("an exact profile source always has a profile"),
                    source,
                )
            } else if self.select_profile {
                load_config(&cwd, self.flag_profile)
            } else {
                load_config_without_profile(&cwd)
            }
        });
        resolved.as_ref().map_err(|error| failure(error.clone()))
    }

    fn mcp_install_profile(&self) -> Result<Option<satelle_core::SelectedProfile>, CliFailure> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        satelle_core::resolve_invocation_profile(&cwd, self.flag_profile).map_err(failure)
    }

    fn resolve_host(&self, flag_host: Option<&str>) -> Result<SelectedHost, CliFailure> {
        self.load()?
            .resolve_host_with_project_source(flag_host)
            .map(SelectedHost::from)
            .map_err(failure)
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    Completions(CompletionsCommand),
    Setup(SetupCommand),
    Repair(RepairCommand),
    Doctor(DoctorCommand),
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Paths(PathsCommand),
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    #[command(name = "self")]
    SelfCtl {
        #[command(subcommand)]
        command: SelfSubcommand,
    },
    Run(RunCommand),
    Steer(SteerCommand),
    Status(StatusCommand),
    Stop(StopCommand),
    Logs(LogsCommand),
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    Support {
        #[command(subcommand)]
        command: SupportCommand,
    },
}

#[derive(Subcommand, Debug)]
enum McpCommand {
    Serve,
    Install(McpInstallCommand),
}

#[derive(Args, Debug)]
struct McpInstallCommand {
    #[arg(
        long,
        value_enum,
        required_unless_present = "all",
        conflicts_with = "all"
    )]
    target: Vec<mcp::install::InstallTarget>,
    #[arg(long)]
    all: bool,
    #[arg(long, default_value = "satelle")]
    server_name: String,
    #[arg(long)]
    satelle_path: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
#[command(
    after_long_help = "Agent-safe noninteractive provider auth flow:\n  1. Configure host-resolved Secret Source descriptors in user-level host config.\n  2. Run satelle setup --no-input --json to get a stable plan.\n  3. Treat missing raw provider secret material as required human input, not as an agent-handled value."
)]
struct SetupCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(
        long,
        help = "Run live native Computer Use readiness checks and any required provider smoke test after setup"
    )]
    verify: bool,
    #[arg(long)]
    on_demand: bool,
    #[arg(long)]
    persistent: bool,
    #[arg(long, value_enum)]
    component: Vec<SetupComponent>,
    #[arg(long)]
    daemon_home: Option<PathBuf>,
    #[arg(long)]
    daemon_config_file: Option<PathBuf>,
    #[arg(long)]
    daemon_state_dir: Option<PathBuf>,
    #[arg(long)]
    daemon_cache_dir: Option<PathBuf>,
    #[arg(long)]
    daemon_log_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Accept ordinary setup mutations without an interactive confirmation"
    )]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[arg(
        long,
        value_name = "HOST_ID",
        help = "Require this exact Host identity during first-time SSH trust"
    )]
    expected_host_id: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct RepairCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long, value_name = "RUN_ID")]
    run: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(
        long,
        help = "Accept ordinary repair mutations without an interactive confirmation"
    )]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct DoctorCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    scope: Vec<String>,
    #[arg(long)]
    refresh: bool,
    #[arg(long)]
    timeout: Option<String>,
    #[arg(long)]
    serial_probes: bool,
    #[arg(long)]
    events: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Check(ConfigCheckCommand),
    Explain(ConfigExplainCommand),
}

#[derive(Args, Debug)]
struct ConfigCheckCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    all: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct ConfigExplainCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    show_secret_references: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct PathsCommand {
    #[arg(long)]
    host: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Subcommand, Debug)]
enum HostCommand {
    Start(HostStartCommand),
    /// Internal owner-local request for a running SSH daemon to release its store.
    #[command(hide = true)]
    ReleaseState,
    /// Authenticate a direct Host and pin its stable identity in user configuration.
    Trust(HostTrustCommand),
    Status(HostStatusCommand),
    Stop(HostLifecycleCommand),
    Restart(HostLifecycleCommand),
    Update(HostUpdateCommand),
    Cleanup(HostCleanupCommand),
    Sessions(HostSessionsCommand),
    Storage {
        #[command(subcommand)]
        command: HostStorageCommand,
    },
    Store {
        #[command(subcommand)]
        command: HostStoreCommand,
    },
    #[command(hide = true)]
    OfflineStorageMaintenance(OfflineStorageMaintenanceCommand),
    #[command(hide = true)]
    OfflineStorageRestorePreview(OfflineStorageRestorePreviewCommand),
    #[command(hide = true)]
    OfflineStorageBackupCleanupPlan(OfflineStorageBackupCleanupPlanCommand),
}

#[derive(Args, Debug)]
struct HostTrustCommand {
    /// Host Binding alias to authenticate and trust.
    #[arg(long, required = true)]
    host: String,
    /// Exact identity required before a noninteractive trust update.
    #[arg(long, value_name = "HOST_ID")]
    expected_host_id: Option<String>,
    /// Permit replacement when the Host Binding already pins a different identity.
    #[arg(long)]
    replace: bool,
    /// Apply trust without an interactive confirmation.
    #[arg(long)]
    yes: bool,
    /// Reject any path that would prompt for input.
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct HostStartCommand {
    #[arg(long, default_value = DEFAULT_HOST_BIND)]
    bind: String,
    /// PEM certificate chain for Host-terminated HTTPS and WSS.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// Owner-only PEM private key matching --tls-cert.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    foreground: bool,
    /// Internal launchd service boundary. Path overrides in this process came
    /// from the Satelle-owned launchd plist.
    #[arg(
        long,
        hide = true,
        requires = "foreground",
        conflicts_with_all = [
            "service_config",
            "tls_cert",
            "tls_key",
            "bootstrap_token_stdin",
            "initial_host_identity",
            "initial_identity_operation_id",
            "initial_identity_record",
            "bootstrap_scope",
            "bootstrap_native_readiness_timeout_ms",
            "bootstrap_provider_smoke_timeout_ms",
            "on_demand_idle_timeout_ms"
        ]
    )]
    launchd_service: bool,
    /// Internal SSH bootstrap boundary. The token is read once from stdin and
    /// retained only by this daemon process.
    #[arg(long, hide = true)]
    bootstrap_token_stdin: bool,
    /// Internal exact identity accepted by the Controller for a fresh SSH Host.
    #[arg(
        long,
        hide = true,
        value_name = "HOST_ID",
        requires = "bootstrap_token_stdin",
        requires = "initial_identity_operation_id",
        requires = "initial_identity_record"
    )]
    initial_host_identity: Option<String>,
    /// Internal Bootstrap Lock operation that owns the fresh identity commit.
    #[arg(
        long,
        hide = true,
        value_name = "OPERATION_ID",
        requires = "bootstrap_token_stdin",
        requires = "initial_host_identity",
        requires = "initial_identity_record"
    )]
    initial_identity_operation_id: Option<String>,
    /// Internal exact v2 identity operation accepted by the Controller.
    #[arg(
        long,
        hide = true,
        value_name = "RECORD",
        requires = "bootstrap_token_stdin",
        requires = "initial_host_identity",
        requires = "initial_identity_operation_id"
    )]
    initial_identity_record: Option<String>,
    /// Internal least-privilege scope for the one SSH bootstrap operation.
    #[arg(long, hide = true, value_enum, requires = "bootstrap_token_stdin")]
    bootstrap_scope: Option<SshBootstrapScope>,
    /// Internal resolved native readiness deadline for an SSH-launched daemon.
    #[arg(long, hide = true, value_name = "MILLISECONDS")]
    bootstrap_native_readiness_timeout_ms: Option<u64>,
    /// Internal resolved provider smoke deadline for an SSH-launched daemon.
    #[arg(long, hide = true, value_name = "MILLISECONDS")]
    bootstrap_provider_smoke_timeout_ms: Option<u64>,
    /// Internal Controller-resolved idle timeout for a durable SSH launch.
    #[arg(long, hide = true, value_name = "MILLISECONDS")]
    on_demand_idle_timeout_ms: Option<u64>,
    /// Internal resolved setup-ledger retention for a persistent launchd service.
    #[arg(
        long,
        hide = true,
        value_name = "MILLISECONDS",
        requires = "launchd_service"
    )]
    setup_ledger_retention_ms: Option<u64>,
    /// Internal owner-only configuration used by the per-user Windows task.
    #[arg(
        long,
        hide = true,
        value_name = "PATH",
        conflicts_with_all = [
            "bind",
            "tls_cert",
            "tls_key",
            "foreground",
            "bootstrap_token_stdin",
            "initial_host_identity",
            "initial_identity_operation_id",
            "initial_identity_record",
            "bootstrap_scope",
            "bootstrap_native_readiness_timeout_ms",
            "bootstrap_provider_smoke_timeout_ms",
            "on_demand_idle_timeout_ms",
            "launchd_service"
        ]
    )]
    service_config: Option<PathBuf>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct HostStatusCommand {
    #[arg(long)]
    host: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct HostLifecycleCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct HostUpdateCommand {
    #[arg(long)]
    host: Vec<String>,
    #[arg(long)]
    component: Vec<String>,
    #[arg(long)]
    all_remotes: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[arg(
        long,
        help = "Suppress non-error human plan and progress output; use --json for stable automation data"
    )]
    quiet: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

struct HostUpdateInvocation {
    host: Vec<String>,
    host_version: String,
    component: Vec<String>,
    all_remotes: bool,
    dry_run: bool,
    yes: bool,
    no_input: bool,
    quiet: bool,
}

impl From<HostUpdateCommand> for HostUpdateInvocation {
    fn from(command: HostUpdateCommand) -> Self {
        Self {
            host: command.host,
            host_version: env!("CARGO_PKG_VERSION").to_string(),
            component: command.component,
            all_remotes: command.all_remotes,
            dry_run: command.dry_run,
            yes: command.yes,
            no_input: command.no_input,
            quiet: command.quiet,
        }
    }
}

#[derive(Args, Debug)]
struct HostCleanupCommand {
    #[arg(long)]
    host: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct HostSessionsCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    no_bootstrap: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Subcommand, Debug)]
enum HostStorageCommand {
    Migrate(HostStorageMigrateCommand),
    Restore(HostStorageRestoreCommand),
    Backup {
        #[command(subcommand)]
        command: HostStorageBackupCommand,
    },
}

#[derive(Args, Debug)]
struct HostStorageMigrateCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    to: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct HostStorageRestoreCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    backup: PathBuf,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Subcommand, Debug)]
enum HostStorageBackupCommand {
    Cleanup(HostStorageBackupCleanupCommand),
}

#[derive(Args, Debug)]
struct HostStorageBackupCleanupCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Subcommand, Debug)]
enum HostStoreCommand {
    Reset(HostStoreResetCommand),
}

#[derive(Args, Debug)]
struct HostStoreResetCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    delete_recordings: bool,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OfflineStorageOperation {
    Restore,
    BackupCleanup,
    StoreReset,
}

#[derive(Args, Debug)]
struct OfflineStorageMaintenanceCommand {
    #[arg(long, value_enum)]
    operation: OfflineStorageOperation,
    #[arg(long)]
    host: String,
    #[arg(long)]
    operation_id: String,
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    backup: Option<PathBuf>,
    #[arg(long)]
    delete_recordings: bool,
    /// Exact backup identities approved by the caller for cleanup.
    #[arg(long = "approved-backup")]
    approved_backup_file_names: Vec<String>,
    /// Apply the already-confirmed offline mutation.
    #[arg(long)]
    yes: bool,
    /// Reconcile a mutation that already completed without repeating it.
    #[arg(long)]
    reconcile_completion: bool,
}

#[derive(Args, Debug)]
struct OfflineStorageBackupCleanupPlanCommand {
    #[arg(long)]
    state_root: PathBuf,
}

#[derive(Args, Debug)]
struct OfflineStorageRestorePreviewCommand {
    #[arg(long)]
    state_root: PathBuf,
    #[arg(long)]
    backup: PathBuf,
}

#[derive(Subcommand, Debug)]
enum SelfSubcommand {
    Update(SelfUpdateCommand),
}

#[derive(Args, Debug)]
struct SelfUpdateCommand {
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    version: Option<String>,
    #[arg(long)]
    update_remotes: bool,
    #[arg(long)]
    host: Vec<String>,
    #[arg(long)]
    all_remotes: bool,
    #[arg(long, default_value_t = 4)]
    concurrency: u8,
    #[arg(long)]
    no_input: bool,
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct RunCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(
        long,
        value_name = "ALIAS",
        help = "Model alias; must resolve with the effective provider alias as one exact Host Provider Binding pair"
    )]
    model: Option<String>,
    #[arg(
        long,
        value_name = "ALIAS",
        help = "Provider alias; must resolve with the effective model alias as one exact Host Provider Binding pair"
    )]
    provider: Option<String>,
    #[arg(long)]
    detach: bool,
    /// Leave an admitted Turn running when the attached command is interrupted
    #[arg(long)]
    detach_on_interrupt: bool,
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(
        long,
        help = "Experimental: attempt non-OpenAI provider Computer Use; behavior may not work correctly and still requires a live provider Computer Use smoke test"
    )]
    experimental_provider_computer_use: bool,
    #[arg(
        long,
        help = "Refresh the cached provider Computer Use smoke-test result before execution; this does not enable experimental provider Computer Use"
    )]
    refresh_provider_smoke_test: bool,
    #[arg(
        long,
        conflicts_with = "no_yolo",
        help = "Enable YOLO mode for this command; Codex-controlled approvals may be auto-accepted when supported"
    )]
    yolo: bool,
    #[arg(long, help = "Disable YOLO mode for this command")]
    no_yolo: bool,
    #[arg(long, value_enum, default_value_t = EventMode::Auto)]
    events: EventMode,
    #[arg(
        long,
        help = "Read prompt text from a local file; recommended for sensitive prompt input"
    )]
    prompt_file: Option<PathBuf>,
    #[arg(
        long = "image",
        value_name = "LOCAL_PATH",
        help = "Attach a local PNG or JPEG image (maximum 2, 5 MiB each, 10 MiB total); accepted media types depend on Host capabilities"
    )]
    images: Vec<PathBuf>,
    #[arg(
        long,
        value_name = "DURATION",
        help = "Shorten this Turn's execution timeout (for example 30s, 5m, or 1h; maximum 24h)"
    )]
    timeout: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
    #[arg(
        value_name = "PROMPT_OR_DASH",
        help = "Prompt text or '-' for stdin. Prompt arguments may be retained by shell history or visible in local process metadata; use stdin or --prompt-file for sensitive input"
    )]
    prompt: Option<String>,
}

#[derive(Args, Debug)]
struct SteerCommand {
    session_id: String,
    #[arg(long)]
    host: Option<String>,
    #[arg(
        long,
        value_name = "ALIAS",
        help = "Model alias; must resolve with the effective provider alias as one exact Host Provider Binding pair"
    )]
    model: Option<String>,
    #[arg(
        long,
        value_name = "ALIAS",
        help = "Provider alias; must resolve with the effective model alias as one exact Host Provider Binding pair"
    )]
    provider: Option<String>,
    #[arg(long)]
    detach: bool,
    /// Leave an admitted Turn running when the attached command is interrupted
    #[arg(long)]
    detach_on_interrupt: bool,
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(
        long,
        help = "Experimental: attempt non-OpenAI provider Computer Use; behavior may not work correctly and still requires a live provider Computer Use smoke test"
    )]
    experimental_provider_computer_use: bool,
    #[arg(
        long,
        help = "Refresh the cached provider Computer Use smoke-test result before execution; this does not enable experimental provider Computer Use"
    )]
    refresh_provider_smoke_test: bool,
    #[arg(
        long,
        conflicts_with = "no_yolo",
        help = "Enable YOLO mode for this command; Codex-controlled approvals may be auto-accepted when supported"
    )]
    yolo: bool,
    #[arg(long, help = "Disable YOLO mode for this command")]
    no_yolo: bool,
    #[arg(long, value_enum, default_value_t = EventMode::Auto)]
    events: EventMode,
    #[arg(
        long,
        help = "Read prompt text from a local file; recommended for sensitive prompt input"
    )]
    prompt_file: Option<PathBuf>,
    #[arg(
        long = "image",
        value_name = "LOCAL_PATH",
        help = "Attach a local PNG or JPEG image (maximum 2, 5 MiB each, 10 MiB total); accepted media types depend on Host capabilities"
    )]
    images: Vec<PathBuf>,
    #[arg(
        long,
        value_name = "DURATION",
        help = "Shorten this Turn's execution timeout (for example 30s, 5m, or 1h; maximum 24h)"
    )]
    timeout: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
    #[arg(
        value_name = "PROMPT_OR_DASH",
        help = "Prompt text or '-' for stdin. Prompt arguments may be retained by shell history or visible in local process metadata; use stdin or --prompt-file for sensitive input"
    )]
    prompt: Option<String>,
}

#[derive(Args, Debug)]
struct StatusCommand {
    session_id: String,
    #[arg(long)]
    host: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct StopCommand {
    session_id: String,
    #[arg(long)]
    host: Option<String>,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Subcommand, Debug)]
enum SupportCommand {
    Bundle(SupportBundleCommand),
}

#[derive(Args, Debug)]
struct SupportBundleCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    no_input: bool,
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum EventMode {
    Auto,
    Human,
    Json,
    None,
}

struct CliFailure {
    error: SatelleError,
    history_session_id: Option<Box<SessionId>>,
    error_reported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, ValueEnum)]
enum SetupComponent {
    Transport,
    Host,
    Codex,
    ComputerUse,
    Desktop,
    ProviderAuth,
    All,
}

impl SetupComponent {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Host => "host",
            Self::Codex => "codex",
            Self::ComputerUse => "computer-use",
            Self::Desktop => "desktop",
            Self::ProviderAuth => "provider-auth",
            Self::All => "all",
        }
    }
}

fn main() -> ExitCode {
    let args = std::env::args_os().collect::<Vec<_>>();
    if process_has_disallowed_bearer_token(&args) {
        let error = SatelleError::invalid_usage(
            "bearer tokens are not accepted through command-line arguments or environment variables; configure a user-level file-backed api_token descriptor",
        );
        let format = parser_error_format(&args);
        print_error(&error, format);
        return process_exit_code(&error);
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error) if !error.use_stderr() => {
            let exit_code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(exit_code as u8);
        }
        Err(error) => {
            let format = parser_error_format(&args);
            let error = parser_error(&error);
            print_error(&error, format);
            return process_exit_code(&error);
        }
    };
    let mut error_format =
        ErrorFormat::resolve(cli.error_format, cli.command.requests_machine_errors());
    install_diagnostics(&cli.command, error_format);

    match try_main(cli, &mut error_format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            if !failure.error_reported {
                print_error(&failure.error, error_format);
            }
            process_exit_code(&failure.error)
        }
    }
}

fn process_has_disallowed_bearer_token(args: &[std::ffi::OsString]) -> bool {
    args.iter()
        .any(|value| contains_api_bearer_token(&value.to_string_lossy()))
        || std::env::vars_os().any(|(name, value)| {
            contains_api_bearer_token(&name.to_string_lossy())
                || contains_api_bearer_token(&value.to_string_lossy())
        })
}

#[cfg(test)]
mod process_boundary_tests {
    use super::*;

    #[test]
    fn bearer_token_in_argument_zero_is_rejected() {
        let token = ApiBearerToken::generate().expect("generate bearer token");
        let exposed = token.expose();

        assert!(process_has_disallowed_bearer_token(&[exposed
            .as_str()
            .into()]));
    }

    #[test]
    fn detach_interrupt_mode_conflict_is_typed_usage() {
        let failure = validate_interrupt_mode(true, true).expect_err("detach modes must conflict");
        assert_eq!(failure.error.code, ErrorCode::InterruptModeConflict);
        assert_eq!(failure.error.exit_code(), 64);
    }
}

fn parser_error_format(args: &[std::ffi::OsString]) -> ErrorFormat {
    let matches = Cli::command()
        .ignore_errors(true)
        .try_get_matches_from(args)
        .ok();
    let configured = matches.as_ref().and_then(|matches| {
        matches
            .try_get_one::<ErrorFormat>("error_format")
            .ok()
            .flatten()
            .copied()
    });
    let machine_selector = matches
        .as_ref()
        .is_some_and(output::partial_requests_machine_errors);
    ErrorFormat::resolve(configured, machine_selector)
}

fn try_main(cli: Cli, error_format: &mut ErrorFormat) -> Result<(), CliFailure> {
    let error_format_configured = cli.error_format.is_some();
    let Cli {
        no_color,
        profile,
        error_format: _,
        command,
    } = cli;
    let config = ConfigContext::new(profile.as_deref());
    preflight_setup_before_history(&command, &config)?;
    let history = start_command_history(&command, &config);
    let outcome = execute_command(
        command,
        no_color,
        profile.as_deref(),
        config,
        error_format,
        error_format_configured,
    );

    if let Some(history) = history {
        let session_id = match &outcome {
            Ok(session_id) => session_id.as_ref(),
            Err(failure) => failure.history_session_id.as_deref(),
        };
        let error_code = outcome.as_ref().err().map(|failure| failure.error.code);
        if let Err(error) = history.finish(session_id, error_code)
            && *error_format == ErrorFormat::Human
        {
            // History is non-authoritative and cannot replace the command's
            // outcome, but operators still need to know when a row was lost.
            eprintln!("warning: command history was not recorded: {error}");
        }
    }

    outcome.map(|_| ())
}

fn preflight_setup_before_history(
    command: &Command,
    config: &ConfigContext<'_>,
) -> Result<(), CliFailure> {
    let Command::Setup(command) = command else {
        return Ok(());
    };
    // Resolve configured precedence, then reject the built-in local backend
    // before command history can mutate operator state.
    command
        .output_args
        .resolve(EventOutput::None)
        .map_err(failure)?;
    let setup_components = setup_components(&command.component).map_err(failure)?;
    if command.on_demand && command.persistent {
        return Err(failure(SatelleError::invalid_usage(
            "--on-demand and --persistent cannot be combined",
        )));
    }
    if command.dry_run {
        return Ok(());
    }
    if let Some(expected) = command.expected_host_id.as_deref() {
        HostIdentityRef::new(expected).map_err(|error| {
            failure(SatelleError::invalid_usage(format!(
                "--expected-host-id is invalid: {error}"
            )))
        })?;
    }
    let resolved = config.load()?;
    let host = resolved
        .resolve_host(command.host.as_deref())
        .map(SelectedHost::from)
        .map_err(failure)?;
    if command.expected_host_id.is_some()
        && host.config.transport != satelle_core::TransportKind::Ssh
    {
        return Err(failure(SatelleError::invalid_usage(
            "setup --expected-host-id is only valid for an SSH Host Binding",
        )));
    }
    let daemon_path_overrides = daemon_path_overrides(command, &host.config);
    let first_ssh_trust = host.config.transport == satelle_core::TransportKind::Ssh
        && (host.config.expected_host_id.is_none() || !daemon_path_overrides.entries().is_empty());
    let setup_mode = setup_mode(command, &host.config)
        .map_err(failure)?
        .mode
        .as_str()
        .to_string();
    let trusted_consent =
        trusted_profile_allows_mutation(resolved, &host.alias, MutationCommandFamily::Setup);
    let verification_checks = if command.verify {
        setup_verification_checks(
            doctor_provider_intent(resolved, &host.config, true, None)
                .map_err(failure)?
                .provider_probe_required(),
        )
    } else {
        Vec::new()
    };
    if let Some(error) = first_ssh_setup_consent_error(
        command,
        config.flag_profile,
        trusted_consent,
        first_ssh_trust,
        &host.alias,
        &setup_mode,
        &setup_components,
        &daemon_path_overrides,
        &verification_checks,
    ) {
        return Err(failure(error));
    }
    if !uses_production_local_setup_backend() {
        return Ok(());
    }
    if host.config.transport != satelle_core::TransportKind::Local {
        return Ok(());
    }
    if command.verify {
        let path_rebind = !daemon_path_overrides.entries().is_empty();
        let (host_setup_components, _) =
            partition_setup_components(&setup_components, false, path_rebind);
        let tailscale_serve_setup = command.component.as_slice() == [SetupComponent::Transport]
            && tailscale_serve::applies_to(&host.config);
        if host_setup_components.is_empty() || tailscale_serve_setup {
            return Ok(());
        }
    }

    let setup_mode = if command.persistent {
        "persistent"
    } else {
        "on_demand"
    };
    Err(failure(SatelleError::not_implemented(format!(
        "{setup_mode} setup mutations are not supported by the local Host transport"
    ))))
}

#[cfg(feature = "test-support")]
fn uses_production_local_setup_backend() -> bool {
    std::env::var_os("SATELLE_TEST_SUPPORT_ADAPTER").is_none()
}

#[cfg(not(feature = "test-support"))]
fn uses_production_local_setup_backend() -> bool {
    true
}

fn execute_command(
    command: Command,
    no_color: bool,
    profile: Option<&str>,
    config: ConfigContext<'_>,
    error_format: &mut ErrorFormat,
    error_format_configured: bool,
) -> Result<Option<SessionId>, CliFailure> {
    let early_lifecycle_host = explicit_lifecycle_json_host(&command).map(str::to_owned);
    let (output_args, event_output) = command.output_request();
    let presentation_default_applies = matches!(
        &command,
        Command::Config { .. }
            | Command::Paths(_)
            | Command::Status(_)
            | Command::Logs(_)
            | Command::Host {
                command: HostCommand::Status(_) | HostCommand::Sessions(_),
            }
    );
    let presentation_default = presentation_default_applies
        .then(|| {
            config
                .load()
                .ok()
                .and_then(|resolved| resolved.config.output_format)
        })
        .flatten();
    let output = match output_args.resolve_with_default(event_output, presentation_default) {
        Ok(output) => output,
        Err(error) => {
            if let Some(host_alias) = early_lifecycle_host.as_deref() {
                let mut event_output = TurnEventOutput::new(EffectiveEventMode::Json, false);
                event_output
                    .emit_command_failed(host_alias, &error, TurnAdmissionPhase::NotAdmitted, None)
                    .map_err(failure)?;
            }
            return Err(failure(error));
        }
    };
    if !error_format_configured && presentation_default.is_some() {
        *error_format = if output.is_json() {
            ErrorFormat::Json
        } else {
            ErrorFormat::Human
        };
        // The configured presentation default is now known, so diagnostics and the terminal
        // command error must use the same resolved format as successful output.
        install_diagnostics(&command, *error_format);
    }
    let human_style = HumanStyle::detect(no_color);

    match command {
        Command::Completions(command) => run_completions(command).map_err(failure).map(|_| None),
        Command::Setup(command) => run_setup(command, human_style, config, output).map(|_| None),
        Command::Repair(command) => run_repair(command, config, output).map(|_| None),
        Command::Doctor(command) => run_doctor(command, config, output).map(|_| None),
        Command::Config { command } => run_config(command, config, output).map(|_| None),
        Command::Paths(command) => show_paths(command, config, output).map(|_| None),
        Command::Host { command } => run_host(command, config, output).map(|_| None),
        Command::SelfCtl { command } => {
            run_self(command, config, output, no_color, *error_format).map(|_| None)
        }
        Command::Run(command) => run_prompt(command, config, output).map(Some),
        Command::Steer(command) => steer_prompt(command, config, output).map(Some),
        Command::Status(command) => show_status(command, config, output).map(|_| None),
        Command::Stop(command) => stop_session(command, config, output).map(|_| None),
        Command::Logs(command) => show_logs(command, config, output).map(|_| None),
        Command::Mcp {
            command: McpCommand::Serve,
        } => mcp::serve(profile).map(|_| None),
        Command::Mcp {
            command: McpCommand::Install(command),
        } => run_mcp_install(command, profile, &config, output).map(|_| None),
        Command::Support { command } => run_support(command).map(|_| None),
    }
}

fn mcp_install_request(
    command: McpInstallCommand,
    profile: Option<&str>,
) -> mcp::install::InstallRequest {
    mcp::install::InstallRequest {
        targets: command.target,
        all: command.all,
        server_name: command.server_name,
        satelle_path: command.satelle_path,
        profile: profile.map(str::to_owned),
        dry_run: command.dry_run,
    }
}

fn mcp_install_profile(selected: Option<&satelle_core::SelectedProfile>) -> Option<&str> {
    selected
        .filter(|profile| {
            matches!(
                profile.source,
                satelle_core::ProfileSelectionSource::CliFlag
                    | satelle_core::ProfileSelectionSource::Environment
            )
        })
        .map(|profile| profile.name.as_str())
}

fn run_mcp_install(
    command: McpInstallCommand,
    _profile: Option<&str>,
    config: &ConfigContext<'_>,
    output: OutputFormat,
) -> Result<(), CliFailure> {
    let selected_profile = config.mcp_install_profile()?;
    let effective_profile = mcp_install_profile(selected_profile.as_ref());
    let report = mcp::install::install(mcp_install_request(command, effective_profile))?;

    if output.is_json() {
        print_json(&mcp_install_report_json(&report)).map_err(failure)?;
        return Ok(());
    }

    for change in report.changes {
        let target = change.target.label();
        if change.skipped {
            println!("{target}: skipped");
            continue;
        }

        let path = change
            .path
            .expect("non-skipped MCP install changes always have a config path");
        let action = match (report.dry_run, change.changed) {
            (true, true) => "would write",
            (false, true) => "wrote",
            (_, false) => "unchanged",
        };
        println!("{target}: {action} {}", path.display());
    }

    Ok(())
}

fn mcp_install_report_json(report: &mcp::install::InstallReport) -> serde_json::Value {
    let changes = report
        .changes
        .iter()
        .map(|change| {
            let action = match (report.dry_run, change.changed, change.skipped) {
                (_, _, true) => "skipped",
                (true, true, false) => "would_write",
                (false, true, false) => "wrote",
                (_, false, false) => "unchanged",
            };
            json!({
                "target": change.target.slug(),
                "path": change.path.as_ref().map(|path| path.display().to_string()),
                "changed": change.changed,
                "skipped": change.skipped,
                "action": action,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema_version": "satelle.mcp.install.v1",
        "dry_run": report.dry_run,
        "changes": changes,
    })
}

struct HistoryTarget<'a> {
    family: &'static str,
    selects_host: bool,
    explicit_host: Option<&'a str>,
    session_id: Option<String>,
}

fn start_command_history(
    command: &Command,
    config: &ConfigContext<'_>,
) -> Option<command_history::Recorder> {
    // Capture the invocation boundary before configuration discovery and
    // validation. Recorder construction happens later because the resolved
    // configuration controls both opt-out policy and redacted attribution.
    let invocation_start = command_history::InvocationStart::capture();
    let selects_profile = !matches!(
        command,
        Command::Config {
            command: ConfigCommand::Check(command),
        } if command.all
    );
    let target = history_target(command)?;
    let environment_preference = command_history_environment_preference();
    if environment_preference == Some(false) {
        return None;
    }

    // Reuse the same cached resolution that command dispatch consumes. Raw
    // CLI and environment selectors never cross the history boundary: only
    // profile and host names accepted by the configuration resolver do.
    let resolved = match config.load() {
        Ok(resolved) => Some(resolved),
        // An invalid configuration may contain an opt-out that could not be
        // decoded safely. Fail closed unless the environment explicitly
        // overrides configuration and enables history.
        Err(_) if environment_preference == Some(true) => None,
        Err(_) => return None,
    };
    let config_enabled = resolved
        .and_then(|resolved| resolved.config.command_history)
        .unwrap_or(true);
    if !environment_preference.unwrap_or(config_enabled) {
        return None;
    }

    let selected_profile = selects_profile
        .then(|| {
            resolved.and_then(|resolved| {
                resolved
                    .selected_profile
                    .as_ref()
                    .map(|profile| profile.name.clone())
            })
        })
        .flatten();
    let selected_host = if target.selects_host {
        resolved
            .and_then(|resolved| resolved.resolve_host(target.explicit_host).ok())
            .map(|(alias, _)| alias)
    } else {
        None
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cache_root = resolve_path_set(&cwd).ok()?.cache_root;
    let invocation = command_history::Invocation::new(
        target.family,
        selected_host,
        selected_profile,
        target.session_id,
    );
    Some(command_history::Recorder::start(
        cache_root,
        invocation,
        invocation_start,
    ))
}

fn history_target(command: &Command) -> Option<HistoryTarget<'_>> {
    let target = match command {
        // A dry-run must not mutate any declared state or cache path. The
        // corresponding mutating invocation is still recorded when executed.
        Command::Setup(command) if command.dry_run => return None,
        Command::Setup(command) => HistoryTarget {
            family: "setup",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: None,
        },
        Command::Repair(command) if command.dry_run => return None,
        Command::Repair(command) => HistoryTarget {
            family: "repair",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: None,
        },
        Command::Doctor(command) => HistoryTarget {
            family: "doctor",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: None,
        },
        Command::Config { command } => HistoryTarget {
            family: "config",
            selects_host: match command {
                ConfigCommand::Check(command) => !command.all,
                ConfigCommand::Explain(_) => true,
            },
            explicit_host: match command {
                ConfigCommand::Check(command) => command.host.as_deref(),
                ConfigCommand::Explain(command) => command.host.as_deref(),
            },
            session_id: None,
        },
        Command::Host {
            command: HostCommand::Update(command),
        } if command.dry_run => return None,
        Command::Host {
            command:
                HostCommand::Storage {
                    command: HostStorageCommand::Migrate(command),
                },
        } if command.dry_run => return None,
        Command::Host {
            command:
                HostCommand::Storage {
                    command: HostStorageCommand::Restore(command),
                },
        } if command.dry_run => return None,
        Command::Host {
            command:
                HostCommand::Storage {
                    command:
                        HostStorageCommand::Backup {
                            command: HostStorageBackupCommand::Cleanup(command),
                        },
                },
        } if command.dry_run => return None,
        Command::Host {
            command:
                HostCommand::Store {
                    command: HostStoreCommand::Reset(command),
                },
        } if command.dry_run => return None,
        Command::Host {
            command: HostCommand::ReleaseState,
        } => return None,
        Command::Host {
            command: HostCommand::OfflineStorageMaintenance(_),
        } => return None,
        Command::Host {
            command: HostCommand::OfflineStorageRestorePreview(_),
        } => return None,
        Command::Host {
            command: HostCommand::OfflineStorageBackupCleanupPlan(_),
        } => return None,
        Command::Host { command } => HistoryTarget {
            family: "host",
            selects_host: match command {
                HostCommand::Start(command) => {
                    !command.foreground
                        && !command.bootstrap_token_stdin
                        && command.service_config.is_none()
                }
                HostCommand::Update(command) => command.host.len() == 1 && !command.all_remotes,
                _ => true,
            },
            explicit_host: match command {
                HostCommand::Start(_) => None,
                HostCommand::ReleaseState => None,
                HostCommand::Trust(command) => Some(command.host.as_str()),
                HostCommand::Status(command) => command.host.as_deref(),
                HostCommand::Stop(command) | HostCommand::Restart(command) => {
                    command.host.as_deref()
                }
                HostCommand::Update(command) => (command.host.len() == 1 && !command.all_remotes)
                    .then(|| command.host[0].as_str()),
                HostCommand::Cleanup(command) => command.host.as_deref(),
                HostCommand::Sessions(command) => command.host.as_deref(),
                HostCommand::Storage {
                    command: HostStorageCommand::Migrate(command),
                } => command.host.as_deref(),
                HostCommand::Storage {
                    command: HostStorageCommand::Restore(command),
                } => command.host.as_deref(),
                HostCommand::Storage {
                    command:
                        HostStorageCommand::Backup {
                            command: HostStorageBackupCommand::Cleanup(command),
                        },
                } => command.host.as_deref(),
                HostCommand::Store {
                    command: HostStoreCommand::Reset(command),
                } => command.host.as_deref(),
                HostCommand::OfflineStorageMaintenance(_) => None,
                HostCommand::OfflineStorageRestorePreview(_) => None,
                HostCommand::OfflineStorageBackupCleanupPlan(_) => None,
            },
            session_id: None,
        },
        Command::Run(command) => HistoryTarget {
            family: "run",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: None,
        },
        Command::Steer(command) => HistoryTarget {
            family: "steer",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: canonical_history_session_id(&command.session_id),
        },
        Command::Status(command) => HistoryTarget {
            family: "status",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: canonical_history_session_id(&command.session_id),
        },
        Command::Stop(command) => HistoryTarget {
            family: "stop",
            selects_host: true,
            explicit_host: command.host.as_deref(),
            session_id: canonical_history_session_id(&command.session_id),
        },
        Command::Logs(command) => HistoryTarget {
            family: "logs",
            selects_host: true,
            explicit_host: command.history_host(),
            session_id: command
                .history_session_id()
                .and_then(canonical_history_session_id),
        },
        Command::Mcp {
            command: McpCommand::Install(command),
        } if command.dry_run => return None,
        Command::Mcp { .. } => HistoryTarget {
            family: "mcp",
            selects_host: false,
            explicit_host: None,
            session_id: None,
        },
        Command::Completions(_)
        | Command::Paths(_)
        | Command::SelfCtl { .. }
        | Command::Support { .. } => return None,
    };
    Some(target)
}

#[cfg(test)]
mod mcp_install_cli_tests {
    use super::*;

    fn parse_install(arguments: &[&str]) -> McpInstallCommand {
        let cli = Cli::try_parse_from(arguments).expect("parse MCP install command");
        let Command::Mcp {
            command: McpCommand::Install(command),
        } = cli.command
        else {
            panic!("expected MCP install command");
        };
        command
    }

    #[test]
    fn accepts_every_supported_target_spelling() {
        let targets = [
            ("claude-code", mcp::install::InstallTarget::ClaudeCode),
            ("claude-desktop", mcp::install::InstallTarget::ClaudeDesktop),
            ("codex", mcp::install::InstallTarget::Codex),
            ("cursor", mcp::install::InstallTarget::Cursor),
            ("vscode", mcp::install::InstallTarget::VsCode),
            ("windsurf", mcp::install::InstallTarget::Windsurf),
            ("gemini", mcp::install::InstallTarget::Gemini),
            ("opencode", mcp::install::InstallTarget::OpenCode),
            ("cline", mcp::install::InstallTarget::Cline),
            ("roo-code", mcp::install::InstallTarget::RooCode),
            ("droid", mcp::install::InstallTarget::Droid),
            ("antigravity", mcp::install::InstallTarget::Antigravity),
        ];

        for (spelling, expected) in targets {
            let command = parse_install(&["satelle", "mcp", "install", "--target", spelling]);
            assert_eq!(command.target, [expected], "target spelling {spelling}");
        }
    }

    #[test]
    fn explicit_profile_reaches_the_installer_request() {
        let cli = Cli::try_parse_from([
            "satelle",
            "--profile",
            "work",
            "mcp",
            "install",
            "--target",
            "codex",
        ])
        .expect("parse profiled MCP install command");
        let Command::Mcp {
            command: McpCommand::Install(command),
        } = cli.command
        else {
            panic!("expected MCP install command");
        };

        let selected = satelle_core::SelectedProfile {
            name: cli.profile.expect("explicit profile"),
            source: satelle_core::ProfileSelectionSource::CliFlag,
        };
        let request = mcp_install_request(command, mcp_install_profile(Some(&selected)));
        assert_eq!(request.profile.as_deref(), Some("work"));
    }

    #[test]
    fn environment_selected_profile_reaches_the_installer_request() {
        let selected = satelle_core::SelectedProfile {
            name: "work".to_string(),
            source: satelle_core::ProfileSelectionSource::Environment,
        };
        let command = parse_install(&["satelle", "mcp", "install", "--target", "cursor"]);

        let request = mcp_install_request(command, mcp_install_profile(Some(&selected)));

        assert_eq!(request.profile.as_deref(), Some("work"));
    }

    #[test]
    fn project_selected_profile_is_not_pinned_in_the_global_installer_request() {
        let selected = satelle_core::SelectedProfile {
            name: "project".to_string(),
            source: satelle_core::ProfileSelectionSource::ProjectConfig,
        };
        let command = parse_install(&["satelle", "mcp", "install", "--target", "cursor"]);

        let request = mcp_install_request(command, mcp_install_profile(Some(&selected)));

        assert_eq!(request.profile, None);
    }

    #[test]
    fn mcp_install_does_not_consume_a_project_aware_config_failure() {
        let resolved = Arc::new(OnceLock::new());
        assert!(
            resolved
                .set(Err(SatelleError::profile_not_found(
                    Path::new("/test/project/.satelle/config.toml"),
                    "project-only",
                    Vec::new(),
                )))
                .is_ok()
        );
        let config = ConfigContext {
            flag_profile: None,
            select_profile: true,
            profile_source: None,
            resolved,
        };
        // The invalid target selection proves the installer reached its own
        // validation without consuming the cached project-aware failure.
        let command = McpInstallCommand {
            target: Vec::new(),
            all: false,
            server_name: "satelle".to_string(),
            satelle_path: None,
            dry_run: false,
            output_args: OutputArgs::default(),
        };

        let failure = run_mcp_install(command, None, &config, OutputFormat::Human)
            .expect_err("installer validation must remain independent of project config");

        assert_eq!(failure.error.code, ErrorCode::InvalidUsage);
        assert_eq!(
            failure.error.message,
            "select at least one --target or use --all"
        );
    }

    #[test]
    fn parses_target_name_path_and_dry_run_options() {
        let command = parse_install(&[
            "satelle",
            "mcp",
            "install",
            "--target",
            "cursor",
            "--target",
            "codex",
            "--server-name",
            "satelle_tools",
            "--satelle-path",
            "/opt/satelle/bin/satelle",
            "--dry-run",
        ]);

        assert_eq!(
            command.target,
            [
                mcp::install::InstallTarget::Cursor,
                mcp::install::InstallTarget::Codex,
            ]
        );
        assert!(!command.all);
        assert_eq!(command.server_name, "satelle_tools");
        assert_eq!(
            command.satelle_path,
            Some(PathBuf::from("/opt/satelle/bin/satelle"))
        );
        assert!(command.dry_run);
    }

    #[test]
    fn parses_all_with_canonical_defaults() {
        let command = parse_install(&["satelle", "mcp", "install", "--all"]);

        assert!(command.target.is_empty());
        assert!(command.all);
        assert_eq!(command.server_name, "satelle");
        assert_eq!(command.satelle_path, None);
        assert!(!command.dry_run);
    }

    #[test]
    fn mcp_install_json_report_has_a_closed_versioned_shape() {
        let command = parse_install(&[
            "satelle",
            "mcp",
            "install",
            "--target",
            "cursor",
            "--dry-run",
            "--json",
        ]);
        assert!(command.output_args.requests_json());

        let report = mcp::install::InstallReport {
            dry_run: true,
            changes: vec![
                mcp::install::InstallChange {
                    target: mcp::install::InstallTarget::Cursor,
                    path: Some(PathBuf::from("/tmp/mcp.json")),
                    changed: true,
                    skipped: false,
                },
                mcp::install::InstallChange {
                    target: mcp::install::InstallTarget::ClaudeDesktop,
                    path: None,
                    changed: false,
                    skipped: true,
                },
            ],
        };

        assert_eq!(
            mcp_install_report_json(&report),
            json!({
                "schema_version": "satelle.mcp.install.v1",
                "dry_run": true,
                "changes": [
                    {
                        "target": "cursor",
                        "path": "/tmp/mcp.json",
                        "changed": true,
                        "skipped": false,
                        "action": "would_write",
                    },
                    {
                        "target": "claude-desktop",
                        "path": null,
                        "changed": false,
                        "skipped": true,
                        "action": "skipped",
                    },
                ],
            })
        );

        let formatted = parse_install(&[
            "satelle", "mcp", "install", "--target", "cursor", "--format", "json",
        ]);
        assert!(formatted.output_args.requests_json());
    }

    #[test]
    fn requires_a_target_selection_and_rejects_ambiguous_selection() {
        let missing = Cli::try_parse_from(["satelle", "mcp", "install"])
            .expect_err("target selection must be required");
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let conflict =
            Cli::try_parse_from(["satelle", "mcp", "install", "--target", "cursor", "--all"])
                .expect_err("--target and --all must conflict");
        assert_eq!(conflict.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn dry_run_is_excluded_from_command_history() {
        let dry_run = Cli::try_parse_from([
            "satelle",
            "mcp",
            "install",
            "--target",
            "cursor",
            "--dry-run",
        ])
        .expect("parse dry-run install");
        let mutating = Cli::try_parse_from(["satelle", "mcp", "install", "--target", "cursor"])
            .expect("parse mutating install");

        assert!(history_target(&dry_run.command).is_none());
        assert_eq!(
            history_target(&mutating.command)
                .expect("mutating install history")
                .family,
            "mcp"
        );
    }
}

fn command_history_environment_preference() -> Option<bool> {
    let value = match std::env::var("SATELLE_COMMAND_HISTORY") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return None,
        // A present value that cannot be decoded is still an explicit,
        // malformed preference. History contains operational metadata, so it
        // must fail closed just like an unrecognized Unicode value.
        Err(std::env::VarError::NotUnicode(_)) => return Some(false),
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        // History contains operational metadata. A malformed opt-out must not
        // silently fall back to enabled recording.
        _ => Some(false),
    }
}

#[cfg(test)]
mod history_target_tests {
    use super::*;

    fn host_start(foreground: bool, bootstrap_token_stdin: bool) -> Command {
        Command::Host {
            command: HostCommand::Start(HostStartCommand {
                bind: "127.0.0.1:3001".to_string(),
                tls_cert: None,
                tls_key: None,
                foreground,
                launchd_service: false,
                bootstrap_token_stdin,
                initial_host_identity: None,
                initial_identity_operation_id: None,
                initial_identity_record: None,
                bootstrap_scope: bootstrap_token_stdin.then_some(SshBootstrapScope::Control),
                bootstrap_native_readiness_timeout_ms: None,
                bootstrap_provider_smoke_timeout_ms: None,
                on_demand_idle_timeout_ms: None,
                setup_ledger_retention_ms: None,
                service_config: None,
                output_args: OutputArgs::default(),
            }),
        }
    }

    #[test]
    fn only_on_demand_host_start_selects_a_configured_host() {
        let on_demand = host_start(false, false);
        let foreground = host_start(true, false);
        let ssh_bootstrap = host_start(false, true);

        assert!(
            history_target(&on_demand)
                .expect("on-demand target")
                .selects_host
        );
        assert!(
            !history_target(&foreground)
                .expect("foreground target")
                .selects_host
        );
        assert!(
            !history_target(&ssh_bootstrap)
                .expect("SSH bootstrap target")
                .selects_host
        );
    }

    #[test]
    fn ssh_bootstrap_scope_is_an_explicit_internal_argument() {
        let cli = Cli::try_parse_from([
            "satelle",
            "host",
            "start",
            "--bootstrap-token-stdin",
            "--bootstrap-scope",
            "read",
        ])
        .expect("parse internal SSH bootstrap start command");

        let Command::Host {
            command: HostCommand::Start(command),
        } = cli.command
        else {
            panic!("expected Host start command");
        };
        assert!(command.bootstrap_token_stdin);
        assert_eq!(command.bootstrap_scope, Some(SshBootstrapScope::Read));
    }

    #[test]
    fn bootstrap_maintenance_is_not_a_host_start_argument() {
        let error = Cli::try_parse_from([
            "satelle",
            "host",
            "start",
            "--bootstrap-token-stdin",
            "--bootstrap-scope",
            "read",
            "--bootstrap-operation-id",
            "operation-1",
            "--bootstrap-operation-kind",
            "missing_daemon_repair",
        ])
        .expect_err("maintenance starts only through the authenticated handoff API");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn durable_ssh_idle_timeout_accepts_bootstrap_handoff_mode() {
        let cli = Cli::try_parse_from([
            "satelle",
            "host",
            "start",
            "--bootstrap-token-stdin",
            "--bootstrap-scope",
            "read",
            "--on-demand-idle-timeout-ms",
            "75000",
        ])
        .expect("parse internal durable SSH start command");

        let Command::Host {
            command: HostCommand::Start(command),
        } = cli.command
        else {
            panic!("expected Host start command");
        };
        assert_eq!(command.on_demand_idle_timeout_ms, Some(75_000));
        assert!(command.bootstrap_token_stdin);
        validate_host_start_mode(&command)
            .expect("durable SSH relaunch accepts its process-local bootstrap credential");
    }

    #[test]
    fn windows_service_config_is_an_internal_non_host_selecting_start_mode() {
        let cli = Cli::try_parse_from([
            "satelle",
            "host",
            "start",
            "--service-config",
            r"C:\Users\owner\AppData\Local\Satelle\service\host-1.json",
        ])
        .expect("parse internal Windows service start command");
        assert!(
            !history_target(&cli.command)
                .expect("Host start history target")
                .selects_host
        );
        let Command::Host {
            command: HostCommand::Start(command),
        } = cli.command
        else {
            panic!("expected Host start command");
        };
        assert!(command.service_config.is_some());
        validate_host_start_mode(&command).expect("service config is a valid closed start mode");
    }

    #[test]
    fn launchd_service_is_an_internal_non_host_selecting_start_mode() {
        let cli = Cli::try_parse_from([
            "satelle",
            "host",
            "start",
            "--foreground",
            "--launchd-service",
            "--setup-ledger-retention-ms",
            "3600000",
        ])
        .expect("parse internal launchd service start command");
        assert!(
            !history_target(&cli.command)
                .expect("Host start history target")
                .selects_host
        );
        let Command::Host {
            command: HostCommand::Start(command),
        } = cli.command
        else {
            panic!("expected Host start command");
        };
        assert!(command.launchd_service);
        assert_eq!(command.setup_ledger_retention_ms, Some(3_600_000));
        validate_host_start_mode(&command).expect("launchd service is a valid closed start mode");
    }

    #[test]
    fn windows_service_config_rejects_competing_start_inputs() {
        for arguments in [
            vec!["--foreground"],
            vec!["--bind", "127.0.0.1:4001"],
            vec!["--on-demand-idle-timeout-ms", "75000"],
            vec!["--bootstrap-token-stdin", "--bootstrap-scope", "read"],
        ] {
            let error = Cli::try_parse_from(
                [
                    "satelle",
                    "host",
                    "start",
                    "--service-config",
                    "service.json",
                ]
                .into_iter()
                .chain(arguments),
            )
            .expect_err("service config must reject competing start inputs");
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn host_start_mode_validation_preserves_incompatible_combinations() {
        let cases = [
            (
                vec![
                    "--foreground",
                    "--bootstrap-token-stdin",
                    "--bootstrap-scope",
                    "read",
                ],
                "SSH bootstrap tokens are valid only for on-demand Host Daemons",
            ),
            (
                vec![
                    "--bootstrap-token-stdin",
                    "--bootstrap-scope",
                    "read",
                    "--tls-cert",
                    "cert.pem",
                    "--tls-key",
                    "key.pem",
                ],
                "SSH bootstrap Host Daemons use loopback plaintext inside the authenticated tunnel and do not accept TLS files",
            ),
            (
                vec!["--foreground", "--on-demand-idle-timeout-ms", "75000"],
                "the resolved on-demand idle timeout is valid only for durable on-demand Host Daemons",
            ),
            (
                vec!["--on-demand-idle-timeout-ms", "0"],
                "the resolved on-demand idle timeout must be positive",
            ),
        ];

        for (arguments, expected_message) in cases {
            let cli =
                Cli::try_parse_from(["satelle", "host", "start"].into_iter().chain(arguments))
                    .expect("parse internal Host start command");
            let Command::Host {
                command: HostCommand::Start(command),
            } = cli.command
            else {
                panic!("expected Host start command");
            };

            let error = validate_host_start_mode(&command)
                .expect_err("incompatible Host start mode must fail");
            assert_eq!(error.code, ErrorCode::InvalidUsage);
            assert_eq!(error.message, expected_message);
        }
    }

    #[test]
    fn host_cleanup_parses_host_selection_and_machine_output() {
        let cli = Cli::try_parse_from(["satelle", "host", "cleanup", "--host", "remote", "--json"])
            .expect("parse Host cleanup command");
        let Command::Host {
            command: HostCommand::Cleanup(command),
        } = cli.command
        else {
            panic!("expected Host cleanup command");
        };
        assert_eq!(command.host.as_deref(), Some("remote"));
        assert_eq!(
            command
                .output_args
                .resolve(EventOutput::None)
                .expect("resolve cleanup output"),
            OutputFormat::Json
        );

        let report = transport::CacheCleanupReport {
            removed_entries: 3,
            retained_entries: 2,
        };
        assert_eq!(
            serde_json::to_value(report).expect("serialize cleanup report"),
            serde_json::json!({"removed_entries": 3, "retained_entries": 2})
        );
    }

    #[test]
    fn storage_maintenance_commands_parse_exact_public_paths() {
        let restore = Cli::try_parse_from([
            "satelle",
            "host",
            "storage",
            "restore",
            "--host",
            "remote",
            "--backup",
            "/state/satelle.sqlite3.migration-v13-example.backup",
            "--dry-run",
            "--json",
        ])
        .expect("parse storage restore");
        let Command::Host {
            command:
                HostCommand::Storage {
                    command: HostStorageCommand::Restore(restore),
                },
        } = restore.command
        else {
            panic!("expected storage restore command");
        };
        assert_eq!(restore.host.as_deref(), Some("remote"));
        assert!(restore.dry_run);

        let restore_preview = Cli::try_parse_from([
            "satelle",
            "host",
            "offline-storage-restore-preview",
            "--state-root",
            "/state",
            "--backup",
            "/state/satelle.sqlite3.migration-v13-example.backup",
        ])
        .expect("parse internal storage restore preview");
        assert!(matches!(
            restore_preview.command,
            Command::Host {
                command: HostCommand::OfflineStorageRestorePreview(_)
            }
        ));

        let cleanup = Cli::try_parse_from([
            "satelle",
            "host",
            "storage",
            "backup",
            "cleanup",
            "--host",
            "remote",
            "--no-input",
            "--yes",
        ])
        .expect("parse storage backup cleanup");
        assert!(matches!(
            cleanup.command,
            Command::Host {
                command: HostCommand::Storage {
                    command: HostStorageCommand::Backup {
                        command: HostStorageBackupCommand::Cleanup(_)
                    }
                }
            }
        ));

        let reset = Cli::try_parse_from([
            "satelle",
            "host",
            "store",
            "reset",
            "--host",
            "remote",
            "--delete-recordings",
            "--no-input",
            "--yes",
        ])
        .expect("parse store reset");
        assert!(matches!(
            reset.command,
            Command::Host {
                command: HostCommand::Store {
                    command: HostStoreCommand::Reset(_)
                }
            }
        ));
    }
}

#[test]
fn empty_remote_cleanup_plan_retains_interrupted_service_recovery() {
    assert!(storage_backup_cleanup_actions(&[], false).is_empty());
    assert_eq!(
        storage_backup_cleanup_actions(&[], true),
        ["restart and verify the unavailable Host API service"]
    );
}

fn canonical_history_session_id(value: &str) -> Option<String> {
    SessionId::from_str(value)
        .ok()
        .map(|session| session.to_string())
}

fn explicit_lifecycle_json_host(command: &Command) -> Option<&str> {
    match command {
        Command::Run(command) if !command.detach && command.events == EventMode::Json => {
            command.host.as_deref().filter(|alias| !alias.is_empty())
        }
        Command::Steer(command) if !command.detach && command.events == EventMode::Json => {
            command.host.as_deref().filter(|alias| !alias.is_empty())
        }
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingSetupDesktopSelection {
    desktop_user: String,
    preference: DesktopSessionPreference,
}

impl PendingSetupDesktopSelection {
    fn action(&self, host_alias: &str) -> String {
        let preference = match self.preference {
            DesktopSessionPreference::Only => "only",
            DesktopSessionPreference::Console => "console",
        };
        format!(
            "set Host Binding {host_alias} desktop_user to '{}' and desktop_session_preference to '{preference}'",
            self.desktop_user
        )
    }
}

fn partition_setup_components(
    setup_components: &[String],
    ssh_transport: bool,
    path_rebind: bool,
) -> (Vec<String>, bool) {
    let desktop_selected = setup_components
        .iter()
        .any(|component| matches!(component.as_str(), "desktop" | "all"));
    let mut host_components = setup_components
        .iter()
        .filter(|component| !matches!(component.as_str(), "desktop" | "provider-auth"))
        .cloned()
        .collect::<Vec<_>>();
    if ssh_transport && host_components == ["all"] {
        // SSH setup currently owns only the authenticated transport handoff.
        // Keep the user-facing `all` selection intact in the final report, but
        // do not send that aggregate CLI selector to the transport-only backend.
        host_components = vec!["transport".to_string()];
    } else if ssh_transport && path_rebind && host_components.is_empty() {
        // Selecting new daemon paths requires the transport handoff even when
        // desktop selection is the only explicit setup component.
        host_components.push("transport".to_string());
    }
    (host_components, desktop_selected)
}

fn setup_transport_if_required<T, E>(
    required: bool,
    build: impl FnOnce() -> Result<T, E>,
) -> Result<Option<T>, E> {
    if required {
        build().map(Some)
    } else {
        Ok(None)
    }
}

fn run_host_setup_if_required<T>(
    required: bool,
    cli_owned_result: impl FnOnce() -> T,
    host_owned_setup: impl FnOnce() -> Result<T, SatelleError>,
) -> Result<T, SatelleError> {
    if required {
        host_owned_setup()
    } else {
        Ok(cli_owned_result())
    }
}

fn run_host_setup_then_follow_up<T, E>(
    host_setup: impl FnOnce() -> Result<T, E>,
    follow_up: impl FnOnce(&mut T) -> Result<(), E>,
) -> Result<T, E> {
    let mut result = host_setup()?;
    follow_up(&mut result)?;
    Ok(result)
}

#[cfg(test)]
fn run_host_setup_after_desktop_preflight<C, T>(
    desktop_preflight: Result<(), CliFailure>,
    setup_config: &mut C,
    persist_desktop_selection: impl FnOnce(&mut C) -> Result<(), CliFailure>,
    host_setup: impl FnOnce(&C) -> Result<T, CliFailure>,
) -> Result<T, CliFailure> {
    desktop_preflight?;
    persist_desktop_selection(setup_config)?;
    host_setup(setup_config)
}

fn cli_owned_setup_report(
    host: &str,
    dry_run: bool,
    setup_mode: &str,
    setup_components: Vec<String>,
) -> SetupReport {
    let service_persistent = setup_mode == "persistent";
    SetupReport {
        schema_version: SetupSchemaVersion::V2,
        host: host.to_string(),
        dry_run,
        status: "planned".to_string(),
        cancellation_reason: None,
        setup_mode: setup_mode.to_string(),
        service_persistent,
        service_scope: if service_persistent {
            "user".to_string()
        } else {
            "on_demand".to_string()
        },
        fallback_reason: None,
        target_platform: None,
        host_artifact: None,
        service_plan: None,
        current_daemon_paths: None,
        planned_daemon_paths: None,
        setup_components,
        planned_actions: Vec::new(),
        applied_actions: Vec::new(),
        required_input: Vec::new(),
        recovery_commands: Vec::new(),
        readiness_summary: SetupReadinessSummary {
            transport: "not_checked".to_string(),
            host_daemon: "not_checked".to_string(),
            codex_runtime: "not_checked".to_string(),
            native_computer_use: "not_verified".to_string(),
            provider_auth: "not_checked".to_string(),
        },
        descriptor_configured: false,
        secret_provisioned: false,
        validation_status: "not_checked".to_string(),
        provider_smoke_test_status: "not_checked".to_string(),
        daemon_path_overrides: Vec::new(),
        changed: false,
        mutated: false,
        mutation_planned: false,
        native_computer_use_readiness: "not_verified".to_string(),
        next_command: "satelle doctor --scope computer-use --refresh --json".to_string(),
        verification: None,
    }
}

fn add_setup_component_plan(report: &mut SetupReport) {
    let components = [
        ("transport", "check transport readiness"),
        ("host", "check Host Daemon readiness"),
        ("codex", "check Codex runtime prerequisites"),
        (
            "computer-use",
            "check native Codex Computer Use prerequisites",
        ),
        ("desktop", "check Desktop Binding"),
        ("provider-auth", "check provider authentication"),
    ];
    for (component, action) in components {
        if report
            .setup_components
            .iter()
            .any(|selected| selected == component || selected == "all")
            && !report
                .planned_actions
                .iter()
                .any(|planned| planned == action)
        {
            report.planned_actions.push((*action).to_string());
        }
    }
}

fn setup_verification_checks(provider_probe_required: bool) -> Vec<String> {
    let mut checks = vec!["native_computer_use".to_string()];
    if provider_probe_required {
        checks.push("provider_computer_use".to_string());
    }
    checks
}

fn add_setup_verification_plan(report: &mut SetupReport, checks: &[String]) {
    report.verification = Some(SetupVerification::planned(checks.to_vec()));
    if !report
        .planned_actions
        .iter()
        .any(|action| action == "run live native Computer Use readiness verification")
    {
        report
            .planned_actions
            .push("run live native Computer Use readiness verification".to_string());
    }
    if checks.iter().any(|check| check == "provider_computer_use")
        && !report
            .planned_actions
            .iter()
            .any(|action| action == "run required provider Computer Use smoke verification")
    {
        report
            .planned_actions
            .push("run required provider Computer Use smoke verification".to_string());
    }
}

fn ensure_exact_setup_verification_recovery(report: &mut SetupReport, host: &str) {
    let recovery = format!(
        "satelle setup --host {} --verify --no-input",
        shell_argument(host)
    );
    if !report.recovery_commands.contains(&recovery) {
        report.recovery_commands.insert(0, recovery);
    }
}

fn trusted_profile_allows_mutation(
    resolved: &ResolvedConfig,
    host_alias: &str,
    command_family: MutationCommandFamily,
) -> bool {
    let Some(selected) = resolved.selected_profile.as_ref() else {
        return false;
    };
    if !matches!(
        selected.source,
        ProfileSelectionSource::CliFlag | ProfileSelectionSource::UserConfig
    ) {
        return false;
    }
    resolved
        .config
        .trusted_profiles
        .get(&selected.name)
        .is_some_and(|trusted| {
            trusted.hosts.contains(host_alias) && trusted.command_families.contains(&command_family)
        })
}

#[allow(clippy::too_many_arguments)]
fn first_ssh_setup_consent_error(
    command: &SetupCommand,
    flag_profile: Option<&str>,
    trusted_consent: bool,
    first_ssh_trust: bool,
    host_alias: &str,
    setup_mode: &str,
    setup_components: &[String],
    daemon_path_overrides: &DaemonPathOverrides,
    verification_checks: &[String],
) -> Option<SatelleError> {
    if !first_ssh_trust
        || command.dry_run
        || command.yes
        || trusted_consent
        || (!command.no_input && io::stdin().is_terminal())
    {
        return None;
    }

    // First-time SSH discovery can upload and start a temporary Host. Reject
    // before command-history initialization or transport construction.
    let mut consent_report =
        cli_owned_setup_report(host_alias, false, setup_mode, setup_components.to_vec());
    add_setup_component_plan(&mut consent_report);
    consent_report.mutation_planned = true;
    consent_report.planned_actions.insert(
        0,
        "bootstrap the temporary Host Daemon, discover its Host Identity, and persist explicit trust"
            .to_string(),
    );
    if command.verify {
        add_setup_verification_plan(&mut consent_report, verification_checks);
    }
    let recovery_command = setup_consent_recovery_command(
        command,
        flag_profile,
        setup_mode,
        daemon_path_overrides,
        true,
    );
    Some(SatelleError::setup_consent_required(
        &consent_report.planned_actions,
        &recovery_command,
    ))
}

fn setup_interaction_error(message: &str, source: io::Error) -> SatelleError {
    SatelleError {
        code: if source.kind() == io::ErrorKind::Interrupted {
            ErrorCode::Interrupted
        } else {
            ErrorCode::InvalidUsage
        },
        message: message.to_string(),
        recovery_command: Some("rerun with --yes or --dry-run".to_string()),
        source_detail: Some(source.to_string()),
        details: BTreeMap::from([
            ("changed".to_string(), json!(false)),
            ("applied_actions".to_string(), json!([])),
        ]),
    }
}

fn finish_cancelled_setup(report: &mut SetupReport, json: bool) -> Result<(), CliFailure> {
    report.status = "cancelled".to_string();
    report.cancellation_reason = Some("user_declined_confirmation".to_string());
    report.changed = false;
    report.mutated = false;
    report.applied_actions.clear();
    if json {
        print_json(
            &serde_json::to_value(report)
                .map_err(|error| failure(SatelleError::invalid_usage(error.to_string())))?,
        )
        .map_err(failure)
    } else {
        println!("No changes applied.");
        Ok(())
    }
}

fn resolve_setup_desktop_selection(
    report: &HostSessionsReport,
    host_config: &HostConfig,
    interactive: bool,
    authenticated_bootstrap_user: Option<&str>,
) -> Result<Option<PendingSetupDesktopSelection>, SatelleError> {
    let mut policy = DesktopSelectionPolicy::from_host_config(host_config);
    if policy.desktop_user.is_none()
        && let Some(authenticated_user) = authenticated_bootstrap_user
    {
        let bootstrap_policy = DesktopSelectionPolicy {
            desktop_user: Some(authenticated_user.to_string()),
            preference: None,
            native_selector: None,
        };
        match resolve_desktop_session(report, &bootstrap_policy) {
            Ok(_) => policy.desktop_user = bootstrap_policy.desktop_user,
            Err(error) if error.code == ErrorCode::DesktopSessionAmbiguous => {
                policy.desktop_user = bootstrap_policy.desktop_user;
            }
            Err(_) => {}
        }
    }

    loop {
        match resolve_desktop_session(report, &policy) {
            Ok(session) => {
                if policy.native_selector.is_some() {
                    return Ok(None);
                }
                let preference = policy
                    .preference
                    .clone()
                    .unwrap_or(DesktopSessionPreference::Only);
                let selection = PendingSetupDesktopSelection {
                    desktop_user: session.desktop_user.clone(),
                    preference,
                };
                if host_config.desktop_user.as_deref() == Some(selection.desktop_user.as_str())
                    && host_config.desktop_session_preference.as_ref()
                        == Some(&selection.preference)
                {
                    return Ok(None);
                }
                return Ok(Some(selection));
            }
            Err(error) if error.code == ErrorCode::DesktopBindingRequired && interactive => {
                let candidates = error
                    .details
                    .get("candidate_desktop_users")
                    .and_then(serde_json::Value::as_array)
                    .expect("the desktop-binding-required contract contains candidates")
                    .iter()
                    .map(|candidate| {
                        candidate
                            .as_str()
                            .expect("candidate desktop users are strings")
                            .to_string()
                    })
                    .collect::<Vec<_>>();
                let mut prompt = cliclack::select("Choose the Desktop Binding for this Host");
                for candidate in candidates {
                    prompt = prompt.item(
                        candidate.clone(),
                        candidate,
                        "active compatible desktop user",
                    );
                }
                policy.desktop_user = Some(prompt.interact().map_err(|source| {
                    setup_interaction_error("could not read Desktop Binding selection", source)
                })?);
            }
            Err(error) if error.code == ErrorCode::DesktopSessionAmbiguous && interactive => {
                let desktop_user = policy
                    .desktop_user
                    .clone()
                    .or_else(|| {
                        error
                            .details
                            .get("desktop_user")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string)
                    })
                    .expect("desktop-session-ambiguous identifies its Desktop Binding");
                let console_policy = DesktopSelectionPolicy {
                    desktop_user: Some(desktop_user),
                    preference: Some(DesktopSessionPreference::Console),
                    native_selector: None,
                };
                if resolve_desktop_session(report, &console_policy).is_err() {
                    return Err(error);
                }
                policy = console_policy;
                policy.preference = Some(
                    cliclack::select("Choose the Desktop Session Preference")
                        .item(
                            DesktopSessionPreference::Console,
                            "console",
                            "the compatible physical console session",
                        )
                        .interact()
                        .map_err(|source| {
                            setup_interaction_error(
                                "could not read Desktop Session Preference selection",
                                source,
                            )
                        })?,
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn run_setup(
    command: SetupCommand,
    style: HumanStyle,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    if let Some(expected) = command.expected_host_id.as_deref() {
        HostIdentityRef::new(expected).map_err(|error| {
            failure(SatelleError::invalid_usage(format!(
                "--expected-host-id is invalid: {error}"
            )))
        })?;
    }
    let resolved = config.load()?;
    let mut host = resolved
        .resolve_host(command.host.as_deref())
        .map(SelectedHost::from)
        .map_err(failure)?;
    let user_config_path = resolved.user_config_path.clone();
    if command.expected_host_id.is_some()
        && host.config.transport != satelle_core::TransportKind::Ssh
    {
        return Err(failure(SatelleError::invalid_usage(
            "setup --expected-host-id is only valid for an SSH Host Binding",
        )));
    }
    let daemon_path_overrides = daemon_path_overrides(&command, &host.config);
    let path_rebind = !daemon_path_overrides.entries().is_empty();
    if !path_rebind
        && command
            .expected_host_id
            .as_deref()
            .zip(host.config.expected_host_id.as_deref())
            .is_some_and(|(required, configured)| required != configured)
    {
        return Err(failure(SatelleError::host_identity_mismatch(&host.alias)));
    }
    let first_ssh_trust = host.config.transport == satelle_core::TransportKind::Ssh
        && (host.config.expected_host_id.is_none() || path_rebind);
    let setup_components = setup_components(&command.component).map_err(failure)?;
    let native_affecting_setup = setup_components.iter().any(|component| {
        matches!(
            component.as_str(),
            "all" | "host" | "codex" | "computer-use" | "desktop"
        )
    });
    let provider_auth_setup = setup_components
        .iter()
        .any(|component| component == "all" || component == "provider-auth");
    let ssh_transport = host.config.transport == satelle_core::TransportKind::Ssh;
    let (host_setup_components, desktop_setup) =
        partition_setup_components(&setup_components, ssh_transport, path_rebind);
    let setup_mode_selection = setup_mode(&command, &host.config).map_err(failure)?;
    let local_service_decision = (host.config.transport == satelle_core::TransportKind::Local)
        .then(|| {
            PersistentServiceDecision::resolve(
                setup_mode_selection,
                current_daemon_service_platform(),
            )
        });
    if local_service_decision
        .as_ref()
        .is_some_and(|decision| decision.explicit_persistent_unsupported)
    {
        return Err(failure(SatelleError::persistent_service_unsupported(
            current_daemon_service_platform().as_str(),
        )));
    }
    let setup_mode = local_service_decision
        .as_ref()
        .map_or(setup_mode_selection.mode, |decision| decision.setup_mode)
        .as_str()
        .to_string();
    let tailscale_serve_setup = command.component.as_slice() == [SetupComponent::Transport]
        && tailscale_serve::applies_to(&host.config);
    let host_setup_required = !host_setup_components.is_empty();
    let interactive_selection = !command.no_input && io::stdin().is_terminal();
    let trusted_consent =
        trusted_profile_allows_mutation(resolved, &host.alias, MutationCommandFamily::Setup);
    let mut provider_selection =
        resolve_provider_selection(resolved, &host, None, None, false, false)?;
    let provider_probe_required = if command.verify {
        doctor_provider_intent(resolved, &host.config, true, None)
            .map_err(failure)?
            .provider_probe_required()
    } else {
        false
    };
    let verification_checks = setup_verification_checks(provider_probe_required);
    let mut provider_auth_validation = None;
    let mut pending_provider_auth = None;
    let mut pending_provider_binding_authorization = None;
    let mut pending_provider_secret_authorization = None;
    let mut provider_secret_setup_completed = false;
    if let Some(error) = first_ssh_setup_consent_error(
        &command,
        config.flag_profile,
        trusted_consent,
        first_ssh_trust,
        &host.alias,
        &setup_mode,
        &setup_components,
        &daemon_path_overrides,
        &verification_checks,
    ) {
        return Err(failure(error));
    }
    let mut transport = if tailscale_serve_setup || !host_setup_required {
        None
    } else {
        setup_transport_if_required(host_setup_required, || transport_for_setup(&host))?
    };
    let mut report = if tailscale_serve_setup {
        tailscale_serve::configure(
            &host.alias,
            &host.config,
            &daemon_path_overrides,
            true,
            &setup_mode,
        )
        .map_err(failure)?
    } else {
        run_host_setup_if_required(
            host_setup_required,
            || cli_owned_setup_report(&host.alias, true, &setup_mode, setup_components.clone()),
            || {
                transport
                    .as_ref()
                    .expect("Host-owned setup transport is present")
                    .setup(
                        true,
                        setup_mode_selection,
                        host_setup_components.clone(),
                        daemon_path_overrides.clone(),
                    )
            },
        )
        .map_err(failure)?
    };
    report.setup_components.clone_from(&setup_components);
    add_setup_component_plan(&mut report);
    if command.verify {
        add_setup_verification_plan(&mut report, &verification_checks);
    }
    if let Some(decision) = &local_service_decision {
        apply_service_decision_to_report(&mut report, decision);
    }
    report.dry_run = command.dry_run;
    if let Some((auth_source_name, _)) = &pending_provider_auth {
        report.planned_actions.push(format!(
            "save provider authentication descriptor reference '{auth_source_name}' for Host '{}'",
            host.alias
        ));
    }
    if command.dry_run {
        add_setup_required_inputs(&mut report, &provider_selection, provider_auth_setup);
        if provider_auth_setup
            && provider_selection
                .authorization
                .as_ref()
                .and_then(ProviderBindingAuthorization::auth_source)
                .is_some()
        {
            report.descriptor_configured = true;
            report.validation_status = "deferred".to_string();
            report.planned_actions.push(format!(
                "inspect the provider secret destination on Host '{}' and provision it if required",
                host.alias
            ));
        }
    }
    let mut desktop_selection = None;
    if desktop_setup
        && !command.dry_run
        && report.required_input.is_empty()
        && (host.config.transport != satelle_core::TransportKind::Ssh || !first_ssh_trust)
    {
        let authenticated_bootstrap_user = (host.config.transport
            == satelle_core::TransportKind::Ssh)
            .then(|| authenticated_ssh_bootstrap_user(&host))
            .transpose()
            .map_err(failure)?;
        let sessions = transport_for(&host)?.host_sessions(true).map_err(failure)?;
        desktop_selection = resolve_setup_desktop_selection(
            &sessions,
            &host.config,
            interactive_selection,
            authenticated_bootstrap_user.as_deref(),
        )
        .map_err(failure)?;
        if let Some(selection) = &desktop_selection {
            report.planned_actions.push(selection.action(&host.alias));
            report.mutation_planned = true;
        }
    } else if desktop_setup
        && !command.dry_run
        && report.required_input.is_empty()
        && host.config.transport == satelle_core::TransportKind::Ssh
    {
        report.planned_actions.push(
            "inspect compatible desktop sessions through the authenticated Host Daemon".to_string(),
        );
    }

    if first_ssh_trust {
        report.mutation_planned = true;
        report.planned_actions.insert(
            0,
            "bootstrap the temporary Host Daemon, discover its Host Identity, and persist explicit trust"
                .to_string(),
        );
    }
    // Capture this before provider-auth planning can mark an otherwise native-stable
    // setup as mutating. First SSH trust has no prior authenticated Host cache.
    let native_readiness_invalidation_planned =
        native_affecting_setup && report.mutation_planned && !first_ssh_trust;

    if provider_auth_setup && !command.dry_run && report.required_input.is_empty() {
        let provider_aliases = match (
            provider_selection.requested_model_alias.as_deref(),
            provider_selection.requested_provider_alias.as_deref(),
        ) {
            (Some(model_alias), Some(provider_alias)) => Some((model_alias, provider_alias)),
            _ => {
                report.readiness_summary.provider_auth = "host_owned".to_string();
                None
            }
        };
        if let Some((model_alias, provider_alias)) = provider_aliases {
            if first_ssh_trust {
                report.planned_actions.push(format!(
                    "validate provider binding '{provider_alias}/{model_alias}' on Host '{}'",
                    host.alias
                ));
            } else {
                let provider_transport = transport_for(&host)?;
                match provider_transport.validate_provider_descriptor(
                    model_alias,
                    provider_alias,
                    provider_selection.model_alias_from_project,
                    provider_selection.provider_alias_from_project,
                    satelle_core::ProviderAuthValidationMode::Cached,
                    provider_selection.experimental_provider_computer_use,
                ) {
                    Ok(validation)
                        if validation.validation.outcome()
                            == satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret =>
                    {
                        pending_provider_secret_authorization =
                            Some(plan_provider_secret_provisioning(
                                &mut report,
                                &provider_selection,
                                &host.alias,
                            )?);
                    }
                    Ok(validation) => {
                        provider_auth_validation = accept_setup_provider_auth_validation(
                            &mut report,
                            &provider_selection,
                            validation,
                        )?;
                    }
                    Err(error) if error.code == ErrorCode::ModelProviderBindingMissing => {
                        provider_selection =
                            resolve_provider_selection(resolved, &host, None, None, false, true)?;
                    }
                    Err(error) => return Err(failure(error)),
                }
            }

            if provider_auth_validation.is_none()
                && report.required_input.is_empty()
                && provider_selection.authorization.is_some()
            {
                if interactive_selection
                    && provider_selection
                        .authorization
                        .as_ref()
                        .and_then(ProviderBindingAuthorization::auth_source)
                        .is_none()
                    && let Some(auth_source_name) = provider_selection.auth_source_name.clone()
                {
                    let descriptor = prompt_provider_auth_descriptor(&auth_source_name)?;
                    host.config
                        .provider_auth
                        .insert(auth_source_name.clone(), descriptor.clone());
                    pending_provider_auth = Some((auth_source_name.clone(), descriptor));
                    report.mutation_planned = true;
                    report.planned_actions.push(format!(
                        "save provider authentication descriptor reference '{auth_source_name}' for Host '{}'",
                        host.alias
                    ));
                    provider_selection =
                        resolve_provider_selection(resolved, &host, None, None, false, true)?;
                }
                add_setup_required_inputs(&mut report, &provider_selection, provider_auth_setup);
                if report.required_input.is_empty()
                    && pending_provider_secret_authorization.is_none()
                    && let Some(authorization) = provider_selection.authorization.as_ref()
                {
                    pending_provider_binding_authorization = Some(authorization.clone());
                    report.mutation_planned = true;
                    report.planned_actions.push(format!(
                        "authorize provider binding '{}/{}' on Host '{}'",
                        authorization.requested_provider_alias(),
                        authorization.requested_model_alias(),
                        host.alias
                    ));
                }
            }
        }
    }

    if !command.dry_run
        && !interactive_selection
        && report.required_input.iter().any(|input| {
            input.component == "provider-auth"
                && input.input_kind == "provider_secret_source_descriptor"
        })
    {
        return Err(failure(provider_secret_setup_error(
            ErrorCode::ProviderSecretSourceRequired,
            "provider authentication requires a host-resolved Secret Source descriptor",
        )));
    }

    let mut first_ssh_discovery = None;

    let mut prompted_for_consent = false;
    let mut verification_cache_updates = Vec::new();
    let mut native_invalidation_action = None;
    if !command.dry_run && report.required_input.is_empty() && report.mutation_planned {
        if !command.yes && !trusted_consent && (command.no_input || !io::stdin().is_terminal()) {
            let consent_recovery_command = setup_consent_recovery_command(
                &command,
                config.flag_profile,
                &report.setup_mode,
                &daemon_path_overrides,
                first_ssh_trust,
            );
            return Err(failure(SatelleError::setup_consent_required(
                &report.planned_actions,
                &consent_recovery_command,
            )));
        }

        if !json {
            print_setup_human(&report);
        }
        if !command.yes && !trusted_consent {
            prompted_for_consent = true;
            let _color_enabled = style.color_enabled();
            cliclack::intro(format!("{PRODUCT_NAME} setup")).map_err(|source| {
                failure(SatelleError {
                    code: ErrorCode::InvalidUsage,
                    message: "could not start interactive setup prompt".to_string(),
                    recovery_command: Some("rerun with --yes or --dry-run".to_string()),
                    source_detail: Some(source.to_string()),
                    details: BTreeMap::new(),
                })
            })?;
            let confirmed = cliclack::confirm("Apply these setup mutations?")
                .initial_value(false)
                .interact()
                .map_err(|source| {
                    failure(setup_interaction_error(
                        "could not read setup confirmation",
                        source,
                    ))
                })?;
            if !confirmed {
                return finish_cancelled_setup(&mut report, json);
            }
        }

        if first_ssh_trust {
            let discovery =
                inspect_first_ssh_host_during_setup(&command, true, &daemon_path_overrides, &host)?;
            let action = format!(
                "trust observed Host Identity '{}' for Host '{}'",
                discovery.identity, host.alias
            );
            if !report.planned_actions.contains(&action) {
                report.planned_actions.push(action);
            }
            if desktop_setup {
                desktop_selection = resolve_setup_desktop_selection(
                    &discovery.sessions,
                    &host.config,
                    interactive_selection,
                    Some(&discovery.authenticated_user),
                )
                .map_err(failure)?;
                if let Some(selection) = &desktop_selection {
                    let action = selection.action(&host.alias);
                    if !report.planned_actions.contains(&action) {
                        report.planned_actions.push(action);
                    }
                }
            }
            first_ssh_discovery = Some(discovery);
        }

        if native_readiness_invalidation_planned {
            // The configured Host still identifies the old readiness key here. Invalidate
            // after consent but before any setup write changes that identity.
            let invalidation_request = SetupVerificationRequest::new(
                provider_selection.requested_model_alias.clone(),
                provider_selection.requested_provider_alias.clone(),
                provider_selection.model_alias_from_project,
                provider_selection.provider_alias_from_project,
                provider_selection.experimental_provider_computer_use,
            )
            .map_err(|message| failure(SatelleError::invalid_usage(message)))?;
            let invalidated =
                match transport_for(&host)?.invalidate_native_readiness(&invalidation_request) {
                    Ok(invalidated) => invalidated,
                    Err(error) if command.verify => {
                        ensure_exact_setup_verification_recovery(&mut report, &host.alias);
                        if let Some(recovery) = error.recovery_command.as_ref()
                            && !report.recovery_commands.contains(recovery)
                        {
                            report.recovery_commands.push(recovery.clone());
                        }
                        report.status = "failed".to_string();
                        report.verification = Some(SetupVerification {
                            status: "failed".to_string(),
                            planned_checks: verification_checks.clone(),
                            result: None,
                            cache_updates: verification_cache_updates,
                        });
                        return Err(failure(SatelleError::setup_verification_failed(&report)));
                    }
                    Err(error) => return Err(failure(error)),
                };
            let cache_update = format!("invalidated_native_readiness_results:{invalidated}");
            verification_cache_updates.push(cache_update.clone());
            native_invalidation_action = Some(cache_update);
        }

        if let Some(discovery) = first_ssh_discovery.as_mut() {
            discovery.finalize_after_binding().map_err(failure)?;
            persist_host_identity(&user_config_path, &host.alias, &discovery.identity)
                .map_err(failure)?;
            host.config.expected_host_id = Some(discovery.identity.clone());
            transport =
                setup_transport_if_required(host_setup_required, || transport_for_setup(&host))?;
        }
        let mut persisted_desktop_action = None;
        let mut persisted_provider_auth_action = None;
        if report.required_input.is_empty() {
            if let Some(selection) = &desktop_selection {
                persist_desktop_selection(
                    &user_config_path,
                    &host.alias,
                    &selection.desktop_user,
                    Some(&selection.preference),
                )
                .map_err(failure)?;
                host.config.desktop_user = Some(selection.desktop_user.clone());
                host.config.desktop_session_preference = Some(selection.preference.clone());
                host.config.desktop_session_native_selector = None;
                persisted_desktop_action = Some(selection.action(&host.alias));
            }
            report = run_host_setup_then_follow_up(
                || {
                    if tailscale_serve_setup {
                        tailscale_serve::configure(
                            &host.alias,
                            &host.config,
                            &daemon_path_overrides,
                            false,
                            &setup_mode,
                        )
                        .map_err(failure)
                    } else {
                        run_host_setup_if_required(
                            host_setup_required,
                            || {
                                report.dry_run = false;
                                report
                            },
                            || {
                                transport
                                    .as_ref()
                                    .expect("Host-owned setup transport is present")
                                    .setup(
                                        false,
                                        setup_mode_selection,
                                        host_setup_components,
                                        daemon_path_overrides,
                                    )
                            },
                        )
                        .map_err(failure)
                    }
                },
                |report| {
                    if let Some(authorization) = pending_provider_secret_authorization.take() {
                        // Build the provider client only after Host setup has installed
                        // every prerequisite needed by live readiness validation.
                        let provider_transport = if host.config.transport
                            == satelle_core::TransportKind::Ssh
                        {
                            transport_for_with_ssh_bootstrap(&host, Some(SshBootstrapScope::Admin))?
                        } else {
                            transport_for(&host)?
                        };
                        let response = provision_provider_secret(
                            provider_transport.as_ref(),
                            &authorization,
                            &host.alias,
                            &command,
                            &format,
                        )?;
                        provider_secret_setup_completed = true;
                        report.secret_provisioned = response.provisioned();
                        report.validation_status =
                            response.validation_status().as_str().to_string();
                        report.readiness_summary.provider_auth =
                            response.validation_status().as_str().to_string();
                        report.applied_actions.push(format!(
                            "provisioned and authorized {} provider authentication on Host '{}'",
                            response.destination_kind(),
                            host.alias,
                        ));
                        report.mutated = true;
                        report.changed = true;
                        report.status = "applied".to_string();
                    }
                    Ok(())
                },
            )?;
        }

        if provider_auth_setup
            && report.required_input.is_empty()
            && provider_auth_validation.is_none()
            && !provider_secret_setup_completed
            && let (Some(model_alias), Some(provider_alias)) = (
                provider_selection.requested_model_alias.as_deref(),
                provider_selection.requested_provider_alias.as_deref(),
            )
        {
            let provider_transport = if host.config.transport == satelle_core::TransportKind::Ssh {
                transport_for_with_ssh_bootstrap(&host, Some(SshBootstrapScope::Admin))?
            } else {
                transport_for(&host)?
            };
            let pending_authorization = match provider_transport.validate_provider_descriptor(
                model_alias,
                provider_alias,
                provider_selection.model_alias_from_project,
                provider_selection.provider_alias_from_project,
                satelle_core::ProviderAuthValidationMode::Cached,
                provider_selection.experimental_provider_computer_use,
            ) {
                Ok(validation)
                    if validation.validation.outcome()
                        == satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret =>
                {
                    let authorization = provider_selection
                        .authorization
                        .as_ref()
                        .ok_or_else(|| {
                            failure(provider_secret_setup_error(
                                ErrorCode::ProviderSecretSourceRequired,
                                "provider authentication requires a host-resolved Secret Source descriptor",
                            ))
                        })?
                        .clone();
                    ensure_file_provider_secret_source(&authorization)?;
                    let response = provision_provider_secret(
                        provider_transport.as_ref(),
                        &authorization,
                        &host.alias,
                        &command,
                        &format,
                    )?;
                    provider_secret_setup_completed = true;
                    report.secret_provisioned = response.provisioned();
                    report.validation_status = response.validation_status().as_str().to_string();
                    report.readiness_summary.provider_auth =
                        response.validation_status().as_str().to_string();
                    report.applied_actions.push(format!(
                        "provisioned and authorized {} provider authentication on Host '{}'",
                        response.destination_kind(),
                        host.alias,
                    ));
                    report.mutated = true;
                    report.changed = true;
                    report.status = "applied".to_string();
                    None
                }
                Ok(validation) => {
                    provider_auth_validation = accept_setup_provider_auth_validation(
                        &mut report,
                        &provider_selection,
                        validation,
                    )?;
                    if provider_auth_validation.is_none() {
                        pending_provider_binding_authorization.as_ref()
                    } else {
                        None
                    }
                }
                Err(error) if error.code == ErrorCode::ModelProviderBindingMissing => {
                    let Some(authorization) = pending_provider_binding_authorization.as_ref()
                    else {
                        return Err(failure(error));
                    };
                    Some(authorization)
                }
                Err(error) => return Err(failure(error)),
            };
            if let Some(authorization) = pending_authorization {
                let authorization_requires_provisioning =
                    match provider_transport.authorize_provider_binding(authorization) {
                        Ok(_) => false,
                        Err(error)
                            if file_authorization_requires_provisioning(authorization, &error) =>
                        {
                            true
                        }
                        Err(error) => return Err(failure(error)),
                    };
                let validation = if authorization_requires_provisioning {
                    None
                } else {
                    let cached = provider_transport
                        .validate_provider_descriptor(
                            authorization.requested_model_alias(),
                            authorization.requested_provider_alias(),
                            provider_selection.model_alias_from_project,
                            provider_selection.provider_alias_from_project,
                            satelle_core::ProviderAuthValidationMode::Cached,
                            authorization.experimental_provider_computer_use(),
                        )
                        .map_err(failure)?;
                    if cached.validation.outcome()
                        == satelle_core::ProviderAuthValidationOutcome::ConfiguredDeferred
                    {
                        Some(
                            provider_transport
                                .validate_provider_descriptor(
                                    authorization.requested_model_alias(),
                                    authorization.requested_provider_alias(),
                                    provider_selection.model_alias_from_project,
                                    provider_selection.provider_alias_from_project,
                                    satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
                                    authorization.experimental_provider_computer_use(),
                                )
                                .map_err(failure)?,
                        )
                    } else {
                        Some(cached)
                    }
                };
                let provisioning_required = authorization_requires_provisioning
                    || validation.as_ref().is_some_and(|validation| {
                        validation.validation.outcome()
                            == satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret
                    });

                if provisioning_required {
                    ensure_file_provider_secret_source(authorization)?;
                    let response = provision_provider_secret(
                        provider_transport.as_ref(),
                        authorization,
                        &host.alias,
                        &command,
                        &format,
                    )?;
                    provider_secret_setup_completed = true;
                    report.secret_provisioned = response.provisioned();
                    report.validation_status = response.validation_status().as_str().to_string();
                    report.readiness_summary.provider_auth =
                        response.validation_status().as_str().to_string();
                    report.applied_actions.push(format!(
                        "provisioned and authorized {} provider authentication on Host '{}'",
                        response.destination_kind(),
                        host.alias,
                    ));
                    report.mutated = true;
                    report.changed = true;
                    report.status = "applied".to_string();
                } else {
                    let validation = accept_setup_provider_auth_validation(
                        &mut report,
                        &provider_selection,
                        validation.expect("non-provisioning authorization has cached validation"),
                    )?;
                    if validation.is_some() {
                        report.applied_actions.push(format!(
                            "authorize provider binding '{}/{}' on Host '{}'",
                            authorization.requested_provider_alias(),
                            authorization.requested_model_alias(),
                            host.alias
                        ));
                        report.mutated = true;
                        report.changed = true;
                        if report.status == "planned" {
                            report.status = "applied".to_string();
                        }
                    }
                    provider_auth_validation = validation;
                }
            }
        }

        if (provider_secret_setup_completed || provider_auth_validation.is_some())
            && let Some((auth_source_name, descriptor)) = &pending_provider_auth
        {
            if let Err(error) = persist_provider_auth_descriptor(
                &user_config_path,
                &host.alias,
                auth_source_name,
                descriptor,
            ) {
                return Err(failure(error));
            }
            host.config
                .provider_auth
                .insert(auth_source_name.clone(), descriptor.clone());
            persisted_provider_auth_action = Some(format!(
                "saved provider authentication descriptor reference '{auth_source_name}' for Host '{}'",
                host.alias
            ));
        }

        report.setup_components.clone_from(&setup_components);
        if let Some(decision) = &local_service_decision {
            apply_service_decision_to_report(&mut report, decision);
        }
        if !provider_secret_setup_completed
            && provider_auth_validation.is_none()
            && report.required_input.is_empty()
        {
            add_setup_required_inputs(&mut report, &provider_selection, provider_auth_setup);
        }
        if let Some(action) = persisted_provider_auth_action {
            report.applied_actions.push(action);
            report.mutated = true;
            report.changed = true;
            if report.status == "planned" {
                report.status = "applied".to_string();
            }
        }
        if let Some(action) = persisted_desktop_action {
            if !report.planned_actions.contains(&action) {
                report.planned_actions.push(action.clone());
            }
            report.applied_actions.push(action);
            report.mutated = true;
            report.changed = true;
            if report.status == "planned" {
                report.status = "applied".to_string();
            }
        }
        if let Some(action) = native_invalidation_action.take() {
            report.applied_actions.push(action);
            report.mutated = true;
            report.changed = true;
            if report.status == "planned" {
                report.status = "applied".to_string();
            }
        }
        if first_ssh_trust {
            report.applied_actions.insert(
                0,
                "discovered and explicitly trusted the reachable Host Identity".to_string(),
            );
            report.mutated = true;
            report.changed = true;
        }
    }

    // A Host setup response replaces the planning report. Restore the verification plan
    // before invalidation and live verification so all result paths retain the same contract.
    if command.verify {
        add_setup_verification_plan(&mut report, &verification_checks);
    }

    if command.verify && !command.dry_run && report.required_input.is_empty() {
        let verification_request = SetupVerificationRequest::new(
            provider_selection.requested_model_alias.clone(),
            provider_selection.requested_provider_alias.clone(),
            provider_selection.model_alias_from_project,
            provider_selection.provider_alias_from_project,
            provider_selection.experimental_provider_computer_use,
        )
        .map_err(|message| failure(SatelleError::invalid_usage(message)))?;
        let verification_response = match transport_for(&host)?.verify_setup(&verification_request)
        {
            Ok(response) => response,
            Err(error) => {
                ensure_exact_setup_verification_recovery(&mut report, &host.alias);
                if let Some(recovery) = error.recovery_command.as_ref()
                    && !report.recovery_commands.contains(recovery)
                {
                    report.recovery_commands.push(recovery.clone());
                }
                report.status = "failed".to_string();
                report.verification = Some(SetupVerification {
                    status: "failed".to_string(),
                    planned_checks: verification_checks.clone(),
                    result: None,
                    cache_updates: verification_cache_updates,
                });
                return Err(failure(SatelleError::setup_verification_failed(&report)));
            }
        };
        let mut verification_report = verification_response;
        let ready = verification_report.summary.ready;
        let manual_action_required = verification_report
            .findings
            .iter()
            .any(|finding| finding.fixability == DoctorFixability::ManualActionRequired);
        let verification_status = if ready {
            "passed"
        } else if manual_action_required {
            "manual_action_required"
        } else {
            "failed"
        };
        if !ready {
            let recovery = format!(
                "satelle setup --host {} --verify --no-input",
                shell_argument(&host.alias)
            );
            if !verification_report.recovery_commands.contains(&recovery) {
                verification_report.recovery_commands.insert(0, recovery);
            }
        }
        for recovery in verification_report.recovery_commands.iter().rev() {
            if !report.recovery_commands.contains(recovery) {
                report.recovery_commands.insert(0, recovery.clone());
            }
        }
        for cache_update in &verification_report.cache_updates {
            if !verification_cache_updates.contains(cache_update) {
                verification_cache_updates.push(cache_update.clone());
            }
        }
        if !ready {
            ensure_exact_setup_verification_recovery(&mut report, &host.alias);
        }
        report.native_computer_use_readiness =
            native_verification_status(&verification_report.findings).to_string();
        report.readiness_summary.native_computer_use = report.native_computer_use_readiness.clone();
        if verification_checks
            .iter()
            .any(|check| check == "provider_computer_use")
        {
            report.provider_smoke_test_status = verification_status.to_string();
            report.readiness_summary.provider_auth = if ready {
                "ready".to_string()
            } else {
                verification_status.to_string()
            };
        }
        report.verification = Some(SetupVerification::completed(
            verification_status,
            verification_checks.clone(),
            verification_report,
            verification_cache_updates,
        ));
        if !ready {
            report.status = verification_status.to_string();
            return Err(failure(SatelleError::setup_verification_failed(&report)));
        }
    }

    if prompted_for_consent && !json {
        cliclack::outro("Satelle setup produced a readiness plan").map_err(|source| {
            failure(SatelleError {
                code: ErrorCode::InvalidUsage,
                message: "could not finish interactive setup prompt".to_string(),
                recovery_command: Some("rerun with --no-input --yes or --dry-run".to_string()),
                source_detail: Some(source.to_string()),
                details: std::collections::BTreeMap::new(),
            })
        })?;
    }

    if json {
        let mut output = serde_json::to_value(&report)
            .map_err(|error| failure(SatelleError::invalid_usage(error.to_string())))?;
        if provider_auth_setup
            && !provider_secret_setup_completed
            && let Some(validation) = provider_auth_validation_json(
                &provider_selection,
                provider_auth_validation.as_ref(),
            )
        {
            output
                .as_object_mut()
                .expect("a Setup report serializes as an object")
                .insert("provider_auth_validation".to_string(), validation);
        }
        print_json(&output).map_err(failure)
    } else {
        print_setup_human(&report);
        Ok(())
    }
}

fn inspect_first_ssh_host_during_setup(
    command: &SetupCommand,
    consent_granted: bool,
    daemon_path_overrides: &DaemonPathOverrides,
    host: &SelectedHost,
) -> Result<SshHostDiscovery, CliFailure> {
    let noninteractive = command.no_input || !io::stdin().is_terminal();
    if noninteractive && (!command.no_input || !command.yes || command.expected_host_id.is_none()) {
        return Err(failure(SatelleError::invalid_usage(
            "noninteractive SSH Host trust requires --no-input --yes --expected-host-id <exact-id>",
        )));
    }
    if !noninteractive && !command.yes && !consent_granted {
        let confirmed = cliclack::confirm(format!(
            "Run the temporary SSH identity probe for Host '{}' at '{}'?",
            host.alias,
            host.config.address.as_deref().unwrap_or("not configured")
        ))
        .initial_value(false)
        .interact()
        .map_err(|source| {
            failure(setup_interaction_error(
                "could not read temporary SSH identity probe confirmation",
                source,
            ))
        })?;
        if !confirmed {
            return Err(failure(SatelleError::setup_consent_required(
                &["run the temporary SSH identity probe".to_string()],
                "rerun setup and approve the temporary SSH identity probe",
            )));
        }
    }
    let pending = discover_ssh_host(
        host,
        daemon_path_overrides,
        command.expected_host_id.as_deref(),
    )
    .map_err(failure)?;
    let observed_identity = pending.identity().to_string();
    HostIdentityRef::new(observed_identity.clone()).map_err(|_| {
        failure(SatelleError::remote_api_error(
            &host.alias,
            "invalid-daemon-response",
        ))
    })?;
    if command
        .expected_host_id
        .as_deref()
        .is_some_and(|expected| expected != observed_identity)
    {
        return Err(failure(SatelleError::host_identity_mismatch(&host.alias)));
    }
    if host.config.expected_host_id.as_deref() == Some(observed_identity.as_str()) {
        return pending.accept().map_err(failure);
    }

    if !noninteractive {
        println!("Host: {}", host.alias);
        println!(
            "Endpoint: {}",
            host.config.address.as_deref().unwrap_or("not configured")
        );
        println!("Observed Host Identity: {observed_identity}");
        println!(
            "Current expected Host Identity: {}",
            host.config
                .expected_host_id
                .as_deref()
                .unwrap_or("not pinned")
        );
        println!(
            "Desktop Binding: {}",
            host.config
                .desktop_user
                .as_deref()
                .unwrap_or("not configured")
        );
        let confirmed = cliclack::confirm(format!(
            "Trust exact observed Host Identity '{observed_identity}' for Host '{}'?",
            host.alias
        ))
        .initial_value(false)
        .interact()
        .map_err(|source| {
            failure(setup_interaction_error(
                "could not read exact Host Identity confirmation",
                source,
            ))
        })?;
        if !confirmed {
            return Err(failure(SatelleError::host_identity_mismatch(&host.alias)));
        }
    }

    pending.accept().map_err(failure)
}

fn accept_setup_provider_auth_validation(
    report: &mut SetupReport,
    provider_selection: &ProviderSelection,
    validation: transport::ProviderDescriptorValidationReport,
) -> Result<Option<transport::ProviderDescriptorValidationReport>, CliFailure> {
    use satelle_core::ProviderAuthValidationOutcome::{
        ConfiguredDeferred, MissingDescriptor, Resolved,
    };

    if provider_selection.auth_source_name.is_some()
        && provider_selection
            .authorization
            .as_ref()
            .and_then(ProviderBindingAuthorization::auth_source)
            .is_none()
    {
        add_missing_provider_descriptor_required_input(report, provider_selection);
        return Ok(None);
    }
    if let Some(authorization) = provider_selection.authorization.as_ref() {
        let current_binding = satelle_core::ResolvedProviderBinding::from_authorization(
            authorization.clone(),
            validation.resolved_binding.source(),
        );
        if current_binding.binding_digest() != validation.resolved_binding.binding_digest() {
            return Ok(None);
        }
    }

    let outcome = validation.validation.outcome();
    report.readiness_summary.provider_auth = outcome.as_str().to_string();
    report.descriptor_configured = provider_selection
        .authorization
        .as_ref()
        .and_then(ProviderBindingAuthorization::auth_source)
        .is_some();
    report.validation_status = outcome.as_str().to_string();
    if matches!(outcome, ConfiguredDeferred | Resolved) {
        return Ok(Some(validation));
    }
    if outcome == MissingDescriptor {
        add_missing_provider_descriptor_required_input(report, provider_selection);
        return Ok(None);
    }
    Err(failure(SatelleError::config_error(
        format!(
            "the Host rejected the provider authentication descriptor: {}",
            outcome.as_str()
        ),
        None,
    )))
}

fn native_verification_status(findings: &[satelle_core::DoctorFinding]) -> &'static str {
    let mut observed = false;
    let mut blocked = false;
    for finding in findings
        .iter()
        .filter(|finding| finding.scope == "computer-use")
    {
        observed = true;
        if finding.fixability == DoctorFixability::ManualActionRequired {
            return "manual_action_required";
        }
        blocked |= finding.readiness_impact != "ready";
    }
    if !observed {
        "not_verified"
    } else if blocked {
        "failed"
    } else {
        "ready"
    }
}

#[cfg(test)]
mod native_verification_status_tests {
    use super::*;

    fn finding(
        scope: &str,
        impact: &str,
        fixability: DoctorFixability,
    ) -> satelle_core::DoctorFinding {
        satelle_core::DoctorFinding {
            finding_id: format!("{scope}.{impact}"),
            scope: scope.to_string(),
            severity: "info".to_string(),
            fixability,
            readiness_impact: impact.to_string(),
            summary: "fixture".to_string(),
            evidence: Vec::new(),
            recovery_command: None,
        }
    }

    #[test]
    fn provider_failure_does_not_downgrade_native_readiness() {
        let findings = vec![
            finding("computer-use", "ready", DoctorFixability::Informational),
            finding("provider", "blocked", DoctorFixability::Blocked),
        ];

        assert_eq!(native_verification_status(&findings), "ready");
    }
}

fn add_missing_provider_descriptor_required_input(
    report: &mut SetupReport,
    provider_selection: &ProviderSelection,
) {
    let Some(auth_source_name) = provider_selection.auth_source_name.as_deref() else {
        return;
    };
    report.status = "input_required".to_string();
    report.readiness_summary.provider_auth = "missing_descriptor".to_string();
    report.required_input.push(SetupRequiredInput {
        component: "provider-auth".to_string(),
        input_kind: "provider_secret_source_descriptor".to_string(),
        reason: format!(
            "the effective provider binding requires host-resolved Secret Source descriptor '{auth_source_name}'; raw provider secrets are not accepted through setup"
        ),
        recovery_command: format!(
            "add [hosts.<alias>.provider_auth.{auth_source_name}] to user-level config, then rerun satelle setup --no-input --json"
        ),
    });
    report.recovery_commands.push(
        "add a host-resolved provider_auth Secret Source descriptor to user-level config"
            .to_string(),
    );
}

fn add_setup_required_inputs(
    report: &mut SetupReport,
    provider_selection: &ProviderSelection,
    provider_auth_setup: bool,
) {
    if !provider_auth_setup {
        return;
    }
    let Some(authorization) = provider_selection.authorization.as_ref() else {
        report.readiness_summary.provider_auth = "host_owned".to_string();
        return;
    };
    let Some(auth_source_name) = provider_selection.auth_source_name.as_deref() else {
        report.readiness_summary.provider_auth = "not_required".to_string();
        return;
    };
    if authorization.auth_source().is_some() {
        report.readiness_summary.provider_auth = "configured_deferred".to_string();
        report.descriptor_configured = true;
        report.validation_status = "deferred".to_string();
        return;
    }

    report.status = "input_required".to_string();
    report.readiness_summary.provider_auth = "missing_descriptor".to_string();
    report.required_input.push(SetupRequiredInput {
        component: "provider-auth".to_string(),
        input_kind: "provider_secret_source_descriptor".to_string(),
        reason: format!(
            "the effective provider binding requires host-resolved Secret Source descriptor '{auth_source_name}'; raw provider secrets are not accepted through setup"
        ),
        recovery_command: format!(
            "add [hosts.<alias>.provider_auth.{auth_source_name}] to user-level config, then rerun satelle setup --no-input --json"
        ),
    });
    report.recovery_commands.push(
        "add a host-resolved provider_auth Secret Source descriptor to user-level config"
            .to_string(),
    );
}

fn provider_auth_validation_json(
    provider_selection: &ProviderSelection,
    validation: Option<&transport::ProviderDescriptorValidationReport>,
) -> Option<serde_json::Value> {
    if let Some(validation) = validation {
        return Some(json!({
            "resolved_codex_model": validation.resolved_binding.model(),
            "resolved_model_provider": validation.resolved_binding.model_provider(),
            "provider_binding_source": validation.resolved_binding.source().as_str(),
            "auth_source_name": provider_selection.auth_source_name,
            "model_alias_from_project": provider_selection.model_alias_from_project,
            "provider_alias_from_project": provider_selection.provider_alias_from_project,
            "outcome": validation.validation.outcome().as_str(),
            "source": validation.validation.observation_source().as_str(),
        }));
    }
    let authorization = provider_selection.authorization.as_ref()?;
    let auth_source_name = provider_selection.auth_source_name.as_deref()?;
    Some(json!({
        "resolved_codex_model": null,
        "resolved_model_provider": null,
        "provider_binding_source": null,
        "auth_source_name": auth_source_name,
        "model_alias_from_project": provider_selection.model_alias_from_project,
        "provider_alias_from_project": provider_selection.provider_alias_from_project,
        "outcome": if authorization.auth_source().is_some() {
            "configured_deferred"
        } else {
            "missing_descriptor"
        },
        "source": "deferred",
    }))
}

fn prompt_provider_auth_descriptor(
    auth_source_name: &str,
) -> Result<ProviderSecretSource, CliFailure> {
    let kind = cliclack::select(format!(
        "How should Host resolve provider authentication '{auth_source_name}'?"
    ))
    .item(
        "environment",
        "Environment variable",
        "Host reads a named environment variable",
    )
    .item("file", "File", "Host reads an absolute secret file path")
    .interact()
    .map_err(|source| {
        failure(SatelleError::invalid_usage(format!(
            "could not read provider authentication descriptor kind: {source}"
        )))
    })?;
    match kind {
        "environment" => {
            let variable: String = cliclack::input("Environment variable name")
                .interact()
                .map_err(|source| {
                    failure(SatelleError::invalid_usage(format!(
                        "could not read provider authentication environment variable name: {source}"
                    )))
                })?;
            let variable = variable.trim();
            if variable.is_empty() {
                return Err(failure(SatelleError::input_required(
                    "provider authentication environment variable name is required",
                )));
            }
            Ok(ProviderSecretSource::Environment {
                variable: variable.to_string(),
            })
        }
        "file" => {
            let path: String = cliclack::input("Absolute provider secret file path")
                .interact()
                .map_err(|source| {
                    failure(SatelleError::invalid_usage(format!(
                        "could not read provider authentication file path: {source}"
                    )))
                })?;
            let path = PathBuf::from(path.trim());
            if path.as_os_str().is_empty() {
                return Err(failure(SatelleError::invalid_usage(
                    "provider authentication file path is required",
                )));
            }
            Ok(ProviderSecretSource::File { path })
        }
        _ => unreachable!("provider authentication prompt exposes only supported descriptor kinds"),
    }
}

fn provider_secret_setup_error(code: ErrorCode, message: impl Into<String>) -> SatelleError {
    SatelleError {
        code,
        message: message.into(),
        recovery_command: Some(
            "satelle setup --host <host-alias> --component provider-auth".to_string(),
        ),
        source_detail: None,
        details: BTreeMap::new(),
    }
}

fn ensure_file_provider_secret_source(
    authorization: &ProviderBindingAuthorization,
) -> Result<(), CliFailure> {
    match authorization.auth_source() {
        Some(ProviderSecretSource::File { .. }) => Ok(()),
        Some(_) => Err(failure(provider_secret_setup_error(
            ErrorCode::ProviderSecretProvisioningRequired,
            "interactive provider secret provisioning supports only File Secret Source descriptors",
        ))),
        None => Err(failure(provider_secret_setup_error(
            ErrorCode::ProviderSecretSourceRequired,
            "provider authentication requires a host-resolved Secret Source descriptor",
        ))),
    }
}

fn file_authorization_requires_provisioning(
    authorization: &ProviderBindingAuthorization,
    error: &SatelleError,
) -> bool {
    matches!(
        authorization.auth_source(),
        Some(ProviderSecretSource::File { .. })
    ) && error.code == ErrorCode::ProviderSecretResolutionFailed
}

fn plan_provider_secret_provisioning(
    report: &mut SetupReport,
    provider_selection: &ProviderSelection,
    host_alias: &str,
) -> Result<ProviderBindingAuthorization, CliFailure> {
    let authorization = provider_selection
        .authorization
        .as_ref()
        .ok_or_else(|| {
            failure(provider_secret_setup_error(
                ErrorCode::ProviderSecretSourceRequired,
                "provider authentication requires a host-resolved Secret Source descriptor",
            ))
        })?
        .clone();
    ensure_file_provider_secret_source(&authorization)?;
    report.descriptor_configured = true;
    report.secret_provisioned = false;
    report.validation_status = "provisioning_required".to_string();
    report.readiness_summary.provider_auth = "provisioning_required".to_string();
    report.mutation_planned = true;
    report.planned_actions.push(format!(
        "preview and provision the File provider secret destination on Host '{host_alias}'"
    ));
    Ok(authorization)
}

fn provision_provider_secret(
    provider_transport: &dyn transport::TransportClient,
    authorization: &ProviderBindingAuthorization,
    host_alias: &str,
    command: &SetupCommand,
    format: &OutputFormat,
) -> Result<satelle_transport::ProviderSecretProvisioningResponse, CliFailure> {
    ensure_file_provider_secret_source(authorization)?;
    let destination_descriptor = match authorization.auth_source() {
        Some(ProviderSecretSource::File { path }) => format!("file:{}", path.display()),
        _ => unreachable!("provider secret provisioning accepts only File destinations"),
    };

    let interaction_available = !command.no_input
        && !format.is_json()
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && io::stderr().is_terminal();
    if !interaction_available {
        return Err(failure(provider_secret_setup_error(
            ErrorCode::ProviderSecretProvisioningRequired,
            "provider secret provisioning requires an immediate confirmation in an interactive human terminal",
        )));
    }

    // Prove that this client is authenticated to the selected, pinned Host before
    // prompting. The later preview and provision calls use the same client.
    provider_transport.host_status().map_err(failure)?;
    println!("Target Host: {host_alias}");
    println!(
        "Provider alias: {}",
        authorization.requested_provider_alias()
    );
    println!("Provider Secret Source kind: file");
    println!("Exact destination descriptor: {destination_descriptor}");

    let idempotency_key = format!(
        "provider-secret-provision-{}",
        satelle_transport::RequestId::new()
    );
    let preview_metadata =
        satelle_transport::ProviderSecretProvisioningMetadata::new(authorization.clone(), true);
    let preview = provider_transport
        .preview_provider_secret_provisioning(&preview_metadata, &idempotency_key)
        .map_err(failure)?;
    println!(
        "Provider secret destination kind: {}",
        preview.destination_kind()
    );
    println!(
        "Provider secret persistence location class: {}",
        preview.persistence_location_class()
    );
    println!(
        "Provider secret overwrite behavior: {}",
        preview.overwrite_behavior()
    );

    // Read the secret only after the authenticated preview fixes its exact
    // destination. Keep it zeroized while asking for the dedicated,
    // immediately-pre-transmission confirmation.
    let secret = Zeroizing::new(
        cliclack::password("Provider secret")
            .interact()
            .map_err(|source| {
                failure(setup_interaction_error(
                    "could not read provider secret",
                    source,
                ))
            })?
            .into_bytes(),
    );
    let confirmed =
        cliclack::confirm("Provision or replace the provider secret at this exact destination?")
            .initial_value(false)
            .interact()
            .map_err(|source| {
                failure(setup_interaction_error(
                    "could not read provider secret provisioning confirmation",
                    source,
                ))
            })?;
    if !confirmed {
        return Err(failure(provider_secret_setup_error(
            ErrorCode::ProviderSecretProvisioningRequired,
            "provider secret provisioning or replacement was not authorized",
        )));
    }

    // No flag or profile can set this transport bit. The raw material is sent
    // by the next operation only after this dedicated confirmation.
    let overwrite_authorized = confirmed;
    let metadata = satelle_transport::ProviderSecretProvisioningMetadata::new(
        authorization.clone(),
        overwrite_authorized,
    );
    provider_transport
        .provision_provider_secret(&preview, &metadata, secret, &idempotency_key)
        .map_err(failure)
}

fn daemon_path_overrides(command: &SetupCommand, host_config: &HostConfig) -> DaemonPathOverrides {
    let mut sources = BTreeMap::new();
    let home = select_daemon_path_override(
        "SATELLE_HOME",
        command.daemon_home.as_ref(),
        host_config.daemon_home.as_ref(),
        &mut sources,
    );
    let config_file = select_daemon_path_override(
        "SATELLE_CONFIG_FILE",
        command.daemon_config_file.as_ref(),
        host_config.daemon_config_file.as_ref(),
        &mut sources,
    );
    let state_dir = select_daemon_path_override(
        "SATELLE_STATE_DIR",
        command.daemon_state_dir.as_ref(),
        host_config.daemon_state_dir.as_ref(),
        &mut sources,
    );
    let cache_dir = select_daemon_path_override(
        "SATELLE_CACHE_DIR",
        command.daemon_cache_dir.as_ref(),
        host_config.daemon_cache_dir.as_ref(),
        &mut sources,
    );
    let log_dir = select_daemon_path_override(
        "SATELLE_LOG_DIR",
        command.daemon_log_dir.as_ref(),
        host_config.daemon_log_dir.as_ref(),
        &mut sources,
    );

    DaemonPathOverrides {
        home,
        config_file,
        state_dir,
        cache_dir,
        log_dir,
        sources,
    }
}

fn select_daemon_path_override(
    environment_variable: &'static str,
    flag_value: Option<&PathBuf>,
    config_value: Option<&PathBuf>,
    sources: &mut BTreeMap<String, String>,
) -> Option<PathBuf> {
    if let Some(value) = flag_value {
        sources.insert(environment_variable.to_string(), "setup_flag".to_string());
        return Some(value.clone());
    }

    if let Some(value) = config_value {
        sources.insert(environment_variable.to_string(), "user_config".to_string());
        return Some(value.clone());
    }

    None
}

fn setup_components(components: &[SetupComponent]) -> Result<Vec<String>, SatelleError> {
    if components.is_empty() {
        return Ok(vec!["all".to_string()]);
    }
    if components.len() > 1
        && components
            .iter()
            .any(|component| component == &SetupComponent::All)
    {
        return Err(SatelleError::component_selection_conflict());
    }

    Ok(components
        .iter()
        .map(SetupComponent::as_str)
        .map(str::to_string)
        .collect())
}

fn setup_mode(
    command: &SetupCommand,
    host_config: &HostConfig,
) -> Result<SetupModeSelection, SatelleError> {
    if command.on_demand && command.persistent {
        return Err(SatelleError::invalid_usage(
            "--on-demand and --persistent cannot be combined",
        ));
    }
    if command.on_demand {
        return Ok(SetupModeSelection::new(
            SetupMode::OnDemand,
            SetupModeSource::SetupFlag,
        ));
    }
    if command.persistent {
        return Ok(SetupModeSelection::new(
            SetupMode::Persistent,
            SetupModeSource::SetupFlag,
        ));
    }

    Ok(host_config.setup_mode.map_or_else(
        || SetupModeSelection::new(SetupMode::OnDemand, SetupModeSource::Default),
        |mode| SetupModeSelection::new(mode, SetupModeSource::UserConfig),
    ))
}

fn apply_service_decision_to_report(
    report: &mut SetupReport,
    decision: &PersistentServiceDecision,
) {
    report.setup_mode = decision.setup_mode.as_str().to_string();
    report.service_persistent = decision.service_persistent;
    report.service_scope.clone_from(&decision.service_scope);
    report.fallback_reason.clone_from(&decision.fallback_reason);
}

fn current_daemon_service_platform() -> DaemonServicePlatform {
    #[cfg(target_os = "macos")]
    {
        DaemonServicePlatform::Macos
    }
    #[cfg(target_os = "windows")]
    {
        DaemonServicePlatform::Windows
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        DaemonServicePlatform::Linux
    }
}

fn setup_consent_recovery_command(
    command: &SetupCommand,
    profile: Option<&str>,
    setup_mode: &str,
    daemon_path_overrides: &DaemonPathOverrides,
    first_ssh_trust: bool,
) -> String {
    let mut arguments = vec!["satelle".to_string()];
    if let Some(profile) = profile {
        arguments.extend(["--profile".to_string(), shell_argument(profile)]);
    }
    arguments.push("setup".to_string());
    if let Some(host) = command.host.as_deref() {
        arguments.extend(["--host".to_string(), shell_argument(host)]);
    }
    arguments.push(if setup_mode == "persistent" {
        "--persistent".to_string()
    } else {
        "--on-demand".to_string()
    });
    for component in &command.component {
        arguments.extend(["--component".to_string(), component.as_str().to_string()]);
    }
    for path_override in daemon_path_overrides.entries() {
        let flag = match path_override.environment_variable.as_str() {
            "SATELLE_HOME" => "--daemon-home",
            "SATELLE_CONFIG_FILE" => "--daemon-config-file",
            "SATELLE_STATE_DIR" => "--daemon-state-dir",
            "SATELLE_CACHE_DIR" => "--daemon-cache-dir",
            "SATELLE_LOG_DIR" => "--daemon-log-dir",
            _ => continue,
        };
        arguments.extend([flag.to_string(), shell_argument(&path_override.value)]);
    }
    if let Some(expected_host_id) = command.expected_host_id.as_deref() {
        arguments.extend([
            "--expected-host-id".to_string(),
            shell_argument(expected_host_id),
        ]);
    }
    if command.verify {
        arguments.push("--verify".to_string());
    }
    if first_ssh_trust && command.expected_host_id.is_none() {
        // The first trust prompt must remain interactive unless the operator
        // supplied the exact identity that noninteractive recovery can pin.
        return arguments.join(" ");
    }
    arguments.extend([
        "--no-input".to_string(),
        "--json".to_string(),
        "--yes".to_string(),
    ]);
    arguments.join(" ")
}

#[cfg(test)]
mod setup_consent_recovery_tests {
    use super::*;

    #[test]
    fn first_ssh_trust_recovery_preserves_the_expected_host_identity() {
        let cli = Cli::try_parse_from([
            "satelle",
            "setup",
            "--host",
            "remote",
            "--expected-host-id",
            "host-expected",
        ])
        .expect("parse SSH setup command");
        let Command::Setup(command) = cli.command else {
            panic!("expected setup command");
        };

        assert_eq!(
            setup_consent_recovery_command(
                &command,
                None,
                "on_demand",
                &DaemonPathOverrides::default(),
                true,
            ),
            "satelle setup --host remote --on-demand --expected-host-id host-expected --no-input --json --yes"
        );
    }

    #[test]
    fn first_ssh_trust_recovery_without_an_expected_identity_remains_interactive() {
        let cli = Cli::try_parse_from(["satelle", "setup", "--host", "remote"])
            .expect("parse SSH setup command");
        let Command::Setup(command) = cli.command else {
            panic!("expected setup command");
        };

        assert_eq!(
            setup_consent_recovery_command(
                &command,
                None,
                "on_demand",
                &DaemonPathOverrides::default(),
                true,
            ),
            "satelle setup --host remote --on-demand"
        );
    }
}

fn shell_argument(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_./:".contains(character))
    {
        return value.to_string();
    }

    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_repair(
    command: RepairCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let host = config.resolve_host(command.host.as_deref())?;
    let mut mutation_consent = command.yes;
    let mut report = transport::plan_repair_upgrades(
        &host,
        command.run.as_deref(),
        mutation_consent && !command.dry_run,
    )
    .map_err(failure)?;
    if command.dry_run {
        report = report.into_dry_run();
        if format.is_json() {
            print_json(&report).map_err(failure)?;
        } else {
            print!("{}", host_update::render_repair_upgrade_plan(&report));
        }
        return Ok(());
    }

    if !report.requires_mutation() {
        if format.is_json() {
            print_json(&report).map_err(failure)?;
        } else {
            print!("{}", host_update::render_repair_upgrade_plan(&report));
        }
        return Ok(());
    }

    if !format.is_json() {
        print!("{}", host_update::render_repair_upgrade_plan(&report));
    }
    let noninteractive = command.no_input || format.is_json() || !io::stdin().is_terminal();
    if noninteractive && !command.yes {
        let recovery_command = match command.run.as_deref() {
            Some(run_id) => format!(
                "satelle repair --host {} --run {} --no-input --yes --json",
                shell_argument(&host.alias),
                shell_argument(run_id)
            ),
            None => format!(
                "satelle repair --host {} --no-input --yes --json",
                shell_argument(&host.alias)
            ),
        };
        return Err(failure(SatelleError::setup_consent_required(
            &report.planned_actions,
            recovery_command,
        )));
    }
    if !command.yes {
        let confirmed = cliclack::confirm("Apply these repair mutations?")
            .initial_value(false)
            .interact()
            .map_err(|source| {
                failure(setup_interaction_error(
                    "could not read repair confirmation",
                    source,
                ))
            })?;
        if !confirmed {
            report = report.cancelled();
            if format.is_json() {
                print_json(&report).map_err(failure)?;
            } else {
                println!("No changes applied.");
            }
            return Ok(());
        }
        mutation_consent = true;
    }

    // Consent applies to one exact live plan. Re-read every Host-owned input
    // immediately before the first durable maintenance transition.
    let revalidated =
        transport::plan_repair_upgrades(&host, command.run.as_deref(), mutation_consent)
            .map_err(failure)?;
    if revalidated != report {
        return Err(failure(SatelleError::state_conflict()));
    }
    report = transport::apply_repair_upgrades(&host, revalidated, command.run.as_deref())
        .map_err(failure)?;
    if format.is_json() {
        print_json(&report).map_err(failure)
    } else {
        print!("{}", host_update::render_repair_upgrade_result(&report));
        Ok(())
    }
}

fn run_doctor(
    command: DoctorCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let scope_selection = validate_doctor_scope(&command.scope)?;
    let timeout = match command
        .timeout
        .as_deref()
        .map(parse_positive_duration_ms)
        .transpose()
    {
        Ok(timeout) => timeout.map(std::time::Duration::from_millis),
        Err(error) => return Err(failure(error)),
    };
    if timeout.is_some() && (!command.refresh || !scope_selection.supports_refresh()) {
        return Err(failure(
            SatelleError::doctor_refresh_timeout_without_refresh(),
        ));
    }
    if command.refresh && !scope_selection.supports_refresh() {
        return Err(failure(SatelleError::doctor_refresh_scope_required()));
    }

    let resolved_config = config.load()?;
    let host = SelectedHost::from(
        resolved_config
            .resolve_host(command.host.as_deref())
            .map_err(failure)?,
    );
    let options = DoctorOptions::new(command.refresh, timeout)
        .map_err(failure)?
        .with_serial_probes(command.serial_probes);
    let transport_probe = transport_doctor_probe(&scope_selection, &host.config);
    let transport_only =
        prepare_transport_only_doctor(&host.config, &scope_selection, options).map_err(failure)?;
    if let Some(prepared) = transport_only {
        if command.events {
            print_doctor_started_event(&host.alias, &scope_selection).map_err(failure)?;
        }
        let outcome = execute_transport_only_doctor(
            &host.alias,
            &scope_selection,
            &transport_probe,
            prepared,
        )
        .map_err(DoctorExecutionFailure::from);
        return finish_doctor_outcome(outcome, command.events, json, &host.alias, &scope_selection);
    }
    let transport = transport_for(&host)?;
    let provider_intent = doctor_provider_intent(
        resolved_config,
        &host.config,
        command.refresh,
        options.probe_timeout(),
    )
    .map_err(failure)?;
    if command.events {
        print_doctor_started_event(&host.alias, &scope_selection).map_err(failure)?;
    }
    let outcome = transport.doctor(
        &scope_selection,
        Arc::new(transport_probe),
        options,
        &provider_intent,
    );

    finish_doctor_outcome(outcome, command.events, json, &host.alias, &scope_selection)
}

fn finish_doctor_outcome(
    outcome: DoctorExecutionResult,
    events: bool,
    json: bool,
    target: &str,
    scope_selection: &DoctorScopeSelection,
) -> Result<(), CliFailure> {
    match outcome {
        Ok(report) => emit_doctor_report(report, events, json),
        Err(failed) if events => {
            print_doctor_failed_event(
                target,
                scope_selection,
                2,
                &failed.error,
                &failed.partial_probe_results,
            )
            .map_err(failure)?;
            Err(reported_failure(failed.error))
        }
        Err(failed) => Err(failure(failed.error)),
    }
}

fn emit_doctor_report(report: DoctorReport, events: bool, json: bool) -> Result<(), CliFailure> {
    let readiness_error = if report.summary.ready {
        None
    } else {
        Some(SatelleError::doctor_readiness_blockers_found(
            &report.recovery_commands,
        ))
    };

    if events {
        print_doctor_events(&report, readiness_error.as_ref()).map_err(failure)?;
        if let Some(error) = readiness_error {
            return Err(reported_failure(error));
        }
        Ok(())
    } else if json {
        print_json(&report).map_err(failure)?;
        if let Some(error) = readiness_error {
            return Err(failure(error));
        }
        Ok(())
    } else {
        println!("Host: {}", report.host);
        println!("Status: {}", report.status);
        println!("Ready: {}", report.summary.ready);
        println!("Scopes: {}", report.scopes.join(", "));
        for finding in report.findings {
            println!(
                "[{}] {} ({})",
                finding.severity, finding.summary, finding.fixability
            );
            for evidence in finding.evidence {
                println!("  evidence: {evidence}");
            }
        }
        if let Some(error) = readiness_error {
            return Err(failure(error));
        }
        Ok(())
    }
}

fn validate_doctor_scope(scopes: &[String]) -> Result<DoctorScopeSelection, CliFailure> {
    DoctorScopeSelection::parse(scopes).map_err(|error| {
        failure(match error {
            DoctorScopeSelectionError::UnsupportedScope(scope) => SatelleError::invalid_usage(
                format!(
                    "unsupported doctor scope '{scope}'; expected transport, codex, computer-use, provider, config, or all"
                ),
            ),
            DoctorScopeSelectionError::AllWithSpecificScopes(scopes) => {
                SatelleError::scope_selection_conflict(&scopes)
            }
        })
    })
}

fn parse_duration_ms(value: &str) -> Result<u64, SatelleError> {
    if let Some(ms) = value.strip_suffix("ms") {
        return parse_duration_component(ms, 1);
    }

    if let Some(seconds) = value.strip_suffix('s') {
        return parse_duration_component(seconds, 1_000);
    }

    if let Some(minutes) = value.strip_suffix('m') {
        return parse_duration_component(minutes, 60_000);
    }

    Err(SatelleError::invalid_usage(
        "duration values require an explicit unit such as 500ms, 30s, or 2m",
    ))
}

fn parse_positive_duration_ms(value: &str) -> Result<u64, SatelleError> {
    let duration = parse_duration_ms(value)?;
    if duration == 0 {
        return Err(SatelleError::invalid_usage(
            "duration must use a positive number",
        ));
    }
    Ok(duration)
}

fn parse_duration_component(value: &str, multiplier: u64) -> Result<u64, SatelleError> {
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .ok_or_else(|| SatelleError::invalid_usage("duration must use a positive number"))
}

fn print_doctor_events(
    report: &DoctorReport,
    terminal_error: Option<&SatelleError>,
) -> Result<(), SatelleError> {
    for record in doctor_event_records(report, terminal_error) {
        println!(
            "{}",
            serde_json::to_string(&record).map_err(|source| SatelleError {
                code: ErrorCode::InvalidUsage,
                message: "could not serialize doctor event".to_string(),
                recovery_command: None,
                source_detail: Some(source.to_string()),
                details: std::collections::BTreeMap::new(),
            })?
        );
    }

    Ok(())
}

fn doctor_event_records(
    report: &DoctorReport,
    terminal_error: Option<&SatelleError>,
) -> Vec<DoctorEventRecord> {
    let mut seq = 2_u64;
    let mut records = Vec::new();

    for event in &report.probe_schedule_events {
        let probe_id = event.probe_id();
        let Some(probe) = report
            .probe_results
            .iter()
            .find(|probe| probe.probe_id == probe_id)
        else {
            // Internal prerequisite probes do not have public result rows.
            continue;
        };
        match event {
            satelle_core::doctor::DoctorProbeScheduleEvent::Started { timestamp, .. } => {
                if probe.dependency_status == "blocked" {
                    continue;
                }
                let mut record = doctor_event(
                    &mut seq,
                    DoctorEventType::ProbeStarted,
                    report,
                    &probe.scope,
                    Some(&probe.probe_id),
                    "running",
                    json!({"cache_status": probe.cache_status}),
                );
                record.timestamp.clone_from(timestamp);
                records.push(record);
            }
            satelle_core::doctor::DoctorProbeScheduleEvent::Finished { timestamp, .. } => {
                let mut record = doctor_event(
                    &mut seq,
                    DoctorEventType::ProbeFinished,
                    report,
                    &probe.scope,
                    Some(&probe.probe_id),
                    &probe.status,
                    json!(probe),
                );
                record.timestamp.clone_from(timestamp);
                records.push(record);
            }
        }
    }

    for finding in &report.findings {
        records.push(doctor_event(
            &mut seq,
            DoctorEventType::FindingReported,
            report,
            &finding.scope,
            None,
            &finding.readiness_impact,
            json!(finding),
        ));
    }

    for cache_update in &report.cache_updates {
        records.push(doctor_event(
            &mut seq,
            DoctorEventType::CacheUpdated,
            report,
            "all",
            None,
            "updated",
            json!({"cache_update": cache_update}),
        ));
    }

    if let Some(error) = terminal_error {
        records.push(doctor_event(
            &mut seq,
            DoctorEventType::DoctorFailed,
            report,
            "all",
            None,
            error.code.as_str(),
            json!({
                "error": {
                    "code": error.code.as_str(),
                    "message": error.message,
                    "exit_code": error.exit_code(),
                    "recovery_command": error.recovery_command,
                },
                "partial_probe_results": report.probe_results,
                "recovery_commands": report.recovery_commands,
            }),
        ));
    } else {
        records.push(doctor_event(
            &mut seq,
            DoctorEventType::DoctorFinished,
            report,
            "all",
            None,
            &report.status,
            json!(report),
        ));
    }

    records
}

#[cfg(test)]
mod doctor_event_tests {
    use super::*;
    use satelle_core::{DoctorProbeResult, DoctorSchemaVersion, DoctorSummary};

    fn probe(probe_id: &str, scope: &str) -> DoctorProbeResult {
        DoctorProbeResult {
            probe_id: probe_id.to_string(),
            scope: scope.to_string(),
            status: "passed".to_string(),
            started_at: "2026-07-29T00:00:00Z".to_string(),
            finished_at: "2026-07-29T00:00:01Z".to_string(),
            duration_ms: 1,
            cache_status: "not_persisted".to_string(),
            dependency_status: "satisfied".to_string(),
            finding_ids: Vec::new(),
        }
    }

    #[test]
    fn doctor_events_preserve_completion_order_without_changing_final_report_order() {
        let mut skipped = probe("skipped-probe", "provider");
        skipped.dependency_status = "blocked".to_string();
        let report = DoctorReport {
            schema_version: DoctorSchemaVersion::V1,
            status: "ready".to_string(),
            target: "local-demo".to_string(),
            host: "local-demo".to_string(),
            scopes: vec!["config".to_string(), "transport".to_string()],
            started_at: "2026-07-29T00:00:00Z".to_string(),
            finished_at: "2026-07-29T00:00:01Z".to_string(),
            duration_ms: 1,
            summary: DoctorSummary {
                ready: true,
                blocking_findings: 0,
                repairable_findings: 0,
                informational_findings: 0,
            },
            probe_results: vec![
                probe("a-probe", "config"),
                probe("computer-use.native.refresh", "computer-use"),
                skipped,
                probe("provider.smoke.refresh", "provider"),
            ],
            probe_schedule_events: vec![
                satelle_core::doctor::DoctorProbeScheduleEvent::Started {
                    probe_id: "provider.smoke.refresh".to_string(),
                    timestamp: "2026-07-29T00:00:10Z".to_string(),
                },
                satelle_core::doctor::DoctorProbeScheduleEvent::Finished {
                    probe_id: "provider.smoke.refresh".to_string(),
                    timestamp: "2026-07-29T00:00:11Z".to_string(),
                },
                satelle_core::doctor::DoctorProbeScheduleEvent::Started {
                    probe_id: "computer-use.native.refresh".to_string(),
                    timestamp: "2026-07-29T00:00:12Z".to_string(),
                },
                satelle_core::doctor::DoctorProbeScheduleEvent::Finished {
                    probe_id: "computer-use.native.refresh".to_string(),
                    timestamp: "2026-07-29T00:00:13Z".to_string(),
                },
                satelle_core::doctor::DoctorProbeScheduleEvent::Started {
                    probe_id: "a-probe".to_string(),
                    timestamp: "2026-07-29T00:00:14Z".to_string(),
                },
                satelle_core::doctor::DoctorProbeScheduleEvent::Finished {
                    probe_id: "a-probe".to_string(),
                    timestamp: "2026-07-29T00:00:15Z".to_string(),
                },
                satelle_core::doctor::DoctorProbeScheduleEvent::Finished {
                    probe_id: "skipped-probe".to_string(),
                    timestamp: "2026-07-29T00:00:16Z".to_string(),
                },
            ]
            .into_boxed_slice(),
            ready: true,
            findings: Vec::new(),
            recovery_commands: Vec::new(),
            changed: false,
            cache_updates: Vec::new(),
        };

        let records = doctor_event_records(&report, None);
        let event_position = |event_type, probe_id| {
            records
                .iter()
                .position(|record| {
                    record.event_type == event_type && record.probe_id.as_deref() == Some(probe_id)
                })
                .expect("expected probe lifecycle event")
        };
        assert!(
            event_position(DoctorEventType::ProbeFinished, "provider.smoke.refresh")
                < event_position(DoctorEventType::ProbeStarted, "computer-use.native.refresh"),
            "a dependent probe must not start before its prerequisite finishes"
        );
        let started = records
            .iter()
            .filter(|record| record.event_type == DoctorEventType::ProbeStarted)
            .collect::<Vec<_>>();
        let finished = records
            .iter()
            .filter(|record| record.event_type == DoctorEventType::ProbeFinished)
            .map(|record| record.probe_id.as_deref().expect("finished probe id"))
            .collect::<Vec<_>>();

        assert_eq!(
            started
                .iter()
                .map(|record| record.probe_id.as_deref().expect("started probe id"))
                .collect::<Vec<_>>(),
            [
                "provider.smoke.refresh",
                "computer-use.native.refresh",
                "a-probe",
            ]
        );
        assert_eq!(
            started
                .iter()
                .map(|record| record.timestamp.as_str())
                .collect::<Vec<_>>(),
            [
                "2026-07-29T00:00:10Z",
                "2026-07-29T00:00:12Z",
                "2026-07-29T00:00:14Z",
            ],
            "public start records must use this scheduler run, not cached probe timestamps"
        );
        assert_eq!(
            finished,
            [
                "provider.smoke.refresh",
                "computer-use.native.refresh",
                "a-probe",
                "skipped-probe"
            ]
        );
        assert_eq!(
            report
                .probe_results
                .iter()
                .map(|probe| probe.probe_id.as_str())
                .collect::<Vec<_>>(),
            [
                "a-probe",
                "computer-use.native.refresh",
                "skipped-probe",
                "provider.smoke.refresh"
            ]
        );
        assert!(
            serde_json::to_value(&report)
                .expect("serialize final report")
                .get("probe_schedule_events")
                .is_none(),
            "derived event order must not change the final JSON contract"
        );
    }
}

fn print_doctor_started_event(
    target: &str,
    scope_selection: &DoctorScopeSelection,
) -> Result<(), SatelleError> {
    let scopes = scope_selection
        .scopes()
        .iter()
        .map(|scope| scope.as_str())
        .collect::<Vec<_>>();
    let scope = if scopes.len() == 1 { scopes[0] } else { "all" };
    print_doctor_event_record(&DoctorEventRecord {
        schema_version: DoctorEventSchemaVersion::V1,
        event_id: "doctor_event_1".to_string(),
        event_type: DoctorEventType::DoctorStarted,
        target: target.to_string(),
        scope: scope.to_string(),
        probe_id: None,
        timestamp: utc_now(),
        status: "running".to_string(),
        data: json!({"scopes": scopes}),
    })
}

fn print_doctor_failed_event(
    target: &str,
    scope_selection: &DoctorScopeSelection,
    seq: u64,
    error: &SatelleError,
    partial_probe_results: &[satelle_core::DoctorProbeResult],
) -> Result<(), SatelleError> {
    print_doctor_event_record(&doctor_failed_event_record(
        target,
        scope_selection,
        seq,
        error,
        partial_probe_results,
    ))
}

fn doctor_failed_event_record(
    target: &str,
    scope_selection: &DoctorScopeSelection,
    seq: u64,
    error: &SatelleError,
    partial_probe_results: &[satelle_core::DoctorProbeResult],
) -> DoctorEventRecord {
    let scopes = scope_selection
        .scopes()
        .iter()
        .map(|scope| scope.as_str())
        .collect::<Vec<_>>();
    let scope = if scopes.len() == 1 { scopes[0] } else { "all" };
    DoctorEventRecord {
        schema_version: DoctorEventSchemaVersion::V1,
        event_id: format!("doctor_event_{seq}"),
        event_type: DoctorEventType::DoctorFailed,
        target: target.to_string(),
        scope: scope.to_string(),
        probe_id: None,
        timestamp: utc_now(),
        status: error.code.as_str().to_string(),
        data: json!({
            "error": {
                "code": error.code.as_str(),
                "message": error.message,
                "exit_code": error.exit_code(),
                "recovery_command": error.recovery_command,
            },
            "partial_probe_results": partial_probe_results,
            "scopes": scopes,
            "recovery_commands": error.recovery_command.iter().collect::<Vec<_>>(),
        }),
    }
}

#[cfg(test)]
#[test]
fn post_start_doctor_failure_event_includes_completed_probe_results() {
    let scope_selection = DoctorScopeSelection::parse(&["config".to_string()])
        .expect("config is a supported Doctor scope");
    let partial = satelle_core::DoctorProbeResult {
        probe_id: "config.selected_host_resolution".to_string(),
        scope: "config".to_string(),
        status: "passed".to_string(),
        started_at: "2026-07-29T00:00:00Z".to_string(),
        finished_at: "2026-07-29T00:00:00Z".to_string(),
        duration_ms: 0,
        cache_status: "not_persisted".to_string(),
        dependency_status: "satisfied".to_string(),
        finding_ids: Vec::new(),
    };

    let record = doctor_failed_event_record(
        LOCAL_DEMO_HOST,
        &scope_selection,
        2,
        &SatelleError::state_conflict(),
        std::slice::from_ref(&partial),
    );

    assert_eq!(record.event_type, DoctorEventType::DoctorFailed);
    assert_eq!(record.data["partial_probe_results"], json!([partial]));
}

fn print_doctor_event_record(record: &DoctorEventRecord) -> Result<(), SatelleError> {
    println!(
        "{}",
        serde_json::to_string(record).map_err(|source| SatelleError {
            code: ErrorCode::InvalidUsage,
            message: "could not serialize doctor event".to_string(),
            recovery_command: None,
            source_detail: Some(source.to_string()),
            details: std::collections::BTreeMap::new(),
        })?
    );

    Ok(())
}

fn doctor_event(
    seq: &mut u64,
    event_type: DoctorEventType,
    report: &DoctorReport,
    scope: &str,
    probe_id: Option<&str>,
    status: &str,
    data: serde_json::Value,
) -> DoctorEventRecord {
    let event = DoctorEventRecord {
        schema_version: DoctorEventSchemaVersion::V1,
        event_id: format!("doctor_event_{seq}"),
        event_type,
        target: report.target.clone(),
        scope: scope.to_string(),
        probe_id: probe_id.map(str::to_string),
        timestamp: utc_now(),
        status: status.to_string(),
        data,
    };
    *seq += 1;
    event
}

fn run_config(
    command: ConfigCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    match command {
        ConfigCommand::Check(command) => config_check(command, config, format),
        ConfigCommand::Explain(command) => config_explain(command, config, format),
    }
}

fn config_check(
    command: ConfigCheckCommand,
    config_context: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let output = read::config_check_report(command.host, command.all, config_context)?;

    if json {
        print_json(&output).map_err(failure)
    } else {
        println!("Config: ok");
        println!(
            "Mode: {}",
            if output["mode"] == "all" {
                "all-contexts"
            } else {
                "selected-context"
            }
        );
        println!(
            "Host: {}",
            output["selected_host"].as_str().unwrap_or_default()
        );
        println!(
            "User config: {}",
            output["checked_files"][0].as_str().unwrap_or_default()
        );
        println!(
            "Project config: {}",
            output["checked_files"][1].as_str().unwrap_or_default()
        );
        println!("Not checked: remote_host, provider_auth, native_computer_use");
        Ok(())
    }
}

fn config_explain(
    command: ConfigExplainCommand,
    config_context: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let output =
        read::config_explain_report(command.host, command.show_secret_references, config_context)?;

    if json {
        print_json(&output).map_err(failure)
    } else {
        println!(
            "Selected host: {}",
            output["selected_host"].as_str().unwrap_or_default()
        );
        println!(
            "User config: {}",
            output["checked_files"][0].as_str().unwrap_or_default()
        );
        println!(
            "Project config: {}",
            output["checked_files"][1].as_str().unwrap_or_default()
        );
        println!(
            "Default host: {}",
            output["values"]["default_host"]
                .as_str()
                .unwrap_or_default()
        );
        println!(
            "Host aliases: {}",
            output["values"]["host_count"].as_u64().unwrap_or_default()
        );
        print_config_explain_values("", &output["effective"]);
        Ok(())
    }
}

fn print_config_explain_values(path: &str, value: &serde_json::Value) {
    if value.get("redacted").and_then(serde_json::Value::as_bool) == Some(true) {
        println!(
            "{}: <redacted> (reason: {}, source: {})",
            path,
            value["redaction_reason"].as_str().unwrap_or("secret"),
            value["source"].as_str().unwrap_or("unknown")
        );
        return;
    }
    match value {
        serde_json::Value::Object(fields) => {
            for (name, field) in fields {
                let child_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                print_config_explain_values(&child_path, field);
            }
        }
        serde_json::Value::String(value) => println!("{path}: {value}"),
        _ => println!("{path}: {value}"),
    }
}

fn env_source(name: &str) -> serde_json::Value {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => json!({
            "name": name,
            "set": true,
            "value": value,
        }),
        _ => json!({
            "name": name,
            "set": false,
        }),
    }
}

fn redacted_config_json(
    config: &satelle_core::SatelleConfig,
    show_secret_references: bool,
) -> serde_json::Value {
    let mut value = serde_json::to_value(config).unwrap_or_else(|_| json!({}));
    redact_schema_marked_config_values(&mut value, &mut Vec::new(), show_secret_references);
    value
}

const CONFIG_SECRET_SOURCE_SCHEMA_PATHS: &[&[&str]] = &[
    &["hosts", "*", "api_token"],
    &["hosts", "*", "provider_auth", "*"],
];

fn redact_schema_marked_config_values(
    value: &mut serde_json::Value,
    path: &mut Vec<String>,
    show_secret_references: bool,
) {
    if CONFIG_SECRET_SOURCE_SCHEMA_PATHS.iter().any(|schema_path| {
        schema_path.len() == path.len()
            && schema_path
                .iter()
                .zip(path.iter())
                .all(|(schema, actual)| *schema == "*" || *schema == actual)
    }) {
        redact_secret_source_descriptor(value, show_secret_references);
        return;
    }
    match value {
        serde_json::Value::Object(fields) => {
            for (name, field) in fields {
                path.push(name.clone());
                redact_schema_marked_config_values(field, path, show_secret_references);
                path.pop();
            }
        }
        serde_json::Value::Array(values) => {
            for (index, field) in values.iter_mut().enumerate() {
                path.push(index.to_string());
                redact_schema_marked_config_values(field, path, show_secret_references);
                path.pop();
            }
        }
        _ => {}
    }
}

fn redact_secret_source_descriptor(
    descriptor: &mut serde_json::Value,
    show_secret_references: bool,
) {
    let kind = descriptor
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    *descriptor = if show_secret_references {
        reveal_secret_source_descriptor(&kind, descriptor)
    } else {
        json!({
            "kind": kind,
            "value": null,
            "redacted": true,
            "redaction_reason": "secret_source_reference",
            "source": "user_config",
        })
    };
}

fn reveal_secret_source_descriptor(
    kind: &str,
    descriptor: &serde_json::Value,
) -> serde_json::Value {
    match kind {
        "environment" => json!({
            "kind": kind,
            "variable": descriptor.get("variable").cloned().unwrap_or(serde_json::Value::Null),
            "redacted": false,
            "source": "user_config",
        }),
        "file" => json!({
            "kind": kind,
            "path": descriptor.get("path").cloned().unwrap_or(serde_json::Value::Null),
            "redacted": false,
            "source": "user_config",
        }),
        "credential-store" => json!({
            "kind": kind,
            "service": descriptor.get("service").cloned().unwrap_or(serde_json::Value::Null),
            "account": descriptor.get("account").cloned().unwrap_or(serde_json::Value::Null),
            "redacted": false,
            "source": "user_config",
        }),
        "host-store" => json!({
            "kind": kind,
            "name": descriptor.get("name").cloned().unwrap_or(serde_json::Value::Null),
            "redacted": false,
            "source": "user_config",
        }),
        _ => json!({
            "kind": kind,
            "value": null,
            "redacted": true,
            "redaction_reason": "unsupported_secret_source_kind",
            "source": "user_config",
        }),
    }
}

#[cfg(test)]
mod config_redaction_tests {
    use super::redact_schema_marked_config_values;
    use serde_json::json;

    #[test]
    fn schema_marked_secret_fields_never_fall_back_to_raw_values() {
        const CANARY: &str = "PRIVATE_CONFIG_REDACTION_FAILURE_CANARY";
        let mut value = json!({
            "hosts": {
                "selected": {
                    "transport": "direct",
                    "api_token": {
                        "kind": "file",
                        "path": CANARY,
                    },
                    "provider_auth": {
                        "operator-auth": {
                            "kind": "auth-command",
                            "argv": ["/usr/bin/credential-helper", CANARY],
                            "secret": CANARY,
                        },
                    },
                },
            },
        });

        redact_schema_marked_config_values(&mut value, &mut Vec::new(), false);

        let selected = &value["hosts"]["selected"];
        assert_eq!(selected["transport"], "direct");
        assert_eq!(selected["api_token"]["value"], serde_json::Value::Null);
        assert_eq!(selected["api_token"]["redacted"], true);
        assert_eq!(
            selected["provider_auth"]["operator-auth"]["value"],
            serde_json::Value::Null
        );
        assert_eq!(
            selected["provider_auth"]["operator-auth"]["redaction_reason"],
            "secret_source_reference"
        );
        assert!(
            !serde_json::to_string(&value)
                .expect("redacted config should serialize")
                .contains(CANARY)
        );

        let mut revealed = json!({
            "hosts": {
                "selected": {
                    "provider_auth": {
                        "operator-auth": {
                            "kind": "auth-command",
                            "argv": ["/usr/bin/credential-helper", CANARY],
                        },
                    },
                },
            },
        });
        redact_schema_marked_config_values(&mut revealed, &mut Vec::new(), true);
        let unknown = &revealed["hosts"]["selected"]["provider_auth"]["operator-auth"];
        assert_eq!(unknown["value"], serde_json::Value::Null);
        assert_eq!(unknown["redacted"], true);
        assert_eq!(
            unknown["redaction_reason"],
            "unsupported_secret_source_kind"
        );
        assert!(
            !serde_json::to_string(&revealed)
                .expect("unknown secret source should serialize as redacted")
                .contains(CANARY)
        );
    }
}

fn daemon_path_overrides_json(host_config: &HostConfig) -> serde_json::Value {
    let entries = [
        ("SATELLE_HOME", &host_config.daemon_home),
        ("SATELLE_CONFIG_FILE", &host_config.daemon_config_file),
        ("SATELLE_STATE_DIR", &host_config.daemon_state_dir),
        ("SATELLE_CACHE_DIR", &host_config.daemon_cache_dir),
        ("SATELLE_LOG_DIR", &host_config.daemon_log_dir),
    ]
    .into_iter()
    .filter_map(|(environment_variable, value)| {
        value.as_ref().map(|value| {
            json!({
                "environment_variable": environment_variable,
                "value": value,
                "source": "user_config",
                "setup_must_persist": true,
                "service_configuration_surface": "satelle_service_configuration",
            })
        })
    })
    .collect::<Vec<_>>();

    serde_json::Value::Array(entries)
}

fn model_provider_config_json(
    config: &satelle_core::ResolvedConfig,
    selected_host: &str,
    selected_host_config: &HostConfig,
) -> serde_json::Value {
    let model_alias_source =
        if config.profile_overrides_for_host(ProfileField::ModelAlias, selected_host) {
            if config.model_alias_from_project() {
                json!("project_selected_profile")
            } else {
                json!("user_config_profile")
            }
        } else {
            root_config_key_source(
                "model_alias",
                &config.user_config_path,
                &config.project_config_path,
            )
        };
    let provider_alias_source =
        if config.profile_overrides_for_host(ProfileField::ProviderAlias, selected_host) {
            if config.provider_alias_from_project() {
                json!("project_selected_profile")
            } else {
                json!("user_config_profile")
            }
        } else {
            root_config_key_source(
                "provider_alias",
                &config.user_config_path,
                &config.project_config_path,
            )
        };

    let binding = config
        .config
        .provider_alias
        .as_deref()
        .zip(config.config.model_alias.as_deref())
        .and_then(|(provider, model)| selected_host_config.provider_binding(provider, model));
    let binding_status = match (
        config.config.model_alias.as_ref(),
        config.config.provider_alias.as_ref(),
        binding,
    ) {
        (None, None, _) => "host_default",
        (Some(_), Some(_), Some(_)) => "resolved",
        _ => "binding_missing",
    };

    json!({
        "requested_model_alias": config.config.model_alias,
        "requested_provider_alias": config.config.provider_alias,
        "resolved_codex_model": binding.map(|binding| binding.model.as_str()),
        "resolved_model_provider": binding.map(|binding| binding.model_provider.as_str()),
        "provider_binding_source": binding.map(|_| "user_config"),
        "binding_status": binding_status,
        "model_alias_source": model_alias_source,
        "provider_alias_source": provider_alias_source,
        "model_alias_from_project": config.model_alias_from_project(),
        "provider_alias_from_project": config.provider_alias_from_project(),
        "contributing_config_files": [
            config.user_config_path,
            config.project_config_path,
        ],
        "winning_source": if binding.is_some() {
            "user_config"
        } else {
            model_alias_source
                .as_str()
                .or_else(|| provider_alias_source.as_str())
                .unwrap_or("host_default")
        },
    })
}

fn experimental_provider_computer_use_json(
    config: &satelle_core::ResolvedConfig,
    selected_host: &str,
    selected_host_config: &HostConfig,
) -> serde_json::Value {
    if let Some(provider_alias) = config.config.provider_alias.as_deref() {
        if let Some(active) = selected_host_config
            .experimental_provider_computer_use_by_provider
            .get(provider_alias)
        {
            return json!({
                "active": active,
                "source": "user_config_host_or_profile",
                "host": selected_host,
                "provider_alias": provider_alias,
                "selected_by_cli_flag": false,
            });
        }
        if let Some(active) = config
            .config
            .experimental_provider_computer_use_by_provider
            .get(provider_alias)
        {
            return json!({
                "active": active,
                "source": "user_config_global",
                "host": selected_host,
                "provider_alias": provider_alias,
                "selected_by_cli_flag": false,
            });
        }
    }
    if config
        .profile_overrides_for_host(ProfileField::ExperimentalProviderComputerUse, selected_host)
    {
        return json!({
            "active": selected_host_config.experimental_provider_computer_use.unwrap_or(false),
            "source": "user_config_profile",
            "host": selected_host,
            "selected_by_cli_flag": false,
        });
    }

    if let Some(active) = selected_host_config.experimental_provider_computer_use {
        return json!({
            "active": active,
            "source": "user_config_host",
            "host": selected_host,
            "selected_by_cli_flag": false,
        });
    }

    if let Some(active) = config.config.experimental_provider_computer_use {
        return json!({
            "active": active,
            "source": "user_config_global",
            "host": selected_host,
            "selected_by_cli_flag": false,
        });
    }

    json!({
        "active": false,
        "source": "absent",
        "host": selected_host,
        "selected_by_cli_flag": false,
    })
}

#[derive(Clone, Debug)]
struct YoloPolicy {
    active: bool,
    source: &'static str,
}

impl YoloPolicy {
    const fn execution_mode(&self) -> TurnExecutionMode {
        if self.active {
            TurnExecutionMode::Yolo
        } else {
            TurnExecutionMode::Standard
        }
    }
}

fn resolve_yolo_policy(
    config: &satelle_core::ResolvedConfig,
    selected_host: &str,
    selected_host_config: &HostConfig,
    flag_yolo: bool,
    flag_no_yolo: bool,
) -> YoloPolicy {
    if flag_yolo {
        return YoloPolicy {
            active: true,
            source: "cli_flag",
        };
    }
    if flag_no_yolo {
        return YoloPolicy {
            active: false,
            source: "cli_flag",
        };
    }
    if config.profile_overrides_for_host(ProfileField::Yolo, selected_host) {
        return YoloPolicy {
            active: selected_host_config.yolo.unwrap_or(false),
            source: "user_config_profile",
        };
    }
    if let Some(active) = selected_host_config.yolo {
        return YoloPolicy {
            active,
            source: "user_config_host",
        };
    }
    if let Some(active) = config.config.yolo {
        return YoloPolicy {
            active,
            source: "user_config_global",
        };
    }

    YoloPolicy {
        active: false,
        source: "absent",
    }
}

fn resolve_experimental_provider_computer_use(
    command_flag: bool,
    provider_alias: Option<&str>,
    host_config: &HostConfig,
    config: &satelle_core::ResolvedConfig,
) -> bool {
    if command_flag {
        return true;
    }
    if let Some(provider_alias) = provider_alias
        && let Some(active) = host_config
            .experimental_provider_computer_use_by_provider
            .get(provider_alias)
            .or_else(|| {
                config
                    .config
                    .experimental_provider_computer_use_by_provider
                    .get(provider_alias)
            })
    {
        return *active;
    }
    host_config
        .experimental_provider_computer_use
        .or(config.config.experimental_provider_computer_use)
        .unwrap_or(false)
}

#[derive(Clone, Debug)]
struct ProviderSelection {
    requested_model_alias: Option<String>,
    requested_provider_alias: Option<String>,
    model_alias_from_project: bool,
    provider_alias_from_project: bool,
    authorization: Option<ProviderBindingAuthorization>,
    auth_source_name: Option<String>,
    experimental_provider_computer_use: bool,
}

impl ProviderSelection {
    fn provider_smoke_status(&self, refresh: bool) -> &'static str {
        if self.requested_model_alias.is_none() && self.requested_provider_alias.is_none() {
            "host_owned"
        } else if refresh {
            "refresh_required"
        } else {
            "required"
        }
    }

    fn missing_auth_source_name(&self) -> Option<&str> {
        self.auth_source_name.as_deref().filter(|_| {
            self.authorization
                .as_ref()
                .is_some_and(|authorization| authorization.auth_source().is_none())
        })
    }
}

fn projected_experimental_provider_computer_use(
    provider_selection: &ProviderSelection,
    provider_validation: Option<&transport::ProviderDescriptorValidationReport>,
) -> bool {
    provider_validation.map_or(
        provider_selection.experimental_provider_computer_use,
        |validation| {
            validation
                .resolved_binding
                .experimental_provider_computer_use()
        },
    )
}

fn resolve_provider_selection(
    config: &ResolvedConfig,
    host: &SelectedHost,
    model_override: Option<&str>,
    provider_override: Option<&str>,
    command_experimental: bool,
    require_local_binding: bool,
) -> Result<ProviderSelection, CliFailure> {
    let model_alias_from_project = model_override.is_none() && config.model_alias_from_project();
    let provider_alias_from_project =
        provider_override.is_none() && config.provider_alias_from_project();
    let requested_model_alias = model_override
        .map(str::to_string)
        .or_else(|| config.config.model_alias.clone());
    let requested_provider_alias = provider_override
        .map(str::to_string)
        .or_else(|| config.config.provider_alias.clone());
    validate_explicit_provider_alias_pair(
        requested_model_alias.as_deref(),
        requested_provider_alias.as_deref(),
    )
    .map_err(failure)?;
    let experimental_provider_computer_use = resolve_experimental_provider_computer_use(
        command_experimental,
        requested_provider_alias.as_deref(),
        &host.config,
        config,
    );

    let (Some(model_alias), Some(provider_alias)) = (
        requested_model_alias.as_deref(),
        requested_provider_alias.as_deref(),
    ) else {
        if requested_model_alias.is_none() && requested_provider_alias.is_none() {
            return Ok(ProviderSelection {
                requested_model_alias,
                requested_provider_alias,
                model_alias_from_project,
                provider_alias_from_project,
                authorization: None,
                auth_source_name: None,
                experimental_provider_computer_use,
            });
        }
        return Err(provider_selection_error(
            ErrorCode::ModelProviderBindingMissing,
            &host.alias,
            requested_model_alias.as_deref(),
            requested_provider_alias.as_deref(),
            "model and provider aliases must resolve as one exact Host Binding pair",
            "set both model_alias and provider_alias, or pass both --model and --provider",
        ));
    };
    let Some(binding) = host.config.provider_binding(provider_alias, model_alias) else {
        if !require_local_binding {
            return Ok(ProviderSelection {
                requested_model_alias,
                requested_provider_alias,
                model_alias_from_project,
                provider_alias_from_project,
                authorization: None,
                auth_source_name: None,
                experimental_provider_computer_use,
            });
        }
        return Err(provider_selection_error(
            ErrorCode::ModelProviderBindingMissing,
            &host.alias,
            Some(model_alias),
            Some(provider_alias),
            "the selected Host has no exact binding for the requested model and provider aliases",
            "add the exact provider_bindings entry to the selected user-level Host Binding",
        ));
    };
    if (model_alias_from_project || provider_alias_from_project) && !binding.allow_project_selection
    {
        return Err(failure(
            SatelleError::project_provider_selection_not_allowed(
                &host.alias,
                provider_alias,
                model_alias,
            ),
        ));
    }

    let mut authorization = ProviderBindingAuthorization::new(
        model_alias,
        provider_alias,
        &binding.model,
        &binding.model_provider,
    )
    .with_experimental_provider_computer_use(experimental_provider_computer_use)
    .with_allow_project_selection(binding.allow_project_selection);
    if let Some(endpoint) = binding.endpoint.as_deref() {
        authorization = authorization.with_endpoint(endpoint);
    }
    if let Some(auth_source) = binding.auth_source.as_deref()
        && let Some(descriptor) = host.config.provider_auth.get(auth_source)
    {
        authorization = authorization.with_auth_source(descriptor.clone());
    }
    Ok(ProviderSelection {
        requested_model_alias,
        requested_provider_alias,
        model_alias_from_project,
        provider_alias_from_project,
        authorization: Some(authorization),
        auth_source_name: binding.auth_source.clone(),
        experimental_provider_computer_use,
    })
}

fn validate_explicit_provider_alias_pair(
    model_alias: Option<&str>,
    provider_alias: Option<&str>,
) -> Result<(), SatelleError> {
    if model_alias == Some("codex-default") && provider_alias == Some("codex-default") {
        return Err(SatelleError::config_error(
            "the provider binding alias pair `codex-default/codex-default` is reserved for implicit Codex defaults",
            None,
        ));
    }
    Ok(())
}

fn provider_selection_error(
    code: ErrorCode,
    host: &str,
    requested_model_alias: Option<&str>,
    requested_provider_alias: Option<&str>,
    message: &str,
    recovery_command: &str,
) -> CliFailure {
    let mut details = BTreeMap::new();
    details.insert("host".to_string(), json!(host));
    details.insert(
        "requested_model_alias".to_string(),
        json!(requested_model_alias),
    );
    details.insert(
        "requested_provider_alias".to_string(),
        json!(requested_provider_alias),
    );
    failure(SatelleError {
        code,
        message: message.to_string(),
        recovery_command: Some(recovery_command.to_string()),
        source_detail: None,
        details,
    })
}

fn doctor_provider_intent(
    config: &ResolvedConfig,
    host_config: &HostConfig,
    refresh: bool,
    probe_timeout: Option<std::time::Duration>,
) -> Result<ProviderComputerUseIntent, SatelleError> {
    validate_explicit_provider_alias_pair(
        config.config.model_alias.as_deref(),
        config.config.provider_alias.as_deref(),
    )?;
    let model = config
        .config
        .model_alias
        .as_deref()
        .map(EffectiveModelRef::new)
        .transpose()
        .map_err(|_| SatelleError::invalid_usage("the selected model alias is invalid"))?;
    let provider = config
        .config
        .provider_alias
        .as_deref()
        .map(ProviderBindingRef::new)
        .transpose()
        .map_err(|_| SatelleError::invalid_usage("the selected provider alias is invalid"))?;
    let experimental_provider_computer_use = resolve_experimental_provider_computer_use(
        false,
        config.config.provider_alias.as_deref(),
        host_config,
        config,
    );
    let intent = ProviderComputerUseIntent::new(model, provider, refresh)
        .with_project_selection_provenance(
            config.model_alias_from_project(),
            config.provider_alias_from_project(),
        )
        .with_experimental_provider_computer_use(experimental_provider_computer_use);
    Ok(match probe_timeout {
        Some(timeout) => intent.with_provider_smoke_timeout(timeout),
        None => intent,
    })
}

fn yolo_config_json(
    config: &satelle_core::ResolvedConfig,
    selected_host: &str,
    selected_host_config: &HostConfig,
) -> serde_json::Value {
    let policy = resolve_yolo_policy(config, selected_host, selected_host_config, false, false);
    json!({
        "active": policy.active,
        "source": policy.source,
        "target_host": selected_host,
        "selected_profile": config
            .selected_profile
            .as_ref()
            .map(|profile| profile.name.as_str()),
        "contributing_config_files": [
            config.user_config_path,
            config.project_config_path,
        ],
        "winning_source": policy.source,
    })
}

fn yolo_state_json(policy: &YoloPolicy) -> serde_json::Value {
    json!({
        "active": policy.active,
        "source": policy.source,
    })
}

fn root_config_key_source(
    key: &str,
    user_config_path: &std::path::Path,
    project_config_path: &std::path::Path,
) -> serde_json::Value {
    if config_file_has_root_key(project_config_path, key) {
        return json!("project_config");
    }
    if config_file_has_root_key(user_config_path, key) {
        return json!("user_config");
    }
    serde_json::Value::Null
}

fn config_file_has_root_key(path: &std::path::Path, key: &str) -> bool {
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = toml::from_str::<toml::Value>(&raw) else {
        return false;
    };
    value
        .as_table()
        .map(|table| table.contains_key(key))
        .unwrap_or(false)
}

fn show_paths(
    command: PathsCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let selected_host = command
        .host
        .as_deref()
        .map(|alias| config.resolve_host(Some(alias)))
        .transpose()?;
    let output = read::paths_report(selected_host.as_ref())?;

    if json {
        print_json(&output).map_err(failure)
    } else {
        println!("Host: {}", output["host"].as_str().unwrap_or_default());
        if let Some(observation_source) = output["observation_source"].as_str() {
            println!("Observation source: {observation_source}");
        }
        for (label, field) in [
            ("Config", "config_file"),
            ("Cache", "cache_root"),
            ("State", "state_root"),
            ("SQLite", "sqlite_store"),
            ("Operator logs", "operator_log_root"),
            ("Recordings", "recording_root"),
            ("Project config", "project_config_file"),
            ("Install receipt", "install_receipt"),
        ] {
            println!(
                "{label} [{}]: {}",
                output["sources"][field].as_str().unwrap_or_default(),
                output[field].as_str().unwrap_or_default()
            );
        }
        Ok(())
    }
}

fn run_host(
    command: HostCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    match command {
        HostCommand::Start(command) => start_host_daemon(command, config, format),
        HostCommand::ReleaseState => release_ssh_state_owner(),
        HostCommand::Trust(command) => trust_host(command, config, format),
        HostCommand::Status(command) => {
            let status = read::host_status(command.host.as_deref(), config)?;
            if json {
                print_json(&status).map_err(failure)
            } else {
                println!("Running: {}", status.running);
                println!("Mode: {}", status.mode);
                println!("Sessions: {}", status.sessions);
                Ok(())
            }
        }
        HostCommand::Stop(command) => run_host_lifecycle(
            command,
            transport::SshPersistentServiceLifecycle::Stop,
            config,
            format,
        ),
        HostCommand::Restart(command) => run_host_lifecycle(
            command,
            transport::SshPersistentServiceLifecycle::Restart,
            config,
            format,
        ),
        HostCommand::Update(command) => run_host_update(command, config, format),
        HostCommand::Cleanup(command) => run_host_cleanup(command, config, format),
        HostCommand::Sessions(command) => show_host_sessions(command, config, format),
        HostCommand::Storage { command } => run_host_storage(command, config, format),
        HostCommand::Store { command } => run_host_store(command, config, format),
        HostCommand::OfflineStorageMaintenance(command) => run_offline_storage_maintenance(command),
        HostCommand::OfflineStorageRestorePreview(command) => {
            run_offline_storage_restore_preview(command)
        }
        HostCommand::OfflineStorageBackupCleanupPlan(command) => {
            run_offline_storage_backup_cleanup_plan(command)
        }
    }
}

fn run_host_lifecycle(
    command: HostLifecycleCommand,
    lifecycle: transport::SshPersistentServiceLifecycle,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let host = config.resolve_host(command.host.as_deref())?;
    let action = lifecycle.as_str();
    let planned_actions = vec![format!(
        "{action} the persistent Host service on '{}' through SSH and verify its exact postconditions",
        host.alias
    )];
    let recovery_command = format!("satelle host {action} --host {} --yes", host.alias);
    if !command.yes && (command.no_input || format.is_json() || !io::stdin().is_terminal()) {
        return Err(failure(SatelleError::setup_consent_required(
            &planned_actions,
            recovery_command,
        )));
    }
    if !command.yes {
        let confirmed = cliclack::confirm(format!(
            "{} the persistent Host service on '{}'?",
            lifecycle.prompt_verb(),
            host.alias
        ))
        .initial_value(false)
        .interact()
        .map_err(|source| {
            failure(SatelleError {
                code: ErrorCode::InvalidUsage,
                message: format!("could not read Host service {action} confirmation"),
                recovery_command: Some(recovery_command.clone()),
                source_detail: Some(source.to_string()),
                details: BTreeMap::new(),
            })
        })?;
        if !confirmed {
            println!("No changes applied.");
            return Ok(());
        }
    }
    let report = transport::manage_ssh_persistent_service(&host, lifecycle).map_err(failure)?;
    if format.is_json() {
        print_json(&report).map_err(failure)
    } else {
        println!("Host: {}", report.host);
        println!("Action: {}", report.action);
        println!("Status: {}", report.status);
        println!("Service manager: {}", report.service_manager);
        Ok(())
    }
}

fn run_host_cleanup(
    command: HostCleanupCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let host = config.resolve_host(command.host.as_deref())?;
    let report = transport::cleanup_ssh_host_cache(&host).map_err(failure)?;
    if format.is_json() {
        print_json(&report).map_err(failure)
    } else {
        println!("Removed cache entries: {}", report.removed_entries);
        println!("Retained cache entries: {}", report.retained_entries);
        Ok(())
    }
}

fn release_ssh_state_owner() -> Result<(), CliFailure> {
    let state_root = satelle_core::state_dir().map_err(failure)?;
    release_ssh_state_owner_at(&state_root).map_err(failure)
}

fn release_ssh_state_owner_at(state_root: &Path) -> Result<(), SatelleError> {
    drop(
        open_or_create_owner_only_directory(state_root)
            .map_err(|error| state_release_failure(state_root, error))?,
    );
    let requester_lock_path = state_root.join(SSH_STATE_RELEASE_REQUESTER_LOCK);
    let requester_lock = open_or_create_owner_only_file(&requester_lock_path)
        .map_err(|error| state_release_failure(&requester_lock_path, error))?;
    requester_lock
        .lock()
        .map_err(|error| state_release_failure(&requester_lock_path, error))?;
    let request_path = state_root.join(SSH_STATE_RELEASE_REQUEST);
    drop(
        open_or_create_owner_only_file(&request_path)
            .map_err(|error| state_release_failure(&request_path, error))?,
    );
    let lock_path = state_root.join(STATE_OWNERSHIP_LOCK);
    let lock = open_or_create_owner_only_file(&lock_path)
        .map_err(|error| state_release_failure(&lock_path, error))?;
    let deadline = Instant::now() + STATE_RELEASE_TIMEOUT;
    loop {
        match lock.try_lock() {
            Ok(()) => {
                let _ = fs::remove_file(&request_path);
                let _ = lock.unlock();
                return Ok(());
            }
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(STATE_RELEASE_POLL_INTERVAL);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                let _ = fs::remove_file(&request_path);
                return Err(state_release_failure(
                    &lock_path,
                    "the running Host Daemon did not release the state store before the deadline",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => {
                let _ = fs::remove_file(&request_path);
                return Err(state_release_failure(&lock_path, error));
            }
        }
    }
}

async fn wait_for_ssh_state_release_request(state_root: PathBuf) {
    let request_path = state_root.join(SSH_STATE_RELEASE_REQUEST);
    let requester_lock_path = state_root.join(SSH_STATE_RELEASE_REQUESTER_LOCK);
    loop {
        match fs::metadata(&request_path) {
            Ok(_) => {
                let requester_lock = match open_or_create_owner_only_file(&requester_lock_path) {
                    Ok(lock) => lock,
                    // The state directory is owner-only, so an unverifiable
                    // requester lock must fail closed by releasing the store.
                    Err(_) => return,
                };
                match requester_lock.try_lock() {
                    // A live requester holds this lock before publishing the
                    // marker and keeps it until state ownership transfers.
                    Err(std::fs::TryLockError::WouldBlock) => return,
                    Ok(()) => {
                        // No live requester owns the marker. Remove it without
                        // stopping the newly started daemon, then keep watching.
                        let _ = fs::remove_file(&request_path);
                        let _ = requester_lock.unlock();
                    }
                    // Fail closed when requester liveness cannot be proven.
                    Err(std::fs::TryLockError::Error(_)) => return,
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            // The state directory is owner-only, so any other error means the
            // handoff cannot be trusted. Fail closed by releasing the store.
            Err(_) => return,
        }
        tokio::time::sleep(STATE_RELEASE_POLL_INTERVAL).await;
    }
}

fn state_release_failure(path: &Path, error: impl std::fmt::Display) -> SatelleError {
    SatelleError::config_error(
        format!(
            "could not coordinate SSH state release at '{}': {error}",
            path.display()
        ),
        None,
    )
}

#[cfg(test)]
mod ssh_state_release_tests {
    use super::*;

    #[test]
    fn stale_release_request_is_removed_without_stopping_the_next_daemon() {
        let state = satelle_host::test_support::TestStateDir::new()
            .expect("create secure state-release directory");
        let state_root = state.path().to_path_buf();
        drop(
            open_or_create_owner_only_file(&state_root.join(SSH_STATE_RELEASE_REQUEST))
                .expect("create stale release marker"),
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build marker watcher runtime");
        runtime.block_on(async {
            let outcome = tokio::time::timeout(
                STATE_RELEASE_POLL_INTERVAL * 3,
                wait_for_ssh_state_release_request(state_root.clone()),
            )
            .await;
            assert!(
                outcome.is_err(),
                "a stale marker must not request daemon shutdown"
            );
        });
        assert!(!state_root.join(SSH_STATE_RELEASE_REQUEST).exists());
    }

    #[test]
    fn release_request_waits_for_the_running_owner_and_cleans_up() {
        #[cfg(unix)]
        let state = tempfile::Builder::new()
            .prefix("satelle-state-release-")
            .tempdir_in(PathBuf::from(
                std::env::var_os("HOME").expect("test HOME directory"),
            ))
            .expect("create secure state-release directory");
        #[cfg(unix)]
        let state_root = state.path().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
                .expect("restrict state-release directory");
        }
        #[cfg(windows)]
        let state = satelle_host::test_support::TestStateDir::new()
            .expect("create secure state-release directory");
        #[cfg(windows)]
        let state_root = state.path().to_path_buf();
        let lock_path = state_root.join(STATE_OWNERSHIP_LOCK);
        let owner_lock = open_or_create_owner_only_file(&lock_path).expect("open ownership lock");
        owner_lock
            .lock()
            .expect("simulate the running daemon owner");

        let release_root = state_root.clone();
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
        let requester = std::thread::spawn(move || {
            let result = release_ssh_state_owner_at(&release_root);
            let _ = result_sender.send(result);
        });
        let request_path = state_root.join(SSH_STATE_RELEASE_REQUEST);
        let request_deadline = Instant::now() + Duration::from_secs(5);
        while !request_path.exists() && Instant::now() < request_deadline {
            if let Ok(result) = result_receiver.try_recv() {
                panic!("release requester exited before publishing its marker: {result:?}");
            }
            std::thread::sleep(STATE_RELEASE_POLL_INTERVAL);
        }
        assert!(
            request_path.exists(),
            "release requester publishes its marker before the owner watches it"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("build marker watcher runtime");
        runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(2),
                    wait_for_ssh_state_release_request(state_root.clone()),
                )
                .await
            })
            .expect("running owner observes the release request");
        assert!(
            request_path.exists(),
            "a live release request remains published until ownership transfers"
        );

        owner_lock
            .unlock()
            .expect("running owner releases the store");
        result_receiver
            .recv_timeout(STATE_RELEASE_TIMEOUT)
            .expect("release requester reports completion")
            .expect("release requester acquires the released store");
        requester.join().expect("release requester exits");
        assert!(!state_root.join(SSH_STATE_RELEASE_REQUEST).exists());
    }
}

fn trust_host(
    command: HostTrustCommand,
    config_context: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    if let Some(expected) = command.expected_host_id.as_deref() {
        HostIdentityRef::new(expected).map_err(|error| {
            failure(SatelleError::invalid_usage(format!(
                "--expected-host-id is invalid: {error}"
            )))
        })?;
    }
    if command.yes && command.expected_host_id.is_none() {
        return Err(failure(SatelleError::invalid_usage(
            "host trust --yes requires --expected-host-id <exact-id>",
        )));
    }
    let noninteractive = command.no_input || format.is_json() || !io::stdin().is_terminal();
    if noninteractive && (!command.no_input || !command.yes || command.expected_host_id.is_none()) {
        return Err(failure(SatelleError::invalid_usage(
            "noninteractive host trust requires --no-input --yes --expected-host-id <exact-id>",
        )));
    }

    let resolved = config_context.load()?;
    let host = resolved
        .resolve_host(Some(&command.host))
        .map(SelectedHost::from)
        .map_err(failure)?;
    let endpoint = host.config.address.clone().ok_or_else(|| {
        failure(SatelleError::config_error(
            "host trust requires a configured direct HTTPS address",
            None,
        ))
    })?;
    let observed_identity = discover_direct_host_identity(&host).map_err(failure)?;
    HostIdentityRef::new(&observed_identity).map_err(|_| {
        failure(SatelleError::remote_api_error(
            &host.alias,
            "invalid-daemon-response",
        ))
    })?;
    if command
        .expected_host_id
        .as_deref()
        .is_some_and(|expected| expected != observed_identity)
    {
        return Err(failure(SatelleError::host_identity_mismatch(&host.alias)));
    }
    let previous_identity = host.config.expected_host_id.clone();
    if previous_identity
        .as_deref()
        .is_some_and(|previous| previous != observed_identity)
        && !command.replace
    {
        return Err(failure(SatelleError::invalid_usage(
            "replacing an existing expected_host_id requires --replace",
        )));
    }

    if !command.yes {
        println!("Host: {}", host.alias);
        println!("Endpoint: {endpoint}");
        println!("Observed Host Identity: {observed_identity}");
        println!(
            "Current expected Host Identity: {}",
            previous_identity.as_deref().unwrap_or("not pinned")
        );
        println!(
            "Desktop Binding: {}",
            host.config
                .desktop_user
                .as_deref()
                .unwrap_or("not configured")
        );
        let confirmed = cliclack::confirm("Trust this Host Identity?")
            .initial_value(false)
            .interact()
            .map_err(|error| {
                failure(SatelleError::invalid_usage(format!(
                    "could not read Host trust confirmation: {error}"
                )))
            })?;
        if !confirmed {
            println!("No changes applied.");
            return Ok(());
        }
    }

    let changed =
        persist_host_identity(&resolved.user_config_path, &host.alias, &observed_identity)
            .map_err(failure)?;
    let report = HostTrustReport::new(
        host.alias,
        endpoint,
        observed_identity,
        previous_identity,
        changed,
    );
    if format.is_json() {
        print_json(&report).map_err(failure)
    } else {
        println!("Trusted Host: {}", report.host());
        println!("Endpoint: {}", report.endpoint());
        println!("Host Identity: {}", report.observed_host_identity());
        println!(
            "Previous Host Identity: {}",
            report
                .previous_expected_host_identity()
                .unwrap_or("not pinned")
        );
        println!("Changed: {}", report.changed());
        Ok(())
    }
}

fn validate_host_start_mode(command: &HostStartCommand) -> Result<(), SatelleError> {
    if command.launchd_service
        && (!command.foreground
            || command.service_config.is_some()
            || command.tls_cert.is_some()
            || command.tls_key.is_some()
            || command.bootstrap_token_stdin
            || command.bootstrap_scope.is_some()
            || command.bootstrap_native_readiness_timeout_ms.is_some()
            || command.bootstrap_provider_smoke_timeout_ms.is_some()
            || command.on_demand_idle_timeout_ms.is_some()
            || command.setup_ledger_retention_ms.is_none())
    {
        return Err(SatelleError::invalid_usage(
            "--launchd-service is an internal launchd input and cannot be combined with other internal or TLS Host start options",
        ));
    }
    if command.service_config.is_some()
        && (command.bind != DEFAULT_HOST_BIND
            || command.foreground
            || command.tls_cert.is_some()
            || command.tls_key.is_some()
            || command.bootstrap_token_stdin
            || command.bootstrap_scope.is_some()
            || command.bootstrap_native_readiness_timeout_ms.is_some()
            || command.bootstrap_provider_smoke_timeout_ms.is_some()
            || command.on_demand_idle_timeout_ms.is_some()
            || command.setup_ledger_retention_ms.is_some())
    {
        return Err(SatelleError::invalid_usage(
            "--service-config is an internal Windows service input and cannot be combined with ordinary Host start options",
        ));
    }
    if command.foreground && command.bootstrap_token_stdin {
        return Err(SatelleError::invalid_usage(
            "SSH bootstrap tokens are valid only for on-demand Host Daemons",
        ));
    }
    if command.bootstrap_token_stdin && (command.tls_cert.is_some() || command.tls_key.is_some()) {
        return Err(SatelleError::invalid_usage(
            "SSH bootstrap Host Daemons use loopback plaintext inside the authenticated tunnel and do not accept TLS files",
        ));
    }
    if command.on_demand_idle_timeout_ms.is_some() && command.foreground {
        return Err(SatelleError::invalid_usage(
            "the resolved on-demand idle timeout is valid only for durable on-demand Host Daemons",
        ));
    }
    if command.on_demand_idle_timeout_ms == Some(0) {
        return Err(SatelleError::invalid_usage(
            "the resolved on-demand idle timeout must be positive",
        ));
    }
    Ok(())
}

async fn bind_host_daemon(
    service: HostService,
    server_config: DaemonServerConfig,
    tls: Option<DaemonTlsFiles>,
) -> Result<(DaemonServer, Option<DaemonTlsWatcher>), CliFailure> {
    match tls {
        Some(tls) => {
            let DaemonTlsFiles {
                certificate_path,
                private_key_path,
                config,
            } = tls;
            let server = DaemonServer::bind_tls(service, server_config, config)
                .await
                .map_err(daemon_server_failure)?;
            let reloader = server
                .tls_reloader()
                .expect("a TLS listener always exposes its reload handle");
            let watcher = DaemonTlsWatcher::start(certificate_path, private_key_path, reloader)?;
            Ok((server, Some(watcher)))
        }
        None => Ok((
            DaemonServer::bind(service, server_config)
                .await
                .map_err(daemon_server_failure)?,
            None,
        )),
    }
}

fn start_host_daemon(
    command: HostStartCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    start_host_daemon_with(
        command,
        config,
        format,
        read_ssh_bootstrap_token,
        HostService::production_for_ssh_bootstrap,
    )
}

fn start_host_daemon_with(
    #[allow(unused_mut)] mut command: HostStartCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
    read_bootstrap_token: impl FnOnce() -> Result<ApiBearerToken, CliFailure>,
    build_bootstrap_service: impl FnOnce(
        &ApiBearerToken,
        satelle_host::ApiScopes,
        OffsetDateTime,
        &HostConfig,
    ) -> HostService,
) -> Result<(), CliFailure> {
    validate_host_start_mode(&command).map_err(failure)?;
    let (service_path_overrides, service_setup_ledger_retention_ms) =
        if let Some(_service_config_path) = command.service_config.as_deref() {
            #[cfg(not(windows))]
            return Err(failure(SatelleError::invalid_usage(
                "--service-config is supported only for the per-user Windows Host service",
            )));

            #[cfg(windows)]
            {
                let service_config = read_windows_service_config(_service_config_path)?;
                let path_overrides = service_config.path_overrides();
                apply_windows_service_environment(&service_config);
                command.bind = service_config.bind().to_string();
                command.foreground = true;
                (
                    Some(path_overrides),
                    Some(service_config.setup_ledger_retention_ms()),
                )
            }
        } else if command.launchd_service {
            (
                Some(daemon_path_overrides_from_process_environment()),
                command.setup_ledger_retention_ms,
            )
        } else {
            (None, None)
        };
    let bootstrap_scopes = match (command.bootstrap_token_stdin, command.bootstrap_scope) {
        (true, Some(scope)) => Some(scope.api_scopes()),
        (true, None) => {
            return Err(failure(SatelleError::invalid_usage(
                "SSH bootstrap Host Daemons require an explicit bootstrap scope",
            )));
        }
        (false, None) => None,
        (false, Some(_)) => {
            return Err(failure(SatelleError::invalid_usage(
                "SSH bootstrap scope is valid only with --bootstrap-token-stdin",
            )));
        }
    };
    let initial_identity = match (
        command.initial_host_identity.as_deref(),
        command.initial_identity_operation_id.as_deref(),
        command.initial_identity_record.as_deref(),
    ) {
        (Some(identity), Some(operation_id), Some(encoded_record)) => {
            let identity = HostIdentityRef::new(identity.to_string()).map_err(|_| {
                failure(SatelleError::invalid_usage(
                    "--initial-host-identity must be a valid Host Identity",
                ))
            })?;
            let record =
                satelle_core::SshIdentityCommitRecord::parse(encoded_record).map_err(|_| {
                    failure(SatelleError::invalid_usage(
                        "--initial-identity-record must be a valid v2 identity operation record",
                    ))
                })?;
            if record.candidate_host_identity() != &identity
                || record.operation_id() != operation_id
            {
                return Err(failure(SatelleError::invalid_usage(
                    "fresh SSH identity commit arguments must describe the same operation",
                )));
            }
            Some(record)
        }
        (None, None, None) => None,
        _ => {
            return Err(failure(SatelleError::invalid_usage(
                "fresh SSH identity commit arguments require each other",
            )));
        }
    };
    let bind_addr = command.bind.parse::<SocketAddr>().map_err(|error| {
        failure(SatelleError {
            code: ErrorCode::InvalidUsage,
            message: format!(
                "host start --bind must be an IP socket address, got '{}'",
                command.bind
            ),
            recovery_command: Some(
                "use satelle host start --foreground --bind 127.0.0.1:3001".to_string(),
            ),
            source_detail: Some(error.to_string()),
            details: BTreeMap::from([(
                "bind".to_string(),
                serde_json::Value::String(command.bind.clone()),
            )]),
        })
    })?;
    let tls = daemon_tls_config(&command)?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let user_config_path = resolve_path_set(&cwd).map_err(failure)?.config_file;
    let api_rate_limits = load_user_api_rate_limits(&user_config_path).map_err(failure)?;

    // Durable SSH relaunch must reopen the same default state store used by
    // bootstrap token issuance. The Controller has already resolved the idle
    // and readiness timeouts, so consulting the remote user's default Host here
    // could redirect the daemon to another daemon_state_dir and strand the
    // durable credential.
    let durable_ssh_launch = command.on_demand_idle_timeout_ms.is_some();
    let on_demand_host = should_resolve_on_demand_host(
        command.foreground,
        command.bootstrap_token_stdin,
        durable_ssh_launch,
    )
    .then(|| config.resolve_host(None))
    .transpose()?;
    let idle_timeout = if let Some(milliseconds) = command.on_demand_idle_timeout_ms {
        Some(Duration::from_millis(milliseconds))
    } else if command.bootstrap_token_stdin {
        Some(DEFAULT_ON_DEMAND_IDLE_TIMEOUT)
    } else {
        on_demand_host
            .as_ref()
            .map(|host| on_demand_idle_timeout(&host.config))
    };
    let bootstrap_token = command
        .bootstrap_token_stdin
        .then(read_bootstrap_token)
        .transpose()?;
    let forwarded_readiness_timeouts = ssh_launch_readiness_timeouts(
        command.bootstrap_native_readiness_timeout_ms,
        command.bootstrap_provider_smoke_timeout_ms,
    )
    .map_err(failure)?;
    let state_release_root = on_demand_host
        .as_ref()
        .and_then(|host| host.config.daemon_state_dir.clone())
        .map_or_else(satelle_core::state_dir, Ok)
        .map_err(failure)?;
    if initial_identity.is_none()
        && HostService::fresh_ssh_identity_commit_pending(&state_release_root).map_err(failure)?
    {
        return Err(failure(SatelleError::config_error(
            "the Host has an unfinished SSH identity commit",
            Some("rerun SSH setup with the exact previously accepted Host Identity".to_string()),
        )));
    }
    let service = match (on_demand_host.as_ref(), bootstrap_token.as_ref()) {
        (_, None) if service_path_overrides.is_some() => HostService::production_for_service(
            service_path_overrides
                .as_ref()
                .expect("persistent service path overrides were checked"),
            service_setup_ledger_retention_ms.expect("persistent service retention was checked"),
        )
        .map_err(failure)?,
        (_, Some(token)) => {
            let mut host_config = satelle_core::SatelleConfig::defaults()
                .hosts
                .remove(LOCAL_DEMO_HOST)
                .expect("the built-in local Host config exists");
            host_config.timeouts = forwarded_readiness_timeouts;
            if let Some(record) = initial_identity.as_ref() {
                let committed =
                    HostService::commit_fresh_ssh_host_identity(&state_release_root, record)
                        .map_err(failure)?;
                if committed != *record.candidate_host_identity() {
                    return Err(failure(SatelleError::state_conflict()));
                }
            }
            build_bootstrap_service(
                token,
                bootstrap_scopes.expect("bootstrap token has a validated scope"),
                OffsetDateTime::now_utc() + time::Duration::minutes(15),
                &host_config,
            )
        }
        (Some(host), None) => HostService::production_for_host(&host.config),
        (None, None) => match forwarded_readiness_timeouts {
            Some(timeouts) => {
                let mut host_config = satelle_core::SatelleConfig::defaults()
                    .hosts
                    .remove(LOCAL_DEMO_HOST)
                    .expect("the built-in local Host config exists");
                host_config.timeouts = Some(timeouts);
                HostService::production_for_host(&host_config)
            }
            None => HostService::production(),
        },
    };
    // The service retained only the verifier. Zeroize the raw bootstrap token
    // before the listener starts accepting requests.
    drop(bootstrap_token);
    let mode = if command.foreground {
        "foreground"
    } else {
        "on_demand"
    };
    let bootstrap_protocol = command.bootstrap_token_stdin;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| daemon_process_failure("runtime-create-failed", error.to_string()))?;
    runtime.block_on(async move {
        let mut server_config =
            DaemonServerConfig::loopback(bind_addr).with_api_rate_limits(api_rate_limits);
        if let Some(idle_timeout) = idle_timeout {
            server_config = server_config.with_idle_timeout(idle_timeout);
        }
        let (server, _tls_reload_watcher) = bind_host_daemon(service, server_config, tls).await?;

        let ready = json!({
            "schema_version": "satelle.host.start.v1",
            "mode": mode,
            "bind": server.local_addr(),
            "running": true,
        });
        let shutdown_handle = server.shutdown_handle();
        let state_release_shutdown = shutdown_handle.clone();
        let state_release_task = tokio::spawn(async move {
            wait_for_ssh_state_release_request(state_release_root).await;
            state_release_shutdown.request_shutdown();
        });
        if bootstrap_protocol {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, &ready).map_err(|_| {
                daemon_process_failure(
                    "bootstrap-protocol-write-failed",
                    "serialization failed".to_string(),
                )
            })?;
            writeln!(stdout).map_err(|_| {
                daemon_process_failure(
                    "bootstrap-protocol-write-failed",
                    "write failed".to_string(),
                )
            })?;
            stdout.flush().map_err(|_| {
                daemon_process_failure(
                    "bootstrap-protocol-write-failed",
                    "flush failed".to_string(),
                )
            })?;
        } else if format.is_json() {
            print_json(&ready).map_err(failure)?;
        } else {
            println!("Host Daemon listening on {}", server.local_addr());
        }

        let mut server_wait = Box::pin(server.wait());
        let result = if command.foreground {
            tokio::select! {
                result = &mut server_wait => result.map_err(daemon_server_failure),
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|error| {
                        daemon_process_failure("signal-wait-failed", error.to_string())
                    })?;
                    shutdown_handle.request_shutdown();
                    server_wait.await.map_err(daemon_server_failure)
                }
            }
        } else {
            server_wait.await.map_err(daemon_server_failure)
        };
        state_release_task.abort();
        result
    })
}

#[cfg(any(windows, test))]
fn read_windows_service_config(path: &Path) -> Result<WindowsServiceConfigV2, CliFailure> {
    if !path.is_absolute() {
        return Err(failure(SatelleError::invalid_usage(
            "Windows Host service config path must be absolute",
        )));
    }
    let raw = read_owner_only_secret_config_file(path).map_err(|error| {
        failure(SatelleError::config_error(
            format!(
                "Windows Host service config '{}' is unavailable or does not satisfy the owner-only security policy",
                path.display()
            ),
            Some(error.to_string()),
        ))
    })?;
    serde_json::from_str(raw.as_str()).map_err(|error| {
        failure(SatelleError::config_error(
            format!(
                "Windows Host service config '{}' is invalid",
                path.display()
            ),
            Some(error.to_string()),
        ))
    })
}

#[cfg(test)]
mod windows_service_config_tests {
    use super::*;

    fn write_owner_only_config(path: &Path, contents: &str) {
        let mut file = open_or_create_owner_only_file(path).expect("create owner-only config");
        file.write_all(contents.as_bytes())
            .expect("write owner-only config");
        file.sync_all().expect("sync owner-only config");
    }

    #[test]
    fn reads_the_closed_service_schema_from_an_owner_only_file() {
        let state = satelle_host::test_support::TestStateDir::new()
            .expect("create owner-only test directory");
        let path = state.path().join("service.json");
        let overrides = DaemonPathOverrides {
            home: Some(PathBuf::from(r"C:\Users\owner\AppData\Local\Satelle")),
            config_file: Some(PathBuf::from(
                r"C:\Users\owner\AppData\Local\Satelle\config\config.toml",
            )),
            state_dir: Some(PathBuf::from(r"C:\Users\owner\AppData\Local\Satelle\state")),
            cache_dir: Some(PathBuf::from(r"C:\Users\owner\AppData\Local\Satelle\cache")),
            log_dir: Some(PathBuf::from(r"C:\Users\owner\AppData\Local\Satelle\logs")),
            sources: BTreeMap::new(),
        };
        let expected = WindowsServiceConfigV2::new("127.0.0.1:3001", &overrides, 3_600_000)
            .expect("build service config");
        write_owner_only_config(
            &path,
            &serde_json::to_string(&expected).expect("serialize service config"),
        );

        let observed = match read_windows_service_config(&path) {
            Ok(config) => config,
            Err(failure) => panic!("read service config: {}", failure.error),
        };

        assert_eq!(observed, expected);
        assert_eq!(
            observed.daemon_arguments(),
            ["host", "start", "--foreground", "--bind", "127.0.0.1:3001"]
        );
        assert_eq!(observed.environment().len(), 5);
        assert_eq!(observed.setup_ledger_retention_ms(), 3_600_000);
    }

    #[test]
    fn rejects_a_relative_service_config_path() {
        let error = read_windows_service_config(Path::new("service.json"))
            .expect_err("service startup must not resolve config relative to its working directory")
            .error;

        assert_eq!(error.code, ErrorCode::InvalidUsage);
        assert!(error.message.contains("must be absolute"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_service_config_that_is_not_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let state = satelle_host::test_support::TestStateDir::new()
            .expect("create owner-only test directory");
        let path = state.path().join("service.json");
        fs::write(&path, "{}").expect("write unsafe config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("broaden config permissions");

        let error = read_windows_service_config(&path)
            .expect_err("group-readable service config must fail closed")
            .error;

        assert!(error.message.contains("owner-only security policy"));
    }
}

#[cfg(windows)]
fn apply_windows_service_environment(config: &WindowsServiceConfigV2) {
    const PATH_OVERRIDES: [&str; 5] = [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
    ];

    // This runs on the initial process thread before the Tokio runtime, Host
    // service, or any worker thread exists. Clearing the full allowlist first
    // prevents ambient task state from becoming a second configuration source.
    unsafe {
        for key in PATH_OVERRIDES {
            std::env::remove_var(key);
        }
        for (key, value) in config.environment() {
            std::env::set_var(key, value);
        }
    }
}

fn daemon_path_overrides_from_process_environment() -> DaemonPathOverrides {
    DaemonPathOverrides {
        home: std::env::var_os("SATELLE_HOME").map(PathBuf::from),
        config_file: std::env::var_os("SATELLE_CONFIG_FILE").map(PathBuf::from),
        state_dir: std::env::var_os("SATELLE_STATE_DIR").map(PathBuf::from),
        cache_dir: std::env::var_os("SATELLE_CACHE_DIR").map(PathBuf::from),
        log_dir: std::env::var_os("SATELLE_LOG_DIR").map(PathBuf::from),
        sources: BTreeMap::new(),
    }
}

const fn should_resolve_on_demand_host(
    foreground: bool,
    bootstrap_token_stdin: bool,
    durable_ssh_launch: bool,
) -> bool {
    !foreground && !bootstrap_token_stdin && !durable_ssh_launch
}

fn ssh_launch_readiness_timeouts(
    native_readiness_timeout_ms: Option<u64>,
    provider_smoke_timeout_ms: Option<u64>,
) -> Result<Option<satelle_core::TimeoutConfig>, SatelleError> {
    match (native_readiness_timeout_ms, provider_smoke_timeout_ms) {
        (Some(native), Some(provider)) => Ok(Some(satelle_core::TimeoutConfig {
            native_readiness: satelle_core::ExplicitDuration::parse(&format!("{native}ms")),
            provider_smoke_test: satelle_core::ExplicitDuration::parse(&format!("{provider}ms")),
            turn_execution: None,
        })),
        (None, None) => Ok(None),
        _ => Err(SatelleError::invalid_usage(
            "SSH launch readiness timeouts must be provided together",
        )),
    }
}

fn install_diagnostics(command: &Command, error_format: ErrorFormat) {
    if error_format == ErrorFormat::Json {
        return;
    }
    let default_level = if matches!(
        command,
        Command::Host {
            command: HostCommand::Start(_)
        }
    ) {
        tracing_subscriber::filter::LevelFilter::INFO
    } else {
        tracing_subscriber::filter::LevelFilter::OFF
    };
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default_level.into())
        .with_env_var("SATELLE_LOG")
        .from_env_lossy();
    let _subscriber_already_installed = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(true)
        .with_writer(io::stderr)
        .with_env_filter(filter)
        .try_init();
    tracing::debug!("Satelle diagnostics initialized");
}

struct DaemonTlsFiles {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    config: DaemonTlsConfig,
}

fn daemon_tls_config(command: &HostStartCommand) -> Result<Option<DaemonTlsFiles>, CliFailure> {
    let (certificate_path, private_key_path) =
        match (command.tls_cert.as_deref(), command.tls_key.as_deref()) {
            (None, None) => return Ok(None),
            (Some(certificate_path), Some(private_key_path)) => {
                (certificate_path, private_key_path)
            }
            _ => {
                return Err(failure(SatelleError::invalid_usage(
                    "--tls-cert and --tls-key must be provided together",
                )));
            }
        };
    // Absolute TLS paths do not depend on the process working directory. This
    // matters for long-lived launchers whose original directory may be removed
    // before the Host daemon starts.
    let current_directory = (certificate_path.is_relative() || private_key_path.is_relative())
        .then(std::env::current_dir)
        .transpose()
        .map_err(|error| daemon_process_failure("tls-path-resolution-failed", error.to_string()))?;
    let certificate_path =
        absolute_path(certificate_path, current_directory.as_deref()).map_err(|reason| {
            tls_file_failure("certificate path", certificate_path, reason.to_string())
        })?;
    let private_key_path =
        absolute_path(private_key_path, current_directory.as_deref()).map_err(|reason| {
            tls_file_failure("private-key path", private_key_path, reason.to_string())
        })?;
    let _boundary_guards = open_daemon_tls_boundaries(
        &certificate_path,
        &private_key_path,
        TlsBoundaryOpenMode::CreateIfMissing,
    )
    .map_err(|error| tls_material_failure(error, &certificate_path, &private_key_path))?;
    let config = read_daemon_tls_config(&certificate_path, &private_key_path)
        .map_err(|error| tls_material_failure(error, &certificate_path, &private_key_path))?;
    Ok(Some(DaemonTlsFiles {
        certificate_path,
        private_key_path,
        config,
    }))
}

fn absolute_path(path: &Path, current_directory: Option<&Path>) -> Result<PathBuf, &'static str> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_directory
            .ok_or("relative TLS material paths require a current directory")?
            .join(path)
    };
    if !absolute.is_absolute() {
        return Err("TLS material paths must resolve to an absolute path");
    }
    comparable_path(&absolute)
}

fn comparable_path(path: &Path) -> Result<PathBuf, &'static str> {
    // Rewriting parent traversal is unsafe when an ancestor is a symlink, and
    // canonicalization would follow the very symlinks that secure TLS reads
    // must reject. Fail fast on `..` and normalize only harmless `.` segments.
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err("TLS material paths must not contain parent traversal (`..`)");
            }
        }
    }
    Ok(normalized)
}

#[derive(Debug, thiserror::Error)]
enum DaemonTlsMaterialError {
    #[error("the TLS file boundary '{}' is unavailable or unsafe: {source}", path.display())]
    Boundary {
        path: PathBuf,
        #[source]
        source: SecureFileError,
    },
    #[error("the certificate-chain file is unavailable or unsafe: {0}")]
    Certificate(#[source] SecureFileError),
    #[error("the private-key file is unavailable or unsafe: {0}")]
    PrivateKey(#[source] SecureFileError),
    #[error("the replacement TLS configuration is invalid: {0}")]
    Configuration(#[source] DaemonTlsConfigError),
    #[error("the TLS listener stopped before the replacement could be installed")]
    ListenerStopped,
}

impl DaemonTlsMaterialError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Boundary { .. } => "tls-reload-boundary-unavailable",
            Self::Certificate(_) => "tls-reload-certificate-unavailable",
            Self::PrivateKey(_) => "tls-reload-private-key-unavailable",
            Self::Configuration(_) => "tls-reload-invalid-configuration",
            Self::ListenerStopped => "tls-reload-listener-stopped",
        }
    }
}

#[derive(Clone, Copy)]
enum TlsBoundaryOpenMode {
    CreateIfMissing,
    Existing,
}

fn open_daemon_tls_boundaries(
    certificate_path: &Path,
    private_key_path: &Path,
    mode: TlsBoundaryOpenMode,
) -> Result<Vec<OwnerOnlyDirectory>, DaemonTlsMaterialError> {
    let open_boundary = match mode {
        TlsBoundaryOpenMode::CreateIfMissing => open_or_create_owner_only_directory,
        TlsBoundaryOpenMode::Existing => open_owner_only_directory,
    };
    [certificate_path, private_key_path]
        .into_iter()
        .map(|path| {
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or_else(|| DaemonTlsMaterialError::Boundary {
                    path: path.to_path_buf(),
                    source: SecureFileError::UnsafeOrUnavailable,
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .map(|path| {
            open_boundary(path).map_err(|source| DaemonTlsMaterialError::Boundary {
                path: path.to_path_buf(),
                source,
            })
        })
        .collect()
}

fn read_daemon_tls_config(
    certificate_path: &Path,
    private_key_path: &Path,
) -> Result<DaemonTlsConfig, DaemonTlsMaterialError> {
    let certificate = read_owner_controlled_config_file(certificate_path)
        .map_err(DaemonTlsMaterialError::Certificate)?;
    let private_key = read_owner_only_secret_config_file(private_key_path)
        .map_err(DaemonTlsMaterialError::PrivateKey)?;
    DaemonTlsConfig::from_pem(certificate.as_bytes(), private_key.as_bytes())
        .map_err(DaemonTlsMaterialError::Configuration)
}

fn tls_material_failure(
    error: DaemonTlsMaterialError,
    certificate_path: &Path,
    private_key_path: &Path,
) -> CliFailure {
    match error {
        DaemonTlsMaterialError::Boundary { path, source } => {
            tls_file_failure("file boundary", &path, source.to_string())
        }
        DaemonTlsMaterialError::Certificate(source) => {
            tls_file_failure("certificate chain", certificate_path, source.to_string())
        }
        DaemonTlsMaterialError::PrivateKey(source) => {
            tls_file_failure("private key", private_key_path, source.to_string())
        }
        DaemonTlsMaterialError::Configuration(source) => tls_configuration_failure(source),
        DaemonTlsMaterialError::ListenerStopped => {
            daemon_process_failure("tls-reload-listener-stopped", error.to_string())
        }
    }
}

struct DaemonTlsWatcher {
    task: tokio::task::JoinHandle<()>,
}

const TLS_DIRECTORY_WATCH_RETRY_INITIAL: Duration = Duration::from_millis(50);
const TLS_DIRECTORY_WATCH_RETRY_MAX: Duration = Duration::from_secs(1);

impl DaemonTlsWatcher {
    fn start(
        certificate_path: PathBuf,
        private_key_path: PathBuf,
        reloader: DaemonTlsReloader,
    ) -> Result<Self, CliFailure> {
        // Retaining these handles pins the boundary against replacement on
        // Windows. Unix reloads additionally revalidate the trusted ancestry
        // before every path-based read below.
        let boundary_guards = open_daemon_tls_boundaries(
            &certificate_path,
            &private_key_path,
            TlsBoundaryOpenMode::Existing,
        )
        .map_err(|error| tls_material_failure(error, &certificate_path, &private_key_path))?;
        let watched_paths = Arc::new([certificate_path.clone(), private_key_path.clone()]);
        let callback_paths = Arc::clone(&watched_paths);
        let file_directories = watched_paths
            .iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect::<BTreeSet<_>>();
        let (reload_sender, mut reload_receiver) = tokio::sync::watch::channel(0_u64);
        let mut watcher = RecommendedWatcher::new(
            move |event: notify::Result<Event>| match event {
                Ok(event) if tls_event_requires_reload(&event, &callback_paths) => {
                    signal_tls_reload(&reload_sender);
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("Host Daemon TLS reload failed [tls-reload-watch-failed]: {error}");
                    signal_tls_reload(&reload_sender);
                }
            },
            NotifyConfig::default(),
        )
        .map_err(|error| daemon_process_failure("tls-reload-watch-failed", error.to_string()))?;
        install_initial_tls_directory_watches(&mut watcher, &file_directories).map_err(
            |error| daemon_process_failure("tls-reload-watch-failed", error.to_string()),
        )?;
        // Close the startup race between the initial TLS read and watcher
        // registration. Any rotation overlapping this authoritative re-read
        // also produces a watched event and is retried by the task below.
        if let Err(error) =
            reload_daemon_tls_config(&certificate_path, &private_key_path, &reloader)
        {
            report_daemon_tls_reload_error(&error);
        }
        let task = tokio::spawn(async move {
            // Keep ownership in the reload task so it can replace stale
            // directory watches after an atomic directory swap.
            let mut watcher = watcher;
            let _boundary_guards = boundary_guards;
            while reload_receiver.changed().await.is_ok() {
                let watch_registration =
                    refresh_tls_directory_watches(&mut watcher, &file_directories);
                if let Err(error) =
                    reload_daemon_tls_config(&certificate_path, &private_key_path, &reloader)
                {
                    report_daemon_tls_reload_error(&error);
                }
                if let Err(error) = watch_registration {
                    report_daemon_tls_watch_error(&error);
                    retry_tls_directory_watches(&mut watcher, &file_directories).await;
                    // A parent namespace watch is optional because secure TLS
                    // ancestry may be execute-only. Re-read after polling has
                    // attached to a replacement boundary: its files may have
                    // arrived before the new watch existed.
                    if let Err(error) =
                        reload_daemon_tls_config(&certificate_path, &private_key_path, &reloader)
                    {
                        report_daemon_tls_reload_error(&error);
                    }
                }
            }
        });
        Ok(Self { task })
    }
}

fn install_initial_tls_directory_watches(
    watcher: &mut RecommendedWatcher,
    file_directories: &BTreeSet<PathBuf>,
) -> notify::Result<()> {
    // The TLS boundary itself is owner-readable and must be watched. A
    // move/delete event on this inode starts the bounded re-registration loop.
    for directory in file_directories {
        watcher.watch(directory, RecursiveMode::NonRecursive)?;
    }

    // Watching the parent namespace shortens atomic directory rotation, but
    // Linux inotify requires read access while the secure path contract permits
    // execute-only ancestors. Keep this optimization best-effort; when it is
    // unavailable, the boundary move event and retry loop preserve correctness.
    let parent_namespaces = file_directories
        .iter()
        .filter_map(|directory| directory.parent().map(Path::to_path_buf))
        .filter(|parent| !file_directories.contains(parent))
        .collect::<BTreeSet<_>>();
    for parent in parent_namespaces {
        if let Err(error) = watcher.watch(&parent, RecursiveMode::NonRecursive) {
            eprintln!(
                "Host Daemon TLS reload warning [tls-reload-namespace-watch-unavailable]: '{}': {error}; boundary replacement polling remains active",
                parent.display()
            );
        }
    }
    Ok(())
}

fn refresh_tls_directory_watches(
    watcher: &mut RecommendedWatcher,
    file_directories: &BTreeSet<PathBuf>,
) -> notify::Result<()> {
    let mut first_error = None;
    for directory in file_directories {
        // A deleted or renamed-away directory may no longer be registered, so
        // unwatch failure is expected. The following watch call is the
        // authoritative attempt against the directory now at this path.
        let _ = watcher.unwatch(directory);
        if let Err(error) = watcher.watch(directory, RecursiveMode::NonRecursive) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn retry_tls_directory_watches(
    watcher: &mut RecommendedWatcher,
    file_directories: &BTreeSet<PathBuf>,
) -> usize {
    let mut delay = TLS_DIRECTORY_WATCH_RETRY_INITIAL;
    let mut attempts = 0;
    loop {
        tokio::time::sleep(delay).await;
        attempts += 1;
        match refresh_tls_directory_watches(watcher, file_directories) {
            Ok(()) => return attempts,
            Err(error) => report_daemon_tls_watch_error(&error),
        }
        delay = delay.saturating_mul(2).min(TLS_DIRECTORY_WATCH_RETRY_MAX);
    }
}

fn report_daemon_tls_watch_error(error: &notify::Error) {
    eprintln!("Host Daemon TLS reload failed [tls-reload-watch-failed]: {error}");
}

fn signal_tls_reload(sender: &tokio::sync::watch::Sender<u64>) {
    // The generation counter coalesces repeated filesystem events in constant
    // memory. `changed()` marks one generation as observed before re-reading,
    // so an event arriving during that read advances the version and schedules
    // another authoritative file-pair read.
    sender.send_modify(|generation| *generation = generation.wrapping_add(1));
}

fn reload_daemon_tls_config(
    certificate_path: &Path,
    private_key_path: &Path,
    reloader: &DaemonTlsReloader,
) -> Result<(), DaemonTlsMaterialError> {
    let _boundary_guards = open_daemon_tls_boundaries(
        certificate_path,
        private_key_path,
        TlsBoundaryOpenMode::Existing,
    )?;
    let config = read_daemon_tls_config(certificate_path, private_key_path)?;
    reloader.reload(config).map_err(|error| match error {
        DaemonTlsReloadError::InvalidConfiguration(source) => {
            DaemonTlsMaterialError::Configuration(source)
        }
        DaemonTlsReloadError::ListenerStopped | DaemonTlsReloadError::TlsNotConfigured => {
            DaemonTlsMaterialError::ListenerStopped
        }
    })
}

fn report_daemon_tls_reload_error(error: &DaemonTlsMaterialError) {
    eprintln!("Host Daemon TLS reload failed [{}]: {error}", error.code());
}

impl Drop for DaemonTlsWatcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn tls_event_requires_reload(event: &Event, watched_paths: &[PathBuf; 2]) -> bool {
    if event.need_rescan() {
        return true;
    }
    // Secure file reads can emit Access(Open) and Access(Close(Read)) for the
    // watched files. Treating those non-mutating events as changes would make
    // each reload schedule the next one. Close(Write) remains relevant because
    // it marks completed mutation on backends that expose that distinction.
    if matches!(event.kind, notify::EventKind::Access(kind) if !matches!(
        kind,
        notify::event::AccessKind::Close(notify::event::AccessMode::Write)
    )) {
        return false;
    }
    event.paths.iter().any(|event_path| {
        let Ok(event_path) = comparable_path(event_path) else {
            return false;
        };
        watched_paths.iter().any(|path| {
            comparable_path(path).is_ok_and(|path| {
                tls_paths_equal(&path, &event_path)
                    || path
                        .parent()
                        .is_some_and(|directory| tls_paths_equal(directory, &event_path))
            })
        })
    })
}

#[cfg(not(windows))]
fn tls_paths_equal(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(windows)]
fn tls_paths_equal(left: &Path, right: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};

    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    let (Ok(left_length), Ok(right_length)) =
        (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: both pointers reference initialized UTF-16 buffers for the exact
    // lengths passed to CompareStringOrdinal and remain alive for the call.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_length, right.as_ptr(), right_length, 1)
            == CSTR_EQUAL
    }
}

#[cfg(test)]
mod daemon_tls_watcher_tests {
    use super::*;
    use notify::EventKind;
    use notify::event::{AccessKind, AccessMode, Flag};

    fn tls_command(tls_cert: Option<&str>, tls_key: Option<&str>) -> HostStartCommand {
        HostStartCommand {
            bind: "127.0.0.1:3001".to_string(),
            tls_cert: tls_cert.map(PathBuf::from),
            tls_key: tls_key.map(PathBuf::from),
            foreground: true,
            launchd_service: false,
            bootstrap_token_stdin: false,
            initial_host_identity: None,
            initial_identity_operation_id: None,
            initial_identity_record: None,
            bootstrap_scope: None,
            bootstrap_native_readiness_timeout_ms: None,
            bootstrap_provider_smoke_timeout_ms: None,
            on_demand_idle_timeout_ms: None,
            setup_ledger_retention_ms: None,
            service_config: None,
            output_args: OutputArgs::default(),
        }
    }

    #[test]
    fn rejects_each_one_sided_tls_configuration_before_plaintext_startup() {
        match daemon_tls_config(&tls_command(None, None)) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("no TLS flags must preserve plaintext loopback startup"),
            Err(_) => panic!("no TLS flags must remain valid"),
        }
        for command in [
            tls_command(Some("certificate.pem"), None),
            tls_command(None, Some("private-key.pem")),
        ] {
            let error = match daemon_tls_config(&command) {
                Err(failure) => failure.error,
                Ok(_) => panic!("one-sided TLS configuration must fail closed"),
            };
            assert_eq!(error.code, ErrorCode::InvalidUsage);
            assert_eq!(
                error.message,
                "--tls-cert and --tls-key must be provided together"
            );
        }
    }

    #[test]
    fn reloads_only_for_tls_material_changes_or_rescan_requests() {
        let watched = [
            PathBuf::from("/host/tls/certificate.pem"),
            PathBuf::from("/host/tls/private-key.pem"),
        ];
        let certificate_change = Event::new(EventKind::Any).add_path(watched[0].clone());
        let unrelated_change =
            Event::new(EventKind::Any).add_path(PathBuf::from("/host/tls/other.pem"));
        let directory_replacement = Event::new(EventKind::Any).add_path(PathBuf::from("/host/tls"));
        let read_open = Event::new(EventKind::Access(AccessKind::Open(AccessMode::Read)))
            .add_path(watched[0].clone());
        let read_close = Event::new(EventKind::Access(AccessKind::Close(AccessMode::Read)))
            .add_path(watched[0].clone());
        let read_close_rescan = Event::new(EventKind::Access(AccessKind::Close(AccessMode::Read)))
            .add_path(watched[0].clone())
            .set_flag(Flag::Rescan);
        let write_close = Event::new(EventKind::Access(AccessKind::Close(AccessMode::Write)))
            .add_path(watched[0].clone());
        let rescan = Event::new(EventKind::Any).set_flag(Flag::Rescan);

        assert!(tls_event_requires_reload(&certificate_change, &watched));
        assert!(tls_event_requires_reload(&directory_replacement, &watched));
        assert!(!tls_event_requires_reload(&read_open, &watched));
        assert!(!tls_event_requires_reload(&read_close, &watched));
        assert!(tls_event_requires_reload(&read_close_rescan, &watched));
        assert!(tls_event_requires_reload(&write_close, &watched));
        assert!(!tls_event_requires_reload(&unrelated_change, &watched));
        assert!(tls_event_requires_reload(&rescan, &watched));
    }

    #[test]
    fn normalizes_dot_segments_and_rejects_parent_traversal() {
        let current_directory = std::env::current_dir()
            .expect("read current directory")
            .join("host-config");
        let certificate =
            absolute_path(Path::new("tls/./certificate.pem"), Some(&current_directory))
                .expect("dot segments are safe");
        let private_key = absolute_path(Path::new("tls/private-key.pem"), Some(&current_directory))
            .expect("ordinary relative path is safe");
        let watched = [certificate.clone(), private_key];
        let equivalent_event = Event::new(EventKind::Any).add_path(
            current_directory
                .join("tls")
                .join(".")
                .join("certificate.pem"),
        );

        assert_eq!(
            certificate,
            current_directory.join("tls").join("certificate.pem")
        );
        assert!(tls_event_requires_reload(&equivalent_event, &watched));

        let root = current_directory
            .ancestors()
            .last()
            .expect("absolute current directory has a root");
        let root_overflow = root
            .join("..")
            .join("..")
            .join("tls")
            .join("certificate.pem");
        assert_eq!(
            comparable_path(&root_overflow),
            Err("TLS material paths must not contain parent traversal (`..`)")
        );
        let relative_parents = Path::new("..")
            .join("..")
            .join("tls")
            .join("certificate.pem");
        assert_eq!(
            absolute_path(&relative_parents, Some(&current_directory)),
            Err("TLS material paths must not contain parent traversal (`..`)")
        );
        assert_eq!(
            absolute_path(&certificate, None),
            Ok(certificate),
            "absolute TLS paths do not require a current directory"
        );
        assert_eq!(
            absolute_path(Path::new("tls/certificate.pem"), None),
            Err("relative TLS material paths require a current directory")
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_drive_relative_tls_paths() {
        assert_eq!(
            absolute_path(
                Path::new(r"C:tls\certificate.pem"),
                Some(Path::new(r"C:\host-config")),
            ),
            Err("TLS material paths must resolve to an absolute path")
        );
    }

    #[cfg(windows)]
    #[test]
    fn matches_windows_watcher_paths_case_insensitively() {
        let watched = [
            PathBuf::from(r"C:\Host\TLS\CERTIFICATE.PEM"),
            PathBuf::from(r"C:\Host\TLS\PRIVATE-KEY.PEM"),
        ];
        let certificate_change =
            Event::new(EventKind::Any).add_path(PathBuf::from(r"c:\host\tls\certificate.pem"));

        assert!(tls_event_requires_reload(&certificate_change, &watched));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retries_a_failed_tls_directory_watch_until_registration_succeeds() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("create TLS watch retry fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict TLS watch retry fixture");
        let directory = root.path().join("temporarily-missing");
        let directories = BTreeSet::from([directory.clone()]);
        let mut watcher = RecommendedWatcher::new(|_| {}, NotifyConfig::default())
            .expect("create real filesystem watcher");

        assert!(
            refresh_tls_directory_watches(&mut watcher, &directories).is_err(),
            "the missing directory must force the initial registration failure"
        );
        let create_directory = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(90)).await;
            fs::create_dir(&directory).expect("restore watched TLS directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("restrict restored TLS directory");
        });

        let attempts = tokio::time::timeout(
            Duration::from_secs(2),
            retry_tls_directory_watches(&mut watcher, &directories),
        )
        .await
        .expect("bounded retry must restore the TLS directory watch");
        create_directory.await.expect("join directory restoration");

        assert!(attempts >= 2, "at least one scheduled retry must fail");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn initial_tls_watch_accepts_an_execute_only_parent_namespace() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("create execute-only watch fixture");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict execute-only watch fixture");
        let ancestor = root.path().join("search-only");
        let boundary = ancestor.join("tls");
        fs::create_dir(&ancestor).expect("create watch ancestor");
        fs::create_dir(&boundary).expect("create watched TLS boundary");
        fs::set_permissions(&boundary, fs::Permissions::from_mode(0o700))
            .expect("restrict watched TLS boundary");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o100))
            .expect("make watch ancestor execute-only");

        let mut parent_watcher = RecommendedWatcher::new(|_| {}, NotifyConfig::default())
            .expect("create parent namespace watcher");
        assert!(
            parent_watcher
                .watch(&ancestor, RecursiveMode::NonRecursive)
                .is_err(),
            "Linux inotify must reject an unreadable parent namespace"
        );
        let mut watcher = RecommendedWatcher::new(|_| {}, NotifyConfig::default())
            .expect("create TLS boundary watcher");
        let installed =
            install_initial_tls_directory_watches(&mut watcher, &BTreeSet::from([boundary]));

        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("restore watch ancestor for fixture cleanup");
        assert!(
            installed.is_ok(),
            "an optional parent watch must not reject a safe TLS boundary"
        );
    }

    #[cfg(all(feature = "test-support", unix))]
    #[tokio::test]
    async fn reconciles_the_startup_gap_and_later_notify_rotation() {
        use satelle_host::{ApiScopes, test_support::TestStateDir};
        use std::net::Ipv4Addr;
        use std::os::unix::fs::PermissionsExt;

        let state = TestStateDir::new().expect("create secure Host state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic Host service");
        let host_identity = service
            .initialize_daemon()
            .expect("initialize Host state")
            .host_identity()
            .to_string();
        let token = ApiBearerToken::generate().expect("generate API token");
        service
            .register_api_token(&token, "principal-cli-tls-reload", ApiScopes::READ, None)
            .expect("register API token");
        let initial = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate initial certificate");
        let replacement = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate replacement certificate");
        let live_rotation = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate live-rotation certificate");
        let directory_rotation = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate directory-rotation certificate");
        let initial_tls = DaemonTlsConfig::from_pem(
            initial.cert.pem().as_bytes(),
            initial.signing_key.serialize_pem().as_bytes(),
        )
        .expect("validate initial TLS configuration");
        let server = DaemonServer::bind_tls(
            service,
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            initial_tls,
        )
        .await
        .expect("bind initial TLS listener");

        // Model a rotation that happened after the daemon's initial read but
        // before watcher registration. No filesystem event can be relied on.
        let tls_root = state.path().join("tls");
        let active_directory = tls_root.join("current");
        fs::create_dir(&tls_root).expect("create TLS namespace");
        fs::create_dir(&active_directory).expect("create active TLS directory");
        fs::set_permissions(&tls_root, fs::Permissions::from_mode(0o700))
            .expect("restrict TLS namespace");
        fs::set_permissions(&active_directory, fs::Permissions::from_mode(0o700))
            .expect("restrict active TLS directory");
        let certificate_path = active_directory.join("certificate.pem");
        let private_key_path = active_directory.join("private-key.pem");
        fs::write(&certificate_path, replacement.cert.pem())
            .expect("write replacement certificate");
        fs::write(&private_key_path, replacement.signing_key.serialize_pem())
            .expect("write replacement private key");
        fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))
            .expect("restrict replacement certificate");
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))
            .expect("restrict replacement private key");

        let watcher = DaemonTlsWatcher::start(
            certificate_path.clone(),
            private_key_path.clone(),
            server
                .tls_reloader()
                .expect("TLS listener exposes its reload handle"),
        )
        .unwrap_or_else(|_| panic!("start TLS file watcher"));
        let url = format!(
            "https://localhost:{}/v1/host/status",
            server.local_addr().port()
        );
        let authorization = format!("Bearer {}", token.expose().as_str());
        let client = reqwest::Client::builder()
            .tls_certs_only([
                reqwest::Certificate::from_pem(replacement.cert.pem().as_bytes())
                    .expect("parse replacement trust root"),
            ])
            .build()
            .expect("build replacement HTTPS client");
        let response = client
            .get(&url)
            .header("Authorization", &authorization)
            .header("Satelle-Expected-Host-Identity", &host_identity)
            .header(
                "Satelle-Request-Id",
                satelle_transport::RequestId::new().to_string(),
            )
            .send()
            .await
            .expect("request Host status with reconciled certificate");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        // A second rotation after watcher startup must travel through notify,
        // the bounded dirty flag, and the background reload task. Leave a
        // mismatched pair visible long enough to exercise failed validation;
        // the later key event must still install the valid pair.
        fs::write(&certificate_path, live_rotation.cert.pem())
            .expect("write live-rotation certificate");
        tokio::time::sleep(Duration::from_millis(150)).await;
        fs::write(&private_key_path, live_rotation.signing_key.serialize_pem())
            .expect("write live-rotation private key");
        let live_client = reqwest::Client::builder()
            .tls_certs_only([
                reqwest::Certificate::from_pem(live_rotation.cert.pem().as_bytes())
                    .expect("parse live-rotation trust root"),
            ])
            .build()
            .expect("build live-rotation HTTPS client");
        let live_response = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(response) = live_client
                    .get(&url)
                    .header("Authorization", &authorization)
                    .header("Satelle-Expected-Host-Identity", &host_identity)
                    .header(
                        "Satelle-Request-Id",
                        satelle_transport::RequestId::new().to_string(),
                    )
                    .send()
                    .await
                    && response.status() == reqwest::StatusCode::OK
                {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("notify must install the live-rotation certificate");

        assert_eq!(live_response.status(), reqwest::StatusCode::OK);

        // Certificate managers may rotate an entire directory atomically. The
        // namespace watch must notice the swap, re-register the new directory,
        // and load the pair now present at the original paths.
        let replacement_directory = tls_root.join("replacement");
        let retired_directory = tls_root.join("retired");
        fs::create_dir(&replacement_directory).expect("create replacement TLS directory");
        fs::set_permissions(&replacement_directory, fs::Permissions::from_mode(0o700))
            .expect("restrict replacement TLS directory");
        let replacement_certificate = replacement_directory.join("certificate.pem");
        let replacement_private_key = replacement_directory.join("private-key.pem");
        fs::write(&replacement_certificate, directory_rotation.cert.pem())
            .expect("write directory-rotation certificate");
        fs::write(
            &replacement_private_key,
            directory_rotation.signing_key.serialize_pem(),
        )
        .expect("write directory-rotation private key");
        fs::set_permissions(&replacement_certificate, fs::Permissions::from_mode(0o600))
            .expect("restrict directory-rotation certificate");
        fs::set_permissions(&replacement_private_key, fs::Permissions::from_mode(0o600))
            .expect("restrict directory-rotation private key");
        fs::rename(&active_directory, &retired_directory).expect("retire active TLS directory");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !active_directory.exists(),
            "reload validation must not recreate a temporarily missing boundary"
        );
        fs::rename(&replacement_directory, &active_directory)
            .expect("install replacement TLS directory");

        let directory_client = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(
                directory_rotation.cert.pem().as_bytes(),
            )
            .expect("parse directory-rotation trust root")])
            .build()
            .expect("build directory-rotation HTTPS client");
        let directory_response = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(response) = directory_client
                    .get(&url)
                    .header("Authorization", &authorization)
                    .header("Satelle-Expected-Host-Identity", &host_identity)
                    .header(
                        "Satelle-Request-Id",
                        satelle_transport::RequestId::new().to_string(),
                    )
                    .send()
                    .await
                    && response.status() == reqwest::StatusCode::OK
                {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("notify must install the atomically replaced TLS directory");

        assert_eq!(directory_response.status(), reqwest::StatusCode::OK);
        drop(watcher);
        server.shutdown().await.expect("stop TLS listener");
    }
}

fn tls_file_failure(kind: &str, path: &std::path::Path, source: String) -> CliFailure {
    failure(SatelleError {
        code: ErrorCode::InvalidUsage,
        message: format!(
            "Host Daemon TLS {kind} '{}' is unavailable or violates the required file security policy",
            path.display()
        ),
        recovery_command: Some(
            "use regular non-symlink TLS files under the Host user's configuration boundary; keep the private key owner-only"
                .to_string(),
        ),
        source_detail: Some(source),
        details: BTreeMap::new(),
    })
}

fn tls_configuration_failure(error: DaemonTlsConfigError) -> CliFailure {
    let code = if error == DaemonTlsConfigError::CertificateExpired {
        ErrorCode::CertificateExpired
    } else {
        ErrorCode::InvalidUsage
    };
    failure(SatelleError {
        code,
        message: format!("Host Daemon TLS configuration is invalid: {error}"),
        recovery_command: Some(
            "replace the certificate chain or private key, then restart the Host Daemon"
                .to_string(),
        ),
        source_detail: None,
        details: BTreeMap::new(),
    })
}

fn read_ssh_bootstrap_token() -> Result<ApiBearerToken, CliFailure> {
    const MAX_BOOTSTRAP_TOKEN_BYTES: u64 = 4096;

    let mut encoded = String::new();
    io::stdin()
        .take(MAX_BOOTSTRAP_TOKEN_BYTES + 1)
        .read_to_string(&mut encoded)
        .map_err(|_| failure(SatelleError::authentication_failed("ssh-bootstrap")))?;
    if encoded.len() as u64 > MAX_BOOTSTRAP_TOKEN_BYTES {
        return Err(failure(SatelleError::authentication_failed(
            "ssh-bootstrap",
        )));
    }
    let encoded = encoded.strip_suffix('\n').unwrap_or(&encoded);
    let encoded = encoded.strip_suffix('\r').unwrap_or(encoded);
    if encoded.contains(['\r', '\n']) {
        return Err(failure(SatelleError::authentication_failed(
            "ssh-bootstrap",
        )));
    }
    ApiBearerToken::parse(encoded)
        .map_err(|_| failure(SatelleError::authentication_failed("ssh-bootstrap")))
}

fn on_demand_idle_timeout(config: &HostConfig) -> Duration {
    config
        .daemon_idle_timeout
        .as_ref()
        .map_or(DEFAULT_ON_DEMAND_IDLE_TIMEOUT, |timeout| {
            Duration::from_millis(timeout.milliseconds())
        })
}

#[cfg(test)]
mod bootstrap_startup_tests {
    use super::*;
    use satelle_host::{ApiScopes, test_support::TestStateDir};
    use std::net::Ipv4Addr;

    fn bootstrap_service(state: &TestStateDir, token: &ApiBearerToken) -> HostService {
        HostService::local_demo_for_tests_at(state.path())
            .expect("construct bootstrap Host service")
            .with_ssh_bootstrap_auth_for_tests(
                token,
                ApiScopes::READ,
                OffsetDateTime::now_utc() + time::Duration::minutes(15),
            )
    }

    #[tokio::test]
    async fn failed_start_host_daemon_does_not_strand_maintenance() {
        const OPERATION_ID: &str = "bind-failure-must-not-acquire";

        let state = TestStateDir::new().expect("create temporary state directory");
        let token = ApiBearerToken::generate().expect("generate bootstrap token");
        let service = bootstrap_service(&state, &token);
        let occupied =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupy a loopback port");
        let address = occupied.local_addr().expect("read occupied address");
        let start_token = ApiBearerToken::parse(token.expose().as_str())
            .expect("parse bootstrap token for failed startup");
        let start_service = service.clone();
        let command = HostStartCommand {
            bind: address.to_string(),
            tls_cert: None,
            tls_key: None,
            foreground: false,
            launchd_service: false,
            bootstrap_token_stdin: true,
            initial_host_identity: None,
            initial_identity_operation_id: None,
            initial_identity_record: None,
            bootstrap_scope: Some(SshBootstrapScope::Read),
            bootstrap_native_readiness_timeout_ms: None,
            bootstrap_provider_smoke_timeout_ms: None,
            on_demand_idle_timeout_ms: Some(75_000),
            setup_ledger_retention_ms: None,
            service_config: None,
            output_args: OutputArgs::default(),
        };
        let start_result = std::thread::spawn(move || {
            start_host_daemon_with(
                command,
                ConfigContext::new(None),
                OutputFormat::Json,
                move || Ok(start_token),
                move |_, _, _, _| start_service,
            )
        })
        .join()
        .expect("join failed startup thread");
        assert!(
            start_result.is_err(),
            "occupied address must reject startup"
        );
        assert!(
            service
                .load_setup_run(OPERATION_ID)
                .expect("read setup ledger after failed bind")
                .is_none(),
            "startup failure must not create a setup run before authenticated begin"
        );

        let host_identity = service
            .initialize_daemon()
            .expect("initialize bootstrap Host after failed bind")
            .host_identity()
            .to_string();
        let (server, _tls_reload_watcher) = bind_host_daemon(
            service.clone(),
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            None,
        )
        .await
        .unwrap_or_else(|_| panic!("bind replacement bootstrap Host"));
        let address = server.local_addr();
        tokio::task::spawn_blocking(move || {
            let client = satelle_transport::DaemonClient::loopback(address, token, host_identity)
                .expect("construct replacement bootstrap client");
            client
                .begin_bootstrap_maintenance(OPERATION_ID, "missing_daemon_repair")
                .expect("later authenticated begin is not blocked by failed startup");
            client
                .complete_bootstrap_maintenance(OPERATION_ID)
                .expect("complete replacement bootstrap maintenance");
        })
        .await
        .expect("join replacement handoff requests");
        assert_eq!(
            service
                .load_setup_run(OPERATION_ID)
                .expect("read replacement setup run")
                .expect("later begin persists setup run")
                .status(),
            satelle_host::SetupRunStatus::Completed
        );
        server
            .shutdown()
            .await
            .expect("stop replacement bootstrap Host");
    }

    #[tokio::test]
    async fn bootstrap_maintenance_starts_only_at_authenticated_begin_and_completes() {
        const OPERATION_ID: &str = "authenticated-handoff";

        let state = TestStateDir::new().expect("create temporary state directory");
        let token = ApiBearerToken::generate().expect("generate bootstrap token");
        let service = bootstrap_service(&state, &token);
        let host_identity = service
            .initialize_daemon()
            .expect("initialize bootstrap Host")
            .host_identity()
            .to_string();
        let server = DaemonServer::bind(
            service.clone(),
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        )
        .await
        .expect("bind bootstrap Host");
        assert!(
            service
                .load_setup_run(OPERATION_ID)
                .expect("read setup ledger before handoff")
                .is_none(),
            "listener readiness alone must not acquire maintenance"
        );

        let address = server.local_addr();
        let raw_token = token.expose();
        let completion_host_identity = host_identity.clone();
        tokio::task::spawn_blocking(move || {
            let client = satelle_transport::DaemonClient::loopback(address, token, host_identity)
                .expect("construct bootstrap client");
            client
                .begin_bootstrap_maintenance(OPERATION_ID, "missing_daemon_repair")
                .expect("begin authenticated bootstrap maintenance");
        })
        .await
        .expect("join begin handoff request");
        assert_eq!(
            service
                .load_setup_run(OPERATION_ID)
                .expect("read begun setup run")
                .expect("begin persists setup run")
                .status(),
            satelle_host::SetupRunStatus::Running
        );

        let address = server.local_addr();
        let completion_token = ApiBearerToken::parse(raw_token.as_str())
            .expect("parse bootstrap token for completion");
        tokio::task::spawn_blocking(move || {
            let client = satelle_transport::DaemonClient::loopback(
                address,
                completion_token,
                completion_host_identity,
            )
            .expect("construct completion bootstrap client");
            client
                .complete_bootstrap_maintenance(OPERATION_ID)
                .expect("complete authenticated bootstrap maintenance");
        })
        .await
        .expect("join complete handoff request");
        assert_eq!(
            service
                .load_setup_run(OPERATION_ID)
                .expect("read completed setup run")
                .expect("completed setup run remains durable")
                .status(),
            satelle_host::SetupRunStatus::Completed
        );
        server.shutdown().await.expect("stop bootstrap Host");
    }
}

#[cfg(test)]
mod on_demand_idle_timeout_tests {
    use super::*;

    #[test]
    fn defaults_to_ten_minutes_and_accepts_an_explicit_host_value() {
        let mut config = satelle_core::SatelleConfig::defaults()
            .hosts
            .remove(LOCAL_DEMO_HOST)
            .expect("built-in local Host config");
        assert_eq!(
            on_demand_idle_timeout(&config),
            Duration::from_secs(10 * 60)
        );

        config.daemon_idle_timeout = Some(
            satelle_core::ExplicitDuration::parse("75s")
                .expect("parse explicit daemon idle timeout"),
        );
        assert_eq!(on_demand_idle_timeout(&config), Duration::from_secs(75));
    }

    #[test]
    fn durable_ssh_launch_keeps_the_bootstrap_state_store() {
        assert!(should_resolve_on_demand_host(false, false, false));
        assert!(!should_resolve_on_demand_host(false, false, true));
        assert!(!should_resolve_on_demand_host(false, true, false));
        assert!(!should_resolve_on_demand_host(false, true, true));
        assert!(!should_resolve_on_demand_host(true, false, false));
    }

    #[test]
    fn durable_ssh_launch_applies_both_forwarded_readiness_timeouts() {
        let timeouts = ssh_launch_readiness_timeouts(Some(2_500), Some(7_500))
            .expect("paired SSH launch timeouts")
            .expect("paired timeouts produce a Host override");
        assert_eq!(
            timeouts
                .native_readiness
                .expect("native readiness timeout")
                .milliseconds(),
            2_500
        );
        assert_eq!(
            timeouts
                .provider_smoke_test
                .expect("provider smoke timeout")
                .milliseconds(),
            7_500
        );
        assert!(
            ssh_launch_readiness_timeouts(None, None)
                .expect("omitted SSH launch timeouts")
                .is_none()
        );
        assert!(ssh_launch_readiness_timeouts(Some(2_500), None).is_err());
    }
}

fn daemon_server_failure(error: DaemonServerError) -> CliFailure {
    if let Some(host_error) = error.host_error() {
        return failure(host_error.clone());
    }

    match error {
        DaemonServerError::SshBootstrapNonLoopbackBind
        | DaemonServerError::NonLoopbackPlaintextBind
        | DaemonServerError::InvalidConnectionLimit
        | DaemonServerError::InvalidShutdownGrace
        | DaemonServerError::InvalidIdleTimeout => {
            failure(SatelleError::invalid_usage(error.to_string()))
        }
        _ => daemon_process_failure(error.code(), error.to_string()),
    }
}

fn daemon_process_failure(code: &str, message: String) -> CliFailure {
    failure(SatelleError {
        code: ErrorCode::RemoteExecution,
        message,
        recovery_command: Some("satelle doctor --scope host --json".to_string()),
        source_detail: None,
        details: BTreeMap::from([(
            "daemon_error_code".to_string(),
            serde_json::Value::String(code.to_string()),
        )]),
    })
}

fn show_host_sessions(
    command: HostSessionsCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let report = read::host_sessions(command.host.as_deref(), command.no_bootstrap, config)?;

    if json {
        print_json(&report).map_err(failure)
    } else {
        println!("Host: {}", report.host);
        println!("Connection: {}", report.connection_mode);
        println!("Bootstrapped: {}", report.bootstrapped);
        println!("Host daemon: {}", report.host_daemon_version);
        for session in &report.sessions {
            println!("Session: {}", session.session_id);
            println!("  User: {}", session.desktop_user);
            println!("  State: {}", session.state);
            println!("  Kind: {}", session.session_kind);
            println!("  Display: {}", session.display_summary);
            println!("  Selected: {}", session.selected_by_current_config);
            println!(
                "  Portable selectors: {}",
                session.portable_selectors.join(", ")
            );
            println!(
                "  Native selectors: {}",
                session.native_selectors.join(", ")
            );
        }
        Ok(())
    }
}

fn apply_current_desktop_selection(report: &mut HostSessionsReport, host: &HostConfig) {
    for session in &mut report.sessions {
        session.selected_by_current_config = false;
    }

    let policy = DesktopSelectionPolicy::from_host_config(host);
    if let Ok(selected) = resolve_desktop_session(report, &policy) {
        let selected_id = selected.session_id.clone();
        if let Some(session) = report
            .sessions
            .iter_mut()
            .find(|session| session.session_id == selected_id)
        {
            session.selected_by_current_config = true;
        }
    }
}

fn resolve_execution_desktop(
    transport: &dyn transport::TransportClient,
    host: &SelectedHost,
) -> Result<(), CliFailure> {
    let policy = DesktopSelectionPolicy::from_host_config(&host.config);
    if !desktop_policy_is_active(&policy) {
        return Ok(());
    }

    let report = transport.host_sessions(true).map_err(failure)?;
    resolve_desktop_session(&report, &policy)
        .map(|_| ())
        .map_err(failure)
}

fn desktop_policy_is_active(policy: &DesktopSelectionPolicy) -> bool {
    policy.desktop_user.is_some() || policy.preference.is_some() || policy.native_selector.is_some()
}

fn run_host_update(
    command: HostUpdateCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    run_host_update_invocation(command.into(), config, format)
}

fn run_host_update_invocation(
    command: HostUpdateInvocation,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    validate_host_update_components(&command.component).map_err(failure)?;
    if command.all_remotes || command.host.len() > 1 {
        return Err(failure(SatelleError::not_implemented(
            "multi-Host update planning belongs to the packet 26 update train",
        )));
    }
    let host = config.resolve_host(command.host.first().map(String::as_str))?;
    let trusted_consent = trusted_profile_allows_mutation(
        config.load()?,
        &host.alias,
        MutationCommandFamily::HostUpdate,
    );
    let includes_all = command.component.iter().any(|component| component == "all");
    let components = command
        .component
        .iter()
        .filter_map(|component| match component.as_str() {
            "host" => Some(satelle_core::host_update::HostUpdateComponent::Host),
            "codex" => Some(satelle_core::host_update::HostUpdateComponent::Codex),
            "all" => None,
            _ => unreachable!("validated update component"),
        })
        .collect::<Vec<_>>();
    let mut report =
        transport::plan_host_update(&host, &command.host_version, &components, includes_all)
            .map_err(failure)?;
    if command.dry_run {
        report = report.into_dry_run();
        if format.is_json() {
            print_json(&report).map_err(failure)?;
        } else if !command.quiet {
            print!("{}", host_update::render_host_update_plan(&report));
        }
        return Ok(());
    }
    if !report.confirmation_required {
        if format.is_json() {
            print_json(&report).map_err(failure)?;
        } else if !command.quiet {
            let has_skipped_targets = report.targets.iter().any(|target| {
                target.disposition == satelle_core::host_update::HostUpdateDisposition::Skipped
            });
            if report.status == satelle_core::host_update::HostUpdateStatus::UpToDate
                && !has_skipped_targets
            {
                println!("Host update status for {}: up to date", report.host);
            } else {
                print!("{}", host_update::render_host_update_plan(&report));
            }
        }
        return Ok(());
    }
    if !format.is_json() && !command.quiet {
        print!("{}", host_update::render_host_update_plan(&report));
    }
    let noninteractive = command.no_input || format.is_json() || !io::stdin().is_terminal();
    let consent_granted = host_update_consent_granted(command.yes, trusted_consent);
    if noninteractive && !consent_granted {
        return Err(failure(SatelleError::setup_consent_required(
            &report.planned_actions,
            host_update_consent_command(&host.alias, &command.component),
        )));
    }
    if !consent_granted {
        let confirmed = cliclack::confirm(format!("Apply the Host update to '{}'?", host.alias))
            .initial_value(false)
            .interact()
            .map_err(|source| {
                failure(setup_interaction_error(
                    "could not read Host update confirmation",
                    source,
                ))
            })?;
        if !confirmed {
            if !command.quiet {
                println!("No changes applied.");
            }
            return Ok(());
        }
    }

    report = transport::apply_host_update(
        &host,
        &command.host_version,
        report,
        &components,
        includes_all,
    )
    .map_err(failure)?;
    if format.is_json() {
        print_json(&report).map_err(failure)
    } else if command.quiet {
        println!(
            "Updated Host '{}': {} actions applied.",
            report.host,
            report.applied_actions.len()
        );
        Ok(())
    } else {
        print!("{}", host_update::render_host_update_result(&report));
        Ok(())
    }
}

const fn host_update_consent_granted(command_yes: bool, trusted_profile: bool) -> bool {
    command_yes || trusted_profile
}

fn host_update_consent_command(host: &str, components: &[String]) -> String {
    let component_selection = components
        .iter()
        .map(|component| format!(" --component {component}"))
        .collect::<String>();
    format!(
        "satelle host update --host {}{component_selection} --no-input --yes --json",
        shell_argument(host)
    )
}

fn validate_host_update_components(raw_components: &[String]) -> Result<(), SatelleError> {
    let has_all = raw_components.iter().any(|component| component == "all");
    if has_all && raw_components.len() > 1 {
        return Err(SatelleError::component_selection_conflict());
    }
    if has_all {
        return Ok(());
    }

    for component in raw_components {
        if !matches!(component.as_str(), "host" | "codex") {
            return Err(SatelleError::unsupported_update_component(component));
        }
    }

    Ok(())
}

#[cfg(test)]
mod host_update_consent_tests {
    use super::*;

    #[test]
    fn trusted_profile_consent_satisfies_both_host_update_confirmation_gates() {
        assert!(host_update_consent_granted(false, true));
        assert!(host_update_consent_granted(true, false));
        assert!(!host_update_consent_granted(false, false));
    }

    #[test]
    fn recovery_command_preserves_the_exact_component_selection() {
        assert_eq!(
            host_update_consent_command("office", &["host".to_string(), "codex".to_string()]),
            "satelle host update --host office --component host --component codex --no-input --yes --json"
        );
        assert_eq!(
            host_update_consent_command("office", &[]),
            "satelle host update --host office --no-input --yes --json"
        );
        assert_eq!(
            host_update_consent_command("remote host'; touch /tmp/pwn", &["host".to_string()]),
            "satelle host update --host 'remote host'\"'\"'; touch /tmp/pwn' --component host --no-input --yes --json"
        );
    }

    #[test]
    fn self_update_remote_handoff_preserves_global_presentation_options() {
        assert_eq!(
            self_update_remote_handoff_arguments(
                Some("work"),
                "office",
                true,
                ErrorFormat::Json,
                true,
                true,
            ),
            [
                "--no-color",
                "--profile",
                "work",
                "--error-format",
                "json",
                "host",
                "update",
                "--host",
                "office",
                "--no-input",
                "--yes",
            ]
        );
        assert_eq!(
            self_update_remote_handoff_arguments(
                None,
                "office",
                false,
                ErrorFormat::Human,
                false,
                false,
            ),
            [
                "--error-format",
                "human",
                "host",
                "update",
                "--host",
                "office",
            ]
        );
    }
}

fn confirm_storage_maintenance(
    planned_actions: &[String],
    recovery_command: String,
    yes: bool,
    no_input: bool,
    format: OutputFormat,
) -> Result<bool, CliFailure> {
    if yes {
        return Ok(true);
    }
    if no_input || format.is_json() || !io::stdin().is_terminal() {
        return Err(failure(SatelleError::setup_consent_required(
            planned_actions,
            recovery_command,
        )));
    }
    cliclack::confirm("Apply these Host storage mutations?")
        .initial_value(false)
        .interact()
        .map_err(|source| {
            failure(setup_interaction_error(
                "could not read Host storage confirmation",
                source,
            ))
        })
}

fn local_storage_state_root(host: &SelectedHost) -> Result<PathBuf, CliFailure> {
    satelle_host::HostService::resolved_daemon_paths_for_host(&host.config)
        .map(|paths| PathBuf::from(paths.state_root))
        .map_err(failure)
}

#[cfg(test)]
#[test]
fn local_storage_state_root_uses_the_selected_hosts_resolved_daemon_home() {
    let state =
        satelle_host::test_support::TestStateDir::new().expect("create local storage path state");
    let daemon_home = state.path().join("configured-daemon-home");
    let mut config = satelle_core::SatelleConfig::defaults()
        .hosts
        .remove(LOCAL_DEMO_HOST)
        .expect("the built-in local Host exists");
    config.daemon_home = Some(daemon_home.clone());
    let mut host = SelectedHost::from(("configured-local".to_string(), config));

    assert_eq!(
        daemon_home.join("state"),
        local_storage_state_root(&host)
            .ok()
            .expect("resolve state under configured daemon home")
    );

    let explicit_state = state.path().join("explicit-state");
    host.config.daemon_state_dir = Some(explicit_state.clone());
    assert_eq!(
        explicit_state,
        local_storage_state_root(&host)
            .ok()
            .expect("prefer the explicit daemon state directory")
    );
}

fn storage_maintenance_mutation_failure(
    mut source: SatelleError,
    recovery_command: &str,
) -> SatelleError {
    // The operator already consented to one exact storage mutation. Keep the
    // source classification and evidence, but make its retry guidance point
    // back to that exact operation instead of a generic storage diagnostic.
    source.recovery_command = Some(recovery_command.to_string());
    source
}

fn offline_storage_completion_recovery_command(
    operation: OfflineStorageOperation,
    host: &str,
    operation_id: &str,
    state_root: &Path,
    backup: Option<&Path>,
    delete_recordings: bool,
) -> String {
    let operation = match operation {
        OfflineStorageOperation::Restore => "restore",
        OfflineStorageOperation::BackupCleanup => "backup-cleanup",
        OfflineStorageOperation::StoreReset => "store-reset",
    };
    let mut command = format!(
        "satelle host offline-storage-maintenance --operation {operation} --host {} --operation-id {} --state-root {}",
        shell_argument(host),
        shell_argument(operation_id),
        shell_argument(&state_root.display().to_string()),
    );
    if let Some(backup) = backup {
        command.push_str(&format!(
            " --backup {}",
            shell_argument(&backup.display().to_string())
        ));
    }
    if delete_recordings {
        command.push_str(" --delete-recordings");
    }
    command.push_str(" --yes --reconcile-completion");
    command
}

fn apply_local_offline_storage_maintenance<T>(
    state_root: &Path,
    action_id: &str,
    action_label: &str,
    recovery_command: &str,
    completion_recovery_command: impl FnOnce(&str) -> String,
    mutate: impl FnOnce() -> Result<T, SatelleError>,
) -> Result<T, CliFailure> {
    let operation_id = format!("storage-maintenance-{}", Uuid::now_v7());
    satelle_host::HostService::start_offline_storage_maintenance(
        state_root,
        &operation_id,
        action_id,
        action_label,
    )
    .map_err(failure)?;
    let result = match mutate() {
        Ok(result) => result,
        Err(source) => {
            let _ = satelle_host::HostService::record_failed_offline_storage_maintenance(
                state_root,
                &operation_id,
                action_id,
            );
            return Err(failure(storage_maintenance_mutation_failure(
                source,
                recovery_command,
            )));
        }
    };
    if let Err(source) = satelle_host::HostService::record_completed_offline_storage_maintenance(
        state_root,
        &operation_id,
        action_id,
        action_label,
    ) {
        let completion_recovery_command = completion_recovery_command(&operation_id);
        return Err(failure(
            SatelleError::storage_maintenance_partially_applied(
                &[action_id.to_string()],
                "record-storage-maintenance-ledger-completion",
                &[],
                completion_recovery_command,
                source.to_string(),
            ),
        ));
    }
    Ok(result)
}

#[cfg(test)]
#[test]
fn local_storage_mutation_failure_keeps_source_evidence_and_exact_retry_command() {
    let source = SatelleError::host_unreachable("local-demo");
    let source_code = source.code;
    let source_details = source.details.clone();
    let retry = "satelle host storage backup cleanup --host local-demo --no-input --yes";

    let error = storage_maintenance_mutation_failure(source, retry);

    assert_eq!(error.code, source_code);
    assert_eq!(error.details, source_details);
    assert_eq!(error.recovery_command.as_deref(), Some(retry));
}

#[cfg(test)]
#[test]
fn storage_completion_recovery_command_preserves_operation_identity() {
    assert_eq!(
        offline_storage_completion_recovery_command(
            OfflineStorageOperation::Restore,
            "remote host",
            "storage-maintenance-exact",
            Path::new("/state root"),
            Some(Path::new("/state root/backup file")),
            false,
        ),
        "satelle host offline-storage-maintenance --operation restore --host 'remote host' --operation-id storage-maintenance-exact --state-root '/state root' --backup '/state root/backup file' --yes --reconcile-completion"
    );
}

#[cfg(test)]
#[test]
fn storage_completion_recovery_reconciles_the_retained_operation_without_restarting_it() {
    let state = satelle_host::test_support::TestStateDir::new()
        .expect("create offline maintenance recovery state");
    let operation_id = "storage-maintenance-completion-recovery";
    let action_id = "cleanup-storage-backups";
    let action_label = "Delete older validated Host storage backups";
    satelle_host::HostService::start_offline_storage_maintenance(
        state.path(),
        operation_id,
        action_id,
        action_label,
    )
    .expect("record the interrupted offline maintenance operation");

    let completion_command = || OfflineStorageMaintenanceCommand {
        operation: OfflineStorageOperation::BackupCleanup,
        host: "local-demo".to_string(),
        operation_id: operation_id.to_string(),
        state_root: state.path().to_path_buf(),
        backup: None,
        delete_recordings: false,
        approved_backup_file_names: Vec::new(),
        yes: true,
        reconcile_completion: true,
    };
    assert!(
        run_offline_storage_maintenance(completion_command()).is_ok(),
        "the retained exact operation must reconcile instead of starting again"
    );
    assert!(
        run_offline_storage_maintenance(completion_command()).is_ok(),
        "repeating exact completion recovery must be idempotent"
    );
}

fn storage_backup_cleanup_actions(
    eligible_backup_file_names: &[String],
    service_recovery_required: bool,
) -> Vec<String> {
    let mut actions = eligible_backup_file_names
        .iter()
        .map(|name| format!("delete validated migration backup {name}"))
        .collect::<Vec<_>>();
    if service_recovery_required {
        actions.push("restart and verify the unavailable Host API service".to_string());
    }
    actions
}

fn run_host_storage(
    command: HostStorageCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    match command {
        HostStorageCommand::Migrate(command) => {
            Err(failure(SatelleError::not_implemented(format!(
                "host storage migration is not implemented yet for host {}",
                command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
            ))))
        }
        HostStorageCommand::Restore(command) => {
            let host = config.resolve_host(command.host.as_deref())?;
            let local_state_root = (host.config.transport == TransportKind::Local)
                .then(|| local_storage_state_root(&host))
                .transpose()?;
            if let Some(state_root) = &local_state_root {
                if command.dry_run {
                    satelle_host::HostService::preview_storage_restore(state_root, &command.backup)
                        .map_err(failure)?;
                } else {
                    satelle_host::HostService::validate_storage_restore(
                        state_root,
                        &command.backup,
                    )
                    .map_err(failure)?;
                }
            } else if command.dry_run {
                transport::preview_ssh_storage_restore(&host, &command.backup).map_err(failure)?;
            } else {
                transport::preflight_ssh_storage_maintenance(&host).map_err(failure)?;
            }
            let planned_actions = vec![
                "verify backup integrity and schema compatibility".to_string(),
                "preserve the failed active store".to_string(),
                "atomically activate the selected backup".to_string(),
            ];
            if command.dry_run {
                return print_storage_plan(&host.alias, "restore", &planned_actions, format);
            }
            let recovery_command = format!(
                "satelle host storage restore --host {} --backup {} --no-input --yes",
                shell_argument(&host.alias),
                shell_argument(&command.backup.display().to_string())
            );
            if !confirm_storage_maintenance(
                &planned_actions,
                recovery_command.clone(),
                command.yes,
                command.no_input,
                format,
            )? {
                return print_storage_cancelled(&host.alias, "restore", format);
            }
            let activation = if let Some(state_root) = &local_state_root {
                serde_json::to_value(apply_local_offline_storage_maintenance(
                    state_root,
                    "restore-storage-backup",
                    "Restore the validated Host storage backup",
                    &recovery_command,
                    |operation_id| {
                        offline_storage_completion_recovery_command(
                            OfflineStorageOperation::Restore,
                            &host.alias,
                            operation_id,
                            state_root,
                            Some(&command.backup),
                            false,
                        )
                    },
                    || {
                        satelle_host::HostService::restore_storage_backup_offline(
                            state_root,
                            &command.backup,
                        )
                    },
                )?)
                .map_err(|error| {
                    failure(SatelleError::invalid_usage(format!(
                        "could not serialize storage restore result: {error}"
                    )))
                })?
            } else {
                let mut activation = transport::apply_ssh_storage_maintenance(
                    &host,
                    transport::SshStorageMaintenance::Restore,
                    Some(&command.backup),
                    false,
                    &[],
                )
                .map_err(failure)?;
                activation
                    .as_object_mut()
                    .ok_or_else(|| failure(SatelleError::state_conflict()))?
                    .insert("api_service_restarted".to_string(), json!(true));
                activation
            };
            print_storage_result(
                &host.alias,
                "restore",
                activation,
                true,
                &["restore-storage-backup"],
                format,
            )
        }
        HostStorageCommand::Backup {
            command: HostStorageBackupCommand::Cleanup(command),
        } => {
            let host = config.resolve_host(command.host.as_deref())?;
            let local_state_root = (host.config.transport == TransportKind::Local)
                .then(|| local_storage_state_root(&host))
                .transpose()?;
            let (cleanup_plan, service_recovery_required) =
                if let Some(state_root) = &local_state_root {
                    (
                        satelle_host::HostService::plan_storage_backup_cleanup(state_root)
                            .map_err(failure)?,
                        false,
                    )
                } else {
                    transport::plan_ssh_storage_backup_cleanup(&host).map_err(failure)?
                };
            let planned_actions = storage_backup_cleanup_actions(
                &cleanup_plan.eligible_backup_file_names,
                service_recovery_required,
            );
            if command.dry_run {
                return print_storage_plan(&host.alias, "backup_cleanup", &planned_actions, format);
            }
            if planned_actions.is_empty() {
                return print_storage_result(
                    &host.alias,
                    "backup_cleanup",
                    json!({"removed_backup_file_names": []}),
                    false,
                    &[],
                    format,
                );
            }
            let recovery_command = format!(
                "satelle host storage backup cleanup --host {} --no-input --yes",
                shell_argument(&host.alias)
            );
            if !confirm_storage_maintenance(
                &planned_actions,
                recovery_command.clone(),
                command.yes,
                command.no_input,
                format,
            )? {
                return print_storage_cancelled(&host.alias, "backup_cleanup", format);
            }
            let cleanup = if let Some(state_root) = &local_state_root {
                let removed_backup_file_names = apply_local_offline_storage_maintenance(
                    state_root,
                    "cleanup-storage-backups",
                    "Delete older validated Host storage backups",
                    &recovery_command,
                    |operation_id| {
                        offline_storage_completion_recovery_command(
                            OfflineStorageOperation::BackupCleanup,
                            &host.alias,
                            operation_id,
                            state_root,
                            None,
                            false,
                        )
                    },
                    || {
                        satelle_host::HostService::cleanup_planned_storage_backups_offline(
                            state_root,
                            &cleanup_plan.eligible_backup_file_names,
                            &recovery_command,
                        )
                    },
                )?;
                json!({"removed_backup_file_names": removed_backup_file_names})
            } else {
                transport::apply_ssh_storage_maintenance(
                    &host,
                    transport::SshStorageMaintenance::BackupCleanup,
                    None,
                    false,
                    &cleanup_plan.eligible_backup_file_names,
                )
                .map_err(failure)?
            };
            let changed = cleanup
                .get("removed_backup_file_names")
                .and_then(Value::as_array)
                .is_some_and(|removed| !removed.is_empty())
                || service_recovery_required;
            print_storage_result(
                &host.alias,
                "backup_cleanup",
                cleanup,
                changed,
                &["cleanup-storage-backups"],
                format,
            )
        }
    }
}

fn run_host_store(
    command: HostStoreCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    match command {
        HostStoreCommand::Reset(command) => {
            let host = config.resolve_host(command.host.as_deref())?;
            let local_state_root = (host.config.transport == TransportKind::Local)
                .then(|| local_storage_state_root(&host))
                .transpose()?;
            if local_state_root.is_none() {
                transport::preflight_ssh_storage_maintenance(&host).map_err(failure)?;
            }
            let mut planned_actions = vec![
                "delete Host metadata from the SQLite store".to_string(),
                "preserve Host recordings".to_string(),
            ];
            if command.delete_recordings {
                planned_actions[1] = "delete Host recordings explicitly".to_string();
            }
            if command.dry_run {
                return print_storage_plan(&host.alias, "store_reset", &planned_actions, format);
            }
            let recovery_command = format!(
                "satelle host store reset --host {}{} --no-input --yes",
                shell_argument(&host.alias),
                if command.delete_recordings {
                    " --delete-recordings"
                } else {
                    ""
                }
            );
            if !confirm_storage_maintenance(
                &planned_actions,
                recovery_command.clone(),
                command.yes,
                command.no_input,
                format,
            )? {
                return print_storage_cancelled(&host.alias, "store_reset", format);
            }
            let reset = if let Some(state_root) = &local_state_root {
                serde_json::to_value(apply_local_offline_storage_maintenance(
                    state_root,
                    "reset-host-store",
                    "Reset Host metadata",
                    &recovery_command,
                    |operation_id| {
                        offline_storage_completion_recovery_command(
                            OfflineStorageOperation::StoreReset,
                            &host.alias,
                            operation_id,
                            state_root,
                            None,
                            command.delete_recordings,
                        )
                    },
                    || {
                        satelle_host::HostService::reset_store_metadata_offline(
                            state_root,
                            command.delete_recordings,
                            &recovery_command,
                        )
                    },
                )?)
                .map_err(|error| {
                    failure(SatelleError::invalid_usage(format!(
                        "could not serialize store reset result: {error}"
                    )))
                })?
            } else {
                let mut reset = transport::apply_ssh_storage_maintenance(
                    &host,
                    transport::SshStorageMaintenance::StoreReset,
                    None,
                    command.delete_recordings,
                    &[],
                )
                .map_err(failure)?;
                reset
                    .as_object_mut()
                    .ok_or_else(|| failure(SatelleError::state_conflict()))?
                    .insert("api_service_restarted".to_string(), json!(true));
                reset
            };
            let changed = reset
                .get("removed_metadata_file_names")
                .and_then(Value::as_array)
                .is_some_and(|removed| !removed.is_empty())
                || reset
                    .get("recordings_deleted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            print_storage_result(
                &host.alias,
                "store_reset",
                reset,
                changed,
                &["reset-host-store"],
                format,
            )
        }
    }
}

fn run_offline_storage_maintenance(
    command: OfflineStorageMaintenanceCommand,
) -> Result<(), CliFailure> {
    if !command.yes {
        return Err(failure(SatelleError::invalid_usage(
            "offline storage maintenance requires explicit --yes authorization",
        )));
    }
    let (action_id, action_label) = match command.operation {
        OfflineStorageOperation::Restore => (
            "restore-storage-backup",
            "Restore the validated Host storage backup",
        ),
        OfflineStorageOperation::BackupCleanup => (
            "cleanup-storage-backups",
            "Delete older validated Host storage backups",
        ),
        OfflineStorageOperation::StoreReset => ("reset-host-store", "Reset Host metadata"),
    };
    let backup = match command.operation {
        OfflineStorageOperation::Restore => Some(command.backup.as_deref().ok_or_else(|| {
            failure(SatelleError::invalid_usage(
                "offline storage restore requires --backup",
            ))
        })?),
        OfflineStorageOperation::BackupCleanup | OfflineStorageOperation::StoreReset => {
            if command.backup.is_some() {
                return Err(failure(SatelleError::invalid_usage(
                    "only offline storage restore accepts --backup",
                )));
            }
            None
        }
    };
    if !matches!(command.operation, OfflineStorageOperation::BackupCleanup)
        && !command.approved_backup_file_names.is_empty()
    {
        return Err(failure(SatelleError::invalid_usage(
            "only offline backup cleanup accepts --approved-backup",
        )));
    }
    let recovery_command = match command.operation {
        OfflineStorageOperation::Restore => format!(
            "satelle host storage restore --host {} --backup {} --no-input --yes",
            shell_argument(&command.host),
            shell_argument(
                &backup
                    .expect("validated restore backup")
                    .display()
                    .to_string()
            )
        ),
        OfflineStorageOperation::BackupCleanup => format!(
            "satelle host storage backup cleanup --host {} --no-input --yes",
            shell_argument(&command.host)
        ),
        OfflineStorageOperation::StoreReset => format!(
            "satelle host store reset --host {}{} --no-input --yes",
            shell_argument(&command.host),
            if command.delete_recordings {
                " --delete-recordings"
            } else {
                ""
            }
        ),
    };
    if command.reconcile_completion {
        satelle_host::HostService::record_completed_offline_storage_maintenance(
            &command.state_root,
            &command.operation_id,
            action_id,
            action_label,
        )
        .map_err(failure)?;
        return print_json(&json!({
            "operation_id": command.operation_id,
            "status": "completed",
            "reconciled": true,
        }))
        .map_err(failure);
    }
    satelle_host::HostService::start_offline_storage_maintenance(
        &command.state_root,
        &command.operation_id,
        action_id,
        action_label,
    )
    .map_err(failure)?;
    let mutation = match command.operation {
        OfflineStorageOperation::Restore => {
            satelle_host::HostService::restore_storage_backup_offline(
                &command.state_root,
                backup.expect("validated restore backup"),
            )
            .and_then(|result| {
                serde_json::to_value(result).map_err(|error| {
                    SatelleError::invalid_usage(format!(
                        "could not serialize storage restore result: {error}"
                    ))
                })
            })
        }
        OfflineStorageOperation::BackupCleanup => {
            satelle_host::HostService::cleanup_planned_storage_backups_offline(
                &command.state_root,
                &command.approved_backup_file_names,
                &recovery_command,
            )
            .map(|removed_backup_file_names| {
                json!({"removed_backup_file_names": removed_backup_file_names})
            })
        }
        OfflineStorageOperation::StoreReset => {
            satelle_host::HostService::reset_store_metadata_offline(
                &command.state_root,
                command.delete_recordings,
                &recovery_command,
            )
            .and_then(|result| {
                serde_json::to_value(result).map_err(|error| {
                    SatelleError::invalid_usage(format!(
                        "could not serialize store reset result: {error}"
                    ))
                })
            })
        }
    };
    let result = match mutation {
        Ok(result) => result,
        Err(source) => {
            let _ = satelle_host::HostService::record_failed_offline_storage_maintenance(
                &command.state_root,
                &command.operation_id,
                action_id,
            );
            let _ = print_json(&json!({"error": &source}));
            return Err(failure(source));
        }
    };
    if let Err(source) = satelle_host::HostService::record_completed_offline_storage_maintenance(
        &command.state_root,
        &command.operation_id,
        action_id,
        action_label,
    ) {
        let completion_recovery_command = offline_storage_completion_recovery_command(
            command.operation,
            &command.host,
            &command.operation_id,
            &command.state_root,
            backup,
            command.delete_recordings,
        );
        return Err(failure(
            SatelleError::storage_maintenance_partially_applied(
                &[action_id.to_string()],
                "record-storage-maintenance-ledger-completion",
                &[],
                completion_recovery_command,
                source.to_string(),
            ),
        ));
    }
    print_json(&result).map_err(failure)
}

fn run_offline_storage_backup_cleanup_plan(
    command: OfflineStorageBackupCleanupPlanCommand,
) -> Result<(), CliFailure> {
    let plan = satelle_host::HostService::plan_storage_backup_cleanup(&command.state_root)
        .map_err(failure)?;
    print_json(&plan).map_err(failure)
}

fn run_offline_storage_restore_preview(
    command: OfflineStorageRestorePreviewCommand,
) -> Result<(), CliFailure> {
    satelle_host::HostService::preview_storage_restore(&command.state_root, &command.backup)
        .map_err(failure)?;
    print_json(&json!({"valid": true})).map_err(failure)
}

#[cfg(test)]
#[test]
fn direct_offline_storage_mutation_requires_explicit_authorization() {
    let state = satelle_host::test_support::TestStateDir::new()
        .expect("create unauthorized offline maintenance state");
    let operation_id = "unauthorized-offline-storage-maintenance";
    let failure = run_offline_storage_maintenance(OfflineStorageMaintenanceCommand {
        operation: OfflineStorageOperation::BackupCleanup,
        host: "local-demo".to_string(),
        operation_id: operation_id.to_string(),
        state_root: state.path().to_path_buf(),
        backup: None,
        delete_recordings: false,
        approved_backup_file_names: Vec::new(),
        yes: false,
        reconcile_completion: false,
    })
    .expect_err("reject a hidden offline mutation without explicit authorization");

    assert_eq!(ErrorCode::InvalidUsage, failure.error.code);
    assert!(
        !state.path().join("satelle.sqlite3").exists(),
        "authorization must be checked before the operation is persisted"
    );
}

fn print_storage_plan(
    host: &str,
    operation: &str,
    planned_actions: &[String],
    format: OutputFormat,
) -> Result<(), CliFailure> {
    if format.is_json() {
        print_json(&json!({
            "schema_version": "satelle.host.storage.v1",
            "host": host,
            "operation": operation,
            "status": "planned",
            "changed": false,
            "planned_actions": planned_actions,
            "applied_actions": [],
            "cancellation_reason": null,
            "result": null
        }))
        .map_err(failure)
    } else {
        println!("Host: {host}");
        println!("Operation: {operation}");
        for action in planned_actions {
            println!("- {action}");
        }
        Ok(())
    }
}

fn print_storage_cancelled(
    host: &str,
    operation: &str,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    if format.is_json() {
        print_json(&json!({
            "schema_version": "satelle.host.storage.v1",
            "host": host,
            "operation": operation,
            "status": "cancelled",
            "changed": false,
            "planned_actions": [],
            "applied_actions": [],
            "cancellation_reason": "user_declined_confirmation",
            "result": null
        }))
        .map_err(failure)
    } else {
        println!("No changes applied.");
        Ok(())
    }
}

fn print_storage_result(
    host: &str,
    operation: &str,
    result: Value,
    changed: bool,
    applied_actions: &[&str],
    format: OutputFormat,
) -> Result<(), CliFailure> {
    if format.is_json() {
        print_json(&json!({
            "schema_version": "satelle.host.storage.v1",
            "host": host,
            "operation": operation,
            "status": "applied",
            "changed": changed,
            "planned_actions": [],
            "applied_actions": applied_actions,
            "cancellation_reason": null,
            "result": result
        }))
        .map_err(failure)
    } else {
        println!("Host: {host}");
        println!("Operation: {operation}");
        println!("Status: applied");
        Ok(())
    }
}

fn run_self(
    command: SelfSubcommand,
    config: ConfigContext<'_>,
    output: OutputFormat,
    no_color: bool,
    error_format: ErrorFormat,
) -> Result<(), CliFailure> {
    match command {
        SelfSubcommand::Update(command) => {
            if command.concurrency == 0 || command.concurrency > 16 {
                return Err(failure(SatelleError::concurrency_limit_exceeded(
                    command.concurrency,
                )));
            }

            if !command.update_remotes {
                if command.yes {
                    return Err(failure(SatelleError::invalid_usage(
                        "--yes requires --update-remotes",
                    )));
                }
                if command.concurrency != 4 {
                    return Err(failure(SatelleError::concurrency_without_remote_update()));
                }

                if command.all_remotes || !command.host.is_empty() {
                    return Err(failure(SatelleError::invalid_usage(
                        "--host and --all-remotes require --update-remotes",
                    )));
                }
            } else {
                if command.all_remotes || !command.host.is_empty() || command.concurrency != 4 {
                    return Err(failure(SatelleError::not_implemented(
                        "explicit remote selectors and concurrency belong to the packet 26 update train",
                    )));
                }
                if command.dry_run || output.is_json() {
                    return Err(failure(SatelleError::not_implemented(
                        "configured-remote dry-run and JSON summaries belong to the packet 26 update train",
                    )));
                }
            }

            let remote_host_handoff_supported =
                self_update::remote_host_handoff_supported(command.version.as_deref())
                    .map_err(|error| failure(error.into_satelle_error()))?;
            if command.update_remotes && !remote_host_handoff_supported {
                return Err(failure(SatelleError::invalid_usage(
                    "prerelease self-updates cannot be combined with --update-remotes; update the local CLI without a Host handoff",
                )));
            }

            let current_host = std::env::var("SATELLE_HOST")
                .ok()
                .filter(|host| !host.is_empty());
            let remote_choices = match config.load() {
                Ok(resolved) => self_update::remote_host_choices(
                    current_host.as_deref(),
                    resolved.config.default_host.as_deref(),
                    resolved
                        .config
                        .hosts
                        .iter()
                        .filter(|(_, host)| host.transport != satelle_core::TransportKind::Local)
                        .map(|(alias, _)| alias.clone()),
                ),
                Err(error) if command.update_remotes => return Err(error),
                // Configured-Host discovery is optional for a local update. A
                // broken Host config must not prevent installing a CLI that can
                // understand or repair that config.
                Err(_) => Vec::new(),
            };
            let follow_up_host =
                self_update::selected_remote_host(&remote_choices).map(str::to_owned);
            if command.update_remotes && follow_up_host.is_none() {
                return Err(failure(SatelleError::not_implemented(
                    "--update-remotes could not resolve a current or configured default Host; explicit selectors belong to the packet 26 update train",
                )));
            }

            let stdin_is_terminal = io::stdin().is_terminal();
            if command.update_remotes && (command.no_input || !stdin_is_terminal) && !command.yes {
                return Err(failure(SatelleError::setup_consent_required(
                    &["update the selected configured remote Host".to_string()],
                    "satelle self update --update-remotes --no-input --yes".to_string(),
                )));
            }
            let interactive_offer_candidate = !command.update_remotes
                && !command.no_input
                && stdin_is_terminal
                && !output.is_json()
                && !command.dry_run
                && remote_host_handoff_supported;
            let request = self_update::SelfUpdateRequest::current(
                command.version,
                command.dry_run,
                if interactive_offer_candidate
                    || command.update_remotes
                    || !remote_host_handoff_supported
                {
                    None
                } else {
                    follow_up_host.clone()
                },
            )
            .map_err(|error| failure(error.into_satelle_error()))?;
            let report =
                self_update::run(request).map_err(|error| failure(error.into_satelle_error()))?;
            if output.is_json() {
                print_json(&report).map_err(failure)?;
            } else {
                for line in report.human_lines() {
                    println!("{line}");
                }
            }

            let selected_host = if command.update_remotes {
                follow_up_host
            } else if remote_host_handoff_supported
                && report.should_offer_remote_update(
                    command.no_input,
                    stdin_is_terminal,
                    output.is_json(),
                    command.dry_run,
                )
            {
                prompt_remote_host_update(&remote_choices)?
            } else {
                None
            };

            let Some(host) = selected_host else {
                return Ok(());
            };
            run_self_update_remote_handoff(
                report.installed_executable(),
                config.flag_profile,
                &host,
                no_color,
                error_format,
                command.no_input,
                command.yes,
            )
        }
    }
}

fn self_update_remote_handoff_arguments(
    profile: Option<&str>,
    host: &str,
    no_color: bool,
    error_format: ErrorFormat,
    no_input: bool,
    yes: bool,
) -> Vec<String> {
    let mut arguments = Vec::new();
    if no_color {
        arguments.push("--no-color".to_string());
    }
    if let Some(profile) = profile {
        arguments.extend(["--profile".to_string(), profile.to_string()]);
    }
    arguments.extend([
        "--error-format".to_string(),
        match error_format {
            ErrorFormat::Human => "human",
            ErrorFormat::Json => "json",
        }
        .to_string(),
    ]);
    arguments.extend([
        "host".to_string(),
        "update".to_string(),
        "--host".to_string(),
        host.to_string(),
    ]);
    if no_input {
        arguments.push("--no-input".to_string());
    }
    if yes {
        arguments.push("--yes".to_string());
    }
    arguments
}

fn run_self_update_remote_handoff(
    installed_executable: &Path,
    profile: Option<&str>,
    host: &str,
    no_color: bool,
    error_format: ErrorFormat,
    no_input: bool,
    yes: bool,
) -> Result<(), CliFailure> {
    io::stdout().flush().map_err(|error| {
        failure(SatelleError {
            code: ErrorCode::SelfUpdateFailed,
            message: "could not flush self-update output before remote handoff".to_string(),
            recovery_command: Some(self_update::host_update_command(host)),
            source_detail: Some(error.to_string()),
            details: BTreeMap::from([("host".to_string(), json!(host))]),
        })
    })?;
    let status = ProcessCommand::new(installed_executable)
        .args(self_update_remote_handoff_arguments(
            profile,
            host,
            no_color,
            error_format,
            no_input,
            yes,
        ))
        .status()
        .map_err(|error| {
            failure(SatelleError {
                code: ErrorCode::SelfUpdateFailed,
                message: "could not start the updated Satelle executable".to_string(),
                recovery_command: Some(self_update::host_update_command(host)),
                source_detail: Some(error.to_string()),
                details: BTreeMap::from([("host".to_string(), json!(host))]),
            })
        })?;
    if status.success() {
        return Ok(());
    }

    // The re-executed binary already emitted its typed Host update failure.
    // Preserve that single diagnostic while returning the remote execution class.
    Err(reported_failure(SatelleError {
        code: ErrorCode::RemoteExecution,
        message: "the updated Satelle executable could not complete the remote Host update"
            .to_string(),
        recovery_command: Some(self_update::host_update_command(host)),
        source_detail: None,
        details: BTreeMap::from([
            ("host".to_string(), json!(host)),
            ("child_exit_code".to_string(), json!(status.code())),
        ]),
    }))
}

fn prompt_remote_host_update(
    choices: &[self_update::RemoteHostChoice],
) -> Result<Option<String>, CliFailure> {
    if choices.is_empty() {
        return Ok(None);
    }

    let mut items = choices
        .iter()
        .map(|choice| {
            (
                Some(choice.alias.clone()),
                choice.alias.clone(),
                if choice.selected { "preselected" } else { "" }.to_string(),
            )
        })
        .collect::<Vec<_>>();
    items.push((
        None,
        "Not now".to_string(),
        "leave remote Hosts unchanged".to_string(),
    ));
    let initial = self_update::selected_remote_host(choices).map(str::to_owned);
    cliclack::select("Check and update a configured remote Host?")
        .items(&items)
        .initial_value(initial)
        .interact()
        .map_err(|source| {
            failure(setup_interaction_error(
                "could not read configured remote Host selection",
                source,
            ))
        })
}

fn run_support(command: SupportCommand) -> Result<(), CliFailure> {
    match command {
        SupportCommand::Bundle(command) => Err(failure(SatelleError::not_implemented(format!(
            "support bundle export is not implemented yet{}",
            command
                .output
                .as_ref()
                .map(|path| format!(" for output {}", path.display()))
                .unwrap_or_default()
        )))),
    }
}

fn report_not_admitted<T>(
    event_output: &mut TurnEventOutput,
    explicit_host_alias: Option<&str>,
    operation: Result<T, CliFailure>,
) -> Result<T, CliFailure> {
    match operation {
        Ok(value) => Ok(value),
        Err(cli_failure) => {
            if let Some(host_alias) = explicit_host_alias.filter(|alias| !alias.is_empty()) {
                event_output
                    .emit_command_failed(
                        host_alias,
                        &cli_failure.error,
                        TurnAdmissionPhase::NotAdmitted,
                        None,
                    )
                    .map_err(failure)?;
            }
            Err(cli_failure)
        }
    }
}

fn load_image_attachments(
    paths: &[PathBuf],
    supported_media_types: Vec<String>,
) -> Result<Vec<satelle_transport::ImageAttachment>, CliFailure> {
    use base64::Engine as _;
    use sha2::Digest as _;

    if paths.len() > satelle_transport::MAX_IMAGE_ATTACHMENT_COUNT {
        return Err(failure(SatelleError::invalid_usage(
            "at most two image attachments may be supplied",
        )));
    }
    if !paths.is_empty() && supported_media_types.is_empty() {
        return Err(failure(SatelleError::invalid_usage(
            "the selected Host does not advertise image attachment support",
        )));
    }

    let mut total = 0_usize;
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let number = index + 1;
            let bytes = satelle_core::read_bounded_regular_file_no_follow(
                path,
                satelle_transport::MAX_IMAGE_ATTACHMENT_BYTES,
            )
            .map_err(|error| match error {
                satelle_core::SecureFileError::TooLarge => {
                    image_input_error(number, "exceeds the per-image byte limit")
                }
                _ => image_input_error(number, "is unavailable or unsafe"),
            })?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| image_input_error(number, "exceeds the aggregate byte limit"))?;
            if total > satelle_transport::MAX_IMAGE_ATTACHMENT_BYTES_TOTAL {
                return Err(image_input_error(
                    number,
                    "exceeds the aggregate byte limit",
                ));
            }
            let media_type = sniff_local_image_media_type(&bytes)
                .ok_or_else(|| image_input_error(number, "has an unsupported media type"))?;
            if !supported_media_types
                .iter()
                .any(|value| value == media_type)
            {
                return Err(image_input_error(
                    number,
                    "is not supported by the selected Host",
                ));
            }
            let digest = sha2::Sha256::digest(&bytes);
            let sha256: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            let data_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(satelle_transport::ImageAttachment::new(
                media_type,
                bytes.len() as u64,
                sha256,
                data_base64,
            ))
        })
        .collect()
}

fn image_input_error(number: usize, reason: &str) -> CliFailure {
    failure(SatelleError::invalid_usage(format!(
        "image attachment {number} {reason}"
    )))
}

fn sniff_local_image_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else {
        None
    }
}

#[test]
fn image_loader_accepts_a_relative_png_with_truthful_metadata() {
    use base64::Engine as _;
    use sha2::Digest as _;

    let directory = tempfile::tempdir_in(".").expect("create image fixture directory");
    let path = directory.path().join("fixture.png");
    let bytes = b"\x89PNG\r\n\x1a\nfixture";
    std::fs::write(&path, bytes).expect("write image fixture");
    let path = path
        .strip_prefix(std::env::current_dir().expect("resolve Controller cwd"))
        .expect("fixture is inside the Controller cwd")
        .to_path_buf();
    assert!(!path.is_absolute());

    let attachments = match load_image_attachments(&[path], vec!["image/png".to_string()]) {
        Ok(attachments) => attachments,
        Err(_) => panic!("load supported image fixture"),
    };

    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].media_type(), "image/png");
    assert_eq!(attachments[0].size_bytes(), bytes.len() as u64);
    assert_eq!(
        attachments[0].data_base64(),
        base64::engine::general_purpose::STANDARD.encode(bytes)
    );
    assert_eq!(
        attachments[0].sha256(),
        sha2::Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
}

#[test]
fn image_loader_rejects_parent_traversal_before_file_access() {
    assert!(
        load_image_attachments(
            &[PathBuf::from("../PRIVATE_PATH_MUST_NOT_BE_READ.png")],
            vec!["image/png".to_string()]
        )
        .is_err()
    );
}

#[test]
fn image_loader_checks_the_count_before_reading_files() {
    let paths = vec![PathBuf::from("not-read"); satelle_transport::MAX_IMAGE_ATTACHMENT_COUNT + 1];

    assert!(load_image_attachments(&paths, vec!["image/png".to_string()]).is_err());
}

#[cfg(unix)]
#[test]
fn image_loader_rejects_symlinks() {
    let directory = tempfile::tempdir().expect("create image fixture directory");
    let target = directory.path().join("target.png");
    let link = directory.path().join("private-link.png");
    std::fs::write(&target, b"\x89PNG\r\n\x1a\nfixture").expect("write image fixture");
    std::os::unix::fs::symlink(&target, &link).expect("create image fixture symlink");
    let link = directory
        .path()
        .canonicalize()
        .expect("canonicalize fixture directory")
        .join("private-link.png");

    assert!(load_image_attachments(&[link], vec!["image/png".to_string()]).is_err());
}

#[test]
fn image_loader_rejects_unsupported_media_and_oversized_files() {
    let directory = tempfile::tempdir_in(".").expect("create image fixture directory");
    let cwd = std::env::current_dir().expect("resolve Controller cwd");

    let unsupported = directory.path().join("unsupported.gif");
    std::fs::write(&unsupported, b"GIF89a-private").expect("write unsupported image");
    let unsupported = unsupported
        .strip_prefix(&cwd)
        .expect("fixture is inside Controller cwd")
        .to_path_buf();
    assert!(
        load_image_attachments(
            &[unsupported],
            vec!["image/png".to_string(), "image/jpeg".to_string()],
        )
        .is_err()
    );

    let oversized = directory.path().join("oversized.png");
    let file = std::fs::File::create(&oversized).expect("create oversized image");
    file.set_len((satelle_transport::MAX_IMAGE_ATTACHMENT_BYTES + 1) as u64)
        .expect("size oversized image");
    let oversized = oversized
        .strip_prefix(&cwd)
        .expect("fixture is inside Controller cwd")
        .to_path_buf();
    assert!(load_image_attachments(&[oversized], vec!["image/png".to_string()]).is_err());
}

#[test]
fn turn_request_construction_carries_provider_aliases_refresh_and_one_shot_opt_in() {
    let candidate =
        ProviderBindingAuthorization::new("vision", "anthropic", "claude-sonnet", "anthropic")
            .with_endpoint("https://provider.example.test")
            .with_auth_source(ProviderSecretSource::Environment {
                variable: "ANTHROPIC_API_KEY".to_string(),
            })
            .with_experimental_provider_computer_use(true);
    let selection = ProviderSelection {
        requested_model_alias: Some("vision".to_string()),
        requested_provider_alias: Some("anthropic".to_string()),
        model_alias_from_project: true,
        provider_alias_from_project: false,
        authorization: Some(candidate),
        auth_source_name: None,
        experimental_provider_computer_use: true,
    };

    // `quiet` is deliberately absent from this request boundary. It controls
    // presentation only and cannot remove binding or smoke-test requirements.
    let request = build_turn_request(
        "inspect the desktop".to_string(),
        TurnExecutionMode::Standard,
        &selection,
        true,
        satelle_core::DEFAULT_TURN_EXECUTION_TIMEOUT_MS,
    );

    assert_eq!(
        serde_json::to_value(request).expect("TurnRequest should serialize"),
        json!({
            "schema_version": "satelle.api.v7",
            "prompt": "inspect the desktop",
            "execution_mode": "standard",
            "model": "vision",
            "provider": "anthropic",
            "model_from_project": true,
            "provider_from_project": false,
            "refresh_provider_smoke_test": true,
            "experimental_provider_computer_use": true,
            "turn_execution_timeout_ms": satelle_core::DEFAULT_TURN_EXECUTION_TIMEOUT_MS,
        })
    );
}

fn print_experimental_provider_warning(
    validation: &transport::ProviderDescriptorValidationReport,
    quiet: bool,
    machine_output: bool,
) {
    let binding = &validation.resolved_binding;
    if binding.experimental_provider_computer_use()
        && !quiet
        && !machine_output
        && (!binding.model_provider().eq_ignore_ascii_case("openai")
            || binding.endpoint().is_some())
    {
        eprintln!(
            "Warning: non-OpenAI provider Computer Use is experimental and requires a live provider smoke test when no matching cached pass exists."
        );
    }
}

fn run_prompt(
    command: RunCommand,
    config_context: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<SessionId, CliFailure> {
    let json = format.is_json();
    validate_interrupt_mode(command.detach, command.detach_on_interrupt)?;
    validate_event_mode(command.detach, command.events)?;
    let effective_mode = effective_event_mode(command.events, command.detach, command.quiet, json);
    let mut event_output = TurnEventOutput::new(effective_mode, command.verbose);
    let explicit_host_alias = command.host.as_deref();
    let prompt = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        read_prompt(command.prompt, command.prompt_file),
    )?;
    let config = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        config_context.load(),
    )?;
    let host = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        config
            .resolve_host_with_project_source(explicit_host_alias)
            .map(SelectedHost::from)
            .map_err(failure),
    )?;
    let provider_selection = report_not_admitted(
        &mut event_output,
        Some(&host.alias),
        resolve_provider_selection(
            config,
            &host,
            command.model.as_deref(),
            command.provider.as_deref(),
            command.experimental_provider_computer_use,
            false,
        ),
    )?;
    let transport = match transport_for(&host) {
        Ok(transport) => transport,
        Err(transport_failure) => {
            if !command.detach {
                event_output
                    .emit_preflight(
                        &host,
                        "run",
                        config,
                        &provider_selection,
                        None,
                        command.refresh_provider_smoke_test,
                    )
                    .map_err(failure)?;
                event_output
                    .emit_command_failed(
                        &host.alias,
                        &transport_failure.error,
                        TurnAdmissionPhase::NotAdmitted,
                        None,
                    )
                    .map_err(failure)?;
            }
            return Err(transport_failure);
        }
    };
    let provider_validation = match transport.validate_provider_descriptor(
        provider_selection
            .requested_model_alias
            .as_deref()
            .unwrap_or("codex-default"),
        provider_selection
            .requested_provider_alias
            .as_deref()
            .unwrap_or("codex-default"),
        provider_selection.model_alias_from_project,
        provider_selection.provider_alias_from_project,
        satelle_core::ProviderAuthValidationMode::Cached,
        provider_selection.experimental_provider_computer_use,
    ) {
        Ok(validation) => validation,
        Err(error) => {
            let error = if host.config.transport == satelle_core::TransportKind::Direct
                && error.code == ErrorCode::HostUnreachable
            {
                SatelleError::direct_daemon_unreachable(&host.alias)
            } else {
                error
            };
            let validation_failure = failure(error);
            if !command.detach {
                event_output
                    .emit_preflight(
                        &host,
                        "run",
                        config,
                        &provider_selection,
                        None,
                        command.refresh_provider_smoke_test,
                    )
                    .map_err(failure)?;
                event_output
                    .emit_command_failed(
                        &host.alias,
                        &validation_failure.error,
                        TurnAdmissionPhase::NotAdmitted,
                        None,
                    )
                    .map_err(failure)?;
            }
            return Err(validation_failure);
        }
    };
    print_experimental_provider_warning(
        &provider_validation,
        command.quiet,
        json || effective_mode == EffectiveEventMode::Json,
    );
    report_not_admitted(
        &mut event_output,
        Some(&host.alias),
        resolve_execution_desktop(transport.as_ref(), &host),
    )?;
    let turn_execution_timeout_ms = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        resolve_turn_execution_timeout_ms(&host.config, command.timeout.as_deref()),
    )?;
    let supported_image_media_types = if command.images.is_empty() {
        Vec::new()
    } else {
        report_not_admitted(
            &mut event_output,
            explicit_host_alias,
            transport.supported_image_media_types().map_err(failure),
        )?
    };
    let attachments = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        load_image_attachments(&command.images, supported_image_media_types),
    )?;
    let effective_timeouts = effective_timeouts_json(&host.config, turn_execution_timeout_ms);
    let yolo_policy = resolve_yolo_policy(
        config,
        &host.alias,
        &host.config,
        command.yolo,
        command.no_yolo,
    );
    let request = build_turn_request(
        prompt,
        yolo_policy.execution_mode(),
        &provider_selection,
        command.refresh_provider_smoke_test,
        turn_execution_timeout_ms,
    )
    .with_attachments(attachments);
    if command.detach {
        let session = transport.run_detached(&request).map_err(failure)?;
        return print_detached_session(
            session,
            DetachedOutputOptions {
                host: &host.alias,
                effective_timeouts,
                yolo_policy: &yolo_policy,
                provider_selection: &provider_selection,
                provider_validation: &provider_validation,
                schema_version: SessionResultSchemaVersion::RunV2,
                json,
            },
        );
    }

    event_output
        .emit_preflight(
            &host,
            "run",
            config,
            &provider_selection,
            Some(&provider_validation),
            command.refresh_provider_smoke_test,
        )
        .map_err(failure)?;
    let outcome = match transport.run(&request, command.detach_on_interrupt, &mut |event| {
        event_output.emit(&host.alias, event)
    }) {
        Ok(outcome) => outcome,
        Err(attached_failure) => {
            let history_session_id = attached_failure
                .durable_handles()
                .map(|(session_id, _)| Box::new(session_id.clone()));
            event_output
                .emit_admission_failure(
                    &host.alias,
                    attached_failure.error(),
                    attached_failure.phase(),
                    attached_failure.durable_handles(),
                )
                .map_err(|error| CliFailure {
                    error,
                    history_session_id: history_session_id.clone(),
                    error_reported: false,
                })?;
            return Err(CliFailure {
                error: attached_failure.into_error(),
                history_session_id,
                error_reported: false,
            });
        }
    };
    print_turn_session(
        outcome,
        TurnOutputOptions {
            effective_mode,
            quiet: command.quiet,
            host: &host.alias,
            effective_timeouts,
            yolo_policy: &yolo_policy,
            provider_selection: &provider_selection,
            provider_validation: &provider_validation,
            schema_version: SessionResultSchemaVersion::RunV2,
            json,
        },
    )
}

fn steer_prompt(
    command: SteerCommand,
    config_context: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<SessionId, CliFailure> {
    let json = format.is_json();
    validate_interrupt_mode(command.detach, command.detach_on_interrupt)?;
    validate_event_mode(command.detach, command.events)?;
    let effective_mode = effective_event_mode(command.events, command.detach, command.quiet, json);
    let mut event_output = TurnEventOutput::new(effective_mode, command.verbose);
    let explicit_host_alias = command.host.as_deref();
    let prompt = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        read_prompt(command.prompt, command.prompt_file),
    )?;
    let session_id = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        SessionId::from_str(&command.session_id).map_err(|error| failure(error.into())),
    )?;
    let config = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        config_context.load(),
    )?;
    let host = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        config
            .resolve_host_with_project_source(explicit_host_alias)
            .map(SelectedHost::from)
            .map_err(failure),
    )?;
    let provider_selection = report_not_admitted(
        &mut event_output,
        Some(&host.alias),
        resolve_provider_selection(
            config,
            &host,
            command.model.as_deref(),
            command.provider.as_deref(),
            command.experimental_provider_computer_use,
            false,
        ),
    )?;
    let transport = match transport_for(&host) {
        Ok(transport) => transport,
        Err(transport_failure) => {
            if !command.detach {
                event_output
                    .emit_preflight(
                        &host,
                        "steer",
                        config,
                        &provider_selection,
                        None,
                        command.refresh_provider_smoke_test,
                    )
                    .map_err(failure)?;
                event_output
                    .emit_command_failed(
                        &host.alias,
                        &transport_failure.error,
                        TurnAdmissionPhase::NotAdmitted,
                        None,
                    )
                    .map_err(failure)?;
            }
            return Err(transport_failure);
        }
    };
    let provider_validation = match transport.validate_provider_descriptor(
        provider_selection
            .requested_model_alias
            .as_deref()
            .unwrap_or("codex-default"),
        provider_selection
            .requested_provider_alias
            .as_deref()
            .unwrap_or("codex-default"),
        provider_selection.model_alias_from_project,
        provider_selection.provider_alias_from_project,
        satelle_core::ProviderAuthValidationMode::Cached,
        provider_selection.experimental_provider_computer_use,
    ) {
        Ok(validation) => validation,
        Err(error) => {
            let error = if host.config.transport == satelle_core::TransportKind::Direct
                && error.code == ErrorCode::HostUnreachable
            {
                SatelleError::direct_daemon_unreachable(&host.alias)
            } else {
                error
            };
            let validation_failure = failure(error);
            if !command.detach {
                event_output
                    .emit_preflight(
                        &host,
                        "steer",
                        config,
                        &provider_selection,
                        None,
                        command.refresh_provider_smoke_test,
                    )
                    .map_err(failure)?;
                event_output
                    .emit_command_failed(
                        &host.alias,
                        &validation_failure.error,
                        TurnAdmissionPhase::NotAdmitted,
                        None,
                    )
                    .map_err(failure)?;
            }
            return Err(validation_failure);
        }
    };
    print_experimental_provider_warning(
        &provider_validation,
        command.quiet,
        json || effective_mode == EffectiveEventMode::Json,
    );
    report_not_admitted(
        &mut event_output,
        Some(&host.alias),
        resolve_execution_desktop(transport.as_ref(), &host),
    )?;
    let turn_execution_timeout_ms = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        resolve_turn_execution_timeout_ms(&host.config, command.timeout.as_deref()),
    )?;
    let supported_image_media_types = if command.images.is_empty() {
        Vec::new()
    } else {
        report_not_admitted(
            &mut event_output,
            explicit_host_alias,
            transport.supported_image_media_types().map_err(failure),
        )?
    };
    let attachments = report_not_admitted(
        &mut event_output,
        explicit_host_alias,
        load_image_attachments(&command.images, supported_image_media_types),
    )?;
    let effective_timeouts = effective_timeouts_json(&host.config, turn_execution_timeout_ms);
    let yolo_policy = resolve_yolo_policy(
        config,
        &host.alias,
        &host.config,
        command.yolo,
        command.no_yolo,
    );
    let request = build_turn_request(
        prompt,
        yolo_policy.execution_mode(),
        &provider_selection,
        command.refresh_provider_smoke_test,
        turn_execution_timeout_ms,
    )
    .with_attachments(attachments);
    if command.detach {
        let session = transport
            .steer_detached(&session_id, &request)
            .map_err(failure)?;
        return print_detached_session(
            session,
            DetachedOutputOptions {
                host: &host.alias,
                effective_timeouts,
                yolo_policy: &yolo_policy,
                provider_selection: &provider_selection,
                provider_validation: &provider_validation,
                schema_version: SessionResultSchemaVersion::SteerV2,
                json,
            },
        );
    }

    event_output
        .emit_preflight(
            &host,
            "steer",
            config,
            &provider_selection,
            Some(&provider_validation),
            command.refresh_provider_smoke_test,
        )
        .map_err(failure)?;
    let outcome = match transport.steer(
        &session_id,
        &request,
        command.detach_on_interrupt,
        &mut |event| event_output.emit(&host.alias, event),
    ) {
        Ok(outcome) => outcome,
        Err(attached_failure) => {
            let history_session_id = attached_failure
                .durable_handles()
                .map(|(session_id, _)| Box::new(session_id.clone()));
            event_output
                .emit_admission_failure(
                    &host.alias,
                    attached_failure.error(),
                    attached_failure.phase(),
                    attached_failure.durable_handles(),
                )
                .map_err(|error| CliFailure {
                    error,
                    history_session_id: history_session_id.clone(),
                    error_reported: false,
                })?;
            return Err(CliFailure {
                error: attached_failure.into_error(),
                history_session_id,
                error_reported: false,
            });
        }
    };
    print_turn_session(
        outcome,
        TurnOutputOptions {
            effective_mode,
            quiet: command.quiet,
            host: &host.alias,
            effective_timeouts,
            yolo_policy: &yolo_policy,
            provider_selection: &provider_selection,
            provider_validation: &provider_validation,
            schema_version: SessionResultSchemaVersion::SteerV2,
            json,
        },
    )
}

fn build_turn_request(
    prompt: String,
    execution_mode: TurnExecutionMode,
    provider_selection: &ProviderSelection,
    refresh_provider_smoke_test: bool,
    turn_execution_timeout_ms: u64,
) -> TurnRequest {
    TurnRequest::new(prompt)
        .with_execution_mode(execution_mode)
        .with_provider_intent(
            provider_selection.requested_model_alias.clone(),
            provider_selection.requested_provider_alias.clone(),
            provider_selection.model_alias_from_project,
            provider_selection.provider_alias_from_project,
            refresh_provider_smoke_test,
        )
        .with_experimental_provider_computer_use(
            provider_selection.experimental_provider_computer_use,
        )
        .with_turn_execution_timeout_ms(turn_execution_timeout_ms)
}

fn show_status(
    command: StatusCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let (session, host_alias) = read::status(&command.session_id, command.host.as_deref(), config)?;

    if json {
        print_json(&StatusReport::new(&session, &host_alias)).map_err(failure)
    } else {
        print_session_human(&session, latest_turn(&session), &host_alias);
        Ok(())
    }
}

fn stop_session(
    command: StopCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let session_id =
        SessionId::from_str(&command.session_id).map_err(|error| failure(error.into()))?;
    let host = config.resolve_host(command.host.as_deref())?;
    let transport = transport_for(&host)?;
    let result = transport.stop(&session_id).map_err(failure)?;

    if json {
        print_json(&result).map_err(failure)
    } else {
        println!("Outcome: {}", result.outcome().as_str());
        println!("Session: {}", result.session_id());
        println!("Turn: {}", result.turn_id());
        println!("Previous state: {}", result.previous_state().as_str());
        println!("Current state: {}", result.current_state().as_str());
        println!("Changed: {}", result.changed());
        println!(
            "Stopped at: {}",
            result.stopped_at().unwrap_or("not applicable")
        );
        Ok(())
    }
}

fn effective_timeouts_json(
    host_config: &satelle_core::HostConfig,
    turn_execution_timeout_ms: u64,
) -> serde_json::Value {
    let timeouts = host_config.timeouts.as_ref();
    json!({
        "native_readiness_timeout_ms": timeouts
            .and_then(|timeouts| timeouts.native_readiness.as_ref())
            .map(|duration| duration.milliseconds()),
        "provider_smoke_test_timeout_ms": timeouts
            .and_then(|timeouts| timeouts.provider_smoke_test.as_ref())
            .map(|duration| duration.milliseconds()),
        "turn_execution_timeout_ms": turn_execution_timeout_ms,
        "provider_smoke_success_cache_ttl_ms": host_config
            .provider_smoke_success_cache_ttl
            .as_ref()
            .map(|duration| duration.milliseconds()),
        "provider_smoke_failure_cache_ttl_ms": host_config
            .provider_smoke_failure_cache_ttl
            .as_ref()
            .map(|duration| duration.milliseconds()),
    })
}

fn resolve_turn_execution_timeout_ms(
    host_config: &satelle_core::HostConfig,
    command_timeout: Option<&str>,
) -> Result<u64, CliFailure> {
    let configured = configured_turn_execution_timeout_ms(host_config);
    let Some(command_timeout) = command_timeout else {
        return Ok(configured);
    };
    let requested = satelle_core::TurnExecutionDuration::parse(command_timeout).ok_or_else(|| {
        failure(SatelleError::invalid_usage(
            "--timeout requires a duration from 1s through 24h with an explicit s, m, or h unit",
        ))
    })?;
    Ok(configured.min(requested.milliseconds()))
}

fn configured_turn_execution_timeout_ms(host_config: &satelle_core::HostConfig) -> u64 {
    host_config
        .timeouts
        .as_ref()
        .and_then(|timeouts| timeouts.turn_execution.as_ref())
        .map_or(
            satelle_core::DEFAULT_TURN_EXECUTION_TIMEOUT_MS,
            satelle_core::TurnExecutionDuration::milliseconds,
        )
}

fn validate_event_mode(detach: bool, mode: EventMode) -> Result<(), CliFailure> {
    if detach && matches!(mode, EventMode::Human | EventMode::Json) {
        return Err(failure(SatelleError::events_with_detach()));
    }

    Ok(())
}

fn validate_interrupt_mode(detach: bool, detach_on_interrupt: bool) -> Result<(), CliFailure> {
    if detach && detach_on_interrupt {
        return Err(failure(SatelleError::interrupt_mode_conflict()));
    }
    Ok(())
}

fn read_prompt(prompt: Option<String>, prompt_file: Option<PathBuf>) -> Result<String, CliFailure> {
    if prompt.is_some() && prompt_file.is_some() {
        return Err(failure(SatelleError::prompt_source_conflict()));
    }

    let value = if let Some(prompt_file) = prompt_file {
        fs::read_to_string(&prompt_file).map_err(|source| {
            failure(SatelleError {
                code: ErrorCode::InputRequired,
                message: format!("could not read prompt file {}", prompt_file.display()),
                recovery_command: Some(
                    "pass a readable --prompt-file path or use a prompt argument".to_string(),
                ),
                source_detail: Some(source.to_string()),
                details: std::collections::BTreeMap::new(),
            })
        })?
    } else if prompt.as_deref() == Some("-") {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).map_err(|source| {
            failure(SatelleError {
                code: ErrorCode::InputRequired,
                message: "could not read prompt from stdin".to_string(),
                recovery_command: Some("pipe prompt text or pass a prompt argument".to_string()),
                source_detail: Some(source.to_string()),
                details: std::collections::BTreeMap::new(),
            })
        })?;
        buffer
    } else if let Some(prompt) = prompt {
        prompt
    } else {
        return Err(failure(SatelleError::input_required(
            "prompt text is required",
        )));
    };

    if value.trim().is_empty() {
        return Err(failure(SatelleError::input_required(
            "prompt text is required",
        )));
    }

    Ok(value.trim().to_string())
}

struct TurnOutputOptions<'a> {
    effective_mode: EffectiveEventMode,
    quiet: bool,
    host: &'a str,
    effective_timeouts: serde_json::Value,
    yolo_policy: &'a YoloPolicy,
    provider_selection: &'a ProviderSelection,
    provider_validation: &'a transport::ProviderDescriptorValidationReport,
    schema_version: SessionResultSchemaVersion,
    json: bool,
}

fn print_turn_session(
    outcome: AttachedTurnOutcome,
    options: TurnOutputOptions<'_>,
) -> Result<SessionId, CliFailure> {
    let AttachedTurnOutcome {
        session,
        turn_id,
        provider_smoke,
    } = outcome;
    let target_turn = session
        .turns()
        .iter()
        .find(|turn| turn.turn_id() == &turn_id)
        .expect("an attached Turn outcome retains its admitted target Turn");
    let session_id = session.session_id().clone();
    if options.effective_mode == EffectiveEventMode::Json {
        return Ok(session_id);
    }

    if options.json {
        let provider_smoke_test_status = provider_smoke
            .as_ref()
            .and_then(|provider_smoke| provider_smoke.get("status"))
            .cloned()
            .unwrap_or_else(|| json!(options.provider_validation.validation.outcome().as_str()));
        print_json(&json!({
            "schema_version": options.schema_version,
            "session_id": session.session_id(),
            "status": target_turn.state(),
            "effective_timeouts": options.effective_timeouts,
            "provider_smoke": provider_smoke,
            "requested_model_alias": options.provider_selection.requested_model_alias,
            "requested_provider_alias": options.provider_selection.requested_provider_alias,
            "resolved_codex_model": options.provider_validation.resolved_binding.model(),
            "resolved_model_provider": options.provider_validation.resolved_binding.model_provider(),
            "provider_binding_source": options.provider_validation.resolved_binding.source().as_str(),
            "experimental_provider_computer_use": projected_experimental_provider_computer_use(
                options.provider_selection,
                Some(options.provider_validation),
            ),
            "provider_smoke_test_status": provider_smoke_test_status,
            "yolo": yolo_state_json(options.yolo_policy),
            "latest_turn": target_turn,
        }))
        .map_err(|error| failure_for_admitted_session(error, &session_id))?;
    } else {
        if options.yolo_policy.active && !options.quiet {
            println!("YOLO mode: active ({})", options.yolo_policy.source);
        }
        print_session_human(&session, target_turn, options.host);
    }
    Ok(session_id)
}

struct DetachedOutputOptions<'a> {
    host: &'a str,
    effective_timeouts: serde_json::Value,
    yolo_policy: &'a YoloPolicy,
    provider_selection: &'a ProviderSelection,
    provider_validation: &'a transport::ProviderDescriptorValidationReport,
    schema_version: SessionResultSchemaVersion,
    json: bool,
}

fn print_detached_session(
    session: PublicSession,
    options: DetachedOutputOptions<'_>,
) -> Result<SessionId, CliFailure> {
    let session_id = session.session_id().clone();
    let latest_turn = latest_turn(&session);
    if options.json {
        print_json(&json!({
            "schema_version": options.schema_version,
            "session_id": session.session_id(),
            "host": options.host,
            "status": latest_turn.state(),
            "created_at": session.created_at().format(&Rfc3339).expect("a public Session timestamp is RFC 3339 representable"),
            "updated_at": session.updated_at().format(&Rfc3339).expect("a public Session timestamp is RFC 3339 representable"),
            "effective_timeouts": options.effective_timeouts,
            "requested_model_alias": options.provider_selection.requested_model_alias,
            "requested_provider_alias": options.provider_selection.requested_provider_alias,
            "resolved_codex_model": options.provider_validation.resolved_binding.model(),
            "resolved_model_provider": options.provider_validation.resolved_binding.model_provider(),
            "provider_binding_source": options.provider_validation.resolved_binding.source().as_str(),
            "experimental_provider_computer_use": projected_experimental_provider_computer_use(
                options.provider_selection,
                Some(options.provider_validation),
            ),
            "provider_smoke_test_status": options.provider_validation.validation.outcome().as_str(),
            "yolo": yolo_state_json(options.yolo_policy),
            "turns": session.turns(),
        }))
        .map_err(|error| failure_for_admitted_session(error, &session_id))?;
    } else {
        if options.yolo_policy.active {
            println!("YOLO mode: active ({})", options.yolo_policy.source);
        }
        println!("Session: {}", session.session_id());
        println!("Status: {}", status_label(latest_turn.state()));
    }
    Ok(session_id)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectiveEventMode {
    Human,
    Json,
    None,
}

struct TurnEventOutput {
    mode: EffectiveEventMode,
    verbose: bool,
    next_sequence: u64,
}

impl TurnEventOutput {
    fn new(mode: EffectiveEventMode, verbose: bool) -> Self {
        Self {
            mode,
            verbose,
            next_sequence: 1,
        }
    }

    fn emit_preflight(
        &mut self,
        host: &SelectedHost,
        operation: &str,
        config: &ResolvedConfig,
        provider_selection: &ProviderSelection,
        provider_validation: Option<&transport::ProviderDescriptorValidationReport>,
        refresh_provider_smoke_test: bool,
    ) -> Result<(), SatelleError> {
        if self.mode == EffectiveEventMode::None {
            return Ok(());
        }
        let body = SatelleEventBody::new(
            EventType::Preflight,
            EventSource::Cli,
            OffsetDateTime::now_utc(),
            &host.alias,
            None,
            "resolved configuration and selected Host transport",
            json!({
                "operation": operation,
                "transport": host.config.transport,
                "selected_profile": config.selected_profile.as_ref().map(|profile| &profile.name),
                "effective_timeouts": effective_timeouts_json(
                    &host.config,
                    configured_turn_execution_timeout_ms(&host.config),
                ),
                "project_config_intent": {
                    "host": host.from_project,
                    "model": config.model_alias_from_project(),
                    "provider": config.provider_alias_from_project(),
                    "profile": config.selected_profile.as_ref().is_some_and(
                        |profile| profile.source.as_str() == "project_config"
                    ),
                    "timeouts": config.timeout_intent_from_project(&host.alias),
                    "transport": config.transport_intent_from_project(&host.alias),
                    "output_format": config.output_format_from_project(),
                },
                "requested_model_alias": provider_selection.requested_model_alias,
                "requested_provider_alias": provider_selection.requested_provider_alias,
                "model_alias_from_project": provider_selection.model_alias_from_project,
                "provider_alias_from_project": provider_selection.provider_alias_from_project,
                "resolved_codex_model": provider_validation.map(|validation| validation.resolved_binding.model()),
                "resolved_model_provider": provider_validation.map(|validation| validation.resolved_binding.model_provider()),
                "provider_binding_source": provider_validation.map(|validation| validation.resolved_binding.source().as_str()),
                "experimental_provider_computer_use": projected_experimental_provider_computer_use(
                    provider_selection,
                    provider_validation,
                ),
                "provider_smoke_test_status": provider_validation.map_or_else(
                    || provider_selection.provider_smoke_status(refresh_provider_smoke_test),
                    |validation| validation.validation.outcome().as_str(),
                ),
            }),
        )
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
        self.emit_body(body)
    }

    fn emit(&mut self, host_alias: &str, event: SatelleEvent) -> Result<(), SatelleError> {
        let body = event
            .into_body()
            .with_host(host_alias)
            .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
        self.emit_body(body)
    }

    fn emit_command_failed(
        &mut self,
        host: &str,
        error: &SatelleError,
        admission_phase: TurnAdmissionPhase,
        durable_handles: Option<(&SessionId, &satelle_core::TurnId)>,
    ) -> Result<(), SatelleError> {
        if self.mode != EffectiveEventMode::Json {
            return Ok(());
        }
        let body = command_failed_event_body(host, error, admission_phase, durable_handles)?;
        self.emit_body(body)
    }

    fn emit_admission_failure(
        &mut self,
        host: &str,
        error: &SatelleError,
        admission_phase: TurnAdmissionPhase,
        durable_handles: Option<(&SessionId, &satelle_core::TurnId)>,
    ) -> Result<(), SatelleError> {
        if self.mode != EffectiveEventMode::Json {
            return Ok(());
        }
        for body in admission_failure_event_bodies(host, error, admission_phase, durable_handles)? {
            self.emit_body(body)?;
        }
        Ok(())
    }

    fn emit_body(&mut self, body: SatelleEventBody) -> Result<(), SatelleError> {
        if self.mode == EffectiveEventMode::None {
            return Ok(());
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| SatelleError::invalid_usage("event output sequence is exhausted"))?;
        let event = body
            .with_seq(sequence)
            .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
        match self.mode {
            EffectiveEventMode::Json => {
                let mut stdout = io::stdout().lock();
                serde_json::to_writer(&mut stdout, &event)
                    .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
                writeln!(stdout).map_err(event_output_error)?;
                stdout.flush().map_err(event_output_error)
            }
            EffectiveEventMode::Human => {
                if self.verbose {
                    eprintln!(
                        "{}: {} data={}",
                        event.event_type(),
                        event.message(),
                        serde_json::to_string(event.data())
                            .map_err(|error| SatelleError::invalid_usage(error.to_string()))?
                    );
                } else {
                    eprintln!("{}: {}", event.event_type(), event.message());
                }
                Ok(())
            }
            EffectiveEventMode::None => Ok(()),
        }
    }
}

fn admission_failure_event_bodies(
    host: &str,
    error: &SatelleError,
    admission_phase: TurnAdmissionPhase,
    durable_handles: Option<(&SessionId, &satelle_core::TurnId)>,
) -> Result<Vec<SatelleEventBody>, SatelleError> {
    let mut bodies = Vec::with_capacity(2);
    if let Some(body) = native_readiness_failure_event_body(host, error)? {
        bodies.push(body);
    }
    bodies.push(command_failed_event_body(
        host,
        error,
        admission_phase,
        durable_handles,
    )?);
    Ok(bodies)
}

fn native_readiness_failure_event_body(
    host: &str,
    error: &SatelleError,
) -> Result<Option<SatelleEventBody>, SatelleError> {
    let Some(readiness) = error
        .details
        .get("native_readiness")
        .filter(|readiness| readiness.is_object())
    else {
        return Ok(None);
    };
    let Some((event_type, message)) = readiness
        .get("status")
        .and_then(serde_json::Value::as_str)
        .and_then(|status| match status {
            "failed" => Some((EventType::Readiness, "native Computer Use readiness failed")),
            "manual_action_required" => Some((
                EventType::ActionRequired,
                "native Computer Use readiness requires manual action",
            )),
            _ => None,
        })
    else {
        return Ok(None);
    };
    SatelleEventBody::new(
        event_type,
        EventSource::Cli,
        OffsetDateTime::now_utc(),
        host,
        None,
        message,
        readiness.clone(),
    )
    .map(Some)
    .map_err(|error| SatelleError::invalid_usage(error.to_string()))
}

fn command_failed_event_body(
    host: &str,
    error: &SatelleError,
    admission_phase: TurnAdmissionPhase,
    durable_handles: Option<(&SessionId, &satelle_core::TurnId)>,
) -> Result<SatelleEventBody, SatelleError> {
    let (session_id, turn_id) = durable_handles.unzip();
    SatelleEventBody::new(
        EventType::CommandFailed,
        EventSource::Cli,
        OffsetDateTime::now_utc(),
        host,
        None,
        error.message.clone(),
        json!({
            "code": error.code.as_str(),
            "message": &error.message,
            "recovery_command": &error.recovery_command,
            "source_detail": &error.source_detail,
            "details": &error.details,
            "admission_phase": admission_phase.as_str(),
            "session_id": session_id,
            "turn_id": turn_id,
        }),
    )
    .map_err(|error| SatelleError::invalid_usage(error.to_string()))
}

fn event_output_error(error: io::Error) -> SatelleError {
    SatelleError::invalid_usage(format!("could not write event output: {error}"))
}

fn effective_event_mode(
    mode: EventMode,
    detach: bool,
    quiet: bool,
    json: bool,
) -> EffectiveEventMode {
    if detach {
        return EffectiveEventMode::None;
    }

    match mode {
        EventMode::Human => EffectiveEventMode::Human,
        EventMode::Json => EffectiveEventMode::Json,
        EventMode::None => EffectiveEventMode::None,
        EventMode::Auto => {
            if quiet {
                return EffectiveEventMode::None;
            }
            if !json && io::stdout().is_terminal() {
                EffectiveEventMode::Human
            } else {
                EffectiveEventMode::None
            }
        }
    }
}

fn print_setup_human(report: &SetupReport) {
    println!("Host: {}", report.host);
    println!("Dry run: {}", report.dry_run);
    println!("Setup mode: {}", report.setup_mode);
    println!("Service persistent: {}", report.service_persistent);
    println!("Service scope: {}", report.service_scope);
    println!("Components: {}", report.setup_components.join(", "));
    println!("Changed: {}", report.changed);
    println!(
        "Provider descriptor configured: {}",
        report.descriptor_configured
    );
    println!("Provider secret provisioned: {}", report.secret_provisioned);
    println!("Provider validation: {}", report.validation_status);
    println!("Provider smoke test: {}", report.provider_smoke_test_status);
    println!(
        "Native Computer Use readiness: {}",
        report.native_computer_use_readiness
    );
    for action in &report.planned_actions {
        println!("Plan: {action}");
    }
    if let Some(verification) = &report.verification {
        println!("Verification: {}", verification.status);
        for check in &verification.planned_checks {
            println!("Verification check: {check}");
        }
        for cache_update in &verification.cache_updates {
            println!("Verification cache: {cache_update}");
        }
    }
    for override_entry in &report.daemon_path_overrides {
        println!(
            "Daemon env: {}={}",
            override_entry.environment_variable, override_entry.value
        );
    }
    println!("Next: {}", report.next_command);
}

fn print_session_human(session: &PublicSession, turn: &PublicTurn, host: &str) {
    println!("Session: {}", session.session_id());
    println!("Host: {host}");
    println!("Status: {}", status_label(turn.state()));
    println!("Turns: {}", session.turns().len());
    println!("Latest turn: {}", turn.turn_id());
    println!("Latest status: {}", status_label(turn.state()));
    if let Some(summary) = turn.safe_summary() {
        println!("Summary: {}", summary.as_str());
    }
}

fn latest_turn(session: &PublicSession) -> &PublicTurn {
    session
        .turns()
        .last()
        .expect("validated public Sessions always contain Turn history")
}

fn status_label(status: TurnState) -> &'static str {
    match status {
        TurnState::Starting => "starting",
        TurnState::Running => "running",
        TurnState::RecoveryPending => "recovery_pending",
        TurnState::Completed => "completed",
        TurnState::Blocked => "blocked",
        TurnState::Failed => "failed",
        TurnState::Stopped => "stopped",
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<(), SatelleError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).map_err(|source| SatelleError {
        code: ErrorCode::InvalidUsage,
        message: "could not serialize JSON output".to_string(),
        recovery_command: None,
        source_detail: Some(source.to_string()),
        details: std::collections::BTreeMap::new(),
    })?;
    writeln!(stdout).map_err(|source| SatelleError {
        code: ErrorCode::InvalidUsage,
        message: "could not write JSON output".to_string(),
        recovery_command: None,
        source_detail: Some(source.to_string()),
        details: std::collections::BTreeMap::new(),
    })
}

fn failure(error: SatelleError) -> CliFailure {
    CliFailure {
        error,
        history_session_id: None,
        error_reported: false,
    }
}

fn reported_failure(error: SatelleError) -> CliFailure {
    CliFailure {
        error,
        history_session_id: None,
        error_reported: true,
    }
}

fn failure_for_admitted_session(error: SatelleError, session_id: &SessionId) -> CliFailure {
    CliFailure {
        error,
        history_session_id: Some(Box::new(session_id.clone())),
        error_reported: false,
    }
}

#[cfg(test)]
mod setup_desktop_binding_tests {
    use super::*;
    use satelle_core::{DesktopSessionRecord, HostSessionsSchemaVersion};

    fn host_config() -> HostConfig {
        toml::from_str("transport = \"local\"\nadapter = \"fake\"\n")
            .expect("test Host Binding should parse")
    }

    fn session(id: &str, user: &str, is_console: bool) -> DesktopSessionRecord {
        DesktopSessionRecord {
            session_id: id.to_string(),
            desktop_user: user.to_string(),
            state: "active".to_string(),
            session_kind: "visible_desktop".to_string(),
            is_console,
            is_remote: !is_console,
            display_summary: id.to_string(),
            portable_selectors: vec!["active".to_string()],
            native_selectors: Vec::new(),
            selected_by_current_config: false,
        }
    }

    fn report(sessions: Vec<DesktopSessionRecord>) -> HostSessionsReport {
        HostSessionsReport {
            schema_version: HostSessionsSchemaVersion::V1,
            host: "setup-test".to_string(),
            detected_platform: "windows".to_string(),
            connection_mode: "direct".to_string(),
            bootstrapped: false,
            bootstrap_actions: Vec::new(),
            host_daemon_version: "test".to_string(),
            sessions,
        }
    }

    #[test]
    fn deterministic_session_persists_concrete_binding_and_only_preference() {
        let selection = resolve_setup_desktop_selection(
            &report(vec![session("console", "alice", true)]),
            &host_config(),
            false,
            None,
        )
        .expect("one compatible session should resolve")
        .expect("the inferred selection must be persisted");

        assert_eq!(selection.desktop_user, "alice");
        assert_eq!(selection.preference, DesktopSessionPreference::Only);
    }

    #[test]
    fn noninteractive_setup_preserves_binding_and_session_ambiguity() {
        let binding_error = resolve_setup_desktop_selection(
            &report(vec![
                session("alice-console", "alice", true),
                session("bob-console", "bob", true),
            ]),
            &host_config(),
            false,
            None,
        )
        .expect_err("multiple users require a Desktop Binding");
        assert_eq!(binding_error.code, ErrorCode::DesktopBindingRequired);

        let session_error = resolve_setup_desktop_selection(
            &report(vec![
                session("alice-console", "alice", true),
                session("alice-remote", "alice", false),
            ]),
            &host_config(),
            false,
            None,
        )
        .expect_err("multiple sessions require a Desktop Session Preference");
        assert_eq!(session_error.code, ErrorCode::DesktopSessionAmbiguous);
    }

    #[test]
    fn unavailable_configured_binding_is_not_rewritten() {
        let mut config = host_config();
        config.desktop_user = Some("missing".to_string());
        let error = resolve_setup_desktop_selection(
            &report(vec![session("console", "alice", true)]),
            &config,
            false,
            None,
        )
        .expect_err("a missing configured user must fail");

        assert_eq!(error.code, ErrorCode::DesktopSessionUnavailable);
        assert_eq!(config.desktop_user.as_deref(), Some("missing"));
    }

    #[test]
    fn authenticated_ssh_user_is_the_default_among_multiple_desktop_users() {
        let selection = resolve_setup_desktop_selection(
            &report(vec![
                session("alice-console", "alice", true),
                session("alias-console", "alias-resolved-user", true),
            ]),
            &host_config(),
            false,
            Some("alias-resolved-user"),
        )
        .expect("the authenticated SSH user should resolve")
        .expect("the authenticated SSH default should be persisted");

        assert_eq!(selection.desktop_user, "alias-resolved-user");
        assert_eq!(selection.preference, DesktopSessionPreference::Only);
    }

    #[test]
    fn setup_component_partition_preserves_cli_and_host_ownership() {
        assert_eq!(
            partition_setup_components(&["desktop".to_string()], true, false),
            (Vec::new(), true)
        );
        assert_eq!(
            partition_setup_components(&["all".to_string()], false, false),
            (vec!["all".to_string()], true)
        );
        assert_eq!(
            partition_setup_components(&["all".to_string()], false, true),
            (vec!["all".to_string()], true)
        );
        assert_eq!(
            partition_setup_components(&["provider-auth".to_string()], false, false),
            (Vec::new(), false)
        );
        assert_eq!(
            partition_setup_components(
                &["desktop".to_string(), "provider-auth".to_string()],
                false,
                false,
            ),
            (Vec::new(), true)
        );
    }

    #[test]
    fn ssh_all_and_path_rebind_normalize_to_the_transport_subplan() {
        assert_eq!(
            partition_setup_components(&["all".to_string()], true, false),
            (vec!["transport".to_string()], true)
        );
        assert_eq!(
            partition_setup_components(&["desktop".to_string()], true, true),
            (vec!["transport".to_string()], true)
        );
    }

    #[test]
    fn execution_desktop_probe_requires_an_explicit_policy() {
        let mut config = host_config();
        assert!(!desktop_policy_is_active(
            &DesktopSelectionPolicy::from_host_config(&config)
        ));

        config.desktop_user = Some("operator".to_string());
        assert!(desktop_policy_is_active(
            &DesktopSelectionPolicy::from_host_config(&config)
        ));

        config.desktop_user = None;
        config.desktop_session_preference = Some(DesktopSessionPreference::Only);
        assert!(desktop_policy_is_active(
            &DesktopSelectionPolicy::from_host_config(&config)
        ));

        config.desktop_session_preference = None;
        config.desktop_session_native_selector = Some(satelle_core::DesktopSessionNativeSelector {
            platform: "windows".to_string(),
            kind: "wts-session".to_string(),
            value: "7".to_string(),
        });
        assert!(desktop_policy_is_active(
            &DesktopSelectionPolicy::from_host_config(&config)
        ));
    }

    #[test]
    fn empty_ssh_desktop_subplan_never_constructs_or_calls_host_mutation() {
        let (host_components, desktop_selected) =
            partition_setup_components(&["desktop".to_string()], true, false);
        let host_setup_required = !host_components.is_empty();
        let constructed = std::cell::Cell::new(false);
        let transport = setup_transport_if_required(host_setup_required, || {
            constructed.set(true);
            Ok::<_, CliFailure>("SSH setup transport")
        })
        .unwrap_or_else(|_| panic!("skipping transport construction cannot fail"));
        let called = std::cell::Cell::new(false);
        let result = run_host_setup_if_required(
            host_setup_required,
            || "cli-owned",
            || {
                called.set(true);
                Ok("host-owned")
            },
        )
        .expect("an empty Host subplan should use the CLI-owned result");

        assert_eq!(result, "cli-owned");
        assert!(desktop_selected);
        assert!(transport.is_none());
        assert!(!constructed.get());
        assert!(!called.get());
    }

    #[test]
    fn host_setup_precedes_provider_follow_up_and_failure_blocks_it() {
        let result = run_host_setup_then_follow_up(
            || Ok::<_, &'static str>(vec!["configured fake native Computer Use readiness"]),
            |applied_actions| {
                applied_actions.push(
                    "provisioned and authorized file provider authentication on Host 'selected'",
                );
                Ok(())
            },
        );
        assert_eq!(
            result,
            Ok(vec![
                "configured fake native Computer Use readiness",
                "provisioned and authorized file provider authentication on Host 'selected'",
            ])
        );

        let provider_called = std::cell::Cell::new(false);
        let result = run_host_setup_then_follow_up(
            || Err::<(), _>("host setup failed"),
            |_| {
                provider_called.set(true);
                Ok(())
            },
        );
        assert_eq!(result, Err("host setup failed"));
        assert!(!provider_called.get());
    }

    #[test]
    fn failed_desktop_preflight_blocks_host_mutation() {
        let called = std::cell::Cell::new(false);
        let mut setup_config = ();
        let result = run_host_setup_after_desktop_preflight(
            Err(failure(SatelleError::invalid_usage(
                "desktop preflight failed",
            ))),
            &mut setup_config,
            |_| Ok(()),
            |_| {
                called.set(true);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert!(!called.get());
    }

    #[test]
    fn desktop_persistence_precedes_host_apply_and_failure_blocks_it() {
        let events = std::cell::RefCell::new(Vec::new());
        let mut setup_config = ();
        run_host_setup_after_desktop_preflight(
            Ok(()),
            &mut setup_config,
            |_| {
                events.borrow_mut().push("persist");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("host");
                Ok(())
            },
        )
        .unwrap_or_else(|_| panic!("successful desktop persistence should permit Host apply"));
        assert_eq!(*events.borrow(), ["persist", "host"]);

        let host_called = std::cell::Cell::new(false);
        let mut setup_config = ();
        let result = run_host_setup_after_desktop_preflight(
            Ok(()),
            &mut setup_config,
            |_| {
                Err(failure(SatelleError::config_error(
                    "desktop selection was not persisted",
                    None,
                )))
            },
            |_| {
                host_called.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!host_called.get());
    }
}

#[cfg(test)]
mod admitted_session_failure_tests {
    use super::*;

    fn native_readiness_error(status: &str) -> SatelleError {
        let mut error = SatelleError::native_readiness_timeout();
        error.details.insert(
            "native_readiness".to_string(),
            json!({
                "source": "live",
                "status": status,
                "checks": [{
                    "kind": "pointer_drag",
                    "status": status,
                    "reason": "pointer_drag_not_confirmed",
                }],
            }),
        );
        error
    }

    fn admission_event_types(error: &SatelleError) -> Vec<EventType> {
        admission_failure_event_bodies(
            "readiness-host",
            error,
            TurnAdmissionPhase::NotAdmitted,
            None,
        )
        .expect("construct admission failure events")
        .iter()
        .map(SatelleEventBody::event_type)
        .collect()
    }

    #[test]
    fn retains_the_durable_session_id() {
        let session_id = SessionId::new();
        let failure = failure_for_admitted_session(
            SatelleError::input_required("synthetic output failure"),
            &session_id,
        );

        assert_eq!(failure.history_session_id.as_deref(), Some(&session_id));
    }

    fn assert_unknown_machine_event(host: &str) {
        let body = command_failed_event_body(
            host,
            &SatelleError::interrupted_attached_command(),
            TurnAdmissionPhase::AdmissionUnknown,
            None,
        )
        .expect("construct command-failed event");

        assert_eq!(body.event_type(), EventType::CommandFailed);
        assert_eq!(body.data()["admission_phase"], "admission_unknown");
        assert!(body.data()["session_id"].is_null());
        assert!(body.data()["turn_id"].is_null());
    }

    #[test]
    fn run_machine_event_preserves_unknown_admission_phase() {
        assert_unknown_machine_event("run-host");
    }

    #[test]
    fn steer_machine_event_preserves_unknown_admission_phase() {
        assert_unknown_machine_event("steer-host");
    }

    #[test]
    fn failed_native_readiness_precedes_command_failure() {
        let error = native_readiness_error("failed");
        let bodies = admission_failure_event_bodies(
            "readiness-host",
            &error,
            TurnAdmissionPhase::NotAdmitted,
            None,
        )
        .expect("construct admission failure events");

        assert_eq!(
            bodies
                .iter()
                .map(SatelleEventBody::event_type)
                .collect::<Vec<_>>(),
            [EventType::Readiness, EventType::CommandFailed]
        );
        assert_eq!(bodies[0].data(), &error.details["native_readiness"]);
    }

    #[test]
    fn manual_native_readiness_precedes_command_failure() {
        let error = native_readiness_error("manual_action_required");

        assert_eq!(
            admission_event_types(&error),
            [EventType::ActionRequired, EventType::CommandFailed]
        );
    }

    #[test]
    fn missing_or_malformed_native_readiness_emits_only_command_failure() {
        let missing = SatelleError::native_readiness_timeout();
        let mut malformed = missing.clone();
        malformed.details.insert(
            "native_readiness".to_string(),
            json!({"source": "live", "status": "unexpected", "checks": []}),
        );

        for error in [&missing, &malformed] {
            assert_eq!(admission_event_types(error), [EventType::CommandFailed]);
        }
    }

    #[test]
    fn none_event_mode_returns_without_emitting_or_changing_sequence() {
        let transport_calls = std::cell::Cell::new(0_u8);
        let mut event_output = TurnEventOutput::new(EffectiveEventMode::None, false);
        transport_calls.set(transport_calls.get() + 1);

        event_output
            .emit_admission_failure(
                "readiness-host",
                &native_readiness_error("failed"),
                TurnAdmissionPhase::NotAdmitted,
                None,
            )
            .expect("none mode must suppress output without failing");

        assert_eq!(transport_calls.get(), 1);
        assert_eq!(event_output.next_sequence, 1);
    }
}

#[derive(Clone, Copy)]
struct HumanStyle {
    color: bool,
}

impl HumanStyle {
    fn detect(no_color_flag: bool) -> Self {
        let color = !no_color_flag
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM")
                .map(|term| term != "dumb")
                .unwrap_or(true);

        let _palette = (BEACON_CORAL, RELAY_ROSE, SUCCESS_GREEN, ERROR_RED, CLI_NAME);

        Self { color }
    }

    fn color_enabled(&self) -> bool {
        self.color
    }
}
