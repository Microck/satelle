#[path = "command-history.rs"]
mod command_history;
mod completions;
#[path = "error-output.rs"]
mod error_output;
#[path = "host-trust.rs"]
mod host_trust;
mod logs;
mod mcp;
mod output;
mod read;
mod tailscale;
#[path = "tailscale-serve.rs"]
mod tailscale_serve;
mod transport;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use completions::{CompletionsCommand, run_completions};
use error_output::{ErrorFormat, parser_error, print_error};
use host_trust::{HostTrustReport, persist_host_identity};
use logs::{LogsCommand, show_logs};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use output::{OutputArgs, OutputFormat, SessionResultSchemaVersion, StatusReport};
use satelle_core::session::{
    EffectiveModelRef, HostIdentityRef, ProviderBindingRef, PublicSession, PublicTurn,
    TurnAdmissionPhase, TurnExecutionMode, TurnState,
};
use satelle_core::{
    BEACON_CORAL, CLI_NAME, DaemonPathOverrides, DesktopSessionPreference, DoctorEventRecord,
    DoctorOptions, DoctorReport, ERROR_RED, ErrorCode, EventSource, EventType, HostConfig,
    HostSessionsReport, LOCAL_DEMO_HOST, OwnerOnlyDirectory, PRODUCT_NAME, ProfileField,
    RELAY_ROSE, ResolvedConfig, SUCCESS_GREEN, SatelleError, SatelleEvent, SatelleEventBody,
    SecureFileError, SessionId, SetupMode, SetupReport, SetupRequiredInput, load_config,
    open_or_create_owner_only_directory, open_or_create_owner_only_file, open_owner_only_directory,
    read_owner_controlled_config_file, read_owner_only_secret_config_file, resolve_path_set,
    utc_now,
};
use satelle_host::{
    ApiBearerToken, HostService, ProviderComputerUseIntent, contains_api_bearer_token,
};
use satelle_transport::{
    DaemonServer, DaemonServerConfig, DaemonServerError, DaemonTlsConfig, DaemonTlsConfigError,
    DaemonTlsReloadError, DaemonTlsReloader, TurnRequest,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tailscale::transport_doctor_report;
use transport::{
    AttachedTurnOutcome, SshBootstrapScope, discover_direct_host_identity,
    discover_ssh_host_identity, transport_for, transport_for_setup,
};

const CONFIG_CHECK_SCHEMA_VERSION: &str = "satelle.config.check.v1";
const CONFIG_EXPLAIN_SCHEMA_VERSION: &str = "satelle.config.explain.v1";
const PATHS_SCHEMA_VERSION: &str = "satelle.paths.v1";
const DEFAULT_ON_DEMAND_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SSH_STATE_RELEASE_REQUEST: &str = "ssh-state-release.request";
const SSH_STATE_RELEASE_REQUESTER_LOCK: &str = "ssh-state-release.requester.lock";
const STATE_OWNERSHIP_LOCK: &str = "satelle.sqlite3.lock";
const STATE_RELEASE_TIMEOUT: Duration = Duration::from_secs(20);
const STATE_RELEASE_POLL_INTERVAL: Duration = Duration::from_millis(50);
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

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
    resolved: Arc<OnceLock<Result<ResolvedConfig, SatelleError>>>,
}

#[derive(Debug)]
struct SelectedHost {
    alias: String,
    config: HostConfig,
}

impl From<(String, HostConfig)> for SelectedHost {
    fn from((alias, config): (String, HostConfig)) -> Self {
        Self { alias, config }
    }
}

impl<'a> ConfigContext<'a> {
    fn new(flag_profile: Option<&'a str>) -> Self {
        Self {
            flag_profile,
            resolved: Arc::new(OnceLock::new()),
        }
    }

    fn load(&self) -> Result<&ResolvedConfig, CliFailure> {
        let resolved = self.resolved.get_or_init(|| {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            load_config(&cwd, self.flag_profile)
        });
        resolved.as_ref().map_err(|error| failure(error.clone()))
    }

    fn resolve_host(&self, flag_host: Option<&str>) -> Result<SelectedHost, CliFailure> {
        self.load()?
            .resolve_host(flag_host)
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
    scope: Option<String>,
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
    /// Internal SSH setup lock held only while stdin remains connected.
    #[command(hide = true)]
    BootstrapLock,
    /// Internal owner-local request for a running SSH daemon to release its store.
    #[command(hide = true)]
    ReleaseState,
    /// Authenticate a direct Host and pin its stable identity in user configuration.
    Trust(HostTrustCommand),
    Status(HostStatusCommand),
    Stop(HostLifecycleCommand),
    Restart(HostLifecycleCommand),
    Update(HostUpdateCommand),
    Sessions(HostSessionsCommand),
    Storage {
        #[command(subcommand)]
        command: HostStorageCommand,
    },
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
    #[arg(long, default_value = "127.0.0.1:3001")]
    bind: String,
    /// PEM certificate chain for Host-terminated HTTPS and WSS.
    #[arg(long, value_name = "PATH", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// Owner-only PEM private key matching --tls-cert.
    #[arg(long, value_name = "PATH", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    #[arg(long)]
    foreground: bool,
    /// Internal SSH bootstrap boundary. The token is read once from stdin and
    /// retained only by this daemon process.
    #[arg(long, hide = true)]
    bootstrap_token_stdin: bool,
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
    #[command(flatten)]
    output_args: OutputArgs,
}

#[derive(Args, Debug)]
struct RunCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    detach: bool,
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
    #[arg(long)]
    prompt_file: Option<PathBuf>,
    #[command(flatten)]
    output_args: OutputArgs,
    #[arg(value_name = "PROMPT_OR_DASH")]
    prompt: Option<String>,
}

#[derive(Args, Debug)]
struct SteerCommand {
    session_id: String,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    detach: bool,
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
    #[arg(long)]
    prompt_file: Option<PathBuf>,
    #[command(flatten)]
    output_args: OutputArgs,
    #[arg(value_name = "PROMPT_OR_DASH")]
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
        return ExitCode::from(error.exit_code() as u8);
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
            return ExitCode::from(error.exit_code() as u8);
        }
    };
    let error_format =
        ErrorFormat::resolve(cli.error_format, cli.command.requests_machine_errors());

    match try_main(cli, error_format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            print_error(&failure.error, error_format);
            ExitCode::from(failure.error.exit_code() as u8)
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

fn try_main(cli: Cli, error_format: ErrorFormat) -> Result<(), CliFailure> {
    let Cli {
        no_color,
        profile,
        error_format: _,
        command,
    } = cli;
    let config = ConfigContext::new(profile.as_deref());
    let history = start_command_history(&command, &config);
    let outcome = execute_command(command, no_color, profile.as_deref(), config);

    if let Some(history) = history {
        let session_id = match &outcome {
            Ok(session_id) => session_id.as_ref(),
            Err(failure) => failure.history_session_id.as_deref(),
        };
        let error_code = outcome.as_ref().err().map(|failure| failure.error.code);
        if let Err(error) = history.finish(session_id, error_code)
            && error_format == ErrorFormat::Human
        {
            // History is non-authoritative and cannot replace the command's
            // outcome, but operators still need to know when a row was lost.
            eprintln!("warning: command history was not recorded: {error}");
        }
    }

    outcome.map(|_| ())
}

fn execute_command(
    command: Command,
    no_color: bool,
    profile: Option<&str>,
    config: ConfigContext<'_>,
) -> Result<Option<SessionId>, CliFailure> {
    let early_lifecycle_host = explicit_lifecycle_json_host(&command).map(str::to_owned);
    let (output_args, event_output) = command.output_request();
    let output = match output_args.resolve(event_output) {
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
    let human_style = HumanStyle::detect(no_color);

    match command {
        Command::Completions(command) => run_completions(command).map_err(failure).map(|_| None),
        Command::Setup(command) => run_setup(command, human_style, config, output).map(|_| None),
        Command::Repair(command) => run_repair(command).map(|_| None),
        Command::Doctor(command) => run_doctor(command, config, output).map(|_| None),
        Command::Config { command } => run_config(command, config, output).map(|_| None),
        Command::Paths(command) => show_paths(command, output).map(|_| None),
        Command::Host { command } => run_host(command, config, output).map(|_| None),
        Command::SelfCtl { command } => run_self(command).map(|_| None),
        Command::Run(command) => run_prompt(command, config, output).map(Some),
        Command::Steer(command) => steer_prompt(command, config, output).map(Some),
        Command::Status(command) => show_status(command, config, output).map(|_| None),
        Command::Stop(command) => stop_session(command, config, output).map(|_| None),
        Command::Logs(command) => show_logs(command, config, output).map(|_| None),
        Command::Mcp {
            command: McpCommand::Serve,
        } => mcp::serve(profile).map(|_| None),
        Command::Support { command } => run_support(command).map(|_| None),
    }
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
            // Repair does not consume ConfigContext; its handler defaults
            // directly to the local demo Host when --host is absent.
            explicit_host: Some(command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)),
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
            command: HostCommand::BootstrapLock | HostCommand::ReleaseState,
        } => return None,
        Command::Host { command } => HistoryTarget {
            family: "host",
            selects_host: match command {
                HostCommand::Start(command) => {
                    !command.foreground && !command.bootstrap_token_stdin
                }
                HostCommand::Update(command) => command.host.len() == 1 && !command.all_remotes,
                _ => true,
            },
            explicit_host: match command {
                HostCommand::Start(_) => None,
                HostCommand::BootstrapLock => None,
                HostCommand::ReleaseState => None,
                HostCommand::Trust(command) => Some(command.host.as_str()),
                HostCommand::Status(command) => command.host.as_deref(),
                HostCommand::Stop(command) | HostCommand::Restart(command) => {
                    Some(command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST))
                }
                HostCommand::Update(command) => (command.host.len() == 1 && !command.all_remotes)
                    .then(|| command.host[0].as_str()),
                HostCommand::Sessions(command) => command.host.as_deref(),
                HostCommand::Storage {
                    command: HostStorageCommand::Migrate(command),
                } => Some(command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)),
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
                bootstrap_token_stdin,
                bootstrap_scope: bootstrap_token_stdin.then_some(SshBootstrapScope::Control),
                bootstrap_native_readiness_timeout_ms: None,
                bootstrap_provider_smoke_timeout_ms: None,
                on_demand_idle_timeout_ms: None,
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
    fn durable_ssh_idle_timeout_is_an_explicit_internal_argument() {
        let cli = Cli::try_parse_from([
            "satelle",
            "host",
            "start",
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
        assert!(!command.bootstrap_token_stdin);
    }
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
    if command
        .expected_host_id
        .as_deref()
        .zip(host.config.expected_host_id.as_deref())
        .is_some_and(|(required, configured)| required != configured)
    {
        return Err(failure(SatelleError::host_identity_mismatch(&host.alias)));
    }
    let first_ssh_trust = host.config.transport == satelle_core::TransportKind::Ssh
        && host.config.expected_host_id.is_none();
    let daemon_path_overrides = daemon_path_overrides(&command, &host.config).map_err(failure)?;
    let setup_components = setup_components(&command.component).map_err(failure)?;
    let explicit_provider_auth = command
        .component
        .iter()
        .any(|component| component == &SetupComponent::ProviderAuth);
    let setup_mode = setup_mode(&command, &host.config).map_err(failure)?;
    let consent_recovery_command = setup_consent_recovery_command(
        &command,
        config.flag_profile,
        &setup_mode,
        &daemon_path_overrides,
        first_ssh_trust,
    );

    let tailscale_serve_setup = command.component.as_slice() == [SetupComponent::Transport]
        && tailscale_serve::applies_to(&host.config);
    let mut transport = if tailscale_serve_setup {
        None
    } else {
        Some(transport_for_setup(&host)?)
    };
    let mut report = if tailscale_serve_setup {
        tailscale_serve::configure(&host.alias, &host.config, true, &setup_mode).map_err(failure)?
    } else {
        transport
            .as_ref()
            .expect("ordinary setup transport is present")
            .setup(
                true,
                setup_mode.clone(),
                setup_components.clone(),
                daemon_path_overrides.clone(),
            )
            .map_err(failure)?
    };
    report.dry_run = command.dry_run;
    add_setup_required_inputs(&mut report, &host.config, explicit_provider_auth);

    if !command.dry_run && report.required_input.is_empty() {
        if !command.yes && (command.no_input || json || !io::stdin().is_terminal()) {
            return Err(failure(SatelleError::setup_consent_required(
                &report.planned_actions,
                &consent_recovery_command,
            )));
        }

        if !command.yes {
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
            print_setup_human(&report);
            let confirmed = cliclack::confirm("Apply these setup mutations?")
                .initial_value(false)
                .interact()
                .map_err(|source| {
                    failure(SatelleError {
                        code: ErrorCode::InvalidUsage,
                        message: "could not read setup confirmation".to_string(),
                        recovery_command: Some("rerun with --yes or --dry-run".to_string()),
                        source_detail: Some(source.to_string()),
                        details: BTreeMap::new(),
                    })
                })?;
            if !confirmed {
                return Err(failure(SatelleError::setup_consent_required(
                    &report.planned_actions,
                    &consent_recovery_command,
                )));
            }
        }

        if first_ssh_trust {
            if !trust_first_ssh_host_during_setup(&command, json, &user_config_path, &mut host)? {
                println!("No changes applied.");
                return Ok(());
            }
            transport = Some(transport_for_setup(&host)?);
        }

        report = if tailscale_serve_setup {
            tailscale_serve::configure(&host.alias, &host.config, false, &setup_mode)
                .map_err(failure)?
        } else {
            transport
                .as_ref()
                .expect("ordinary setup transport is present")
                .setup(false, setup_mode, setup_components, daemon_path_overrides)
                .map_err(failure)?
        };
        add_setup_required_inputs(&mut report, &host.config, explicit_provider_auth);
        if first_ssh_trust {
            report.planned_actions.insert(
                0,
                "discover and explicitly trust the reachable Host Identity".to_string(),
            );
            report.applied_actions.insert(
                0,
                "discovered and explicitly trusted the reachable Host Identity".to_string(),
            );
            report.mutated = true;
        }
    }

    if !command.dry_run && report.required_input.is_empty() && !command.no_input && !json {
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
        print_json(&report).map_err(failure)
    } else {
        print_setup_human(&report);
        Ok(())
    }
}

fn trust_first_ssh_host_during_setup(
    command: &SetupCommand,
    json: bool,
    user_config_path: &Path,
    host: &mut SelectedHost,
) -> Result<bool, CliFailure> {
    let noninteractive = command.no_input || json || !io::stdin().is_terminal();
    if noninteractive && (!command.no_input || !command.yes || command.expected_host_id.is_none()) {
        return Err(failure(SatelleError::invalid_usage(
            "noninteractive first-time SSH setup requires --no-input --yes --expected-host-id <exact-id>",
        )));
    }

    let observed_identity = discover_ssh_host_identity(host).map_err(failure)?;
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

    if command.expected_host_id.is_none() {
        println!("Host: {}", host.alias);
        println!(
            "Endpoint: {}",
            host.config.address.as_deref().unwrap_or("not configured")
        );
        println!("Observed Host Identity: {observed_identity}");
        println!("Current expected Host Identity: not pinned");
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
            return Ok(false);
        }
    }

    persist_host_identity(user_config_path, &host.alias, &observed_identity).map_err(failure)?;
    host.config.expected_host_id = Some(observed_identity);
    Ok(true)
}

fn add_setup_required_inputs(
    report: &mut SetupReport,
    host_config: &HostConfig,
    explicit_provider_auth: bool,
) {
    if !explicit_provider_auth || !host_config.provider_auth.is_empty() {
        return;
    }

    report.status = "input_required".to_string();
    report.readiness_summary.provider_auth = "secret_source_required".to_string();
    report.required_input.push(SetupRequiredInput {
        component: "provider-auth".to_string(),
        input_kind: "provider_secret_source_descriptor".to_string(),
        reason: "provider authentication setup needs a host-resolved Secret Source descriptor; raw provider secrets are not accepted through noninteractive setup".to_string(),
        recovery_command: "add [hosts.<alias>.provider_auth.<provider>] to user-level config, then rerun satelle setup --component provider-auth --no-input --json".to_string(),
    });
    report.recovery_commands.push(
        "add a host-resolved provider_auth Secret Source descriptor to user-level config"
            .to_string(),
    );
}

fn daemon_path_overrides(
    command: &SetupCommand,
    host_config: &HostConfig,
) -> Result<DaemonPathOverrides, SatelleError> {
    let mut sources = BTreeMap::new();
    let home = select_daemon_path_override(
        "--daemon-home",
        "SATELLE_HOME",
        command.daemon_home.as_ref(),
        host_config.daemon_home.as_ref(),
        &mut sources,
    )?;
    let config_file = select_daemon_path_override(
        "--daemon-config-file",
        "SATELLE_CONFIG_FILE",
        command.daemon_config_file.as_ref(),
        host_config.daemon_config_file.as_ref(),
        &mut sources,
    )?;
    let state_dir = select_daemon_path_override(
        "--daemon-state-dir",
        "SATELLE_STATE_DIR",
        command.daemon_state_dir.as_ref(),
        host_config.daemon_state_dir.as_ref(),
        &mut sources,
    )?;
    let cache_dir = select_daemon_path_override(
        "--daemon-cache-dir",
        "SATELLE_CACHE_DIR",
        command.daemon_cache_dir.as_ref(),
        host_config.daemon_cache_dir.as_ref(),
        &mut sources,
    )?;
    let log_dir = select_daemon_path_override(
        "--daemon-log-dir",
        "SATELLE_LOG_DIR",
        command.daemon_log_dir.as_ref(),
        host_config.daemon_log_dir.as_ref(),
        &mut sources,
    )?;

    Ok(DaemonPathOverrides {
        home,
        config_file,
        state_dir,
        cache_dir,
        log_dir,
        sources,
    })
}

fn select_daemon_path_override(
    flag: &'static str,
    environment_variable: &'static str,
    flag_value: Option<&PathBuf>,
    config_value: Option<&PathBuf>,
    sources: &mut BTreeMap<String, String>,
) -> Result<Option<PathBuf>, SatelleError> {
    if let Some(value) = validate_daemon_path(flag, flag_value)? {
        sources.insert(environment_variable.to_string(), "setup_flag".to_string());
        return Ok(Some(value));
    }

    if let Some(value) = validate_daemon_path(environment_variable, config_value)? {
        sources.insert(environment_variable.to_string(), "user_config".to_string());
        return Ok(Some(value));
    }

    Ok(None)
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

fn setup_mode(command: &SetupCommand, host_config: &HostConfig) -> Result<String, SatelleError> {
    if command.on_demand && command.persistent {
        return Err(SatelleError::invalid_usage(
            "--on-demand and --persistent cannot be combined",
        ));
    }
    if command.on_demand {
        return Ok("on_demand".to_string());
    }
    if command.persistent {
        return Ok("persistent".to_string());
    }

    Ok(host_config
        .setup_mode
        .unwrap_or(SetupMode::OnDemand)
        .as_str()
        .to_string())
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

fn validate_daemon_path(
    flag: &str,
    path: Option<&PathBuf>,
) -> Result<Option<PathBuf>, SatelleError> {
    let Some(path) = path else {
        return Ok(None);
    };
    if path.is_absolute() && !path.starts_with("~") {
        return Ok(Some(path.clone()));
    }

    Err(SatelleError::daemon_path_override_not_absolute(
        flag,
        path.display().to_string(),
    ))
}

fn run_repair(command: RepairCommand) -> Result<(), CliFailure> {
    if command.no_input && !command.dry_run && !command.yes {
        return Err(failure(SatelleError::input_required(
            "repair needs --yes when --no-input is used for mutations",
        )));
    }

    Err(failure(SatelleError::not_implemented(format!(
        "repair planning is not implemented yet for host {}",
        command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
    ))))
}

fn run_doctor(
    command: DoctorCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let json = format.is_json();
    let target_hint = command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST);
    if let Err(failure) = validate_doctor_scope(command.scope.as_deref()) {
        return fail_doctor(
            failure,
            command.events,
            target_hint,
            command.scope.as_deref(),
        );
    }
    let timeout = match command
        .timeout
        .as_deref()
        .map(parse_positive_duration_ms)
        .transpose()
    {
        Ok(timeout) => timeout.map(std::time::Duration::from_millis),
        Err(error) => {
            return fail_doctor(
                failure(error),
                command.events,
                target_hint,
                command.scope.as_deref(),
            );
        }
    };
    if timeout.is_some()
        && (!command.refresh || !doctor_scope_supports_refresh(command.scope.as_deref()))
    {
        return fail_doctor(
            failure(SatelleError::doctor_refresh_timeout_without_refresh()),
            command.events,
            target_hint,
            command.scope.as_deref(),
        );
    }
    if command.refresh && !doctor_scope_supports_refresh(command.scope.as_deref()) {
        return fail_doctor(
            failure(SatelleError::doctor_refresh_scope_required()),
            command.events,
            target_hint,
            command.scope.as_deref(),
        );
    }

    let resolved_config = match config.load() {
        Ok(config) => config,
        Err(failure) => {
            return fail_doctor(
                failure,
                command.events,
                target_hint,
                command.scope.as_deref(),
            );
        }
    };
    let host = match resolved_config.resolve_host(command.host.as_deref()) {
        Ok(resolved) => SelectedHost::from(resolved),
        Err(error) => {
            return fail_doctor(
                failure(error),
                command.events,
                target_hint,
                command.scope.as_deref(),
            );
        }
    };
    if command.scope.as_deref() == Some("transport")
        && let Some(report) = transport_doctor_report(&host.alias, &host.config)
    {
        return emit_doctor_report(report, command.events, json);
    }
    let transport = match transport_for(&host) {
        Ok(transport) => transport,
        Err(failure) => {
            return fail_doctor(
                failure,
                command.events,
                &host.alias,
                command.scope.as_deref(),
            );
        }
    };
    let options = DoctorOptions::new(command.refresh, timeout);
    let provider_intent = match doctor_provider_intent(
        resolved_config,
        &host.config,
        command.refresh,
        options.probe_timeout(),
    ) {
        Ok(intent) => intent,
        Err(error) => {
            return fail_doctor(
                failure(error),
                command.events,
                &host.alias,
                command.scope.as_deref(),
            );
        }
    };
    let report = match transport.doctor(command.scope.as_deref(), options, &provider_intent) {
        Ok(report) => report,
        Err(error) => {
            return fail_doctor(
                failure(error),
                command.events,
                &host.alias,
                command.scope.as_deref(),
            );
        }
    };

    emit_doctor_report(report, command.events, json)
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
            return Err(failure(error));
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

fn fail_doctor(
    failure: CliFailure,
    events: bool,
    target: &str,
    scope: Option<&str>,
) -> Result<(), CliFailure> {
    if events {
        print_doctor_failed_event(target, scope, &failure.error).map_err(|error| CliFailure {
            error,
            history_session_id: None,
        })?;
    }

    Err(failure)
}

fn validate_doctor_scope(scope: Option<&str>) -> Result<(), CliFailure> {
    let Some(scope) = scope else {
        return Ok(());
    };

    if [
        "transport",
        "codex",
        "computer-use",
        "provider",
        "config",
        "all",
    ]
    .contains(&scope)
    {
        return Ok(());
    }

    Err(failure(SatelleError::invalid_usage(format!(
        "unsupported doctor scope '{scope}'; expected transport, codex, computer-use, provider, config, or all"
    ))))
}

fn doctor_scope_supports_refresh(scope: Option<&str>) -> bool {
    matches!(scope, None | Some("computer-use" | "provider" | "all"))
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
    let mut seq = 1_u64;
    let mut records = Vec::new();
    records.push(doctor_event(
        &mut seq,
        "doctor_started",
        report,
        "all",
        None,
        "running",
        json!({"scopes": report.scopes}),
    ));

    for probe in &report.probe_results {
        records.push(doctor_event(
            &mut seq,
            "probe_started",
            report,
            &probe.scope,
            Some(&probe.probe_id),
            "running",
            json!({"cache_status": probe.cache_status}),
        ));
        records.push(doctor_event(
            &mut seq,
            "probe_finished",
            report,
            &probe.scope,
            Some(&probe.probe_id),
            &probe.status,
            json!(probe),
        ));
    }

    for finding in &report.findings {
        records.push(doctor_event(
            &mut seq,
            "finding_reported",
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
            "cache_updated",
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
            "doctor_failed",
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
            "doctor_finished",
            report,
            "all",
            None,
            &report.status,
            json!(report),
        ));
    }

    for record in records {
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

fn print_doctor_failed_event(
    target: &str,
    scope: Option<&str>,
    error: &SatelleError,
) -> Result<(), SatelleError> {
    let record = DoctorEventRecord {
        schema_version: "satelle.doctor.events.v1".to_string(),
        event_id: "doctor_event_1".to_string(),
        event_type: "doctor_failed".to_string(),
        target: target.to_string(),
        scope: scope.unwrap_or("all").to_string(),
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
            "partial_probe_results": [],
            "recovery_commands": error.recovery_command.iter().collect::<Vec<_>>(),
        }),
    };

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

    Ok(())
}

fn doctor_event(
    seq: &mut u64,
    event_type: &str,
    report: &DoctorReport,
    scope: &str,
    probe_id: Option<&str>,
    status: &str,
    data: serde_json::Value,
) -> DoctorEventRecord {
    let event = DoctorEventRecord {
        schema_version: "satelle.doctor.events.v1".to_string(),
        event_id: format!("doctor_event_{seq}"),
        event_type: event_type.to_string(),
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
        Ok(())
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
    let Some(hosts) = value
        .get_mut("hosts")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return value;
    };

    for host in hosts.values_mut() {
        let Some(host_object) = host.as_object_mut() else {
            continue;
        };

        if let Some(api_token) = host_object.get_mut("api_token") {
            redact_secret_source_descriptor(api_token, show_secret_references);
        }

        let Some(provider_auth) = host_object
            .get_mut("provider_auth")
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };

        for descriptor in provider_auth.values_mut() {
            redact_secret_source_descriptor(descriptor, show_secret_references);
        }
    }

    value
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
) -> serde_json::Value {
    let model_alias_source =
        if config.profile_overrides_for_host(ProfileField::ModelAlias, selected_host) {
            json!("user_config_profile")
        } else {
            root_config_key_source(
                "model_alias",
                &config.user_config_path,
                &config.project_config_path,
            )
        };
    let provider_alias_source =
        if config.profile_overrides_for_host(ProfileField::ProviderAlias, selected_host) {
            json!("user_config_profile")
        } else {
            root_config_key_source(
                "provider_alias",
                &config.user_config_path,
                &config.project_config_path,
            )
        };

    json!({
        "requested_model_alias": config.config.model_alias,
        "requested_provider_alias": config.config.provider_alias,
        "resolved_codex_model": serde_json::Value::Null,
        "resolved_model_provider": serde_json::Value::Null,
        "binding_status": if config.config.model_alias.is_some() || config.config.provider_alias.is_some() {
            "binding_required"
        } else {
            "host_default"
        },
        "model_alias_source": model_alias_source,
        "provider_alias_source": provider_alias_source,
        "contributing_config_files": [
            config.user_config_path,
            config.project_config_path,
        ],
        "winning_source": model_alias_source
            .as_str()
            .or_else(|| provider_alias_source.as_str())
            .unwrap_or("host_default"),
    })
}

fn experimental_provider_computer_use_json(
    config: &satelle_core::ResolvedConfig,
    selected_host: &str,
    selected_host_config: &HostConfig,
) -> serde_json::Value {
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
    host_config: &HostConfig,
    config: &satelle_core::ResolvedConfig,
) -> bool {
    command_flag
        || host_config
            .experimental_provider_computer_use
            .or(config.config.experimental_provider_computer_use)
            .unwrap_or(false)
}

fn doctor_provider_intent(
    config: &ResolvedConfig,
    host_config: &HostConfig,
    refresh: bool,
    probe_timeout: Option<std::time::Duration>,
) -> Result<ProviderComputerUseIntent, SatelleError> {
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
    let intent = ProviderComputerUseIntent::new(
        model,
        provider,
        resolve_experimental_provider_computer_use(false, host_config, config),
        refresh,
    );
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

fn show_paths(command: PathsCommand, format: OutputFormat) -> Result<(), CliFailure> {
    let json = format.is_json();
    let output = read::paths_report(command.host)?;

    if json {
        print_json(&output).map_err(failure)
    } else {
        println!("Host: {}", output["host"].as_str().unwrap_or_default());
        println!(
            "Config: {}",
            output["config_file"].as_str().unwrap_or_default()
        );
        println!(
            "Cache: {}",
            output["cache_root"].as_str().unwrap_or_default()
        );
        println!(
            "State: {}",
            output["state_root"].as_str().unwrap_or_default()
        );
        println!(
            "SQLite: {}",
            output["sqlite_store"].as_str().unwrap_or_default()
        );
        println!(
            "Operator logs: {}",
            output["operator_log_root"].as_str().unwrap_or_default()
        );
        println!(
            "Recordings: {}",
            output["recording_root"].as_str().unwrap_or_default()
        );
        println!(
            "Project config: {}",
            output["project_config_file"].as_str().unwrap_or_default()
        );
        println!(
            "Install receipt: {}",
            output["install_receipt"].as_str().unwrap_or_default()
        );
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
        HostCommand::BootstrapLock => hold_ssh_bootstrap_lock(),
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
        HostCommand::Stop(command) => Err(failure(SatelleError::not_implemented(format!(
            "host stop is not implemented yet for host {}",
            command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
        )))),
        HostCommand::Restart(command) => Err(failure(SatelleError::not_implemented(format!(
            "host restart is not implemented yet for host {}",
            command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
        )))),
        HostCommand::Update(command) => run_host_update(command),
        HostCommand::Sessions(command) => show_host_sessions(command, config, format),
        HostCommand::Storage { command } => run_host_storage(command),
    }
}

fn hold_ssh_bootstrap_lock() -> Result<(), CliFailure> {
    let state_root = satelle_core::state_dir().map_err(failure)?;
    drop(
        open_or_create_owner_only_directory(&state_root)
            .map_err(|error| ssh_bootstrap_lock_failure(&state_root, error))?,
    );
    let lock_path = state_root.join("bootstrap.lock");
    let lock = open_or_create_owner_only_file(&lock_path)
        .map_err(|error| ssh_bootstrap_lock_failure(&lock_path, error))?;
    lock.lock()
        .map_err(|error| ssh_bootstrap_lock_failure(&lock_path, error))?;

    serve_ssh_bootstrap_lock_protocol(io::stdin().lock(), io::stdout().lock())
        .map_err(|error| ssh_bootstrap_lock_failure(&lock_path, error))?;
    Ok(())
}

fn serve_ssh_bootstrap_lock_protocol(
    input: impl BufRead,
    mut output: impl Write,
) -> io::Result<()> {
    writeln!(output, "{}", transport::SSH_BOOTSTRAP_LOCK_READY)?;
    output.flush()?;
    for line in input.lines() {
        writeln!(output, "{}", line?)?;
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod ssh_bootstrap_lock_tests {
    use super::*;

    #[test]
    fn lock_protocol_echoes_challenges_only_after_readiness() {
        let mut output = Vec::new();
        serve_ssh_bootstrap_lock_protocol(
            io::Cursor::new(b"challenge-one\nchallenge-two\n"),
            &mut output,
        )
        .expect("serve lock protocol");

        assert_eq!(
            String::from_utf8(output).expect("UTF-8 lock protocol"),
            format!(
                "{}\nchallenge-one\nchallenge-two\n",
                transport::SSH_BOOTSTRAP_LOCK_READY
            )
        );
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

fn ssh_bootstrap_lock_failure(path: &Path, error: impl std::fmt::Display) -> CliFailure {
    failure(SatelleError::config_error(
        format!(
            "could not hold the SSH bootstrap lock at '{}': {error}",
            path.display()
        ),
        None,
    ))
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

fn start_host_daemon(
    command: HostStartCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    if command.foreground && command.bootstrap_token_stdin {
        return Err(failure(SatelleError::invalid_usage(
            "SSH bootstrap tokens are valid only for on-demand Host Daemons",
        )));
    }
    if command.bootstrap_token_stdin && (command.tls_cert.is_some() || command.tls_key.is_some()) {
        return Err(failure(SatelleError::invalid_usage(
            "SSH bootstrap Host Daemons use loopback plaintext inside the authenticated tunnel and do not accept TLS files",
        )));
    }
    if command.on_demand_idle_timeout_ms.is_some()
        && (command.foreground || command.bootstrap_token_stdin)
    {
        return Err(failure(SatelleError::invalid_usage(
            "the resolved on-demand idle timeout is valid only for durable on-demand Host Daemons",
        )));
    }
    if command.on_demand_idle_timeout_ms == Some(0) {
        return Err(failure(SatelleError::invalid_usage(
            "the resolved on-demand idle timeout must be positive",
        )));
    }
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
    install_host_daemon_diagnostics();
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
        .then(read_ssh_bootstrap_token)
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
    let service = match (on_demand_host.as_ref(), bootstrap_token.as_ref()) {
        (_, Some(token)) => {
            let mut host_config = satelle_core::SatelleConfig::defaults()
                .hosts
                .remove(LOCAL_DEMO_HOST)
                .expect("the built-in local Host config exists");
            host_config.timeouts = forwarded_readiness_timeouts;
            HostService::production_for_ssh_bootstrap(
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
        let mut server_config = DaemonServerConfig::loopback(bind_addr);
        if let Some(idle_timeout) = idle_timeout {
            server_config = server_config.with_idle_timeout(idle_timeout);
        }
        let (server, _tls_reload_watcher) = match tls {
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
                let watcher =
                    DaemonTlsWatcher::start(certificate_path, private_key_path, reloader)?;
                (server, Some(watcher))
            }
            None => (
                DaemonServer::bind(service, server_config)
                    .await
                    .map_err(daemon_server_failure)?,
                None,
            ),
        };

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
        })),
        (None, None) => Ok(None),
        _ => Err(SatelleError::invalid_usage(
            "SSH launch readiness timeouts must be provided together",
        )),
    }
}

fn install_host_daemon_diagnostics() {
    // Host start reserves stdout for its human or machine-readable readiness
    // response. Send structured runtime diagnostics to stderr so token
    // lifecycle events are observable without corrupting that protocol.
    let _subscriber_already_installed = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(true)
        .with_writer(io::stderr)
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .try_init();
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
            bootstrap_token_stdin: false,
            bootstrap_scope: None,
            bootstrap_native_readiness_timeout_ms: None,
            bootstrap_provider_smoke_timeout_ms: None,
            on_demand_idle_timeout_ms: None,
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

    let native_selector = host
        .desktop_session_native_selector
        .as_ref()
        .map(|selector| format!("{}:{}:{}", selector.platform, selector.kind, selector.value));
    let selected_index = {
        let mut matches = report
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, session)| {
                host.desktop_user
                    .as_deref()
                    .is_none_or(|user| user == session.desktop_user)
            })
            .filter(|(_, session)| {
                if let Some(selector) = &native_selector {
                    session.native_selectors.contains(selector)
                } else {
                    match host.desktop_session_preference {
                        Some(DesktopSessionPreference::Console) => session.is_console,
                        Some(DesktopSessionPreference::Only) | None => true,
                    }
                }
            })
            .map(|(index, _)| index);
        let first = matches.next();
        if matches.next().is_some() {
            None
        } else {
            first
        }
    };

    if let Some(index) = selected_index {
        report.sessions[index].selected_by_current_config = true;
    }
}

fn run_host_update(command: HostUpdateCommand) -> Result<(), CliFailure> {
    validate_host_update_components(&command.component).map_err(failure)?;
    Err(failure(SatelleError::not_implemented(concat!(
        "Host update was not run because live Host planning and application are not ",
        "implemented. No Host state or Satelle sessions were changed."
    ))))
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

fn run_host_storage(command: HostStorageCommand) -> Result<(), CliFailure> {
    match command {
        HostStorageCommand::Migrate(command) => {
            Err(failure(SatelleError::not_implemented(format!(
                "host storage migration is not implemented yet for host {}",
                command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
            ))))
        }
    }
}

fn run_self(command: SelfSubcommand) -> Result<(), CliFailure> {
    match command {
        SelfSubcommand::Update(command) => {
            if command.concurrency == 0 || command.concurrency > 16 {
                return Err(failure(SatelleError::concurrency_limit_exceeded(
                    command.concurrency,
                )));
            }

            if !command.update_remotes {
                if command.concurrency != 4 {
                    return Err(failure(SatelleError::concurrency_without_remote_update()));
                }

                if command.all_remotes || !command.host.is_empty() {
                    return Err(failure(SatelleError::invalid_usage(
                        "--host and --all-remotes require --update-remotes",
                    )));
                }
            }

            Err(failure(SatelleError::not_implemented(format!(
                "self update is not implemented yet{}",
                command
                    .version
                    .as_ref()
                    .map(|version| format!(" for version {version}"))
                    .unwrap_or_default()
            ))))
        }
    }
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

fn run_prompt(
    command: RunCommand,
    config_context: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<SessionId, CliFailure> {
    let json = format.is_json();
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
            .resolve_host(explicit_host_alias)
            .map(SelectedHost::from)
            .map_err(failure),
    )?;
    let transport = match transport_for(&host) {
        Ok(transport) => transport,
        Err(transport_failure) => {
            if !command.detach {
                event_output
                    .emit_preflight(&host.alias, "run", &host.config.transport)
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
    let effective_timeouts = effective_timeouts_json(&host.config);
    let yolo_policy = resolve_yolo_policy(
        config,
        &host.alias,
        &host.config,
        command.yolo,
        command.no_yolo,
    );
    let experimental_provider_computer_use = resolve_experimental_provider_computer_use(
        command.experimental_provider_computer_use,
        &host.config,
        config,
    );
    let request = TurnRequest::new(prompt)
        .with_execution_mode(yolo_policy.execution_mode())
        .with_provider_intent(
            config.config.model_alias.clone(),
            config.config.provider_alias.clone(),
            experimental_provider_computer_use,
            command.refresh_provider_smoke_test,
        );
    if command.detach {
        let session = transport.run_detached(&request).map_err(failure)?;
        return print_detached_session(
            session,
            &host.alias,
            effective_timeouts,
            &yolo_policy,
            SessionResultSchemaVersion::RunV2,
            json,
        );
    }

    event_output
        .emit_preflight(&host.alias, "run", &host.config.transport)
        .map_err(failure)?;
    let outcome = match transport.run(&request, &mut |event| event_output.emit(&host.alias, event))
    {
        Ok(outcome) => outcome,
        Err(attached_failure) => {
            let history_session_id = attached_failure
                .durable_handles()
                .map(|(session_id, _)| Box::new(session_id.clone()));
            event_output
                .emit_command_failed(
                    &host.alias,
                    attached_failure.error(),
                    attached_failure.phase(),
                    attached_failure.durable_handles(),
                )
                .map_err(|error| CliFailure {
                    error,
                    history_session_id: history_session_id.clone(),
                })?;
            return Err(CliFailure {
                error: attached_failure.into_error(),
                history_session_id,
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
            .resolve_host(explicit_host_alias)
            .map(SelectedHost::from)
            .map_err(failure),
    )?;
    let transport = match transport_for(&host) {
        Ok(transport) => transport,
        Err(transport_failure) => {
            if !command.detach {
                event_output
                    .emit_preflight(&host.alias, "steer", &host.config.transport)
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
    let effective_timeouts = effective_timeouts_json(&host.config);
    let yolo_policy = resolve_yolo_policy(
        config,
        &host.alias,
        &host.config,
        command.yolo,
        command.no_yolo,
    );
    let experimental_provider_computer_use = resolve_experimental_provider_computer_use(
        command.experimental_provider_computer_use,
        &host.config,
        config,
    );
    let request = TurnRequest::new(prompt)
        .with_execution_mode(yolo_policy.execution_mode())
        .with_provider_intent(
            config.config.model_alias.clone(),
            config.config.provider_alias.clone(),
            experimental_provider_computer_use,
            command.refresh_provider_smoke_test,
        );
    if command.detach {
        let session = transport
            .steer_detached(&session_id, &request)
            .map_err(failure)?;
        return print_detached_session(
            session,
            &host.alias,
            effective_timeouts,
            &yolo_policy,
            SessionResultSchemaVersion::SteerV2,
            json,
        );
    }

    event_output
        .emit_preflight(&host.alias, "steer", &host.config.transport)
        .map_err(failure)?;
    let outcome = match transport.steer(&session_id, &request, &mut |event| {
        event_output.emit(&host.alias, event)
    }) {
        Ok(outcome) => outcome,
        Err(attached_failure) => {
            let history_session_id = attached_failure
                .durable_handles()
                .map(|(session_id, _)| Box::new(session_id.clone()));
            event_output
                .emit_command_failed(
                    &host.alias,
                    attached_failure.error(),
                    attached_failure.phase(),
                    attached_failure.durable_handles(),
                )
                .map_err(|error| CliFailure {
                    error,
                    history_session_id: history_session_id.clone(),
                })?;
            return Err(CliFailure {
                error: attached_failure.into_error(),
                history_session_id,
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
            schema_version: SessionResultSchemaVersion::SteerV2,
            json,
        },
    )
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

fn effective_timeouts_json(host_config: &satelle_core::HostConfig) -> serde_json::Value {
    let timeouts = host_config.timeouts.as_ref();
    json!({
        "native_readiness_timeout_ms": timeouts
            .and_then(|timeouts| timeouts.native_readiness.as_ref())
            .map(|duration| duration.milliseconds()),
        "provider_smoke_test_timeout_ms": timeouts
            .and_then(|timeouts| timeouts.provider_smoke_test.as_ref())
            .map(|duration| duration.milliseconds()),
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

fn validate_event_mode(detach: bool, mode: EventMode) -> Result<(), CliFailure> {
    if detach && matches!(mode, EventMode::Human | EventMode::Json) {
        return Err(failure(SatelleError::events_with_detach()));
    }

    Ok(())
}

fn read_prompt(prompt: Option<String>, prompt_file: Option<PathBuf>) -> Result<String, CliFailure> {
    if prompt.is_some() && prompt_file.is_some() {
        return Err(failure(SatelleError::invalid_usage(
            "pass either PROMPT_OR_DASH or --prompt-file, not both",
        )));
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
        print_json(&json!({
            "schema_version": options.schema_version,
            "session_id": session.session_id(),
            "status": target_turn.state(),
            "effective_timeouts": options.effective_timeouts,
            "provider_smoke": provider_smoke,
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

fn print_detached_session(
    session: PublicSession,
    host: &str,
    effective_timeouts: serde_json::Value,
    yolo_policy: &YoloPolicy,
    schema_version: SessionResultSchemaVersion,
    json: bool,
) -> Result<SessionId, CliFailure> {
    let session_id = session.session_id().clone();
    let latest_turn = latest_turn(&session);
    if json {
        print_json(&json!({
            "schema_version": schema_version,
            "session_id": session.session_id(),
            "host": host,
            "status": latest_turn.state(),
            "created_at": session.created_at().format(&Rfc3339).expect("a public Session timestamp is RFC 3339 representable"),
            "updated_at": session.updated_at().format(&Rfc3339).expect("a public Session timestamp is RFC 3339 representable"),
            "effective_timeouts": effective_timeouts,
            "yolo": yolo_state_json(yolo_policy),
            "turns": session.turns(),
        }))
        .map_err(|error| failure_for_admitted_session(error, &session_id))?;
    } else {
        if yolo_policy.active {
            println!("YOLO mode: active ({})", yolo_policy.source);
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
        host: &str,
        operation: &str,
        transport: &satelle_core::TransportKind,
    ) -> Result<(), SatelleError> {
        if self.mode == EffectiveEventMode::None {
            return Ok(());
        }
        let body = SatelleEventBody::new(
            EventType::Preflight,
            EventSource::Cli,
            OffsetDateTime::now_utc(),
            host,
            None,
            "resolved configuration and selected Host transport",
            json!({
                "operation": operation,
                "transport": transport,
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
        let (session_id, turn_id) = durable_handles.unzip();
        let body = SatelleEventBody::new(
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
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
        self.emit_body(body)
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
    println!("Mutated: {}", report.mutated);
    println!(
        "Native Computer Use readiness: {}",
        report.native_computer_use_readiness
    );
    for action in &report.planned_actions {
        println!("Plan: {action}");
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
    }
}

fn failure_for_admitted_session(error: SatelleError, session_id: &SessionId) -> CliFailure {
    CliFailure {
        error,
        history_session_id: Some(Box::new(session_id.clone())),
    }
}

#[cfg(test)]
mod admitted_session_failure_tests {
    use super::*;

    #[test]
    fn retains_the_durable_session_id() {
        let session_id = SessionId::new();
        let failure = failure_for_admitted_session(
            SatelleError::input_required("synthetic output failure"),
            &session_id,
        );

        assert_eq!(failure.history_session_id.as_deref(), Some(&session_id));
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
