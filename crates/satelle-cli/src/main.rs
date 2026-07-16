mod completions;
#[path = "error-output.rs"]
mod error_output;
mod logs;
mod mcp;
mod output;
mod read;
mod transport;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use completions::{CompletionsCommand, run_completions};
use error_output::{ErrorFormat, parser_error, print_error};
use logs::{LogsCommand, show_logs};
use output::{OutputArgs, OutputFormat, SessionResultSchemaVersion, StatusReport};
use satelle_core::session::{
    PublicSession, PublicTurn, TurnAdmissionPhase, TurnExecutionMode, TurnState,
};
use satelle_core::{
    BEACON_CORAL, CLI_NAME, DaemonPathOverrides, DesktopSessionPreference, DoctorEventRecord,
    DoctorReport, ERROR_RED, ErrorCode, EventSource, EventType, HostConfig, HostSessionsReport,
    LOCAL_DEMO_HOST, PRODUCT_NAME, ProfileField, RELAY_ROSE, ResolvedConfig, SUCCESS_GREEN,
    SatelleError, SatelleEvent, SatelleEventBody, SessionId, SetupReport, SetupRequiredInput,
    load_config, resolve_path_set, utc_now,
};
use satelle_host::HostService;
use satelle_transport::{DaemonServer, DaemonServerConfig, DaemonServerError, TurnRequest};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use transport::{AttachedTurnOutcome, transport_for};

const CONFIG_CHECK_SCHEMA_VERSION: &str = "satelle.config.check.v1";
const CONFIG_EXPLAIN_SCHEMA_VERSION: &str = "satelle.config.explain.v1";
const PATHS_SCHEMA_VERSION: &str = "satelle.paths.v1";
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

#[derive(Clone, Copy)]
struct ConfigContext<'a> {
    flag_profile: Option<&'a str>,
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

impl ConfigContext<'_> {
    fn load(self) -> Result<ResolvedConfig, CliFailure> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        load_config(&cwd, self.flag_profile).map_err(failure)
    }

    fn resolve_host(self, flag_host: Option<&str>) -> Result<SelectedHost, CliFailure> {
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
struct HostStartCommand {
    #[arg(long, default_value = "127.0.0.1:3001")]
    bind: String,
    #[arg(long)]
    foreground: bool,
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

    match try_main(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            print_error(&failure.error, error_format);
            ExitCode::from(failure.error.exit_code() as u8)
        }
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

fn try_main(cli: Cli) -> Result<(), CliFailure> {
    let Cli {
        no_color,
        profile,
        error_format: _,
        command,
    } = cli;
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
    let config = ConfigContext {
        flag_profile: profile.as_deref(),
    };

    match command {
        Command::Completions(command) => run_completions(command).map_err(failure),
        Command::Setup(command) => run_setup(command, human_style, config, output),
        Command::Repair(command) => run_repair(command),
        Command::Doctor(command) => run_doctor(command, config, output),
        Command::Config { command } => run_config(command, config, output),
        Command::Paths(command) => show_paths(command, output),
        Command::Host { command } => run_host(command, config, output),
        Command::SelfCtl { command } => run_self(command),
        Command::Run(command) => run_prompt(command, config, output),
        Command::Steer(command) => steer_prompt(command, config, output),
        Command::Status(command) => show_status(command, config, output),
        Command::Stop(command) => stop_session(command, config, output),
        Command::Logs(command) => show_logs(command, config, output),
        Command::Mcp {
            command: McpCommand::Serve,
        } => mcp::serve(profile.as_deref()),
        Command::Support { command } => run_support(command),
    }
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
    if command.no_input && !command.dry_run && !command.yes && !json {
        return Err(failure(SatelleError::input_required(
            "setup needs --yes when --no-input is used for mutations",
        )));
    }

    if !command.dry_run && !command.no_input && !json {
        let _color_enabled = style.color_enabled();
        cliclack::intro(format!("{PRODUCT_NAME} setup")).map_err(|source| {
            failure(SatelleError {
                code: ErrorCode::InvalidUsage,
                message: "could not start interactive setup prompt".to_string(),
                recovery_command: Some("rerun with --no-input --yes or --dry-run".to_string()),
                source_detail: Some(source.to_string()),
                details: std::collections::BTreeMap::new(),
            })
        })?;
    }

    let host = config.resolve_host(command.host.as_deref())?;
    let transport = transport_for(&host)?;
    let daemon_path_overrides = daemon_path_overrides(&command, &host.config).map_err(failure)?;
    let setup_components = setup_components(&command.component).map_err(failure)?;
    let explicit_provider_auth = command
        .component
        .iter()
        .any(|component| component == &SetupComponent::ProviderAuth);
    let setup_mode = setup_mode(&command).map_err(failure)?;

    let mut report = transport
        .setup(
            command.dry_run,
            setup_mode,
            setup_components,
            daemon_path_overrides,
        )
        .map_err(failure)?;
    add_setup_required_inputs(&mut report, &host.config, explicit_provider_auth);

    if !command.dry_run && !command.no_input && !json {
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

fn setup_mode(command: &SetupCommand) -> Result<String, SatelleError> {
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

    Ok("persistent".to_string())
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
    if let Some(timeout) = &command.timeout
        && let Err(error) = parse_duration_ms(timeout)
    {
        return fail_doctor(
            failure(error),
            command.events,
            target_hint,
            command.scope.as_deref(),
        );
    }

    let host = match config.resolve_host(command.host.as_deref()) {
        Ok(resolved) => resolved,
        Err(failure) => {
            return fail_doctor(
                failure,
                command.events,
                target_hint,
                command.scope.as_deref(),
            );
        }
    };
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
    let report = match transport.doctor(command.scope.as_deref(), command.refresh) {
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

    let _serial_probes = command.serial_probes;
    let _no_input = command.no_input;
    let readiness_error = if report.summary.ready {
        None
    } else {
        Some(SatelleError::doctor_readiness_blockers_found(
            &report.recovery_commands,
        ))
    };

    if command.events {
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
        print_doctor_failed_event(target, scope, &failure.error)
            .map_err(|error| CliFailure { error })?;
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

fn parse_duration_ms(value: &str) -> Result<u64, SatelleError> {
    if let Some(ms) = value.strip_suffix("ms") {
        return ms
            .parse::<u64>()
            .map_err(|_| SatelleError::invalid_usage("duration must use a positive number"));
    }

    if let Some(seconds) = value.strip_suffix('s') {
        return seconds
            .parse::<u64>()
            .map(|seconds| seconds.saturating_mul(1_000))
            .map_err(|_| SatelleError::invalid_usage("duration must use a positive number"));
    }

    if let Some(minutes) = value.strip_suffix('m') {
        return minutes
            .parse::<u64>()
            .map(|minutes| minutes.saturating_mul(60_000))
            .map_err(|_| SatelleError::invalid_usage("duration must use a positive number"));
    }

    Err(SatelleError::invalid_usage(
        "duration values require an explicit unit such as 500ms, 30s, or 2m",
    ))
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
        HostCommand::Start(command) => start_host_daemon(command, format),
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

fn start_host_daemon(command: HostStartCommand, format: OutputFormat) -> Result<(), CliFailure> {
    if !command.foreground {
        return Err(failure(SatelleError::invalid_usage(
            "host start currently requires --foreground; persistent service installation is owned by satelle setup --persistent",
        )));
    }

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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| daemon_process_failure("runtime-create-failed", error.to_string()))?;
    runtime.block_on(async move {
        let server = DaemonServer::bind(
            HostService::production(),
            DaemonServerConfig::loopback(bind_addr),
        )
        .await
        .map_err(daemon_server_failure)?;

        if format.is_json() {
            print_json(&json!({
                "schema_version": "satelle.host.start.v1",
                "mode": "foreground",
                "bind": server.local_addr(),
                "running": true,
            }))
            .map_err(failure)?;
        } else {
            println!("Host Daemon listening on {}", server.local_addr());
        }

        tokio::signal::ctrl_c()
            .await
            .map_err(|error| daemon_process_failure("signal-wait-failed", error.to_string()))?;
        server.shutdown().await.map_err(daemon_server_failure)
    })
}

fn daemon_server_failure(error: DaemonServerError) -> CliFailure {
    if let Some(host_error) = error.host_error() {
        return failure(host_error.clone());
    }

    match error {
        DaemonServerError::NonLoopbackPlaintextBind
        | DaemonServerError::InvalidConnectionLimit
        | DaemonServerError::InvalidShutdownGrace => {
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
) -> Result<(), CliFailure> {
    let json = format.is_json();
    validate_event_mode(command.detach, command.events)?;
    let effective_mode = effective_event_mode(command.events, command.detach, command.quiet, json);
    let mut event_output = TurnEventOutput::new(effective_mode, command.verbose);
    let _provider_computer_use_options = (
        command.experimental_provider_computer_use,
        command.refresh_provider_smoke_test,
    );
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
        &config,
        &host.alias,
        &host.config,
        command.yolo,
        command.no_yolo,
    );
    let request = TurnRequest::new(prompt).with_execution_mode(yolo_policy.execution_mode());
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
    let outcome = match transport.run(&request, &mut |event| event_output.emit(event)) {
        Ok(outcome) => outcome,
        Err(attached_failure) => {
            event_output
                .emit_command_failed(
                    &host.alias,
                    attached_failure.error(),
                    attached_failure.phase(),
                    attached_failure.durable_handles(),
                )
                .map_err(failure)?;
            return Err(failure(attached_failure.into_error()));
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
) -> Result<(), CliFailure> {
    let json = format.is_json();
    validate_event_mode(command.detach, command.events)?;
    let effective_mode = effective_event_mode(command.events, command.detach, command.quiet, json);
    let mut event_output = TurnEventOutput::new(effective_mode, command.verbose);
    let _provider_computer_use_options = (
        command.experimental_provider_computer_use,
        command.refresh_provider_smoke_test,
    );
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
        &config,
        &host.alias,
        &host.config,
        command.yolo,
        command.no_yolo,
    );
    let request = TurnRequest::new(prompt).with_execution_mode(yolo_policy.execution_mode());
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
    let outcome =
        match transport.steer(&session_id, &request, &mut |event| event_output.emit(event)) {
            Ok(outcome) => outcome,
            Err(attached_failure) => {
                event_output
                    .emit_command_failed(
                        &host.alias,
                        attached_failure.error(),
                        attached_failure.phase(),
                        attached_failure.durable_handles(),
                    )
                    .map_err(failure)?;
                return Err(failure(attached_failure.into_error()));
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
) -> Result<(), CliFailure> {
    let AttachedTurnOutcome { session, turn_id } = outcome;
    let target_turn = session
        .turns()
        .iter()
        .find(|turn| turn.turn_id() == &turn_id)
        .expect("an attached Turn outcome retains its admitted target Turn");
    if options.effective_mode == EffectiveEventMode::Json {
        return Ok(());
    }

    if options.json {
        print_json(&json!({
            "schema_version": options.schema_version,
            "session_id": session.session_id(),
            "status": target_turn.state(),
            "effective_timeouts": options.effective_timeouts,
            "yolo": yolo_state_json(options.yolo_policy),
            "latest_turn": target_turn,
        }))
        .map_err(failure)
    } else {
        if options.yolo_policy.active && !options.quiet {
            println!("YOLO mode: active ({})", options.yolo_policy.source);
        }
        print_session_human(&session, target_turn, options.host);
        Ok(())
    }
}

fn print_detached_session(
    session: PublicSession,
    host: &str,
    effective_timeouts: serde_json::Value,
    yolo_policy: &YoloPolicy,
    schema_version: SessionResultSchemaVersion,
    json: bool,
) -> Result<(), CliFailure> {
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
        .map_err(failure)
    } else {
        if yolo_policy.active {
            println!("YOLO mode: active ({})", yolo_policy.source);
        }
        println!("Session: {}", session.session_id());
        println!("Status: {}", status_label(latest_turn.state()));
        Ok(())
    }
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

    fn emit(&mut self, event: SatelleEvent) -> Result<(), SatelleError> {
        self.emit_body(event.into_body())
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
    CliFailure { error }
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
