use clap::{Args, Parser, Subcommand, ValueEnum};
use satelle_core::{
    BEACON_CORAL, CLI_NAME, DaemonPathOverrides, DoctorEventRecord, DoctorReport, ERROR_RED,
    ErrorCode, HostConfig, HostSessionsReport, LOCAL_DEMO_HOST, LogEntry, PRODUCT_NAME, RELAY_ROSE,
    SUCCESS_GREEN, SatelleError, SessionId, SessionRecord, SetupReport, SetupRequiredInput,
    StopResult, TurnStatus, load_config, resolve_path_set, utc_now,
};
use satelle_host::{HostService, HostStatus, TurnOutcome};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

#[cfg(feature = "test-support")]
const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";
const CONFIG_CHECK_SCHEMA_VERSION: &str = "satelle.config.check.v1";
const CONFIG_EXPLAIN_SCHEMA_VERSION: &str = "satelle.config.explain.v1";
const ERROR_SCHEMA_VERSION: &str = "satelle.error.v1";
const PATHS_SCHEMA_VERSION: &str = "satelle.paths.v1";
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
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
    Support {
        #[command(subcommand)]
        command: SupportCommand,
    },
}

#[derive(Args, Debug)]
#[command(
    after_long_help = "Agent-safe noninteractive provider auth flow:\n  1. Configure host-resolved Secret Source descriptors in user-level host config.\n  2. Run satelle setup --no-input --json to get a stable plan.\n  3. Treat missing raw provider secret material as required human input, not as an agent-handled value."
)]
struct SetupCommand {
    #[arg(long, default_value = LOCAL_DEMO_HOST)]
    host: String,
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
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ConfigExplainCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    profile: Option<String>,
    #[arg(long)]
    show_secret_references: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct PathsCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct HostStatusCommand {
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct HostLifecycleCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct HostSessionsCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    no_bootstrap: bool,
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    json: bool,
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
    json: bool,
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
    #[arg(long)]
    json: bool,
    #[arg(value_name = "PROMPT_OR_DASH")]
    prompt: Option<String>,
}

#[derive(Args, Debug)]
struct SteerCommand {
    session_id: String,
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
    #[arg(long)]
    json: bool,
    #[arg(value_name = "PROMPT_OR_DASH")]
    prompt: Option<String>,
}

#[derive(Args, Debug)]
struct StatusCommand {
    session_id: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct StopCommand {
    session_id: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct LogsCommand {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long)]
    tail: Option<usize>,
    #[arg(long)]
    since: Option<String>,
    #[arg(long)]
    source: Vec<String>,
    #[arg(long)]
    level: Option<String>,
    #[arg(long)]
    json: bool,
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
    #[arg(long)]
    json: bool,
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
    json: bool,
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

trait TransportClient {
    fn setup(
        &self,
        host: &str,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError>;

    fn doctor(
        &self,
        host: &str,
        scope: Option<&str>,
        refresh: bool,
    ) -> Result<DoctorReport, SatelleError>;

    fn host_status(&self) -> Result<HostStatus, SatelleError>;

    fn host_sessions(
        &self,
        host: &str,
        no_bootstrap: bool,
    ) -> Result<HostSessionsReport, SatelleError>;

    fn run(&self, host: &str, prompt: &str) -> Result<TurnOutcome, SatelleError>;

    fn run_detached(&self, host: &str, prompt: &str) -> Result<SessionRecord, SatelleError>;

    fn steer(&self, session_id: &SessionId, prompt: &str) -> Result<TurnOutcome, SatelleError>;

    fn steer_detached(
        &self,
        session_id: &SessionId,
        prompt: &str,
    ) -> Result<SessionRecord, SatelleError>;

    fn status(&self, session_id: &SessionId) -> Result<SessionRecord, SatelleError>;

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError>;

    fn logs(&self, host: &str) -> Result<Vec<LogEntry>, SatelleError>;
}

struct LocalTransport {
    service: HostService,
}

impl LocalTransport {
    fn new(service: HostService) -> Self {
        Self { service }
    }
}

impl TransportClient for LocalTransport {
    fn setup(
        &self,
        host: &str,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        self.service.setup(
            host,
            dry_run,
            setup_mode,
            setup_components,
            daemon_path_overrides,
        )
    }

    fn doctor(
        &self,
        host: &str,
        scope: Option<&str>,
        refresh: bool,
    ) -> Result<DoctorReport, SatelleError> {
        self.service.doctor(host, scope, refresh)
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        self.service.host_status()
    }

    fn host_sessions(
        &self,
        host: &str,
        no_bootstrap: bool,
    ) -> Result<HostSessionsReport, SatelleError> {
        self.service.host_sessions(host, no_bootstrap)
    }

    fn run(&self, host: &str, prompt: &str) -> Result<TurnOutcome, SatelleError> {
        self.service.run(host, prompt)
    }

    fn run_detached(&self, host: &str, prompt: &str) -> Result<SessionRecord, SatelleError> {
        self.service.run_detached(host, prompt)
    }

    fn steer(&self, session_id: &SessionId, prompt: &str) -> Result<TurnOutcome, SatelleError> {
        self.service.steer(session_id, prompt)
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        prompt: &str,
    ) -> Result<SessionRecord, SatelleError> {
        self.service.steer_detached(session_id, prompt)
    }

    fn status(&self, session_id: &SessionId) -> Result<SessionRecord, SatelleError> {
        self.service.status(session_id)
    }

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.service.stop(session_id)
    }

    fn logs(&self, host: &str) -> Result<Vec<LogEntry>, SatelleError> {
        self.service.logs(host)
    }
}

fn main() -> ExitCode {
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            print_error(&failure.error, failure.json);
            ExitCode::from(failure.error.exit_code() as u8)
        }
    }
}

fn try_main() -> Result<(), CliFailure> {
    let cli = Cli::parse();
    let human_style = HumanStyle::detect(cli.no_color);

    match cli.command {
        Command::Setup(command) => {
            let transport = local_transport(command.json)?;
            run_setup(command, &transport, human_style)
        }
        Command::Repair(command) => run_repair(command),
        Command::Doctor(command) => {
            let json = command.json;
            let transport = local_transport(json)?;
            run_doctor(command, &transport)
        }
        Command::Config { command } => run_config(command),
        Command::Paths(command) => show_paths(command),
        Command::Host { command } => {
            let json = host_command_json(&command);
            let transport = local_transport(json)?;
            run_host(command, &transport)
        }
        Command::SelfCtl { command } => run_self(command),
        Command::Run(command) => {
            let json = command.json;
            let transport = local_transport(json)?;
            run_prompt(command, &transport)
        }
        Command::Steer(command) => {
            let json = command.json;
            let transport = local_transport(json)?;
            steer_prompt(command, &transport)
        }
        Command::Status(command) => {
            let json = command.json;
            let transport = local_transport(json)?;
            show_status(command, &transport)
        }
        Command::Stop(command) => {
            let json = command.json;
            let transport = local_transport(json)?;
            stop_session(command, &transport)
        }
        Command::Logs(command) => {
            let json = command.json;
            let transport = local_transport(json)?;
            show_logs(command, &transport)
        }
        Command::Support { command } => run_support(command),
    }
}

fn local_transport(_json: bool) -> Result<LocalTransport, CliFailure> {
    #[cfg(feature = "test-support")]
    match std::env::var(TEST_SUPPORT_ADAPTER_ENV) {
        Ok(value) if value == "fake" => {
            return HostService::local_demo_for_tests()
                .map(LocalTransport::new)
                .map_err(|error| failure(error, _json));
        }
        Ok(_) => {
            return Err(failure(
                SatelleError::invalid_usage(
                    "SATELLE_TEST_SUPPORT_ADAPTER must be exactly 'fake' or unset",
                ),
                _json,
            ));
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(failure(
                SatelleError::invalid_usage(
                    "SATELLE_TEST_SUPPORT_ADAPTER must contain valid UTF-8",
                ),
                _json,
            ));
        }
        Err(std::env::VarError::NotPresent) => {}
    }

    Ok(LocalTransport::new(HostService::production()))
}

fn host_command_json(command: &HostCommand) -> bool {
    match command {
        HostCommand::Start(command) => command.json,
        HostCommand::Status(command) => command.json,
        HostCommand::Stop(command) => command.json,
        HostCommand::Restart(command) => command.json,
        HostCommand::Update(command) => command.json,
        HostCommand::Sessions(command) => command.json,
        HostCommand::Storage { command } => match command {
            HostStorageCommand::Migrate(command) => command.json,
        },
    }
}

fn run_setup(
    command: SetupCommand,
    transport: &impl TransportClient,
    style: HumanStyle,
) -> Result<(), CliFailure> {
    if command.no_input && !command.dry_run && !command.yes && !command.json {
        return Err(failure(
            SatelleError::input_required("setup needs --yes when --no-input is used for mutations"),
            command.json,
        ));
    }

    if !command.dry_run && !command.no_input && !command.json {
        let _color_enabled = style.color_enabled();
        cliclack::intro(format!("{PRODUCT_NAME} setup")).map_err(|source| {
            failure(
                SatelleError {
                    code: ErrorCode::InvalidUsage,
                    message: "could not start interactive setup prompt".to_string(),
                    recovery_command: Some("rerun with --no-input --yes or --dry-run".to_string()),
                    source_detail: Some(source.to_string()),
                    details: std::collections::BTreeMap::new(),
                },
                command.json,
            )
        })?;
    }

    let (_, host_config) = resolve_host(Some(&command.host), command.json)?;
    let daemon_path_overrides = daemon_path_overrides(&command, &host_config)
        .map_err(|error| failure(error, command.json))?;
    let setup_components =
        setup_components(&command.component).map_err(|error| failure(error, command.json))?;
    let explicit_provider_auth = command
        .component
        .iter()
        .any(|component| component == &SetupComponent::ProviderAuth);
    let setup_mode = setup_mode(&command).map_err(|error| failure(error, command.json))?;

    let mut report = transport
        .setup(
            &command.host,
            command.dry_run,
            setup_mode,
            setup_components,
            daemon_path_overrides,
        )
        .map_err(|error| failure(error, command.json))?;
    add_setup_required_inputs(&mut report, &host_config, explicit_provider_auth);

    if !command.dry_run && !command.no_input && !command.json {
        cliclack::outro("Satelle setup produced a readiness plan").map_err(|source| {
            failure(
                SatelleError {
                    code: ErrorCode::InvalidUsage,
                    message: "could not finish interactive setup prompt".to_string(),
                    recovery_command: Some("rerun with --no-input --yes or --dry-run".to_string()),
                    source_detail: Some(source.to_string()),
                    details: std::collections::BTreeMap::new(),
                },
                command.json,
            )
        })?;
    }

    if command.json {
        print_json(&report).map_err(|error| failure(error, command.json))
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
        return Err(failure(
            SatelleError::input_required(
                "repair needs --yes when --no-input is used for mutations",
            ),
            command.json,
        ));
    }

    Err(failure(
        SatelleError::not_implemented(format!(
            "repair planning is not implemented yet for host {}",
            command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
        )),
        command.json,
    ))
}

fn run_doctor(command: DoctorCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    if command.events && command.json {
        return Err(failure(
            SatelleError::output_mode_conflict("doctor --events cannot be combined with --json"),
            command.json,
        ));
    }

    let target_hint = command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST);
    if let Err(failure) = validate_doctor_scope(command.scope.as_deref(), command.json) {
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
            failure(error, command.json),
            command.events,
            target_hint,
            command.scope.as_deref(),
        );
    }

    let (host, _) = match resolve_host(command.host.as_deref(), command.json) {
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
    let report = match transport.doctor(&host, command.scope.as_deref(), command.refresh) {
        Ok(report) => report,
        Err(error) => {
            return fail_doctor(
                failure(error, command.json),
                command.events,
                &host,
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
        print_doctor_events(&report, readiness_error.as_ref())
            .map_err(|error| failure(error, false))?;
        if let Some(error) = readiness_error {
            return Err(failure(error, false));
        }
        Ok(())
    } else if command.json {
        print_json(&report).map_err(|error| failure(error, command.json))?;
        if let Some(error) = readiness_error {
            return Err(failure(error, true));
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
            return Err(failure(error, false));
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
            .map_err(|error| CliFailure { error, json: false })?;
    }

    Err(failure)
}

fn validate_doctor_scope(scope: Option<&str>, json: bool) -> Result<(), CliFailure> {
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

    Err(failure(
        SatelleError::invalid_usage(format!(
            "unsupported doctor scope '{scope}'; expected transport, codex, computer-use, provider, config, or all"
        )),
        json,
    ))
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

fn run_config(command: ConfigCommand) -> Result<(), CliFailure> {
    match command {
        ConfigCommand::Check(command) => config_check(command),
        ConfigCommand::Explain(command) => config_explain(command),
    }
}

fn config_check(command: ConfigCheckCommand) -> Result<(), CliFailure> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = load_config(&cwd).map_err(|error| failure(error, command.json))?;
    let selected_profile = selected_profile(command.profile);
    let selected_host = config
        .resolve_host(command.host.as_deref())
        .map(|(alias, _)| alias)
        .map_err(|error| failure(error, command.json))?;
    let output = json!({
        "schema_version": CONFIG_CHECK_SCHEMA_VERSION,
        "status": "ok",
        "mode": if command.all { "all" } else { "selected" },
        "selected_host": selected_host,
        "selected_profile": selected_profile,
        "checked_files": [
            config.user_config_path,
            config.project_config_path,
        ],
        "checks": ["toml_parse", "host_resolution"],
        "checked_contexts": [{
            "host": selected_host,
            "profile": selected_profile,
            "source": "effective",
            "status": "ok",
            "checks": ["toml_parse", "host_resolution"],
            "errors": [],
            "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
        }],
        "errors": [],
        "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
        "recovery_commands": [],
    });

    if command.json {
        print_json(&output).map_err(|error| failure(error, command.json))
    } else {
        println!("Config: ok");
        println!(
            "Mode: {}",
            if command.all {
                "all-contexts"
            } else {
                "selected-context"
            }
        );
        println!("Host: {selected_host}");
        println!("User config: {}", config.user_config_path.display());
        println!("Project config: {}", config.project_config_path.display());
        println!("Not checked: remote_host, provider_auth, native_computer_use");
        Ok(())
    }
}

fn config_explain(command: ConfigExplainCommand) -> Result<(), CliFailure> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = load_config(&cwd).map_err(|error| failure(error, command.json))?;
    let selected_profile = selected_profile(command.profile);
    let (selected_host, selected_host_config) = config
        .resolve_host(command.host.as_deref())
        .map_err(|error| failure(error, command.json))?;
    let environment_sources = json!({
        "host": env_source("SATELLE_HOST"),
        "profile": env_source("SATELLE_PROFILE"),
        "paths": {
            "home": env_source("SATELLE_HOME"),
            "config_file": env_source("SATELLE_CONFIG_FILE"),
            "state_dir": env_source("SATELLE_STATE_DIR"),
            "cache_dir": env_source("SATELLE_CACHE_DIR"),
            "log_dir": env_source("SATELLE_LOG_DIR"),
        },
    });
    let output = json!({
        "schema_version": CONFIG_EXPLAIN_SCHEMA_VERSION,
        "status": "ok",
        "selected_host": selected_host,
        "selected_profile": selected_profile,
        "checked_files": [
            config.user_config_path,
            config.project_config_path,
        ],
        "sources": {
            "defaults": true,
            "user_config": config.user_config_path,
            "project_config": config.project_config_path,
            "environment": environment_sources,
            "flags": ["--host", "--profile"],
        },
        "effective": redacted_config_json(&config.config, command.show_secret_references),
        "values": {
            "default_host": config.config.default_host,
            "host_count": config.config.hosts.len(),
            "effective_timeouts": effective_timeouts_json(&selected_host_config),
            "daemon_path_overrides": daemon_path_overrides_json(&selected_host_config),
            "model_provider": model_provider_config_json(&config),
            "experimental_provider_computer_use": experimental_provider_computer_use_json(
                &config,
                &selected_host,
                &selected_host_config,
            ),
            "yolo": yolo_config_json(&config, &selected_host, &selected_host_config),
            "show_secret_references": command.show_secret_references,
        },
        "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
    });

    if command.json {
        print_json(&output).map_err(|error| failure(error, command.json))
    } else {
        println!("Selected host: {selected_host}");
        println!("User config: {}", config.user_config_path.display());
        println!("Project config: {}", config.project_config_path.display());
        println!(
            "Default host: {}",
            config.config.default_host.unwrap_or_default()
        );
        println!("Host aliases: {}", config.config.hosts.len());
        Ok(())
    }
}

fn selected_profile(flag_profile: Option<String>) -> Option<String> {
    flag_profile.or_else(|| {
        std::env::var("SATELLE_PROFILE")
            .ok()
            .filter(|profile| !profile.is_empty())
    })
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
        let Some(provider_auth) = host_object
            .get_mut("provider_auth")
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };

        for descriptor in provider_auth.values_mut() {
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
    }

    value
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

fn model_provider_config_json(config: &satelle_core::ResolvedConfig) -> serde_json::Value {
    let model_alias_source = root_config_key_source(
        "model_alias",
        &config.user_config_path,
        &config.project_config_path,
    );
    let provider_alias_source = root_config_key_source(
        "provider_alias",
        &config.user_config_path,
        &config.project_config_path,
    );

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

    let _ = selected_host;
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
        "selected_profile": serde_json::Value::Null,
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

fn show_paths(command: PathsCommand) -> Result<(), CliFailure> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let selected_host = command.host.unwrap_or_else(|| LOCAL_DEMO_HOST.to_string());
    let paths = resolve_path_set(&cwd).map_err(|error| failure(error, command.json))?;
    let output = json!({
        "schema_version": PATHS_SCHEMA_VERSION,
        "host": selected_host,
        "config_file": paths.config_file,
        "cache_root": paths.cache_root,
        "state_root": paths.state_root,
        "sqlite_store": paths.sqlite_store,
        "operator_log_root": paths.operator_log_root,
        "recording_root": paths.recording_root,
        "project_config_file": paths.project_config_file,
        "install_receipt": paths.install_receipt,
        "sources": paths.sources,
    });

    if command.json {
        print_json(&output).map_err(|error| failure(error, command.json))
    } else {
        println!("Host: {selected_host}");
        println!("Config: {}", paths.config_file.display());
        println!("Cache: {}", paths.cache_root.display());
        println!("State: {}", paths.state_root.display());
        println!("SQLite: {}", paths.sqlite_store.display());
        println!("Operator logs: {}", paths.operator_log_root.display());
        println!("Recordings: {}", paths.recording_root.display());
        println!("Project config: {}", paths.project_config_file.display());
        println!("Install receipt: {}", paths.install_receipt.display());
        Ok(())
    }
}

fn run_host(command: HostCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    match command {
        HostCommand::Start(command) => {
            let error = SatelleError::not_implemented(format!(
                "persistent Host Daemon start on {} is not implemented yet; run setup and doctor to inspect readiness",
                command.bind
            ));
            Err(failure(error, command.json))
        }
        HostCommand::Status(command) => {
            let status = transport
                .host_status()
                .map_err(|error| failure(error, command.json))?;
            if command.json {
                print_json(&status).map_err(|error| failure(error, command.json))
            } else {
                println!("Running: {}", status.running);
                println!("Mode: {}", status.mode);
                println!("Sessions: {}", status.sessions);
                Ok(())
            }
        }
        HostCommand::Stop(command) => Err(failure(
            SatelleError::not_implemented(format!(
                "host stop is not implemented yet for host {}",
                command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
            )),
            command.json,
        )),
        HostCommand::Restart(command) => Err(failure(
            SatelleError::not_implemented(format!(
                "host restart is not implemented yet for host {}",
                command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
            )),
            command.json,
        )),
        HostCommand::Update(command) => run_host_update(command),
        HostCommand::Sessions(command) => show_host_sessions(command, transport),
        HostCommand::Storage { command } => run_host_storage(command),
    }
}

fn show_host_sessions(
    command: HostSessionsCommand,
    transport: &impl TransportClient,
) -> Result<(), CliFailure> {
    let (host, _) = resolve_host(command.host.as_deref(), command.json)?;
    let report = transport
        .host_sessions(&host, command.no_bootstrap)
        .map_err(|error| failure(error, command.json))?;

    if command.json {
        print_json(&report).map_err(|error| failure(error, command.json))
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

fn run_host_update(command: HostUpdateCommand) -> Result<(), CliFailure> {
    validate_host_update_components(&command.component)
        .map_err(|error| failure(error, command.json))?;
    Err(failure(
        SatelleError::not_implemented(concat!(
            "Host update was not run because live Host planning and application are not ",
            "implemented. No Host state or Satelle sessions were changed."
        )),
        command.json,
    ))
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
        HostStorageCommand::Migrate(command) => Err(failure(
            SatelleError::not_implemented(format!(
                "host storage migration is not implemented yet for host {}",
                command.host.as_deref().unwrap_or(LOCAL_DEMO_HOST)
            )),
            command.json,
        )),
    }
}

fn run_self(command: SelfSubcommand) -> Result<(), CliFailure> {
    match command {
        SelfSubcommand::Update(command) => {
            if command.concurrency == 0 || command.concurrency > 16 {
                return Err(failure(
                    SatelleError::concurrency_limit_exceeded(command.concurrency),
                    command.json,
                ));
            }

            if !command.update_remotes {
                if command.concurrency != 4 {
                    return Err(failure(
                        SatelleError::concurrency_without_remote_update(),
                        command.json,
                    ));
                }

                if command.all_remotes || !command.host.is_empty() {
                    return Err(failure(
                        SatelleError::invalid_usage(
                            "--host and --all-remotes require --update-remotes",
                        ),
                        command.json,
                    ));
                }
            }

            Err(failure(
                SatelleError::not_implemented(format!(
                    "self update is not implemented yet{}",
                    command
                        .version
                        .as_ref()
                        .map(|version| format!(" for version {version}"))
                        .unwrap_or_default()
                )),
                command.json,
            ))
        }
    }
}

fn run_support(command: SupportCommand) -> Result<(), CliFailure> {
    match command {
        SupportCommand::Bundle(command) => Err(failure(
            SatelleError::not_implemented(format!(
                "support bundle export is not implemented yet{}",
                command
                    .output
                    .as_ref()
                    .map(|path| format!(" for output {}", path.display()))
                    .unwrap_or_default()
            )),
            command.json,
        )),
    }
}

fn run_prompt(command: RunCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    validate_event_mode(command.detach, command.events, command.json)?;
    let _provider_computer_use_options = (
        command.experimental_provider_computer_use,
        command.refresh_provider_smoke_test,
    );
    let prompt = read_prompt(command.prompt, command.prompt_file, command.json)?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = load_config(&cwd).map_err(|error| failure(error, command.json))?;
    let (host, host_config) = config
        .resolve_host(command.host.as_deref())
        .map_err(|error| failure(error, command.json))?;
    let effective_timeouts = effective_timeouts_json(&host_config);
    let yolo_policy =
        resolve_yolo_policy(&config, &host, &host_config, command.yolo, command.no_yolo);
    if command.detach {
        let session = transport
            .run_detached(&host, &prompt)
            .map_err(|error| failure(error, command.json))?;
        return print_detached_session(session, effective_timeouts, &yolo_policy, command.json);
    }

    let outcome = transport
        .run(&host, &prompt)
        .map_err(|error| failure(error, command.json))?;
    print_turn_outcome(
        outcome,
        TurnOutputOptions {
            mode: command.events,
            detach: command.detach,
            quiet: command.quiet,
            verbose: command.verbose,
            effective_timeouts,
            yolo_policy: &yolo_policy,
            json: command.json,
        },
    )
}

fn steer_prompt(command: SteerCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    validate_event_mode(command.detach, command.events, command.json)?;
    let _provider_computer_use_options = (
        command.experimental_provider_computer_use,
        command.refresh_provider_smoke_test,
    );
    let prompt = read_prompt(command.prompt, command.prompt_file, command.json)?;
    let session_id = SessionId::from_str(&command.session_id)
        .map_err(|error| failure(error.into(), command.json))?;
    let session = transport
        .status(&session_id)
        .map_err(|error| failure(error, command.json))?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = load_config(&cwd).map_err(|error| failure(error, command.json))?;
    let (_, host_config) = config
        .resolve_host(Some(&session.host))
        .map_err(|error| failure(error, command.json))?;
    let effective_timeouts = effective_timeouts_json(&host_config);
    let yolo_policy = resolve_yolo_policy(
        &config,
        &session.host,
        &host_config,
        command.yolo,
        command.no_yolo,
    );
    if command.detach {
        let session = transport
            .steer_detached(&session_id, &prompt)
            .map_err(|error| failure(error, command.json))?;
        return print_detached_session(session, effective_timeouts, &yolo_policy, command.json);
    }

    let outcome = transport
        .steer(&session_id, &prompt)
        .map_err(|error| failure(error, command.json))?;
    print_turn_outcome(
        outcome,
        TurnOutputOptions {
            mode: command.events,
            detach: command.detach,
            quiet: command.quiet,
            verbose: command.verbose,
            effective_timeouts,
            yolo_policy: &yolo_policy,
            json: command.json,
        },
    )
}

fn show_status(command: StatusCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    let session_id = SessionId::from_str(&command.session_id)
        .map_err(|error| failure(error.into(), command.json))?;
    let session = transport
        .status(&session_id)
        .map_err(|error| failure(error, command.json))?;

    if command.json {
        print_json(&session).map_err(|error| failure(error, command.json))
    } else {
        print_session_human(&session);
        Ok(())
    }
}

fn stop_session(command: StopCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    let session_id = SessionId::from_str(&command.session_id)
        .map_err(|error| failure(error.into(), command.json))?;
    let result = transport
        .stop(&session_id)
        .map_err(|error| failure(error, command.json))?;

    if command.json {
        print_json(&result).map_err(|error| failure(error, command.json))
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

fn show_logs(command: LogsCommand, transport: &impl TransportClient) -> Result<(), CliFailure> {
    let started_at = utc_now();
    let session_id = command
        .session
        .as_deref()
        .map(SessionId::from_str)
        .transpose()
        .map_err(|error| failure(error.into(), command.json))?;
    let (host, _) = if let Some(session_id) = &session_id {
        let session = transport
            .status(session_id)
            .map_err(|error| failure(error, command.json))?;
        (
            session.host,
            satelle_core::HostConfig {
                transport: satelle_core::TransportKind::Local,
                adapter: satelle_core::AdapterKind::Codex,
                address: None,
                network: None,
                timeouts: None,
                desktop_user: None,
                desktop_session_preference: None,
                desktop_session_native_selector: None,
                daemon_home: None,
                daemon_config_file: None,
                daemon_state_dir: None,
                daemon_cache_dir: None,
                daemon_log_dir: None,
                experimental_provider_computer_use: None,
                yolo: None,
                provider_auth: BTreeMap::new(),
            },
        )
    } else {
        resolve_host(command.host.as_deref(), command.json)?
    };

    let tail = match command.tail {
        Some(1..=10_000) => command.tail,
        Some(value) => {
            return Err(failure(
                SatelleError::log_tail_limit_exceeded(value),
                command.json,
            ));
        }
        None => {
            if command.since.is_none() {
                Some(200)
            } else {
                None
            }
        }
    };
    let minimum_level = command.level.as_deref().unwrap_or("info");
    let minimum_level_rank = log_level_rank(minimum_level).ok_or_else(|| {
        failure(
            SatelleError::invalid_usage(
                "--level must be one of trace, debug, info, warn, or error",
            ),
            command.json,
        )
    })?;
    let since = command
        .since
        .as_deref()
        .map(parse_log_since)
        .transpose()
        .map_err(|error| failure(error, command.json))?;
    let allowed_sources = [
        "host_daemon",
        "codex_adapter",
        "transport",
        "readiness",
        "provider_smoke",
        "setup",
        "repair",
    ];
    for source in &command.source {
        if !allowed_sources.contains(&source.as_str()) {
            return Err(failure(
                SatelleError::invalid_usage(format!(
                    "--source must be one of {}",
                    allowed_sources.join(", ")
                )),
                command.json,
            ));
        }
    }

    let mut entries = transport
        .logs(&host)
        .map_err(|error| failure(error, command.json))?;
    entries.retain(|entry| {
        session_id
            .as_ref()
            .is_none_or(|session_id| entry.session_id.as_ref() == Some(session_id))
            && (command.source.is_empty()
                || command.source.iter().any(|source| source == &entry.source))
    });
    entries.retain(|entry| {
        log_level_rank(&entry.severity).unwrap_or(usize::MAX) >= minimum_level_rank
            && since.is_none_or(|since| log_timestamp_at_or_after(&entry.timestamp, since))
    });
    let matching_count = entries.len();
    let truncated = tail.is_some_and(|tail| matching_count > tail);
    if let Some(tail) = tail
        && entries.len() > tail
    {
        entries = entries.split_off(entries.len() - tail);
    }
    let next_since = entries.last().map(|entry| entry.timestamp.clone());

    if command.json {
        let output = json!({
            "schema_version": 1,
            "target": {
                "host": host,
                "session_id": session_id,
            },
            "filters": {
                "tail": tail,
                "since": command.since,
                "source": command.source,
                "level": minimum_level,
            },
            "entries": entries,
            "truncated": truncated,
            "started_at": started_at,
            "finished_at": utc_now(),
            "next_since": next_since,
        });
        print_json(&output).map_err(|error| failure(error, command.json))
    } else if entries.is_empty() {
        println!("No local demo logs for host {host}");
        Ok(())
    } else {
        for entry in entries {
            let session = entry
                .session_id
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{} [{}] host={} session={} {}",
                entry.timestamp, entry.severity, entry.host, session, entry.message
            );
        }
        Ok(())
    }
}

fn log_level_rank(level: &str) -> Option<usize> {
    match level {
        "trace" => Some(0),
        "debug" => Some(1),
        "info" => Some(2),
        "warn" => Some(3),
        "error" => Some(4),
        _ => None,
    }
}

fn parse_log_since(value: &str) -> Result<OffsetDateTime, SatelleError> {
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(timestamp);
    }

    let millis = parse_duration_ms(value)?;
    Ok(OffsetDateTime::now_utc() - Duration::milliseconds(millis.min(i64::MAX as u64) as i64))
}

fn log_timestamp_at_or_after(timestamp: &str, since: OffsetDateTime) -> bool {
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .map(|timestamp| timestamp >= since)
        .unwrap_or(false)
}

fn resolve_host(
    flag_host: Option<&str>,
    json: bool,
) -> Result<(String, satelle_core::HostConfig), CliFailure> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = load_config(&cwd).map_err(|error| failure(error, json))?;
    config
        .resolve_host(flag_host)
        .map_err(|error| failure(error, json))
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

fn validate_event_mode(detach: bool, mode: EventMode, json: bool) -> Result<(), CliFailure> {
    if detach && matches!(mode, EventMode::Human | EventMode::Json) {
        return Err(failure(SatelleError::events_with_detach(), json));
    }

    Ok(())
}

fn read_prompt(
    prompt: Option<String>,
    prompt_file: Option<PathBuf>,
    json: bool,
) -> Result<String, CliFailure> {
    if prompt.is_some() && prompt_file.is_some() {
        return Err(failure(
            SatelleError::invalid_usage("pass either PROMPT_OR_DASH or --prompt-file, not both"),
            json,
        ));
    }

    let value = if let Some(prompt_file) = prompt_file {
        fs::read_to_string(&prompt_file).map_err(|source| {
            failure(
                SatelleError {
                    code: ErrorCode::InputRequired,
                    message: format!("could not read prompt file {}", prompt_file.display()),
                    recovery_command: Some(
                        "pass a readable --prompt-file path or use a prompt argument".to_string(),
                    ),
                    source_detail: Some(source.to_string()),
                    details: std::collections::BTreeMap::new(),
                },
                json,
            )
        })?
    } else if prompt.as_deref() == Some("-") {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).map_err(|source| {
            failure(
                SatelleError {
                    code: ErrorCode::InputRequired,
                    message: "could not read prompt from stdin".to_string(),
                    recovery_command: Some(
                        "pipe prompt text or pass a prompt argument".to_string(),
                    ),
                    source_detail: Some(source.to_string()),
                    details: std::collections::BTreeMap::new(),
                },
                json,
            )
        })?;
        buffer
    } else if let Some(prompt) = prompt {
        prompt
    } else {
        return Err(failure(
            SatelleError::input_required("prompt text is required"),
            json,
        ));
    };

    if value.trim().is_empty() {
        return Err(failure(
            SatelleError::input_required("prompt text is required"),
            json,
        ));
    }

    Ok(value.trim().to_string())
}

struct TurnOutputOptions<'a> {
    mode: EventMode,
    detach: bool,
    quiet: bool,
    verbose: bool,
    effective_timeouts: serde_json::Value,
    yolo_policy: &'a YoloPolicy,
    json: bool,
}

fn print_turn_outcome(
    outcome: TurnOutcome,
    options: TurnOutputOptions<'_>,
) -> Result<(), CliFailure> {
    let effective_mode =
        effective_event_mode(options.mode, options.detach, options.quiet, options.json);
    match effective_mode {
        EffectiveEventMode::Json => {
            for event in &outcome.events {
                println!(
                    "{}",
                    serde_json::to_string(event).map_err(|error| failure(
                        SatelleError::invalid_usage(error.to_string()),
                        options.json
                    ))?
                );
            }
        }
        EffectiveEventMode::Human => {
            for event in &outcome.events {
                if options.verbose {
                    eprintln!(
                        "{}: {} data={}",
                        event.event_type(),
                        event.message(),
                        serde_json::to_string(event.data()).map_err(|error| failure(
                            SatelleError::invalid_usage(error.to_string()),
                            options.json
                        ))?
                    );
                } else {
                    eprintln!("{}: {}", event.event_type(), event.message());
                }
            }
        }
        EffectiveEventMode::None => {}
    }

    if effective_mode == EffectiveEventMode::Json {
        return Ok(());
    }

    if options.json {
        print_json(&json!({
            "session_id": outcome.session.session_id,
            "status": outcome.session.status,
            "effective_timeouts": options.effective_timeouts,
            "yolo": yolo_state_json(options.yolo_policy),
            "latest_turn": outcome.session.latest_turn(),
        }))
        .map_err(|error| failure(error, options.json))
    } else {
        if options.yolo_policy.active && !options.quiet {
            println!("YOLO mode: active ({})", options.yolo_policy.source);
        }
        print_session_human(&outcome.session);
        Ok(())
    }
}

fn print_detached_session(
    session: SessionRecord,
    effective_timeouts: serde_json::Value,
    yolo_policy: &YoloPolicy,
    json: bool,
) -> Result<(), CliFailure> {
    if json {
        print_json(&json!({
            "session_id": session.session_id,
            "host": session.host,
            "status": session.status,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
            "effective_timeouts": effective_timeouts,
            "yolo": yolo_state_json(yolo_policy),
            "turns": session.turns,
        }))
        .map_err(|error| failure(error, json))
    } else {
        if yolo_policy.active {
            println!("YOLO mode: active ({})", yolo_policy.source);
        }
        println!("Session: {}", session.session_id);
        println!("Status: {}", status_label(&session.status));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectiveEventMode {
    Human,
    Json,
    None,
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

fn print_session_human(session: &SessionRecord) {
    println!("Session: {}", session.session_id);
    println!("Host: {}", session.host);
    println!("Status: {}", status_label(&session.status));
    println!("Turns: {}", session.turns.len());
    if let Some(turn) = session.latest_turn() {
        println!("Latest turn: {}", turn.turn_id);
        println!("Latest status: {}", status_label(&turn.status));
        println!("Summary: {}", turn.summary);
    }
}

fn status_label(status: &TurnStatus) -> &'static str {
    match status {
        TurnStatus::Started => "started",
        TurnStatus::Completed => "completed",
        TurnStatus::Blocked => "blocked",
        TurnStatus::Failed => "failed",
        TurnStatus::Stopped => "stopped",
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

fn print_error(error: &SatelleError, json: bool) {
    if json {
        let mut error_object = serde_json::Map::new();
        error_object.insert("code".to_string(), json!(error.code.as_str()));
        error_object.insert("message".to_string(), json!(error.message));
        error_object.insert(
            "recovery_command".to_string(),
            json!(error.recovery_command),
        );
        error_object.insert("source_detail".to_string(), json!(error.source_detail));
        for (key, value) in &error.details {
            error_object.insert(key.clone(), value.clone());
        }
        let value = json!({
            "schema_version": ERROR_SCHEMA_VERSION,
            "error": error_object,
        });
        if let Ok(raw) = serde_json::to_string_pretty(&value) {
            eprintln!("{raw}");
            return;
        }
    }

    eprintln!("error: {}", error.code.as_str());
    eprintln!("{}", error.message);
    if let Some(command) = &error.recovery_command {
        eprintln!("next: {command}");
    }
}

fn failure(error: SatelleError, json: bool) -> CliFailure {
    CliFailure { error, json }
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
