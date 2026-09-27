use crate::error_output::error_envelope;
use crate::output::{OutputFormat, has_explicit_output_selector};
use crate::transport::process_interrupt_signal;
use crate::{Cli, Command as SatelleCommand, ConfigCommand};
use clap::{Args, CommandFactory, FromArgMatches, ValueEnum};
use satelle::command_group::CommandGroup as _;
use satelle::core::{
    ExplicitDuration, SatelleError, WebhookNotifierConfig, open_new_owner_only_file, utc_now,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BATCH_REQUEST_SCHEMA_VERSION: &str = "satelle.batch.request.v1";
const BATCH_RESULT_SCHEMA_VERSION: &str = "satelle.batch.result.v1";
const BATCH_SUMMARY_SCHEMA_VERSION: &str = "satelle.batch.summary.v1";
pub(crate) const REPL_TRANSCRIPT_SCHEMA_VERSION: &str = "satelle.repl.transcript.v1";
pub(crate) const WATCH_CHANGE_SCHEMA_VERSION: &str = "satelle.watch.change.v1";
pub(crate) const NOTIFY_WEBHOOK_SCHEMA_VERSION: &str = "satelle.notify.webhook.v1";
const DEFAULT_WATCH_INTERVAL: &str = "2s";
const DEFAULT_RECONNECT_ATTEMPTS: usize = 8;
const MAX_RECONNECT_ATTEMPTS: usize = 100;
const MAX_WEBHOOK_ATTEMPTS: usize = 3;
const WATCH_POLL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WATCH_POLL_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const REPL_CAPTURE_LIMIT: usize = 8 * 1024 * 1024;
pub(crate) const AUTOMATION_POLL_ENV: &str = "SATELLE_AUTOMATION_POLL";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WatchTarget {
    Sessions,
    Logs,
    Doctor,
    Host,
}

impl WatchTarget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sessions => "sessions",
            Self::Logs => "logs",
            Self::Doctor => "doctor",
            Self::Host => "host",
        }
    }
}

#[derive(Args, Clone, Debug)]
pub(crate) struct WatchCommand {
    #[arg(value_enum)]
    target: WatchTarget,
    /// Read state from this configured Host.
    #[arg(long)]
    host: Option<String>,
    /// Include only log entries for this Session.
    #[arg(long)]
    session: Option<String>,
    /// Delay between successful polls, such as 500ms or 2s.
    #[arg(long, default_value = DEFAULT_WATCH_INTERVAL)]
    interval: String,
    /// Consecutive failed polls allowed before the watch stops.
    #[arg(
        long,
        default_value_t = DEFAULT_RECONNECT_ATTEMPTS,
        value_parser = parse_reconnect_attempts
    )]
    reconnect_attempts: usize,
}

impl WatchCommand {
    pub(crate) fn history_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub(crate) fn history_session_id(&self) -> Option<&str> {
        (self.target == WatchTarget::Logs)
            .then_some(self.session.as_deref())
            .flatten()
    }
}

#[derive(Args, Debug)]
pub(crate) struct NotifyCommand {
    /// Satelle state category to watch.
    #[arg(long, value_enum)]
    watch: WatchTarget,
    /// User-level webhook notifier alias.
    #[arg(long)]
    webhook: String,
    /// Read state from this configured Host.
    #[arg(long)]
    host: Option<String>,
    /// Include only log entries for this Session.
    #[arg(long)]
    session: Option<String>,
    /// Delay between successful polls, such as 500ms or 2s.
    #[arg(long, default_value = DEFAULT_WATCH_INTERVAL)]
    interval: String,
    /// Consecutive failed polls allowed before the notification watch stops.
    #[arg(
        long,
        default_value_t = DEFAULT_RECONNECT_ATTEMPTS,
        value_parser = parse_reconnect_attempts
    )]
    reconnect_attempts: usize,
    /// Print webhook payloads without making network requests.
    #[arg(long)]
    dry_run: bool,
}

impl NotifyCommand {
    pub(crate) fn webhook(&self) -> &str {
        &self.webhook
    }

    pub(crate) fn history_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub(crate) fn history_session_id(&self) -> Option<&str> {
        (self.watch == WatchTarget::Logs)
            .then_some(self.session.as_deref())
            .flatten()
    }

    fn watch_command(&self) -> WatchCommand {
        WatchCommand {
            target: self.watch,
            host: self.host.clone(),
            session: self.session.clone(),
            interval: self.interval.clone(),
            reconnect_attempts: self.reconnect_attempts,
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct BatchCommand {
    /// NDJSON request file, or - for standard input.
    #[arg(long, value_name = "PATH_OR_DASH")]
    input: String,
    /// Maximum commands executed at once.
    #[arg(long, default_value_t = 4, value_parser = parse_batch_concurrency)]
    concurrency: usize,
}

#[derive(Args, Debug)]
pub(crate) struct ReplCommand {
    /// Select the Host used by every command in this REPL.
    #[arg(long)]
    host: Option<String>,
    /// Write one redacted versioned NDJSON record per executed command.
    #[arg(long, value_name = "PATH")]
    export: Option<PathBuf>,
    /// Preserve inline run and steer prompts in the exported transcript.
    #[arg(long, requires = "export")]
    include_prompts: bool,
}

impl ReplCommand {
    pub(crate) fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

fn parse_batch_concurrency(raw: &str) -> Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|_| "concurrency must be an integer from 1 through 16".to_string())?;
    (1..=16)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| "concurrency must be from 1 through 16".to_string())
}

fn parse_reconnect_attempts(raw: &str) -> Result<usize, String> {
    let value = raw.parse::<usize>().map_err(|_| {
        format!("reconnect attempts must be an integer from 1 through {MAX_RECONNECT_ATTEMPTS}")
    })?;
    (1..=MAX_RECONNECT_ATTEMPTS)
        .contains(&value)
        .then_some(value)
        .ok_or_else(|| {
            format!("reconnect attempts must be from 1 through {MAX_RECONNECT_ATTEMPTS}")
        })
}

#[derive(Clone)]
pub(crate) struct AutomationContext {
    executable: PathBuf,
    profile: Option<String>,
    no_color: bool,
}

impl AutomationContext {
    pub(crate) fn current(profile: Option<&str>, no_color: bool) -> Result<Self, SatelleError> {
        let executable = std::env::current_exe().map_err(|error| {
            SatelleError::invalid_usage(format!("could not locate the Satelle executable: {error}"))
        })?;
        Ok(Self {
            executable,
            profile: profile.map(str::to_string),
            no_color,
        })
    }

    fn machine_arguments(&self) -> Vec<String> {
        let mut arguments = Vec::new();
        if self.no_color {
            arguments.push("--no-color".to_string());
        }
        if let Some(profile) = &self.profile {
            arguments.extend(["--profile".to_string(), profile.clone()]);
        }
        arguments.extend(["--error-format".to_string(), "json".to_string()]);
        arguments
    }

    fn machine_command(&self) -> ProcessCommand {
        let mut command = ProcessCommand::new(&self.executable);
        command.args(self.machine_arguments());
        command
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRequest {
    schema_version: String,
    request_id: String,
    arguments: Vec<String>,
}

#[derive(Debug)]
struct IndexedRequest {
    index: usize,
    state: RequestState,
}

#[derive(Debug)]
enum RequestState {
    Ready(BatchRequest),
    Rejected {
        request_id: Option<String>,
        error: Value,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AutomationResultStatus {
    Success,
    Failure,
}

#[derive(Debug, Serialize)]
struct BatchResult {
    schema_version: &'static str,
    index: usize,
    request_id: Option<String>,
    status: AutomationResultStatus,
    exit_code: Option<i32>,
    duration_ms: u64,
    output: Vec<Value>,
    errors: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BatchSummaryStatus {
    Completed,
    CompletedWithFailures,
}

#[derive(Debug, Serialize)]
struct BatchSummary {
    schema_version: &'static str,
    status: BatchSummaryStatus,
    total: usize,
    succeeded: usize,
    failed: usize,
    concurrency: usize,
    duration_ms: u64,
}

pub(crate) struct BatchRunStatus {
    pub(crate) failed: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WatchChange {
    schema_version: &'static str,
    target: WatchTarget,
    sequence: u64,
    observed_at: String,
    state: Vec<Value>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct WebhookPayload<'a> {
    schema_version: &'static str,
    notifier: &'a str,
    change: &'a WatchChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplCommandKind {
    Run,
    Steer,
    Status,
    Logs,
    Doctor,
    ConfigCheck,
    ConfigExplain,
}

impl ReplCommandKind {
    const fn host_argument_index(self) -> usize {
        match self {
            Self::ConfigCheck | Self::ConfigExplain => 2,
            Self::Run | Self::Steer | Self::Status | Self::Logs | Self::Doctor => 1,
        }
    }

    const fn output_format(self) -> OutputFormat {
        if matches!(self, Self::Logs) {
            OutputFormat::Json
        } else {
            OutputFormat::CompactJson
        }
    }
}

#[derive(Debug)]
struct ParsedReplCommand {
    arguments: Vec<String>,
    kind: ReplCommandKind,
    prompt_index: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ReplTranscriptRecord {
    schema_version: &'static str,
    sequence: u64,
    host: String,
    command: Vec<String>,
    status: AutomationResultStatus,
    exit_code: Option<i32>,
    started_at: String,
    duration_ms: u64,
    output: Vec<Value>,
    errors: Vec<Value>,
    session_ids: Vec<String>,
}

#[derive(Debug)]
struct ReplStreamCapture {
    bytes: Vec<u8>,
    exceeded_limit: bool,
}

#[cfg(unix)]
struct ReplChildInterruptGuard {
    previous: libc::sigaction,
}

#[cfg(unix)]
impl ReplChildInterruptGuard {
    fn install() -> Result<Self, SatelleError> {
        unsafe extern "C" fn retain_parent(_: libc::c_int) {}

        // A caught disposition resets to the default across exec, so the child
        // still receives Ctrl-C while this REPL parent remains alive.
        let mut handler = unsafe { std::mem::zeroed::<libc::sigaction>() };
        handler.sa_sigaction = retain_parent as *const () as usize;
        handler.sa_flags = libc::SA_RESTART;
        if unsafe { libc::sigemptyset(&mut handler.sa_mask) } != 0 {
            return Err(repl_io_error(io::Error::last_os_error()));
        }
        let mut previous = unsafe { std::mem::zeroed::<libc::sigaction>() };
        if unsafe { libc::sigaction(libc::SIGINT, &handler, &mut previous) } != 0 {
            return Err(repl_io_error(io::Error::last_os_error()));
        }
        Ok(Self { previous })
    }
}

#[cfg(unix)]
impl Drop for ReplChildInterruptGuard {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGINT, &self.previous, std::ptr::null_mut());
        }
    }
}

#[cfg(windows)]
struct ReplChildInterruptGuard;

#[cfg(windows)]
impl ReplChildInterruptGuard {
    fn install() -> Result<Self, SatelleError> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

        if unsafe { SetConsoleCtrlHandler(Some(retain_repl_parent), 1) } == 0 {
            return Err(repl_io_error(io::Error::last_os_error()));
        }
        Ok(Self)
    }
}

#[cfg(windows)]
impl Drop for ReplChildInterruptGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

        unsafe {
            SetConsoleCtrlHandler(Some(retain_repl_parent), 0);
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn retain_repl_parent(control: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};

    i32::from(matches!(control, CTRL_C_EVENT | CTRL_BREAK_EVENT))
}

pub(crate) fn run_repl(
    command: ReplCommand,
    context: AutomationContext,
    selected_host: String,
) -> Result<(), SatelleError> {
    let mut transcript = command
        .export
        .as_deref()
        .map(|path| {
            open_new_owner_only_file(path).map_err(|error| {
                SatelleError::invalid_usage(format!(
                    "could not create owner-only REPL transcript '{}': {error}",
                    path.display()
                ))
            })
        })
        .transpose()?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    // Do not retain stderr's lock while a child is active. The live child
    // reader tees its structured error stream to the same terminal.
    let mut prompt_writer = io::stderr();
    let mut line = String::new();
    let mut sequence = 0_u64;
    let mut parser = Cli::command();

    writeln!(
        prompt_writer,
        "Satelle REPL for Host {selected_host}. Type help for commands or exit to leave."
    )
    .map_err(repl_io_error)?;
    loop {
        write!(prompt_writer, "satelle[{selected_host}]> ").map_err(repl_io_error)?;
        prompt_writer.flush().map_err(repl_io_error)?;
        line.clear();
        if input.read_line(&mut line).map_err(repl_io_error)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            break;
        }
        if trimmed == "help" {
            writeln!(
                prompt_writer,
                "commands: run, steer, status, logs, doctor, config check, config explain, help, exit, quit"
            )
            .map_err(repl_io_error)?;
            continue;
        }

        let parsed = match parse_repl_command_with(&mut parser, trimmed, transcript.is_some()) {
            Ok(parsed) => parsed,
            Err(error) => {
                writeln!(prompt_writer, "error: {}", error.message).map_err(repl_io_error)?;
                continue;
            }
        };
        sequence = sequence.saturating_add(1);
        let record = execute_repl_command(
            parsed,
            &context,
            &selected_host,
            command.include_prompts,
            transcript.is_some(),
            sequence,
        )?;
        if let (Some(file), Some(record)) = (transcript.as_mut(), record.as_ref()) {
            write_record(file, record)?;
        }
    }
    Ok(())
}

pub(crate) fn ensure_repl_terminal() -> Result<(), SatelleError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !io::stderr().is_terminal() {
        return Err(SatelleError::invalid_usage(
            "satelle repl requires interactive standard input, output, and error terminals",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn parse_repl_command(line: &str, exporting: bool) -> Result<ParsedReplCommand, SatelleError> {
    parse_repl_command_with(&mut Cli::command(), line, exporting)
}

fn parse_repl_command_with(
    parser: &mut clap::Command,
    line: &str,
    exporting: bool,
) -> Result<ParsedReplCommand, SatelleError> {
    let arguments = shlex::split(line)
        .ok_or_else(|| SatelleError::invalid_usage("REPL command contains an unclosed quote"))?;
    let Some(family) = arguments.first().map(String::as_str) else {
        return Err(SatelleError::invalid_usage("REPL command is empty"));
    };
    if !matches!(
        family,
        "run" | "steer" | "status" | "logs" | "doctor" | "config"
    ) {
        return Err(SatelleError::invalid_usage(
            "REPL accepts only run, steer, status, logs, doctor, config check, and config explain",
        ));
    }

    let matches = parser
        .try_get_matches_from_mut(
            std::iter::once("satelle").chain(arguments.iter().map(String::as_str)),
        )
        .map_err(|_| {
            SatelleError::invalid_usage("REPL command contains invalid Satelle arguments")
        })?;
    if has_explicit_output_selector(&matches) {
        return Err(SatelleError::invalid_usage(
            "REPL commands cannot override machine output selectors",
        ));
    }
    // Clap's positional index identifies the prompt even when an option value
    // contains the same text. Clap does not count `--`, so map its index back
    // to the entered token list before transcript redaction.
    let prompt_index = if matches!(family, "run" | "steer") {
        let parsed_index = matches
            .subcommand()
            .and_then(|(_, command)| command.indices_of("prompt"))
            .and_then(|mut indices| indices.next_back());
        parsed_index.map(|index| {
            if arguments
                .iter()
                .position(|argument| argument == "--")
                .is_some_and(|delimiter| delimiter <= index)
            {
                index + 1
            } else {
                index
            }
        })
    } else {
        None
    };
    let parsed = Cli::from_arg_matches(&matches).map_err(|_| {
        SatelleError::invalid_usage("REPL command contains invalid Satelle arguments")
    })?;
    if parsed.profile.is_some() || parsed.no_color || parsed.log_verbosity.is_some() {
        return Err(SatelleError::invalid_usage(
            "REPL commands cannot override the selected profile or global display settings",
        ));
    }

    let kind = match parsed.command {
        SatelleCommand::Run(command) if command.host.is_none() => ReplCommandKind::Run,
        SatelleCommand::Steer(command) if command.host.is_none() => ReplCommandKind::Steer,
        SatelleCommand::Status(command) if command.host.is_none() => ReplCommandKind::Status,
        SatelleCommand::Logs(command) if command.history_host().is_none() => ReplCommandKind::Logs,
        SatelleCommand::Doctor(command) if command.host.is_none() && !command.fix => {
            ReplCommandKind::Doctor
        }
        SatelleCommand::Config {
            command: ConfigCommand::Check(command),
        } if command.host.is_none() && !command.all => ReplCommandKind::ConfigCheck,
        SatelleCommand::Config {
            command: ConfigCommand::Explain(command),
        } if command.host.is_none() && !(exporting && command.show_secret_references) => {
            ReplCommandKind::ConfigExplain
        }
        _ => {
            return Err(SatelleError::invalid_usage(
                "REPL commands must use the selected Host and cannot start repair, all-Host, or nested automation work",
            ));
        }
    };
    Ok(ParsedReplCommand {
        arguments,
        kind,
        prompt_index,
    })
}

fn execute_repl_command(
    parsed: ParsedReplCommand,
    context: &AutomationContext,
    selected_host: &str,
    include_prompts: bool,
    capture_transcript: bool,
    sequence: u64,
) -> Result<Option<ReplTranscriptRecord>, SatelleError> {
    let transcript_metadata = capture_transcript.then(|| {
        (
            Instant::now(),
            utc_now(),
            redact_repl_command(&parsed, include_prompts),
        )
    });
    let mut arguments = parsed.arguments;
    arguments.splice(
        parsed.kind.host_argument_index()..parsed.kind.host_argument_index(),
        ["--host".to_string(), selected_host.to_string()],
    );
    let mut child = context.machine_command();
    append_machine_command_arguments(&mut child, &arguments, parsed.kind.output_format());
    let _interrupt_guard = ReplChildInterruptGuard::install()?;
    if !capture_transcript {
        child
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        child.status().map_err(|error| {
            SatelleError::invalid_usage(format!("could not execute REPL command: {error}"))
        })?;
        return Ok(None);
    }
    child
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child.spawn().map_err(|error| {
        SatelleError::invalid_usage(format!("could not execute REPL command: {error}"))
    })?;
    let stdout = child
        .stdout
        .take()
        .expect("REPL child standard output is piped");
    let stderr = child
        .stderr
        .take()
        .expect("REPL child standard error is piped");
    let (status, stdout, stderr) = std::thread::scope(|scope| {
        let stdout = scope.spawn(move || read_and_tee_repl_stream(stdout, false));
        let stderr = scope.spawn(move || read_and_tee_repl_stream(stderr, true));
        let status = child.wait();
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let stdout = stdout
            .join()
            .map_err(|_| SatelleError::invalid_usage("REPL output reader panicked"))??;
        let stderr = stderr
            .join()
            .map_err(|_| SatelleError::invalid_usage("REPL error reader panicked"))??;
        let status = status.map_err(repl_io_error)?;
        Ok::<_, SatelleError>((status, stdout, stderr))
    })?;
    let Some((started, started_at, transcript_command)) = transcript_metadata else {
        return Ok(None);
    };
    let (output, mut errors) = machine_stream_values(&stdout.bytes, &stderr.bytes, "REPL command");
    for (stream, capture) in [("standard output", stdout), ("standard error", stderr)] {
        if capture.exceeded_limit {
            errors.push(error_envelope(&SatelleError::invalid_usage(format!(
                "REPL command {stream} exceeded the {REPL_CAPTURE_LIMIT}-byte transcript limit"
            ))));
        }
    }
    let mut session_ids = BTreeSet::new();
    for value in output.iter().chain(&errors) {
        collect_session_ids(value, &mut session_ids);
    }
    let failed = !status.success() || !errors.is_empty();
    Ok(Some(ReplTranscriptRecord {
        schema_version: REPL_TRANSCRIPT_SCHEMA_VERSION,
        sequence,
        host: selected_host.to_string(),
        command: transcript_command,
        status: if failed {
            AutomationResultStatus::Failure
        } else {
            AutomationResultStatus::Success
        },
        exit_code: status.code(),
        started_at,
        duration_ms: elapsed_millis(started),
        output,
        errors,
        session_ids: session_ids.into_iter().collect(),
    }))
}

fn read_and_tee_repl_stream(
    reader: impl Read,
    to_stderr: bool,
) -> Result<ReplStreamCapture, SatelleError> {
    if to_stderr {
        read_and_tee_repl_stream_to(reader, io::stderr().lock())
    } else {
        read_and_tee_repl_stream_to(reader, io::stdout().lock())
    }
}

fn read_and_tee_repl_stream_to(
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<ReplStreamCapture, SatelleError> {
    let mut captured = Vec::new();
    let mut exceeded_limit = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(repl_io_error)?;
        if read == 0 {
            break;
        }
        if !exceeded_limit && captured.len().saturating_add(read) <= REPL_CAPTURE_LIMIT {
            captured.extend_from_slice(&buffer[..read]);
        } else {
            exceeded_limit = true;
            captured = Vec::new();
        }
        writer.write_all(&buffer[..read]).map_err(repl_io_error)?;
        writer.flush().map_err(repl_io_error)?;
    }
    Ok(ReplStreamCapture {
        bytes: captured,
        exceeded_limit,
    })
}

fn redact_repl_command(parsed: &ParsedReplCommand, include_prompts: bool) -> Vec<String> {
    let mut arguments = parsed.arguments.clone();
    let option_end = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    for index in 0..option_end {
        let flag = arguments[index].as_str();
        if matches!(
            flag,
            "--prompt-file" | "--image" | "--remote-image" | "--output"
        ) {
            if let Some(value) = arguments.get_mut(index + 1) {
                *value = "<redacted>".to_string();
            }
        } else if ["--prompt-file=", "--image=", "--remote-image=", "--output="]
            .iter()
            .any(|prefix| flag.starts_with(prefix))
        {
            let name = flag.split_once('=').map_or(flag, |(name, _)| name);
            arguments[index] = format!("{name}=<redacted>");
        }
    }
    if !include_prompts
        && let Some(index) = parsed.prompt_index
        && arguments.get(index).is_some_and(|prompt| prompt != "-")
    {
        arguments[index] = "<redacted>".to_string();
    }
    arguments
}

fn append_machine_command_arguments(
    command: &mut ProcessCommand,
    arguments: &[String],
    format: OutputFormat,
) {
    let delimiter = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    command
        .args(&arguments[..delimiter])
        .args(["--format", format.cli_name()])
        .args(&arguments[delimiter..]);
}

fn collect_session_ids(value: &Value, session_ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(Value::String(session_id)) = fields.get("session_id") {
                session_ids.insert(session_id.clone());
            }
            for value in fields.values() {
                collect_session_ids(value, session_ids);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_session_ids(value, session_ids);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn repl_io_error(error: io::Error) -> SatelleError {
    SatelleError::invalid_usage(format!("REPL input or output failed: {error}"))
}

pub(crate) fn run_watch(
    command: WatchCommand,
    context: AutomationContext,
) -> Result<(), SatelleError> {
    validate_watch_command(&command)?;
    let interval = watch_interval(&command.interval)?;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    watch_changes(command, interval, context, |change, _| {
        write_record(&mut writer, change)
    })
}

pub(crate) fn run_notify(
    command: NotifyCommand,
    context: AutomationContext,
    notifier: WebhookNotifierConfig,
) -> Result<(), SatelleError> {
    let watch = command.watch_command();
    validate_watch_command(&watch)?;
    let interval = watch_interval(&watch.interval)?;
    let endpoint = notifier.validate(&command.webhook)?;
    let authorization = notification_authorization(&notifier, &command.webhook, command.dry_run)?;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let mut client = None;
    watch_changes(watch, interval, context, |change, interrupted| {
        notify_change(
            change,
            &command.webhook,
            command.dry_run,
            &mut writer,
            |payload| {
                if client.is_none() {
                    client = Some(webhook_client(&command.webhook)?);
                }
                let client = client
                    .as_ref()
                    .expect("webhook client must exist before delivery");
                deliver_webhook(
                    client,
                    &endpoint,
                    authorization.as_ref().map(|secret| secret.as_str()),
                    payload,
                    &command.webhook,
                    interrupted,
                )
            },
        )
    })
}

fn notify_change(
    change: &WatchChange,
    notifier_alias: &str,
    dry_run: bool,
    writer: &mut impl Write,
    mut deliver: impl FnMut(&WebhookPayload<'_>) -> Result<(), SatelleError>,
) -> Result<(), SatelleError> {
    let payload = WebhookPayload {
        schema_version: NOTIFY_WEBHOOK_SCHEMA_VERSION,
        notifier: notifier_alias,
        change,
    };
    if dry_run {
        write_record(writer, &payload)
    } else {
        deliver(&payload)
    }
}

fn notification_authorization(
    notifier: &WebhookNotifierConfig,
    alias: &str,
    dry_run: bool,
) -> Result<Option<zeroize::Zeroizing<String>>, SatelleError> {
    if dry_run {
        Ok(None)
    } else {
        notifier.resolve_authorization(alias)
    }
}

fn watch_changes(
    command: WatchCommand,
    interval: Duration,
    context: AutomationContext,
    mut on_change: impl FnMut(&WatchChange, &AtomicBool) -> Result<(), SatelleError>,
) -> Result<(), SatelleError> {
    let interrupted = interrupt_flag()?;
    let mut previous_fingerprint = None;
    let mut sequence = 0_u64;
    let mut consecutive_failures = 0_usize;

    loop {
        if interrupted.load(Ordering::Acquire) {
            return Err(SatelleError::interrupted_attached_command());
        }
        match poll_watch_state(&command, &context, &interrupted) {
            Ok(state) => {
                consecutive_failures = 0;
                if let Some(change) = next_watch_change(
                    command.target,
                    &mut previous_fingerprint,
                    &mut sequence,
                    state,
                ) {
                    on_change(&change, &interrupted)?;
                }
                interruptible_sleep(interval, &interrupted)?;
            }
            Err(WatchPollError::Interrupted) => {
                return Err(SatelleError::interrupted_attached_command());
            }
            Err(WatchPollError::Failed) => {
                consecutive_failures += 1;
                if consecutive_failures >= command.reconnect_attempts {
                    return Err(SatelleError::watch_reconnect_exhausted(
                        command.target.as_str(),
                        consecutive_failures,
                    ));
                }
                let retry_delay = reconnect_delay(consecutive_failures);
                interruptible_sleep(retry_delay, &interrupted)?;
            }
        }
    }
}

fn validate_watch_command(command: &WatchCommand) -> Result<(), SatelleError> {
    if command.session.is_some() && command.target != WatchTarget::Logs {
        return Err(SatelleError::invalid_usage(
            "--session can be used only when watching logs",
        ));
    }
    Ok(())
}

fn next_watch_change(
    target: WatchTarget,
    previous_fingerprint: &mut Option<Vec<Value>>,
    sequence: &mut u64,
    state: Vec<Value>,
) -> Option<WatchChange> {
    if target == WatchTarget::Doctor {
        let fingerprint = watch_fingerprint(&state);
        if previous_fingerprint.as_ref() == Some(&fingerprint) {
            return None;
        }
        *previous_fingerprint = Some(fingerprint);
    } else {
        if previous_fingerprint.as_deref() == Some(state.as_slice()) {
            return None;
        }
        *previous_fingerprint = Some(state.clone());
    }
    *sequence = sequence.saturating_add(1);
    Some(WatchChange {
        schema_version: WATCH_CHANGE_SCHEMA_VERSION,
        target,
        sequence: *sequence,
        observed_at: utc_now(),
        state,
    })
}

fn watch_fingerprint(state: &[Value]) -> Vec<Value> {
    let mut fingerprint = state.to_vec();
    for value in &mut fingerprint {
        remove_doctor_observation_fields(value);
    }
    fingerprint
}

fn remove_doctor_observation_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for field in ["started_at", "finished_at", "duration_ms"] {
                object.remove(field);
            }
            for child in object.values_mut() {
                remove_doctor_observation_fields(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                remove_doctor_observation_fields(child);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn watch_interval(raw: &str) -> Result<Duration, SatelleError> {
    let milliseconds = ExplicitDuration::parse(raw)
        .map(|duration| duration.milliseconds())
        .filter(|milliseconds| (250..=60_000).contains(milliseconds))
        .ok_or_else(|| {
            SatelleError::invalid_usage("watch interval must be from 250ms through 60s")
        })?;
    Ok(Duration::from_millis(milliseconds))
}

fn reconnect_delay(attempt: usize) -> Duration {
    Duration::from_millis(250_u64.saturating_mul(1_u64 << attempt.min(4)))
}

fn interrupt_flag() -> Result<Arc<AtomicBool>, SatelleError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            SatelleError::invalid_usage(format!(
                "could not start watch interrupt listener: {error}"
            ))
        })?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let listener = Arc::clone(&interrupted);
    let watcher = std::thread::current();
    std::thread::Builder::new()
        .name("satelle-watch-interrupt".to_string())
        .spawn(move || {
            if runtime.block_on(process_interrupt_signal()).is_ok() {
                listener.store(true, Ordering::Release);
                watcher.unpark();
            }
        })
        .map_err(|error| {
            SatelleError::invalid_usage(format!(
                "could not start watch interrupt listener: {error}"
            ))
        })?;
    Ok(interrupted)
}

fn interruptible_sleep(duration: Duration, interrupted: &AtomicBool) -> Result<(), SatelleError> {
    let deadline = Instant::now() + duration;
    loop {
        if interrupted.load(Ordering::Acquire) {
            return Err(SatelleError::interrupted_attached_command());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        std::thread::park_timeout(remaining);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchPollError {
    Failed,
    Interrupted,
}

fn poll_watch_state(
    command: &WatchCommand,
    context: &AutomationContext,
    interrupted: &AtomicBool,
) -> Result<Vec<Value>, WatchPollError> {
    let mut child = ProcessCommand::new(&context.executable);
    child.args(watch_arguments(command, context));
    child
        // Polls are implementation details of the one outer watch. Keeping
        // them out of history and telemetry avoids an unbounded local trail.
        .env("SATELLE_COMMAND_HISTORY", "off")
        .env(AUTOMATION_POLL_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child
        .group()
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| WatchPollError::Failed)?;
    let stdout = child.inner().stdout.take().ok_or(WatchPollError::Failed)?;
    let stderr = child.inner().stderr.take().ok_or(WatchPollError::Failed)?;
    let stdout_reader = std::thread::spawn(move || capture_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || capture_bounded(stderr));
    let deadline = Instant::now() + WATCH_POLL_TIMEOUT;

    let status = loop {
        if interrupted.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(WatchPollError::Interrupted);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::park_timeout(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(25)),
                );
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(WatchPollError::Failed);
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| WatchPollError::Failed)?
        .map_err(|_| WatchPollError::Failed)?
        .ok_or(WatchPollError::Failed)?;
    // Child diagnostics do not invalidate otherwise valid machine output.
    // The bounded reader still drains stderr so the child cannot deadlock.
    let _ = stderr_reader.join().map_err(|_| WatchPollError::Failed)?;
    if !status.success() {
        return Err(WatchPollError::Failed);
    }
    json_values(&stdout, "standard output", "watch poll").map_err(|_| WatchPollError::Failed)
}

fn capture_bounded(mut reader: impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut captured = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if !exceeded && captured.len().saturating_add(read) <= WATCH_POLL_OUTPUT_LIMIT {
            captured.extend_from_slice(&buffer[..read]);
        } else {
            exceeded = true;
            captured.clear();
        }
    }
    Ok((!exceeded).then_some(captured))
}

fn watch_arguments(command: &WatchCommand, context: &AutomationContext) -> Vec<String> {
    let mut arguments = context.machine_arguments();
    match command.target {
        WatchTarget::Sessions => {
            arguments.extend(["host".to_string(), "sessions".to_string()]);
        }
        WatchTarget::Logs => {
            arguments.extend(["logs".to_string(), "--tail".to_string(), "200".to_string()]);
            if let Some(session) = &command.session {
                arguments.extend(["--session".to_string(), session.clone()]);
            }
        }
        WatchTarget::Doctor => {
            arguments.extend(["doctor".to_string(), "--no-input".to_string()]);
        }
        WatchTarget::Host => {
            arguments.extend(["host".to_string(), "status".to_string()]);
        }
    }
    if let Some(host) = &command.host {
        arguments.extend(["--host".to_string(), host.clone()]);
    }
    arguments.extend([
        "--format".to_string(),
        if command.target == WatchTarget::Logs {
            OutputFormat::Json.cli_name().to_string()
        } else {
            OutputFormat::CompactJson.cli_name().to_string()
        },
    ]);
    arguments
}

fn webhook_client(notifier_alias: &str) -> Result<reqwest::blocking::Client, SatelleError> {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| SatelleError::notify_delivery_failed(notifier_alias, 0))
}

fn deliver_webhook(
    client: &reqwest::blocking::Client,
    endpoint: &reqwest::Url,
    authorization: Option<&str>,
    payload: &WebhookPayload<'_>,
    notifier_alias: &str,
    interrupted: &AtomicBool,
) -> Result<(), SatelleError> {
    for attempt in 1..=MAX_WEBHOOK_ATTEMPTS {
        if interrupted.load(Ordering::Acquire) {
            return Err(SatelleError::interrupted_attached_command());
        }
        let request = client.post(endpoint.clone()).json(payload);
        let request = if let Some(secret) = authorization {
            request.bearer_auth(secret)
        } else {
            request
        };
        if request
            .send()
            .ok()
            .is_some_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        if attempt < MAX_WEBHOOK_ATTEMPTS {
            interruptible_sleep(Duration::from_millis(250 * attempt as u64), interrupted)?;
        }
    }
    Err(SatelleError::notify_delivery_failed(
        notifier_alias,
        MAX_WEBHOOK_ATTEMPTS,
    ))
}

pub(crate) fn run_batch(
    command: BatchCommand,
    context: AutomationContext,
) -> Result<BatchRunStatus, SatelleError> {
    let started = Instant::now();
    let requests = if command.input == "-" {
        read_requests(io::stdin().lock())?
    } else {
        let file = File::open(&command.input).map_err(|error| {
            SatelleError::invalid_usage(format!(
                "could not open batch input '{}': {error}",
                command.input
            ))
        })?;
        read_requests(BufReader::new(file))?
    };

    let mut succeeded = 0;
    let mut failed = 0;
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    // Workers claim the next input slot as they become free. Results are put
    // back into indexed slots so one slow command does not idle the pool or
    // change the output order.
    let next_request = AtomicUsize::new(0);
    let worker_count = command.concurrency.min(requests.len());
    let completed = std::thread::scope(|scope| {
        let workers = (0..worker_count)
            .map(|_| {
                let next_request = &next_request;
                let requests = &requests;
                let context = &context;
                scope.spawn(move || {
                    let mut completed = Vec::new();
                    loop {
                        let index = next_request.fetch_add(1, Ordering::Relaxed);
                        let Some(request) = requests.get(index) else {
                            break;
                        };
                        completed.push((index, execute_request(request, context)));
                    }
                    completed
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("batch command worker must not panic"))
            .collect::<Vec<_>>()
    });
    let mut ordered_results = (0..requests.len()).map(|_| None).collect::<Vec<_>>();
    for (index, result) in completed {
        ordered_results[index] = Some(result);
    }
    for result in ordered_results {
        let result = result.expect("every batch request must produce one result");
        if result.status == AutomationResultStatus::Success {
            succeeded += 1;
        } else {
            failed += 1;
        }
        write_record(&mut writer, &result)?;
    }

    write_record(
        &mut writer,
        &BatchSummary {
            schema_version: BATCH_SUMMARY_SCHEMA_VERSION,
            status: if failed == 0 {
                BatchSummaryStatus::Completed
            } else {
                BatchSummaryStatus::CompletedWithFailures
            },
            total: requests.len(),
            succeeded,
            failed,
            concurrency: command.concurrency,
            duration_ms: elapsed_millis(started),
        },
    )?;
    Ok(BatchRunStatus { failed })
}

fn read_requests(reader: impl BufRead) -> Result<Vec<IndexedRequest>, SatelleError> {
    reader
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let line = line.map_err(|error| {
                SatelleError::invalid_usage(format!(
                    "could not read batch input line {}: {error}",
                    index + 1
                ))
            })?;
            Ok(parse_request(index, &line))
        })
        .collect()
}

fn parse_request(index: usize, line: &str) -> IndexedRequest {
    let state = match serde_json::from_str::<BatchRequest>(line) {
        Ok(request) => {
            let request_id = Some(request.request_id.clone());
            match validate_request(index, request) {
                Ok(request) => RequestState::Ready(request),
                Err(error) => RequestState::Rejected { request_id, error },
            }
        }
        Err(error) => RequestState::Rejected {
            request_id: None,
            error: error_envelope(&SatelleError::invalid_usage(format!(
                "batch input line {} is not a valid {BATCH_REQUEST_SCHEMA_VERSION} object: {error}",
                index + 1
            ))),
        },
    };
    IndexedRequest { index, state }
}

fn validate_request(index: usize, request: BatchRequest) -> Result<BatchRequest, Value> {
    let invalid = |message: String| error_envelope(&SatelleError::invalid_usage(message));
    if request.schema_version != BATCH_REQUEST_SCHEMA_VERSION {
        return Err(invalid(format!(
            "batch input line {} uses unsupported schema_version '{}'",
            index + 1,
            request.schema_version
        )));
    }
    if request.request_id.is_empty() {
        return Err(invalid(format!(
            "batch input line {} requires a non-empty request_id",
            index + 1
        )));
    }
    if request.arguments.is_empty() {
        return Err(invalid(format!(
            "batch input line {} requires at least one command argument",
            index + 1
        )));
    }
    let arguments = std::iter::once("satelle").chain(request.arguments.iter().map(String::as_str));
    let matches = Cli::command()
        .try_get_matches_from(arguments)
        .map_err(|_| {
            invalid(format!(
                "batch input line {} contains invalid Satelle arguments",
                index + 1
            ))
        })?;
    if has_explicit_output_selector(&matches) {
        return Err(invalid(format!(
            "batch input line {} cannot override machine output selectors",
            index + 1
        )));
    }
    let parsed = Cli::from_arg_matches(&matches).map_err(|_| {
        invalid(format!(
            "batch input line {} contains invalid Satelle arguments",
            index + 1
        ))
    })?;
    if matches!(
        parsed.command,
        SatelleCommand::Batch(_)
            | SatelleCommand::Repl(_)
            | SatelleCommand::Watch(_)
            | SatelleCommand::Notify(_)
    ) {
        return Err(invalid(format!(
            "batch input line {} cannot start another automation workflow",
            index + 1
        )));
    }
    Ok(request)
}

fn execute_request(indexed: &IndexedRequest, context: &AutomationContext) -> BatchResult {
    let started = Instant::now();
    let request = match &indexed.state {
        RequestState::Ready(request) => request,
        RequestState::Rejected { request_id, error } => {
            return BatchResult {
                schema_version: BATCH_RESULT_SCHEMA_VERSION,
                index: indexed.index,
                request_id: request_id.clone(),
                status: AutomationResultStatus::Failure,
                exit_code: Some(64),
                duration_ms: elapsed_millis(started),
                output: Vec::new(),
                errors: vec![error.clone()],
            };
        }
    };

    let mut child = context.machine_command();
    append_machine_command_arguments(&mut child, &request.arguments, OutputFormat::CompactJson);
    child.stdin(Stdio::null());
    match child.output() {
        Ok(output) => {
            let (output_values, error_values) =
                machine_stream_values(&output.stdout, &output.stderr, "batch item");
            let contract_failed = !output.status.success() || !error_values.is_empty();
            BatchResult {
                schema_version: BATCH_RESULT_SCHEMA_VERSION,
                index: indexed.index,
                request_id: Some(request.request_id.clone()),
                status: if !contract_failed {
                    AutomationResultStatus::Success
                } else {
                    AutomationResultStatus::Failure
                },
                exit_code: output.status.code(),
                duration_ms: elapsed_millis(started),
                output: output_values,
                errors: error_values,
            }
        }
        Err(error) => BatchResult {
            schema_version: BATCH_RESULT_SCHEMA_VERSION,
            index: indexed.index,
            request_id: Some(request.request_id.clone()),
            status: AutomationResultStatus::Failure,
            exit_code: None,
            duration_ms: elapsed_millis(started),
            output: Vec::new(),
            errors: vec![error_envelope(&SatelleError::invalid_usage(format!(
                "could not execute batch item: {error}"
            )))],
        },
    }
}

fn machine_stream_values(
    stdout: &[u8],
    stderr: &[u8],
    operation: &str,
) -> (Vec<Value>, Vec<Value>) {
    let (output, output_error) = match json_values(stdout, "standard output", operation) {
        Ok(values) => (values, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let mut errors = match json_values(stderr, "standard error", operation) {
        Ok(values) => values,
        Err(error) => vec![error],
    };
    if let Some(error) = output_error {
        errors.push(error);
    }
    (output, errors)
}

fn json_values(bytes: &[u8], stream_name: &str, operation: &str) -> Result<Vec<Value>, Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            error_envelope(&SatelleError::invalid_usage(format!(
                "{operation} produced invalid JSON on {stream_name}: {error}"
            )))
        })
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn write_record(writer: &mut impl Write, value: &impl Serialize) -> Result<(), SatelleError> {
    serde_json::to_writer(&mut *writer, value).map_err(|error| {
        SatelleError::invalid_usage(format!("could not encode automation output: {error}"))
    })?;
    writeln!(writer).map_err(|error| {
        SatelleError::invalid_usage(format!("could not write automation output: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use satelle::core::WebhookSecretSource;

    #[test]
    fn rejects_recursive_workflows_and_output_overrides() {
        for arguments in [
            vec!["batch", "--input", "work.ndjson"],
            vec!["repl"],
            vec!["--no-color", "batch", "--input", "work.ndjson"],
            vec!["status", "rs_example", "--json"],
        ] {
            let line = serde_json::json!({
                "schema_version": BATCH_REQUEST_SCHEMA_VERSION,
                "request_id": "item-1",
                "arguments": arguments,
            })
            .to_string();
            assert!(matches!(
                parse_request(0, &line).state,
                RequestState::Rejected { .. }
            ));
        }
    }

    #[test]
    fn repl_accepts_only_selected_context_commands() {
        let parsed = parse_repl_command(r#"run "inspect the queue""#, false)
            .expect("parse quoted run command");
        assert_eq!(parsed.kind, ReplCommandKind::Run);
        assert_eq!(parsed.prompt_index, Some(1));

        for line in [
            "satelle status rs_01890a5d-ac96-7b7c-8f89-37c3d0a66ee11",
            "batch --input work.ndjson",
            "repl",
            "run --host office inspect",
            "status rs_01890a5d-ac96-7b7c-8f89-37c3d0a66ee11 --json",
            "doctor --fix --yes",
            "config check --all",
            "config repair",
        ] {
            assert!(parse_repl_command(line, false).is_err(), "accepted {line}");
        }
        assert!(parse_repl_command("config explain --show-secret-references", true).is_err());
    }

    #[test]
    fn repl_transcript_redacts_prompts_and_local_paths() {
        let parsed = parse_repl_command(
            r#"run --prompt-file "/private/prompt.txt" --image "/private/screen.png""#,
            true,
        )
        .expect("parse file-backed run");
        assert_eq!(
            redact_repl_command(&parsed, false),
            [
                "run",
                "--prompt-file",
                "<redacted>",
                "--image",
                "<redacted>",
            ]
        );

        let parsed = parse_repl_command(
            r#"steer rs_01890a5d-ac96-7b7c-8f89-37c3d0a66ee11 "private prompt""#,
            false,
        )
        .expect("parse steer command");
        assert_eq!(
            redact_repl_command(&parsed, false)
                .last()
                .map(String::as_str),
            Some("<redacted>")
        );
        assert_eq!(
            redact_repl_command(&parsed, true)
                .last()
                .map(String::as_str),
            Some("private prompt")
        );

        let parsed = parse_repl_command(r#"run "same value" --model "same value""#, false)
            .expect("parse prompt followed by an equal option value");
        assert_eq!(
            redact_repl_command(&parsed, false),
            ["run", "<redacted>", "--model", "same value"]
        );

        let parsed = parse_repl_command(r#"run -- "--image=/not-an-option""#, false)
            .expect("parse delimiter-protected prompt");
        assert_eq!(
            redact_repl_command(&parsed, true),
            ["run", "--", "--image=/not-an-option"]
        );
        assert_eq!(
            redact_repl_command(&parsed, false),
            ["run", "--", "<redacted>"]
        );
    }

    #[test]
    fn machine_output_selector_precedes_the_argument_delimiter() {
        let arguments = vec!["run".to_string(), "--".to_string(), "--format".to_string()];
        let mut command = ProcessCommand::new("satelle");
        append_machine_command_arguments(&mut command, &arguments, OutputFormat::CompactJson);

        assert_eq!(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["run", "--format", "compact-json", "--", "--format"]
        );
    }

    #[test]
    fn repl_stream_capture_reports_overflow_without_retaining_bytes() {
        let input = vec![b'x'; REPL_CAPTURE_LIMIT + 1];
        let mut terminal = Vec::new();
        let capture = read_and_tee_repl_stream_to(input.as_slice(), &mut terminal)
            .expect("tee over-limit stream");

        assert!(capture.exceeded_limit);
        assert!(capture.bytes.is_empty());
        assert_eq!(terminal, input);
    }

    #[test]
    fn repl_transcript_collects_stable_session_ids_once() {
        let mut session_ids = BTreeSet::new();
        collect_session_ids(
            &serde_json::json!({
                "session_id": "rs_first",
                "turns": [
                    {"session_id": "rs_second"},
                    {"nested": {"session_id": "rs_first"}}
                ]
            }),
            &mut session_ids,
        );
        assert_eq!(
            session_ids.into_iter().collect::<Vec<_>>(),
            ["rs_first", "rs_second"]
        );
    }

    #[test]
    fn repl_transcript_record_has_one_closed_versioned_shape() {
        let record = ReplTranscriptRecord {
            schema_version: REPL_TRANSCRIPT_SCHEMA_VERSION,
            sequence: 1,
            host: "office".to_string(),
            command: vec!["config".to_string(), "check".to_string()],
            status: AutomationResultStatus::Success,
            exit_code: Some(0),
            started_at: "2026-09-13T23:14:52Z".to_string(),
            duration_ms: 11,
            output: vec![serde_json::json!({"schema_version": "satelle.config.check.v1"})],
            errors: Vec::new(),
            session_ids: vec!["rs_example".to_string()],
        };

        assert_eq!(
            serde_json::to_value(record).expect("serialize REPL transcript"),
            serde_json::json!({
                "schema_version": "satelle.repl.transcript.v1",
                "sequence": 1,
                "host": "office",
                "command": ["config", "check"],
                "status": "success",
                "exit_code": 0,
                "started_at": "2026-09-13T23:14:52Z",
                "duration_ms": 11,
                "output": [{"schema_version": "satelle.config.check.v1"}],
                "errors": [],
                "session_ids": ["rs_example"],
            })
        );
    }

    #[test]
    fn accepts_one_closed_request_object() {
        let line = serde_json::json!({
            "schema_version": BATCH_REQUEST_SCHEMA_VERSION,
            "request_id": "item-1",
            "arguments": ["status", "rs_example"],
        })
        .to_string();
        let RequestState::Ready(request) = parse_request(0, &line).state else {
            panic!("request should be valid");
        };
        assert_eq!(request.request_id, "item-1");
        assert_eq!(request.arguments[0], "status");
    }

    #[test]
    fn output_like_prompt_text_after_the_delimiter_is_not_an_option() {
        let line = serde_json::json!({
            "schema_version": BATCH_REQUEST_SCHEMA_VERSION,
            "request_id": "item-1",
            "arguments": ["run", "--host", "office", "--", "--format"],
        })
        .to_string();
        assert!(matches!(
            parse_request(0, &line).state,
            RequestState::Ready(_)
        ));
    }

    #[test]
    fn invalid_child_output_becomes_a_typed_error_without_copying_raw_bytes() {
        let canary = "PRIVATE_CHILD_OUTPUT_CANARY";
        let error = json_values(canary.as_bytes(), "standard output", "batch item")
            .expect_err("plain text must not satisfy the child output contract");
        assert_eq!(error["code"], "invalid-usage");
        assert!(!error.to_string().contains(canary));
    }

    #[test]
    fn watch_arguments_keep_the_selected_context_and_target() {
        let command = WatchCommand {
            target: WatchTarget::Logs,
            host: Some("office".to_string()),
            session: Some("rs_example".to_string()),
            interval: DEFAULT_WATCH_INTERVAL.to_string(),
            reconnect_attempts: DEFAULT_RECONNECT_ATTEMPTS,
        };
        let context = AutomationContext {
            executable: PathBuf::from("satelle"),
            profile: Some("work".to_string()),
            no_color: true,
        };

        assert_eq!(
            watch_arguments(&command, &context),
            [
                "--no-color",
                "--profile",
                "work",
                "--error-format",
                "json",
                "logs",
                "--tail",
                "200",
                "--session",
                "rs_example",
                "--host",
                "office",
                "--format",
                "json",
            ]
        );
    }

    #[test]
    fn watch_emits_the_initial_state_and_only_later_changes() {
        let mut previous = None;
        let mut sequence = 0;
        let first = vec![serde_json::json!({"status": "running"})];
        let changed = vec![serde_json::json!({"status": "completed"})];

        assert_eq!(
            next_watch_change(
                WatchTarget::Sessions,
                &mut previous,
                &mut sequence,
                first.clone(),
            )
            .expect("emit the initial snapshot")
            .sequence,
            1
        );
        assert!(
            next_watch_change(WatchTarget::Sessions, &mut previous, &mut sequence, first,)
                .is_none()
        );
        assert_eq!(
            next_watch_change(WatchTarget::Sessions, &mut previous, &mut sequence, changed,)
                .expect("emit a changed snapshot")
                .sequence,
            2
        );
    }

    #[test]
    fn doctor_watch_ignores_probe_observation_timing() {
        let mut previous_fingerprint = None;
        let mut sequence = 0;
        let first = vec![serde_json::json!({
            "status": "ready",
            "started_at": "2026-09-13T10:00:00Z",
            "finished_at": "2026-09-13T10:00:01Z",
            "duration_ms": 1000,
            "probe_results": [{
                "probe_id": "native",
                "status": "ready",
                "started_at": "2026-09-13T10:00:00Z",
                "finished_at": "2026-09-13T10:00:01Z",
                "duration_ms": 1000
            }]
        })];
        let later = vec![serde_json::json!({
            "status": "ready",
            "started_at": "2026-09-13T10:00:02Z",
            "finished_at": "2026-09-13T10:00:03Z",
            "duration_ms": 900,
            "probe_results": [{
                "probe_id": "native",
                "status": "ready",
                "started_at": "2026-09-13T10:00:02Z",
                "finished_at": "2026-09-13T10:00:03Z",
                "duration_ms": 900
            }]
        })];

        assert!(
            next_watch_change(
                WatchTarget::Doctor,
                &mut previous_fingerprint,
                &mut sequence,
                first,
            )
            .is_some()
        );
        assert!(
            next_watch_change(
                WatchTarget::Doctor,
                &mut previous_fingerprint,
                &mut sequence,
                later,
            )
            .is_none()
        );
    }

    #[test]
    fn watch_rejects_session_filters_for_non_log_targets_and_invalid_budgets() {
        let command = WatchCommand {
            target: WatchTarget::Host,
            host: None,
            session: Some("rs_example".to_string()),
            interval: DEFAULT_WATCH_INTERVAL.to_string(),
            reconnect_attempts: DEFAULT_RECONNECT_ATTEMPTS,
        };
        assert_eq!(
            validate_watch_command(&command).unwrap_err().code,
            satelle::core::ErrorCode::InvalidUsage
        );
        for budget in ["0", "101", "many"] {
            assert!(
                Cli::try_parse_from([
                    "satelle",
                    "watch",
                    "sessions",
                    "--reconnect-attempts",
                    budget,
                ])
                .is_err(),
                "budget={budget}"
            );
        }
    }

    #[test]
    fn notify_dry_run_does_not_resolve_authorization() {
        let notifier = WebhookNotifierConfig {
            endpoint: "https://hooks.example.test/satelle".to_string(),
            authorization: Some(WebhookSecretSource::Environment {
                variable: "SATELLE_TEST_MISSING_WEBHOOK_TOKEN".to_string(),
            }),
        };

        assert!(
            notification_authorization(&notifier, "ops", true)
                .unwrap()
                .is_none()
        );
        assert!(notification_authorization(&notifier, "ops", false).is_err());
    }

    #[test]
    fn notify_dry_run_writes_the_exact_payload_without_delivery() {
        let change = WatchChange {
            schema_version: WATCH_CHANGE_SCHEMA_VERSION,
            target: WatchTarget::Host,
            sequence: 1,
            observed_at: "2026-09-13T10:00:00Z".to_string(),
            state: vec![serde_json::json!({"status": "ready"})],
        };
        let mut output = Vec::new();
        let mut delivery_count = 0;

        notify_change(&change, "ops", true, &mut output, |_| {
            delivery_count += 1;
            Ok(())
        })
        .expect("write dry-run notification");

        assert_eq!(delivery_count, 0);
        assert_eq!(
            serde_json::from_slice::<Value>(&output).expect("valid payload JSON"),
            serde_json::json!({
                "schema_version": NOTIFY_WEBHOOK_SCHEMA_VERSION,
                "notifier": "ops",
                "change": {
                    "schema_version": WATCH_CHANGE_SCHEMA_VERSION,
                    "target": "host",
                    "sequence": 1,
                    "observed_at": "2026-09-13T10:00:00Z",
                    "state": [{"status": "ready"}]
                }
            })
        );
    }

    #[test]
    fn notify_validates_the_watch_before_resolving_authorization() {
        let command = NotifyCommand {
            watch: WatchTarget::Host,
            webhook: "ops".to_string(),
            host: None,
            session: Some("rs_example".to_string()),
            interval: DEFAULT_WATCH_INTERVAL.to_string(),
            reconnect_attempts: DEFAULT_RECONNECT_ATTEMPTS,
            dry_run: false,
        };
        let context = AutomationContext {
            executable: PathBuf::from("satelle"),
            profile: None,
            no_color: false,
        };
        let notifier = WebhookNotifierConfig {
            endpoint: "https://hooks.example.test/satelle".to_string(),
            authorization: Some(WebhookSecretSource::Environment {
                variable: "SATELLE_TEST_MISSING_WEBHOOK_TOKEN".to_string(),
            }),
        };

        let error = run_notify(command, context, notifier).expect_err("invalid watch target");
        assert_eq!(error.code, satelle::core::ErrorCode::InvalidUsage);
        assert!(error.message.contains("--session"));
    }
}
