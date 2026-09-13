use crate::error_output::error_envelope;
use crate::output::has_explicit_output_selector;
use crate::transport::process_interrupt_signal;
use crate::{Cli, Command as SatelleCommand};
use clap::{Args, CommandFactory, FromArgMatches, ValueEnum};
use command_group::CommandGroup as _;
use satelle_core::{ExplicitDuration, SatelleError, WebhookNotifierConfig, utc_now};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BATCH_REQUEST_SCHEMA_VERSION: &str = "satelle.batch.request.v1";
const BATCH_RESULT_SCHEMA_VERSION: &str = "satelle.batch.result.v1";
const BATCH_SUMMARY_SCHEMA_VERSION: &str = "satelle.batch.summary.v1";
pub(crate) const WATCH_CHANGE_SCHEMA_VERSION: &str = "satelle.watch.change.v1";
pub(crate) const NOTIFY_WEBHOOK_SCHEMA_VERSION: &str = "satelle.notify.webhook.v1";
const DEFAULT_WATCH_INTERVAL: &str = "2s";
const DEFAULT_RECONNECT_ATTEMPTS: usize = 8;
const MAX_RECONNECT_ATTEMPTS: usize = 100;
const MAX_WEBHOOK_ATTEMPTS: usize = 3;
const WATCH_POLL_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WATCH_POLL_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
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

    fn finish_machine_command(&self, command: &mut ProcessCommand) {
        command
            .args(["--format", "compact-json"])
            .stdin(Stdio::null());
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
enum BatchResultStatus {
    Success,
    Failure,
}

#[derive(Debug, Serialize)]
struct BatchResult {
    schema_version: &'static str,
    index: usize,
    request_id: Option<String>,
    status: BatchResultStatus,
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
    json_values(&stdout, "standard output").map_err(|_| WatchPollError::Failed)
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
    arguments.extend(["--format".to_string(), "compact-json".to_string()]);
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
        if result.status == BatchResultStatus::Success {
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
        SatelleCommand::Batch(_) | SatelleCommand::Watch(_) | SatelleCommand::Notify(_)
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
                status: BatchResultStatus::Failure,
                exit_code: Some(64),
                duration_ms: elapsed_millis(started),
                output: Vec::new(),
                errors: vec![error.clone()],
            };
        }
    };

    let mut child = context.machine_command();
    child.args(&request.arguments);
    context.finish_machine_command(&mut child);
    match child.output() {
        Ok(output) => {
            let (output_values, output_error) = match json_values(&output.stdout, "standard output")
            {
                Ok(values) => (values, None),
                Err(error) => (Vec::new(), Some(error)),
            };
            let mut error_values = match json_values(&output.stderr, "standard error") {
                Ok(values) => values,
                Err(error) => vec![error],
            };
            if let Some(error) = output_error {
                error_values.push(error);
            }
            let contract_failed = !output.status.success() || !error_values.is_empty();
            BatchResult {
                schema_version: BATCH_RESULT_SCHEMA_VERSION,
                index: indexed.index,
                request_id: Some(request.request_id.clone()),
                status: if !contract_failed {
                    BatchResultStatus::Success
                } else {
                    BatchResultStatus::Failure
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
            status: BatchResultStatus::Failure,
            exit_code: None,
            duration_ms: elapsed_millis(started),
            output: Vec::new(),
            errors: vec![error_envelope(&SatelleError::invalid_usage(format!(
                "could not execute batch item: {error}"
            )))],
        },
    }
}

fn json_values(bytes: &[u8], stream_name: &str) -> Result<Vec<Value>, Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            error_envelope(&SatelleError::invalid_usage(format!(
                "batch item produced invalid JSON on {stream_name}: {error}"
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
    use satelle_core::WebhookSecretSource;

    #[test]
    fn rejects_recursive_workflows_and_output_overrides() {
        for arguments in [
            vec!["batch", "--input", "work.ndjson"],
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
        let error = json_values(canary.as_bytes(), "standard output")
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
                "compact-json",
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
            satelle_core::ErrorCode::InvalidUsage
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
        assert_eq!(error.code, satelle_core::ErrorCode::InvalidUsage);
        assert!(error.message.contains("--session"));
    }
}
