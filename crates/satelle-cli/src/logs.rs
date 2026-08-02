use super::output::{OutputArgs, OutputFormat};
use super::transport::{TransportClient, transport_for};
use super::{CliFailure, ConfigContext, failure, parse_duration_ms, shell_argument};
use clap::Args;
use satelle_core::{ErrorCode, SatelleError, SessionId};
use satelle_host::{DaemonLogEntry, LogCursor, LogPageQuery, LogSeverity, LogSource};
use std::io::{self, Write};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration as StdDuration, Instant, SystemTime};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const DEFAULT_LOG_PAGE_LIMIT: usize = 200;
const MAX_LOG_PAGE_LIMIT: usize = 10_000;
const INTERRUPT_POLL_INTERVAL: StdDuration = StdDuration::from_millis(50);
const FOLLOW_IDLE_INTERVAL: StdDuration = StdDuration::from_millis(250);
const RECONNECT_BUDGET: StdDuration = StdDuration::from_secs(60);
const RECONNECT_INITIAL_DELAY: StdDuration = StdDuration::from_millis(250);
const RECONNECT_MAX_DELAY: StdDuration = StdDuration::from_secs(5);
const MAX_STREAM_INTERRUPTS: usize = 10;

#[derive(Args, Debug)]
pub(crate) struct LogsCommand {
    #[arg(
        long,
        value_name = "ALIAS",
        help = "Read logs from this configured Host"
    )]
    host: Option<String>,
    #[arg(
        long,
        value_name = "SESSION_ID",
        help = "Include only entries for this Session"
    )]
    session: Option<String>,
    #[arg(
        long,
        value_name = "COUNT",
        help = "Return the most recent 1 to 10000 matching entries (default: 200)"
    )]
    tail: Option<usize>,
    #[arg(
        long,
        value_name = "DURATION_OR_RFC3339",
        help = "Include entries at or after this duration or RFC 3339 time"
    )]
    since: Option<String>,
    #[arg(
        long,
        value_name = "LOG_CURSOR",
        help = "Return entries strictly after this opaque cursor; conflicts with --since and --tail"
    )]
    after: Option<String>,
    #[arg(
        long,
        value_name = "SOURCE",
        help = "Include a source: host_daemon, storage, or codex_adapter; repeat to select multiple"
    )]
    source: Vec<String>,
    #[arg(
        long,
        value_name = "SEVERITY",
        help = "Set minimum severity: info, warn, or error (default: info)"
    )]
    level: Option<String>,
    #[arg(
        short = 'f',
        long,
        help = "Continue streaming new matching Log Entries"
    )]
    follow: bool,
    #[arg(
        long,
        requires = "follow",
        help = "Fail on transport loss instead of reconnecting"
    )]
    no_reconnect: bool,
    #[command(flatten)]
    pub(crate) output_args: OutputArgs,
}

impl LogsCommand {
    pub(super) fn history_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub(super) fn history_session_id(&self) -> Option<&str> {
        self.session.as_deref()
    }
}

pub(crate) struct LogReadRequest {
    pub(crate) host: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) tail: Option<usize>,
    pub(crate) since: Option<String>,
    pub(crate) after: Option<String>,
    pub(crate) source: Vec<String>,
    pub(crate) level: Option<String>,
    pub(crate) follow: bool,
    pub(crate) no_reconnect: bool,
    pub(crate) format: OutputFormat,
}

impl LogReadRequest {
    fn from_command(command: LogsCommand, format: OutputFormat) -> Self {
        Self {
            host: command.host,
            session: command.session,
            tail: command.tail,
            since: command.since,
            after: command.after,
            source: command.source,
            level: command.level,
            follow: command.follow,
            no_reconnect: command.no_reconnect,
            format,
        }
    }

    fn follow_rerun_command(&self, host: &str, cursor: LogCursor) -> String {
        let mut command = format!("satelle logs --host {}", shell_argument(host));
        if let Some(session) = &self.session {
            command.push_str(" --session ");
            command.push_str(session);
        }
        for source in &self.source {
            command.push_str(" --source ");
            command.push_str(source);
        }
        if let Some(level) = &self.level {
            command.push_str(" --level ");
            command.push_str(level);
        }
        command.push_str(" --after ");
        command.push_str(&cursor.to_string());
        command.push_str(" --follow");
        if self.format.is_json() {
            command.push_str(" --json");
        }
        if self.no_reconnect {
            command.push_str(" --no-reconnect");
        }
        command
    }
}

#[derive(Clone, Copy)]
enum LogPosition {
    Tail(usize),
    After(LogCursor),
    SinceAll,
}

struct LogReadPlan {
    session_id: Option<SessionId>,
    sources: Vec<LogSource>,
    minimum_severity: LogSeverity,
    since: Option<OffsetDateTime>,
    position: LogPosition,
}

trait FollowConnection: Send {
    fn host_identity(&self) -> Result<String, SatelleError>;
    fn session(
        &self,
        session_id: &SessionId,
    ) -> Result<satelle_core::session::PublicSession, SatelleError>;
    fn logs(&self, query: &LogPageQuery) -> Result<satelle_host::DaemonLogPage, SatelleError>;
}

type FollowConnectionFactory =
    Arc<dyn Fn() -> Result<Box<dyn FollowConnection>, SatelleError> + Send + Sync>;
type FollowReconnectResult =
    Result<(Box<dyn FollowConnection>, satelle_host::DaemonLogPage), SatelleError>;
type FollowInitialResult = (Box<dyn FollowConnection>, LogCursor, Option<LogCursor>);

struct TransportFollowConnection {
    transport: Box<dyn TransportClient>,
}

impl FollowConnection for TransportFollowConnection {
    fn host_identity(&self) -> Result<String, SatelleError> {
        self.transport.log_target_identity()
    }

    fn session(
        &self,
        session_id: &SessionId,
    ) -> Result<satelle_core::session::PublicSession, SatelleError> {
        self.transport.status(session_id)
    }

    fn logs(&self, query: &LogPageQuery) -> Result<satelle_host::DaemonLogPage, SatelleError> {
        self.transport.logs(query)
    }
}

trait FollowRuntime {
    fn now(&self) -> Instant;
    fn interrupted(&self) -> bool;
    fn sleep(&self, duration: StdDuration);
    fn jitter(&self, duration: StdDuration) -> StdDuration;
    fn reconnect_budget(&self) -> StdDuration {
        RECONNECT_BUDGET
    }
}

struct ProcessFollowRuntime {
    interrupted: Arc<AtomicBool>,
    jitter_sequence: AtomicU64,
}

impl ProcessFollowRuntime {
    fn new() -> Result<Self, SatelleError> {
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal_interrupted = Arc::clone(&interrupted);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                SatelleError::config_error(
                    "could not initialize Ctrl-C handling",
                    Some(error.to_string()),
                )
            })?;
        thread::Builder::new()
            .name("satelle-logs-follow-interrupt".to_string())
            .spawn(move || {
                if runtime.block_on(tokio::signal::ctrl_c()).is_ok() {
                    signal_interrupted.store(true, Ordering::Release);
                }
            })
            .map_err(|error| {
                SatelleError::config_error(
                    "could not start Ctrl-C handling",
                    Some(error.to_string()),
                )
            })?;
        Ok(Self {
            interrupted,
            jitter_sequence: AtomicU64::new(0),
        })
    }
}

impl FollowRuntime for ProcessFollowRuntime {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Acquire)
    }

    fn sleep(&self, duration: StdDuration) {
        let deadline = Instant::now() + duration;
        while !self.interrupted() {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            thread::sleep((deadline - now).min(INTERRUPT_POLL_INTERVAL));
        }
    }

    fn jitter(&self, duration: StdDuration) -> StdDuration {
        let sequence = self.jitter_sequence.fetch_add(1, Ordering::Relaxed);
        let sample = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(sequence, |time| time.as_nanos() as u64 ^ sequence);
        jittered_delay(duration, sample)
    }
}

struct FollowOutput<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}

struct FollowTarget<'a> {
    plan: &'a LogReadPlan,
    request: &'a LogReadRequest,
    host_alias: &'a str,
    expected_host_identity: &'a str,
}

fn follow_logs(
    plan: &LogReadPlan,
    request: &LogReadRequest,
    host_alias: &str,
    format: OutputFormat,
    runtime: &dyn FollowRuntime,
    connection_factory: &FollowConnectionFactory,
    output: FollowOutput<'_>,
) -> Result<(), SatelleError> {
    let FollowOutput { stdout, stderr } = output;
    let (connection, expected_host_identity) = open_follow_connection(
        Arc::clone(connection_factory),
        None,
        plan.session_id().cloned(),
        false,
        runtime,
    )?;
    let (mut connection, mut query_cursor, mut last_delivered) =
        plan.emit_follow_initial(connection, runtime, format, stdout)?;
    let mut stream_interruptions = 0;

    loop {
        if runtime.interrupted() {
            return Err(SatelleError::interrupted_attached_command());
        }
        let query = plan.follow_query(query_cursor);
        match read_follow_page(connection, query, runtime) {
            Ok((returned_connection, page)) => {
                connection = returned_connection;
                write_entries_to(page.entries(), None, format, stdout)?;
                if let Some(entry) = page.entries().last() {
                    last_delivered = Some(entry.cursor());
                }
                query_cursor = page.next_cursor();
                if !page.truncated() {
                    runtime.sleep(FOLLOW_IDLE_INTERVAL);
                }
            }
            Err(error) if transient_follow_error(error.code) => {
                stream_interruptions += 1;
                let report_cursor = last_delivered.unwrap_or(query_cursor);
                if request.no_reconnect {
                    writeln!(
                        stderr,
                        "log follow stopped after transport loss; last cursor={report_cursor}"
                    )
                    .map_err(log_output_error)?;
                    return Err(error);
                }
                if stream_interruptions >= MAX_STREAM_INTERRUPTS {
                    return Err(follow_reconnect_exhausted(
                        request,
                        host_alias,
                        report_cursor,
                        stream_interruptions,
                    ));
                }
                writeln!(
                    stderr,
                    "log follow reconnecting after interruption {stream_interruptions}/{MAX_STREAM_INTERRUPTS}; last cursor={report_cursor}"
                )
                .map_err(log_output_error)?;
                let target = FollowTarget {
                    plan,
                    request,
                    host_alias,
                    expected_host_identity: &expected_host_identity,
                };
                let (reconnected, page) = reconnect_follow(
                    &target,
                    runtime,
                    connection_factory,
                    query_cursor,
                    report_cursor,
                    stream_interruptions,
                    stderr,
                )?;
                connection = reconnected;
                write_entries_to(page.entries(), None, format, stdout)?;
                if let Some(entry) = page.entries().last() {
                    last_delivered = Some(entry.cursor());
                }
                query_cursor = page.next_cursor();
                if !page.truncated() {
                    runtime.sleep(FOLLOW_IDLE_INTERVAL);
                }
            }
            Err(error) if error.code == ErrorCode::HostIdentityMismatch => {
                return Err(SatelleError::logs_follow_identity_changed(
                    &expected_host_identity,
                    None,
                    plan.session_id().map(SessionId::as_str),
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn reconnect_follow(
    target: &FollowTarget<'_>,
    runtime: &dyn FollowRuntime,
    connection_factory: &FollowConnectionFactory,
    query_cursor: LogCursor,
    report_cursor: LogCursor,
    stream_interruptions: usize,
    stderr: &mut dyn Write,
) -> Result<(Box<dyn FollowConnection>, satelle_host::DaemonLogPage), SatelleError> {
    let deadline = runtime.now() + runtime.reconnect_budget();
    let mut delay = RECONNECT_INITIAL_DELAY;
    let exhausted = || {
        follow_reconnect_exhausted(
            target.request,
            target.host_alias,
            report_cursor,
            stream_interruptions,
        )
    };
    loop {
        if runtime.interrupted() {
            return Err(SatelleError::interrupted_attached_command());
        }
        let now = runtime.now();
        if now >= deadline {
            return Err(exhausted());
        }
        runtime.sleep(runtime.jitter(delay).min(deadline - now));
        if runtime.interrupted() {
            return Err(SatelleError::interrupted_attached_command());
        }
        let attempt_started_at = runtime.now();
        if attempt_started_at >= deadline {
            return Err(exhausted());
        }

        let Some(attempt) = run_reconnect_attempt(
            Arc::clone(connection_factory),
            target.expected_host_identity.to_string(),
            target.plan.session_id().cloned(),
            target.plan.follow_query(query_cursor),
            deadline - attempt_started_at,
            runtime,
        ) else {
            return Err(exhausted());
        };
        match attempt {
            Ok(reconnected) => {
                writeln!(
                    stderr,
                    "log follow reconnected; resuming after cursor={query_cursor}"
                )
                .map_err(log_output_error)?;
                return Ok(reconnected);
            }
            Err(error) if transient_follow_error(error.code) => {
                delay = delay.saturating_mul(2).min(RECONNECT_MAX_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

fn run_reconnect_attempt(
    connection_factory: FollowConnectionFactory,
    expected_host_identity: String,
    session_id: Option<SessionId>,
    query: LogPageQuery,
    timeout: StdDuration,
    runtime: &dyn FollowRuntime,
) -> Option<FollowReconnectResult> {
    match run_follow_operation(runtime, Some(timeout), move || {
        let attempt = (|| {
            let connection = connection_factory()?;
            validate_follow_connection(
                connection.as_ref(),
                Some(&expected_host_identity),
                session_id.as_ref(),
                true,
            )?;
            let page = connection.logs(&query)?;
            Ok((connection, page))
        })();
        attempt.map_err(|error: SatelleError| {
            if error.code == ErrorCode::HostIdentityMismatch {
                SatelleError::logs_follow_identity_changed(
                    &expected_host_identity,
                    None,
                    session_id.as_ref().map(SessionId::as_str),
                )
            } else {
                error
            }
        })
    }) {
        Ok(FollowOperation::Completed(reconnected)) => Some(Ok(reconnected)),
        Ok(FollowOperation::TimedOut) => None,
        Err(error) => Some(Err(error)),
    }
}

enum FollowOperation<T> {
    Completed(T),
    TimedOut,
}

fn run_follow_operation<T: Send + 'static>(
    runtime: &dyn FollowRuntime,
    timeout: Option<StdDuration>,
    operation: impl FnOnce() -> Result<T, SatelleError> + Send + 'static,
) -> Result<FollowOperation<T>, SatelleError> {
    let (completed, completion) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("satelle-log-follow-io".to_string())
        .spawn(move || {
            let _completed = completed.send(operation());
        })
        .map_err(|error| {
            SatelleError::config_error(
                "could not start interruptible log follow I/O",
                Some(error.to_string()),
            )
        })?;
    let receive_deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        if runtime.interrupted() {
            return Err(SatelleError::interrupted_attached_command());
        }
        let wait = match receive_deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(FollowOperation::TimedOut);
                }
                remaining.min(INTERRUPT_POLL_INTERVAL)
            }
            None => INTERRUPT_POLL_INTERVAL,
        };
        match completion.recv_timeout(wait) {
            Ok(result) => return result.map(FollowOperation::Completed),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(SatelleError::config_error(
                    "interruptible log follow I/O stopped without a result",
                    None,
                ));
            }
        }
    }
}

fn open_follow_connection(
    connection_factory: FollowConnectionFactory,
    expected_host_identity: Option<String>,
    session_id: Option<SessionId>,
    reconnect: bool,
    runtime: &dyn FollowRuntime,
) -> Result<(Box<dyn FollowConnection>, String), SatelleError> {
    match run_follow_operation(runtime, None, move || {
        connection_factory().and_then(|connection| {
            validate_follow_connection(
                connection.as_ref(),
                expected_host_identity.as_deref(),
                session_id.as_ref(),
                reconnect,
            )
            .map(|observed_host_identity| (connection, observed_host_identity))
        })
    })? {
        FollowOperation::Completed(connection) => Ok(connection),
        FollowOperation::TimedOut => unreachable!("an initial follow operation has no timeout"),
    }
}

fn read_follow_page(
    connection: Box<dyn FollowConnection>,
    query: LogPageQuery,
    runtime: &dyn FollowRuntime,
) -> Result<(Box<dyn FollowConnection>, satelle_host::DaemonLogPage), SatelleError> {
    match run_follow_operation(runtime, None, move || {
        let page = connection.logs(&query)?;
        Ok((connection, page))
    })? {
        FollowOperation::Completed(page) => Ok(page),
        FollowOperation::TimedOut => unreachable!("an active follow read has no local timeout"),
    }
}

fn validate_follow_connection(
    connection: &dyn FollowConnection,
    expected_host_identity: Option<&str>,
    session_id: Option<&SessionId>,
    reconnect: bool,
) -> Result<String, SatelleError> {
    let observed_host_identity = connection.host_identity()?;
    if let Some(expected) = expected_host_identity
        && observed_host_identity != expected
    {
        return Err(SatelleError::logs_follow_identity_changed(
            expected,
            Some(&observed_host_identity),
            session_id.map(SessionId::as_str),
        ));
    }
    if let Some(session_id) = session_id {
        let session = connection.session(session_id).map_err(|error| {
            if reconnect && error.code == ErrorCode::SessionNotFound {
                SatelleError::logs_follow_identity_changed(
                    expected_host_identity.unwrap_or(&observed_host_identity),
                    Some(&observed_host_identity),
                    Some(session_id.as_str()),
                )
            } else {
                error
            }
        })?;
        if session.session_id() != session_id {
            return Err(SatelleError::logs_follow_identity_changed(
                expected_host_identity.unwrap_or(&observed_host_identity),
                Some(&observed_host_identity),
                Some(session_id.as_str()),
            ));
        }
    }
    Ok(observed_host_identity)
}

fn transient_follow_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::HostUnreachable
            | ErrorCode::HostDaemonUnreachable
            | ErrorCode::DirectDaemonUnreachable
            | ErrorCode::SshBootstrapUnavailable
    )
}

fn follow_reconnect_exhausted(
    request: &LogReadRequest,
    host_alias: &str,
    cursor: LogCursor,
    stream_interruptions: usize,
) -> SatelleError {
    SatelleError::logs_follow_reconnect_exhausted(
        &cursor.to_string(),
        stream_interruptions,
        &request.follow_rerun_command(host_alias, cursor),
    )
}

fn jittered_delay(duration: StdDuration, sample: u64) -> StdDuration {
    let basis_points = 8_000_u128 + u128::from(sample % 4_001);
    let nanos = duration.as_nanos().saturating_mul(basis_points) / 10_000;
    StdDuration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64).min(RECONNECT_MAX_DELAY)
}

impl LogReadPlan {
    fn resolve(command: &LogReadRequest) -> Result<Self, CliFailure> {
        if command.after.is_some() && command.since.is_some() {
            return Err(failure(SatelleError::log_position_conflict("--since")));
        }
        if command.after.is_some() && command.tail.is_some() {
            return Err(failure(SatelleError::log_position_conflict("--tail")));
        }

        let tail = match command.tail {
            Some(value @ 1..=MAX_LOG_PAGE_LIMIT) => Some(value),
            Some(value) => {
                return Err(failure(SatelleError::log_tail_limit_exceeded(value)));
            }
            None => None,
        };
        let session_id = command
            .session
            .as_deref()
            .map(SessionId::from_str)
            .transpose()
            .map_err(|error| failure(error.into()))?;
        let minimum_severity = match command.level.as_deref().unwrap_or("info") {
            "info" => LogSeverity::Info,
            "warn" => LogSeverity::Warning,
            "error" => LogSeverity::Error,
            _ => {
                return Err(failure(SatelleError::invalid_usage(
                    "--level must be one of info, warn, or error",
                )));
            }
        };
        let since = command
            .since
            .as_deref()
            .map(parse_log_since)
            .transpose()
            .map_err(failure)?;
        let sources = command
            .source
            .iter()
            .map(|source| match source.as_str() {
                "host_daemon" => Ok(LogSource::HostDaemon),
                "storage" => Ok(LogSource::Storage),
                "codex_adapter" => Ok(LogSource::CodexAdapter),
                _ => Err(failure(SatelleError::invalid_usage(
                    "--source must be one of host_daemon, storage, or codex_adapter",
                ))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let position = if let Some(after) = command.after.as_deref() {
            LogPosition::After(LogCursor::parse(after).map_err(|error| {
                failure(SatelleError::invalid_usage(format!(
                    "invalid --after cursor: {error}"
                )))
            })?)
        } else if let Some(tail) = tail {
            LogPosition::Tail(tail)
        } else if since.is_some() {
            LogPosition::SinceAll
        } else {
            LogPosition::Tail(DEFAULT_LOG_PAGE_LIMIT)
        };

        Ok(Self {
            session_id,
            sources,
            minimum_severity,
            since,
            position,
        })
    }

    const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    fn query(&self, query: LogPageQuery) -> LogPageQuery {
        let mut query = query.with_minimum_severity(self.minimum_severity);
        if let Some(session_id) = &self.session_id {
            query = query.with_session(session_id.clone());
        }
        if !self.sources.is_empty() {
            query = query.with_sources(self.sources.iter().copied());
        }
        if let Some(since) = self.since {
            query = query.with_since(since);
        }
        query
    }

    fn emit(
        &self,
        transport: &dyn TransportClient,
        format: OutputFormat,
    ) -> Result<(), SatelleError> {
        match self.position {
            LogPosition::Tail(limit) => {
                let query = self.query(
                    LogPageQuery::tail(limit).expect("the validated tail Log limit is valid"),
                );
                let page = transport.logs(&query)?;
                write_entries(page.entries(), None, format)
            }
            LogPosition::After(cursor) => {
                let query = self.query(
                    LogPageQuery::forward(Some(cursor), DEFAULT_LOG_PAGE_LIMIT)
                        .expect("the default forward Log limit is valid"),
                );
                let page = transport.logs(&query)?;
                write_entries(page.entries(), None, format)
            }
            LogPosition::SinceAll => self.emit_since_snapshot(transport, format),
        }
    }

    fn read(&self, transport: &dyn TransportClient) -> Result<Vec<DaemonLogEntry>, SatelleError> {
        match self.position {
            LogPosition::Tail(limit) => {
                let query = self.query(
                    LogPageQuery::tail(limit).expect("the validated tail Log limit is valid"),
                );
                Ok(transport.logs(&query)?.entries().to_vec())
            }
            LogPosition::After(cursor) => {
                let query = self.query(
                    LogPageQuery::forward(Some(cursor), DEFAULT_LOG_PAGE_LIMIT)
                        .expect("the default forward Log limit is valid"),
                );
                Ok(transport.logs(&query)?.entries().to_vec())
            }
            LogPosition::SinceAll => self.read_since_snapshot(transport),
        }
    }

    fn emit_follow_initial(
        &self,
        mut connection: Box<dyn FollowConnection>,
        runtime: &dyn FollowRuntime,
        format: OutputFormat,
        stdout: &mut dyn Write,
    ) -> Result<FollowInitialResult, SatelleError> {
        match self.position {
            LogPosition::Tail(limit) => {
                let (connection, page) = read_follow_page(
                    connection,
                    self.query(
                        LogPageQuery::tail(limit).expect("the validated tail Log limit is valid"),
                    ),
                    runtime,
                )?;
                write_entries_to(page.entries(), None, format, stdout)?;
                Ok((
                    connection,
                    page.next_cursor(),
                    page.entries().last().map(DaemonLogEntry::cursor),
                ))
            }
            LogPosition::After(cursor) => {
                let (connection, page) = read_follow_page(
                    connection,
                    self.query(
                        LogPageQuery::forward(Some(cursor), DEFAULT_LOG_PAGE_LIMIT)
                            .expect("the default forward Log limit is valid"),
                    ),
                    runtime,
                )?;
                write_entries_to(page.entries(), None, format, stdout)?;
                Ok((
                    connection,
                    page.next_cursor(),
                    page.entries().last().map(DaemonLogEntry::cursor),
                ))
            }
            LogPosition::SinceAll => {
                let (returned_connection, snapshot_page) = read_follow_page(
                    connection,
                    self.query(
                        LogPageQuery::tail(1).expect("the snapshot Log page limit is valid"),
                    ),
                    runtime,
                )?;
                connection = returned_connection;
                let snapshot = snapshot_page.next_cursor();
                let mut cursor = None;
                let mut last_delivered = None;
                loop {
                    let (returned_connection, page) = read_follow_page(
                        connection,
                        self.query(
                            LogPageQuery::forward(cursor, MAX_LOG_PAGE_LIMIT)
                                .expect("the maximum forward Log limit is valid"),
                        ),
                        runtime,
                    )?;
                    connection = returned_connection;
                    let reached_snapshot = !page.truncated()
                        || page
                            .entries()
                            .last()
                            .is_some_and(|entry| entry.cursor() >= snapshot);
                    write_entries_to(page.entries(), Some(snapshot), format, stdout)?;
                    if let Some(entry) = page
                        .entries()
                        .iter()
                        .take_while(|entry| entry.cursor() <= snapshot)
                        .last()
                    {
                        last_delivered = Some(entry.cursor());
                    }
                    if reached_snapshot {
                        return Ok((connection, snapshot, last_delivered));
                    }
                    cursor = Some(page.next_cursor());
                }
            }
        }
    }

    fn follow_query(&self, cursor: LogCursor) -> LogPageQuery {
        self.query(
            LogPageQuery::forward(Some(cursor), DEFAULT_LOG_PAGE_LIMIT)
                .expect("the default forward Log limit is valid"),
        )
    }

    fn read_since_snapshot(
        &self,
        transport: &dyn TransportClient,
    ) -> Result<Vec<DaemonLogEntry>, SatelleError> {
        let mut entries = Vec::new();
        self.visit_since_snapshot(transport, |page, snapshot| {
            entries.extend(
                page.iter()
                    .take_while(|entry| entry.cursor() <= snapshot)
                    .cloned(),
            );
            Ok(())
        })?;
        Ok(entries)
    }

    fn emit_since_snapshot(
        &self,
        transport: &dyn TransportClient,
        format: OutputFormat,
    ) -> Result<(), SatelleError> {
        self.visit_since_snapshot(transport, |entries, snapshot| {
            // Logs are record streams. If a later page fails, already-written complete records
            // remain valid stdout while the command reports failure on stderr and exits nonzero.
            write_entries(entries, Some(snapshot), format)
        })
    }

    fn visit_since_snapshot(
        &self,
        transport: &dyn TransportClient,
        mut visit: impl FnMut(&[DaemonLogEntry], LogCursor) -> Result<(), SatelleError>,
    ) -> Result<(), SatelleError> {
        // Capture one Host high-water boundary before paging. New entries may arrive while this
        // finite command runs, but they belong to a later invocation and cannot extend this read.
        let snapshot = transport
            .logs(
                &self.query(LogPageQuery::tail(1).expect("the snapshot Log page limit is valid")),
            )?
            .next_cursor();
        let mut cursor = None;

        loop {
            let query = self.query(
                LogPageQuery::forward(cursor, MAX_LOG_PAGE_LIMIT)
                    .expect("the maximum forward Log limit is valid"),
            );
            let page = transport.logs(&query)?;
            let reached_snapshot = !page.truncated()
                || page
                    .entries()
                    .last()
                    .is_some_and(|entry| entry.cursor() >= snapshot);
            visit(page.entries(), snapshot)?;
            if reached_snapshot {
                return Ok(());
            }
            cursor = Some(page.next_cursor());
        }
    }
}

pub(crate) fn show_logs(
    command: LogsCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let request = LogReadRequest::from_command(command, format);
    let plan = LogReadPlan::resolve(&request)?;
    let host = match plan.session_id() {
        Some(session_id) => config
            .resolve_session_host(request.host.as_deref(), session_id)
            .or_else(|failure| unresolved_log_target(&request, failure))?,
        None => config
            .resolve_host(request.host.as_deref())
            .or_else(|failure| unresolved_log_target(&request, failure))?,
    };
    if request.follow {
        let runtime = ProcessFollowRuntime::new().map_err(failure)?;
        let follow_host = host.clone();
        let connection_factory: FollowConnectionFactory = Arc::new(move || {
            transport_for(&follow_host)
                .map(|transport| {
                    Box::new(TransportFollowConnection { transport }) as Box<dyn FollowConnection>
                })
                .map_err(|failure| failure.error)
        });
        let stdout = io::stdout();
        let stderr = io::stderr();
        let mut stdout = stdout.lock();
        let mut stderr = stderr.lock();
        return follow_logs(
            &plan,
            &request,
            &host.alias,
            format,
            &runtime,
            &connection_factory,
            FollowOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
        )
        .map_err(failure);
    }
    let transport = transport_for(&host)?;
    plan.emit(transport.as_ref(), format).map_err(failure)
}

fn unresolved_log_target(
    request: &LogReadRequest,
    failure: CliFailure,
) -> Result<super::SelectedHost, CliFailure> {
    if request.host.is_none()
        && (failure.error.code == ErrorCode::HostNotFound
            || (failure.error.code == ErrorCode::InvalidUsage
                && failure.error.details.get("candidate_count") == Some(&serde_json::json!(0))))
    {
        Err(super::failure(SatelleError::logs_target_required()))
    } else {
        Err(failure)
    }
}

pub(crate) fn read_logs_for_host(
    request: &LogReadRequest,
    host: &super::SelectedHost,
) -> Result<Vec<DaemonLogEntry>, CliFailure> {
    let plan = LogReadPlan::resolve(request)?;
    let transport = transport_for(host)?;
    plan.read(transport.as_ref()).map_err(failure)
}

fn write_entries(
    entries: &[DaemonLogEntry],
    through: Option<LogCursor>,
    format: OutputFormat,
) -> Result<(), SatelleError> {
    let mut stdout = io::stdout().lock();
    write_entries_to(entries, through, format, &mut stdout)
}

fn write_entries_to(
    entries: &[DaemonLogEntry],
    through: Option<LogCursor>,
    format: OutputFormat,
    stdout: &mut dyn Write,
) -> Result<(), SatelleError> {
    for entry in entries
        .iter()
        .take_while(|entry| through.is_none_or(|cursor| entry.cursor() <= cursor))
    {
        if format.is_json() {
            serde_json::to_writer(&mut *stdout, entry)
                .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
            writeln!(stdout).map_err(log_output_error)?;
        } else {
            writeln!(
                stdout,
                "{} [{}] source={} event={} cursor={} {}",
                entry
                    .timestamp()
                    .format(&Rfc3339)
                    .expect("a valid Log timestamp formats as RFC 3339"),
                entry.severity().as_str(),
                entry.source().as_str(),
                entry.event().as_str(),
                entry.cursor(),
                entry.event().message(),
            )
            .map_err(log_output_error)?;
        }
    }
    stdout.flush().map_err(log_output_error)
}

fn parse_log_since(value: &str) -> Result<OffsetDateTime, SatelleError> {
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(timestamp);
    }

    let millis = parse_duration_ms(value)?;
    Ok(OffsetDateTime::now_utc() - Duration::milliseconds(millis.min(i64::MAX as u64) as i64))
}

fn log_output_error(error: io::Error) -> SatelleError {
    SatelleError::invalid_usage(format!("could not write log output: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    struct FakeFollowConnection {
        host_identity: String,
        pages: Mutex<VecDeque<Result<satelle_host::DaemonLogPage, SatelleError>>>,
        interrupt_on_log: Option<(Arc<AtomicBool>, usize, StdDuration)>,
        log_calls: AtomicUsize,
    }

    struct SessionIdentityMismatchFollowConnection;

    struct SessionScopeMismatchFollowConnection {
        returned_session: satelle_core::session::PublicSession,
    }

    impl FakeFollowConnection {
        fn new(
            host_identity: &str,
            pages: impl IntoIterator<Item = Result<satelle_host::DaemonLogPage, SatelleError>>,
        ) -> Self {
            Self {
                host_identity: host_identity.to_string(),
                pages: Mutex::new(pages.into_iter().collect()),
                interrupt_on_log: None,
                log_calls: AtomicUsize::new(0),
            }
        }

        fn with_interrupt_on_log(
            mut self,
            call: usize,
            interrupted: Arc<AtomicBool>,
            delay: StdDuration,
        ) -> Self {
            self.interrupt_on_log = Some((interrupted, call, delay));
            self
        }
    }

    impl FollowConnection for FakeFollowConnection {
        fn host_identity(&self) -> Result<String, SatelleError> {
            Ok(self.host_identity.clone())
        }

        fn session(
            &self,
            _session_id: &SessionId,
        ) -> Result<satelle_core::session::PublicSession, SatelleError> {
            Err(SatelleError::not_implemented(
                "the no-Session follow fixture does not load Sessions",
            ))
        }

        fn logs(&self, _query: &LogPageQuery) -> Result<satelle_host::DaemonLogPage, SatelleError> {
            let call = self.log_calls.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some((interrupted, interrupt_call, delay)) = &self.interrupt_on_log
                && call == *interrupt_call
            {
                interrupted.store(true, Ordering::Release);
                thread::sleep(*delay);
            }
            self.pages
                .lock()
                .expect("follow fixture queue lock")
                .pop_front()
                .expect("follow fixture has a response")
        }
    }

    impl FollowConnection for SessionIdentityMismatchFollowConnection {
        fn host_identity(&self) -> Result<String, SatelleError> {
            Ok("host-original".to_string())
        }

        fn session(
            &self,
            _session_id: &SessionId,
        ) -> Result<satelle_core::session::PublicSession, SatelleError> {
            Err(SatelleError::host_identity_mismatch("remote"))
        }

        fn logs(&self, _query: &LogPageQuery) -> Result<satelle_host::DaemonLogPage, SatelleError> {
            panic!("identity validation must fail before logs are requested")
        }
    }

    impl FollowConnection for SessionScopeMismatchFollowConnection {
        fn host_identity(&self) -> Result<String, SatelleError> {
            Ok("host-original".to_string())
        }

        fn session(
            &self,
            _session_id: &SessionId,
        ) -> Result<satelle_core::session::PublicSession, SatelleError> {
            Ok(self.returned_session.clone())
        }

        fn logs(&self, _query: &LogPageQuery) -> Result<satelle_host::DaemonLogPage, SatelleError> {
            panic!("Session scope validation must fail before logs are requested")
        }
    }

    fn public_session(session_id: &SessionId) -> satelle_core::session::PublicSession {
        let turn_id = satelle_core::TurnId::new();
        serde_json::from_value(serde_json::json!({
            "session_id": session_id,
            "display_name": null,
            "session_state_revision": 1,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "activity": {
                "state": "starting",
                "turn_id": turn_id,
                "turn_state_revision": 1
            },
            "turns": [{
                "session_id": session_id,
                "turn_id": turn_id,
                "turn_state_revision": 1,
                "state": "starting",
                "started_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "terminal_at": null,
                "safe_summary": null
            }]
        }))
        .expect("construct a coherent public Session fixture")
    }

    fn queued_connection_factory(
        connections: impl IntoIterator<Item = Box<dyn FollowConnection>>,
    ) -> FollowConnectionFactory {
        let connections = Mutex::new(connections.into_iter().collect::<VecDeque<_>>());
        Arc::new(move || {
            connections
                .lock()
                .expect("follow connection fixture lock")
                .pop_front()
                .ok_or_else(|| SatelleError::host_unreachable("remote"))
        })
    }

    struct FakeFollowRuntime {
        started_at: Instant,
        elapsed: Cell<StdDuration>,
        sleeps: Cell<usize>,
        interrupt_after_sleeps: Option<usize>,
        jitter_override: Option<StdDuration>,
        reconnect_budget: StdDuration,
        external_interrupt: Option<Arc<AtomicBool>>,
    }

    impl FakeFollowRuntime {
        fn new(interrupt_after_sleeps: Option<usize>) -> Self {
            Self {
                started_at: Instant::now(),
                elapsed: Cell::new(StdDuration::ZERO),
                sleeps: Cell::new(0),
                interrupt_after_sleeps,
                jitter_override: None,
                reconnect_budget: RECONNECT_BUDGET,
                external_interrupt: None,
            }
        }

        fn with_jitter_override(mut self, jitter: StdDuration) -> Self {
            self.jitter_override = Some(jitter);
            self
        }

        fn with_reconnect_budget(mut self, budget: StdDuration) -> Self {
            self.reconnect_budget = budget;
            self
        }

        fn with_interrupt_flag(mut self, interrupted: Arc<AtomicBool>) -> Self {
            self.external_interrupt = Some(interrupted);
            self
        }
    }

    impl FollowRuntime for FakeFollowRuntime {
        fn now(&self) -> Instant {
            self.started_at + self.elapsed.get()
        }

        fn interrupted(&self) -> bool {
            self.external_interrupt
                .as_ref()
                .is_some_and(|interrupted| interrupted.load(Ordering::Acquire))
                || self
                    .interrupt_after_sleeps
                    .is_some_and(|limit| self.sleeps.get() >= limit)
        }

        fn sleep(&self, duration: StdDuration) {
            self.elapsed.set(self.elapsed.get() + duration);
            self.sleeps.set(self.sleeps.get() + 1);
        }

        fn jitter(&self, duration: StdDuration) -> StdDuration {
            self.jitter_override.unwrap_or(duration)
        }

        fn reconnect_budget(&self) -> StdDuration {
            self.reconnect_budget
        }
    }

    fn request() -> LogReadRequest {
        LogReadRequest {
            host: Some("remote".to_string()),
            session: None,
            tail: Some(1),
            since: None,
            after: None,
            source: Vec::new(),
            level: None,
            follow: true,
            no_reconnect: false,
            format: OutputFormat::Human,
        }
    }

    #[test]
    fn follow_rerun_command_quotes_host_aliases() {
        assert_eq!(
            request().follow_rerun_command(
                "host alias; echo owned",
                serde_json::from_value(serde_json::json!("slc1_0000000000000001"))
                    .expect("valid opaque Log Cursor"),
            ),
            "satelle logs --host 'host alias; echo owned' --after slc1_0000000000000001 --follow"
        );
    }

    #[test]
    fn follow_rerun_command_preserves_json_output() {
        let mut request = request();
        request.format = OutputFormat::Json;

        assert_eq!(
            request.follow_rerun_command(
                "remote",
                serde_json::from_value(serde_json::json!("slc1_0000000000000001"))
                    .expect("valid opaque Log Cursor"),
            ),
            "satelle logs --host remote --after slc1_0000000000000001 --follow --json"
        );
    }

    fn page(cursor: u64) -> satelle_host::DaemonLogPage {
        serde_json::from_value(serde_json::json!({
            "entries": [{
                "schema_version": "satelle.logs.entry.v1",
                "cursor": format!("slc1_{cursor:016x}"),
                "timestamp": "2026-08-02T00:00:00Z",
                "host_identity": "host-original",
                "source": "storage",
                "severity": "info",
                "event": "store_opened",
                "subject": {"kind": "host"},
                "message": "opened Host state store",
                "redacted": true
            }],
            "next_cursor": format!("slc1_{cursor:016x}"),
            "truncated": false
        }))
        .expect("valid normalized Log page fixture")
    }

    #[test]
    fn reconnect_resumes_the_same_ndjson_stream_from_the_stored_cursor() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory = queued_connection_factory([
            Box::new(FakeFollowConnection::new(
                "host-original",
                [Ok(page(1)), Err(SatelleError::host_unreachable("remote"))],
            )) as Box<dyn FollowConnection>,
            Box::new(FakeFollowConnection::new("host-original", [Ok(page(2))]))
                as Box<dyn FollowConnection>,
        ]);
        let runtime = FakeFollowRuntime::new(Some(2));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
        )
        .expect_err("the fixture interrupts after the resumed page");

        assert_eq!(error.code, ErrorCode::Interrupted);
        let records = String::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["cursor"], "slc1_0000000000000001");
        assert_eq!(records[1]["cursor"], "slc1_0000000000000002");
        let notices = String::from_utf8(stderr).unwrap();
        assert!(notices.contains("reconnecting after interruption 1/10"));
        assert!(notices.contains("resuming after cursor=slc1_0000000000000001"));
    }

    #[test]
    fn interrupt_during_initial_read_wins_over_the_transport_failure() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let interrupted = Arc::new(AtomicBool::new(false));
        let connection = FakeFollowConnection::new(
            "host-original",
            [Err(SatelleError::host_unreachable("remote"))],
        )
        .with_interrupt_on_log(1, Arc::clone(&interrupted), StdDuration::from_secs(2));
        let factory =
            queued_connection_factory([Box::new(connection) as Box<dyn FollowConnection>]);
        let runtime = FakeFollowRuntime::new(None).with_interrupt_flag(interrupted);

        let started_at = Instant::now();
        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Human,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("Ctrl-C must take precedence over the interrupted initial read");

        assert_eq!(error.code, ErrorCode::Interrupted);
        assert!(
            started_at.elapsed() < StdDuration::from_millis(500),
            "Ctrl-C waited for the stalled initial read"
        );
    }

    #[test]
    fn interrupt_during_poll_read_wins_over_the_transport_failure() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let interrupted = Arc::new(AtomicBool::new(false));
        let connection = FakeFollowConnection::new(
            "host-original",
            [Ok(page(1)), Err(SatelleError::host_unreachable("remote"))],
        )
        .with_interrupt_on_log(2, Arc::clone(&interrupted), StdDuration::from_secs(2));
        let factory =
            queued_connection_factory([Box::new(connection) as Box<dyn FollowConnection>]);
        let runtime = FakeFollowRuntime::new(None).with_interrupt_flag(interrupted);

        let started_at = Instant::now();
        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Human,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("Ctrl-C must take precedence over the interrupted poll read");

        assert_eq!(error.code, ErrorCode::Interrupted);
        assert!(
            started_at.elapsed() < StdDuration::from_millis(500),
            "Ctrl-C waited for the stalled poll read"
        );
    }

    #[test]
    fn reconnect_rejects_a_changed_host_identity_before_resuming() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory = queued_connection_factory([
            Box::new(FakeFollowConnection::new(
                "host-original",
                [Ok(page(1)), Err(SatelleError::host_unreachable("remote"))],
            )) as Box<dyn FollowConnection>,
            Box::new(FakeFollowConnection::new(
                "host-replacement",
                std::iter::empty::<Result<satelle_host::DaemonLogPage, SatelleError>>(),
            )) as Box<dyn FollowConnection>,
        ]);
        let runtime = FakeFollowRuntime::new(None);

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("identity drift is terminal");
        assert_eq!(error.code, ErrorCode::LogsFollowIdentityChanged);
        assert_eq!(error.details["expected_host_identity"], "host-original");
        assert_eq!(error.details["observed_host_identity"], "host-replacement");
    }

    #[test]
    fn reconnect_maps_factory_identity_failures_to_the_follow_error() {
        let session_id = SessionId::new();
        let factory: FollowConnectionFactory =
            Arc::new(|| Err(SatelleError::host_identity_mismatch("remote")));

        let error = match run_reconnect_attempt(
            factory,
            "host-original".to_string(),
            Some(session_id.clone()),
            LogPageQuery::default(),
            StdDuration::from_secs(1),
            &FakeFollowRuntime::new(None),
        ) {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("the factory identity mismatch must be terminal"),
            None => panic!("the reconnect attempt should finish"),
        };

        assert_eq!(error.code, ErrorCode::LogsFollowIdentityChanged);
        assert_eq!(error.details["expected_host_identity"], "host-original");
        assert_eq!(
            error.details["observed_host_identity"],
            serde_json::Value::Null
        );
        assert_eq!(error.details["session_id"], session_id.as_str());
    }

    #[test]
    fn reconnect_maps_session_validation_identity_failures_to_the_follow_error() {
        let session_id = SessionId::new();
        let factory: FollowConnectionFactory = Arc::new(|| {
            Ok(Box::new(SessionIdentityMismatchFollowConnection) as Box<dyn FollowConnection>)
        });

        let error = match run_reconnect_attempt(
            factory,
            "host-original".to_string(),
            Some(session_id.clone()),
            LogPageQuery::default(),
            StdDuration::from_secs(1),
            &FakeFollowRuntime::new(None),
        ) {
            Some(Err(error)) => error,
            Some(Ok(_)) => panic!("the Session identity mismatch must be terminal"),
            None => panic!("the reconnect attempt should finish"),
        };

        assert_eq!(error.code, ErrorCode::LogsFollowIdentityChanged);
        assert_eq!(error.details["expected_host_identity"], "host-original");
        assert_eq!(
            error.details["observed_host_identity"],
            serde_json::Value::Null
        );
        assert_eq!(error.details["session_id"], session_id.as_str());
    }

    #[test]
    fn reconnect_rejects_a_session_response_for_another_session() {
        let expected_session_id = SessionId::new();
        let returned_session_id = SessionId::new();
        let connection = SessionScopeMismatchFollowConnection {
            returned_session: public_session(&returned_session_id),
        };

        let error = validate_follow_connection(
            &connection,
            Some("host-original"),
            Some(&expected_session_id),
            true,
        )
        .expect_err("a contradictory nested Session ID must stop reconnect");

        assert_eq!(error.code, ErrorCode::LogsFollowIdentityChanged);
        assert_eq!(error.details["expected_host_identity"], "host-original");
        assert_eq!(error.details["observed_host_identity"], "host-original");
        assert_eq!(error.details["session_id"], expected_session_id.as_str());
    }

    #[test]
    fn interrupt_while_reconnect_attempt_is_pending_returns_promptly() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let interrupted = Arc::new(AtomicBool::new(false));
        let factory_interrupt = Arc::clone(&interrupted);
        let factory: FollowConnectionFactory = Arc::new(move || {
            factory_interrupt.store(true, Ordering::Release);
            thread::sleep(StdDuration::from_secs(2));
            Err(SatelleError::host_unreachable("remote"))
        });
        let runtime = FakeFollowRuntime::new(None).with_interrupt_flag(interrupted);
        let target = FollowTarget {
            plan: &plan,
            request: &request,
            host_alias: "remote",
            expected_host_identity: "host-original",
        };
        let cursor = page(1).next_cursor();
        let started_at = Instant::now();

        let error = match reconnect_follow(
            &target,
            &runtime,
            &factory,
            cursor,
            cursor,
            1,
            &mut Vec::new(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("Ctrl-C must stop a pending reconnect attempt"),
        };

        assert_eq!(error.code, ErrorCode::Interrupted);
        assert!(
            started_at.elapsed() < StdDuration::from_millis(500),
            "Ctrl-C waited for the pending transport attempt"
        );
    }

    #[test]
    fn daemon_api_failures_remain_terminal_during_follow() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let observed_factory_calls = Arc::clone(&factory_calls);
        let factory: FollowConnectionFactory = Arc::new(move || {
            observed_factory_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(FakeFollowConnection::new(
                "host-original",
                [
                    Ok(page(1)),
                    Err(SatelleError::remote_api_error(
                        "remote",
                        "storage-integrity-failed",
                    )),
                ],
            )) as Box<dyn FollowConnection>)
        });
        let runtime = FakeFollowRuntime::new(None);

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("a daemon API rejection is terminal");

        assert_eq!(error.code, ErrorCode::RemoteExecution);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.sleeps.get(), 0, "a terminal API error cannot retry");
    }

    #[test]
    fn reconnect_budget_is_finite_and_reports_the_resume_command() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let reconnect_factory_calls = Arc::clone(&factory_calls);
        let factory: FollowConnectionFactory = Arc::new(move || {
            let call = reconnect_factory_calls.fetch_add(1, Ordering::Relaxed);
            let pages = if call == 0 {
                vec![Ok(page(1)), Err(SatelleError::host_unreachable("remote"))]
            } else {
                vec![Err(SatelleError::host_unreachable("remote"))]
            };
            Ok(Box::new(FakeFollowConnection::new("host-original", pages))
                as Box<dyn FollowConnection>)
        });
        let runtime = FakeFollowRuntime::new(None);

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("the per-interruption reconnect budget is finite");
        assert_eq!(error.code, ErrorCode::LogsFollowReconnectExhausted);
        assert_eq!(
            error.details["last_delivered_cursor"],
            "slc1_0000000000000001"
        );
        assert_eq!(
            error.recovery_command.as_deref(),
            Some("satelle logs --host remote --after slc1_0000000000000001 --follow")
        );
        assert!(runtime.elapsed.get() >= RECONNECT_BUDGET);
    }

    #[test]
    fn reconnect_deadline_reached_by_sleep_does_not_start_an_attempt() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let reconnect_factory_calls = Arc::clone(&factory_calls);
        let factory: FollowConnectionFactory = Arc::new(move || {
            let call = reconnect_factory_calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(
                call, 0,
                "an expired reconnect budget started another attempt"
            );
            Ok(Box::new(FakeFollowConnection::new(
                "host-original",
                [Ok(page(1)), Err(SatelleError::host_unreachable("remote"))],
            )) as Box<dyn FollowConnection>)
        });
        let runtime = FakeFollowRuntime::new(None).with_jitter_override(RECONNECT_BUDGET);

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("the attempt at the exact reconnect deadline is rejected");

        assert_eq!(error.code, ErrorCode::LogsFollowReconnectExhausted);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.elapsed.get(), RECONNECT_BUDGET);
    }

    #[test]
    fn reconnect_attempt_is_bounded_by_the_remaining_budget() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let runtime = FakeFollowRuntime::new(None)
            .with_jitter_override(StdDuration::from_millis(1))
            .with_reconnect_budget(StdDuration::from_millis(100));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let reconnect_factory_calls = Arc::clone(&factory_calls);
        let factory: FollowConnectionFactory = Arc::new(move || {
            let call = reconnect_factory_calls.fetch_add(1, Ordering::Relaxed);
            if call == 0 {
                return Ok(Box::new(FakeFollowConnection::new(
                    "host-original",
                    [Ok(page(1)), Err(SatelleError::host_unreachable("remote"))],
                )) as Box<dyn FollowConnection>);
            }
            thread::sleep(StdDuration::from_millis(200));
            Ok(
                Box::new(FakeFollowConnection::new("host-original", [Ok(page(2))]))
                    as Box<dyn FollowConnection>,
            )
        });

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("a stalled attempt reaches the reconnect deadline");

        assert_eq!(error.code, ErrorCode::LogsFollowReconnectExhausted);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn no_reconnect_returns_the_transport_failure_with_the_last_cursor() {
        let mut request = request();
        request.no_reconnect = true;
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory = queued_connection_factory([Box::new(FakeFollowConnection::new(
            "host-original",
            [Ok(page(1)), Err(SatelleError::host_unreachable("remote"))],
        )) as Box<dyn FollowConnection>]);
        let runtime = FakeFollowRuntime::new(None);
        let mut stderr = Vec::new();

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut stderr,
            },
        )
        .expect_err("--no-reconnect returns the first transport loss");
        assert_eq!(error.code, ErrorCode::HostUnreachable);
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("last cursor=slc1_0000000000000001")
        );
    }

    #[test]
    fn the_tenth_stream_interruption_is_terminal() {
        let request = request();
        let plan =
            LogReadPlan::resolve(&request).unwrap_or_else(|_| panic!("resolve follow request"));
        let factory_calls = Arc::new(AtomicU64::new(0));
        let reconnect_factory_calls = Arc::clone(&factory_calls);
        let factory: FollowConnectionFactory = Arc::new(move || {
            let call = reconnect_factory_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(FakeFollowConnection::new(
                "host-original",
                [
                    Ok(page(call + 1)),
                    Err(SatelleError::host_unreachable("remote")),
                ],
            )) as Box<dyn FollowConnection>)
        });
        let runtime = FakeFollowRuntime::new(None);

        let error = follow_logs(
            &plan,
            &request,
            "remote",
            OutputFormat::Json,
            &runtime,
            &factory,
            FollowOutput {
                stdout: &mut Vec::new(),
                stderr: &mut Vec::new(),
            },
        )
        .expect_err("the interruption cap is finite");
        assert_eq!(error.code, ErrorCode::LogsFollowReconnectExhausted);
        assert_eq!(error.details["stream_interruptions"], 10);
        assert_eq!(factory_calls.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn reconnect_jitter_stays_within_the_bounded_twenty_percent_window() {
        let delay = StdDuration::from_secs(1);
        assert_eq!(jittered_delay(delay, 0), StdDuration::from_millis(800));
        assert_eq!(
            jittered_delay(delay, 4_000),
            StdDuration::from_millis(1_200)
        );
        assert!(jittered_delay(RECONNECT_MAX_DELAY, 4_000) <= RECONNECT_MAX_DELAY);
    }
}
