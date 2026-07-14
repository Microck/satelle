use super::output::{OutputArgs, OutputFormat};
use super::transport::{TransportClient, transport_for};
use super::{CliFailure, ConfigContext, failure, parse_duration_ms};
use clap::Args;
use satelle_core::{SatelleError, SessionId};
use satelle_host::{DaemonLogEntry, LogCursor, LogPageQuery, LogSeverity, LogSource};
use std::io::{self, Write};
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const DEFAULT_LOG_PAGE_LIMIT: usize = 200;
const MAX_LOG_PAGE_LIMIT: usize = 10_000;

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
    #[command(flatten)]
    pub(crate) output_args: OutputArgs,
}

pub(crate) struct LogReadRequest {
    pub(crate) host: Option<String>,
    pub(crate) session: Option<String>,
    pub(crate) tail: Option<usize>,
    pub(crate) since: Option<String>,
    pub(crate) after: Option<String>,
    pub(crate) source: Vec<String>,
    pub(crate) level: Option<String>,
}

impl From<LogsCommand> for LogReadRequest {
    fn from(command: LogsCommand) -> Self {
        Self {
            host: command.host,
            session: command.session,
            tail: command.tail,
            since: command.since,
            after: command.after,
            source: command.source,
            level: command.level,
        }
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
    let request = LogReadRequest::from(command);
    let plan = LogReadPlan::resolve(&request)?;
    let host = config.resolve_host(request.host.as_deref())?;
    let transport = transport_for(&host)?;
    plan.emit(transport.as_ref(), format).map_err(failure)
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
    for entry in entries
        .iter()
        .take_while(|entry| through.is_none_or(|cursor| entry.cursor() <= cursor))
    {
        if format.is_json() {
            serde_json::to_writer(&mut stdout, entry)
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
