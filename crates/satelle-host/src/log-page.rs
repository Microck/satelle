use satelle_core::session::{SessionStateRevision, TurnStateRevision};
use satelle_core::{SessionId, TurnId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use std::fmt;
use time::OffsetDateTime;

const LOG_CURSOR_PREFIX: &str = "slc1_";
const LOG_CURSOR_HEX_BYTES: usize = 16;
const DEFAULT_LOG_PAGE_LIMIT: usize = 200;
const MAX_LOG_PAGE_LIMIT: usize = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogCursor(u64);

impl LogCursor {
    pub fn parse(value: &str) -> Result<Self, LogCursorError> {
        let encoded = value
            .strip_prefix(LOG_CURSOR_PREFIX)
            .ok_or(LogCursorError)?;
        if encoded.len() != LOG_CURSOR_HEX_BYTES
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(LogCursorError);
        }
        let position = u64::from_str_radix(encoded, 16).map_err(|_| LogCursorError)?;
        if position > i64::MAX as u64 {
            return Err(LogCursorError);
        }
        Ok(Self(position))
    }

    pub(crate) const fn from_position(position: u64) -> Self {
        Self(position)
    }

    pub(crate) const fn position(self) -> u64 {
        self.0
    }
}

impl fmt::Display for LogCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{LOG_CURSOR_PREFIX}{:016x}", self.0)
    }
}

impl Serialize for LogCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LogCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogCursorError;

impl fmt::Display for LogCursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the Log Cursor is not a supported opaque cursor")
    }
}

impl std::error::Error for LogCursorError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    HostDaemon,
    Storage,
    CodexAdapter,
}

impl LogSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostDaemon => "host_daemon",
            Self::Storage => "storage",
            Self::CodexAdapter => "codex_adapter",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "host_daemon" => Some(Self::HostDaemon),
            "storage" => Some(Self::Storage),
            "codex_adapter" => Some(Self::CodexAdapter),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSeverity {
    Info,
    #[serde(rename = "warn")]
    Warning,
    Error,
}

impl LogSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warn",
            Self::Error => "error",
        }
    }

    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Warning => 1,
            Self::Error => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEvent {
    SessionStarted,
    FollowUpStarted,
    TurnStateCommitted,
    StopConfirmed,
    StopNotConfirmed,
    RestartRecoveryPending,
    StoreOpened,
}

impl LogEvent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStarted => "session_started",
            Self::FollowUpStarted => "follow_up_started",
            Self::TurnStateCommitted => "turn_state_committed",
            Self::StopConfirmed => "stop_confirmed",
            Self::StopNotConfirmed => "stop_not_confirmed",
            Self::RestartRecoveryPending => "restart_recovery_pending",
            Self::StoreOpened => "store_opened",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::SessionStarted => "created Session",
            Self::FollowUpStarted => "admitted follow-up Turn",
            Self::TurnStateCommitted => "committed Turn state",
            Self::StopConfirmed => "confirmed stop request",
            Self::StopNotConfirmed => "stop request requires recovery",
            Self::RestartRecoveryPending => "Turn requires restart recovery",
            Self::StoreOpened => "opened Host state store",
        }
    }

    pub(crate) const fn has_turn_subject(self) -> bool {
        !matches!(self, Self::StoreOpened)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LogSubject {
    Host,
    Turn {
        session_id: SessionId,
        turn_id: TurnId,
        session_state_revision: SessionStateRevision,
        turn_state_revision: TurnStateRevision,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LogEntrySchema;

impl Serialize for LogEntrySchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("satelle.logs.entry.v1")
    }
}

impl<'de> Deserialize<'de> for LogEntrySchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == "satelle.logs.entry.v1" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected schema_version satelle.logs.entry.v1",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Redacted;

impl Serialize for Redacted {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for Redacted {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "Satelle Log Entries must be redacted",
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonLogEntry {
    cursor: LogCursor,
    timestamp: OffsetDateTime,
    source: LogSource,
    severity: LogSeverity,
    event: LogEvent,
    subject: LogSubject,
}

impl DaemonLogEntry {
    pub(crate) fn from_parts(
        cursor: u64,
        timestamp: OffsetDateTime,
        source: LogSource,
        severity: LogSeverity,
        event: LogEvent,
        subject: LogSubject,
    ) -> Result<Self, &'static str> {
        let entry = Self {
            cursor: LogCursor::from_position(cursor),
            timestamp,
            source,
            severity,
            event,
            subject,
        };
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.cursor.position() == 0 {
            return Err("a Log Entry cannot use the retained-history origin cursor");
        }
        if self.event.has_turn_subject() != matches!(self.subject, LogSubject::Turn { .. }) {
            return Err("the Log Entry event contradicts its subject");
        }
        Ok(())
    }

    pub const fn cursor(&self) -> LogCursor {
        self.cursor
    }

    pub const fn timestamp(&self) -> OffsetDateTime {
        self.timestamp
    }

    pub const fn source(&self) -> LogSource {
        self.source
    }

    pub const fn severity(&self) -> LogSeverity {
        self.severity
    }

    pub const fn event(&self) -> LogEvent {
        self.event
    }

    pub const fn subject(&self) -> &LogSubject {
        &self.subject
    }
}

#[derive(Serialize)]
struct DaemonLogEntryRef<'a> {
    schema_version: LogEntrySchema,
    cursor: LogCursor,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    source: LogSource,
    severity: LogSeverity,
    event: LogEvent,
    subject: &'a LogSubject,
    message: &'static str,
    redacted: Redacted,
}

impl Serialize for DaemonLogEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DaemonLogEntryRef {
            schema_version: LogEntrySchema,
            cursor: self.cursor,
            timestamp: self.timestamp,
            source: self.source,
            severity: self.severity,
            event: self.event,
            subject: &self.subject,
            message: self.event.message(),
            redacted: Redacted,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonLogEntryOwned {
    #[serde(rename = "schema_version")]
    _schema_version: LogEntrySchema,
    cursor: LogCursor,
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    source: LogSource,
    severity: LogSeverity,
    event: LogEvent,
    subject: LogSubject,
    message: String,
    #[serde(rename = "redacted")]
    _redacted: Redacted,
}

impl<'de> Deserialize<'de> for DaemonLogEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DaemonLogEntryOwned::deserialize(deserializer)?;
        if wire.message != wire.event.message() {
            return Err(serde::de::Error::custom(
                "the Log Entry message contradicts its event",
            ));
        }
        let entry = Self {
            cursor: wire.cursor,
            timestamp: wire.timestamp,
            source: wire.source,
            severity: wire.severity,
            event: wire.event,
            subject: wire.subject,
        };
        entry.validate().map_err(serde::de::Error::custom)?;
        Ok(entry)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogPageMode {
    #[default]
    Tail,
    Forward,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogSources(BTreeSet<LogSource>);

impl LogSources {
    fn parse(value: &str) -> Result<Self, &'static str> {
        if value.is_empty() {
            return Err("sources must not be empty");
        }
        let mut sources = BTreeSet::new();
        for token in value.split(',') {
            let source = LogSource::parse(token)
                .ok_or("sources must contain only host_daemon, storage, or codex_adapter")?;
            if !sources.insert(source) {
                return Err("sources must not contain duplicate tokens");
            }
        }
        Ok(Self(sources))
    }

    fn contains(&self, source: LogSource) -> bool {
        self.0.contains(&source)
    }
}

impl Serialize for LogSources {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            &self
                .0
                .iter()
                .map(|source| source.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

impl<'de> Deserialize<'de> for LogSources {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogPageQuery {
    mode: LogPageMode,
    cursor: Option<LogCursor>,
    limit: usize,
    session_id: Option<SessionId>,
    sources: Option<LogSources>,
    minimum_severity: LogSeverity,
    since: Option<OffsetDateTime>,
}

impl LogPageQuery {
    pub fn tail(limit: usize) -> Result<Self, LogPageQueryError> {
        Self::new(LogPageMode::Tail, None, limit)
    }

    pub fn forward(cursor: Option<LogCursor>, limit: usize) -> Result<Self, LogPageQueryError> {
        Self::new(LogPageMode::Forward, cursor, limit)
    }

    fn new(
        mode: LogPageMode,
        cursor: Option<LogCursor>,
        limit: usize,
    ) -> Result<Self, LogPageQueryError> {
        if !(1..=MAX_LOG_PAGE_LIMIT).contains(&limit)
            || (mode == LogPageMode::Tail && cursor.is_some())
        {
            return Err(LogPageQueryError);
        }
        Ok(Self {
            mode,
            cursor,
            limit,
            session_id: None,
            sources: None,
            minimum_severity: LogSeverity::Info,
            since: None,
        })
    }

    pub fn with_session(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_sources(mut self, sources: impl IntoIterator<Item = LogSource>) -> Self {
        let sources = sources.into_iter().collect::<BTreeSet<_>>();
        self.sources = (!sources.is_empty()).then_some(LogSources(sources));
        self
    }

    pub const fn with_minimum_severity(mut self, severity: LogSeverity) -> Self {
        self.minimum_severity = severity;
        self
    }

    pub const fn with_since(mut self, since: OffsetDateTime) -> Self {
        self.since = Some(since);
        self
    }

    pub const fn mode(&self) -> LogPageMode {
        self.mode
    }

    pub const fn cursor(&self) -> Option<LogCursor> {
        self.cursor
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub(crate) fn includes_source(&self, source: LogSource) -> bool {
        self.sources
            .as_ref()
            .is_none_or(|sources| sources.contains(source))
    }

    pub const fn minimum_severity(&self) -> LogSeverity {
        self.minimum_severity
    }

    pub const fn since(&self) -> Option<OffsetDateTime> {
        self.since
    }
}

impl Default for LogPageQuery {
    fn default() -> Self {
        Self::tail(DEFAULT_LOG_PAGE_LIMIT).expect("the default log page limit is valid")
    }
}

#[derive(Serialize)]
struct LogPageQueryRef<'a> {
    mode: LogPageMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<LogCursor>,
    limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sources: Option<&'a LogSources>,
    minimum_severity: LogSeverity,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    since: Option<OffsetDateTime>,
}

impl Serialize for LogPageQuery {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        LogPageQueryRef {
            mode: self.mode,
            cursor: self.cursor,
            limit: self.limit,
            session_id: self.session_id.as_ref(),
            sources: self.sources.as_ref(),
            minimum_severity: self.minimum_severity,
            since: self.since,
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LogPageQueryOwned {
    mode: LogPageMode,
    cursor: Option<LogCursor>,
    limit: usize,
    session_id: Option<SessionId>,
    sources: Option<LogSources>,
    minimum_severity: LogSeverity,
    #[serde(with = "time::serde::rfc3339::option")]
    since: Option<OffsetDateTime>,
}

impl Default for LogPageQueryOwned {
    fn default() -> Self {
        Self {
            mode: LogPageMode::Tail,
            cursor: None,
            limit: DEFAULT_LOG_PAGE_LIMIT,
            session_id: None,
            sources: None,
            minimum_severity: LogSeverity::Info,
            since: None,
        }
    }
}

impl<'de> Deserialize<'de> for LogPageQuery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LogPageQueryOwned::deserialize(deserializer)?;
        let mut query =
            Self::new(wire.mode, wire.cursor, wire.limit).map_err(serde::de::Error::custom)?;
        query.session_id = wire.session_id;
        query.sources = wire.sources;
        query.minimum_severity = wire.minimum_severity;
        query.since = wire.since;
        Ok(query)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogPageQueryError;

impl fmt::Display for LogPageQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "the log page limit must be between 1 and 10000 and tail mode cannot use a cursor",
        )
    }
}

impl std::error::Error for LogPageQueryError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DaemonLogPage {
    entries: Vec<DaemonLogEntry>,
    next_cursor: LogCursor,
    truncated: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DaemonLogPageOwned {
    entries: Vec<DaemonLogEntry>,
    next_cursor: LogCursor,
    truncated: bool,
}

impl<'de> Deserialize<'de> for DaemonLogPage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DaemonLogPageOwned::deserialize(deserializer)?;
        if !wire
            .entries
            .windows(2)
            .all(|pair| pair[0].cursor < pair[1].cursor)
            || wire
                .entries
                .last()
                .is_some_and(|entry| wire.next_cursor < entry.cursor)
        {
            return Err(serde::de::Error::custom(
                "the log page cursor order is inconsistent",
            ));
        }
        Ok(Self {
            entries: wire.entries,
            next_cursor: wire.next_cursor,
            truncated: wire.truncated,
        })
    }
}

impl DaemonLogPage {
    pub(crate) fn new(
        entries: Vec<DaemonLogEntry>,
        next_cursor: LogCursor,
        truncated: bool,
    ) -> Self {
        Self {
            entries,
            next_cursor,
            truncated,
        }
    }

    pub fn entries(&self) -> &[DaemonLogEntry] {
        &self.entries
    }

    pub const fn next_cursor(&self) -> LogCursor {
        self.next_cursor
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_and_query_wire_contracts_are_closed() {
        let cursor = LogCursor::from_position(42);
        assert_eq!(cursor.to_string(), "slc1_000000000000002a");
        assert_eq!(LogCursor::parse(&cursor.to_string()), Ok(cursor));
        assert!(LogCursor::parse("slc1_000000000000002A").is_err());
        assert!(LogCursor::parse("slc1_ffffffffffffffff").is_err());

        let query = LogPageQuery::forward(Some(cursor), 50)
            .unwrap()
            .with_sources([LogSource::Storage, LogSource::HostDaemon])
            .with_minimum_severity(LogSeverity::Warning);
        let encoded = serde_json::to_value(&query).unwrap();
        assert_eq!(encoded["mode"], "forward");
        assert_eq!(encoded["cursor"], cursor.to_string());
        assert_eq!(encoded["sources"], "host_daemon,storage");
        assert_eq!(encoded["minimum_severity"], "warn");

        let mut invalid = encoded;
        invalid["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LogPageQuery>(invalid).is_err());
    }

    #[test]
    fn log_entry_and_page_deserialization_reject_contradictions() {
        let entry = DaemonLogEntry::from_parts(
            2,
            OffsetDateTime::UNIX_EPOCH,
            LogSource::Storage,
            LogSeverity::Info,
            LogEvent::StoreOpened,
            LogSubject::Host,
        )
        .unwrap();
        let mut value = serde_json::to_value(&entry).unwrap();
        value["redacted"] = serde_json::json!(false);
        assert!(serde_json::from_value::<DaemonLogEntry>(value).is_err());

        let first = serde_json::to_value(&entry).unwrap();
        let mut older = first.clone();
        older["cursor"] = serde_json::json!("slc1_0000000000000001");
        let invalid_page = serde_json::json!({
            "entries": [first, older],
            "next_cursor": "slc1_0000000000000002",
            "truncated": false
        });
        assert!(serde_json::from_value::<DaemonLogPage>(invalid_page).is_err());
    }
}
