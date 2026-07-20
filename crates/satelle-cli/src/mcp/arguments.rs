use super::super::logs::LogReadRequest;
use rmcp::ErrorData as McpError;
use rmcp::model::JsonObject;
use satelle_core::SessionId;
use satelle_host::LogCursor;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::str::FromStr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigCheckInput {
    pub(super) host: Option<String>,
    #[serde(default)]
    pub(super) all: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigExplainInput {
    pub(super) host: Option<String>,
    #[serde(default)]
    pub(super) show_secret_references: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostInput {
    pub(super) host: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StatusInput {
    pub(super) session_id: String,
    pub(super) host: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogsInput {
    host: Option<String>,
    session: Option<String>,
    tail: Option<usize>,
    since: Option<String>,
    after: Option<String>,
    #[serde(default)]
    source: Vec<String>,
    level: Option<String>,
}

impl LogsInput {
    pub(super) fn validate(&self) -> Result<(), McpError> {
        validate_host(self.host.as_deref())?;
        if let Some(session) = &self.session {
            SessionId::from_str(session).map_err(|error| invalid_params(error.to_string()))?;
        }
        if let Some(tail) = self.tail
            && !(1..=10_000).contains(&tail)
        {
            return Err(invalid_params("tail must be from 1 through 10000"));
        }
        if self.after.is_some() && (self.since.is_some() || self.tail.is_some()) {
            return Err(invalid_params(
                "after cannot be combined with since or tail",
            ));
        }
        if let Some(after) = &self.after {
            LogCursor::parse(after).map_err(|error| invalid_params(error.to_string()))?;
        }
        if let Some(since) = &self.since {
            validate_since(since)?;
        }
        if self
            .source
            .iter()
            .any(|source| !matches!(source.as_str(), "host_daemon" | "storage" | "codex_adapter"))
        {
            return Err(invalid_params(
                "source items must be host_daemon, storage, or codex_adapter",
            ));
        }
        if self
            .level
            .as_deref()
            .is_some_and(|level| !matches!(level, "info" | "warn" | "error"))
        {
            return Err(invalid_params("level must be info, warn, or error"));
        }
        Ok(())
    }

    pub(super) fn into_request(self) -> LogReadRequest {
        LogReadRequest {
            host: self.host,
            session: self.session,
            tail: self.tail,
            since: self.since,
            after: self.after,
            source: self.source,
            level: self.level,
            // MCP tools return finite result objects. Streaming follow remains a CLI record-stream
            // contract because stdio JSON-RPC needs one bounded response per request.
            follow: false,
            no_reconnect: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DoctorInput {
    pub(super) host: Option<String>,
    pub(super) scope: Option<String>,
}

pub(super) fn decode<T: DeserializeOwned>(arguments: JsonObject) -> Result<T, McpError> {
    serde_json::from_value(Value::Object(arguments))
        .map_err(|error| invalid_params(format!("invalid tool arguments: {error}")))
}

pub(super) fn validate_host(host: Option<&str>) -> Result<(), McpError> {
    if host.is_some_and(str::is_empty) {
        return Err(invalid_params("host must be non-empty"));
    }
    Ok(())
}

pub(super) fn validate_doctor_scope(scope: Option<&str>) -> Result<(), McpError> {
    if scope.is_some_and(|scope| {
        !matches!(
            scope,
            "transport" | "codex" | "computer-use" | "provider" | "config" | "all"
        )
    }) {
        return Err(invalid_params("unsupported doctor scope"));
    }
    Ok(())
}

fn validate_since(value: &str) -> Result<(), McpError> {
    if OffsetDateTime::parse(value, &Rfc3339).is_ok() {
        return Ok(());
    }
    let digits = if let Some(digits) = value.strip_suffix("ms") {
        digits
    } else if let Some(digits) = value.strip_suffix('s') {
        digits
    } else if let Some(digits) = value.strip_suffix('m') {
        digits
    } else {
        return Err(invalid_params("since must be RFC 3339 or use ms, s, or m"));
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_params(
            "relative since values require ASCII decimal digits and a unit",
        ));
    }
    digits
        .parse::<u64>()
        .map_err(|_| invalid_params("relative since value exceeds u64"))?;
    Ok(())
}

pub(super) fn invalid_params(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}
