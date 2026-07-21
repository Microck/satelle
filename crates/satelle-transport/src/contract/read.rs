use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_core::{ApiRateLimits, DesktopSessionRecord};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

define_schema_token!(LiveSchema, "satelle.live.v1");
define_schema_token!(CapabilitiesSchema, "satelle.capabilities.v2");
define_schema_token!(HostStatusSchema, "satelle.host.status.v1");
define_schema_token!(
    HostDesktopSessionsSchema,
    "satelle.host.desktop-sessions.v1"
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveResponse {
    schema_version: LiveSchema,
    alive: bool,
}

impl LiveResponse {
    pub(crate) const fn new() -> Self {
        Self {
            schema_version: LiveSchema,
            alive: true,
        }
    }

    pub const fn alive(&self) -> bool {
        self.alive
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Live,
    Capabilities,
    HostStatus,
    HostDesktopSessions,
    SessionCreate,
    TurnCreate,
    SessionRead,
    SessionStop,
    LogsRead,
    EventsRead,
    SetupApiTokenCurrent,
    SetupApiTokenIssue,
    SetupApiTokenActivate,
    SetupApiTokenAbort,
}

impl Operation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Capabilities => "capabilities",
            Self::HostStatus => "host_status",
            Self::HostDesktopSessions => "host_desktop_sessions",
            Self::SessionCreate => "session_create",
            Self::TurnCreate => "turn_create",
            Self::SessionRead => "session_read",
            Self::SessionStop => "session_stop",
            Self::LogsRead => "logs_read",
            Self::EventsRead => "events_read",
            Self::SetupApiTokenCurrent => "setup_api_token_current",
            Self::SetupApiTokenIssue => "setup_api_token_issue",
            Self::SetupApiTokenActivate => "setup_api_token_activate",
            Self::SetupApiTokenAbort => "setup_api_token_abort",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PlatformOs {
    Linux,
    Macos,
    Windows,
    Other,
}

impl PlatformOs {
    const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Platform {
    os: PlatformOs,
    arch: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCapabilities {
    codex_runtime: bool,
    native_computer_use: bool,
    provider_computer_use: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveLimits {
    json_body_bytes: usize,
    http_connections: usize,
    operation_concurrency: usize,
    attachment_count: usize,
    attachment_bytes_each: usize,
    attachment_bytes_total: usize,
    failed_auth_attempts_per_minute: usize,
    authenticated_requests_per_minute: usize,
    control_requests_per_minute: usize,
    websocket_connections_per_principal: usize,
    websocket_message_bytes: usize,
    websocket_subscriptions_per_connection: usize,
    websocket_inbound_messages_per_minute: usize,
    websocket_outbound_queue_messages: usize,
    websocket_ping_interval_ms: u64,
    websocket_idle_timeout_ms: u64,
}

impl EffectiveLimits {
    pub const fn json_body_bytes(self) -> usize {
        self.json_body_bytes
    }

    pub const fn attachment_count(self) -> usize {
        self.attachment_count
    }

    pub const fn attachment_bytes_each(self) -> usize {
        self.attachment_bytes_each
    }

    pub const fn attachment_bytes_total(self) -> usize {
        self.attachment_bytes_total
    }

    pub const fn failed_auth_attempts_per_minute(self) -> usize {
        self.failed_auth_attempts_per_minute
    }

    pub const fn authenticated_requests_per_minute(self) -> usize {
        self.authenticated_requests_per_minute
    }

    pub const fn control_requests_per_minute(self) -> usize {
        self.control_requests_per_minute
    }

    pub const fn operation_concurrency(self) -> usize {
        self.operation_concurrency
    }

    pub const fn websocket_connections_per_principal(self) -> usize {
        self.websocket_connections_per_principal
    }

    pub const fn websocket_message_bytes(self) -> usize {
        self.websocket_message_bytes
    }

    pub const fn websocket_subscriptions_per_connection(self) -> usize {
        self.websocket_subscriptions_per_connection
    }

    pub const fn websocket_inbound_messages_per_minute(self) -> usize {
        self.websocket_inbound_messages_per_minute
    }

    pub const fn websocket_outbound_queue_messages(self) -> usize {
        self.websocket_outbound_queue_messages
    }

    pub const fn websocket_ping_interval_ms(self) -> u64 {
        self.websocket_ping_interval_ms
    }

    pub const fn websocket_idle_timeout_ms(self) -> u64 {
        self.websocket_idle_timeout_ms
    }

    pub const fn http_connections(self) -> usize {
        self.http_connections
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesResponse {
    schema_version: CapabilitiesSchema,
    request_id: RequestId,
    host_identity: String,
    daemon_version: String,
    platform: Platform,
    operations: Vec<Operation>,
    runtime_capabilities: RuntimeCapabilities,
    limits: EffectiveLimits,
}

impl CapabilitiesResponse {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        daemon_version: String,
        codex_runtime: bool,
        native_computer_use: bool,
        provider_computer_use: bool,
        limits: EffectiveLimits,
    ) -> Self {
        Self {
            schema_version: CapabilitiesSchema,
            request_id,
            host_identity,
            daemon_version,
            platform: Platform {
                os: PlatformOs::current(),
                arch: std::env::consts::ARCH.to_string(),
            },
            operations: vec![
                Operation::Live,
                Operation::Capabilities,
                Operation::HostStatus,
                Operation::HostDesktopSessions,
                Operation::SessionCreate,
                Operation::TurnCreate,
                Operation::SessionRead,
                Operation::SessionStop,
                Operation::LogsRead,
                Operation::EventsRead,
                Operation::SetupApiTokenCurrent,
                Operation::SetupApiTokenIssue,
                Operation::SetupApiTokenActivate,
                Operation::SetupApiTokenAbort,
            ],
            runtime_capabilities: RuntimeCapabilities {
                codex_runtime,
                native_computer_use,
                provider_computer_use,
            },
            limits,
        }
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn operations(&self) -> Vec<&'static str> {
        self.operations
            .iter()
            .map(|operation| operation.as_str())
            .collect()
    }

    pub const fn limits(&self) -> EffectiveLimits {
        self.limits
    }
}

impl AuthenticatedResponseContract for CapabilitiesResponse {
    fn request_id(&self) -> &RequestId {
        self.request_id()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProcessMode {
    Foreground,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostStatusResponse {
    schema_version: HostStatusSchema,
    request_id: RequestId,
    host_identity: String,
    daemon_version: String,
    #[serde(with = "time::serde::rfc3339")]
    started_at: OffsetDateTime,
    process_mode: ProcessMode,
    session_count: usize,
    active_turn_count: usize,
    recovery_pending_turn_count: usize,
}

impl HostStatusResponse {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        daemon_version: String,
        started_at: OffsetDateTime,
        session_count: usize,
        active_turn_count: usize,
        recovery_pending_turn_count: usize,
    ) -> Self {
        Self {
            schema_version: HostStatusSchema,
            request_id,
            host_identity,
            daemon_version,
            started_at,
            process_mode: ProcessMode::Foreground,
            session_count,
            active_turn_count,
            recovery_pending_turn_count,
        }
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub const fn session_count(&self) -> usize {
        self.session_count
    }
}

impl AuthenticatedResponseContract for HostStatusResponse {
    fn request_id(&self) -> &RequestId {
        self.request_id()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostDesktopSessionsResponse {
    schema_version: HostDesktopSessionsSchema,
    request_id: RequestId,
    host_identity: String,
    sessions: Vec<DesktopSessionRecord>,
}

impl HostDesktopSessionsResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        sessions: Vec<DesktopSessionRecord>,
    ) -> Self {
        Self {
            schema_version: HostDesktopSessionsSchema,
            request_id,
            host_identity,
            sessions,
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub fn sessions(&self) -> &[DesktopSessionRecord] {
        &self.sessions
    }
}

impl AuthenticatedResponseContract for HostDesktopSessionsResponse {
    fn request_id(&self) -> &RequestId {
        self.request_id()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }
}

pub(crate) fn effective_limits(
    http_connections: usize,
    api_rate_limits: ApiRateLimits,
) -> EffectiveLimits {
    EffectiveLimits {
        json_body_bytes: 1_048_576,
        http_connections,
        operation_concurrency: 1,
        attachment_count: 0,
        attachment_bytes_each: 0,
        attachment_bytes_total: 0,
        failed_auth_attempts_per_minute: api_rate_limits.failed_auth_attempts_per_minute(),
        authenticated_requests_per_minute: api_rate_limits.authenticated_requests_per_minute(),
        control_requests_per_minute: api_rate_limits.control_requests_per_minute(),
        websocket_connections_per_principal: 4,
        websocket_message_bytes: 65_536,
        websocket_subscriptions_per_connection: 16,
        websocket_inbound_messages_per_minute: api_rate_limits
            .websocket_inbound_messages_per_minute(),
        websocket_outbound_queue_messages: 256,
        websocket_ping_interval_ms: 15_000,
        websocket_idle_timeout_ms: 45_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_schema_tokens_reject_drift_and_unknown_fields() {
        assert!(
            serde_json::from_str::<LiveResponse>(
                r#"{"schema_version":"satelle.live.v2","alive":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<LiveResponse>(
                r#"{"schema_version":"satelle.live.v1","alive":true,"extra":1}"#
            )
            .is_err()
        );
    }
}
