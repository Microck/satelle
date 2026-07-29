use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_core::daemon_service::DaemonResolvedPathSet;
use satelle_core::{ApiRateLimits, DesktopSessionRecord};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

define_schema_token!(LiveSchema, "satelle.live.v1");
define_schema_token!(CapabilitiesSchema, "satelle.capabilities.v6");
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSecretUploadCapability {
    envelope_schema_version: String,
    algorithm: String,
    content_type: String,
    max_plaintext_bytes: usize,
}

impl ProviderSecretUploadCapability {
    pub fn envelope_schema_version(&self) -> &str {
        &self.envelope_schema_version
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    pub const fn max_plaintext_bytes(&self) -> usize {
        self.max_plaintext_bytes
    }

    fn current() -> Self {
        Self {
            envelope_schema_version: "satelle.provider-secret-upload.v2".to_string(),
            algorithm: "x25519-hkdf-sha256-chacha20poly1305".to_string(),
            content_type: super::setup::PROVIDER_SECRET_UPLOAD_CONTENT_TYPE.to_string(),
            max_plaintext_bytes: 64 * 1024,
        }
    }
}
define_schema_token!(HostStatusSchema, "satelle.host.status.v1");
define_schema_token!(HostPathsSchema, "satelle.host.paths.v1");
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
    HostPaths,
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
    ProviderSecretProvisioning,
}

impl Operation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Capabilities => "capabilities",
            Self::HostStatus => "host_status",
            Self::HostPaths => "host_paths",
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
            Self::ProviderSecretProvisioning => "provider_secret_provisioning",
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

    const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Other => "other",
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
    codex_update_evidence: satelle_core::host_update::CodexUpdateEvidence,
    limits: EffectiveLimits,
    supported_attachment_media_types: Vec<String>,
    provider_secret_upload: ProviderSecretUploadCapability,
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
        codex_update_evidence: satelle_core::host_update::CodexUpdateEvidence,
        image_attachments: bool,
        limits: EffectiveLimits,
    ) -> Self {
        let limits = if image_attachments {
            limits
        } else {
            EffectiveLimits {
                attachment_count: 0,
                attachment_bytes_each: 0,
                attachment_bytes_total: 0,
                ..limits
            }
        };
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
                Operation::HostPaths,
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
                Operation::ProviderSecretProvisioning,
            ],
            runtime_capabilities: RuntimeCapabilities {
                codex_runtime,
                native_computer_use,
                provider_computer_use,
            },
            codex_update_evidence,
            limits,
            supported_attachment_media_types: if image_attachments {
                super::SUPPORTED_IMAGE_MEDIA_TYPES
                    .iter()
                    .map(|media_type| (*media_type).to_string())
                    .collect()
            } else {
                Vec::new()
            },
            provider_secret_upload: ProviderSecretUploadCapability::current(),
        }
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    pub const fn platform(&self) -> &'static str {
        self.platform.os.as_str()
    }

    pub fn platform_arch(&self) -> &str {
        &self.platform.arch
    }

    pub const fn codex_update_evidence(&self) -> &satelle_core::host_update::CodexUpdateEvidence {
        &self.codex_update_evidence
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

    pub const fn provider_secret_upload(&self) -> &ProviderSecretUploadCapability {
        &self.provider_secret_upload
    }

    pub const fn limits(&self) -> EffectiveLimits {
        self.limits
    }

    pub fn supported_attachment_media_types(&self) -> &[String] {
        &self.supported_attachment_media_types
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
pub struct HostPathsResponse {
    schema_version: HostPathsSchema,
    request_id: RequestId,
    host_identity: String,
    paths: DaemonResolvedPathSet,
}

impl HostPathsResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        paths: DaemonResolvedPathSet,
    ) -> Self {
        Self {
            schema_version: HostPathsSchema,
            request_id,
            host_identity,
            paths,
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn paths(&self) -> &DaemonResolvedPathSet {
        &self.paths
    }
}

impl AuthenticatedResponseContract for HostPathsResponse {
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
        attachment_count: super::MAX_IMAGE_ATTACHMENT_COUNT,
        attachment_bytes_each: super::MAX_IMAGE_ATTACHMENT_BYTES,
        attachment_bytes_total: super::MAX_IMAGE_ATTACHMENT_BYTES_TOTAL,
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

    #[test]
    fn host_paths_exposes_only_daemon_authoritative_paths() {
        let request_id = RequestId::new();
        let paths = DaemonResolvedPathSet {
            config_file: "/daemon/config/config.toml".to_string(),
            cache_root: "/daemon/cache".to_string(),
            state_root: "/daemon/state".to_string(),
            sqlite_store: "/daemon/state/satelle.sqlite3".to_string(),
            operator_log_root: "/daemon/state/logs".to_string(),
            recording_root: "/daemon/state/recordings".to_string(),
            sources: satelle_core::SatellePathSources {
                config_file: satelle_core::PathSource::ServiceConfig,
                cache_root: satelle_core::PathSource::ServiceConfig,
                state_root: satelle_core::PathSource::ServiceConfig,
                sqlite_store: satelle_core::PathSource::ServiceConfig,
                operator_log_root: satelle_core::PathSource::ServiceConfig,
                recording_root: satelle_core::PathSource::ServiceConfig,
                project_config_file: satelle_core::PathSource::ProjectDiscovery,
                install_receipt: satelle_core::PathSource::ServiceConfig,
            },
            project_config_file: Some("/daemon/project/satelle.toml".to_string()),
            install_receipt: "/daemon/state/install-receipt.json".to_string(),
        };
        let response =
            HostPathsResponse::new(request_id.clone(), "host-daemon".to_string(), paths.clone());

        assert_eq!(response.paths(), &paths);
        assert_eq!(
            serde_json::to_value(&response).expect("serialize Host Path Set response"),
            serde_json::json!({
                "schema_version": "satelle.host.paths.v1",
                "request_id": request_id,
                "host_identity": "host-daemon",
                "paths": {
                    "config_file": "/daemon/config/config.toml",
                    "cache_root": "/daemon/cache",
                    "state_root": "/daemon/state",
                    "sqlite_store": "/daemon/state/satelle.sqlite3",
                    "operator_log_root": "/daemon/state/logs",
                    "recording_root": "/daemon/state/recordings",
                    "sources": {
                        "config_file": "service_config",
                        "cache_root": "service_config",
                        "state_root": "service_config",
                        "sqlite_store": "service_config",
                        "operator_log_root": "service_config",
                        "recording_root": "service_config",
                        "project_config_file": "project_discovery",
                        "install_receipt": "service_config"
                    },
                    "project_config_file": "/daemon/project/satelle.toml",
                    "install_receipt": "/daemon/state/install-receipt.json"
                }
            })
        );

        let mut response_with_nested_path_field =
            serde_json::to_value(&response).expect("serialize Host Path Set response");
        response_with_nested_path_field["paths"]["daemon_private_path"] =
            serde_json::json!("/daemon/private");
        assert!(
            serde_json::from_value::<HostPathsResponse>(response_with_nested_path_field).is_err(),
            "the remote response must reject unknown nested path fields"
        );

        let mut response_with_nested_source_field =
            serde_json::to_value(&response).expect("serialize Host Path Set response");
        response_with_nested_source_field["paths"]["sources"]["daemon_private_path"] =
            serde_json::json!("service_config");
        assert!(
            serde_json::from_value::<HostPathsResponse>(response_with_nested_source_field).is_err(),
            "the remote response must reject unknown nested source fields"
        );

        let response_with_controller_path = serde_json::json!({
            "schema_version": "satelle.host.paths.v1",
            "request_id": RequestId::new(),
            "host_identity": "host-daemon",
            "paths": paths,
            "controller_project_config_file": "/controller/project/satelle.toml"
        });
        assert!(
            serde_json::from_value::<HostPathsResponse>(response_with_controller_path).is_err(),
            "the remote response must reject controller-owned path provenance"
        );
    }
}
