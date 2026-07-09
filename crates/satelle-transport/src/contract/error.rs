use super::{RequestId, define_schema_token};
use serde::{Deserialize, Serialize};
use serde_json::Value;

define_schema_token!(ErrorSchema, "satelle.error.v1");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiErrorCode {
    AuthenticationFailed,
    AuthorizationInsufficientScope,
    HostIdentityMismatch,
    InvalidRequest,
    UnsupportedSchema,
    UnsupportedContentType,
    PayloadTooLarge,
    IdempotencyKeyConflict,
    SessionNotFound,
    LogsCursorExpired,
    HostUnreachable,
    HostBusy,
    ComputerUseNotReady,
    StorageIntegrityFailed,
    RemoteExecutionFailed,
    CapacityExceeded,
    RateLimited,
    RouteNotFound,
    MethodNotAllowed,
    InternalError,
}

impl ApiErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "authentication-failed",
            Self::AuthorizationInsufficientScope => "authorization-insufficient-scope",
            Self::HostIdentityMismatch => "host-identity-mismatch",
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedSchema => "unsupported-schema",
            Self::UnsupportedContentType => "unsupported-content-type",
            Self::PayloadTooLarge => "payload-too-large",
            Self::IdempotencyKeyConflict => "idempotency-key-conflict",
            Self::SessionNotFound => "session-not-found",
            Self::LogsCursorExpired => "logs-cursor-expired",
            Self::HostUnreachable => "host-unreachable",
            Self::HostBusy => "host-busy",
            Self::ComputerUseNotReady => "computer-use-not-ready",
            Self::StorageIntegrityFailed => "storage-integrity-failed",
            Self::RemoteExecutionFailed => "remote-execution-failed",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::RateLimited => "rate-limited",
            Self::RouteNotFound => "route-not-found",
            Self::MethodNotAllowed => "method-not-allowed",
            Self::InternalError => "internal-error",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiErrorCategory {
    Authentication,
    Authorization,
    Conflict,
    InvalidRequest,
    Readiness,
    Storage,
    RemoteExecution,
    Capacity,
    RateLimit,
    NotFound,
    Internal,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    schema_version: ErrorSchema,
    request_id: RequestId,
    host_identity: Option<String>,
    code: ApiErrorCode,
    category: ApiErrorCategory,
    retryable: bool,
    message: String,
    details: Option<Value>,
    docs_url: Option<String>,
    suggested_commands: Vec<String>,
}

impl ApiError {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: Option<String>,
        code: ApiErrorCode,
        category: ApiErrorCategory,
        retryable: bool,
        message: impl Into<String>,
        details: Option<Value>,
    ) -> Self {
        Self {
            schema_version: ErrorSchema,
            request_id,
            host_identity,
            code,
            category,
            retryable,
            message: message.into(),
            details,
            docs_url: None,
            suggested_commands: Vec::new(),
        }
    }

    pub const fn code(&self) -> ApiErrorCode {
        self.code
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> Option<&str> {
        self.host_identity.as_deref()
    }

    pub const fn details(&self) -> Option<&Value> {
        self.details.as_ref()
    }
}
