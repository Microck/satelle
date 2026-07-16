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
    StoreInUse,
    StateConflict,
    StopNotConfirmed,
    IncompatibleProtocol,
    IncompatibleControlPlane,
    ComputerUseNotReady,
    NativeReadinessTimeout,
    ProviderSmokeTestTimeout,
    UnsupportedProviderComputerUse,
    StorageBusy,
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
            Self::StoreInUse => "store-in-use",
            Self::StateConflict => "state-conflict",
            Self::StopNotConfirmed => "stop-not-confirmed",
            Self::IncompatibleProtocol => "incompatible-protocol",
            Self::IncompatibleControlPlane => "incompatible-control-plane",
            Self::ComputerUseNotReady => "computer-use-not-ready",
            Self::NativeReadinessTimeout => "native-readiness-timeout",
            Self::ProviderSmokeTestTimeout => "provider-smoke-test-timeout",
            Self::UnsupportedProviderComputerUse => "unsupported-provider-computer-use",
            Self::StorageBusy => "storage-busy",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incompatible_control_plane_code_has_exact_public_token() {
        assert_eq!(
            ApiErrorCode::IncompatibleControlPlane.as_str(),
            "incompatible-control-plane"
        );
        assert_eq!(
            serde_json::to_value(ApiErrorCode::IncompatibleControlPlane).unwrap(),
            json!("incompatible-control-plane")
        );
    }

    #[test]
    fn provider_smoke_codes_have_exact_public_tokens() {
        for (code, token) in [
            (
                ApiErrorCode::ProviderSmokeTestTimeout,
                "provider-smoke-test-timeout",
            ),
            (
                ApiErrorCode::UnsupportedProviderComputerUse,
                "unsupported-provider-computer-use",
            ),
        ] {
            assert_eq!(code.as_str(), token);
            assert_eq!(serde_json::to_value(code).unwrap(), json!(token));
        }
    }

    #[test]
    fn native_readiness_timeout_has_exact_public_token() {
        assert_eq!(
            ApiErrorCode::NativeReadinessTimeout.as_str(),
            "native-readiness-timeout"
        );
        assert_eq!(
            serde_json::to_value(ApiErrorCode::NativeReadinessTimeout).unwrap(),
            json!("native-readiness-timeout")
        );
    }

    #[test]
    fn storage_busy_code_has_exact_public_token() {
        assert_eq!(ApiErrorCode::StorageBusy.as_str(), "storage-busy");
        assert_eq!(
            serde_json::to_value(ApiErrorCode::StorageBusy).unwrap(),
            json!("storage-busy")
        );
    }

    #[test]
    fn storage_conflict_codes_have_exact_public_tokens() {
        for (code, token) in [
            (ApiErrorCode::StoreInUse, "store-in-use"),
            (ApiErrorCode::StateConflict, "state-conflict"),
        ] {
            assert_eq!(code.as_str(), token);
            assert_eq!(serde_json::to_value(code).unwrap(), json!(token));
        }
    }

    #[test]
    fn stop_not_confirmed_has_exact_public_token() {
        assert_eq!(
            ApiErrorCode::StopNotConfirmed.as_str(),
            "stop-not-confirmed"
        );
        assert_eq!(
            serde_json::to_value(ApiErrorCode::StopNotConfirmed).unwrap(),
            json!("stop-not-confirmed")
        );
    }

    #[test]
    fn api_error_requires_nullable_fields() {
        let error = ApiError::new(
            RequestId::new(),
            None,
            ApiErrorCode::InvalidRequest,
            ApiErrorCategory::InvalidRequest,
            false,
            "the request is invalid",
            None,
        );
        let wire = serde_json::to_value(error).expect("serialize API error");
        serde_json::from_value::<ApiError>(wire.clone())
            .expect("decode complete serialized API error");

        for field in ["host_identity", "details", "docs_url"] {
            assert_eq!(
                wire.get(field),
                Some(&serde_json::Value::Null),
                "serialization must emit {field} as explicit null"
            );
            let mut missing = wire.clone();
            let removed = missing
                .as_object_mut()
                .expect("API error is an object")
                .remove(field);
            assert_eq!(removed, Some(serde_json::Value::Null));
            assert!(
                serde_json::from_value::<ApiError>(missing).is_err(),
                "missing {field} must be rejected"
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiErrorCategory {
    Authentication,
    Authorization,
    Conflict,
    Compatibility,
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
    #[serde(deserialize_with = "Option::deserialize")]
    host_identity: Option<String>,
    code: ApiErrorCode,
    category: ApiErrorCategory,
    retryable: bool,
    message: String,
    #[serde(deserialize_with = "Option::deserialize")]
    details: Option<Value>,
    #[serde(deserialize_with = "Option::deserialize")]
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
