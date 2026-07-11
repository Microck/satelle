use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response};
use crate::contract::{ApiErrorCategory, ApiErrorCode};
use axum::http::StatusCode;
use axum::response::Response;
use satelle_core::{ErrorCode, SatelleError};

pub(super) fn response(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    error: &SatelleError,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        failure(error),
    )
}

pub(super) fn task_failure(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ApiErrorCode::InternalError,
            category: ApiErrorCategory::Internal,
            retryable: false,
            message: "the Host operation task did not complete",
            details: None,
        },
    )
}

fn failure(error: &SatelleError) -> ApiFailure {
    match error.code {
        ErrorCode::InvalidUsage
        | ErrorCode::ConfigError
        | ErrorCode::ConfigNotFound
        | ErrorCode::UnknownConfigKey
        | ErrorCode::ConfigInterpolationNotSupported
        | ErrorCode::UnknownTimeoutKey
        | ErrorCode::DurationUnitRequired
        | ErrorCode::UnsupportedConfigComposition
        | ErrorCode::ProjectDaemonPathOverrideNotAllowed
        | ErrorCode::ProjectDesktopBindingNotAllowed
        | ErrorCode::ProjectYoloEnableNotAllowed
        | ErrorCode::ProjectExperimentalProviderOptInNotAllowed
        | ErrorCode::ProjectMutationConsentNotAllowed
        | ErrorCode::ProjectSecretSourceNotAllowed
        | ErrorCode::ProjectCredentialHelperNotAllowed
        | ErrorCode::UnsupportedSecretSourceKind
        | ErrorCode::SecretFilePathNotAbsolute
        | ErrorCode::DesktopSessionSelectorConflict
        | ErrorCode::PathOverrideNotAbsolute
        | ErrorCode::DaemonPathOverrideNotAbsolute
        | ErrorCode::EventsWithDetach
        | ErrorCode::OutputModeConflict
        | ErrorCode::LogTailLimitExceeded
        | ErrorCode::ConcurrencyWithoutRemoteUpdate
        | ErrorCode::ComponentSelectionConflict
        | ErrorCode::UnsupportedUpdateComponent
        | ErrorCode::InputRequired => ApiFailure {
            status: StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "the Host rejected the operation input",
            details: None,
        },
        ErrorCode::IdempotencyKeyConflict => ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::IdempotencyKeyConflict,
            category: ApiErrorCategory::Conflict,
            retryable: false,
            message: "the idempotency key was already used for a different request",
            details: None,
        },
        ErrorCode::SessionNotFound => ApiFailure {
            status: StatusCode::NOT_FOUND,
            code: ApiErrorCode::SessionNotFound,
            category: ApiErrorCategory::NotFound,
            retryable: false,
            message: "the requested Satelle Session does not exist",
            details: None,
        },
        ErrorCode::LogsCursorExpired => ApiFailure {
            status: StatusCode::GONE,
            code: ApiErrorCode::LogsCursorExpired,
            category: ApiErrorCategory::NotFound,
            retryable: false,
            message: "the Log Cursor is older than retained Host history",
            details: Some(serde_json::json!({
                "earliest_available_cursor": error
                    .details
                    .get("earliest_available_cursor")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "resume_cursor": error
                    .details
                    .get("resume_cursor")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            })),
        },
        ErrorCode::HostBusy => ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::HostBusy,
            category: ApiErrorCategory::Conflict,
            retryable: true,
            message: "the Host is already controlling its authorized desktop",
            details: None,
        },
        ErrorCode::ComputerUseNotReady | ErrorCode::DoctorReadinessBlockersFound => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::ComputerUseNotReady,
            category: ApiErrorCategory::Readiness,
            retryable: false,
            message: "native Computer Use is not ready on this Host",
            details: None,
        },
        ErrorCode::HostUnreachable => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::HostUnreachable,
            category: ApiErrorCategory::RemoteExecution,
            retryable: true,
            message: "the configured execution runtime is unreachable",
            details: None,
        },
        ErrorCode::RemoteExecution => ApiFailure {
            status: StatusCode::BAD_GATEWAY,
            code: ApiErrorCode::RemoteExecutionFailed,
            category: ApiErrorCategory::RemoteExecution,
            retryable: true,
            message: "the execution runtime could not complete the operation",
            details: None,
        },
        // Completion installation and profile activation are Controller-local workflows. If
        // either code crosses the Host boundary, expose only the stable internal-error contract.
        ErrorCode::CompletionInstallFailed | ErrorCode::CompletionProfileUpdateFailed => {
            ApiFailure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: ApiErrorCode::InternalError,
                category: ApiErrorCategory::Internal,
                retryable: false,
                message: "the Host operation failed unexpectedly",
                details: None,
            }
        }
        ErrorCode::CapacityExceeded | ErrorCode::ConcurrencyLimitExceeded => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::CapacityExceeded,
            category: ApiErrorCategory::Capacity,
            retryable: true,
            message: "the Host has no operation capacity available",
            details: None,
        },
        ErrorCode::StorageIntegrityFailed | ErrorCode::PlatformDirectoriesUnavailable => {
            ApiFailure {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: ApiErrorCode::StorageIntegrityFailed,
                category: ApiErrorCategory::Storage,
                retryable: false,
                message: "the Host state failed an integrity requirement",
                details: None,
            }
        }
        ErrorCode::HostNotFound | ErrorCode::NotImplemented => ApiFailure {
            status: StatusCode::NOT_IMPLEMENTED,
            code: ApiErrorCode::InternalError,
            category: ApiErrorCategory::Internal,
            retryable: false,
            message: "the Host does not implement the requested operation",
            details: None,
        },
    }
}
