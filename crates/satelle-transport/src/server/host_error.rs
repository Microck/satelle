use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response};
use crate::contract::{ApiErrorCategory, ApiErrorCode};
use axum::http::StatusCode;
use axum::response::Response;
use satelle_core::{ErrorCode, IncompatibleControlPlaneDetails, SatelleError};

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
        | ErrorCode::ProfileNotFound
        | ErrorCode::ProjectProfileDefinitionNotAllowed
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
        ErrorCode::IncompatibleControlPlane => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::IncompatibleControlPlane,
            category: ApiErrorCategory::Readiness,
            retryable: false,
            message: "the Codex control plane cannot admit this operation",
            details: validated_control_plane_details(error),
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
        ErrorCode::StorageBusy => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::StorageBusy,
            category: ApiErrorCategory::Storage,
            retryable: true,
            message: "the Host state store is temporarily busy",
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

fn validated_control_plane_details(error: &SatelleError) -> Option<serde_json::Value> {
    let value = serde_json::Value::Object(error.details.clone().into_iter().collect());
    let details = serde_json::from_value::<IncompatibleControlPlaneDetails>(value).ok()?;
    serde_json::to_value(details).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::{
        ControlPlaneCapability, ControlPlaneFailureReason, ControlPlaneOperation,
        IncompatibleControlPlaneDetails,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn incompatible_control_plane_is_a_sanitized_readiness_failure() {
        let details = IncompatibleControlPlaneDetails::new(
            ControlPlaneOperation::Run,
            ControlPlaneFailureReason::RequiredCapabilityMissing,
            &[ControlPlaneCapability::EventObservation],
        )
        .unwrap();
        let failure = failure(&SatelleError::incompatible_control_plane(details));

        assert_eq!(failure.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(failure.code, ApiErrorCode::IncompatibleControlPlane);
        assert_eq!(failure.category, ApiErrorCategory::Readiness);
        assert!(!failure.retryable);
        assert_eq!(
            failure.details,
            Some(json!({
                "operation": "run",
                "reason": "required_capability_missing",
                "required_capabilities": [
                    "session_creation",
                    "turn_start",
                    "event_observation"
                ],
                "missing_capabilities": ["event_observation"]
            }))
        );
    }

    #[test]
    fn malformed_internal_details_never_cross_the_http_boundary() {
        let error = SatelleError {
            code: ErrorCode::IncompatibleControlPlane,
            message: "PRIVATE_MESSAGE_CANARY".to_string(),
            recovery_command: None,
            source_detail: Some("PRIVATE_SOURCE_CANARY".to_string()),
            details: BTreeMap::from([("raw_message".to_string(), json!("PRIVATE_DETAILS_CANARY"))]),
        };

        let mapped = failure(&error);

        assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.code, ApiErrorCode::IncompatibleControlPlane);
        assert_eq!(mapped.category, ApiErrorCategory::Readiness);
        assert!(!mapped.retryable);
        assert_eq!(mapped.details, None);
        assert!(!mapped.message.contains("PRIVATE_"));
    }

    #[test]
    fn storage_busy_is_a_retryable_service_unavailable_response() {
        let mapped = failure(&SatelleError::storage_busy());

        assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.code, ApiErrorCode::StorageBusy);
        assert_eq!(mapped.category, ApiErrorCategory::Storage);
        assert!(mapped.retryable);
        assert_eq!(mapped.details, None);
    }
}
