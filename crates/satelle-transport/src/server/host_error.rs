use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response};
use crate::contract::{ApiErrorCategory, ApiErrorCode};
use axum::http::StatusCode;
use axum::response::Response;
use satelle_core::{ErrorCode, IncompatibleControlPlaneDetails, SatelleError, SessionId, TurnId};

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
        | ErrorCode::ProjectHostBindingNotAllowed
        | ErrorCode::ProjectHostSelectionNotAllowed
        | ErrorCode::ProjectSecretSourceNotAllowed
        | ErrorCode::ProjectCredentialHelperNotAllowed
        | ErrorCode::UnsupportedSecretSourceKind
        | ErrorCode::SecretFilePathNotAbsolute
        | ErrorCode::DesktopSessionSelectorConflict
        | ErrorCode::PathOverrideNotAbsolute
        | ErrorCode::DaemonPathOverrideNotAbsolute
        | ErrorCode::EventsWithDetach
        | ErrorCode::InterruptModeConflict
        | ErrorCode::OutputModeConflict
        | ErrorCode::LogTailLimitExceeded
        | ErrorCode::LogPositionConflict
        | ErrorCode::ConcurrencyWithoutRemoteUpdate
        | ErrorCode::ComponentSelectionConflict
        | ErrorCode::UnsupportedUpdateComponent
        | ErrorCode::SetupConsentRequired
        | ErrorCode::DoctorFixConsentRequired
        | ErrorCode::DoctorRefreshScopeRequired
        | ErrorCode::DoctorRefreshTimeoutWithoutRefresh
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
        ErrorCode::BootstrapBusy | ErrorCode::HostBusy => ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::HostBusy,
            category: ApiErrorCategory::Conflict,
            retryable: true,
            message: "the Host is already controlling its authorized desktop",
            details: None,
        },
        ErrorCode::StoreInUse => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::StoreInUse,
            category: ApiErrorCategory::Storage,
            retryable: true,
            message: "the Host state store is already owned by another daemon process",
            details: None,
        },
        ErrorCode::StateConflict => ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::StateConflict,
            category: ApiErrorCategory::Conflict,
            retryable: true,
            message: "the Host state changed before the operation could commit",
            details: None,
        },
        ErrorCode::StopNotConfirmed => ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::StopNotConfirmed,
            category: ApiErrorCategory::Conflict,
            retryable: true,
            message: "upstream cancellation could not be confirmed",
            details: validated_stop_not_confirmed_details(error),
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
        ErrorCode::NativeReadinessTimeout => ApiFailure {
            status: StatusCode::GATEWAY_TIMEOUT,
            code: ApiErrorCode::NativeReadinessTimeout,
            category: ApiErrorCategory::Readiness,
            retryable: true,
            message: "the native Computer Use readiness smoke test timed out",
            details: None,
        },
        ErrorCode::ProviderSmokeTestTimeout => ApiFailure {
            status: StatusCode::GATEWAY_TIMEOUT,
            code: ApiErrorCode::ProviderSmokeTestTimeout,
            category: ApiErrorCategory::Readiness,
            retryable: true,
            message: "the live provider Computer Use smoke test timed out",
            details: None,
        },
        ErrorCode::UnsupportedProviderComputerUse => ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::UnsupportedProviderComputerUse,
            category: ApiErrorCategory::Readiness,
            retryable: false,
            message: "the selected provider does not support native Computer Use",
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
        ErrorCode::CompletionInstallFailed
        | ErrorCode::CompletionProfileUpdateFailed
        | ErrorCode::CertificateUntrusted
        | ErrorCode::CertificateHostnameMismatch
        | ErrorCode::CertificateExpired
        | ErrorCode::TlsVersionUnsupported
        | ErrorCode::TlsHandshakeFailed
        | ErrorCode::AuthenticationFailed
        | ErrorCode::AuthorizationInsufficientScope
        | ErrorCode::HostIdentityMismatch
        // This is a Controller-local reachability error. If it ever reaches
        // the Host boundary, fail closed instead of inventing a wire code.
        | ErrorCode::DirectDaemonUnreachable
        // Process interruption is a Controller-local process-exit contract.
        // If it crosses the Host boundary, expose no extra API surface.
        | ErrorCode::Interrupted
        | ErrorCode::SshHostKeyVerificationRequired => ApiFailure {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ApiErrorCode::InternalError,
            category: ApiErrorCategory::Internal,
            retryable: false,
            message: "the Host operation failed unexpectedly",
            details: None,
        },
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

fn validated_stop_not_confirmed_details(error: &SatelleError) -> Option<serde_json::Value> {
    if error.details.len() != 7 {
        return None;
    }
    let session_id = error.details.get("session_id")?.as_str()?;
    let turn_id = error.details.get("turn_id")?.as_str()?;
    SessionId::parse(session_id).ok()?;
    TurnId::parse(turn_id).ok()?;
    let ownership = error.details.get("ownership")?.as_str()?;
    if !matches!(ownership, "active" | "recovery_pending") {
        return None;
    }
    let state_changed = error.details.get("state_changed")?.as_bool()?;
    let session_state_revision = error
        .details
        .get("session_state_revision")?
        .as_u64()
        .and_then(|value| satelle_core::session::SessionStateRevision::new(value).ok())?;
    let turn_state_revision = error
        .details
        .get("turn_state_revision")?
        .as_u64()
        .and_then(|value| satelle_core::session::TurnStateRevision::new(value).ok())?;
    if !error.details.get("retryable")?.as_bool()? {
        return None;
    }
    Some(serde_json::json!({
        "session_id": session_id,
        "turn_id": turn_id,
        "ownership": ownership,
        "state_changed": state_changed,
        "session_state_revision": session_state_revision,
        "turn_state_revision": turn_state_revision,
        "retryable": true
    }))
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
    fn provider_smoke_failures_keep_distinct_typed_api_codes() {
        let timeout = failure(&SatelleError::provider_smoke_test_timeout());
        assert_eq!(timeout.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(timeout.code, ApiErrorCode::ProviderSmokeTestTimeout);
        assert!(timeout.retryable);

        let unsupported = failure(&SatelleError::unsupported_provider_computer_use());
        assert_eq!(unsupported.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            unsupported.code,
            ApiErrorCode::UnsupportedProviderComputerUse
        );
        assert!(!unsupported.retryable);
    }

    #[test]
    fn native_readiness_timeout_is_a_retryable_gateway_timeout() {
        let timeout = failure(&SatelleError::native_readiness_timeout());
        assert_eq!(timeout.status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(timeout.code, ApiErrorCode::NativeReadinessTimeout);
        assert_eq!(timeout.category, ApiErrorCategory::Readiness);
        assert!(timeout.retryable);
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
    fn direct_daemon_unreachable_is_sanitized_at_the_host_boundary() {
        let mapped = failure(&SatelleError::direct_daemon_unreachable(
            "PRIVATE_HOST_CANARY",
        ));

        assert_eq!(mapped.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(mapped.code, ApiErrorCode::InternalError);
        assert_eq!(mapped.category, ApiErrorCategory::Internal);
        assert!(!mapped.retryable);
        assert_eq!(mapped.message, "the Host operation failed unexpectedly");
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

    #[test]
    fn operation_capacity_failures_use_the_public_capacity_contract() {
        for error in [
            SatelleError::capacity_exceeded("operation", 1),
            SatelleError::concurrency_limit_exceeded(1),
        ] {
            let mapped = failure(&error);

            assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(mapped.code, ApiErrorCode::CapacityExceeded);
            assert_eq!(mapped.category, ApiErrorCategory::Capacity);
            assert!(mapped.retryable);
            assert_eq!(mapped.details, None);
        }
    }

    #[test]
    fn store_in_use_is_a_retryable_storage_unavailable_response() {
        let mapped = failure(&SatelleError::store_in_use());

        assert_eq!(mapped.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.code, ApiErrorCode::StoreInUse);
        assert_eq!(mapped.category, ApiErrorCategory::Storage);
        assert!(mapped.retryable);
        assert_eq!(mapped.details, None);
    }

    #[test]
    fn state_conflict_is_a_retryable_conflict_response() {
        let mapped = failure(&SatelleError::state_conflict());

        assert_eq!(mapped.status, StatusCode::CONFLICT);
        assert_eq!(mapped.code, ApiErrorCode::StateConflict);
        assert_eq!(mapped.category, ApiErrorCategory::Conflict);
        assert!(mapped.retryable);
        assert_eq!(mapped.details, None);
    }

    #[test]
    fn stop_not_confirmed_is_a_retryable_conflict_response() {
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let mapped = failure(&SatelleError {
            code: ErrorCode::StopNotConfirmed,
            message: "PRIVATE_INTERNAL_STOP_MESSAGE".to_string(),
            recovery_command: None,
            source_detail: None,
            details: BTreeMap::from([
                ("session_id".to_string(), json!(session_id)),
                ("turn_id".to_string(), json!(turn_id)),
                ("ownership".to_string(), json!("recovery_pending")),
                ("state_changed".to_string(), json!(true)),
                ("session_state_revision".to_string(), json!(3)),
                ("turn_state_revision".to_string(), json!(2)),
                ("retryable".to_string(), json!(true)),
            ]),
        });

        assert_eq!(mapped.status, StatusCode::CONFLICT);
        assert_eq!(mapped.code, ApiErrorCode::StopNotConfirmed);
        assert_eq!(mapped.category, ApiErrorCategory::Conflict);
        assert!(mapped.retryable);
        assert!(!mapped.message.contains("PRIVATE_"));
        assert_eq!(
            mapped.details,
            Some(json!({
                "session_id": session_id,
                "turn_id": turn_id,
                "ownership": "recovery_pending",
                "state_changed": true,
                "session_state_revision": 3,
                "turn_state_revision": 2,
                "retryable": true
            }))
        );
    }

    #[test]
    fn malformed_stop_details_do_not_cross_the_http_boundary() {
        let mapped = failure(&SatelleError {
            code: ErrorCode::StopNotConfirmed,
            message: "PRIVATE_INTERNAL_STOP_MESSAGE".to_string(),
            recovery_command: None,
            source_detail: Some("PRIVATE_SOURCE_CANARY".to_string()),
            details: BTreeMap::from([
                ("ownership".to_string(), json!("PRIVATE_INVALID_OWNER")),
                ("raw".to_string(), json!("PRIVATE_DETAILS_CANARY")),
            ]),
        });

        assert_eq!(mapped.details, None);
        assert!(!mapped.message.contains("PRIVATE_"));
    }
}
