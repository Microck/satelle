use rmcp::model::CallToolResult;
use satelle_core::{ErrorCode, SatelleError};
use serde::Serialize;
use serde_json::{Value, json};

const ERROR_SCHEMA_VERSION: &str = "satelle.error.v1";

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCategory {
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

impl ErrorCategory {
    const ALL: [Self; 12] = [
        Self::Authentication,
        Self::Authorization,
        Self::Conflict,
        Self::Compatibility,
        Self::InvalidRequest,
        Self::Readiness,
        Self::Storage,
        Self::RemoteExecution,
        Self::Capacity,
        Self::RateLimit,
        Self::NotFound,
        Self::Internal,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::Conflict => "conflict",
            Self::Compatibility => "compatibility",
            Self::InvalidRequest => "invalid_request",
            Self::Readiness => "readiness",
            Self::Storage => "storage",
            Self::RemoteExecution => "remote_execution",
            Self::Capacity => "capacity",
            Self::RateLimit => "rate_limit",
            Self::NotFound => "not_found",
            Self::Internal => "internal",
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema_version: &'static str,
    code: &'static str,
    category: ErrorCategory,
    retryable: bool,
    message: &'a str,
    details: Value,
    docs_url: Option<&'static str>,
    suggested_commands: Vec<&'a str>,
}

pub(super) fn structured(value: Value, is_error: bool) -> CallToolResult {
    if is_error {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    }
}

pub(super) fn operational_error(error: SatelleError) -> CallToolResult {
    structured(error_envelope(&error), true)
}

fn error_envelope(error: &SatelleError) -> Value {
    let (category, retryable) = error_class(error.code);
    let details = if error.details.is_empty() {
        Value::Null
    } else {
        Value::Object(error.details.clone().into_iter().collect())
    };
    serde_json::to_value(ErrorEnvelope {
        schema_version: ERROR_SCHEMA_VERSION,
        code: error.code.as_str(),
        category,
        retryable,
        message: &error.message,
        details,
        docs_url: None,
        suggested_commands: error.recovery_command.iter().map(String::as_str).collect(),
    })
    .expect("the closed MCP error envelope is JSON serializable")
}

pub(super) fn error_schema() -> Value {
    let categories = ErrorCategory::ALL
        .iter()
        .copied()
        .map(ErrorCategory::as_str)
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "schema_version": {"const": ERROR_SCHEMA_VERSION},
            "code": {"type": "string", "minLength": 1},
            "category": {"enum": categories},
            "retryable": {"type": "boolean"},
            "message": {"type": "string", "minLength": 1},
            "details": {"type": ["object", "null"]},
            "docs_url": {"type": ["string", "null"]},
            "suggested_commands": {"type": "array", "items": {"type": "string"}}
        },
        "required": [
            "schema_version", "code", "category", "retryable", "message", "details",
            "docs_url", "suggested_commands"
        ],
        "additionalProperties": false
    })
}

fn error_class(code: ErrorCode) -> (ErrorCategory, bool) {
    match code {
        ErrorCode::AuthenticationFailed => (ErrorCategory::Authentication, false),
        ErrorCode::AuthorizationInsufficientScope => (ErrorCategory::Authorization, false),
        ErrorCode::IdempotencyKeyConflict => (ErrorCategory::Conflict, false),
        ErrorCode::HostBusy | ErrorCode::StateConflict | ErrorCode::StopNotConfirmed => {
            (ErrorCategory::Conflict, true)
        }
        ErrorCode::IncompatibleControlPlane
        | ErrorCode::ComputerUseNotReady
        | ErrorCode::DoctorReadinessBlockersFound => (ErrorCategory::Readiness, false),
        ErrorCode::StoreInUse | ErrorCode::StorageBusy => (ErrorCategory::Storage, true),
        ErrorCode::StorageIntegrityFailed => (ErrorCategory::Storage, false),
        ErrorCode::HostUnreachable
        | ErrorCode::DirectDaemonUnreachable
        | ErrorCode::RemoteExecution => (ErrorCategory::RemoteExecution, true),
        ErrorCode::CapacityExceeded | ErrorCode::ConcurrencyLimitExceeded => {
            (ErrorCategory::Capacity, true)
        }
        ErrorCode::HostNotFound | ErrorCode::SessionNotFound | ErrorCode::LogsCursorExpired => {
            (ErrorCategory::NotFound, false)
        }
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
        | ErrorCode::OutputModeConflict
        | ErrorCode::LogTailLimitExceeded
        | ErrorCode::LogPositionConflict
        | ErrorCode::ConcurrencyWithoutRemoteUpdate
        | ErrorCode::ComponentSelectionConflict
        | ErrorCode::UnsupportedUpdateComponent
        | ErrorCode::InputRequired => (ErrorCategory::InvalidRequest, false),
        ErrorCode::CertificateUntrusted
        | ErrorCode::CertificateHostnameMismatch
        | ErrorCode::CertificateExpired
        | ErrorCode::TlsVersionUnsupported
        | ErrorCode::TlsHandshakeFailed
        | ErrorCode::HostIdentityMismatch
        | ErrorCode::CompletionInstallFailed
        | ErrorCode::CompletionProfileUpdateFailed
        | ErrorCode::PlatformDirectoriesUnavailable
        | ErrorCode::NotImplemented => (ErrorCategory::Internal, false),
    }
}
