use clap::ValueEnum;
use satelle_core::{ErrorCode, SatelleError};
use serde::Serialize;
use serde_json::Value;

pub(crate) const ERROR_SCHEMA_VERSION: &str = "satelle.error.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ErrorFormat {
    Human,
    Json,
}

impl ErrorFormat {
    pub(crate) fn resolve(configured: Option<Self>, machine_selector: bool) -> Self {
        configured.unwrap_or(if machine_selector {
            Self::Json
        } else {
            Self::Human
        })
    }
}

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

pub(crate) fn parser_error(error: &clap::Error) -> SatelleError {
    SatelleError::invalid_usage(error.render().to_string())
}

pub(crate) fn print_error(error: &SatelleError, format: ErrorFormat) {
    match format {
        ErrorFormat::Json => {
            let raw = serde_json::to_string_pretty(&error_envelope(error))
                .expect("the closed error envelope is JSON serializable");
            eprintln!("{raw}");
        }
        ErrorFormat::Human => {
            eprintln!("error: {}", error.code.as_str());
            eprintln!("{}", error.message);
            if let Some(command) = &error.recovery_command {
                eprintln!("next: {command}");
            }
        }
    }
}

pub(crate) fn error_envelope(error: &SatelleError) -> Value {
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
    .expect("the closed error envelope is JSON serializable")
}

pub(crate) fn error_categories() -> Vec<&'static str> {
    ErrorCategory::ALL
        .iter()
        .copied()
        .map(ErrorCategory::as_str)
        .collect()
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
        ErrorCode::SshHostKeyVerificationRequired => (ErrorCategory::RemoteExecution, false),
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
        | ErrorCode::SetupConsentRequired
        | ErrorCode::DoctorRefreshScopeRequired
        | ErrorCode::DoctorRefreshTimeoutWithoutRefresh
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
