use clap::ValueEnum;
use satelle_core::{ErrorCode, SatelleError};
use serde::Serialize;
use serde_json::Value;
use std::process::ExitCode;

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
    Interrupted,
    Capacity,
    RateLimit,
    NotFound,
    Internal,
}

#[derive(Clone, Copy)]
struct ErrorContract {
    category: ErrorCategory,
    retryable: bool,
    outcome: &'static str,
    default_recovery: &'static str,
}

impl ErrorCategory {
    const ALL: [Self; 13] = [
        Self::Authentication,
        Self::Authorization,
        Self::Conflict,
        Self::Compatibility,
        Self::InvalidRequest,
        Self::Readiness,
        Self::Storage,
        Self::RemoteExecution,
        Self::Interrupted,
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
            Self::Interrupted => "interrupted",
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

/// Converts the core error classification into the CLI process boundary exactly once.
pub(crate) fn process_exit_code(error: &SatelleError) -> ExitCode {
    ExitCode::from(error.exit_code() as u8)
}

pub(crate) fn print_error(error: &SatelleError, format: ErrorFormat) {
    match format {
        ErrorFormat::Json => {
            let raw = serde_json::to_string_pretty(&error_envelope(error))
                .expect("the closed error envelope is JSON serializable");
            eprintln!("{raw}");
        }
        ErrorFormat::Human => {
            eprintln!("{}", human_error(error));
        }
    }
}

fn human_error(error: &SatelleError) -> String {
    let contract = error_contract(error.code);
    // Parser errors can contain a full multi-line Clap report. Human framing keeps the cause on
    // one line so the outcome, cause, preserved state, and recovery step remain scannable.
    let cause = error
        .message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let recovery = error
        .recovery_command
        .as_deref()
        .unwrap_or(contract.default_recovery);
    let mut lines = vec![
        format!("error: {}", contract.outcome),
        format!("cause: {cause} [{}]", error.code.as_str()),
    ];
    if error.details.get("mutated") == Some(&Value::Bool(false)) {
        lines.push("state: No changes were applied.".to_string());
    }
    lines.push(format!("next: {recovery}"));
    lines.join("\n")
}

pub(crate) fn error_envelope(error: &SatelleError) -> Value {
    let contract = error_contract(error.code);
    let details = if error.details.is_empty() {
        Value::Null
    } else {
        Value::Object(error.details.clone().into_iter().collect())
    };
    serde_json::to_value(ErrorEnvelope {
        schema_version: ERROR_SCHEMA_VERSION,
        code: error.code.as_str(),
        category: contract.category,
        retryable: contract.retryable,
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

fn error_contract(code: ErrorCode) -> ErrorContract {
    match code {
        ErrorCode::AuthenticationFailed => ErrorContract {
            category: ErrorCategory::Authentication,
            retryable: false,
            outcome: "Authentication failed.",
            default_recovery: "check the configured authentication and retry the command",
        },
        ErrorCode::AuthorizationInsufficientScope => ErrorContract {
            category: ErrorCategory::Authorization,
            retryable: false,
            outcome: "The requested action was not authorized.",
            default_recovery: "use credentials with the required scope and retry the command",
        },
        ErrorCode::IdempotencyKeyConflict => ErrorContract {
            category: ErrorCategory::Conflict,
            retryable: false,
            outcome: "The request conflicted with an earlier operation.",
            default_recovery: "retry with a new idempotency key",
        },
        ErrorCode::BootstrapBusy
        | ErrorCode::HostBusy
        | ErrorCode::StateConflict
        | ErrorCode::StopNotConfirmed => ErrorContract {
            category: ErrorCategory::Conflict,
            retryable: true,
            outcome: "The requested state change was not applied.",
            default_recovery: "check the current Host and Session status, then retry",
        },
        ErrorCode::IncompatibleControlPlane
        | ErrorCode::ComputerUseNotReady
        | ErrorCode::UnsupportedProviderComputerUse
        | ErrorCode::DoctorReadinessBlockersFound => ErrorContract {
            category: ErrorCategory::Readiness,
            retryable: false,
            outcome: "The Host is not ready for this command.",
            default_recovery: "run satelle doctor and resolve the reported readiness blockers",
        },
        ErrorCode::NativeReadinessTimeout | ErrorCode::ProviderSmokeTestTimeout => ErrorContract {
            category: ErrorCategory::Readiness,
            retryable: true,
            outcome: "The Host readiness check did not finish.",
            default_recovery: "run satelle doctor --refresh and retry the command",
        },
        ErrorCode::StoreInUse | ErrorCode::StorageBusy => ErrorContract {
            category: ErrorCategory::Storage,
            retryable: true,
            outcome: "The Host state could not be changed.",
            default_recovery: "wait for the active operation to finish, then retry",
        },
        ErrorCode::StorageIntegrityFailed => ErrorContract {
            category: ErrorCategory::Storage,
            retryable: false,
            outcome: "The Host state could not be read safely.",
            default_recovery: "run satelle doctor and repair the reported storage problem",
        },
        ErrorCode::HostUnreachable | ErrorCode::DirectDaemonUnreachable => ErrorContract {
            category: ErrorCategory::RemoteExecution,
            retryable: true,
            outcome: "The Host could not be reached.",
            default_recovery: "run satelle doctor --scope transport and retry the command",
        },
        ErrorCode::RemoteExecution => ErrorContract {
            category: ErrorCategory::RemoteExecution,
            retryable: true,
            outcome: "The remote operation did not complete.",
            default_recovery: "check the Host status and retry the command",
        },
        ErrorCode::SshHostKeyVerificationRequired => ErrorContract {
            category: ErrorCategory::RemoteExecution,
            retryable: false,
            outcome: "The SSH Host identity was not accepted.",
            default_recovery: "verify and trust the Host key, then retry the command",
        },
        ErrorCode::CapacityExceeded => ErrorContract {
            category: ErrorCategory::Capacity,
            retryable: true,
            outcome: "The requested work could not start.",
            default_recovery: "reduce concurrent work or wait for capacity, then retry",
        },
        ErrorCode::HostNotFound | ErrorCode::SessionNotFound | ErrorCode::LogsCursorExpired => {
            ErrorContract {
                category: ErrorCategory::NotFound,
                retryable: false,
                outcome: "The requested Satelle resource was not found.",
                default_recovery: "check the configured Host or Session identifier and retry",
            }
        }
        ErrorCode::InvalidUsage
        | ErrorCode::EventsWithDetach
        | ErrorCode::InterruptModeConflict
        | ErrorCode::OutputModeConflict
        | ErrorCode::LogTailLimitExceeded
        | ErrorCode::LogPositionConflict
        | ErrorCode::ConcurrencyLimitExceeded
        | ErrorCode::ConcurrencyWithoutRemoteUpdate
        | ErrorCode::ComponentSelectionConflict
        | ErrorCode::UnsupportedUpdateComponent
        | ErrorCode::SetupConsentRequired
        | ErrorCode::DoctorFixConsentRequired
        | ErrorCode::DoctorRefreshScopeRequired
        | ErrorCode::DoctorRefreshTimeoutWithoutRefresh
        | ErrorCode::InputRequired => ErrorContract {
            category: ErrorCategory::InvalidRequest,
            retryable: false,
            outcome: match code {
                ErrorCode::SetupConsentRequired => "Setup was not applied.",
                ErrorCode::DoctorFixConsentRequired => "Doctor fix was not applied.",
                _ => "Command input was not accepted.",
            },
            default_recovery: "review satelle --help and retry with valid input",
        },
        ErrorCode::Interrupted => ErrorContract {
            category: ErrorCategory::Interrupted,
            retryable: true,
            outcome: "The attached command was interrupted.",
            default_recovery: "rerun the command or inspect the Session status",
        },
        ErrorCode::CertificateUntrusted
        | ErrorCode::CertificateHostnameMismatch
        | ErrorCode::CertificateExpired
        | ErrorCode::TlsVersionUnsupported
        | ErrorCode::TlsHandshakeFailed
        | ErrorCode::HostIdentityMismatch => ErrorContract {
            category: ErrorCategory::RemoteExecution,
            retryable: false,
            outcome: "The Host identity or secure connection was not accepted.",
            default_recovery: "verify the Host identity and TLS configuration, then retry",
        },
        ErrorCode::ConfigError
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
        | ErrorCode::DaemonPathOverrideNotAbsolute => ErrorContract {
            category: ErrorCategory::InvalidRequest,
            retryable: false,
            outcome: "The Satelle configuration was not accepted.",
            default_recovery: "run satelle config check, correct the configuration, and retry",
        },
        ErrorCode::CompletionInstallFailed | ErrorCode::CompletionProfileUpdateFailed => {
            ErrorContract {
                category: ErrorCategory::Internal,
                retryable: false,
                outcome: "Satelle could not install the requested shell integration.",
                default_recovery: "correct the reported filesystem problem and retry the command",
            }
        }
        ErrorCode::PlatformDirectoriesUnavailable => ErrorContract {
            category: ErrorCategory::Internal,
            retryable: false,
            outcome: "Satelle could not resolve the platform directories.",
            default_recovery: "configure the required platform directory and retry the command",
        },
        ErrorCode::NotImplemented => ErrorContract {
            category: ErrorCategory::Internal,
            retryable: false,
            outcome: "Satelle could not complete the command.",
            default_recovery: "run satelle doctor and report the typed error if the problem remains",
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    fn error_with_code(code: ErrorCode) -> SatelleError {
        SatelleError {
            code,
            message: "representative process failure".to_string(),
            recovery_command: None,
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    #[test]
    fn broad_process_exit_classes_are_stable_at_the_cli_boundary() {
        for (code, expected) in [
            (ErrorCode::InvalidUsage, 64),
            (ErrorCode::ConcurrencyLimitExceeded, 64),
            (ErrorCode::ConfigError, 66),
            (ErrorCode::HostUnreachable, 69),
            (ErrorCode::ComputerUseNotReady, 75),
            (ErrorCode::RemoteExecution, 74),
            (ErrorCode::CompletionInstallFailed, 73),
            (ErrorCode::AuthenticationFailed, 74),
            (ErrorCode::CertificateUntrusted, 74),
            (ErrorCode::StorageIntegrityFailed, 74),
            (ErrorCode::DoctorFixConsentRequired, 64),
            (ErrorCode::Interrupted, 130),
            (ErrorCode::NotImplemented, 70),
        ] {
            assert_eq!(
                process_exit_code(&error_with_code(code)),
                ExitCode::from(expected),
                "unexpected process exit for {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn human_errors_lead_with_outcome_and_end_with_recovery() {
        let error = SatelleError {
            code: ErrorCode::SetupConsentRequired,
            message: "setup requires explicit consent".to_string(),
            recovery_command: Some("satelle setup --yes".to_string()),
            source_detail: None,
            details: BTreeMap::from([("mutated".to_string(), json!(false))]),
        };

        assert_eq!(
            human_error(&error),
            [
                "error: Setup was not applied.",
                "cause: setup requires explicit consent [setup-consent-required]",
                "state: No changes were applied.",
                "next: satelle setup --yes",
            ]
            .join("\n")
        );
    }

    #[test]
    fn human_errors_preserve_significant_inline_cause_whitespace() {
        let error = SatelleError::invalid_usage("path 'two  spaces\tand a tab' is invalid");

        assert!(human_error(&error).contains("path 'two  spaces\tand a tab' is invalid"));
    }

    #[test]
    fn configured_error_format_precedes_machine_detection() {
        assert_eq!(
            ErrorFormat::resolve(Some(ErrorFormat::Human), true),
            ErrorFormat::Human
        );
        assert_eq!(
            ErrorFormat::resolve(Some(ErrorFormat::Json), false),
            ErrorFormat::Json
        );
        assert_eq!(ErrorFormat::resolve(None, true), ErrorFormat::Json);
        assert_eq!(ErrorFormat::resolve(None, false), ErrorFormat::Human);
    }

    #[test]
    fn error_envelope_has_a_closed_shape_and_canonical_empty_values() {
        let error = SatelleError {
            code: ErrorCode::InvalidUsage,
            message: "the command could not be parsed".to_string(),
            recovery_command: None,
            source_detail: Some("private parser implementation detail".to_string()),
            details: BTreeMap::new(),
        };

        assert_eq!(
            error_envelope(&error),
            json!({
                "schema_version": "satelle.error.v1",
                "code": "invalid-usage",
                "category": "invalid_request",
                "retryable": false,
                "message": "the command could not be parsed",
                "details": null,
                "docs_url": null,
                "suggested_commands": [],
            })
        );
    }

    #[test]
    fn error_envelope_exposes_actionable_details_but_not_diagnostics() {
        let error = SatelleError {
            code: ErrorCode::HostUnreachable,
            message: "host 'remote' is unreachable".to_string(),
            recovery_command: Some("satelle doctor --scope transport --json".to_string()),
            source_detail: Some("tcp connect failed at private socket address".to_string()),
            details: BTreeMap::from([("host".to_string(), json!("remote"))]),
        };

        let envelope = error_envelope(&error);
        assert_eq!(envelope["details"], json!({"host": "remote"}));
        assert_eq!(
            envelope["suggested_commands"],
            json!(["satelle doctor --scope transport --json"])
        );
        assert_eq!(envelope["category"], "remote_execution");
        assert_eq!(envelope["retryable"], true);
        assert!(envelope.get("source_detail").is_none());
    }

    #[test]
    fn automation_fields_do_not_depend_on_human_copy() {
        let first = SatelleError::invalid_usage("first human explanation");
        let second = SatelleError::invalid_usage("clearer replacement explanation");
        let first = error_envelope(&first);
        let second = error_envelope(&second);

        for field in [
            "schema_version",
            "code",
            "category",
            "retryable",
            "suggested_commands",
        ] {
            assert_eq!(first[field], second[field], "unstable {field}");
        }
        assert_ne!(first["message"], second["message"]);
    }

    #[test]
    fn provider_smoke_timeout_is_retryable_readiness_failure() {
        let contract = error_contract(ErrorCode::ProviderSmokeTestTimeout);
        assert_eq!(contract.category.as_str(), "readiness");
        assert!(contract.retryable);
    }

    #[test]
    fn native_readiness_timeout_is_retryable_readiness_failure() {
        let contract = error_contract(ErrorCode::NativeReadinessTimeout);
        assert_eq!(contract.category.as_str(), "readiness");
        assert!(contract.retryable);
    }

    #[test]
    fn consent_and_interrupt_errors_have_stable_cli_contracts() {
        let doctor_fix = SatelleError::doctor_fix_consent_required(
            &["repair Host state".to_string()],
            "satelle doctor --fix --yes",
        );
        assert_eq!(process_exit_code(&doctor_fix), ExitCode::from(64));
        assert_eq!(
            human_error(&doctor_fix),
            [
                "error: Doctor fix was not applied.",
                "cause: doctor fix has planned mutations that require explicit consent; no changes were applied [doctor-fix-consent-required]",
                "state: No changes were applied.",
                "next: satelle doctor --fix --yes",
            ]
            .join("\n")
        );

        let interrupted = SatelleError::interrupted_attached_command();
        let envelope = error_envelope(&interrupted);
        assert_eq!(process_exit_code(&interrupted), ExitCode::from(130));
        assert_eq!(envelope["code"], "interrupted");
        assert_eq!(envelope["category"], "interrupted");
        assert_eq!(envelope["retryable"], true);
    }

    #[test]
    fn host_trust_errors_are_non_retryable_remote_execution_failures() {
        for code in [
            ErrorCode::CertificateUntrusted,
            ErrorCode::CertificateHostnameMismatch,
            ErrorCode::CertificateExpired,
            ErrorCode::TlsVersionUnsupported,
            ErrorCode::TlsHandshakeFailed,
            ErrorCode::HostIdentityMismatch,
        ] {
            let contract = error_contract(code);
            assert_eq!(contract.category.as_str(), "remote_execution");
            assert!(!contract.retryable);
        }
    }
}
