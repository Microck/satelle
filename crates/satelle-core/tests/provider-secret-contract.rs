use satelle_core::{
    ErrorCode, ProviderAuthValidationOutcome, ProviderSecretProvisioningResult, SatelleError,
    SetupReadinessSummary, SetupReport, SetupSchemaVersion,
};

#[test]
fn packet_13_owns_exact_setup_and_provider_secret_tokens() {
    assert_eq!(
        serde_json::to_value(SetupSchemaVersion::V2).expect("setup schema token should serialize"),
        serde_json::json!("satelle.setup.v2")
    );
    assert_eq!(
        ErrorCode::ProviderSecretSourceRequired.as_str(),
        "provider-secret-source-required"
    );
    assert_eq!(
        ErrorCode::ProviderSecretProvisioningRequired.as_str(),
        "provider-secret-provisioning-required"
    );
    assert_eq!(
        ErrorCode::ProviderSecretOverwriteRequired.as_str(),
        "provider-secret-overwrite-required"
    );
    assert_eq!(
        ErrorCode::ProviderSecretResolutionFailed.as_str(),
        "provider-secret-resolution-failed"
    );
}

#[test]
fn provider_secret_provisioning_validation_status_is_closed() {
    let result =
        ProviderSecretProvisioningResult::file(true, ProviderAuthValidationOutcome::Resolved);
    assert_eq!(
        serde_json::to_value(result).expect("provisioning result should serialize"),
        serde_json::json!({
            "destination_kind": "file",
            "overwritten": true,
            "validation_status": "resolved"
        })
    );

    let unknown_status = serde_json::json!({
        "destination_kind": "file",
        "overwritten": false,
        "validation_status": "unknown_future_status"
    });
    assert!(
        serde_json::from_value::<ProviderSecretProvisioningResult>(unknown_status).is_err(),
        "unknown validation status tokens must fail closed"
    );
}

#[test]
fn setup_verification_failure_preserves_or_derives_recovery_command() {
    let supplied = "satelle doctor --host workstation --scope provider --json";
    let supplied_report = setup_report("workstation", vec![supplied.to_string()]);
    assert_eq!(
        SatelleError::setup_verification_failed(&supplied_report)
            .recovery_command
            .as_deref(),
        Some(supplied)
    );

    let fallback_report = setup_report("remote-host", Vec::new());
    assert_eq!(
        SatelleError::setup_verification_failed(&fallback_report)
            .recovery_command
            .as_deref(),
        Some("satelle doctor --host remote-host --scope all --json")
    );
}

fn setup_report(host: &str, recovery_commands: Vec<String>) -> SetupReport {
    SetupReport {
        schema_version: SetupSchemaVersion::V2,
        host: host.to_string(),
        dry_run: false,
        status: "verification_failed".to_string(),
        cancellation_reason: None,
        verification: None,
        setup_mode: "managed".to_string(),
        service_persistent: false,
        service_scope: "user".to_string(),
        fallback_reason: None,
        target_platform: None,
        host_artifact: None,
        service_plan: None,
        current_daemon_paths: None,
        planned_daemon_paths: None,
        setup_components: Vec::new(),
        planned_actions: Vec::new(),
        applied_actions: Vec::new(),
        required_input: Vec::new(),
        recovery_commands,
        readiness_summary: SetupReadinessSummary {
            transport: "unknown".to_string(),
            host_daemon: "unknown".to_string(),
            codex_runtime: "unknown".to_string(),
            native_computer_use: "unknown".to_string(),
            provider_auth: "unknown".to_string(),
        },
        descriptor_configured: false,
        secret_provisioned: false,
        validation_status: "failed".to_string(),
        provider_smoke_test_status: "not_run".to_string(),
        daemon_path_overrides: Vec::new(),
        changed: false,
        mutated: false,
        mutation_planned: false,
        native_computer_use_readiness: "unknown".to_string(),
        next_command: "satelle doctor".to_string(),
    }
}
