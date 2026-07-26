use satelle_core::{ErrorCode, SetupSchemaVersion};

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
}
