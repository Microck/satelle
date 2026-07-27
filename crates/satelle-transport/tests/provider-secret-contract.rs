use satelle_core::{ProviderBindingAuthorization, ProviderSecretSource};
use satelle_host::ApiBearerToken;
use satelle_transport::{
    DaemonClient, PreparedProviderSecretProvisioning, ProviderSecretProvisioningMetadata,
    ProviderSecretProvisioningPreviewResponse, ProviderSecretProvisioningResponse,
};
use serde_json::json;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[test]
fn provisioning_metadata_is_versioned_and_carries_no_raw_secret_field() {
    let metadata = ProviderSecretProvisioningMetadata::new(
        ProviderBindingAuthorization::new("vision", "open_ai", "gpt-image", "openai")
            .with_auth_source(ProviderSecretSource::File {
                path: PathBuf::from("/run/secrets/openai"),
            }),
        true,
    );
    let value = serde_json::to_value(metadata).expect("metadata should serialize");

    assert_eq!(
        value["schema_version"],
        "satelle.provider-secret-provisioning.v1"
    );
    assert_eq!(value["overwrite_authorized"], true);
    assert!(value.get("secret").is_none());
    assert!(value.get("value").is_none());
}

#[test]
fn provisioning_metadata_rejects_unknown_secret_carriers() {
    let value = json!({
        "schema_version": "satelle.provider-secret-provisioning.v1",
        "authorization": {
            "requested_model_alias": "vision",
            "requested_provider_alias": "open_ai",
            "model": "gpt-image",
            "model_provider": "openai",
            "auth_source": {
                "kind": "file",
                "path": "/run/secrets/openai"
            },
            "allow_project_selection": false,
            "experimental_provider_computer_use": false
        },
        "overwrite_authorized": false,
        "secret": "must-not-enter-json"
    });

    assert!(serde_json::from_value::<ProviderSecretProvisioningMetadata>(value).is_err());
}

#[test]
fn provisioning_response_schema_has_no_secret_carrier() {
    let value = json!({
        "schema_version": "satelle.provider-secret-provisioning-response.v1",
        "request_id": "0195f6d5-18da-7a80-8000-000000000001",
        "host_identity": "host-test",
        "destination_kind": "file",
        "provisioned": true,
        "overwritten": false,
        "validation_status": "resolved"
    });
    let response: ProviderSecretProvisioningResponse =
        serde_json::from_value(value).expect("redacted response should decode");
    let encoded = serde_json::to_value(response).expect("redacted response should encode");

    assert!(encoded.get("secret").is_none());
    assert!(encoded.get("value").is_none());
}

#[test]
fn preview_response_contains_only_metadata_and_ephemeral_upload_grant() {
    let value = json!({
        "schema_version": "satelle.provider-secret-provisioning-preview-response.v2",
        "request_id": "0195f6d5-18da-7a80-8000-000000000001",
        "host_identity": "host-test",
        "destination_kind": "file",
        "persistence_location_class": "host_private_file",
        "overwrite_behavior": "reject_existing_without_explicit_authorization",
        "upload_id": "0195f6d5-18da-7a80-8000-000000000002",
        "recipient_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "expires_at": "2026-07-27T02:10:00Z"
    });
    let response: ProviderSecretProvisioningPreviewResponse =
        serde_json::from_value(value).expect("metadata-only preview should decode");
    let encoded = serde_json::to_value(response).expect("metadata-only preview should encode");

    assert_eq!(encoded["destination_kind"], "file");
    assert_eq!(encoded["persistence_location_class"], "host_private_file");
    assert_eq!(
        encoded["overwrite_behavior"],
        "reject_existing_without_explicit_authorization"
    );
    assert!(encoded.get("destination_exists").is_none());
    assert!(encoded.get("overwrite_required").is_none());
    assert!(encoded.get("path").is_none());
}

#[test]
fn prepared_provider_secret_debug_is_fully_redacted() {
    let preview: ProviderSecretProvisioningPreviewResponse = serde_json::from_value(json!({
        "schema_version": "satelle.provider-secret-provisioning-preview-response.v2",
        "request_id": "0195f6d5-18da-7a80-8000-000000000001",
        "host_identity": "host-debug-redaction-marker",
        "destination_kind": "file",
        "persistence_location_class": "host_private_file",
        "overwrite_behavior": "reject_existing_without_explicit_authorization",
        "upload_id": "0195f6d5-18da-7a80-8000-000000000002",
        "recipient_public_key": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
        "expires_at": "2099-07-27T02:10:00Z"
    }))
    .expect("provider-secret preview should decode");
    let metadata = ProviderSecretProvisioningMetadata::new(
        ProviderBindingAuthorization::new(
            "model-debug-redaction-marker",
            "provider-debug-redaction-marker",
            "gpt-image",
            "openai",
        )
        .with_auth_source(ProviderSecretSource::File {
            path: PathBuf::from("/run/secrets/debug-redaction-marker"),
        }),
        true,
    );
    let client = DaemonClient::loopback(
        "127.0.0.1:1"
            .parse()
            .expect("loopback fixture address should parse"),
        ApiBearerToken::generate().expect("generate client token"),
        "host-debug-redaction-marker",
    )
    .expect("construct loopback client");
    let prepared: PreparedProviderSecretProvisioning = client
        .prepare_provider_secret_provisioning(
            &preview,
            &metadata,
            Zeroizing::new(b"provider-secret-debug-redaction-marker".to_vec()),
            "idempotency-debug-redaction-marker",
        )
        .expect("prepare provider-secret upload");

    assert_eq!(
        format!("{prepared:?}"),
        "PreparedProviderSecretProvisioning { .. }"
    );
}
