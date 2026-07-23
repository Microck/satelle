use super::session::ApiRequestContract;
use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_core::{
    ProviderAuthObservationSource, ProviderAuthValidationMode, ProviderAuthValidationOutcome,
    ProviderAuthValidationResult, ProviderBindingAuthorization, PublicProviderDescriptorValidation,
    PublicResolvedProviderBinding,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const DURABLE_SETUP_PENDING_TTL: time::Duration = time::Duration::minutes(5);

define_schema_token!(DurableTokenIssuanceSchema, "satelle.setup-api-token.v1");
define_schema_token!(
    DurableTokenConfirmationSchema,
    "satelle.setup-api-token-confirmation.v1"
);
define_schema_token!(
    DurableTokenActivationSchema,
    "satelle.setup-api-token-activation.v1"
);
define_schema_token!(
    BootstrapMaintenanceSchema,
    "satelle.bootstrap-maintenance.v1"
);
define_schema_token!(
    ProviderBindingAuthorizationSchema,
    "satelle.provider-binding-authorization.v1"
);
define_schema_token!(
    ProviderBindingAuthorizationResponseSchema,
    "satelle.provider-binding-authorization-response.v1"
);
define_schema_token!(
    ProviderBindingDeletionResponseSchema,
    "satelle.provider-binding-deletion-response.v1"
);
define_schema_token!(
    ProviderDescriptorValidationSchema,
    "satelle.provider-binding-validation.v3"
);
define_schema_token!(
    ProviderDescriptorValidationResponseSchema,
    "satelle.provider-binding-validation-response.v3"
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBindingAuthorizationRequest {
    schema_version: ProviderBindingAuthorizationSchema,
    #[serde(flatten)]
    authorization: ProviderBindingAuthorization,
}

impl ProviderBindingAuthorizationRequest {
    pub fn new(authorization: ProviderBindingAuthorization) -> Self {
        Self {
            schema_version: ProviderBindingAuthorizationSchema,
            authorization,
        }
    }

    pub fn authorization(&self) -> &ProviderBindingAuthorization {
        &self.authorization
    }

    pub fn into_authorization(self) -> ProviderBindingAuthorization {
        self.authorization
    }
}

impl ApiRequestContract for ProviderBindingAuthorizationRequest {
    const SCHEMA_VERSION: &'static str = ProviderBindingAuthorizationSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptorValidationRequest {
    schema_version: ProviderDescriptorValidationSchema,
    mode: ProviderAuthValidationMode,
}

impl ProviderDescriptorValidationRequest {
    pub fn new(mode: ProviderAuthValidationMode) -> Self {
        Self {
            schema_version: ProviderDescriptorValidationSchema,
            mode,
        }
    }

    pub const fn mode(&self) -> ProviderAuthValidationMode {
        self.mode
    }
}

impl ApiRequestContract for ProviderDescriptorValidationRequest {
    const SCHEMA_VERSION: &'static str = ProviderDescriptorValidationSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBindingAuthorizationResponse {
    schema_version: ProviderBindingAuthorizationResponseSchema,
    request_id: RequestId,
    host_identity: String,
    binding: PublicResolvedProviderBinding,
}

impl ProviderBindingAuthorizationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        binding: PublicResolvedProviderBinding,
    ) -> Self {
        Self {
            schema_version: ProviderBindingAuthorizationResponseSchema,
            request_id,
            host_identity,
            binding,
        }
    }

    pub fn binding(&self) -> &PublicResolvedProviderBinding {
        &self.binding
    }
}

impl AuthenticatedResponseContract for ProviderBindingAuthorizationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBindingDeletionResponse {
    schema_version: ProviderBindingDeletionResponseSchema,
    request_id: RequestId,
    host_identity: String,
    deleted: bool,
}

impl ProviderBindingDeletionResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String, deleted: bool) -> Self {
        Self {
            schema_version: ProviderBindingDeletionResponseSchema,
            request_id,
            host_identity,
            deleted,
        }
    }

    pub const fn deleted(&self) -> bool {
        self.deleted
    }
}

impl AuthenticatedResponseContract for ProviderBindingDeletionResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptorValidationResponse {
    schema_version: ProviderDescriptorValidationResponseSchema,
    request_id: RequestId,
    host_identity: String,
    resolved_binding: PublicResolvedProviderBinding,
    validation: ProviderAuthValidationResult,
}

impl ProviderDescriptorValidationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        result: &PublicProviderDescriptorValidation,
    ) -> Self {
        Self {
            schema_version: ProviderDescriptorValidationResponseSchema,
            request_id,
            host_identity,
            resolved_binding: result.resolved_binding().clone(),
            validation: result.validation(),
        }
    }

    pub fn resolved_binding(&self) -> &PublicResolvedProviderBinding {
        &self.resolved_binding
    }

    pub fn model(&self) -> &str {
        self.resolved_binding.model()
    }

    pub fn model_provider(&self) -> &str {
        self.resolved_binding.model_provider()
    }

    pub const fn outcome(&self) -> ProviderAuthValidationOutcome {
        self.validation.outcome()
    }

    pub const fn observation_source(&self) -> ProviderAuthObservationSource {
        self.validation.observation_source()
    }

    pub const fn validation(&self) -> ProviderAuthValidationResult {
        self.validation
    }
}

impl AuthenticatedResponseContract for ProviderDescriptorValidationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapMaintenanceResponse {
    schema_version: BootstrapMaintenanceSchema,
    request_id: RequestId,
    host_identity: String,
    operation_id: String,
    reconciled: bool,
}

impl BootstrapMaintenanceResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String, operation_id: String) -> Self {
        Self {
            schema_version: BootstrapMaintenanceSchema,
            request_id,
            host_identity,
            operation_id,
            reconciled: true,
        }
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn reconciled(&self) -> bool {
        self.reconciled
    }
}

impl AuthenticatedResponseContract for BootstrapMaintenanceResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Serialize, Deserialize)]
pub struct DurableTokenIssuanceResponse {
    schema_version: DurableTokenIssuanceSchema,
    request_id: RequestId,
    host_identity: String,
    token_id: String,
    bearer_token: Option<String>,
    pending_expires_at: String,
}

impl DurableTokenIssuanceResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        token_id: String,
        bearer_token: Option<String>,
        pending_expires_at: String,
    ) -> Self {
        Self {
            schema_version: DurableTokenIssuanceSchema,
            request_id,
            host_identity,
            token_id,
            bearer_token,
            pending_expires_at,
        }
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub fn pending_expires_at(&self) -> &str {
        &self.pending_expires_at
    }

    /// Moves the one-time bearer value directly into zeroizing storage.
    pub fn into_bearer_token(mut self) -> Option<Zeroizing<String>> {
        self.bearer_token.take().map(Zeroizing::new)
    }
}

impl fmt::Debug for DurableTokenIssuanceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableTokenIssuanceResponse")
            .field("request_id", &self.request_id)
            .field("host_identity", &self.host_identity)
            .field("token_id", &self.token_id)
            .field("pending_expires_at", &self.pending_expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for DurableTokenIssuanceResponse {
    fn drop(&mut self) {
        self.bearer_token.zeroize();
    }
}

impl AuthenticatedResponseContract for DurableTokenIssuanceResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableTokenConfirmationResponse {
    schema_version: DurableTokenConfirmationSchema,
    request_id: RequestId,
    host_identity: String,
    token_id: String,
    setup_active: bool,
    control_scoped: bool,
}

impl DurableTokenConfirmationResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String, token_id: String) -> Self {
        Self {
            schema_version: DurableTokenConfirmationSchema,
            request_id,
            host_identity,
            token_id,
            setup_active: true,
            control_scoped: true,
        }
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub const fn setup_active(&self) -> bool {
        self.setup_active
    }

    pub const fn control_scoped(&self) -> bool {
        self.control_scoped
    }
}

impl AuthenticatedResponseContract for DurableTokenConfirmationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableTokenActivationResponse {
    schema_version: DurableTokenActivationSchema,
    request_id: RequestId,
    host_identity: String,
    token_id: String,
    active: bool,
}

impl DurableTokenActivationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        token_id: String,
        active: bool,
    ) -> Self {
        Self {
            schema_version: DurableTokenActivationSchema,
            request_id,
            host_identity,
            token_id,
            active,
        }
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub const fn active(&self) -> bool {
        self.active
    }
}

impl AuthenticatedResponseContract for DurableTokenActivationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[cfg(test)]
mod provider_binding_contract_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authorization_is_explicit_and_validation_is_alias_scoped() {
        let authorization = ProviderBindingAuthorizationRequest::new(
            ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai")
                .with_experimental_provider_computer_use(true),
        );
        assert_eq!(
            serde_json::to_value(authorization).unwrap(),
            json!({
                "schema_version": "satelle.provider-binding-authorization.v1",
                "requested_model_alias": "vision",
                "requested_provider_alias": "open_ai",
                "model": "gpt-5.6",
                "model_provider": "openai",
                "experimental_provider_computer_use": true
            })
        );

        assert_eq!(
            serde_json::to_value(ProviderDescriptorValidationRequest::new(
                ProviderAuthValidationMode::RefreshProviderSmoke,
            ))
            .unwrap(),
            json!({
                "schema_version": "satelle.provider-binding-validation.v3",
                "mode": "refresh_provider_smoke"
            })
        );
    }

    #[test]
    fn validation_rejects_caller_binding_material() {
        let request = json!({
            "schema_version": "satelle.provider-binding-validation.v3",
            "mode": "cached",
            "endpoint": "https://attacker.example"
        });
        assert!(serde_json::from_value::<ProviderDescriptorValidationRequest>(request).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_schema_is_exact_and_the_secret_moves_into_zeroizing_storage() {
        let response = DurableTokenIssuanceResponse::new(
            RequestId::new(),
            "host-test".to_string(),
            "token-test".to_string(),
            Some("satelle_v1.token-test.secret".to_string()),
            "2026-07-17T12:00:00Z".to_string(),
        );
        let encoded = serde_json::to_value(&response).expect("encode issuance response");
        assert_eq!(encoded["schema_version"], "satelle.setup-api-token.v1");
        assert_eq!(
            response
                .into_bearer_token()
                .expect("first issuance carries the secret")
                .as_str(),
            "satelle_v1.token-test.secret"
        );
    }

    #[test]
    fn confirmation_schema_explicitly_proves_setup_state_and_scope() {
        let response = DurableTokenConfirmationResponse::new(
            RequestId::new(),
            "host-test".to_string(),
            "token-test".to_string(),
        );
        let encoded = serde_json::to_value(&response).expect("encode confirmation response");
        assert_eq!(
            encoded["schema_version"],
            "satelle.setup-api-token-confirmation.v1"
        );
        assert_eq!(encoded["setup_active"], true);
        assert_eq!(encoded["control_scoped"], true);
    }

    #[test]
    fn bootstrap_maintenance_schema_carries_the_reconciled_operation() {
        let response = BootstrapMaintenanceResponse::new(
            RequestId::new(),
            "host-test".to_string(),
            "bootstrap-operation-1".to_string(),
        );
        let encoded = serde_json::to_value(&response).expect("encode maintenance response");
        assert_eq!(
            encoded["schema_version"],
            "satelle.bootstrap-maintenance.v1"
        );
        assert_eq!(encoded["operation_id"], "bootstrap-operation-1");
        assert_eq!(encoded["reconciled"], true);
    }
}
