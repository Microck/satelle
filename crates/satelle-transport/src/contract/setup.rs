use super::session::ApiRequestContract;
use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_core::{
    DoctorReport, ProviderAuthObservationSource, ProviderAuthValidationMode,
    ProviderAuthValidationOutcome, ProviderAuthValidationResult, ProviderBindingAuthorization,
    PublicProviderDescriptorValidation, PublicResolvedProviderBinding,
    host_update::HostUpdateRecoveryIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    HostUpdateMaintenanceSchema,
    "satelle.host-update-maintenance.v1"
);
define_schema_token!(RepairMaintenanceSchema, "satelle.repair-maintenance.v1");
define_schema_token!(
    ProviderBindingAuthorizationSchema,
    "satelle.provider-binding-authorization.v2"
);
define_schema_token!(
    ProviderBindingAuthorizationResponseSchema,
    "satelle.provider-binding-authorization-response.v2"
);
define_schema_token!(
    ProviderBindingDeletionResponseSchema,
    "satelle.provider-binding-deletion-response.v1"
);
define_schema_token!(
    ProviderDescriptorValidationSchema,
    "satelle.provider-binding-validation.v5"
);
define_schema_token!(
    ProviderDescriptorValidationResponseSchema,
    "satelle.provider-binding-validation-response.v4"
);
define_schema_token!(
    ProviderSecretProvisioningSchema,
    "satelle.provider-secret-provisioning.v1"
);
define_schema_token!(
    ProviderSecretProvisioningResponseSchema,
    "satelle.provider-secret-provisioning-response.v1"
);
define_schema_token!(
    ProviderSecretProvisioningPreviewResponseSchema,
    "satelle.provider-secret-provisioning-preview-response.v2"
);
define_schema_token!(
    ProviderSecretUploadEnvelopeSchema,
    "satelle.provider-secret-upload.v2"
);
define_schema_token!(SetupVerificationSchema, "satelle.setup-verification.v1");
define_schema_token!(
    SetupVerificationResponseSchema,
    "satelle.setup-verification-response.v1"
);
define_schema_token!(
    NativeReadinessInvalidationSchema,
    "satelle.native-readiness-invalidation.v2"
);
define_schema_token!(
    NativeReadinessInvalidationResponseSchema,
    "satelle.native-readiness-invalidation-response.v1"
);
define_schema_token!(SetupRepairPlanSchema, "satelle.setup-repair-plan.v1");
define_schema_token!(
    SetupRepairPlanResponseSchema,
    "satelle.setup-repair-plan-response.v2"
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupRepairPostcondition {
    Satisfied,
    Unsatisfied,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRepairProbe {
    pub action_id: String,
    pub label: String,
    pub retry_safe: bool,
    pub postcondition: SetupRepairPostcondition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostUpdateMaintenanceRequest {
    schema_version: HostUpdateMaintenanceSchema,
    recovery_identity: HostUpdateRecoveryIdentity,
}

impl HostUpdateMaintenanceRequest {
    pub fn new(recovery_identity: HostUpdateRecoveryIdentity) -> Self {
        Self {
            schema_version: HostUpdateMaintenanceSchema,
            recovery_identity,
        }
    }

    pub fn recovery_identity(&self) -> &HostUpdateRecoveryIdentity {
        &self.recovery_identity
    }
}

impl ApiRequestContract for HostUpdateMaintenanceRequest {
    const SCHEMA_VERSION: &'static str = HostUpdateMaintenanceSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepairMaintenanceRequest {
    schema_version: RepairMaintenanceSchema,
    recovery_identity: HostUpdateRecoveryIdentity,
}

impl RepairMaintenanceRequest {
    pub fn new(recovery_identity: HostUpdateRecoveryIdentity) -> Self {
        Self {
            schema_version: RepairMaintenanceSchema,
            recovery_identity,
        }
    }

    pub fn recovery_identity(&self) -> &HostUpdateRecoveryIdentity {
        &self.recovery_identity
    }
}

impl ApiRequestContract for RepairMaintenanceRequest {
    const SCHEMA_VERSION: &'static str = RepairMaintenanceSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRepairPlanRequest {
    schema_version: SetupRepairPlanSchema,
    run_id: Option<String>,
    probes: Vec<SetupRepairProbe>,
}

impl SetupRepairPlanRequest {
    pub fn new(run_id: Option<String>, probes: Vec<SetupRepairProbe>) -> Self {
        Self {
            schema_version: SetupRepairPlanSchema,
            run_id,
            probes,
        }
    }

    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    pub fn probes(&self) -> &[SetupRepairProbe] {
        &self.probes
    }
}

impl ApiRequestContract for SetupRepairPlanRequest {
    const SCHEMA_VERSION: &'static str = SetupRepairPlanSchema::TOKEN;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupRepairDecision {
    NoActionRequired,
    RetryAutomatically,
    OperatorActionRequired,
    ProbeRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupRepairPreviousStatus {
    Planned,
    Started,
    Completed,
    Failed,
    Skipped,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupRepairOperationKind {
    Setup,
    Repair,
    HostUpdate,
    StorageMigration,
    ServiceStop,
    ServiceRestart,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupRepairRunStatus {
    Running,
    Completed,
    Failed,
    PartialFailure,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRepairPlanAction {
    pub action_id: String,
    pub label: String,
    pub decision: SetupRepairDecision,
    pub retry_safe: bool,
    pub previous_run_id: Option<String>,
    pub previous_status: Option<SetupRepairPreviousStatus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRepairPlanResponse {
    schema_version: SetupRepairPlanResponseSchema,
    request_id: RequestId,
    host_identity: String,
    ledger_available: bool,
    selected_operation_kind: Option<SetupRepairOperationKind>,
    selected_run_status: Option<SetupRepairRunStatus>,
    host_update_recovery_identity: Option<HostUpdateRecoveryIdentity>,
    actions: Vec<SetupRepairPlanAction>,
}

impl SetupRepairPlanResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        selected_operation_kind: Option<SetupRepairOperationKind>,
        selected_run_status: Option<SetupRepairRunStatus>,
        host_update_recovery_identity: Option<HostUpdateRecoveryIdentity>,
        actions: Vec<SetupRepairPlanAction>,
    ) -> Self {
        let ledger_available = selected_operation_kind.is_some()
            || actions
                .iter()
                .any(|action| action.previous_run_id.is_some());
        Self {
            schema_version: SetupRepairPlanResponseSchema,
            request_id,
            host_identity,
            ledger_available,
            selected_operation_kind,
            selected_run_status,
            host_update_recovery_identity,
            actions,
        }
    }

    pub const fn ledger_available(&self) -> bool {
        self.ledger_available
    }

    pub const fn selected_operation_kind(&self) -> Option<SetupRepairOperationKind> {
        self.selected_operation_kind
    }

    pub const fn selected_run_status(&self) -> Option<SetupRepairRunStatus> {
        self.selected_run_status
    }

    pub fn host_update_recovery_identity(&self) -> Option<&HostUpdateRecoveryIdentity> {
        self.host_update_recovery_identity.as_ref()
    }

    pub fn actions(&self) -> &[SetupRepairPlanAction] {
        &self.actions
    }
}

impl AuthenticatedResponseContract for SetupRepairPlanResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderBindingAuthorizationRequest {
    schema_version: ProviderBindingAuthorizationSchema,
    #[serde(flatten)]
    authorization: ProviderBindingAuthorization,
}

const PROVIDER_BINDING_AUTHORIZATION_REQUEST_FIELDS: &[&str] = &[
    "schema_version",
    "requested_model_alias",
    "requested_provider_alias",
    "model",
    "model_provider",
    "endpoint",
    "auth_source",
    "allow_project_selection",
    "experimental_provider_computer_use",
];

impl<'de> Deserialize<'de> for ProviderBindingAuthorizationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        if let Some(unknown) = fields
            .keys()
            .find(|field| !PROVIDER_BINDING_AUTHORIZATION_REQUEST_FIELDS.contains(&field.as_str()))
        {
            return Err(serde::de::Error::unknown_field(
                unknown,
                PROVIDER_BINDING_AUTHORIZATION_REQUEST_FIELDS,
            ));
        }
        if !fields.contains_key("allow_project_selection") {
            return Err(serde::de::Error::missing_field("allow_project_selection"));
        }

        #[derive(Deserialize)]
        struct WireRequest {
            schema_version: ProviderBindingAuthorizationSchema,
            #[serde(flatten)]
            authorization: ProviderBindingAuthorization,
        }

        let request: WireRequest =
            serde_json::from_value(Value::Object(fields)).map_err(serde::de::Error::custom)?;
        Ok(Self {
            schema_version: request.schema_version,
            authorization: request.authorization,
        })
    }
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
pub struct ProviderSecretProvisioningMetadata {
    schema_version: ProviderSecretProvisioningSchema,
    authorization: ProviderBindingAuthorization,
    overwrite_authorized: bool,
}

impl ProviderSecretProvisioningMetadata {
    pub fn new(authorization: ProviderBindingAuthorization, overwrite_authorized: bool) -> Self {
        Self {
            schema_version: ProviderSecretProvisioningSchema,
            authorization,
            overwrite_authorized,
        }
    }

    pub fn authorization(&self) -> &ProviderBindingAuthorization {
        &self.authorization
    }

    pub fn into_authorization(self) -> ProviderBindingAuthorization {
        self.authorization
    }

    pub const fn overwrite_authorized(&self) -> bool {
        self.overwrite_authorized
    }
}

impl ApiRequestContract for ProviderSecretProvisioningMetadata {
    const SCHEMA_VERSION: &'static str = ProviderSecretProvisioningSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSecretProvisioningPreviewResponse {
    schema_version: ProviderSecretProvisioningPreviewResponseSchema,
    request_id: RequestId,
    host_identity: String,
    destination_kind: String,
    persistence_location_class: String,
    overwrite_behavior: String,
    upload_id: String,
    recipient_public_key: String,
    expires_at: String,
}

impl ProviderSecretProvisioningPreviewResponse {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        destination_kind: impl Into<String>,
        persistence_location_class: impl Into<String>,
        overwrite_behavior: impl Into<String>,
        upload_id: impl Into<String>,
        recipient_public_key: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: ProviderSecretProvisioningPreviewResponseSchema,
            request_id,
            host_identity,
            destination_kind: destination_kind.into(),
            persistence_location_class: persistence_location_class.into(),
            overwrite_behavior: overwrite_behavior.into(),
            upload_id: upload_id.into(),
            recipient_public_key: recipient_public_key.into(),
            expires_at: expires_at.into(),
        }
    }

    pub fn destination_kind(&self) -> &str {
        &self.destination_kind
    }

    pub fn persistence_location_class(&self) -> &str {
        &self.persistence_location_class
    }

    pub fn overwrite_behavior(&self) -> &str {
        &self.overwrite_behavior
    }

    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    pub fn recipient_public_key(&self) -> &str {
        &self.recipient_public_key
    }

    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

impl AuthenticatedResponseContract for ProviderSecretProvisioningPreviewResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSecretUploadEnvelope {
    schema_version: ProviderSecretUploadEnvelopeSchema,
    upload_id: String,
    host_identity: String,
    expires_at: String,
    metadata: ProviderSecretProvisioningMetadata,
    encapsulated_key: String,
    ciphertext: String,
}

impl ProviderSecretUploadEnvelope {
    pub(crate) fn new(
        preview: &ProviderSecretProvisioningPreviewResponse,
        metadata: ProviderSecretProvisioningMetadata,
        encapsulated_key: String,
        ciphertext: String,
    ) -> Self {
        Self {
            schema_version: ProviderSecretUploadEnvelopeSchema,
            upload_id: preview.upload_id.clone(),
            host_identity: preview.host_identity.clone(),
            expires_at: preview.expires_at.clone(),
            metadata,
            encapsulated_key,
            ciphertext,
        }
    }

    pub fn upload_id(&self) -> &str {
        &self.upload_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    pub fn metadata(&self) -> &ProviderSecretProvisioningMetadata {
        &self.metadata
    }

    pub fn encapsulated_key(&self) -> &str {
        &self.encapsulated_key
    }

    pub fn ciphertext(&self) -> &str {
        &self.ciphertext
    }
}

impl Drop for ProviderSecretUploadEnvelope {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

pub(crate) const PROVIDER_SECRET_UPLOAD_CONTENT_TYPE: &str =
    "application/vnd.satelle.provider-secret-upload+json";
pub(crate) const PROVIDER_SECRET_UPLOAD_INFO: &[u8] = b"satelle.provider-secret-upload.v2";

pub(crate) fn provider_secret_upload_aad(
    preview: &ProviderSecretProvisioningPreviewResponse,
    metadata: &ProviderSecretProvisioningMetadata,
    token_id: &str,
    idempotency_key: &str,
) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    let metadata = Zeroizing::new(serde_json::to_vec(metadata)?);
    let mut aad = Zeroizing::new(Vec::new());
    for field in [
        PROVIDER_SECRET_UPLOAD_INFO,
        b"POST",
        b"/v1/setup/provider-secret",
        super::PROTOCOL_VERSION.as_bytes(),
        preview.host_identity().as_bytes(),
        preview.upload_id().as_bytes(),
        token_id.as_bytes(),
        idempotency_key.as_bytes(),
        satelle_core::LOCAL_DEMO_HOST.as_bytes(),
        preview.expires_at().as_bytes(),
        metadata.as_slice(),
    ] {
        let length = u32::try_from(field.len()).unwrap_or(u32::MAX);
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(field);
    }
    Ok(aad)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSecretProvisioningResponse {
    schema_version: ProviderSecretProvisioningResponseSchema,
    request_id: RequestId,
    host_identity: String,
    destination_kind: String,
    provisioned: bool,
    overwritten: bool,
    validation_status: ProviderAuthValidationOutcome,
}

impl ProviderSecretProvisioningResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        destination_kind: impl Into<String>,
        overwritten: bool,
        validation_status: ProviderAuthValidationOutcome,
    ) -> Self {
        Self {
            schema_version: ProviderSecretProvisioningResponseSchema,
            request_id,
            host_identity,
            destination_kind: destination_kind.into(),
            provisioned: true,
            overwritten,
            validation_status,
        }
    }

    pub fn destination_kind(&self) -> &str {
        &self.destination_kind
    }

    pub const fn provisioned(&self) -> bool {
        self.provisioned
    }

    pub const fn overwritten(&self) -> bool {
        self.overwritten
    }

    pub const fn validation_status(&self) -> ProviderAuthValidationOutcome {
        self.validation_status
    }
}

impl AuthenticatedResponseContract for ProviderSecretProvisioningResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDescriptorValidationRequest {
    schema_version: ProviderDescriptorValidationSchema,
    mode: ProviderAuthValidationMode,
    model_from_project: bool,
    provider_from_project: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    experimental_provider_computer_use: bool,
}

impl ProviderDescriptorValidationRequest {
    pub fn new(
        mode: ProviderAuthValidationMode,
        model_from_project: bool,
        provider_from_project: bool,
    ) -> Self {
        Self {
            schema_version: ProviderDescriptorValidationSchema,
            mode,
            model_from_project,
            provider_from_project,
            experimental_provider_computer_use: false,
        }
    }

    pub const fn mode(&self) -> ProviderAuthValidationMode {
        self.mode
    }

    pub const fn model_from_project(&self) -> bool {
        self.model_from_project
    }

    pub const fn provider_from_project(&self) -> bool {
        self.provider_from_project
    }

    pub fn with_experimental_provider_computer_use(mut self, enabled: bool) -> Self {
        self.experimental_provider_computer_use = enabled;
        self
    }

    pub const fn experimental_provider_computer_use(&self) -> bool {
        self.experimental_provider_computer_use
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ApiRequestContract for ProviderDescriptorValidationRequest {
    const SCHEMA_VERSION: &'static str = ProviderDescriptorValidationSchema::TOKEN;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SetupVerificationRequest {
    schema_version: SetupVerificationSchema,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_alias: Option<String>,
    model_from_project: bool,
    provider_from_project: bool,
    experimental_provider_computer_use: bool,
}

impl<'de> Deserialize<'de> for SetupVerificationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            schema_version: SetupVerificationSchema,
            model_alias: Option<String>,
            provider_alias: Option<String>,
            model_from_project: bool,
            provider_from_project: bool,
            experimental_provider_computer_use: bool,
        }

        let request = WireRequest::deserialize(deserializer)?;
        if request.model_alias.is_some() != request.provider_alias.is_some() {
            return Err(serde::de::Error::custom(
                "model_alias and provider_alias must be supplied together",
            ));
        }
        if request.model_alias.as_deref().is_some_and(str::is_empty)
            || request.provider_alias.as_deref().is_some_and(str::is_empty)
        {
            return Err(serde::de::Error::custom(
                "model_alias and provider_alias must be non-empty",
            ));
        }

        Ok(Self {
            schema_version: request.schema_version,
            model_alias: request.model_alias,
            provider_alias: request.provider_alias,
            model_from_project: request.model_from_project,
            provider_from_project: request.provider_from_project,
            experimental_provider_computer_use: request.experimental_provider_computer_use,
        })
    }
}

impl SetupVerificationRequest {
    pub fn new(
        model_alias: Option<String>,
        provider_alias: Option<String>,
        model_from_project: bool,
        provider_from_project: bool,
        experimental_provider_computer_use: bool,
    ) -> Result<Self, &'static str> {
        if model_alias.is_some() != provider_alias.is_some() {
            return Err("model_alias and provider_alias must be supplied together");
        }
        if model_alias.as_deref().is_some_and(str::is_empty)
            || provider_alias.as_deref().is_some_and(str::is_empty)
        {
            return Err("model_alias and provider_alias must be non-empty");
        }
        Ok(Self {
            schema_version: SetupVerificationSchema,
            model_alias,
            provider_alias,
            model_from_project,
            provider_from_project,
            experimental_provider_computer_use,
        })
    }

    pub fn model_alias(&self) -> Option<&str> {
        self.model_alias.as_deref()
    }

    pub fn provider_alias(&self) -> Option<&str> {
        self.provider_alias.as_deref()
    }

    pub const fn model_from_project(&self) -> bool {
        self.model_from_project
    }

    pub const fn provider_from_project(&self) -> bool {
        self.provider_from_project
    }

    pub const fn experimental_provider_computer_use(&self) -> bool {
        self.experimental_provider_computer_use
    }
}

impl ApiRequestContract for SetupVerificationRequest {
    const SCHEMA_VERSION: &'static str = SetupVerificationSchema::TOKEN;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeReadinessInvalidationScope {
    Intent,
    Host,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeReadinessInvalidationRequest {
    schema_version: NativeReadinessInvalidationSchema,
    scope: NativeReadinessInvalidationScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_alias: Option<String>,
    model_from_project: bool,
    provider_from_project: bool,
    experimental_provider_computer_use: bool,
}

impl<'de> Deserialize<'de> for NativeReadinessInvalidationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRequest {
            schema_version: NativeReadinessInvalidationSchema,
            scope: NativeReadinessInvalidationScope,
            model_alias: Option<String>,
            provider_alias: Option<String>,
            model_from_project: bool,
            provider_from_project: bool,
            experimental_provider_computer_use: bool,
        }

        let request = WireRequest::deserialize(deserializer)?;
        if request.model_alias.is_some() != request.provider_alias.is_some() {
            return Err(serde::de::Error::custom(
                "model_alias and provider_alias must be supplied together",
            ));
        }
        if request.model_alias.as_deref().is_some_and(str::is_empty)
            || request.provider_alias.as_deref().is_some_and(str::is_empty)
        {
            return Err(serde::de::Error::custom(
                "model_alias and provider_alias must be non-empty",
            ));
        }
        if request.scope == NativeReadinessInvalidationScope::Host
            && (request.model_alias.is_some()
                || request.provider_alias.is_some()
                || request.model_from_project
                || request.provider_from_project
                || request.experimental_provider_computer_use)
        {
            return Err(serde::de::Error::custom(
                "host-wide native readiness invalidation cannot select provider intent",
            ));
        }

        Ok(Self {
            schema_version: request.schema_version,
            scope: request.scope,
            model_alias: request.model_alias,
            provider_alias: request.provider_alias,
            model_from_project: request.model_from_project,
            provider_from_project: request.provider_from_project,
            experimental_provider_computer_use: request.experimental_provider_computer_use,
        })
    }
}

impl NativeReadinessInvalidationRequest {
    pub fn new(
        model_alias: Option<String>,
        provider_alias: Option<String>,
        model_from_project: bool,
        provider_from_project: bool,
        experimental_provider_computer_use: bool,
    ) -> Result<Self, &'static str> {
        if model_alias.is_some() != provider_alias.is_some() {
            return Err("model_alias and provider_alias must be supplied together");
        }
        if model_alias.as_deref().is_some_and(str::is_empty)
            || provider_alias.as_deref().is_some_and(str::is_empty)
        {
            return Err("model_alias and provider_alias must be non-empty");
        }
        Ok(Self {
            schema_version: NativeReadinessInvalidationSchema,
            scope: NativeReadinessInvalidationScope::Intent,
            model_alias,
            provider_alias,
            model_from_project,
            provider_from_project,
            experimental_provider_computer_use,
        })
    }

    pub fn host() -> Self {
        Self {
            schema_version: NativeReadinessInvalidationSchema,
            scope: NativeReadinessInvalidationScope::Host,
            model_alias: None,
            provider_alias: None,
            model_from_project: false,
            provider_from_project: false,
            experimental_provider_computer_use: false,
        }
    }

    pub const fn scope(&self) -> NativeReadinessInvalidationScope {
        self.scope
    }

    pub fn model_alias(&self) -> Option<&str> {
        self.model_alias.as_deref()
    }

    pub fn provider_alias(&self) -> Option<&str> {
        self.provider_alias.as_deref()
    }

    pub const fn model_from_project(&self) -> bool {
        self.model_from_project
    }

    pub const fn provider_from_project(&self) -> bool {
        self.provider_from_project
    }

    pub const fn experimental_provider_computer_use(&self) -> bool {
        self.experimental_provider_computer_use
    }
}

impl ApiRequestContract for NativeReadinessInvalidationRequest {
    const SCHEMA_VERSION: &'static str = NativeReadinessInvalidationSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupVerificationResponse {
    schema_version: SetupVerificationResponseSchema,
    request_id: RequestId,
    host_identity: String,
    verification: DoctorReport,
}

impl SetupVerificationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        verification: DoctorReport,
    ) -> Self {
        Self {
            schema_version: SetupVerificationResponseSchema,
            request_id,
            host_identity,
            verification,
        }
    }

    pub fn verification(&self) -> &DoctorReport {
        &self.verification
    }
}

impl AuthenticatedResponseContract for SetupVerificationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReadinessInvalidationResponse {
    schema_version: NativeReadinessInvalidationResponseSchema,
    request_id: RequestId,
    host_identity: String,
    deleted: u64,
}

impl NativeReadinessInvalidationResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String, deleted: u64) -> Self {
        Self {
            schema_version: NativeReadinessInvalidationResponseSchema,
            request_id,
            host_identity,
            deleted,
        }
    }

    pub const fn deleted(&self) -> u64 {
        self.deleted
    }
}

impl AuthenticatedResponseContract for NativeReadinessInvalidationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedSetupActionResponse {
    schema_version: BootstrapMaintenanceSchema,
    request_id: RequestId,
    host_identity: String,
    operation_id: String,
    reconciled: bool,
    changed: bool,
}

impl ManagedSetupActionResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        operation_id: String,
        changed: bool,
    ) -> Self {
        Self {
            schema_version: BootstrapMaintenanceSchema,
            request_id,
            host_identity,
            operation_id,
            reconciled: true,
            changed,
        }
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn reconciled(&self) -> bool {
        self.reconciled
    }

    pub const fn changed(&self) -> bool {
        self.changed
    }
}

impl AuthenticatedResponseContract for ManagedSetupActionResponse {
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
                .with_allow_project_selection(true)
                .with_experimental_provider_computer_use(true),
        );
        assert_eq!(
            serde_json::to_value(authorization).unwrap(),
            json!({
                "schema_version": "satelle.provider-binding-authorization.v2",
                "requested_model_alias": "vision",
                "requested_provider_alias": "open_ai",
                "model": "gpt-5.6",
                "model_provider": "openai",
                "allow_project_selection": true,
                "experimental_provider_computer_use": true
            })
        );

        assert_eq!(
            serde_json::to_value(
                ProviderDescriptorValidationRequest::new(
                    ProviderAuthValidationMode::RefreshProviderSmoke,
                    true,
                    false,
                )
                .with_experimental_provider_computer_use(true)
            )
            .unwrap(),
            json!({
                "schema_version": "satelle.provider-binding-validation.v5",
                "model_from_project": true,
                "provider_from_project": false,
                "mode": "refresh_provider_smoke",
                "experimental_provider_computer_use": true
            })
        );
    }

    #[test]
    fn provider_requests_reject_missing_provenance_and_old_schemas() {
        let old_authorization = json!({
            "schema_version": "satelle.provider-binding-authorization.v1",
            "requested_model_alias": "vision",
            "requested_provider_alias": "open_ai",
            "model": "gpt-5.6",
            "model_provider": "openai",
            "allow_project_selection": false
        });
        assert!(
            serde_json::from_value::<ProviderBindingAuthorizationRequest>(old_authorization)
                .is_err()
        );
        assert!(
            serde_json::from_value::<ProviderBindingAuthorizationRequest>(json!({
                "schema_version": "satelle.provider-binding-authorization.v2",
                "requested_model_alias": "vision",
                "requested_provider_alias": "open_ai",
                "model": "gpt-5.6",
                "model_provider": "openai"
            }))
            .is_err()
        );

        for request in [
            json!({
                "schema_version": "satelle.provider-binding-validation.v5",
                "mode": "cached"
            }),
            json!({
                "schema_version": "satelle.provider-binding-validation.v4",
                "model_from_project": false,
                "provider_from_project": false,
                "mode": "cached"
            }),
        ] {
            assert!(
                serde_json::from_value::<ProviderDescriptorValidationRequest>(request).is_err()
            );
        }

        let current_binding = json!({
            "requested_model_alias": "vision",
            "requested_provider_alias": "open_ai",
            "model": "gpt-5.6",
            "model_provider": "openai",
            "source": "host_owned",
            "allow_project_selection": false,
            "experimental_provider_computer_use": false,
            "binding_digest": "digest"
        });
        assert!(
            serde_json::from_value::<PublicResolvedProviderBinding>(current_binding.clone())
                .is_ok()
        );
        let mut missing_consent = current_binding;
        missing_consent
            .as_object_mut()
            .expect("binding fixture is an object")
            .remove("allow_project_selection");
        assert!(serde_json::from_value::<PublicResolvedProviderBinding>(missing_consent).is_err());
    }

    #[test]
    fn validation_rejects_caller_binding_material() {
        let request = json!({
            "schema_version": "satelle.provider-binding-validation.v5",
            "model_from_project": false,
            "provider_from_project": false,
            "mode": "cached",
            "endpoint": "https://attacker.example"
        });
        assert!(serde_json::from_value::<ProviderDescriptorValidationRequest>(request).is_err());
    }

    #[test]
    fn setup_verification_is_strict_and_aliases_are_paired() {
        let request = SetupVerificationRequest::new(
            Some("vision".to_string()),
            Some("open_ai".to_string()),
            true,
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({
                "schema_version": "satelle.setup-verification.v1",
                "model_alias": "vision",
                "provider_alias": "open_ai",
                "model_from_project": true,
                "provider_from_project": false,
                "experimental_provider_computer_use": true
            })
        );

        for invalid in [
            json!({
                "schema_version": "satelle.setup-verification.v1",
                "model_alias": "vision",
                "model_from_project": false,
                "provider_from_project": false,
                "experimental_provider_computer_use": false
            }),
            json!({
                "schema_version": "satelle.setup-verification.v1",
                "model_from_project": false,
                "provider_from_project": false,
                "experimental_provider_computer_use": false,
                "unexpected": true
            }),
        ] {
            assert!(serde_json::from_value::<SetupVerificationRequest>(invalid).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_invalidation_carries_intent_without_exposing_a_cache_key() {
        let request = NativeReadinessInvalidationRequest::new(
            Some("vision".to_string()),
            Some("open_ai".to_string()),
            true,
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "schema_version": "satelle.native-readiness-invalidation.v2",
                "scope": "intent",
                "model_alias": "vision",
                "provider_alias": "open_ai",
                "model_from_project": true,
                "provider_from_project": false,
                "experimental_provider_computer_use": true
            })
        );
    }

    #[test]
    fn host_native_invalidation_is_explicit_and_carries_no_intent() {
        let request = NativeReadinessInvalidationRequest::host();
        assert_eq!(request.scope(), NativeReadinessInvalidationScope::Host);
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::json!({
                "schema_version": "satelle.native-readiness-invalidation.v2",
                "scope": "host",
                "model_from_project": false,
                "provider_from_project": false,
                "experimental_provider_computer_use": false
            })
        );

        let mut invalid = serde_json::to_value(request).unwrap();
        invalid["model_alias"] = serde_json::json!("vision");
        invalid["provider_alias"] = serde_json::json!("openai");
        assert!(serde_json::from_value::<NativeReadinessInvalidationRequest>(invalid).is_err());
    }

    #[test]
    fn provider_binding_authorization_rejects_unknown_top_level_fields() {
        let error =
            serde_json::from_value::<ProviderBindingAuthorizationRequest>(serde_json::json!({
                "schema_version": "satelle.provider-binding-authorization.v2",
                "requested_model_alias": "default",
                "requested_provider_alias": "openai",
                "model": "gpt-5",
                "model_provider": "openai",
                "experimental_provider_computer_use": false,
                "bogus": true,
            }))
            .expect_err("unknown authorization request field must be rejected");

        assert!(error.to_string().contains("unknown field `bogus`"));
    }

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

    #[test]
    fn managed_setup_action_schema_carries_the_changed_outcome() {
        for changed in [false, true] {
            let response = ManagedSetupActionResponse::new(
                RequestId::new(),
                "host-test".to_string(),
                "managed-operation-1".to_string(),
                changed,
            );
            let encoded = serde_json::to_value(&response).expect("encode managed setup response");
            assert_eq!(
                encoded["schema_version"],
                "satelle.bootstrap-maintenance.v1"
            );
            assert_eq!(encoded["operation_id"], "managed-operation-1");
            assert_eq!(encoded["reconciled"], true);
            assert_eq!(encoded["changed"], changed);

            let decoded: ManagedSetupActionResponse =
                serde_json::from_value(encoded.clone()).expect("decode managed setup response");
            assert_eq!(decoded.changed(), changed);

            let mut missing_changed = encoded;
            missing_changed
                .as_object_mut()
                .expect("response is an object")
                .remove("changed");
            assert!(serde_json::from_value::<ManagedSetupActionResponse>(missing_changed).is_err());

            let mut unknown_field = serde_json::to_value(&response)
                .expect("encode managed setup response for strict decoding");
            unknown_field["unexpected"] = serde_json::json!(true);
            assert!(serde_json::from_value::<ManagedSetupActionResponse>(unknown_field).is_err());
        }
    }
}
