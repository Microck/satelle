mod error;
mod events;
mod logs;
mod read;
mod session;
mod setup;

pub(crate) use error::ApiErrorCategory;
pub use error::{ApiError, ApiErrorCode};
pub(crate) use events::MAX_EVENT_SUBSCRIPTIONS;
pub use events::{
    EventSubscription, SubscribeRequest, SubscribeRequestError, SubscribedResponse, WsCloseReason,
    WsControlError, WsServerControl,
};
pub use logs::LogsPageResponse;
pub(crate) use read::effective_limits;
pub use read::{
    CapabilitiesResponse, EffectiveLimits, HostDesktopSessionsResponse, HostPathsResponse,
    HostStatusResponse, LiveResponse, MaintenanceUpdateEvidenceResponse,
};
pub use satelle_core::{
    ProviderAuthObservationSource, ProviderAuthValidationMode, ProviderAuthValidationOutcome,
    ProviderAuthValidationResult, ProviderBindingAuthorization, ProviderBindingSource,
    ResolvedProviderBinding,
};
pub(crate) use session::ApiRequestContract;
pub(crate) use session::TurnRequestParts;
pub use session::{
    AdmissionCancellationOutcome, AdmissionCancellationResponse, ImageAttachment,
    MAX_IMAGE_ATTACHMENT_BYTES, MAX_IMAGE_ATTACHMENT_BYTES_TOTAL, MAX_IMAGE_ATTACHMENT_COUNT,
    SUPPORTED_IMAGE_MEDIA_TYPES, SessionResponse, StopRequest, StopResponse, TaskArtifactsResponse,
    TurnRequest,
};
pub use setup::{
    BootstrapMaintenanceResponse, DURABLE_SETUP_PENDING_TTL, DurableTokenActivationResponse,
    DurableTokenConfirmationResponse, DurableTokenIssuanceResponse, HostUpdateMaintenanceRequest,
    ManagedSetupActionResponse, NativeReadinessInvalidationRequest,
    NativeReadinessInvalidationResponse, NativeReadinessInvalidationScope,
    ProviderBindingAuthorizationRequest, ProviderBindingAuthorizationResponse,
    ProviderBindingDeletionResponse, ProviderDescriptorValidationRequest,
    ProviderDescriptorValidationResponse, ProviderSecretProvisioningMetadata,
    ProviderSecretProvisioningPreviewResponse, ProviderSecretProvisioningResponse,
    ProviderSecretUploadEnvelope, RepairMaintenanceRequest, SetupRepairDecision,
    SetupRepairOperationKind, SetupRepairPlanAction, SetupRepairPlanRequest,
    SetupRepairPlanResponse, SetupRepairPostcondition, SetupRepairPreviousStatus, SetupRepairProbe,
    SetupRepairRunStatus, SetupVerificationRequest, SetupVerificationResponse,
};
pub(crate) use setup::{
    PROVIDER_SECRET_UPLOAD_CONTENT_TYPE, PROVIDER_SECRET_UPLOAD_INFO, provider_secret_upload_aad,
};

pub(crate) const PROTOCOL_VERSION_HEADER: &str = "satelle-protocol-version";
// Protocol v14 adds the authenticated, identity-pinned task artifact read.
// The protocol remains a hard cut because older peers cannot distinguish the
// closed redacted export contract from arbitrary Host file access.
pub(crate) const PROTOCOL_VERSION: &str = "14";

macro_rules! define_schema_token {
    ($name:ident, $token:literal) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct $name;

        impl $name {
            const TOKEN: &'static str = $token;
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(Self::TOKEN)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize>::deserialize(deserializer)?;
                if value == Self::TOKEN {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(concat!(
                        "expected schema_version ",
                        $token
                    )))
                }
            }
        }
    };
}

pub(super) use define_schema_token;

define_schema_token!(
    LocalSetupOperationSchema,
    "satelle.local-setup-operation.v1"
);
define_schema_token!(
    LocalDoctorOperationSchema,
    "satelle.local-doctor-operation.v1"
);
define_schema_token!(
    LocalDaemonRelaunchSchema,
    "satelle.local-daemon-relaunch.v1"
);

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireDuration {
    seconds: u64,
    nanoseconds: u32,
}

impl From<std::time::Duration> for WireDuration {
    fn from(duration: std::time::Duration) -> Self {
        Self {
            seconds: duration.as_secs(),
            nanoseconds: duration.subsec_nanos(),
        }
    }
}

impl From<WireDuration> for std::time::Duration {
    fn from(duration: WireDuration) -> Self {
        Self::new(duration.seconds, duration.nanoseconds)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalSetupOperationRequest {
    schema_version: LocalSetupOperationSchema,
    host: String,
    dry_run: bool,
    setup_mode: String,
    setup_components: Vec<String>,
    daemon_path_overrides: satelle_core::DaemonPathOverrides,
}

impl LocalSetupOperationRequest {
    pub(crate) fn new(
        host: impl Into<String>,
        dry_run: bool,
        setup_mode: impl Into<String>,
        setup_components: Vec<String>,
        daemon_path_overrides: satelle_core::DaemonPathOverrides,
    ) -> Self {
        Self {
            schema_version: LocalSetupOperationSchema,
            host: host.into(),
            dry_run,
            setup_mode: setup_mode.into(),
            setup_components,
            daemon_path_overrides,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        String,
        bool,
        String,
        Vec<String>,
        satelle_core::DaemonPathOverrides,
    ) {
        (
            self.host,
            self.dry_run,
            self.setup_mode,
            self.setup_components,
            self.daemon_path_overrides,
        )
    }
}

impl ApiRequestContract for LocalSetupOperationRequest {
    const SCHEMA_VERSION: &'static str = LocalSetupOperationSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "status")]
enum LocalSetupOperationOutcome {
    Completed {
        report: Box<satelle_core::SetupReport>,
        mutation_planned: bool,
    },
    Failed {
        error: satelle_core::SatelleError,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalSetupOperationResponse {
    schema_version: LocalSetupOperationSchema,
    request_id: RequestId,
    host_identity: String,
    outcome: LocalSetupOperationOutcome,
}

impl LocalSetupOperationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        result: Result<satelle_core::SetupReport, satelle_core::SatelleError>,
    ) -> Self {
        let outcome = match result {
            Ok(report) => LocalSetupOperationOutcome::Completed {
                mutation_planned: report.mutation_planned,
                report: Box::new(report),
            },
            Err(error) => LocalSetupOperationOutcome::Failed { error },
        };
        Self {
            schema_version: LocalSetupOperationSchema,
            request_id,
            host_identity,
            outcome,
        }
    }

    pub(crate) fn into_result(
        self,
    ) -> Result<satelle_core::SetupReport, satelle_core::SatelleError> {
        match self.outcome {
            LocalSetupOperationOutcome::Completed {
                report,
                mutation_planned,
            } => {
                let mut report = *report;
                report.mutation_planned = mutation_planned;
                Ok(report)
            }
            LocalSetupOperationOutcome::Failed { error } => Err(error),
        }
    }
}

impl AuthenticatedResponseContract for LocalSetupOperationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalDoctorOperationRequest {
    schema_version: LocalDoctorOperationSchema,
    host: String,
    scopes: Vec<String>,
    refresh: bool,
    probe_timeout: Option<WireDuration>,
    serial_probes: bool,
    model_alias: Option<String>,
    provider_alias: Option<String>,
    model_from_project: bool,
    provider_from_project: bool,
    experimental_provider_computer_use: bool,
    provider_smoke_timeout: Option<WireDuration>,
}

impl LocalDoctorOperationRequest {
    pub(crate) fn new(
        host: impl Into<String>,
        scope_selection: &satelle_core::doctor::DoctorScopeSelection,
        options: satelle_core::DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Self {
        Self {
            schema_version: LocalDoctorOperationSchema,
            host: host.into(),
            scopes: scope_selection
                .scopes()
                .iter()
                .map(|scope| scope.as_str().to_string())
                .collect(),
            refresh: options.refresh(),
            probe_timeout: options.probe_timeout().map(Into::into),
            serial_probes: options.serial_probes(),
            model_alias: provider_intent.model().map(ToString::to_string),
            provider_alias: provider_intent.provider().map(ToString::to_string),
            model_from_project: provider_intent.model_from_project(),
            provider_from_project: provider_intent.provider_from_project(),
            experimental_provider_computer_use: provider_intent
                .experimental_provider_computer_use(),
            provider_smoke_timeout: provider_intent.provider_smoke_timeout().map(Into::into),
        }
    }

    pub(crate) fn into_inputs(
        self,
    ) -> Result<
        (
            String,
            satelle_core::doctor::DoctorScopeSelection,
            satelle_core::DoctorOptions,
            satelle_host::ProviderComputerUseIntent,
        ),
        satelle_core::SatelleError,
    > {
        use satelle_core::session::{EffectiveModelRef, ProviderBindingRef};

        let scope_selection = satelle_core::doctor::DoctorScopeSelection::parse(&self.scopes)
            .map_err(|_| satelle_core::SatelleError::invalid_usage("invalid Doctor scope"))?;
        let options =
            satelle_core::DoctorOptions::new(self.refresh, self.probe_timeout.map(Into::into))?
                .with_serial_probes(self.serial_probes);
        let model = self
            .model_alias
            .map(EffectiveModelRef::new)
            .transpose()
            .map_err(|_| satelle_core::SatelleError::invalid_usage("invalid model alias"))?;
        let provider = self
            .provider_alias
            .map(ProviderBindingRef::new)
            .transpose()
            .map_err(|_| satelle_core::SatelleError::invalid_usage("invalid provider alias"))?;
        if model.is_some() != provider.is_some() {
            return Err(satelle_core::SatelleError::invalid_usage(
                "Doctor model and provider aliases must be supplied together",
            ));
        }
        let provider_intent =
            satelle_host::ProviderComputerUseIntent::new(model, provider, self.refresh)
                .with_project_selection_provenance(
                    self.model_from_project,
                    self.provider_from_project,
                )
                .with_experimental_provider_computer_use(self.experimental_provider_computer_use);
        let provider_intent = match self.provider_smoke_timeout {
            Some(timeout) => provider_intent.with_provider_smoke_timeout(timeout.into()),
            None => provider_intent,
        };
        Ok((self.host, scope_selection, options, provider_intent))
    }
}

impl ApiRequestContract for LocalDoctorOperationRequest {
    const SCHEMA_VERSION: &'static str = LocalDoctorOperationSchema::TOKEN;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "status")]
enum LocalDoctorOperationOutcome {
    Completed {
        report: Box<satelle_core::DoctorReport>,
        probe_schedule_events: Box<[satelle_core::doctor::DoctorProbeScheduleEvent]>,
    },
    Failed {
        error: satelle_core::SatelleError,
        partial_probe_results: Box<[satelle_core::DoctorProbeResult]>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalDoctorOperationResponse {
    schema_version: LocalDoctorOperationSchema,
    request_id: RequestId,
    host_identity: String,
    outcome: LocalDoctorOperationOutcome,
}

impl LocalDoctorOperationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        result: satelle_host::DoctorExecutionResult,
    ) -> Self {
        let outcome = match result {
            Ok(mut report) => LocalDoctorOperationOutcome::Completed {
                probe_schedule_events: std::mem::take(&mut report.probe_schedule_events),
                report: Box::new(report),
            },
            Err(failure) => LocalDoctorOperationOutcome::Failed {
                error: failure.error,
                partial_probe_results: failure.partial_probe_results,
            },
        };
        Self {
            schema_version: LocalDoctorOperationSchema,
            request_id,
            host_identity,
            outcome,
        }
    }

    pub(crate) fn into_result(self) -> satelle_host::DoctorExecutionResult {
        match self.outcome {
            LocalDoctorOperationOutcome::Completed {
                report,
                probe_schedule_events,
            } => {
                let mut report = *report;
                report.probe_schedule_events = probe_schedule_events;
                Ok(report)
            }
            LocalDoctorOperationOutcome::Failed {
                error,
                partial_probe_results,
            } => Err(satelle_host::DoctorExecutionFailure {
                error,
                partial_probe_results,
            }),
        }
    }
}

impl AuthenticatedResponseContract for LocalDoctorOperationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalDaemonRelaunchResponse {
    schema_version: LocalDaemonRelaunchSchema,
    request_id: RequestId,
    host_identity: String,
}

impl LocalDaemonRelaunchResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String) -> Self {
        Self {
            schema_version: LocalDaemonRelaunchSchema,
            request_id,
            host_identity,
        }
    }
}

impl AuthenticatedResponseContract for LocalDaemonRelaunchResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use uuid::{Uuid, Variant, Version};

pub(crate) trait AuthenticatedResponseContract {
    fn request_id(&self) -> &RequestId;
    fn host_identity(&self) -> &str;

    fn matches_host_identity(&self, expected_host_identity: &str) -> bool {
        self.host_identity() == expected_host_identity
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RequestId(String);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::now_v7().hyphenated().to_string())
    }

    pub fn parse(value: &str) -> Result<Self, RequestIdError> {
        let uuid = Uuid::parse_str(value).map_err(|_| RequestIdError)?;
        if uuid.get_version() != Some(Version::SortRand)
            || uuid.get_variant() != Variant::RFC4122
            || value != uuid.hyphenated().to_string()
        {
            return Err(RequestIdError);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RequestId {
    type Err = RequestIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestIdError;

impl fmt::Display for RequestIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the request ID must be a canonical UUIDv7")
    }
}

impl std::error::Error for RequestIdError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_accept_only_canonical_uuidv7() {
        let generated = RequestId::new();
        assert_eq!(RequestId::parse(generated.as_str()), Ok(generated));
        assert!(RequestId::parse("550e8400-e29b-41d4-a716-446655440000").is_err());
        assert!(RequestId::parse("not-a-request-id").is_err());
    }

    #[test]
    fn protocol_version_is_the_v14_hard_cut() {
        assert_eq!(PROTOCOL_VERSION, "14");
    }

    #[test]
    fn local_setup_response_round_trips_success_and_exact_failure() {
        let report = satelle_host::local_setup_plan_for_tests(
            "local-demo",
            false,
            "on_demand".to_string(),
            vec!["all".to_string()],
            satelle_core::DaemonPathOverrides::default(),
        );
        assert!(report.mutation_planned);
        let response = LocalSetupOperationResponse::new(
            RequestId::new(),
            "host-local-demo".to_string(),
            Ok(report),
        );
        let encoded = serde_json::to_vec(&response).expect("serialize local setup success");
        let decoded = serde_json::from_slice::<LocalSetupOperationResponse>(&encoded)
            .expect("deserialize local setup success");
        assert!(
            decoded
                .into_result()
                .expect("restore local setup success")
                .mutation_planned
        );

        let expected = satelle_core::SatelleError::state_conflict();
        let response = LocalSetupOperationResponse::new(
            RequestId::new(),
            "host-local-demo".to_string(),
            Err(expected.clone()),
        );
        let encoded = serde_json::to_vec(&response).expect("serialize local setup failure");
        let decoded = serde_json::from_slice::<LocalSetupOperationResponse>(&encoded)
            .expect("deserialize local setup failure");
        let actual = decoded
            .into_result()
            .expect_err("restore exact local setup failure");
        assert_eq!(actual.code, expected.code);
        assert_eq!(actual.message, expected.message);
        assert_eq!(actual.recovery_command, expected.recovery_command);
        assert_eq!(actual.details, expected.details);
    }
}
