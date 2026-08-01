mod client;
mod contract;
#[path = "provider-secret-crypto.rs"]
mod provider_secret_crypto;
mod server;
#[path = "transport-tls.rs"]
mod transport_tls;

pub use client::{
    DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError, DaemonEventStream,
    PreparedProviderSecretProvisioning,
};
pub use contract::{
    AdmissionCancellationOutcome, AdmissionCancellationResponse, ApiError, ApiErrorCode,
    CapabilitiesResponse, DURABLE_SETUP_PENDING_TTL, DurableTokenActivationResponse,
    DurableTokenConfirmationResponse, DurableTokenIssuanceResponse, EventSubscription,
    HostDesktopSessionsResponse, HostStatusResponse, HostUpdateMaintenanceRequest, ImageAttachment,
    LiveResponse, LogsPageResponse, MAX_IMAGE_ATTACHMENT_BYTES, MAX_IMAGE_ATTACHMENT_BYTES_TOTAL,
    MAX_IMAGE_ATTACHMENT_COUNT, MaintenanceUpdateEvidenceResponse,
    NativeReadinessInvalidationRequest, NativeReadinessInvalidationResponse,
    NativeReadinessInvalidationScope, ProviderAuthObservationSource, ProviderAuthValidationMode,
    ProviderAuthValidationOutcome, ProviderAuthValidationResult, ProviderBindingAuthorization,
    ProviderBindingAuthorizationRequest, ProviderBindingAuthorizationResponse,
    ProviderBindingDeletionResponse, ProviderBindingSource, ProviderDescriptorValidationRequest,
    ProviderDescriptorValidationResponse, ProviderSecretProvisioningMetadata,
    ProviderSecretProvisioningPreviewResponse, ProviderSecretProvisioningResponse,
    ProviderSecretUploadEnvelope, RepairMaintenanceRequest, RequestId, ResolvedProviderBinding,
    SUPPORTED_IMAGE_MEDIA_TYPES, SessionResponse, SetupRepairDecision, SetupRepairOperationKind,
    SetupRepairPlanAction, SetupRepairPlanRequest, SetupRepairPlanResponse,
    SetupRepairPostcondition, SetupRepairPreviousStatus, SetupRepairProbe, SetupRepairRunStatus,
    SetupVerificationRequest, SetupVerificationResponse, StopRequest, StopResponse,
    SubscribeRequest, SubscribeRequestError, SubscribedResponse, TurnRequest, WsCloseReason,
    WsControlError, WsServerControl,
};
pub use server::{
    DaemonServer, DaemonServerConfig, DaemonServerError, DaemonShutdownHandle, DaemonTlsConfig,
    DaemonTlsConfigError, DaemonTlsReloadError, DaemonTlsReloader, TrustedProxy,
    TrustedProxyParseError,
};
