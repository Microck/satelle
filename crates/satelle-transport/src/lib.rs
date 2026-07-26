mod client;
mod contract;
mod server;
#[path = "transport-tls.rs"]
mod transport_tls;

pub use client::{
    DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError, DaemonEventStream,
};
pub use contract::{
    AdmissionCancellationOutcome, AdmissionCancellationResponse, ApiError, ApiErrorCode,
    CapabilitiesResponse, DURABLE_SETUP_PENDING_TTL, DurableTokenActivationResponse,
    DurableTokenConfirmationResponse, DurableTokenIssuanceResponse, EventSubscription,
    HostDesktopSessionsResponse, HostStatusResponse, ImageAttachment, LiveResponse,
    LogsPageResponse, MAX_IMAGE_ATTACHMENT_BYTES, MAX_IMAGE_ATTACHMENT_BYTES_TOTAL,
    MAX_IMAGE_ATTACHMENT_COUNT, ProviderAuthObservationSource, ProviderAuthValidationMode,
    ProviderAuthValidationOutcome, ProviderAuthValidationResult, ProviderBindingAuthorization,
    ProviderBindingAuthorizationRequest, ProviderBindingAuthorizationResponse,
    ProviderBindingDeletionResponse, ProviderBindingSource, ProviderDescriptorValidationRequest,
    ProviderDescriptorValidationResponse, RequestId, ResolvedProviderBinding,
    SUPPORTED_IMAGE_MEDIA_TYPES, SessionResponse, StopRequest, StopResponse, SubscribeRequest,
    SubscribeRequestError, SubscribedResponse, TurnRequest, WsCloseReason, WsControlError,
    WsServerControl,
};
pub use server::{
    DaemonServer, DaemonServerConfig, DaemonServerError, DaemonShutdownHandle, DaemonTlsConfig,
    DaemonTlsConfigError, DaemonTlsReloadError, DaemonTlsReloader, TrustedProxy,
    TrustedProxyParseError,
};
