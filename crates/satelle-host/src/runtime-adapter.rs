use crate::storage::ProbeRecoverySubject;
use crate::storage::RecoverySubject;
use satelle_core::session::{
    DesktopBindingRef, ExecutionPolicy, FeatureChoice, HostIdentityRef, SessionStateRevision,
    StopObservation, TurnStateRevision, TurnTransition,
};
use satelle_core::{
    ControlPlaneOperation, ErrorCode, SatelleError, SatelleEvent, SessionId, TurnId,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Alias-only provider intent from the Controller. The Host runtime attaches
/// an exact authorized binding before this value can reach an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderComputerUseIntent {
    model: Option<satelle_core::session::EffectiveModelRef>,
    provider: Option<satelle_core::session::ProviderBindingRef>,
    resolved_provider_binding: Option<satelle_core::ResolvedProviderBinding>,
    refresh: bool,
    provider_smoke_timeout: Option<std::time::Duration>,
}

impl ProviderComputerUseIntent {
    pub fn new(
        model: Option<satelle_core::session::EffectiveModelRef>,
        provider: Option<satelle_core::session::ProviderBindingRef>,
        refresh: bool,
    ) -> Self {
        Self {
            model,
            provider,
            resolved_provider_binding: None,
            refresh,
            provider_smoke_timeout: None,
        }
    }

    pub(crate) fn with_resolved_provider_binding(
        mut self,
        binding: satelle_core::ResolvedProviderBinding,
    ) -> Self {
        self.resolved_provider_binding = Some(binding);
        self
    }

    /// Applies a one-shot timeout to a diagnostic provider smoke refresh.
    /// Normal prompt admission continues to use the Host configuration.
    pub fn with_provider_smoke_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.provider_smoke_timeout = Some(timeout);
        self
    }

    pub fn host_default() -> Self {
        Self::new(None, None, false)
    }

    pub fn model(&self) -> Option<&satelle_core::session::EffectiveModelRef> {
        self.model.as_ref()
    }

    pub fn provider(&self) -> Option<&satelle_core::session::ProviderBindingRef> {
        self.provider.as_ref()
    }

    pub(crate) fn resolved_provider_binding(
        &self,
    ) -> Option<&satelle_core::ResolvedProviderBinding> {
        self.resolved_provider_binding.as_ref()
    }

    pub const fn refresh(&self) -> bool {
        self.refresh
    }

    pub const fn provider_smoke_timeout(&self) -> Option<std::time::Duration> {
        self.provider_smoke_timeout
    }
}

/// Typed evidence returned before the runtime may durably admit work.
#[derive(Clone, Eq, PartialEq)]
pub struct AdapterReadiness {
    ready: bool,
    adapter: &'static str,
    message: &'static str,
    desktop_binding: DesktopBindingRef,
    execution_policy: ExecutionPolicy,
    evidence: ReadinessEvidence,
    provider_smoke_evidence: Option<ProviderSmokeEvidence>,
    resolved_provider_binding: Option<satelle_core::ResolvedProviderBinding>,
    source: ReadinessSource,
    checks: Vec<NativeReadinessCheck>,
}

impl std::fmt::Debug for AdapterReadiness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterReadiness")
            .field("ready", &self.ready)
            .field("adapter", &self.adapter)
            .field("desktop_binding", &self.desktop_binding)
            .field("execution_policy", &self.execution_policy)
            .field("source", &self.source)
            .field("checks", &self.checks)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessSource {
    Cache,
    Live,
}

impl ReadinessSource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Live => "live",
        }
    }
}

/// Direct observation state for a native readiness prerequisite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessObservationState {
    /// The prerequisite was directly observed as granted.
    Granted,
    /// The prerequisite was directly observed as denied.
    Denied,
    /// The prerequisite cannot be observed through a stable surface.
    Unknown,
}

impl ReadinessObservationState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeReadinessCheckKind {
    CodexRuntime,
    Authentication,
    NativeComputerUse,
    OsPermissions,
    AppApproval,
    ControlPlane,
    PointerClick,
    PointerDrag,
    FileManagement,
}

impl NativeReadinessCheckKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CodexRuntime => "codex_runtime",
            Self::Authentication => "authentication",
            Self::NativeComputerUse => "native_computer_use",
            Self::OsPermissions => "os_permissions",
            Self::AppApproval => "app_approval",
            Self::ControlPlane => "control_plane",
            Self::PointerClick => "pointer_click",
            Self::PointerDrag => "pointer_drag",
            Self::FileManagement => "file_management",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeReadinessCheckStatus {
    Passed,
    Failed,
    ManualActionRequired,
    NotEvaluated,
}

impl NativeReadinessCheckStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::ManualActionRequired => "manual_action_required",
            Self::NotEvaluated => "not_evaluated",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeReadinessCheck {
    kind: NativeReadinessCheckKind,
    status: NativeReadinessCheckStatus,
    reason: &'static str,
}

impl NativeReadinessCheck {
    pub(crate) const fn new(
        kind: NativeReadinessCheckKind,
        status: NativeReadinessCheckStatus,
        reason: &'static str,
    ) -> Self {
        Self {
            kind,
            status,
            reason,
        }
    }

    pub(crate) const fn kind(&self) -> NativeReadinessCheckKind {
        self.kind
    }

    pub(crate) const fn status(&self) -> NativeReadinessCheckStatus {
        self.status
    }

    pub(crate) const fn reason(&self) -> &'static str {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EvidenceError {
    #[error("preflight evidence contains an invalid normalized identifier")]
    InvalidIdentifier,
    #[error("preflight evidence contains an invalid fingerprint digest")]
    InvalidFingerprint,
    #[error("preflight evidence has an invalid validity window")]
    InvalidWindow,
    #[error("preflight evidence conflicts with the effective execution policy")]
    InconsistentPolicy,
}

#[derive(Clone, Eq, PartialEq)]
struct EvidenceWindow {
    result_id: String,
    observed_at: time::OffsetDateTime,
    expires_at: time::OffsetDateTime,
}

impl EvidenceWindow {
    fn new(
        result_id: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<Self, EvidenceError> {
        let result_id = normalized_identifier(result_id)?;
        if expires_at <= observed_at {
            return Err(EvidenceError::InvalidWindow);
        }
        Ok(Self {
            result_id,
            observed_at,
            expires_at,
        })
    }
}

/// Normalized evidence observed by the provider-specific half of preflight.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderSmokeEvidence {
    window: EvidenceWindow,
    provider_config_fingerprint: String,
    provider_credential_fingerprint: String,
    source: ProviderSmokeSource,
}

impl ProviderSmokeEvidence {
    pub fn new(
        result_id: impl Into<String>,
        provider_config_fingerprint: impl Into<String>,
        provider_credential_fingerprint: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            window: EvidenceWindow::new(result_id, observed_at, expires_at)?,
            provider_config_fingerprint: fingerprint(provider_config_fingerprint)?,
            provider_credential_fingerprint: fingerprint(provider_credential_fingerprint)?,
            source: ProviderSmokeSource::Live,
        })
    }

    pub(crate) const fn with_source(mut self, source: ProviderSmokeSource) -> Self {
        self.source = source;
        self
    }

    pub(crate) fn result_id(&self) -> &str {
        &self.window.result_id
    }

    pub(crate) fn provider_config_fingerprint(&self) -> &str {
        &self.provider_config_fingerprint
    }

    pub(crate) fn provider_credential_fingerprint(&self) -> &str {
        &self.provider_credential_fingerprint
    }

    pub(crate) const fn observed_at(&self) -> time::OffsetDateTime {
        self.window.observed_at
    }

    pub(crate) const fn expires_at(&self) -> time::OffsetDateTime {
        self.window.expires_at
    }

    pub(crate) const fn source(&self) -> ProviderSmokeSource {
        self.source
    }
}

impl std::fmt::Debug for ProviderSmokeEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderSmokeEvidence")
            .finish_non_exhaustive()
    }
}

/// Sanitized evidence from a provider smoke attempt that reached a terminal
/// failure. The result can block an exact matching preflight until its short
/// expiry without persisting raw provider or desktop output.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderSmokeFailureEvidence {
    window: EvidenceWindow,
    provider_config_fingerprint: String,
    provider_credential_fingerprint: String,
    error_code: ErrorCode,
    failure_reason: String,
    source: ProviderSmokeSource,
}

impl ProviderSmokeFailureEvidence {
    pub fn new(
        result_id: impl Into<String>,
        provider_config_fingerprint: impl Into<String>,
        provider_credential_fingerprint: impl Into<String>,
        error_code: ErrorCode,
        failure_reason: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            window: EvidenceWindow::new(result_id, observed_at, expires_at)?,
            provider_config_fingerprint: fingerprint(provider_config_fingerprint)?,
            provider_credential_fingerprint: fingerprint(provider_credential_fingerprint)?,
            error_code,
            failure_reason: normalized_identifier(failure_reason)?,
            source: ProviderSmokeSource::Live,
        })
    }

    pub(crate) const fn with_source(mut self, source: ProviderSmokeSource) -> Self {
        self.source = source;
        self
    }

    pub(crate) fn result_id(&self) -> &str {
        &self.window.result_id
    }

    pub(crate) fn provider_config_fingerprint(&self) -> &str {
        &self.provider_config_fingerprint
    }

    pub(crate) fn provider_credential_fingerprint(&self) -> &str {
        &self.provider_credential_fingerprint
    }

    pub(crate) const fn error_code(&self) -> ErrorCode {
        self.error_code
    }

    pub(crate) fn failure_reason(&self) -> &str {
        &self.failure_reason
    }

    pub(crate) const fn observed_at(&self) -> time::OffsetDateTime {
        self.window.observed_at
    }

    pub(crate) const fn expires_at(&self) -> time::OffsetDateTime {
        self.window.expires_at
    }

    pub(crate) const fn source(&self) -> ProviderSmokeSource {
        self.source
    }
}

impl std::fmt::Debug for ProviderSmokeFailureEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderSmokeFailureEvidence")
            .field("error_code", &self.error_code)
            .field("failure_reason", &self.failure_reason)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderSmokeResult {
    Passed(ProviderSmokeEvidence),
    Failed(ProviderSmokeFailureEvidence),
}

impl ProviderSmokeResult {
    pub(crate) fn provider_credential_fingerprint(&self) -> &str {
        match self {
            Self::Passed(evidence) => evidence.provider_credential_fingerprint(),
            Self::Failed(evidence) => evidence.provider_credential_fingerprint(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSmokeSource {
    Cache,
    Live,
    Refresh,
}

pub(crate) enum NativeProbeResult {
    Passed(ReadinessEvidence),
    Cancelled(StopObservation),
    Failed {
        evidence: ReadinessEvidence,
        reason: &'static str,
        error: SatelleError,
        dispatch_possible: bool,
    },
    UncachedFailure(SatelleError),
}

pub(crate) trait ReadinessProbeDriver: Send + Sync + 'static {
    fn run_native_probe(
        &self,
        key: &ReadinessCacheKey,
        cancellation: &super::request::AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> NativeProbeResult;

    #[allow(clippy::too_many_arguments)]
    fn preflight_terminal_with_provider_probe(
        &self,
        host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
        cancellation: &super::request::AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight;

    fn observe_readiness_probe(&self, subject: &ProbeRecoverySubject) -> RecoveryObservation;
}

impl ProviderSmokeSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Live => "live",
            Self::Refresh => "refresh",
        }
    }
}

/// Versioned evidence observed by a successful live readiness probe.
///
/// The adapter supplies only normalized identifiers and fingerprints. Raw probe
/// output, screenshots, and transcripts never cross this persistence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct ReadinessEvidence {
    window: EvidenceWindow,
    source: ReadinessSource,
    adapter: &'static str,
    desktop_binding: DesktopBindingRef,
    execution_policy: ExecutionPolicy,
    desktop_session_ref: String,
    codex_version: String,
    native_runtime_version: String,
    plugin_version: Option<String>,
    os_permission_fingerprint: String,
    app_approval_fingerprint: String,
    os_permission_state: ReadinessObservationState,
    app_approval_state: ReadinessObservationState,
}

/// Stable inputs that must still match before a successful native readiness
/// result may be reused. The Host runtime owns lookup and persistence; the
/// adapter can only describe the environment it is about to exercise.
#[derive(Clone, Eq, PartialEq)]
pub struct ReadinessCacheKey {
    adapter: &'static str,
    desktop_binding: DesktopBindingRef,
    execution_policy: ExecutionPolicy,
    desktop_session_ref: String,
    codex_version: String,
    native_runtime_version: String,
    plugin_version: Option<String>,
    provider_config_fingerprint: Option<String>,
    os_permission_fingerprint: String,
    app_approval_fingerprint: String,
    os_permission_state: ReadinessObservationState,
    app_approval_state: ReadinessObservationState,
}

impl ReadinessCacheKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapter: &'static str,
        desktop_binding: DesktopBindingRef,
        execution_policy: ExecutionPolicy,
        codex_version: impl Into<String>,
        native_runtime_version: impl Into<String>,
        plugin_version: Option<impl Into<String>>,
        os_permission_fingerprint: impl Into<String>,
        app_approval_fingerprint: impl Into<String>,
        os_permission_state: ReadinessObservationState,
        app_approval_state: ReadinessObservationState,
    ) -> Result<Self, EvidenceError> {
        normalized_identifier(adapter)?;
        let desktop_session_ref =
            normalized_identifier(execution_policy.desktop_target().session_id())?;
        Ok(Self {
            adapter,
            desktop_binding,
            execution_policy,
            desktop_session_ref,
            codex_version: normalized_identifier(codex_version)?,
            native_runtime_version: normalized_identifier(native_runtime_version)?,
            plugin_version: plugin_version.map(normalized_identifier).transpose()?,
            provider_config_fingerprint: None,
            os_permission_fingerprint: fingerprint(os_permission_fingerprint)?,
            app_approval_fingerprint: fingerprint(app_approval_fingerprint)?,
            os_permission_state,
            app_approval_state,
        })
    }

    pub(crate) fn with_provider_binding(
        mut self,
        binding: &satelle_core::ResolvedProviderBinding,
    ) -> Self {
        self.provider_config_fingerprint = Some(binding.binding_digest().to_string());
        self
    }

    pub(crate) const fn adapter(&self) -> &'static str {
        self.adapter
    }

    pub(crate) fn desktop_binding(&self) -> &DesktopBindingRef {
        &self.desktop_binding
    }

    pub(crate) fn execution_policy(&self) -> &ExecutionPolicy {
        &self.execution_policy
    }

    pub(crate) fn desktop_session_ref(&self) -> &str {
        &self.desktop_session_ref
    }

    pub(crate) fn codex_version(&self) -> &str {
        &self.codex_version
    }

    pub(crate) fn native_runtime_version(&self) -> &str {
        &self.native_runtime_version
    }

    pub(crate) fn plugin_version(&self) -> Option<&str> {
        self.plugin_version.as_deref()
    }

    pub(crate) fn os_permission_fingerprint(&self) -> &str {
        &self.os_permission_fingerprint
    }

    pub(crate) fn app_approval_fingerprint(&self) -> &str {
        &self.app_approval_fingerprint
    }

    pub(crate) const fn os_permission_state(&self) -> ReadinessObservationState {
        self.os_permission_state
    }

    pub(crate) const fn app_approval_state(&self) -> ReadinessObservationState {
        self.app_approval_state
    }

    pub(crate) fn matches_evidence(&self, evidence: &ReadinessEvidence) -> bool {
        self.adapter == evidence.adapter
            && self.desktop_binding == evidence.desktop_binding
            && self.execution_policy == evidence.execution_policy
            && self.desktop_session_ref == evidence.desktop_session_ref
            && self.codex_version == evidence.codex_version
            && self.native_runtime_version == evidence.native_runtime_version
            && self.plugin_version == evidence.plugin_version
            && self.os_permission_fingerprint == evidence.os_permission_fingerprint
            && self.app_approval_fingerprint == evidence.app_approval_fingerprint
            && self.os_permission_state == evidence.os_permission_state
            && self.app_approval_state == evidence.app_approval_state
    }

    /// Binds reusable provider evidence to the exact provider/model/runtime
    /// tuple that the next prompt Turn will use.
    pub(crate) fn provider_config_fingerprint(&self) -> String {
        if let Some(fingerprint) = &self.provider_config_fingerprint {
            return fingerprint.clone();
        }
        let mut digest = Sha256::new();
        digest.update(b"satelle-provider-smoke-v1\0");
        digest.update(self.execution_policy.provider_binding().as_str().as_bytes());
        digest.update([0]);
        digest.update(self.execution_policy.effective_model().as_str().as_bytes());
        digest.update([0]);
        digest.update(self.codex_version.as_bytes());
        digest.update([0]);
        digest.update(self.native_runtime_version.as_bytes());
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub(crate) fn evidence(
        &self,
        result_id: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<ReadinessEvidence, EvidenceError> {
        ReadinessEvidence::new(self, result_id, observed_at, expires_at)
    }
}

impl std::fmt::Debug for ReadinessCacheKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadinessCacheKey")
            .field("adapter", &self.adapter)
            .field("desktop_binding", &self.desktop_binding)
            .finish_non_exhaustive()
    }
}

/// One completed native readiness attempt. Failures retain only a closed
/// reason and normalized evidence; raw app-server or desktop output never
/// reaches the Host store.
pub enum AdapterPreflight {
    Ready(AdapterReadiness),
    Cancelled(StopObservation),
    Failed {
        key: ReadinessCacheKey,
        evidence: ReadinessEvidence,
        reason: &'static str,
        error: SatelleError,
        dispatch_possible: bool,
    },
    ProviderFailed {
        key: ReadinessCacheKey,
        readiness: ReadinessEvidence,
        failure: ProviderSmokeFailureEvidence,
        error: SatelleError,
    },
    UncachedFailure(SatelleError),
}

impl AdapterPreflight {
    pub(crate) fn into_result(self) -> Result<AdapterReadiness, SatelleError> {
        match self {
            Self::Ready(readiness) => Ok(readiness),
            Self::Cancelled(observation) => Err(admission_cancelled_error(observation)),
            Self::Failed { error, .. } | Self::ProviderFailed { error, .. } => Err(error),
            Self::UncachedFailure(error) => Err(error),
        }
    }
}

pub(crate) fn admission_cancelled_error(observation: StopObservation) -> SatelleError {
    let mut error = SatelleError::interrupted_attached_command();
    let outcome = match observation {
        StopObservation::CancellationConfirmed | StopObservation::UpstreamInactiveConfirmed => {
            "confirmed"
        }
        StopObservation::UpstreamStillActive => "upstream_still_active",
        StopObservation::OutcomeUnknown => "outcome_unknown",
    };
    error.details.insert(
        "admission_cancellation".to_string(),
        serde_json::Value::String(outcome.to_string()),
    );
    error
}

impl ReadinessEvidence {
    /// Creates native readiness evidence from one exact, validated cache
    /// identity and a bounded validity window.
    pub fn new(
        key: &ReadinessCacheKey,
        result_id: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            window: EvidenceWindow::new(result_id, observed_at, expires_at)?,
            source: ReadinessSource::Live,
            adapter: key.adapter,
            desktop_binding: key.desktop_binding.clone(),
            execution_policy: key.execution_policy.clone(),
            desktop_session_ref: key.desktop_session_ref.clone(),
            codex_version: key.codex_version.clone(),
            native_runtime_version: key.native_runtime_version.clone(),
            plugin_version: key.plugin_version.clone(),
            os_permission_fingerprint: key.os_permission_fingerprint.clone(),
            app_approval_fingerprint: key.app_approval_fingerprint.clone(),
            os_permission_state: key.os_permission_state,
            app_approval_state: key.app_approval_state,
        })
    }

    pub(crate) fn result_id(&self) -> &str {
        &self.window.result_id
    }

    pub(crate) const fn with_source(mut self, source: ReadinessSource) -> Self {
        self.source = source;
        self
    }

    pub(crate) const fn source(&self) -> ReadinessSource {
        self.source
    }

    pub(crate) fn desktop_session_ref(&self) -> &str {
        &self.desktop_session_ref
    }

    pub(crate) fn codex_version(&self) -> &str {
        &self.codex_version
    }

    pub(crate) fn native_runtime_version(&self) -> &str {
        &self.native_runtime_version
    }

    pub(crate) fn plugin_version(&self) -> Option<&str> {
        self.plugin_version.as_deref()
    }

    pub(crate) fn os_permission_fingerprint(&self) -> &str {
        &self.os_permission_fingerprint
    }

    pub(crate) fn app_approval_fingerprint(&self) -> &str {
        &self.app_approval_fingerprint
    }

    pub(crate) const fn os_permission_state(&self) -> ReadinessObservationState {
        self.os_permission_state
    }

    pub(crate) const fn app_approval_state(&self) -> ReadinessObservationState {
        self.app_approval_state
    }

    pub(crate) const fn observed_at(&self) -> time::OffsetDateTime {
        self.window.observed_at
    }

    pub(crate) const fn expires_at(&self) -> time::OffsetDateTime {
        self.window.expires_at
    }
}

impl std::fmt::Debug for ReadinessEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadinessEvidence")
            .finish_non_exhaustive()
    }
}

impl AdapterReadiness {
    pub fn ready(
        adapter: &'static str,
        message: &'static str,
        desktop_binding: DesktopBindingRef,
        execution_policy: ExecutionPolicy,
        evidence: ReadinessEvidence,
        provider_smoke_evidence: Option<ProviderSmokeEvidence>,
        resolved_provider_binding: Option<satelle_core::ResolvedProviderBinding>,
    ) -> Result<Self, EvidenceError> {
        normalized_identifier(adapter)?;
        let features = execution_policy.experimental_features();
        let provider_evidence_matches = matches!(
            (
                features.provider_computer_use(),
                &provider_smoke_evidence,
                &resolved_provider_binding,
            ),
            (FeatureChoice::Enabled, Some(_), Some(_)) | (FeatureChoice::Disabled, None, _)
        );
        if features.computer_use() != FeatureChoice::Enabled
            || execution_policy.desktop_target().binding() != &desktop_binding
            || !provider_evidence_matches
        {
            return Err(EvidenceError::InconsistentPolicy);
        }
        let source = evidence.source();
        Ok(Self {
            ready: true,
            adapter,
            message,
            desktop_binding,
            execution_policy,
            evidence,
            provider_smoke_evidence,
            resolved_provider_binding,
            source,
            checks: successful_native_readiness_checks(),
        })
    }

    pub(crate) fn with_source(mut self, source: ReadinessSource) -> Self {
        self.source = source;
        self
    }

    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    pub const fn adapter(&self) -> &'static str {
        self.adapter
    }

    pub const fn message(&self) -> &'static str {
        self.message
    }

    pub fn desktop_binding(&self) -> &DesktopBindingRef {
        &self.desktop_binding
    }

    pub fn execution_policy(&self) -> &ExecutionPolicy {
        &self.execution_policy
    }

    pub(crate) fn evidence(&self) -> &ReadinessEvidence {
        &self.evidence
    }

    pub(crate) fn provider_smoke_evidence(&self) -> Option<&ProviderSmokeEvidence> {
        self.provider_smoke_evidence.as_ref()
    }

    pub(crate) fn resolved_provider_binding(
        &self,
    ) -> Option<&satelle_core::ResolvedProviderBinding> {
        self.resolved_provider_binding.as_ref()
    }

    pub(crate) const fn source(&self) -> ReadinessSource {
        self.source
    }

    pub(crate) fn checks(&self) -> &[NativeReadinessCheck] {
        &self.checks
    }
}

fn successful_native_readiness_checks() -> Vec<NativeReadinessCheck> {
    use NativeReadinessCheckKind::{
        AppApproval, Authentication, CodexRuntime, ControlPlane, FileManagement, NativeComputerUse,
        OsPermissions, PointerClick, PointerDrag,
    };

    [
        (CodexRuntime, "codex_runtime_available"),
        (Authentication, "authentication_available"),
        (NativeComputerUse, "native_computer_use_available"),
        (OsPermissions, "os_permissions_live_proven"),
        (AppApproval, "app_approval_live_proven"),
        (ControlPlane, "control_plane_admitted"),
        (PointerClick, "pointer_click_confirmed"),
        (PointerDrag, "pointer_drag_confirmed"),
    ]
    .into_iter()
    .map(|(kind, reason)| NativeReadinessCheck {
        kind,
        status: NativeReadinessCheckStatus::Passed,
        reason,
    })
    .chain(std::iter::once(NativeReadinessCheck {
        kind: FileManagement,
        status: NativeReadinessCheckStatus::NotEvaluated,
        reason: "not_required_for_prompt_admission",
    }))
    .collect()
}

fn normalized_identifier(value: impl Into<String>) -> Result<String, EvidenceError> {
    let value = value.into();
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(EvidenceError::InvalidIdentifier);
    }
    Ok(value)
}

fn fingerprint(value: impl Into<String>) -> Result<String, EvidenceError> {
    let value = value.into();
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(EvidenceError::InvalidFingerprint);
    }
    Ok(value)
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    use satelle_core::session::{
        ApprovalPolicy, DesktopTarget, EffectiveModelRef, ExperimentalFeatureChoices,
        ProviderBindingRef, SandboxPolicy, TimeoutPolicy,
    };

    const FINGERPRINT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FINGERPRINT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn public_evidence_boundary_validates_and_redacts_values() {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        let key = readiness_key(
            "boundary-session",
            ReadinessObservationState::Unknown,
            ReadinessObservationState::Unknown,
        );
        let evidence = key
            .evidence(
                "readiness-private-id",
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap();
        let debug = format!("{evidence:?}");
        assert!(!debug.contains("readiness-private-id"));
        assert!(!debug.contains(FINGERPRINT_A));

        assert_eq!(
            EvidenceError::InvalidFingerprint,
            ReadinessCacheKey::new(
                key.adapter,
                key.desktop_binding.clone(),
                key.execution_policy.clone(),
                "0.144.0",
                "1.0.0",
                None::<String>,
                "raw-secret",
                FINGERPRINT_B,
                key.os_permission_state,
                key.app_approval_state,
            )
            .unwrap_err()
        );
        assert_eq!(
            EvidenceError::InvalidWindow,
            ProviderSmokeEvidence::new(
                "provider-1",
                FINGERPRINT_A,
                FINGERPRINT_B,
                observed_at,
                observed_at,
            )
            .unwrap_err()
        );
        assert_eq!(
            EvidenceError::InvalidFingerprint,
            ProviderSmokeEvidence::new(
                "provider-1",
                FINGERPRINT_A,
                "raw-secret",
                observed_at,
                observed_at + time::Duration::minutes(1),
            )
            .unwrap_err()
        );
    }

    #[test]
    fn provider_evidence_presence_matches_the_effective_policy() {
        let desktop = DesktopBindingRef::new("desktop-1").unwrap();
        let policy = policy(desktop.clone(), FeatureChoice::Disabled);
        let evidence = readiness_evidence();

        assert!(
            AdapterReadiness::ready(
                "test",
                "ready",
                desktop.clone(),
                policy.clone(),
                evidence.clone(),
                None,
                None,
            )
            .is_ok()
        );
        assert_eq!(
            EvidenceError::InconsistentPolicy,
            AdapterReadiness::ready(
                "test",
                "ready",
                desktop,
                policy,
                evidence,
                Some(provider_evidence()),
                None,
            )
            .unwrap_err()
        );
    }

    #[test]
    fn native_readiness_reports_a_closed_live_check_set() {
        let desktop = DesktopBindingRef::new("desktop-checks").unwrap();
        let policy = policy(desktop.clone(), FeatureChoice::Disabled);
        let checks = vec![
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::CodexRuntime,
                status: NativeReadinessCheckStatus::Passed,
                reason: "codex_runtime_available",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::Authentication,
                status: NativeReadinessCheckStatus::Passed,
                reason: "authentication_available",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::NativeComputerUse,
                status: NativeReadinessCheckStatus::Passed,
                reason: "native_computer_use_available",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::OsPermissions,
                status: NativeReadinessCheckStatus::Passed,
                reason: "os_permissions_live_proven",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::AppApproval,
                status: NativeReadinessCheckStatus::Passed,
                reason: "app_approval_live_proven",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::ControlPlane,
                status: NativeReadinessCheckStatus::Passed,
                reason: "control_plane_admitted",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::PointerClick,
                status: NativeReadinessCheckStatus::Passed,
                reason: "pointer_click_confirmed",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::PointerDrag,
                status: NativeReadinessCheckStatus::Passed,
                reason: "pointer_drag_confirmed",
            },
            NativeReadinessCheck {
                kind: NativeReadinessCheckKind::FileManagement,
                status: NativeReadinessCheckStatus::NotEvaluated,
                reason: "not_required_for_prompt_admission",
            },
        ];

        let readiness = AdapterReadiness::ready(
            "test",
            "ready",
            desktop,
            policy,
            readiness_evidence(),
            None,
            None,
        )
        .unwrap();

        assert_eq!(readiness.source, ReadinessSource::Live);
        assert_eq!(readiness.checks, checks);
        assert_eq!(ReadinessSource::Cache.as_str(), "cache");
        assert_eq!(
            NativeReadinessCheckStatus::ManualActionRequired.as_str(),
            "manual_action_required"
        );
        assert_eq!(NativeReadinessCheckStatus::Failed.as_str(), "failed");
    }

    #[test]
    fn adapter_readiness_preserves_cached_evidence_source() {
        let desktop = DesktopBindingRef::new("desktop-cache-source").unwrap();
        let policy = policy(desktop.clone(), FeatureChoice::Disabled);
        let readiness = AdapterReadiness::ready(
            "test",
            "ready",
            desktop,
            policy,
            readiness_evidence().with_source(ReadinessSource::Cache),
            None,
            None,
        )
        .unwrap();

        assert_eq!(readiness.source(), ReadinessSource::Cache);
        assert_eq!(readiness.evidence().source(), ReadinessSource::Cache);
    }

    #[test]
    fn native_readiness_cache_identity_includes_session_and_observation_states() {
        let granted = readiness_key(
            "session-a",
            ReadinessObservationState::Granted,
            ReadinessObservationState::Unknown,
        );
        let other_session = readiness_key(
            "session-b",
            ReadinessObservationState::Granted,
            ReadinessObservationState::Unknown,
        );
        let denied_permission = readiness_key(
            "session-a",
            ReadinessObservationState::Denied,
            ReadinessObservationState::Unknown,
        );
        let granted_app = readiness_key(
            "session-a",
            ReadinessObservationState::Granted,
            ReadinessObservationState::Granted,
        );

        assert_ne!(
            granted.desktop_session_ref,
            other_session.desktop_session_ref
        );
        assert_ne!(
            granted.os_permission_state,
            denied_permission.os_permission_state
        );
        assert_ne!(granted.app_approval_state, granted_app.app_approval_state);
    }

    #[test]
    fn native_readiness_cache_key_matches_only_exact_evidence_identity() {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        let key = readiness_key(
            "match-session",
            ReadinessObservationState::Granted,
            ReadinessObservationState::Unknown,
        );
        let evidence = key
            .evidence(
                "readiness-match",
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap();

        assert!(key.matches_evidence(&evidence));
        assert!(
            !readiness_key(
                "other-session",
                ReadinessObservationState::Granted,
                ReadinessObservationState::Unknown,
            )
            .matches_evidence(&evidence)
        );
        assert!(
            !readiness_key(
                "match-session",
                ReadinessObservationState::Denied,
                ReadinessObservationState::Unknown,
            )
            .matches_evidence(&evidence)
        );
        assert!(
            !readiness_key(
                "match-session",
                ReadinessObservationState::Granted,
                ReadinessObservationState::Granted,
            )
            .matches_evidence(&evidence)
        );
    }

    fn readiness_evidence() -> ReadinessEvidence {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        readiness_key(
            "readiness-evidence-session",
            ReadinessObservationState::Unknown,
            ReadinessObservationState::Unknown,
        )
        .evidence(
            "readiness-1",
            observed_at,
            observed_at + time::Duration::minutes(5),
        )
        .unwrap()
    }

    fn readiness_key(
        desktop_session_ref: &str,
        os_permission_state: ReadinessObservationState,
        app_approval_state: ReadinessObservationState,
    ) -> ReadinessCacheKey {
        let desktop = DesktopBindingRef::new("desktop-cache-identity").unwrap();
        let policy = ExecutionPolicy::new(
            EffectiveModelRef::new("model-cache-identity").unwrap(),
            ProviderBindingRef::new("provider-cache-identity").unwrap(),
            DesktopTarget::new(desktop.clone(), desktop_session_ref),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
        );

        ReadinessCacheKey::new(
            "test",
            desktop,
            policy,
            "0.144.0",
            "1.0.0",
            None::<String>,
            FINGERPRINT_A,
            FINGERPRINT_B,
            os_permission_state,
            app_approval_state,
        )
        .unwrap()
    }

    fn provider_evidence() -> ProviderSmokeEvidence {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        ProviderSmokeEvidence::new(
            "provider-1",
            FINGERPRINT_A,
            FINGERPRINT_B,
            observed_at,
            observed_at + time::Duration::hours(24),
        )
        .unwrap()
    }

    fn policy(desktop: DesktopBindingRef, provider_computer_use: FeatureChoice) -> ExecutionPolicy {
        ExecutionPolicy::new(
            EffectiveModelRef::new("model-1").unwrap(),
            ProviderBindingRef::new("provider-1").unwrap(),
            DesktopTarget::new(desktop, "adapter-test-desktop-session"),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, provider_computer_use),
        )
    }
}

/// Opaque durable work identity presented to the external adapter. Storage
/// tokens and ordering decisions remain private to the runtime module.
#[derive(Clone, Copy)]
pub struct AdapterSubject<'a> {
    subject: &'a RecoverySubject,
}

impl<'a> AdapterSubject<'a> {
    pub(super) const fn new(subject: &'a RecoverySubject) -> Self {
        Self { subject }
    }

    pub fn session_id(self) -> &'a SessionId {
        self.subject.session_id()
    }

    pub fn turn_id(self) -> &'a TurnId {
        self.subject.turn_id()
    }

    pub(crate) fn turn_state(self) -> satelle_core::session::TurnState {
        self.subject.turn_state()
    }

    pub fn host_identity(self) -> &'a HostIdentityRef {
        self.subject.host_identity()
    }

    pub fn session_state_revision(self) -> SessionStateRevision {
        self.subject.expected_revisions().session()
    }

    pub fn turn_state_revision(self) -> TurnStateRevision {
        self.subject.expected_revisions().turn()
    }

    pub fn has_upstream_references(self) -> bool {
        self.subject.upstream_thread_ref().is_some() || self.subject.upstream_turn_ref().is_some()
    }

    pub(crate) fn upstream_thread_ref(self) -> Option<&'a str> {
        self.subject
            .upstream_thread_ref()
            .map(crate::storage::PrivateUpstreamRef::as_str)
    }

    pub(crate) fn upstream_turn_ref(self) -> Option<&'a str> {
        self.subject
            .upstream_turn_ref()
            .map(crate::storage::PrivateUpstreamRef::as_str)
    }

    pub(crate) fn upstream_goal_ref(self) -> Option<&'a str> {
        self.subject
            .upstream_goal_ref()
            .map(crate::storage::PrivateUpstreamRef::as_str)
    }

    pub fn has_request_token(self) -> bool {
        let _opaque_token = self.subject.request_token();
        true
    }
}

pub struct ExecuteRequest<'a> {
    host: &'a str,
    prompt: &'a str,
    execution_mode: satelle_core::session::TurnExecutionMode,
    execution_policy: &'a ExecutionPolicy,
    resolved_provider_binding: Option<&'a satelle_core::ResolvedProviderBinding>,
    subject: AdapterSubject<'a>,
    persist_upstream_ref: &'a dyn Fn(UpstreamReference) -> Result<(), SatelleError>,
    attachments: &'a [crate::attachment::StagedImage],
}

impl<'a> ExecuteRequest<'a> {
    pub(super) const fn new(
        host: &'a str,
        prompt: &'a str,
        execution_mode: satelle_core::session::TurnExecutionMode,
        execution_policy: &'a ExecutionPolicy,
        subject: AdapterSubject<'a>,
        persist_upstream_ref: &'a dyn Fn(UpstreamReference) -> Result<(), SatelleError>,
        attachments: &'a [crate::attachment::StagedImage],
    ) -> Self {
        Self {
            host,
            prompt,
            execution_mode,
            execution_policy,
            resolved_provider_binding: None,
            subject,
            persist_upstream_ref,
            attachments,
        }
    }

    pub(super) const fn with_resolved_provider_binding(
        mut self,
        binding: Option<&'a satelle_core::ResolvedProviderBinding>,
    ) -> Self {
        self.resolved_provider_binding = binding;
        self
    }

    pub const fn host(&self) -> &'a str {
        self.host
    }

    pub const fn prompt(&self) -> &'a str {
        self.prompt
    }

    pub(crate) const fn attachments(&self) -> &'a [crate::attachment::StagedImage] {
        self.attachments
    }

    pub const fn execution_mode(&self) -> satelle_core::session::TurnExecutionMode {
        self.execution_mode
    }

    pub const fn execution_policy(&self) -> &'a ExecutionPolicy {
        self.execution_policy
    }

    pub const fn resolved_provider_binding(
        &self,
    ) -> Option<&'a satelle_core::ResolvedProviderBinding> {
        self.resolved_provider_binding
    }

    /// Returns the private Codex thread reference for a follow-up Turn. This
    /// identity is available only at the trusted adapter boundary and never
    /// enters public Session, event, log, or error contracts.
    pub fn upstream_thread_ref(&self) -> Option<&'a str> {
        self.subject
            .subject
            .upstream_thread_ref()
            .map(crate::storage::PrivateUpstreamRef::as_str)
    }

    pub fn upstream_goal_ref(&self) -> Option<&'a str> {
        self.subject.upstream_goal_ref()
    }

    pub const fn subject(&self) -> AdapterSubject<'a> {
        self.subject
    }

    /// Commits the Codex thread identity before the adapter waits for any
    /// later response or notification that depends on it.
    pub fn persist_upstream_thread_ref(&self, value: &str) -> Result<(), SatelleError> {
        (self.persist_upstream_ref)(UpstreamReference::Thread(value.to_string()))
    }

    /// Commits the Codex Turn identity before the adapter waits for terminal
    /// completion, cancellation, or recovery evidence.
    pub fn persist_upstream_turn_ref(&self, value: &str) -> Result<(), SatelleError> {
        (self.persist_upstream_ref)(UpstreamReference::Turn(value.to_string()))
    }

    pub fn persist_upstream_goal_ref(&self, value: &str) -> Result<(), SatelleError> {
        (self.persist_upstream_ref)(UpstreamReference::Goal(value.to_string()))
    }
}

pub(super) enum UpstreamReference {
    Thread(String),
    Turn(String),
    Goal(String),
}

pub struct ExecuteResult {
    outcome: ExecuteOutcome,
    events: Vec<SatelleEvent>,
    terminal_error: Option<SatelleError>,
}

enum ExecuteOutcome {
    Terminal(TurnTransition),
    StoppedByControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryObservation {
    Running,
    Completed,
    Blocked,
    Failed,
    Unknown,
}

impl ExecuteResult {
    pub fn new(transition: TurnTransition, events: Vec<SatelleEvent>) -> Self {
        Self {
            outcome: ExecuteOutcome::Terminal(transition),
            events,
            terminal_error: None,
        }
    }

    pub(crate) fn terminal_failure(error: SatelleError) -> Self {
        Self {
            outcome: ExecuteOutcome::Terminal(TurnTransition::Failed),
            events: Vec::new(),
            terminal_error: Some(error),
        }
    }

    pub(crate) fn stopped_by_control() -> Self {
        Self {
            outcome: ExecuteOutcome::StoppedByControl,
            events: Vec::new(),
            terminal_error: None,
        }
    }

    pub(super) fn transition(&self) -> Option<TurnTransition> {
        match &self.outcome {
            ExecuteOutcome::Terminal(transition) => Some(transition.clone()),
            ExecuteOutcome::StoppedByControl => None,
        }
    }

    pub(super) fn into_events(self) -> Vec<SatelleEvent> {
        self.events
    }

    pub(super) fn terminal_error(&self) -> Option<&SatelleError> {
        self.terminal_error.as_ref()
    }
}

/// The only external Computer Use seam. SQLite remains concrete and internal;
/// production and deterministic adapters vary only at this true I/O seam.
pub trait ComputerUseAdapter: Send + Sync + 'static {
    /// Adapters without an upstream control plane have no separate protocol
    /// admission step. Production Codex adapters must override this method.
    fn admit_operation(&self, _operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        Ok(())
    }

    /// Whether a follow-up must resume a retained upstream thread instead of
    /// allowing the adapter to start unrelated work under the same Session.
    fn requires_upstream_thread_for_follow_up(&self) -> bool {
        false
    }

    /// Resolves one exact provider binding without running readiness or
    /// provider I/O. Adapters must opt in explicitly because synthesizing a
    /// binding here would let non-authoritative callers invent provenance.
    fn resolve_provider_binding(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<satelle_core::ResolvedProviderBinding, SatelleError> {
        Err(SatelleError {
            code: satelle_core::ErrorCode::ModelProviderBindingMissing,
            message: "the Host adapter cannot resolve an exact provider binding".to_string(),
            recovery_command: Some(
                "configure one exact Host model/provider binding before validating it".to_string(),
            ),
            source_detail: None,
            details: std::collections::BTreeMap::new(),
        })
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError>;

    /// Returns a production cache key without running the harmless action.
    /// Adapters that do not represent the native production boundary opt out.
    fn readiness_cache_key(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ReadinessCacheKey>, SatelleError> {
        Ok(None)
    }

    /// Runs preflight or reconstructs readiness from Host-owned evidence.
    /// The default deliberately ignores cached evidence because only an
    /// adapter with an explicit cache key can prove it still matches.
    fn preflight_terminal(
        &self,
        host: &str,
        _cached: Option<ReadinessEvidence>,
        _cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
    ) -> AdapterPreflight {
        match self.preflight(host, provider_intent) {
            Ok(readiness) => AdapterPreflight::Ready(readiness),
            Err(error) => AdapterPreflight::UncachedFailure(error),
        }
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError>;

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError>;

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError>;

    /// Releases an execution exchange that was deliberately held open until
    /// its confirmed stopped state became durable.
    fn stop_committed(&self, _session_id: &SessionId, _turn_id: &TurnId) {}
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct BlockedComputerUseAdapter {
    error: SatelleError,
}

#[cfg(test)]
impl BlockedComputerUseAdapter {
    pub(crate) fn new(error: SatelleError) -> Self {
        Self { error }
    }

    fn blocked<T>(&self) -> Result<T, SatelleError> {
        Err(self.error.clone())
    }
}

#[cfg(test)]
impl ComputerUseAdapter for BlockedComputerUseAdapter {
    fn preflight(
        &self,
        _host: &str,
        _provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.blocked()
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.blocked()
    }

    fn observe_stop(&self, _subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        self.blocked()
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        self.blocked()
    }
}
