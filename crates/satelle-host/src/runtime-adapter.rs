use crate::storage::RecoverySubject;
use satelle_core::session::{
    DesktopBindingRef, ExecutionPolicy, FeatureChoice, HostIdentityRef, SessionStateRevision,
    StopObservation, TurnStateRevision, TurnTransition,
};
use satelle_core::{ControlPlaneOperation, SatelleError, SatelleEvent, SessionId, TurnId};
use std::sync::{Arc, RwLock};
use thiserror::Error;

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
}

impl std::fmt::Debug for AdapterReadiness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterReadiness")
            .field("ready", &self.ready)
            .field("adapter", &self.adapter)
            .field("desktop_binding", &self.desktop_binding)
            .field("execution_policy", &self.execution_policy)
            .finish_non_exhaustive()
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
}

impl ProviderSmokeEvidence {
    pub fn new(
        result_id: impl Into<String>,
        provider_config_fingerprint: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            window: EvidenceWindow::new(result_id, observed_at, expires_at)?,
            provider_config_fingerprint: fingerprint(provider_config_fingerprint)?,
        })
    }

    pub(crate) fn result_id(&self) -> &str {
        &self.window.result_id
    }

    pub(crate) fn provider_config_fingerprint(&self) -> &str {
        &self.provider_config_fingerprint
    }

    pub(crate) const fn observed_at(&self) -> time::OffsetDateTime {
        self.window.observed_at
    }

    pub(crate) const fn expires_at(&self) -> time::OffsetDateTime {
        self.window.expires_at
    }
}

impl std::fmt::Debug for ProviderSmokeEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderSmokeEvidence")
            .finish_non_exhaustive()
    }
}

/// Versioned evidence observed by a successful live readiness probe.
///
/// The adapter supplies only normalized identifiers and fingerprints. Raw probe
/// output, screenshots, and transcripts never cross this persistence boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct ReadinessEvidence {
    window: EvidenceWindow,
    codex_version: String,
    native_runtime_version: String,
    plugin_version: Option<String>,
    os_permission_fingerprint: String,
    app_approval_fingerprint: String,
}

impl ReadinessEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result_id: impl Into<String>,
        codex_version: impl Into<String>,
        native_runtime_version: impl Into<String>,
        plugin_version: Option<impl Into<String>>,
        os_permission_fingerprint: impl Into<String>,
        app_approval_fingerprint: impl Into<String>,
        observed_at: time::OffsetDateTime,
        expires_at: time::OffsetDateTime,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            window: EvidenceWindow::new(result_id, observed_at, expires_at)?,
            codex_version: normalized_identifier(codex_version)?,
            native_runtime_version: normalized_identifier(native_runtime_version)?,
            plugin_version: plugin_version.map(normalized_identifier).transpose()?,
            os_permission_fingerprint: fingerprint(os_permission_fingerprint)?,
            app_approval_fingerprint: fingerprint(app_approval_fingerprint)?,
        })
    }

    pub(crate) fn result_id(&self) -> &str {
        &self.window.result_id
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
    ) -> Result<Self, EvidenceError> {
        normalized_identifier(adapter)?;
        let features = execution_policy.experimental_features();
        let provider_evidence_matches = matches!(
            (features.provider_computer_use(), &provider_smoke_evidence),
            (FeatureChoice::Enabled, Some(_)) | (FeatureChoice::Disabled, None)
        );
        if features.computer_use() != FeatureChoice::Enabled
            || execution_policy.desktop_target().binding() != &desktop_binding
            || !provider_evidence_matches
        {
            return Err(EvidenceError::InconsistentPolicy);
        }
        Ok(Self {
            ready: true,
            adapter,
            message,
            desktop_binding,
            execution_policy,
            evidence,
            provider_smoke_evidence,
        })
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
        let evidence = ReadinessEvidence::new(
            "readiness-private-id",
            "0.144.0",
            "1.0.0",
            Some("plugin-1.0.0"),
            FINGERPRINT_A,
            FINGERPRINT_B,
            observed_at,
            observed_at + time::Duration::minutes(5),
        )
        .unwrap();
        let debug = format!("{evidence:?}");
        assert!(!debug.contains("readiness-private-id"));
        assert!(!debug.contains(FINGERPRINT_A));

        assert_eq!(
            EvidenceError::InvalidFingerprint,
            ReadinessEvidence::new(
                "readiness-2",
                "0.144.0",
                "1.0.0",
                None::<String>,
                "raw-secret",
                FINGERPRINT_B,
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap_err()
        );
        assert_eq!(
            EvidenceError::InvalidWindow,
            ProviderSmokeEvidence::new("provider-1", FINGERPRINT_A, observed_at, observed_at,)
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
            )
            .unwrap_err()
        );
    }

    fn readiness_evidence() -> ReadinessEvidence {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        ReadinessEvidence::new(
            "readiness-1",
            "0.144.0",
            "1.0.0",
            None::<String>,
            FINGERPRINT_A,
            FINGERPRINT_B,
            observed_at,
            observed_at + time::Duration::minutes(5),
        )
        .unwrap()
    }

    fn provider_evidence() -> ProviderSmokeEvidence {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        ProviderSmokeEvidence::new(
            "provider-1",
            FINGERPRINT_A,
            observed_at,
            observed_at + time::Duration::hours(24),
        )
        .unwrap()
    }

    fn policy(desktop: DesktopBindingRef, provider_computer_use: FeatureChoice) -> ExecutionPolicy {
        ExecutionPolicy::new(
            EffectiveModelRef::new("model-1").unwrap(),
            ProviderBindingRef::new("provider-1").unwrap(),
            DesktopTarget::new(desktop),
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

    pub fn has_request_token(self) -> bool {
        let _opaque_token = self.subject.request_token();
        true
    }
}

pub struct ExecuteRequest<'a> {
    host: &'a str,
    prompt: &'a str,
    subject: AdapterSubject<'a>,
    persist_upstream_ref: &'a dyn Fn(UpstreamReference) -> Result<(), SatelleError>,
}

impl<'a> ExecuteRequest<'a> {
    pub(super) const fn new(
        host: &'a str,
        prompt: &'a str,
        subject: AdapterSubject<'a>,
        persist_upstream_ref: &'a dyn Fn(UpstreamReference) -> Result<(), SatelleError>,
    ) -> Self {
        Self {
            host,
            prompt,
            subject,
            persist_upstream_ref,
        }
    }

    pub const fn host(&self) -> &'a str {
        self.host
    }

    pub const fn prompt(&self) -> &'a str {
        self.prompt
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
}

pub(super) enum UpstreamReference {
    Thread(String),
    Turn(String),
}

pub struct ExecuteResult {
    transition: TurnTransition,
    events: Vec<SatelleEvent>,
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
        Self { transition, events }
    }

    pub(super) fn transition(&self) -> TurnTransition {
        self.transition.clone()
    }

    pub(super) fn into_events(self) -> Vec<SatelleEvent> {
        self.events
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

    fn preflight(&self, host: &str) -> Result<AdapterReadiness, SatelleError>;

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError>;

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError>;

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError>;
}

/// Production uses this adapter until the real Codex Computer Use adapter is
/// available and admitted by the Phase 0 capability gate.
#[derive(Clone, Debug)]
pub(crate) struct BlockedComputerUseAdapter {
    state: BlockedComputerUseState,
}

#[derive(Clone, Debug)]
enum BlockedComputerUseState {
    #[cfg(test)]
    Static(SatelleError),
    Production(Arc<RwLock<crate::ProductionCapabilitySnapshot>>),
}

impl BlockedComputerUseAdapter {
    #[cfg(test)]
    pub(crate) fn new(error: SatelleError) -> Self {
        Self {
            state: BlockedComputerUseState::Static(error),
        }
    }

    pub(crate) fn production(snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>) -> Self {
        Self {
            state: BlockedComputerUseState::Production(snapshot),
        }
    }

    fn blocked<T>(&self) -> Result<T, SatelleError> {
        match &self.state {
            #[cfg(test)]
            BlockedComputerUseState::Static(error) => Err(error.clone()),
            BlockedComputerUseState::Production(snapshot) => {
                let snapshot = crate::read_production_snapshot(snapshot)?;
                Err(crate::execution_blocker(&snapshot.verdict))
            }
        }
    }
}

impl ComputerUseAdapter for BlockedComputerUseAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        match &self.state {
            #[cfg(test)]
            BlockedComputerUseState::Static(_) => Ok(()),
            BlockedComputerUseState::Production(snapshot) => {
                crate::read_production_snapshot(snapshot)?
                    .control_plane_admission
                    .admit(operation)
            }
        }
    }

    fn preflight(&self, _host: &str) -> Result<AdapterReadiness, SatelleError> {
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
