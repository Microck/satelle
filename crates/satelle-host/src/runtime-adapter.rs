use crate::storage::RecoverySubject;
use satelle_core::session::{
    DesktopBindingRef, ExecutionPolicy, HostIdentityRef, SessionStateRevision, StopObservation,
    TurnStateRevision, TurnTransition,
};
use satelle_core::{SatelleError, SatelleEvent, SessionId, TurnId};

/// Typed evidence returned before the runtime may durably admit work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterReadiness {
    ready: bool,
    adapter: &'static str,
    message: &'static str,
    desktop_binding: DesktopBindingRef,
    execution_policy: ExecutionPolicy,
}

impl AdapterReadiness {
    pub fn ready(
        adapter: &'static str,
        message: &'static str,
        desktop_binding: DesktopBindingRef,
        execution_policy: ExecutionPolicy,
    ) -> Self {
        Self {
            ready: true,
            adapter,
            message,
            desktop_binding,
            execution_policy,
        }
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
    error: SatelleError,
}

impl BlockedComputerUseAdapter {
    pub(crate) fn new(error: SatelleError) -> Self {
        Self { error }
    }

    fn blocked<T>(&self) -> Result<T, SatelleError> {
        Err(self.error.clone())
    }
}

impl ComputerUseAdapter for BlockedComputerUseAdapter {
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
