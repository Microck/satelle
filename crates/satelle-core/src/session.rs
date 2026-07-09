use crate::ids::{SessionId, TurnId};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use thiserror::Error;
use time::OffsetDateTime;

#[path = "session-public.rs"]
mod public_serde;

const MAX_REFERENCE_BYTES: usize = 128;

/// A rejected reference never retains the supplied text, so the error is safe to log.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReferenceError {
    #[error("the reference is empty")]
    Empty,
    #[error("the reference exceeds {MAX_REFERENCE_BYTES} bytes")]
    TooLong,
    #[error("the reference contains a character outside the safe identifier alphabet")]
    InvalidCharacter,
}

fn validate_reference(value: &str) -> Result<(), ReferenceError> {
    if value.is_empty() {
        return Err(ReferenceError::Empty);
    }
    if value.len() > MAX_REFERENCE_BYTES {
        return Err(ReferenceError::TooLong);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(ReferenceError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! define_reference {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
                let value = value.into();
                validate_reference(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

define_reference!(
    HostIdentityRef,
    "An immutable, non-secret reference to the Host Daemon identity."
);
define_reference!(
    DesktopBindingRef,
    "An immutable, non-secret reference to the authorized desktop binding."
);
define_reference!(
    EffectiveModelRef,
    "The validated effective model identifier captured for one turn."
);
define_reference!(
    ProviderBindingRef,
    "The validated non-secret provider-binding reference captured for one turn."
);

/// A payload-free summary chosen by Satelle, never constructed from runtime text.
///
/// Arbitrary redacted text can be added only after a verified redaction type exists.
/// Keeping this enum closed means a raw prompt or secret cannot be wrapped and then
/// serialized by a public response by ordinary construction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeSummary {
    TaskCompleted,
    BlockedByPolicy,
    ExecutionFailed,
}

impl SafeSummary {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskCompleted => "task_completed",
            Self::BlockedByPolicy => "blocked_by_policy",
            Self::ExecutionFailed => "execution_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RevisionError {
    #[error("a state revision must be at least one")]
    Zero,
    #[error("the state revision is exhausted")]
    Exhausted,
}

macro_rules! define_revision {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub fn initial() -> Self {
                Self(NonZeroU64::MIN)
            }

            pub fn new(value: u64) -> Result<Self, RevisionError> {
                NonZeroU64::new(value).map(Self).ok_or(RevisionError::Zero)
            }

            pub fn get(self) -> u64 {
                self.0.get()
            }

            pub fn next(self) -> Result<Self, RevisionError> {
                self.get()
                    .checked_add(1)
                    .and_then(NonZeroU64::new)
                    .map(Self)
                    .ok_or(RevisionError::Exhausted)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.get().fmt(formatter)
            }
        }
    };
}

define_revision!(SessionStateRevision);
define_revision!(TurnStateRevision);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedRevisions {
    session: SessionStateRevision,
    turn: TurnStateRevision,
}

impl ExpectedRevisions {
    pub fn new(session: SessionStateRevision, turn: TurnStateRevision) -> Self {
        Self { session, turn }
    }

    pub fn session(self) -> SessionStateRevision {
        self.session
    }

    pub fn turn(self) -> TurnStateRevision {
        self.turn
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnState {
    Starting,
    Running,
    RecoveryPending,
    Completed,
    Blocked,
    Failed,
    Stopped,
}

impl TurnState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Blocked | Self::Failed | Self::Stopped
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalTurnState {
    Completed,
    Blocked,
    Failed,
    Stopped,
}

impl TryFrom<TurnState> for TerminalTurnState {
    type Error = ();

    fn try_from(state: TurnState) -> Result<Self, Self::Error> {
        match state {
            TurnState::Completed => Ok(Self::Completed),
            TurnState::Blocked => Ok(Self::Blocked),
            TurnState::Failed => Ok(Self::Failed),
            TurnState::Stopped => Ok(Self::Stopped),
            TurnState::Starting | TurnState::Running | TurnState::RecoveryPending => Err(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
pub enum SessionActivity {
    Idle,
    Starting {
        turn_id: TurnId,
        turn_state_revision: TurnStateRevision,
    },
    Running {
        turn_id: TurnId,
        turn_state_revision: TurnStateRevision,
    },
    RecoveryPending {
        turn_id: TurnId,
        turn_state_revision: TurnStateRevision,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalPolicy {
    Untrusted,
    OnFailure,
    OnRequest,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxPolicy {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureChoice {
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExperimentalFeatureChoices {
    computer_use: FeatureChoice,
    provider_computer_use: FeatureChoice,
}

impl ExperimentalFeatureChoices {
    pub fn new(computer_use: FeatureChoice, provider_computer_use: FeatureChoice) -> Self {
        Self {
            computer_use,
            provider_computer_use,
        }
    }

    pub fn computer_use(self) -> FeatureChoice {
        self.computer_use
    }

    pub fn provider_computer_use(self) -> FeatureChoice {
        self.provider_computer_use
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutPolicy(NonZeroU32);

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("a bounded timeout must be at least one second")]
pub struct TimeoutError;

impl TimeoutPolicy {
    pub fn bounded_seconds(seconds: u32) -> Result<Self, TimeoutError> {
        NonZeroU32::new(seconds).map(Self).ok_or(TimeoutError)
    }

    pub fn seconds(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopTarget(DesktopBindingRef);

impl DesktopTarget {
    pub fn new(binding: DesktopBindingRef) -> Self {
        Self(binding)
    }

    pub fn binding(&self) -> &DesktopBindingRef {
        &self.0
    }
}

/// An immutable effective-policy snapshot. It deliberately has no serde contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPolicy {
    effective_model: EffectiveModelRef,
    provider_binding: ProviderBindingRef,
    desktop_target: DesktopTarget,
    approval_policy: ApprovalPolicy,
    sandbox_policy: SandboxPolicy,
    timeout_policy: TimeoutPolicy,
    experimental_features: ExperimentalFeatureChoices,
}

impl ExecutionPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        effective_model: EffectiveModelRef,
        provider_binding: ProviderBindingRef,
        desktop_target: DesktopTarget,
        approval_policy: ApprovalPolicy,
        sandbox_policy: SandboxPolicy,
        timeout_policy: TimeoutPolicy,
        experimental_features: ExperimentalFeatureChoices,
    ) -> Self {
        Self {
            effective_model,
            provider_binding,
            desktop_target,
            approval_policy,
            sandbox_policy,
            timeout_policy,
            experimental_features,
        }
    }

    pub fn effective_model(&self) -> &EffectiveModelRef {
        &self.effective_model
    }

    pub fn provider_binding(&self) -> &ProviderBindingRef {
        &self.provider_binding
    }

    pub fn desktop_target(&self) -> &DesktopTarget {
        &self.desktop_target
    }

    pub fn approval_policy(&self) -> ApprovalPolicy {
        self.approval_policy
    }

    pub fn sandbox_policy(&self) -> SandboxPolicy {
        self.sandbox_policy
    }

    pub fn timeout_policy(&self) -> TimeoutPolicy {
        self.timeout_policy
    }

    pub fn experimental_features(&self) -> ExperimentalFeatureChoices {
        self.experimental_features
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicTurn {
    session_id: SessionId,
    turn_id: TurnId,
    turn_state_revision: TurnStateRevision,
    state: TurnState,
    #[serde(with = "time::serde::rfc3339")]
    started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    terminal_at: Option<OffsetDateTime>,
    safe_summary: Option<SafeSummary>,
}

impl PublicTurn {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub fn turn_state_revision(&self) -> TurnStateRevision {
        self.turn_state_revision
    }

    pub fn state(&self) -> TurnState {
        self.state
    }

    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn terminal_at(&self) -> Option<OffsetDateTime> {
        self.terminal_at
    }

    pub fn safe_summary(&self) -> Option<&SafeSummary> {
        self.safe_summary.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PublicSession {
    session_id: SessionId,
    session_state_revision: SessionStateRevision,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
    activity: SessionActivity,
    turns: Vec<PublicTurn>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("the public lifecycle snapshot violates a Session invariant")]
pub struct PublicSnapshotError;

impl PublicSession {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn session_state_revision(&self) -> SessionStateRevision {
        self.session_state_revision
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn activity(&self) -> &SessionActivity {
        &self.activity
    }

    pub fn turns(&self) -> &[PublicTurn] {
        &self.turns
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnTransition {
    Running,
    RecoveryPending,
    Completed,
    Blocked,
    Failed,
}

impl TurnTransition {
    fn into_parts(self) -> (TurnState, Option<SafeSummary>) {
        match self {
            Self::Running => (TurnState::Running, None),
            Self::RecoveryPending => (TurnState::RecoveryPending, None),
            Self::Completed => (TurnState::Completed, Some(SafeSummary::TaskCompleted)),
            Self::Blocked => (TurnState::Blocked, Some(SafeSummary::BlockedByPolicy)),
            Self::Failed => (TurnState::Failed, Some(SafeSummary::ExecutionFailed)),
        }
    }
}

fn transition_allowed(from: TurnState, to: TurnState) -> bool {
    matches!(
        (from, to),
        (TurnState::Starting, TurnState::Running)
            | (TurnState::Starting, TurnState::RecoveryPending)
            | (TurnState::Starting, TurnState::Completed)
            | (TurnState::Starting, TurnState::Blocked)
            | (TurnState::Starting, TurnState::Failed)
            | (TurnState::Starting, TurnState::Stopped)
            | (TurnState::Running, TurnState::RecoveryPending)
            | (TurnState::Running, TurnState::Completed)
            | (TurnState::Running, TurnState::Blocked)
            | (TurnState::Running, TurnState::Failed)
            | (TurnState::Running, TurnState::Stopped)
            | (TurnState::RecoveryPending, TurnState::Running)
            | (TurnState::RecoveryPending, TurnState::Completed)
            | (TurnState::RecoveryPending, TurnState::Blocked)
            | (TurnState::RecoveryPending, TurnState::Failed)
            | (TurnState::RecoveryPending, TurnState::Stopped)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionSubject {
    Session,
    Turn,
}

/// A payload-free reason that persisted lifecycle state could not be hydrated.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SnapshotError {
    #[error("the stored Session has no Turn history")]
    EmptyTurnHistory,
    #[error("the stored Session contains a duplicate Turn identifier")]
    DuplicateTurnId,
    #[error("the stored Session contains more than one active Turn")]
    MultipleActiveTurns,
    #[error("the stored active Turn is not the last Turn in history")]
    ActiveTurnNotLast,
    #[error("a stored Turn state is incoherent with its revision")]
    IncoherentTurnRevision,
    #[error("the stored Turn revision sum exceeds the supported range")]
    RevisionSumOverflow,
    #[error("the stored Session revision is incoherent with its Turn revisions")]
    IncoherentSessionRevision,
    #[error("a stored Turn execution policy targets a different desktop binding")]
    DesktopTargetMismatch,
    #[error("the stored Session creation time is later than its update time")]
    SessionTimeInversion,
    #[error("a stored Turn start time is later than its update time")]
    TurnTimeInversion,
    #[error("a stored Turn timestamp is outside its Session bounds")]
    TurnOutsideSessionBounds,
    #[error("the first stored Turn does not start when its Session was created")]
    FirstTurnStartMismatch,
    #[error("stored Turn history moves backwards in time")]
    TurnHistoryTimeInversion,
    #[error("a stored terminal Turn has no terminal timestamp")]
    MissingTerminalTimestamp,
    #[error("a stored terminal Turn has the wrong state-derived safe summary")]
    TerminalSummaryMismatch,
    #[error("a stored nonterminal Turn contains terminal metadata")]
    NonterminalMetadataPresent,
    #[error("a stored terminal timestamp differs from its Turn update time")]
    TerminalTimestampMismatch,
    #[error("the stored Session update time differs from its latest Turn update")]
    LatestTurnUpdateMismatch,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LifecycleError {
    #[error("{subject:?} state revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict {
        subject: RevisionSubject,
        expected: u64,
        actual: u64,
    },
    #[error("{subject:?} state revision is exhausted")]
    RevisionExhausted { subject: RevisionSubject },
    #[error("the requested Satelle Turn does not belong to this Session")]
    TurnNotFound,
    #[error("the Satelle Turn identifier already belongs to this Session")]
    DuplicateTurnId,
    #[error("the Session already has an active Turn in {state:?}")]
    ActiveTurnExists { state: TurnState },
    #[error("the Session has no active Turn")]
    NoActiveTurn,
    #[error("the Turn is already terminal in {state:?}")]
    TerminalTurn { state: TerminalTurnState },
    #[error("the Turn cannot transition from {from:?} to {to:?}")]
    InvalidTransition { from: TurnState, to: TurnState },
    #[error("the Turn execution policy targets a different desktop binding")]
    DesktopTargetMismatch,
    #[error("a lifecycle mutation timestamp precedes committed state")]
    NonMonotonicTimestamp,
    #[error("stored lifecycle state is invalid: {reason}")]
    InvalidSnapshot { reason: SnapshotError },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCommit {
    session_revision: SessionStateRevision,
    turn_revision: TurnStateRevision,
    state: TurnState,
}

impl LifecycleCommit {
    fn new(
        session_revision: SessionStateRevision,
        turn_revision: TurnStateRevision,
        state: TurnState,
    ) -> Self {
        Self {
            session_revision,
            turn_revision,
            state,
        }
    }

    pub fn session_revision(&self) -> SessionStateRevision {
        self.session_revision
    }

    pub fn turn_revision(&self) -> TurnStateRevision {
        self.turn_revision
    }

    pub fn state(&self) -> TurnState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleMutation {
    Unchanged(ExpectedRevisions),
    Committed(LifecycleCommit),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopObservation {
    CancellationConfirmed,
    UpstreamInactiveConfirmed,
    UpstreamStillActive,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedOwnership {
    Active,
    RecoveryPending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    Stopped(LifecycleCommit),
    AlreadyTerminal {
        state: TerminalTurnState,
        revisions: ExpectedRevisions,
    },
    NotConfirmed {
        ownership: RetainedOwnership,
        mutation: LifecycleMutation,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Turn {
    id: TurnId,
    revision: TurnStateRevision,
    state: TurnState,
    execution_policy: ExecutionPolicy,
    started_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    terminal_at: Option<OffsetDateTime>,
    safe_summary: Option<SafeSummary>,
}

impl Turn {
    fn starting(id: TurnId, execution_policy: ExecutionPolicy, at: OffsetDateTime) -> Self {
        Self {
            id,
            revision: TurnStateRevision::initial(),
            state: TurnState::Starting,
            execution_policy,
            started_at: at,
            updated_at: at,
            terminal_at: None,
            safe_summary: None,
        }
    }

    pub fn id(&self) -> &TurnId {
        &self.id
    }

    pub fn turn_state_revision(&self) -> TurnStateRevision {
        self.revision
    }

    pub fn state(&self) -> TurnState {
        self.state
    }

    pub fn execution_policy(&self) -> &ExecutionPolicy {
        &self.execution_policy
    }

    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn terminal_at(&self) -> Option<OffsetDateTime> {
        self.terminal_at
    }

    pub fn safe_summary(&self) -> Option<&SafeSummary> {
        self.safe_summary.as_ref()
    }

    fn to_public(&self, session_id: &SessionId) -> PublicTurn {
        PublicTurn {
            session_id: session_id.clone(),
            turn_id: self.id.clone(),
            turn_state_revision: self.revision,
            state: self.state,
            started_at: self.started_at,
            updated_at: self.updated_at,
            terminal_at: self.terminal_at,
            safe_summary: self.safe_summary,
        }
    }
}

/// Persistence-only Turn state. It deliberately has no serde contract.
///
/// Storage adapters construct this from typed columns, then pass it through
/// [`Session::restore`] before the state can be used as a lifecycle aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnSnapshot {
    id: TurnId,
    revision: TurnStateRevision,
    state: TurnState,
    execution_policy: ExecutionPolicy,
    started_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    terminal_at: Option<OffsetDateTime>,
    safe_summary: Option<SafeSummary>,
}

impl TurnSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: TurnId,
        revision: TurnStateRevision,
        state: TurnState,
        execution_policy: ExecutionPolicy,
        started_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        terminal_at: Option<OffsetDateTime>,
        safe_summary: Option<SafeSummary>,
    ) -> Self {
        Self {
            id,
            revision,
            state,
            execution_policy,
            started_at,
            updated_at,
            terminal_at,
            safe_summary,
        }
    }

    pub fn id(&self) -> &TurnId {
        &self.id
    }

    pub fn turn_state_revision(&self) -> TurnStateRevision {
        self.revision
    }

    pub fn state(&self) -> TurnState {
        self.state
    }

    pub fn execution_policy(&self) -> &ExecutionPolicy {
        &self.execution_policy
    }

    pub fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn terminal_at(&self) -> Option<OffsetDateTime> {
        self.terminal_at
    }

    pub fn safe_summary(&self) -> Option<SafeSummary> {
        self.safe_summary
    }
}

/// Persistence-only Session state. It deliberately has no serde contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshot {
    id: SessionId,
    revision: SessionStateRevision,
    host_identity: HostIdentityRef,
    desktop_binding: DesktopBindingRef,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    turns: Vec<TurnSnapshot>,
}

impl SessionSnapshot {
    pub fn new(
        id: SessionId,
        revision: SessionStateRevision,
        host_identity: HostIdentityRef,
        desktop_binding: DesktopBindingRef,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        turns: Vec<TurnSnapshot>,
    ) -> Self {
        Self {
            id,
            revision,
            host_identity,
            desktop_binding,
            created_at,
            updated_at,
            turns,
        }
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn session_state_revision(&self) -> SessionStateRevision {
        self.revision
    }

    pub fn host_identity(&self) -> &HostIdentityRef {
        &self.host_identity
    }

    pub fn desktop_binding(&self) -> &DesktopBindingRef {
        &self.desktop_binding
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn turns(&self) -> &[TurnSnapshot] {
        &self.turns
    }

    fn validate(&self) -> Result<(), SnapshotError> {
        if self.turns.is_empty() {
            return Err(SnapshotError::EmptyTurnHistory);
        }
        if self.created_at > self.updated_at {
            return Err(SnapshotError::SessionTimeInversion);
        }

        let mut seen_turn_ids = std::collections::HashSet::with_capacity(self.turns.len());
        let mut active_turn_index = None;
        let mut turn_revision_sum = 0_u64;
        let mut previous_turn_updated_at = None;

        for (index, turn) in self.turns.iter().enumerate() {
            if !seen_turn_ids.insert(&turn.id) {
                return Err(SnapshotError::DuplicateTurnId);
            }
            if turn.started_at > turn.updated_at {
                return Err(SnapshotError::TurnTimeInversion);
            }
            if turn.started_at < self.created_at || turn.updated_at > self.updated_at {
                return Err(SnapshotError::TurnOutsideSessionBounds);
            }
            if index == 0 && turn.started_at != self.created_at {
                return Err(SnapshotError::FirstTurnStartMismatch);
            }
            if previous_turn_updated_at.is_some_and(|previous| turn.started_at < previous) {
                return Err(SnapshotError::TurnHistoryTimeInversion);
            }
            previous_turn_updated_at = Some(turn.updated_at);

            if turn.execution_policy.desktop_target().binding() != &self.desktop_binding {
                return Err(SnapshotError::DesktopTargetMismatch);
            }
            if (turn.state == TurnState::Starting) != (turn.revision.get() == 1) {
                return Err(SnapshotError::IncoherentTurnRevision);
            }

            if !turn.state.is_terminal() {
                if active_turn_index.replace(index).is_some() {
                    return Err(SnapshotError::MultipleActiveTurns);
                }
                if turn.terminal_at.is_some() || turn.safe_summary.is_some() {
                    return Err(SnapshotError::NonterminalMetadataPresent);
                }
            } else {
                let terminal_at = turn
                    .terminal_at
                    .ok_or(SnapshotError::MissingTerminalTimestamp)?;
                if terminal_at != turn.updated_at {
                    return Err(SnapshotError::TerminalTimestampMismatch);
                }
                if turn.safe_summary != state_derived_safe_summary(turn.state) {
                    return Err(SnapshotError::TerminalSummaryMismatch);
                }
            }

            turn_revision_sum = turn_revision_sum
                .checked_add(turn.revision.get())
                .ok_or(SnapshotError::RevisionSumOverflow)?;
        }

        if active_turn_index.is_some_and(|index| index + 1 != self.turns.len()) {
            return Err(SnapshotError::ActiveTurnNotLast);
        }
        if turn_revision_sum != self.revision.get() {
            return Err(SnapshotError::IncoherentSessionRevision);
        }
        if self.turns.last().expect("nonempty history").updated_at != self.updated_at {
            return Err(SnapshotError::LatestTurnUpdateMismatch);
        }
        Ok(())
    }
}

fn state_derived_safe_summary(state: TurnState) -> Option<SafeSummary> {
    match state {
        TurnState::Completed => Some(SafeSummary::TaskCompleted),
        TurnState::Blocked => Some(SafeSummary::BlockedByPolicy),
        TurnState::Failed => Some(SafeSummary::ExecutionFailed),
        TurnState::Stopped
        | TurnState::Starting
        | TurnState::Running
        | TurnState::RecoveryPending => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    id: SessionId,
    revision: SessionStateRevision,
    host_identity: HostIdentityRef,
    desktop_binding: DesktopBindingRef,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    turns: Vec<Turn>,
}

impl Session {
    pub fn start(
        id: SessionId,
        host_identity: HostIdentityRef,
        desktop_binding: DesktopBindingRef,
        turn_id: TurnId,
        execution_policy: ExecutionPolicy,
        at: OffsetDateTime,
    ) -> Result<Self, LifecycleError> {
        if execution_policy.desktop_target().binding() != &desktop_binding {
            return Err(LifecycleError::DesktopTargetMismatch);
        }
        Ok(Self {
            id,
            revision: SessionStateRevision::initial(),
            host_identity,
            desktop_binding,
            created_at: at,
            updated_at: at,
            turns: vec![Turn::starting(turn_id, execution_policy, at)],
        })
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn session_state_revision(&self) -> SessionStateRevision {
        self.revision
    }

    pub fn host_identity(&self) -> &HostIdentityRef {
        &self.host_identity
    }

    pub fn desktop_binding(&self) -> &DesktopBindingRef {
        &self.desktop_binding
    }

    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    pub fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    pub fn turns(&self) -> impl ExactSizeIterator<Item = &Turn> {
        self.turns.iter()
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot::new(
            self.id.clone(),
            self.revision,
            self.host_identity.clone(),
            self.desktop_binding.clone(),
            self.created_at,
            self.updated_at,
            self.turns
                .iter()
                .map(|turn| {
                    TurnSnapshot::new(
                        turn.id.clone(),
                        turn.revision,
                        turn.state,
                        turn.execution_policy.clone(),
                        turn.started_at,
                        turn.updated_at,
                        turn.terminal_at,
                        turn.safe_summary,
                    )
                })
                .collect(),
        )
    }

    pub fn restore(snapshot: SessionSnapshot) -> Result<Self, LifecycleError> {
        snapshot
            .validate()
            .map_err(|reason| LifecycleError::InvalidSnapshot { reason })?;
        Ok(Self {
            id: snapshot.id,
            revision: snapshot.revision,
            host_identity: snapshot.host_identity,
            desktop_binding: snapshot.desktop_binding,
            created_at: snapshot.created_at,
            updated_at: snapshot.updated_at,
            turns: snapshot
                .turns
                .into_iter()
                .map(|turn| Turn {
                    id: turn.id,
                    revision: turn.revision,
                    state: turn.state,
                    execution_policy: turn.execution_policy,
                    started_at: turn.started_at,
                    updated_at: turn.updated_at,
                    terminal_at: turn.terminal_at,
                    safe_summary: turn.safe_summary,
                })
                .collect(),
        })
    }

    pub fn turn(&self, turn_id: &TurnId) -> Option<&Turn> {
        self.turns.iter().find(|turn| turn.id() == turn_id)
    }

    pub fn activity(&self) -> SessionActivity {
        let active = self.turns.iter().find(|turn| !turn.state().is_terminal());
        debug_assert_eq!(
            usize::from(active.is_some()),
            self.turns
                .iter()
                .filter(|turn| !turn.state().is_terminal())
                .count(),
            "Session methods must preserve the one-active-Turn invariant"
        );
        match active {
            None => SessionActivity::Idle,
            Some(turn) => match turn.state() {
                TurnState::Starting => SessionActivity::Starting {
                    turn_id: turn.id().clone(),
                    turn_state_revision: turn.turn_state_revision(),
                },
                TurnState::Running => SessionActivity::Running {
                    turn_id: turn.id().clone(),
                    turn_state_revision: turn.turn_state_revision(),
                },
                TurnState::RecoveryPending => SessionActivity::RecoveryPending {
                    turn_id: turn.id().clone(),
                    turn_state_revision: turn.turn_state_revision(),
                },
                TurnState::Completed
                | TurnState::Blocked
                | TurnState::Failed
                | TurnState::Stopped => unreachable!("terminal Turn was selected as active"),
            },
        }
    }

    pub fn is_active(&self) -> bool {
        !matches!(self.activity(), SessionActivity::Idle)
    }

    pub fn to_public(&self) -> PublicSession {
        PublicSession {
            session_id: self.id.clone(),
            session_state_revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
            activity: self.activity(),
            turns: self
                .turns
                .iter()
                .map(|turn| turn.to_public(&self.id))
                .collect(),
        }
    }

    pub fn start_follow_up(
        &mut self,
        expected_session_revision: SessionStateRevision,
        turn_id: TurnId,
        execution_policy: ExecutionPolicy,
        at: OffsetDateTime,
    ) -> Result<LifecycleCommit, LifecycleError> {
        self.check_session_revision(expected_session_revision)?;
        if let Some(active) = self.turns.iter().find(|turn| !turn.state().is_terminal()) {
            return Err(LifecycleError::ActiveTurnExists {
                state: active.state(),
            });
        }
        if self.turns.iter().any(|turn| turn.id() == &turn_id) {
            return Err(LifecycleError::DuplicateTurnId);
        }
        if execution_policy.desktop_target().binding() != &self.desktop_binding {
            return Err(LifecycleError::DesktopTargetMismatch);
        }
        if at < self.updated_at {
            return Err(LifecycleError::NonMonotonicTimestamp);
        }

        let session_revision = self.next_session_revision()?;
        self.turns
            .push(Turn::starting(turn_id, execution_policy, at));
        self.revision = session_revision;
        self.updated_at = at;
        Ok(LifecycleCommit::new(
            session_revision,
            TurnStateRevision::initial(),
            TurnState::Starting,
        ))
    }

    pub fn transition_turn(
        &mut self,
        turn_id: &TurnId,
        expected: ExpectedRevisions,
        transition: TurnTransition,
        at: OffsetDateTime,
    ) -> Result<LifecycleCommit, LifecycleError> {
        let index = self.checked_turn_index(turn_id, expected)?;
        let from = self.turns[index].state();
        if let Ok(state) = TerminalTurnState::try_from(from) {
            return Err(LifecycleError::TerminalTurn { state });
        }
        let (to, summary) = transition.into_parts();
        if !transition_allowed(from, to) {
            return Err(LifecycleError::InvalidTransition { from, to });
        }
        self.commit_turn_state(index, to, summary, at)
    }

    pub fn stop_turn(
        &mut self,
        turn_id: &TurnId,
        expected: ExpectedRevisions,
        observation: StopObservation,
        at: OffsetDateTime,
    ) -> Result<StopOutcome, LifecycleError> {
        let index = self
            .turns
            .iter()
            .position(|turn| turn.id() == turn_id)
            .ok_or(LifecycleError::TurnNotFound)?;
        let from = self.turns[index].state();
        if let Ok(state) = TerminalTurnState::try_from(from) {
            return Ok(StopOutcome::AlreadyTerminal {
                state,
                revisions: ExpectedRevisions::new(
                    self.revision,
                    self.turns[index].turn_state_revision(),
                ),
            });
        }
        self.check_session_revision(expected.session())?;
        self.check_turn_revision(index, expected.turn())?;

        match observation {
            StopObservation::CancellationConfirmed | StopObservation::UpstreamInactiveConfirmed => {
                self.commit_turn_state(index, TurnState::Stopped, None, at)
                    .map(StopOutcome::Stopped)
            }
            StopObservation::UpstreamStillActive => self.retain_ownership(
                index,
                TurnState::Running,
                RetainedOwnership::Active,
                expected,
                at,
            ),
            StopObservation::OutcomeUnknown => self.retain_ownership(
                index,
                TurnState::RecoveryPending,
                RetainedOwnership::RecoveryPending,
                expected,
                at,
            ),
        }
    }

    pub fn mark_active_recovery_pending(
        &mut self,
        expected: ExpectedRevisions,
        at: OffsetDateTime,
    ) -> Result<LifecycleMutation, LifecycleError> {
        self.check_session_revision(expected.session())?;
        let index = self
            .turns
            .iter()
            .position(|turn| !turn.state().is_terminal())
            .ok_or(LifecycleError::NoActiveTurn)?;
        self.check_turn_revision(index, expected.turn())?;
        if self.turns[index].state() == TurnState::RecoveryPending {
            return Ok(LifecycleMutation::Unchanged(expected));
        }
        self.commit_turn_state(index, TurnState::RecoveryPending, None, at)
            .map(LifecycleMutation::Committed)
    }

    fn retain_ownership(
        &mut self,
        index: usize,
        state: TurnState,
        ownership: RetainedOwnership,
        expected: ExpectedRevisions,
        at: OffsetDateTime,
    ) -> Result<StopOutcome, LifecycleError> {
        let mutation = if self.turns[index].state() == state {
            LifecycleMutation::Unchanged(expected)
        } else {
            LifecycleMutation::Committed(self.commit_turn_state(index, state, None, at)?)
        };
        Ok(StopOutcome::NotConfirmed {
            ownership,
            mutation,
        })
    }

    fn checked_turn_index(
        &self,
        turn_id: &TurnId,
        expected: ExpectedRevisions,
    ) -> Result<usize, LifecycleError> {
        self.check_session_revision(expected.session())?;
        let index = self
            .turns
            .iter()
            .position(|turn| turn.id() == turn_id)
            .ok_or(LifecycleError::TurnNotFound)?;
        self.check_turn_revision(index, expected.turn())?;
        Ok(index)
    }

    fn check_session_revision(&self, expected: SessionStateRevision) -> Result<(), LifecycleError> {
        if self.revision == expected {
            Ok(())
        } else {
            Err(LifecycleError::RevisionConflict {
                subject: RevisionSubject::Session,
                expected: expected.get(),
                actual: self.revision.get(),
            })
        }
    }

    fn check_turn_revision(
        &self,
        index: usize,
        expected: TurnStateRevision,
    ) -> Result<(), LifecycleError> {
        let actual = self.turns[index].turn_state_revision();
        if actual == expected {
            Ok(())
        } else {
            Err(LifecycleError::RevisionConflict {
                subject: RevisionSubject::Turn,
                expected: expected.get(),
                actual: actual.get(),
            })
        }
    }

    fn next_session_revision(&self) -> Result<SessionStateRevision, LifecycleError> {
        self.revision
            .next()
            .map_err(|_| LifecycleError::RevisionExhausted {
                subject: RevisionSubject::Session,
            })
    }

    fn commit_turn_state(
        &mut self,
        index: usize,
        state: TurnState,
        safe_summary: Option<SafeSummary>,
        at: OffsetDateTime,
    ) -> Result<LifecycleCommit, LifecycleError> {
        if at < self.updated_at || at < self.turns[index].updated_at {
            return Err(LifecycleError::NonMonotonicTimestamp);
        }
        let session_revision = self.next_session_revision()?;
        let turn_revision =
            self.turns[index]
                .revision
                .next()
                .map_err(|_| LifecycleError::RevisionExhausted {
                    subject: RevisionSubject::Turn,
                })?;

        let turn = &mut self.turns[index];
        turn.state = state;
        turn.revision = turn_revision;
        turn.updated_at = at;
        turn.terminal_at = state.is_terminal().then_some(at);
        turn.safe_summary = safe_summary;
        self.revision = session_revision;
        self.updated_at = at;

        Ok(LifecycleCommit::new(session_revision, turn_revision, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};
    use time::format_description::well_known::Rfc3339;

    const SESSION_ID: &str = "rs_01890a5d-ac96-7b7c-9f89-37c3d0a66e11";
    const TURN_1: &str = "rt_01890a5d-ac96-7b7d-9f89-37c3d0a66e11";
    const TURN_2: &str = "rt_01890a5d-ac96-7b7e-9f89-37c3d0a66e11";

    #[test]
    fn states_have_exact_names_and_terminal_partition() {
        let cases = [
            (TurnState::Starting, "starting", false),
            (TurnState::Running, "running", false),
            (TurnState::RecoveryPending, "recovery_pending", false),
            (TurnState::Completed, "completed", true),
            (TurnState::Blocked, "blocked", true),
            (TurnState::Failed, "failed", true),
            (TurnState::Stopped, "stopped", true),
        ];
        for (state, name, terminal) in cases {
            assert_eq!(
                format!("\"{name}\""),
                serde_json::to_string(&state).unwrap()
            );
            assert_eq!(terminal, state.is_terminal());
        }
    }

    #[test]
    fn transition_matrix_is_exhaustive() {
        let sources = [
            TurnState::Starting,
            TurnState::Running,
            TurnState::RecoveryPending,
            TurnState::Completed,
            TurnState::Blocked,
            TurnState::Failed,
            TurnState::Stopped,
        ];
        let targets = [
            TurnState::Running,
            TurnState::RecoveryPending,
            TurnState::Completed,
            TurnState::Blocked,
            TurnState::Failed,
        ];
        for source in sources {
            for target in targets {
                let mut session = in_state(source);
                let outcome = transition_to(&mut session, target, 10);
                let allowed = matches!(
                    (source, target),
                    (TurnState::Starting, TurnState::Running)
                        | (TurnState::Starting, TurnState::RecoveryPending)
                        | (TurnState::Starting, TurnState::Completed)
                        | (TurnState::Starting, TurnState::Blocked)
                        | (TurnState::Starting, TurnState::Failed)
                        | (TurnState::Running, TurnState::RecoveryPending)
                        | (TurnState::Running, TurnState::Completed)
                        | (TurnState::Running, TurnState::Blocked)
                        | (TurnState::Running, TurnState::Failed)
                        | (TurnState::RecoveryPending, TurnState::Running)
                        | (TurnState::RecoveryPending, TurnState::Completed)
                        | (TurnState::RecoveryPending, TurnState::Blocked)
                        | (TurnState::RecoveryPending, TurnState::Failed)
                );
                if allowed {
                    assert_eq!(target, outcome.unwrap().state());
                } else if source.is_terminal() {
                    assert_eq!(
                        Err(LifecycleError::TerminalTurn {
                            state: TerminalTurnState::try_from(source).unwrap(),
                        }),
                        outcome
                    );
                } else {
                    assert_eq!(
                        Err(LifecycleError::InvalidTransition {
                            from: source,
                            to: target,
                        }),
                        outcome
                    );
                }
            }
        }
    }

    #[test]
    fn terminal_state_derives_its_matching_payload_free_summary() {
        for (state, expected_summary) in [
            (TurnState::Completed, SafeSummary::TaskCompleted),
            (TurnState::Blocked, SafeSummary::BlockedByPolicy),
            (TurnState::Failed, SafeSummary::ExecutionFailed),
        ] {
            let mut session = in_state(TurnState::Running);
            transition_to(&mut session, state, 10).unwrap();

            assert_eq!(
                Some(&expected_summary),
                session.turn(&turn_1()).unwrap().safe_summary()
            );
        }
    }

    #[test]
    fn lifecycle_timestamps_cannot_move_backwards() {
        let turn_id = turn_1();
        let mut active = in_state(TurnState::Running);
        let before = active.to_public();

        assert_eq!(
            Err(LifecycleError::NonMonotonicTimestamp),
            active.transition_turn(
                &turn_id,
                revisions(&active),
                TurnTransition::Completed,
                at(0),
            )
        );
        assert_eq!(before, active.to_public());

        let mut idle = in_state(TurnState::Completed);
        let before = idle.to_public();
        assert_eq!(
            Err(LifecycleError::NonMonotonicTimestamp),
            idle.start_follow_up(
                idle.session_state_revision(),
                turn_2(),
                default_policy(),
                at(0),
            )
        );
        assert_eq!(before, idle.to_public());
    }

    #[test]
    fn stale_revision_cannot_overwrite_the_winning_terminal_state() {
        let turn_id = turn_1();
        let mut completion_wins = in_state(TurnState::Running);
        let stale = revisions(&completion_wins);
        completion_wins
            .transition_turn(
                &turn_id,
                stale,
                terminal_transition(TurnState::Completed),
                at(10),
            )
            .unwrap();
        assert!(matches!(
            completion_wins.stop_turn(
                &turn_id,
                stale,
                StopObservation::CancellationConfirmed,
                at(11),
            ),
            Ok(StopOutcome::AlreadyTerminal {
                state: TerminalTurnState::Completed,
                ..
            })
        ));
        assert_eq!(
            TurnState::Completed,
            completion_wins.turn(&turn_id).unwrap().state()
        );

        let mut stop_wins = in_state(TurnState::Running);
        let stale = revisions(&stop_wins);
        assert!(matches!(
            stop_wins
                .stop_turn(
                    &turn_id,
                    stale,
                    StopObservation::CancellationConfirmed,
                    at(10),
                )
                .unwrap(),
            StopOutcome::Stopped(_)
        ));
        assert!(matches!(
            stop_wins.transition_turn(
                &turn_id,
                stale,
                terminal_transition(TurnState::Completed),
                at(11),
            ),
            Err(LifecycleError::RevisionConflict { .. })
        ));
        assert_eq!(
            TurnState::Stopped,
            stop_wins.turn(&turn_id).unwrap().state()
        );
    }

    #[test]
    fn each_turn_commit_checks_and_increments_both_revisions_once() {
        let mut session = new_session();
        let running = transition_to(&mut session, TurnState::Running, 1).unwrap();
        assert_eq!(
            SessionStateRevision::new(2).unwrap(),
            running.session_revision()
        );
        assert_eq!(TurnStateRevision::new(2).unwrap(), running.turn_revision());

        let before = session.to_public();
        let stale_turn = ExpectedRevisions::new(
            session.session_state_revision(),
            TurnStateRevision::initial(),
        );
        assert!(matches!(
            session.transition_turn(
                &turn_1(),
                stale_turn,
                terminal_transition(TurnState::Completed),
                at(2),
            ),
            Err(LifecycleError::RevisionConflict {
                subject: RevisionSubject::Turn,
                expected: 1,
                actual: 2,
            })
        ));
        assert_eq!(before, session.to_public());

        let completed = transition_to(&mut session, TurnState::Completed, 3).unwrap();
        assert_eq!(
            SessionStateRevision::new(3).unwrap(),
            completed.session_revision()
        );
        assert_eq!(
            TurnStateRevision::new(3).unwrap(),
            completed.turn_revision()
        );
    }

    #[test]
    fn follow_up_preserves_history_and_at_most_one_turn_is_active() {
        let mut session = new_session();
        assert!(matches!(
            session.start_follow_up(
                session.session_state_revision(),
                turn_2(),
                policy(ApprovalPolicy::Never, desktop()),
                at(1),
            ),
            Err(LifecycleError::ActiveTurnExists {
                state: TurnState::Starting,
            })
        ));
        transition_to(&mut session, TurnState::Completed, 2).unwrap();
        let history_before = session.turn(&turn_1()).unwrap().to_public(session.id());
        let prior_revision = session.session_state_revision();
        let commit = session
            .start_follow_up(
                prior_revision,
                turn_2(),
                policy(ApprovalPolicy::Never, desktop()),
                at(3),
            )
            .unwrap();
        assert_eq!(prior_revision.next().unwrap(), commit.session_revision());
        assert_eq!(TurnStateRevision::initial(), commit.turn_revision());
        assert_eq!(
            history_before,
            session.turn(&turn_1()).unwrap().to_public(session.id())
        );
        assert_eq!(2, session.turns().count());
        assert_eq!(
            SessionActivity::Starting {
                turn_id: turn_2(),
                turn_state_revision: TurnStateRevision::initial(),
            },
            session.activity()
        );
        assert!(matches!(
            session.start_follow_up(
                session.session_state_revision(),
                TurnId::new(),
                default_policy(),
                at(4),
            ),
            Err(LifecycleError::ActiveTurnExists { .. })
        ));
    }

    #[test]
    fn stop_without_confirmation_retains_active_or_recovery_ownership() {
        let mut session = new_session();
        let active = session
            .stop_turn(
                &turn_1(),
                revisions(&session),
                StopObservation::UpstreamStillActive,
                at(1),
            )
            .unwrap();
        assert!(matches!(
            active,
            StopOutcome::NotConfirmed {
                ownership: RetainedOwnership::Active,
                mutation: LifecycleMutation::Committed(_),
            }
        ));
        assert_eq!(TurnState::Running, session.turn(&turn_1()).unwrap().state());

        let recovery = session
            .stop_turn(
                &turn_1(),
                revisions(&session),
                StopObservation::OutcomeUnknown,
                at(2),
            )
            .unwrap();
        assert!(matches!(
            recovery,
            StopOutcome::NotConfirmed {
                ownership: RetainedOwnership::RecoveryPending,
                mutation: LifecycleMutation::Committed(_),
            }
        ));
        assert!(session.is_active());

        let current = revisions(&session);
        assert_eq!(
            LifecycleMutation::Unchanged(current),
            session
                .mark_active_recovery_pending(current, at(3))
                .unwrap()
        );
        assert!(matches!(
            session
                .stop_turn(
                    &turn_1(),
                    revisions(&session),
                    StopObservation::UpstreamInactiveConfirmed,
                    at(4),
                )
                .unwrap(),
            StopOutcome::Stopped(_)
        ));
        assert!(!session.is_active());

        let before = session.to_public();
        assert!(matches!(
            session
                .stop_turn(
                    &turn_1(),
                    ExpectedRevisions::new(
                        SessionStateRevision::initial(),
                        TurnStateRevision::initial(),
                    ),
                    StopObservation::CancellationConfirmed,
                    at(5),
                )
                .unwrap(),
            StopOutcome::AlreadyTerminal {
                state: TerminalTurnState::Stopped,
                ..
            }
        ));
        assert_eq!(before, session.to_public());
    }

    #[test]
    fn policy_is_snapshotted_and_desktop_binding_is_immutable() {
        let mut session = in_state(TurnState::Completed);
        let first_policy = session.turn(&turn_1()).unwrap().execution_policy().clone();
        let second_policy = policy(ApprovalPolicy::Never, desktop());
        session
            .start_follow_up(
                session.session_state_revision(),
                turn_2(),
                second_policy.clone(),
                at(3),
            )
            .unwrap();
        assert_eq!(
            &first_policy,
            session.turn(&turn_1()).unwrap().execution_policy()
        );
        assert_eq!(
            &second_policy,
            session.turn(&turn_2()).unwrap().execution_policy()
        );
        assert_ne!(first_policy, second_policy);
        assert_eq!(&host(), session.host_identity());
        assert_eq!(&desktop(), session.desktop_binding());

        let mut idle = in_state(TurnState::Completed);
        let before = idle.to_public();
        assert_eq!(
            Err(LifecycleError::DesktopTargetMismatch),
            idle.start_follow_up(
                idle.session_state_revision(),
                turn_2(),
                policy(
                    ApprovalPolicy::OnRequest,
                    DesktopBindingRef::new("desktop-b").unwrap(),
                ),
                at(3),
            )
        );
        assert_eq!(before, idle.to_public());
    }

    #[test]
    fn public_json_has_exact_safe_allowlist() {
        let mut session = in_state(TurnState::Running);
        transition_to(&mut session, TurnState::Completed, 10).unwrap();
        let value = serde_json::to_value(session.to_public()).unwrap();
        let object = value.as_object().unwrap();
        exact_keys(
            object,
            &[
                "activity",
                "created_at",
                "session_id",
                "session_state_revision",
                "turns",
                "updated_at",
            ],
        );
        exact_keys(object["activity"].as_object().unwrap(), &["state"]);
        exact_keys(
            object["turns"].as_array().unwrap()[0].as_object().unwrap(),
            &[
                "safe_summary",
                "session_id",
                "started_at",
                "state",
                "terminal_at",
                "turn_id",
                "turn_state_revision",
                "updated_at",
            ],
        );
        let json = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "prompt",
            "thread_id",
            "upstream",
            "request_id",
            "goal_id",
            "model",
            "provider_binding",
            "approval_policy",
            "sandbox_policy",
        ] {
            assert!(!json.contains(forbidden), "public JSON leaked {forbidden}");
        }
        assert!(json.contains(SESSION_ID));
        assert!(json.contains(TURN_1));
    }

    #[test]
    fn internal_identity_canaries_do_not_enter_the_public_projection() {
        let host_canary = "CANARY_SECRET_do-not-serialize";
        let desktop_canary = "upstream-thread-01890a5d-ac96-7b7c";
        let desktop_binding = DesktopBindingRef::new(desktop_canary).unwrap();
        let mut session = Session::start(
            SessionId::parse(SESSION_ID).unwrap(),
            HostIdentityRef::new(host_canary).unwrap(),
            desktop_binding.clone(),
            turn_1(),
            policy(ApprovalPolicy::OnRequest, desktop_binding),
            at(0),
        )
        .unwrap();
        transition_to(&mut session, TurnState::Running, 1).unwrap();
        transition_to(&mut session, TurnState::Completed, 10).unwrap();

        let json = serde_json::to_string(&session.to_public()).unwrap();
        assert!(!json.contains(host_canary));
        assert!(!json.contains(desktop_canary));
        assert!(json.contains("task_completed"));
        assert_eq!(
            "\"task_completed\"",
            serde_json::to_string(&SafeSummary::TaskCompleted).unwrap()
        );
    }

    #[test]
    fn snapshot_round_trip_restores_full_history_and_distinct_policies() {
        let mut session = new_session();
        transition_to(&mut session, TurnState::Running, 1).unwrap();
        transition_to(&mut session, TurnState::Completed, 2).unwrap();
        let second_policy = policy(ApprovalPolicy::Never, desktop());
        session
            .start_follow_up(
                session.session_state_revision(),
                turn_2(),
                second_policy.clone(),
                at(3),
            )
            .unwrap();
        session
            .stop_turn(
                &turn_2(),
                ExpectedRevisions::new(
                    session.session_state_revision(),
                    session.turn(&turn_2()).unwrap().turn_state_revision(),
                ),
                StopObservation::CancellationConfirmed,
                at(4),
            )
            .unwrap();

        let snapshot = session.snapshot();
        assert_eq!(session.id(), snapshot.id());
        assert_eq!(
            session.session_state_revision(),
            snapshot.session_state_revision()
        );
        assert_eq!(session.host_identity(), snapshot.host_identity());
        assert_eq!(session.desktop_binding(), snapshot.desktop_binding());
        assert_eq!(session.created_at(), snapshot.created_at());
        assert_eq!(session.updated_at(), snapshot.updated_at());
        assert_eq!(2, snapshot.turns().len());
        assert_eq!(&second_policy, snapshot.turns()[1].execution_policy());
        for (turn, stored_turn) in session.turns().zip(snapshot.turns()) {
            assert_eq!(turn.id(), stored_turn.id());
            assert_eq!(
                turn.turn_state_revision(),
                stored_turn.turn_state_revision()
            );
            assert_eq!(turn.state(), stored_turn.state());
            assert_eq!(turn.execution_policy(), stored_turn.execution_policy());
            assert_eq!(turn.started_at(), stored_turn.started_at());
            assert_eq!(turn.updated_at(), stored_turn.updated_at());
            assert_eq!(turn.terminal_at(), stored_turn.terminal_at());
            assert_eq!(turn.safe_summary().copied(), stored_turn.safe_summary());
        }

        let restored = Session::restore(snapshot.clone()).unwrap();
        assert_eq!(session, restored);
        assert_eq!(snapshot, restored.snapshot());
    }

    #[test]
    fn active_snapshots_restore_and_enter_restart_recovery() {
        for state in [
            TurnState::Starting,
            TurnState::Running,
            TurnState::RecoveryPending,
        ] {
            let session = in_state(state);
            let mut restored = Session::restore(session.snapshot()).unwrap();
            assert_eq!(session, restored);

            let expected = revisions(&restored);
            let mutation = restored
                .mark_active_recovery_pending(expected, at(2))
                .unwrap();

            match state {
                TurnState::Starting | TurnState::Running => {
                    let LifecycleMutation::Committed(commit) = mutation else {
                        panic!("{state:?} must commit restart recovery");
                    };
                    assert_eq!(TurnState::RecoveryPending, commit.state());
                }
                TurnState::RecoveryPending => {
                    assert_eq!(LifecycleMutation::Unchanged(expected), mutation);
                }
                TurnState::Completed
                | TurnState::Blocked
                | TurnState::Failed
                | TurnState::Stopped => unreachable!(),
            }
            assert!(matches!(
                restored.activity(),
                SessionActivity::RecoveryPending { .. }
            ));
        }
    }

    #[test]
    fn restore_rejects_empty_turn_history() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::EmptyTurnHistory)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(0),
                at(0),
                vec![],
            ))
        );
    }

    #[test]
    fn restore_rejects_duplicate_turn_ids() {
        let turn = starting_turn_snapshot(turn_1(), at(0));
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::DuplicateTurnId)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(0),
                vec![turn.clone(), turn],
            ))
        );
    }

    #[test]
    fn restore_rejects_more_than_one_active_turn() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::MultipleActiveTurns)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(1),
                vec![
                    starting_turn_snapshot(turn_1(), at(0)),
                    starting_turn_snapshot(turn_2(), at(1)),
                ],
            ))
        );
    }

    #[test]
    fn restore_rejects_active_turn_before_history_end() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::ActiveTurnNotLast)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(3).unwrap(),
                desktop(),
                at(0),
                at(1),
                vec![
                    starting_turn_snapshot(turn_1(), at(0)),
                    terminal_turn_snapshot(
                        turn_2(),
                        TurnStateRevision::new(2).unwrap(),
                        TurnState::Completed,
                        at(1),
                        SafeSummary::TaskCompleted.into(),
                    ),
                ],
            ))
        );
    }

    #[test]
    fn typed_revisions_reject_zero_before_a_snapshot_can_be_built() {
        assert_eq!(Err(RevisionError::Zero), SessionStateRevision::new(0));
        assert_eq!(Err(RevisionError::Zero), TurnStateRevision::new(0));
    }

    #[test]
    fn restore_rejects_state_incoherent_turn_revision() {
        let turn = TurnSnapshot::new(
            turn_1(),
            TurnStateRevision::new(2).unwrap(),
            TurnState::Starting,
            default_policy(),
            at(0),
            at(0),
            None,
            None,
        );
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::IncoherentTurnRevision)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(0),
                vec![turn],
            ))
        );
    }

    #[test]
    fn restore_rejects_session_revision_incoherent_with_turn_mutations() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::IncoherentSessionRevision)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(0),
                vec![starting_turn_snapshot(turn_1(), at(0))],
            ))
        );
    }

    #[test]
    fn restore_reports_revision_sum_overflow_without_panicking() {
        let exhausted = TurnStateRevision::new(u64::MAX).unwrap();
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::RevisionSumOverflow)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(u64::MAX).unwrap(),
                desktop(),
                at(0),
                at(1),
                vec![
                    terminal_turn_snapshot(
                        turn_1(),
                        exhausted,
                        TurnState::Completed,
                        at(0),
                        Some(SafeSummary::TaskCompleted),
                    ),
                    terminal_turn_snapshot(turn_2(), exhausted, TurnState::Stopped, at(1), None,),
                ],
            ))
        );
    }

    #[test]
    fn restore_rejects_policy_desktop_mismatch() {
        let other_desktop = DesktopBindingRef::new("desktop-b").unwrap();
        let turn = TurnSnapshot::new(
            turn_1(),
            TurnStateRevision::initial(),
            TurnState::Starting,
            policy(ApprovalPolicy::OnRequest, other_desktop),
            at(0),
            at(0),
            None,
            None,
        );
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::DesktopTargetMismatch)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(0),
                at(0),
                vec![turn],
            ))
        );
    }

    #[test]
    fn restore_rejects_session_created_updated_time_inversion() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::SessionTimeInversion)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(2),
                at(1),
                vec![starting_turn_snapshot(turn_1(), at(2))],
            ))
        );
    }

    #[test]
    fn restore_rejects_turn_started_updated_time_inversion() {
        let turn = TurnSnapshot::new(
            turn_1(),
            TurnStateRevision::initial(),
            TurnState::Starting,
            default_policy(),
            at(2),
            at(1),
            None,
            None,
        );
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::TurnTimeInversion)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(0),
                at(2),
                vec![turn],
            ))
        );
    }

    #[test]
    fn restore_rejects_turn_times_outside_session_bounds() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::TurnOutsideSessionBounds)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(1),
                at(2),
                vec![starting_turn_snapshot(turn_1(), at(0))],
            ))
        );
    }

    #[test]
    fn restore_rejects_first_turn_start_different_from_session_creation() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::FirstTurnStartMismatch)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(0),
                at(1),
                vec![starting_turn_snapshot(turn_1(), at(1))],
            ))
        );
    }

    #[test]
    fn restore_rejects_turn_history_time_inversion() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::TurnHistoryTimeInversion)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(3).unwrap(),
                desktop(),
                at(0),
                at(2),
                vec![
                    terminal_turn_snapshot(
                        turn_1(),
                        TurnStateRevision::new(2).unwrap(),
                        TurnState::Completed,
                        at(2),
                        Some(SafeSummary::TaskCompleted),
                    ),
                    starting_turn_snapshot(turn_2(), at(1)),
                ],
            ))
        );
    }

    #[test]
    fn restore_rejects_terminal_turn_without_terminal_timestamp() {
        let turn = TurnSnapshot::new(
            turn_1(),
            TurnStateRevision::new(2).unwrap(),
            TurnState::Completed,
            default_policy(),
            at(0),
            at(1),
            None,
            Some(SafeSummary::TaskCompleted),
        );
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::MissingTerminalTimestamp)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(1),
                vec![turn],
            ))
        );
    }

    #[test]
    fn restore_rejects_terminal_turn_without_state_derived_summary() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::TerminalSummaryMismatch)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(1),
                vec![terminal_turn_snapshot(
                    turn_1(),
                    TurnStateRevision::new(2).unwrap(),
                    TurnState::Completed,
                    at(1),
                    None,
                )],
            ))
        );
    }

    #[test]
    fn restore_rejects_nonterminal_turn_with_terminal_metadata() {
        for (terminal_at, safe_summary) in [
            (Some(at(0)), None),
            (None, Some(SafeSummary::TaskCompleted)),
        ] {
            let turn = TurnSnapshot::new(
                turn_1(),
                TurnStateRevision::initial(),
                TurnState::Starting,
                default_policy(),
                at(0),
                at(0),
                terminal_at,
                safe_summary,
            );
            assert_eq!(
                Err(invalid_snapshot(SnapshotError::NonterminalMetadataPresent)),
                Session::restore(session_snapshot(
                    SessionStateRevision::initial(),
                    desktop(),
                    at(0),
                    at(0),
                    vec![turn],
                ))
            );
        }
    }

    #[test]
    fn restore_rejects_terminal_timestamp_different_from_updated_at() {
        let turn = TurnSnapshot::new(
            turn_1(),
            TurnStateRevision::new(2).unwrap(),
            TurnState::Completed,
            default_policy(),
            at(0),
            at(1),
            Some(at(2)),
            Some(SafeSummary::TaskCompleted),
        );
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::TerminalTimestampMismatch)),
            Session::restore(session_snapshot(
                SessionStateRevision::new(2).unwrap(),
                desktop(),
                at(0),
                at(1),
                vec![turn],
            ))
        );
    }

    #[test]
    fn restore_rejects_session_update_different_from_latest_turn_update() {
        assert_eq!(
            Err(invalid_snapshot(SnapshotError::LatestTurnUpdateMismatch)),
            Session::restore(session_snapshot(
                SessionStateRevision::initial(),
                desktop(),
                at(0),
                at(1),
                vec![starting_turn_snapshot(turn_1(), at(0))],
            ))
        );
    }

    fn new_session() -> Session {
        Session::start(
            SessionId::parse(SESSION_ID).unwrap(),
            host(),
            desktop(),
            turn_1(),
            default_policy(),
            at(0),
        )
        .unwrap()
    }

    fn session_snapshot(
        revision: SessionStateRevision,
        desktop_binding: DesktopBindingRef,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
        turns: Vec<TurnSnapshot>,
    ) -> SessionSnapshot {
        SessionSnapshot::new(
            SessionId::parse(SESSION_ID).unwrap(),
            revision,
            host(),
            desktop_binding,
            created_at,
            updated_at,
            turns,
        )
    }

    fn starting_turn_snapshot(id: TurnId, timestamp: OffsetDateTime) -> TurnSnapshot {
        TurnSnapshot::new(
            id,
            TurnStateRevision::initial(),
            TurnState::Starting,
            default_policy(),
            timestamp,
            timestamp,
            None,
            None,
        )
    }

    fn terminal_turn_snapshot(
        id: TurnId,
        revision: TurnStateRevision,
        state: TurnState,
        timestamp: OffsetDateTime,
        safe_summary: Option<SafeSummary>,
    ) -> TurnSnapshot {
        TurnSnapshot::new(
            id,
            revision,
            state,
            default_policy(),
            at(0),
            timestamp,
            Some(timestamp),
            safe_summary,
        )
    }

    fn invalid_snapshot(reason: SnapshotError) -> LifecycleError {
        LifecycleError::InvalidSnapshot { reason }
    }

    fn in_state(state: TurnState) -> Session {
        let mut session = new_session();
        match state {
            TurnState::Starting => {}
            TurnState::Running
            | TurnState::RecoveryPending
            | TurnState::Completed
            | TurnState::Blocked
            | TurnState::Failed => {
                transition_to(&mut session, state, 1).unwrap();
            }
            TurnState::Stopped => {
                session
                    .stop_turn(
                        &turn_1(),
                        revisions(&session),
                        StopObservation::CancellationConfirmed,
                        at(1),
                    )
                    .unwrap();
            }
        }
        session
    }

    fn transition_to(
        session: &mut Session,
        state: TurnState,
        second: u8,
    ) -> Result<LifecycleCommit, LifecycleError> {
        let transition = match state {
            TurnState::Running => TurnTransition::Running,
            TurnState::RecoveryPending => TurnTransition::RecoveryPending,
            TurnState::Completed | TurnState::Blocked | TurnState::Failed => {
                terminal_transition(state)
            }
            TurnState::Starting | TurnState::Stopped => unreachable!(),
        };
        session.transition_turn(&turn_1(), revisions(session), transition, at(second))
    }

    fn terminal_transition(state: TurnState) -> TurnTransition {
        match state {
            TurnState::Completed => TurnTransition::Completed,
            TurnState::Blocked => TurnTransition::Blocked,
            TurnState::Failed => TurnTransition::Failed,
            _ => unreachable!(),
        }
    }

    fn revisions(session: &Session) -> ExpectedRevisions {
        ExpectedRevisions::new(
            session.session_state_revision(),
            session.turn(&turn_1()).unwrap().turn_state_revision(),
        )
    }

    fn default_policy() -> ExecutionPolicy {
        policy(ApprovalPolicy::OnRequest, desktop())
    }

    fn policy(approval: ApprovalPolicy, desktop: DesktopBindingRef) -> ExecutionPolicy {
        ExecutionPolicy::new(
            EffectiveModelRef::new("computer-use-model").unwrap(),
            ProviderBindingRef::new("provider-binding-a").unwrap(),
            DesktopTarget::new(desktop),
            approval,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(300).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
        )
    }

    fn turn_1() -> TurnId {
        TurnId::parse(TURN_1).unwrap()
    }

    fn turn_2() -> TurnId {
        TurnId::parse(TURN_2).unwrap()
    }

    fn host() -> HostIdentityRef {
        HostIdentityRef::new("host-a").unwrap()
    }

    fn desktop() -> DesktopBindingRef {
        DesktopBindingRef::new("desktop-a").unwrap()
    }

    fn at(second: u8) -> OffsetDateTime {
        OffsetDateTime::parse(&format!("2026-01-02T03:04:{second:02}Z"), &Rfc3339).unwrap()
    }

    fn exact_keys(object: &Map<String, Value>, expected: &[&str]) {
        let mut actual: Vec<_> = object.keys().map(String::as_str).collect();
        actual.sort_unstable();
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        assert_eq!(expected, actual);
    }
}
