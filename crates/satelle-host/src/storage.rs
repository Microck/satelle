mod auth;
mod codec;
mod logs;
mod open;
mod operational;
#[path = "storage/operator-log.rs"]
mod operator_log;
mod retention;
mod setup_ledger;
mod sql;
pub(crate) mod stop;
#[cfg(test)]
mod tests;

// Admission needs an initial expiry, then the terminal commit resets it so the
// full replay window begins only after the operation has finished.
pub(crate) const IDEMPOTENCY_RETENTION: time::Duration = time::Duration::hours(24);
pub(crate) const DEFAULT_LEASE_STALE_AFTER: time::Duration = time::Duration::seconds(30);

pub(crate) use self::auth::{ApiTokenRegistration, SensitiveRequestDigest};
use self::codec::{
    format_time, idempotent_operation_token, load_required_session,
    load_session_at_operation_outcome, load_session_from_connection, parse_time,
    turn_idempotency_token, validated_private_reference,
};
pub(crate) use self::logs::LogPageStorageError;
use self::logs::canonical_log;
pub(crate) use self::logs::{SafeLogRecord, StoredLogRecord};
#[cfg(test)]
use self::open::DATABASE_FILE_NAME;
#[cfg(all(test, unix))]
use self::open::LOCK_FILE_NAME;
use self::open::{PROTECTED_FILE_NAMES, sqlite_error};
#[cfg(test)]
pub(crate) use self::operator_log::{
    OperatorLogFailureKind, OperatorLogSink, OperatorLogWriteOutcome,
};
pub(crate) use self::operator_log::{OperatorLogMirror, OperatorLogPolicy};
pub(crate) use self::setup_ledger::{
    MaintenanceLeaseCapability, MaintenanceLeaseState, MaintenanceRecoverySubject,
};
pub use self::setup_ledger::{
    SetupActionPlan, SetupActionRecord, SetupActionSkipReason, SetupActionStatus,
    SetupOperationKind, SetupRepairAction, SetupRepairDecision, SetupRepairPlan,
    SetupRepairPostcondition, SetupRepairProbe, SetupRunPlan, SetupRunRecord, SetupRunStatus,
};
use self::sql::{
    StoredIdempotency, ensure_control_lease_available, ensure_no_pending_stop,
    insert_control_lease, insert_idempotency, insert_initial_session, insert_safe_log,
    insert_terminal_json_idempotency, insert_turn, load_recovery_subject, matching_idempotency,
    merge_observed_reference, persist_lifecycle_mutation, require_operation,
    synchronize_control_lease, update_session_row, update_turn_idempotency,
    validate_initial_session,
};
pub(crate) use self::stop::{BeginStopOutcome, StopCommit, StopCommitOutcome};
use crate::{ApiBearerToken, ApiPrincipal};
pub(crate) use crate::{LogEvent, LogSeverity, LogSource};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use satelle_core::session::{
    DesktopBindingRef, ExecutionPolicy, ExpectedRevisions, HostIdentityRef, Session,
    SessionStateRevision, TurnState, TurnTransition,
};
use satelle_core::{
    ProviderBindingAuthorization, ProviderBindingSource, PublicResolvedProviderBinding,
    ResolvedProviderBinding, SatelleError, SessionId, TurnId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::Path;
#[cfg(any(test, feature = "test-support"))]
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub(crate) enum ProviderBindingAuthorizationReplay {
    Completed(PublicResolvedProviderBinding),
    Failed(SatelleError),
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub(crate) enum ProviderBindingDeletionReplay {
    Completed(bool),
    Failed(SatelleError),
}

/// Owns a temporary state directory whose path and permissions satisfy the
/// same platform security rules as production state.
#[cfg(any(test, feature = "test-support"))]
pub struct TestStateDir {
    _temporary_parent: tempfile::TempDir,
    path: PathBuf,
}

#[cfg(any(test, feature = "test-support"))]
impl TestStateDir {
    pub fn new() -> std::io::Result<Self> {
        let temporary_parent = tempfile::tempdir()?;
        #[cfg(windows)]
        let path = temporary_parent.path().join("state");
        #[cfg(target_os = "macos")]
        let path = std::fs::canonicalize(temporary_parent.path())?;
        #[cfg(not(any(target_os = "macos", windows)))]
        let path = temporary_parent.path().to_path_buf();
        #[cfg(windows)]
        drop(open::prepare_state_root(&path).map_err(std::io::Error::other)?);
        Ok(Self {
            _temporary_parent: temporary_parent,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StorageErrorKind {
    StateDirectoryUnavailable,
    UnsafeStatePath,
    LockUnavailable,
    StoreInUse,
    OpenFailed,
    Busy,
    MigrationFailed,
    MigrationIntegrity,
    IntegrityCheckFailed,
    InvalidInput,
    InvalidStoredState,
    SessionNotFound,
    SessionNotSteerable,
    LeaseConflict,
    StateConflict,
    IdempotencyConflict,
    AdmissionCancelled,
    PrivateReferenceConflict,
    OperationFailed,
}

impl fmt::Display for StorageErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StateDirectoryUnavailable => "the Satelle state directory is unavailable",
            Self::UnsafeStatePath => "the Satelle state path is unsafe",
            Self::LockUnavailable => "the Satelle store ownership lock is unavailable",
            Self::StoreInUse => "the Satelle store is already in use",
            Self::OpenFailed => "the Satelle SQLite store could not be opened",
            Self::Busy => "the Satelle SQLite store is busy",
            Self::MigrationFailed => "the Satelle SQLite migration failed",
            Self::MigrationIntegrity => "the Satelle SQLite migration history is inconsistent",
            Self::IntegrityCheckFailed => "the Satelle SQLite integrity check failed",
            Self::InvalidInput => "the storage operation input is invalid",
            Self::InvalidStoredState => "the stored Satelle lifecycle state is invalid",
            Self::SessionNotFound => "the requested Satelle Session was not found",
            Self::SessionNotSteerable => {
                "the Session has no retained upstream thread available for steering"
            }
            Self::LeaseConflict => "the selected Satelle Control Lease is already owned",
            Self::StateConflict => "the stored Satelle lifecycle state changed concurrently",
            Self::IdempotencyConflict => "the idempotency key was reused for a different request",
            Self::AdmissionCancelled => "the admission was cancelled before it committed",
            Self::PrivateReferenceConflict => {
                "an observed private runtime reference conflicts with stored state"
            }
            Self::OperationFailed => "the Satelle storage operation failed",
        })
    }
}

pub(crate) struct StorageError {
    kind: StorageErrorKind,
    conflicting_session_id: Option<SessionId>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Debug for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl StorageError {
    fn new(kind: StorageErrorKind) -> Self {
        Self {
            kind,
            conflicting_session_id: None,
            source: None,
        }
    }

    pub(crate) fn kind(&self) -> StorageErrorKind {
        self.kind
    }

    pub(crate) fn state_conflict() -> Self {
        Self::new(StorageErrorKind::StateConflict)
    }

    #[cfg(test)]
    pub(crate) fn for_test(kind: StorageErrorKind) -> Self {
        Self::new(kind)
    }

    pub(crate) fn conflicting_session_id(&self) -> Option<&SessionId> {
        self.conflicting_session_id.as_ref()
    }

    fn lease_conflict(session_id: SessionId) -> Self {
        Self {
            kind: StorageErrorKind::LeaseConflict,
            conflicting_session_id: Some(session_id),
            source: None,
        }
    }

    fn with_source(kind: StorageErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            conflicting_session_id: None,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl Error for StorageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PrivateRequestToken(String);

impl PrivateRequestToken {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        validated_private_reference(value.into()).map(Self)
    }
}

impl fmt::Debug for PrivateRequestToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateRequestToken([redacted])")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PrivateUpstreamRef(String);

impl PrivateUpstreamRef {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        validated_private_reference(value.into()).map(Self)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateUpstreamRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateUpstreamRef([redacted])")
    }
}

#[derive(Clone)]
pub(crate) struct LeaseOwner {
    operation_id: String,
    process_id: u32,
    process_start_ref: String,
    boot_identity_ref: String,
    acquired_at: OffsetDateTime,
}

impl LeaseOwner {
    pub(crate) fn new(
        operation_id: impl Into<String>,
        process_id: u32,
        process_start_ref: impl Into<String>,
        boot_identity_ref: impl Into<String>,
        acquired_at: OffsetDateTime,
    ) -> Result<Self, StorageError> {
        if process_id == 0 {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            operation_id: validated_private_reference(operation_id.into())?,
            process_id,
            process_start_ref: validated_private_reference(process_start_ref.into())?,
            boot_identity_ref: validated_private_reference(boot_identity_ref.into())?,
            acquired_at,
        })
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseFreshness {
    Fresh,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "later API packets consume these frozen mutation classes"
    )
)]
pub(crate) enum IdempotentOperation {
    Run,
    Steer,
    Stop,
    Setup,
    Repair,
    HostUpdate,
    StorageMigration,
    DestructiveMaintenance,
    ProviderDescriptorValidation,
    ProviderBindingAuthorization,
    ProviderBindingDeletion,
}

#[derive(Clone)]
pub(crate) struct IdempotencyInput {
    principal_ref: String,
    operation: IdempotentOperation,
    key: String,
    operation_id: String,
    request_digest: String,
    digest_schema_version: u16,
    hmac_key_version: u16,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl IdempotencyInput {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        principal_ref: impl Into<String>,
        operation: IdempotentOperation,
        key: impl Into<String>,
        operation_id: impl Into<String>,
        request_digest: impl Into<String>,
        digest_schema_version: u16,
        hmac_key_version: u16,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, StorageError> {
        let request_digest = request_digest.into();
        if request_digest.len() != 64
            || !request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || digest_schema_version == 0
            || hmac_key_version == 0
            || expires_at <= created_at
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            principal_ref: validated_private_reference(principal_ref.into())?,
            operation,
            key: validated_private_reference(key.into())?,
            operation_id: validated_private_reference(operation_id.into())?,
            request_digest,
            digest_schema_version,
            hmac_key_version,
            created_at,
            expires_at,
        })
    }
}

#[derive(Clone)]
pub(crate) struct AdmissionContext {
    lease_owner: LeaseOwner,
    idempotency: IdempotencyInput,
    request_token: PrivateRequestToken,
}

impl AdmissionContext {
    pub(crate) fn new(
        lease_owner: LeaseOwner,
        idempotency: IdempotencyInput,
        request_token: PrivateRequestToken,
    ) -> Self {
        Self {
            lease_owner,
            idempotency,
            request_token,
        }
    }

    pub(crate) fn lease_owner(&self) -> &LeaseOwner {
        &self.lease_owner
    }

    #[cfg(test)]
    pub(crate) fn idempotency(&self) -> &IdempotencyInput {
        &self.idempotency
    }
}

pub(crate) enum ObservedUpstreamRef {
    Thread(PrivateUpstreamRef),
    Turn(PrivateUpstreamRef),
    Goal(PrivateUpstreamRef),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessProbeTerminal {
    Failed,
    TimedOut,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessProbeKind {
    Native,
    Provider,
}

impl ReadinessProbeKind {
    pub(crate) const fn owner_kind(self) -> &'static str {
        match self {
            Self::Native => "native_probe",
            Self::Provider => "provider_probe",
        }
    }

    pub(crate) const fn reference_column(self) -> &'static str {
        match self {
            Self::Native => "native_probe_ref",
            Self::Provider => "provider_probe_ref",
        }
    }
}

impl ReadinessProbeTerminal {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ProbeRecoverySubject {
    host_identity: HostIdentityRef,
    desktop_binding: DesktopBindingRef,
    probe_kind: ReadinessProbeKind,
    probe_ref: PrivateUpstreamRef,
    upstream_thread_ref: Option<PrivateUpstreamRef>,
    upstream_turn_ref: Option<PrivateUpstreamRef>,
    recovery_pending: bool,
}

impl ProbeRecoverySubject {
    pub(crate) const fn probe_kind(&self) -> ReadinessProbeKind {
        self.probe_kind
    }

    pub(crate) fn probe_ref(&self) -> &str {
        self.probe_ref.as_str()
    }

    pub(crate) fn upstream_thread_ref(&self) -> Option<&str> {
        self.upstream_thread_ref
            .as_ref()
            .map(PrivateUpstreamRef::as_str)
    }

    pub(crate) fn upstream_turn_ref(&self) -> Option<&str> {
        self.upstream_turn_ref
            .as_ref()
            .map(PrivateUpstreamRef::as_str)
    }

    pub(crate) const fn is_recovery_pending(&self) -> bool {
        self.recovery_pending
    }
}

impl fmt::Debug for ProbeRecoverySubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeRecoverySubject")
            .field("host_identity", &self.host_identity)
            .field("desktop_binding", &self.desktop_binding)
            .finish_non_exhaustive()
    }
}

impl ObservedUpstreamRef {
    pub(crate) fn thread(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Thread(PrivateUpstreamRef::new(value)?))
    }

    pub(crate) fn turn(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Turn(PrivateUpstreamRef::new(value)?))
    }

    pub(crate) fn goal(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Goal(PrivateUpstreamRef::new(value)?))
    }
}

#[derive(Clone)]
pub(crate) struct RecoverySubject {
    session_id: SessionId,
    turn_id: TurnId,
    turn_state: TurnState,
    expected_revisions: ExpectedRevisions,
    host_identity: HostIdentityRef,
    request_token: PrivateRequestToken,
    upstream_thread_ref: Option<PrivateUpstreamRef>,
    upstream_turn_ref: Option<PrivateUpstreamRef>,
    upstream_goal_ref: Option<PrivateUpstreamRef>,
}

impl RecoverySubject {
    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub(crate) fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub(crate) fn turn_state(&self) -> TurnState {
        self.turn_state
    }

    pub(crate) fn expected_revisions(&self) -> ExpectedRevisions {
        self.expected_revisions
    }

    pub(crate) fn host_identity(&self) -> &HostIdentityRef {
        &self.host_identity
    }

    pub(crate) fn request_token(&self) -> &PrivateRequestToken {
        &self.request_token
    }

    pub(crate) fn upstream_thread_ref(&self) -> Option<&PrivateUpstreamRef> {
        self.upstream_thread_ref.as_ref()
    }

    pub(crate) fn upstream_turn_ref(&self) -> Option<&PrivateUpstreamRef> {
        self.upstream_turn_ref.as_ref()
    }

    pub(crate) fn upstream_goal_ref(&self) -> Option<&PrivateUpstreamRef> {
        self.upstream_goal_ref.as_ref()
    }
}

impl fmt::Debug for RecoverySubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverySubject")
            .field("session_id", &self.session_id)
            .field("turn_id", &self.turn_id)
            .field("turn_state", &self.turn_state)
            .field("expected_revisions", &self.expected_revisions)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub(crate) enum AdmissionOutcome {
    Execute {
        session: Session,
        recovery_subject: RecoverySubject,
    },
    InProgress(Session),
    Complete(Session),
}

pub(crate) enum DurableAdmissionState {
    Missing,
    Admitted(Box<AdmissionReplay>),
    Cancelled,
    RecoveryPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableCancellationOutcome {
    Cancelled,
    RecoveryPending,
}

impl DurableCancellationOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::RecoveryPending => "recovery_pending",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "cancelled" => Ok(Self::Cancelled),
            "recovery_pending" => Ok(Self::RecoveryPending),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

/// A durable idempotency replay and the exact handles stored with that record.
///
/// The handles remain explicit because a terminal Session snapshot may later
/// contain additional Turns. Callers must not recover admission identity from
/// Turn history position.
pub(crate) struct AdmissionReplay {
    outcome: AdmissionOutcome,
    session_id: SessionId,
    turn_id: TurnId,
}

impl AdmissionReplay {
    #[cfg(test)]
    pub(crate) fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[cfg(test)]
    pub(crate) fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub(crate) fn into_parts(self) -> (AdmissionOutcome, SessionId, TurnId) {
        (self.outcome, self.session_id, self.turn_id)
    }

    fn into_outcome(self) -> AdmissionOutcome {
        self.outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StorageSnapshot {
    session_count: usize,
    active_turn_count: usize,
    recovery_pending_turn_count: usize,
}

impl StorageSnapshot {
    pub(crate) const fn session_count(self) -> usize {
        self.session_count
    }

    pub(crate) const fn active_turn_count(self) -> usize {
        self.active_turn_count
    }

    pub(crate) const fn recovery_pending_turn_count(self) -> usize {
        self.recovery_pending_turn_count
    }
}

fn replay_admission(
    connection: &Connection,
    record: &StoredIdempotency,
    expected_session_id: Option<&SessionId>,
) -> Result<AdmissionReplay, StorageError> {
    let session_id = record
        .session_id
        .as_deref()
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
        .and_then(|value| {
            SessionId::parse(value)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })?;
    let turn_id = record
        .turn_id
        .as_deref()
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
        .and_then(|value| {
            TurnId::parse(value)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })?;
    if expected_session_id.is_some_and(|expected| expected != &session_id) {
        return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
    }

    let outcome = match record.status.as_str() {
        "in_progress" => {
            let session = load_required_session(connection, &session_id)?;
            validate_replayed_turn_outcome(record, &session, &turn_id)?;
            AdmissionOutcome::InProgress(session)
        }
        "terminal" => {
            let session_revision = record
                .result_session_state_revision
                .as_deref()
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let session_updated_at = record
                .result_session_updated_at
                .as_deref()
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let session = load_session_at_operation_outcome(
                connection,
                &session_id,
                &turn_id,
                session_revision,
                session_updated_at,
            )?;
            validate_replayed_turn_outcome(record, &session, &turn_id)?;
            AdmissionOutcome::Complete(session)
        }
        _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    };
    Ok(AdmissionReplay {
        outcome,
        session_id,
        turn_id,
    })
}

fn validate_replayed_turn_outcome(
    record: &StoredIdempotency,
    session: &Session,
    turn_id: &TurnId,
) -> Result<(), StorageError> {
    let turn = session
        .turn(turn_id)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    if record.durable_outcome != turn_idempotency_token(turn.state()) {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    Ok(())
}

fn matching_admission_cancellation(
    connection: &Connection,
    input: &IdempotencyInput,
    observed_at: OffsetDateTime,
) -> Result<Option<DurableCancellationOutcome>, StorageError> {
    let record = connection
        .query_row(
            "SELECT request_digest, digest_schema_version, hmac_key_version, outcome, expires_at
             FROM admission_cancellations
             WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
            rusqlite::params![
                input.principal_ref.as_str(),
                idempotent_operation_token(input.operation),
                input.key.as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let Some((digest, digest_schema_version, hmac_key_version, outcome, expires_at)) = record
    else {
        return Ok(None);
    };
    let outcome = DurableCancellationOutcome::parse(&outcome)?;
    if outcome == DurableCancellationOutcome::Cancelled && parse_time(&expires_at)? <= observed_at {
        return Ok(None);
    }
    if digest != input.request_digest
        || digest_schema_version != i64::from(input.digest_schema_version)
        || hmac_key_version != i64::from(input.hmac_key_version)
    {
        return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
    }
    // A recovery-pending tombstone records unresolved upstream ownership, not
    // a completed cancellation guarantee. It cannot expire into Missing:
    // callers must reconcile ownership and use a new idempotency key rather
    // than treating elapsed retention time as proof that nothing dispatched.
    Ok(Some(outcome))
}

pub(crate) struct Storage {
    // Field order is a drop invariant: SQLite must close every delegated file
    // before the ownership lock and pinned state directory are released.
    connection: Connection,
    _ownership_lock: open::OwnershipLock,
    _state_directory: open::StateDirectory,
}

impl Storage {
    pub(crate) fn has_existing_state(state_root: &Path) -> Result<bool, StorageError> {
        for file_name in PROTECTED_FILE_NAMES {
            match std::fs::symlink_metadata(state_root.join(file_name)) {
                Ok(_) => return Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(StorageError::with_source(
                        StorageErrorKind::StateDirectoryUnavailable,
                        error,
                    ));
                }
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn open(state_root: &Path) -> Result<(Self, Vec<RecoverySubject>), StorageError> {
        let mut storage = Self::open_without_restart_recovery(state_root)?;
        let recovery_subjects = storage.initialize_restart_recovery()?;
        Ok((storage, recovery_subjects))
    }

    /// Opens and validates the authoritative store without changing lifecycle
    /// state. This is used only for an idempotency replay lookup that must
    /// remain local even when a new operation cannot pass external admission.
    pub(crate) fn open_without_restart_recovery(state_root: &Path) -> Result<Self, StorageError> {
        let (connection, ownership_lock, state_directory) = open::open_parts(state_root)?;
        let storage = Self {
            connection,
            _ownership_lock: ownership_lock,
            _state_directory: state_directory,
        };
        auth::validate_sensitive_state(&storage.connection)?;
        Ok(storage)
    }

    pub(crate) fn initialize_restart_recovery(
        &mut self,
    ) -> Result<Vec<RecoverySubject>, StorageError> {
        let detected_at = OffsetDateTime::now_utc();
        self.mark_interrupted_provider_descriptor_validations_failed(detected_at)?;
        self.mark_interrupted_setup_actions_outcome_unknown(detected_at)?;
        self.mark_restart_recovery_pending()
    }

    fn mark_interrupted_provider_descriptor_validations_failed(
        &mut self,
        detected_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let replay = serde_json::to_string(&serde_json::json!({
            "status": "failed",
            "result": satelle_core::SatelleError::state_conflict(),
        }))
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
        self.connection
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal',
                     durable_outcome = 'v2.provider_descriptor_validation.failed',
                     result_json = ?1,
                     completed_at = ?2
                 WHERE operation = 'provider_descriptor_validation'
                   AND status = 'in_progress'
                   AND durable_outcome = 'v2.provider_descriptor_validation.pending'",
                rusqlite::params![replay, format_time(detected_at)?],
            )
            .map(|_| ())
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn host_identity(&self) -> Result<HostIdentityRef, StorageError> {
        auth::host_identity(&self.connection)
    }

    pub(crate) fn digest_idempotency_payload(
        &self,
        canonical_payload: &[u8],
    ) -> Result<SensitiveRequestDigest, StorageError> {
        auth::digest_idempotency_payload(&self.connection, canonical_payload, None)
    }

    pub(crate) fn digest_idempotency_payload_with_key(
        &self,
        canonical_payload: &[u8],
        key_version: u16,
    ) -> Result<SensitiveRequestDigest, StorageError> {
        auth::digest_idempotency_payload(&self.connection, canonical_payload, Some(key_version))
    }

    pub(crate) fn rotate_idempotency_hmac_key(
        &mut self,
        at: OffsetDateTime,
    ) -> Result<u16, StorageError> {
        auth::rotate_idempotency_hmac_key(&mut self.connection, at)
    }

    pub(crate) fn register_api_token(
        &mut self,
        registration: ApiTokenRegistration,
    ) -> Result<(), StorageError> {
        auth::register_api_token(&mut self.connection, registration)
    }

    pub(crate) fn authenticate_api_token(
        &self,
        token: &ApiBearerToken,
        at: OffsetDateTime,
    ) -> Result<Option<ApiPrincipal>, StorageError> {
        auth::authenticate_api_token(&self.connection, token.token_id(), &token.verifier(), at)
    }

    pub(crate) fn authenticate_pending_setup_api_token(
        &self,
        token: &ApiBearerToken,
        at: OffsetDateTime,
    ) -> Result<Option<ApiPrincipal>, StorageError> {
        auth::authenticate_pending_setup_api_token(
            &self.connection,
            token.token_id(),
            &token.verifier(),
            at,
        )
    }

    pub(crate) fn api_principal_is_active(
        &self,
        principal: &ApiPrincipal,
        at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        auth::api_principal_is_active(&self.connection, principal, at)
    }

    pub(crate) fn rotate_api_token(
        &mut self,
        replacement: &ApiBearerToken,
        expected_credential_revision: u64,
        at: OffsetDateTime,
    ) -> Result<ApiPrincipal, StorageError> {
        auth::rotate_api_token(
            &mut self.connection,
            replacement,
            expected_credential_revision,
            at,
        )
    }

    pub(crate) fn activate_api_token(
        &mut self,
        token_id: &str,
        at: OffsetDateTime,
    ) -> Result<ApiPrincipal, StorageError> {
        auth::activate_api_token(&mut self.connection, token_id, at)
    }

    pub(crate) fn abort_setup_api_token(
        &mut self,
        token_id: &str,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        auth::abort_setup_api_token(&mut self.connection, token_id, at)
    }

    pub(crate) fn revoke_api_token(
        &mut self,
        token_id: &str,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        auth::revoke_api_token(&mut self.connection, token_id, at)
    }

    pub(crate) fn replay_admission_if_present(
        &self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
    ) -> Result<Option<AdmissionReplay>, StorageError> {
        require_operation(idempotency, operation)?;
        matching_idempotency(&self.connection, idempotency)?
            .map(|record| replay_admission(&self.connection, &record, expected_session_id))
            .transpose()
    }

    pub(crate) fn resolve_admission_operation(
        &self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        observed_at: OffsetDateTime,
    ) -> Result<DurableAdmissionState, StorageError> {
        require_operation(idempotency, operation)?;
        if let Some(record) = matching_idempotency(&self.connection, idempotency)? {
            return replay_admission(&self.connection, &record, expected_session_id)
                .map(Box::new)
                .map(DurableAdmissionState::Admitted);
        }
        matching_admission_cancellation(&self.connection, idempotency, observed_at).map(|outcome| {
            match outcome {
                Some(DurableCancellationOutcome::Cancelled) => DurableAdmissionState::Cancelled,
                Some(DurableCancellationOutcome::RecoveryPending) => {
                    DurableAdmissionState::RecoveryPending
                }
                None => DurableAdmissionState::Missing,
            }
        })
    }

    pub(crate) fn record_admission_cancellation(
        &mut self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        outcome: DurableCancellationOutcome,
        observed_at: OffsetDateTime,
    ) -> Result<DurableAdmissionState, StorageError> {
        self.record_admission_cancellation_inner(
            operation,
            idempotency,
            expected_session_id,
            outcome,
            observed_at,
            false,
        )
    }

    pub(crate) fn reconcile_admission_cancellation(
        &mut self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        outcome: DurableCancellationOutcome,
        observed_at: OffsetDateTime,
    ) -> Result<DurableAdmissionState, StorageError> {
        self.record_admission_cancellation_inner(
            operation,
            idempotency,
            expected_session_id,
            outcome,
            observed_at,
            true,
        )
    }

    fn record_admission_cancellation_inner(
        &mut self,
        operation: IdempotentOperation,
        idempotency: &IdempotencyInput,
        expected_session_id: Option<&SessionId>,
        outcome: DurableCancellationOutcome,
        observed_at: OffsetDateTime,
        reconciled: bool,
    ) -> Result<DurableAdmissionState, StorageError> {
        require_operation(idempotency, operation)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = replay_admission(&transaction, &record, expected_session_id)?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(DurableAdmissionState::Admitted(Box::new(replay)));
        }
        let existing = matching_admission_cancellation(&transaction, idempotency, observed_at)?;
        let state = match existing {
            Some(DurableCancellationOutcome::RecoveryPending)
                if reconciled && outcome == DurableCancellationOutcome::Cancelled =>
            {
                transaction
                    .execute(
                        "UPDATE admission_cancellations
                         SET outcome = 'cancelled', created_at = ?4, expires_at = ?5
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                            format_time(observed_at)?,
                            format_time(observed_at + IDEMPOTENCY_RETENTION)?,
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                DurableAdmissionState::Cancelled
            }
            Some(DurableCancellationOutcome::RecoveryPending) => {
                DurableAdmissionState::RecoveryPending
            }
            Some(DurableCancellationOutcome::Cancelled)
                if outcome == DurableCancellationOutcome::RecoveryPending =>
            {
                transaction
                    .execute(
                        "UPDATE admission_cancellations SET outcome = 'recovery_pending'
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                DurableAdmissionState::RecoveryPending
            }
            Some(DurableCancellationOutcome::Cancelled) => DurableAdmissionState::Cancelled,
            None => {
                transaction
                    .execute(
                        "DELETE FROM admission_cancellations
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                transaction
                    .execute(
                        "INSERT INTO admission_cancellations
                         (principal_ref, operation, idempotency_key, request_digest,
                          digest_schema_version, hmac_key_version, outcome, created_at, expires_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        rusqlite::params![
                            idempotency.principal_ref.as_str(),
                            idempotent_operation_token(idempotency.operation),
                            idempotency.key.as_str(),
                            idempotency.request_digest.as_str(),
                            i64::from(idempotency.digest_schema_version),
                            i64::from(idempotency.hmac_key_version),
                            outcome.as_str(),
                            format_time(observed_at)?,
                            format_time(observed_at + IDEMPOTENCY_RETENTION)?,
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                match outcome {
                    DurableCancellationOutcome::Cancelled => DurableAdmissionState::Cancelled,
                    DurableCancellationOutcome::RecoveryPending => {
                        DurableAdmissionState::RecoveryPending
                    }
                }
            }
        };
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(state)
    }

    pub(crate) fn idempotency_hmac_key_version(
        &self,
        principal_ref: &str,
        operation: IdempotentOperation,
        key: &str,
    ) -> Result<Option<u16>, StorageError> {
        let version: Option<i64> = self
            .connection
            .query_row(
                "SELECT hmac_key_version FROM idempotency_records WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3",
                rusqlite::params![principal_ref, idempotent_operation_token(operation), key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let version = match version {
            Some(version) => Some(version),
            None => {
                let observed_at = format_time(OffsetDateTime::now_utc())?;
                self.connection
                    .query_row(
                        "SELECT hmac_key_version FROM admission_cancellations
                         WHERE principal_ref = ?1 AND operation = ?2 AND idempotency_key = ?3
                           AND (outcome = 'recovery_pending' OR expires_at > ?4)",
                        rusqlite::params![
                            principal_ref,
                            idempotent_operation_token(operation),
                            key,
                            observed_at,
                        ],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?
            }
        };
        version
            .map(|version| {
                u16::try_from(version)
                    .ok()
                    .filter(|version| *version > 0)
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
            })
            .transpose()
    }

    pub(crate) fn claim_provider_descriptor_validation(
        &mut self,
        idempotency: &IdempotencyInput,
    ) -> Result<Option<String>, StorageError> {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderDescriptorValidation,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            return match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v2.provider_descriptor_validation.completed"
                    | "v2.provider_descriptor_validation.failed",
                    Some(result_json),
                ) => Ok(Some(result_json)),
                ("in_progress", "v2.provider_descriptor_validation.pending", None) => {
                    Err(StorageError::new(StorageErrorKind::StateConflict))
                }
                _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
        }
        insert_idempotency(
            &transaction,
            idempotency,
            "in_progress",
            "v2.provider_descriptor_validation.pending",
            None,
            None,
            None,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(None)
    }

    pub(crate) fn complete_provider_descriptor_validation(
        &mut self,
        idempotency: &IdempotencyInput,
        result_json: &str,
        failed: bool,
        completed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderDescriptorValidation,
        )?;
        if result_json.is_empty() {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let record = matching_idempotency(&transaction, idempotency)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        if record.status != "in_progress"
            || record.durable_outcome != "v2.provider_descriptor_validation.pending"
            || record.result_json.is_some()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let updated = transaction
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal',
                     durable_outcome = ?1,
                     result_json = ?2,
                     completed_at = ?3
                 WHERE principal_ref = ?4
                   AND operation = ?5
                   AND idempotency_key = ?6
                   AND status = 'in_progress'",
                rusqlite::params![
                    if failed {
                        "v2.provider_descriptor_validation.failed"
                    } else {
                        "v2.provider_descriptor_validation.completed"
                    },
                    result_json,
                    self::codec::format_time(completed_at)?,
                    idempotency.principal_ref.as_str(),
                    self::codec::idempotent_operation_token(idempotency.operation),
                    idempotency.key.as_str(),
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if updated != 1 {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn authorize_provider_binding_idempotent<V, M>(
        &mut self,
        idempotency: &IdempotencyInput,
        completed_at: OffsetDateTime,
        validate: V,
        map_failure: M,
    ) -> Result<ProviderBindingAuthorizationReplay, StorageError>
    where
        V: FnOnce() -> Result<ResolvedProviderBinding, SatelleError>,
        M: FnOnce(&StorageError) -> SatelleError,
    {
        require_operation(
            idempotency,
            IdempotentOperation::ProviderBindingAuthorization,
        )?;
        let mut transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v1.provider_binding_authorization.completed"
                    | "v1.provider_binding_authorization.failed",
                    Some(result_json),
                ) => serde_json::from_str(&result_json)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(replay);
        }

        let replay = match validate() {
            Err(error) => ProviderBindingAuthorizationReplay::Failed(error),
            Ok(binding) => {
                let public_binding = PublicResolvedProviderBinding::from(&binding);
                let savepoint = transaction
                    .savepoint()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                match Self::authorize_provider_binding_in_connection(
                    &savepoint,
                    &binding,
                    completed_at,
                ) {
                    Ok(()) => {
                        savepoint.commit().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingAuthorizationReplay::Completed(public_binding)
                    }
                    Err(error) => {
                        savepoint.finish().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingAuthorizationReplay::Failed(map_failure(&error))
                    }
                }
            }
        };
        let failed = matches!(replay, ProviderBindingAuthorizationReplay::Failed(_));
        let result_json = serde_json::to_string(&replay).map_err(|source| {
            StorageError::with_source(StorageErrorKind::OperationFailed, source)
        })?;
        insert_terminal_json_idempotency(
            &transaction,
            idempotency,
            if failed {
                "v1.provider_binding_authorization.failed"
            } else {
                "v1.provider_binding_authorization.completed"
            },
            &result_json,
            completed_at,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(replay)
    }

    pub(crate) fn delete_provider_binding_idempotent<V, M>(
        &mut self,
        idempotency: &IdempotencyInput,
        model_alias: &str,
        provider_alias: &str,
        completed_at: OffsetDateTime,
        validate: V,
        map_failure: M,
    ) -> Result<ProviderBindingDeletionReplay, StorageError>
    where
        V: FnOnce() -> Result<(), SatelleError>,
        M: FnOnce(&StorageError) -> SatelleError,
    {
        require_operation(idempotency, IdempotentOperation::ProviderBindingDeletion)?;
        let mut transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let replay = match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                (
                    "terminal",
                    "v1.provider_binding_deletion.completed"
                    | "v1.provider_binding_deletion.failed",
                    Some(result_json),
                ) => serde_json::from_str(&result_json)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
            };
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(replay);
        }

        let replay = match validate() {
            Err(error) => ProviderBindingDeletionReplay::Failed(error),
            Ok(()) => {
                let savepoint = transaction
                    .savepoint()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                match Self::delete_provider_binding_in_connection(
                    &savepoint,
                    model_alias,
                    provider_alias,
                ) {
                    Ok(deleted) => {
                        savepoint.commit().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingDeletionReplay::Completed(deleted)
                    }
                    Err(error) => {
                        savepoint.finish().map_err(|source| {
                            sqlite_error(StorageErrorKind::OperationFailed, source)
                        })?;
                        ProviderBindingDeletionReplay::Failed(map_failure(&error))
                    }
                }
            }
        };
        let failed = matches!(replay, ProviderBindingDeletionReplay::Failed(_));
        let result_json = serde_json::to_string(&replay).map_err(|source| {
            StorageError::with_source(StorageErrorKind::OperationFailed, source)
        })?;
        insert_terminal_json_idempotency(
            &transaction,
            idempotency,
            if failed {
                "v1.provider_binding_deletion.failed"
            } else {
                "v1.provider_binding_deletion.completed"
            },
            &result_json,
            completed_at,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(replay)
    }

    pub(crate) fn authorize_provider_binding(
        &mut self,
        binding: &ResolvedProviderBinding,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Self::authorize_provider_binding_in_connection(&transaction, binding, updated_at)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    fn authorize_provider_binding_in_connection(
        connection: &Connection,
        binding: &ResolvedProviderBinding,
        updated_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        if binding.source() != ProviderBindingSource::UserConfig
            || !binding.has_valid_binding_digest()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let auth_source_json = binding
            .auth_source()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|source| {
                StorageError::with_source(StorageErrorKind::OperationFailed, source)
            })?;
        let previous_digest = connection
            .query_row(
                "SELECT binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![
                    binding.requested_provider_alias(),
                    binding.requested_model_alias()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        connection
            .execute(
                "INSERT INTO authorized_provider_bindings (
                    provider_alias,
                    model_alias,
                    model,
                    model_provider,
                    endpoint,
                    auth_source_json,
                    source,
                    experimental_provider_computer_use,
                    binding_digest,
                    updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'user_config', ?7, ?8, ?9)
                 ON CONFLICT(provider_alias, model_alias) DO UPDATE SET
                    model = excluded.model,
                    model_provider = excluded.model_provider,
                    endpoint = excluded.endpoint,
                    auth_source_json = excluded.auth_source_json,
                    source = excluded.source,
                    experimental_provider_computer_use =
                        excluded.experimental_provider_computer_use,
                    binding_digest = excluded.binding_digest,
                    updated_at = excluded.updated_at",
                rusqlite::params![
                    binding.requested_provider_alias(),
                    binding.requested_model_alias(),
                    binding.model(),
                    binding.model_provider(),
                    binding.endpoint(),
                    auth_source_json,
                    i64::from(binding.experimental_provider_computer_use()),
                    binding.binding_digest(),
                    format_time(updated_at)?,
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if let Some(previous_digest) = previous_digest
            && previous_digest != binding.binding_digest()
        {
            connection
                .execute(
                    "DELETE FROM provider_smoke_results
                     WHERE provider_config_fingerprint = ?1",
                    rusqlite::params![previous_digest],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        }
        Ok(())
    }

    pub(crate) fn delete_authorized_provider_binding(
        &mut self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let deleted =
            Self::delete_provider_binding_in_connection(&transaction, model_alias, provider_alias)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(deleted)
    }

    fn delete_provider_binding_in_connection(
        connection: &Connection,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, StorageError> {
        let previous_digest = connection
            .query_row(
                "SELECT binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let deleted = connection
            .execute(
                "DELETE FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if deleted == 1
            && let Some(previous_digest) = previous_digest
        {
            connection
                .execute(
                    "DELETE FROM provider_smoke_results
                     WHERE provider_config_fingerprint = ?1",
                    rusqlite::params![previous_digest],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        }
        Ok(deleted == 1)
    }

    pub(crate) fn load_authorized_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<Option<ResolvedProviderBinding>, StorageError> {
        let stored = self
            .connection
            .query_row(
                "SELECT model,
                        model_provider,
                        endpoint,
                        auth_source_json,
                        source,
                        experimental_provider_computer_use,
                        binding_digest
                 FROM authorized_provider_bindings
                 WHERE provider_alias = ?1 AND model_alias = ?2",
                rusqlite::params![provider_alias, model_alias],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let Some((
            model,
            model_provider,
            endpoint,
            auth_source_json,
            source,
            experimental,
            stored_digest,
        )) = stored
        else {
            return Ok(None);
        };
        if source != ProviderBindingSource::UserConfig.as_str() || !matches!(experimental, 0 | 1) {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let auth_source = auth_source_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|source| {
                StorageError::with_source(StorageErrorKind::InvalidStoredState, source)
            })?;
        let mut authorization =
            ProviderBindingAuthorization::new(model_alias, provider_alias, model, model_provider)
                .with_experimental_provider_computer_use(experimental == 1);
        if let Some(endpoint) = endpoint {
            authorization = authorization.with_endpoint(endpoint);
        }
        if let Some(auth_source) = auth_source {
            authorization = authorization.with_auth_source(auth_source);
        }
        let binding = ResolvedProviderBinding::from_authorization(
            authorization,
            ProviderBindingSource::UserConfig,
        );
        if binding.binding_digest() != stored_digest {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        Ok(Some(binding))
    }

    pub(crate) fn recovery_subject(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<RecoverySubject, StorageError> {
        let session = load_required_session(&self.connection, session_id)?;
        load_recovery_subject(&self.connection, &session, turn_id)
    }

    pub(crate) fn begin_session(
        &mut self,
        session: &Session,
        context: &AdmissionContext,
    ) -> Result<AdmissionOutcome, StorageError> {
        require_operation(&context.idempotency, IdempotentOperation::Run)?;
        if context.idempotency.operation_id != context.lease_owner.operation_id {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        validate_initial_session(session)?;
        let turn = session
            .turns()
            .next()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
        let session_id = session.id().clone();
        let turn_id = turn.id().clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;

        if let Some(record) = matching_idempotency(&transaction, &context.idempotency)? {
            let outcome = replay_admission(&transaction, &record, None)?.into_outcome();
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(outcome);
        }
        if matching_admission_cancellation(
            &transaction,
            &context.idempotency,
            context.idempotency.created_at,
        )?
        .is_some()
        {
            return Err(StorageError::new(StorageErrorKind::AdmissionCancelled));
        }

        ensure_control_lease_available(
            &transaction,
            session.host_identity(),
            session.desktop_binding(),
        )?;
        insert_initial_session(&transaction, session, &context.request_token)?;
        insert_control_lease(&transaction, session, &turn_id, &context.lease_owner)?;
        insert_idempotency(
            &transaction,
            &context.idempotency,
            "in_progress",
            "v1.turn.starting",
            Some(&session_id),
            Some(&turn_id),
            None,
        )?;
        insert_safe_log(
            &transaction,
            &canonical_log(
                LogEvent::SessionStarted,
                LogSeverity::Info,
                session,
                &turn_id,
                session.updated_at(),
            )?,
        )?;
        let recovery_subject = load_recovery_subject(&transaction, session, &turn_id)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(AdmissionOutcome::Execute {
            session: session.clone(),
            recovery_subject,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_follow_up(
        &mut self,
        session_id: &SessionId,
        expected_session_revision: SessionStateRevision,
        turn_id: TurnId,
        execution_policy: ExecutionPolicy,
        at: OffsetDateTime,
        requires_upstream_thread: bool,
        context: &AdmissionContext,
    ) -> Result<AdmissionOutcome, StorageError> {
        require_operation(&context.idempotency, IdempotentOperation::Steer)?;
        if context.idempotency.operation_id != context.lease_owner.operation_id {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;

        if let Some(record) = matching_idempotency(&transaction, &context.idempotency)? {
            let outcome = replay_admission(&transaction, &record, Some(session_id))?.into_outcome();
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(outcome);
        }
        if matching_admission_cancellation(
            &transaction,
            &context.idempotency,
            context.idempotency.created_at,
        )?
        .is_some()
        {
            return Err(StorageError::new(StorageErrorKind::AdmissionCancelled));
        }

        let mut session = load_required_session(&transaction, session_id)?;
        if session.is_active() {
            return Err(StorageError::lease_conflict(session.id().clone()));
        }
        if requires_upstream_thread {
            let upstream_thread_ref = transaction
                .query_row(
                    "SELECT upstream_thread_ref FROM session_private_refs WHERE session_id = ?1",
                    [session_id.as_str()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            let upstream_thread_ref = upstream_thread_ref
                .ok_or_else(|| StorageError::new(StorageErrorKind::SessionNotSteerable))?;
            PrivateUpstreamRef::new(upstream_thread_ref)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        }
        let previous_revision = session.session_state_revision();
        session
            .start_follow_up(
                expected_session_revision,
                turn_id.clone(),
                execution_policy,
                at,
            )
            .map_err(StorageError::from)?;
        ensure_control_lease_available(
            &transaction,
            session.host_identity(),
            session.desktop_binding(),
        )?;
        update_session_row(&transaction, &session, previous_revision)?;
        let turn = session
            .turn(&turn_id)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        insert_turn(
            &transaction,
            session_id,
            session.turns().len() - 1,
            turn,
            &context.request_token,
        )?;
        insert_control_lease(&transaction, &session, &turn_id, &context.lease_owner)?;
        insert_idempotency(
            &transaction,
            &context.idempotency,
            "in_progress",
            "v1.turn.starting",
            Some(session_id),
            Some(&turn_id),
            None,
        )?;
        insert_safe_log(
            &transaction,
            &canonical_log(
                LogEvent::FollowUpStarted,
                LogSeverity::Info,
                &session,
                &turn_id,
                session.updated_at(),
            )?,
        )?;
        let recovery_subject = load_recovery_subject(&transaction, &session, &turn_id)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(AdmissionOutcome::Execute {
            session,
            recovery_subject,
        })
    }

    pub(crate) fn commit_lifecycle(
        &mut self,
        session_id: &SessionId,
        turn_id: &TurnId,
        expected: ExpectedRevisions,
        transition: TurnTransition,
        at: OffsetDateTime,
    ) -> Result<Session, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if matches!(
            &transition,
            &TurnTransition::Running | &TurnTransition::RecoveryPending
        ) {
            // A stop observation owns the next nonterminal transition. A
            // concurrent terminal result may still win through the normal
            // lifecycle compare-and-swap.
            ensure_no_pending_stop(&transaction, session_id, turn_id)?;
        }
        let mut session = load_required_session(&transaction, session_id)?;
        session
            .transition_turn(turn_id, expected, transition, at)
            .map_err(StorageError::from)?;
        persist_lifecycle_mutation(&transaction, &session, turn_id, expected)?;
        synchronize_control_lease(&transaction, &session, turn_id)?;
        update_turn_idempotency(&transaction, &session, turn_id, at)?;
        insert_safe_log(
            &transaction,
            &canonical_log(
                LogEvent::TurnStateCommitted,
                LogSeverity::Info,
                &session,
                turn_id,
                session.updated_at(),
            )?,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(session)
    }

    /// Persists private upstream identity as soon as the adapter observes it.
    /// This transaction deliberately does not mutate lifecycle revisions,
    /// idempotency outcomes, logs, or lease ownership.
    pub(crate) fn record_upstream_ref(
        &mut self,
        session_id: &SessionId,
        turn_id: &TurnId,
        observed_ref: &ObservedUpstreamRef,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        merge_observed_reference(&transaction, session_id, turn_id, observed_ref)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(())
    }

    pub(crate) fn load_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<Session>, StorageError> {
        load_session_from_connection(&self.connection, session_id)
    }

    pub(crate) fn snapshot(&self) -> Result<StorageSnapshot, StorageError> {
        let counts: (i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT \
                    (SELECT count(*) FROM sessions), \
                    (SELECT count(*) FROM turns WHERE state IN ('starting', 'running')), \
                    (SELECT count(*) FROM turns WHERE state = 'recovery_pending')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let decode = |count: i64| {
            usize::try_from(count)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        };
        Ok(StorageSnapshot {
            session_count: decode(counts.0)?,
            active_turn_count: decode(counts.1)?,
            recovery_pending_turn_count: decode(counts.2)?,
        })
    }
}
