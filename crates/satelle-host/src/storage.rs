mod auth;
mod codec;
mod logs;
mod open;
mod operational;
mod sql;
pub(crate) mod stop;
#[cfg(test)]
mod tests;

// Admission needs an initial expiry, then the terminal commit resets it so the
// full replay window begins only after the operation has finished.
pub(crate) const IDEMPOTENCY_RETENTION: time::Duration = time::Duration::hours(24);

pub(crate) use self::auth::{ApiTokenRegistration, SensitiveRequestDigest};
use self::codec::{
    idempotent_operation_token, load_required_session, load_session_at_operation_outcome,
    load_session_from_connection, turn_idempotency_token, validated_private_reference,
};
pub(crate) use self::logs::LogPageStorageError;
use self::logs::canonical_log;
pub(crate) use self::logs::{SafeLogRecord, StoredLogRecord};
#[cfg(test)]
use self::open::DATABASE_FILE_NAME;
#[cfg(all(test, unix))]
use self::open::LOCK_FILE_NAME;
use self::open::{PROTECTED_FILE_NAMES, sqlite_error};
use self::sql::{
    StoredIdempotency, ensure_control_lease_available, ensure_no_pending_stop,
    insert_control_lease, insert_idempotency, insert_initial_session, insert_safe_log, insert_turn,
    load_recovery_subject, matching_idempotency, merge_observed_reference,
    persist_lifecycle_mutation, require_operation, synchronize_control_lease, update_session_row,
    update_turn_idempotency, validate_initial_session,
};
pub(crate) use self::stop::{BeginStopOutcome, StopCommit, StopCommitOutcome};
use crate::{ApiBearerToken, ApiPrincipal};
pub(crate) use crate::{LogEvent, LogSeverity, LogSource};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use satelle_core::session::{
    ExecutionPolicy, ExpectedRevisions, HostIdentityRef, Session, SessionStateRevision, TurnState,
    TurnTransition,
};
use satelle_core::{SessionId, TurnId};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::path::Path;
#[cfg(any(test, feature = "test-support"))]
use std::path::PathBuf;
use time::OffsetDateTime;

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
    LeaseConflict,
    StateConflict,
    IdempotencyConflict,
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
            Self::LeaseConflict => "the selected Satelle Control Lease is already owned",
            Self::StateConflict => "the stored Satelle lifecycle state changed concurrently",
            Self::IdempotencyConflict => "the idempotency key was reused for a different request",
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdempotentOperation {
    Run,
    Steer,
    Stop,
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

    #[cfg(test)]
    pub(crate) fn idempotency(&self) -> &IdempotencyInput {
        &self.idempotency
    }
}

pub(crate) enum ObservedUpstreamRef {
    Thread(PrivateUpstreamRef),
    Turn(PrivateUpstreamRef),
}

impl ObservedUpstreamRef {
    pub(crate) fn thread(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Thread(PrivateUpstreamRef::new(value)?))
    }

    pub(crate) fn turn(value: impl Into<String>) -> Result<Self, StorageError> {
        Ok(Self::Turn(PrivateUpstreamRef::new(value)?))
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

pub(crate) struct Storage {
    // Field order is a drop invariant: SQLite must close every delegated file
    // before the ownership lock and pinned state directory are released.
    connection: Connection,
    _ownership_lock: File,
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
        let recovery_subjects = storage.mark_restart_recovery_pending()?;
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
        self.mark_restart_recovery_pending()
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
        version
            .map(|version| {
                u16::try_from(version)
                    .ok()
                    .filter(|version| *version > 0)
                    .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
            })
            .transpose()
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

        let mut session = load_required_session(&transaction, session_id)?;
        if session.is_active() {
            return Err(StorageError::lease_conflict(session.id().clone()));
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
