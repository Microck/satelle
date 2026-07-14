#[path = "runtime-adapter.rs"]
mod adapter;
#[path = "runtime-codex-adapter.rs"]
mod codex_adapter;
#[path = "runtime-events.rs"]
mod events;
#[path = "runtime-model.rs"]
mod model;
#[path = "runtime-recovery.rs"]
mod recovery;
#[path = "runtime-request.rs"]
mod request;
#[path = "runtime-stop.rs"]
mod stop;
#[path = "runtime-worker.rs"]
mod worker;

pub use adapter::{
    AdapterReadiness, AdapterSubject, ComputerUseAdapter, EvidenceError, ExecuteRequest,
    ExecuteResult, ProviderSmokeEvidence, ReadinessEvidence, RecoveryObservation,
};
pub(crate) use codex_adapter::ProductionComputerUseAdapter;
pub(crate) use request::{RequestIdentity, RunCommand, SteerCommand, StopCommand};
pub(crate) use stop::RuntimeStopOutcome;
use worker::{ExecutionPlan, TurnWork, WorkerRegistry};

use crate::live_events::LiveEventHub;
use crate::process_identity::ProcessIdentity;
use crate::storage::{
    AdmissionOutcome, ApiTokenRegistration, IdempotentOperation, LogPageStorageError,
    SensitiveRequestDigest, Storage, StorageSnapshot,
};
use crate::{ApiBearerToken, ApiPrincipal, DaemonLogPage, LogCursor, LogPageQuery};
use recovery::RecoveryQueue;
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    ControlPlaneOperation, LOCAL_DEMO_HOST, SatelleError, SatelleEvent, SessionId, TurnId,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug)]
pub(crate) struct RuntimeTurnOutcome {
    pub(crate) session: PublicSession,
    pub(crate) events: Vec<SatelleEvent>,
}

impl RuntimeTurnOutcome {
    pub(crate) fn into_command_outcome(self) -> crate::TurnOutcome {
        crate::TurnOutcome {
            session: self.session,
            events: self.events,
        }
    }
}

pub(crate) fn admitted_session(
    result: Result<RuntimeTurnOutcome, TurnAdmissionFailure>,
) -> Result<PublicSession, SatelleError> {
    match result {
        Ok(outcome) => Ok(outcome.session),
        Err(TurnAdmissionFailure::Admitted { session, .. }) => Ok(*session),
        Err(failure) => Err(failure.into_error()),
    }
}

pub(crate) struct RuntimeAdmissionReplay {
    outcome: RuntimeTurnOutcome,
    turn_id: TurnId,
}

impl RuntimeAdmissionReplay {
    pub(crate) fn into_session(self) -> PublicSession {
        self.outcome.session
    }
}

pub(crate) fn storage_error(error: crate::storage::StorageError) -> SatelleError {
    model::storage_failure(error)
}

pub(crate) fn integrity_error(message: impl Into<String>) -> SatelleError {
    model::integrity_failure(message)
}

pub(crate) fn idempotency_conflict() -> SatelleError {
    model::idempotency_conflict()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeStartupState {
    Ready,
    RecoveryRequired,
}

pub(crate) struct RuntimeEngine {
    // This is the sole SQLite owner for the runtime. The mutex protects short
    // admission/read/commit sections only and is never held across adapter I/O.
    storage: Mutex<Storage>,
    adapter: Arc<dyn ComputerUseAdapter>,
    recovery: Mutex<RecoveryQueue>,
    restart_recovery_initialized: Mutex<bool>,
    workers: Mutex<WorkerRegistry>,
    live_events: LiveEventHub,
    process_identity: ProcessIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeSnapshot {
    host_identity: satelle_core::session::HostIdentityRef,
    storage: StorageSnapshot,
}

impl RuntimeSnapshot {
    pub(crate) fn host_identity(&self) -> &satelle_core::session::HostIdentityRef {
        &self.host_identity
    }

    pub(crate) const fn session_count(&self) -> usize {
        self.storage.session_count()
    }

    pub(crate) const fn active_turn_count(&self) -> usize {
        self.storage.active_turn_count()
    }

    pub(crate) const fn recovery_pending_turn_count(&self) -> usize {
        self.storage.recovery_pending_turn_count()
    }
}

impl RuntimeEngine {
    fn open(
        state_root: &Path,
        adapter: Arc<dyn ComputerUseAdapter>,
    ) -> Result<Arc<Self>, SatelleError> {
        let process_identity =
            ProcessIdentity::current().map_err(model::process_identity_failure)?;
        let storage =
            Storage::open_without_restart_recovery(state_root).map_err(model::storage_failure)?;
        Ok(Arc::new(Self {
            storage: Mutex::new(storage),
            adapter,
            recovery: Mutex::new(RecoveryQueue::new(Vec::new())),
            restart_recovery_initialized: Mutex::new(false),
            workers: Mutex::new(WorkerRegistry::default()),
            live_events: LiveEventHub::new(),
            process_identity,
        }))
    }

    fn replay_admission(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
    ) -> Result<Option<RuntimeAdmissionReplay>, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        self.maintain_session_retention(requested_at)?;
        let idempotency = model::idempotency(operation, identity, requested_at)?;
        let replay = self
            .lock_storage()?
            .replay_admission_if_present(operation, &idempotency, expected_session_id)
            .map_err(model::storage_failure)?;
        replay
            .map(|replay| {
                let (outcome, _session_id, turn_id) = replay.into_parts();
                let outcome = match outcome {
                    AdmissionOutcome::InProgress(session) | AdmissionOutcome::Complete(session) => {
                        model::turn_outcome(&session, Vec::new())
                    }
                    AdmissionOutcome::Execute { .. } => {
                        return Err(model::integrity_failure(
                            "a stored idempotency replay requested new adapter execution",
                        ));
                    }
                };
                Ok(RuntimeAdmissionReplay { outcome, turn_id })
            })
            .transpose()
    }

    fn initialize_restart_recovery(&self) -> Result<(), SatelleError> {
        let mut initialized = self.restart_recovery_initialized.lock().map_err(|_| {
            model::integrity_failure("the restart recovery initialization lock was poisoned")
        })?;
        if *initialized {
            return Ok(());
        }
        let subjects = self
            .lock_storage()?
            .initialize_restart_recovery()
            .map_err(model::storage_failure)?;
        *self.recovery.lock().map_err(|_| {
            model::integrity_failure("the runtime recovery lock was poisoned during startup")
        })? = RecoveryQueue::new(subjects);
        *initialized = true;
        Ok(())
    }

    fn run(
        self: &Arc<Self>,
        command: RunCommand<'_>,
        readiness: AdapterReadiness,
    ) -> Result<RuntimeTurnOutcome, SatelleError> {
        ensure_local_host(command.host)?;
        self.persist_readiness(&readiness)?;
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let started_at = time::OffsetDateTime::now_utc();
        let host_identity = self.host_identity()?;
        let execution_policy = readiness
            .execution_policy()
            .for_turn_mode(command.execution_mode);
        let initial = model::initial_session(
            session_id.clone(),
            turn_id.clone(),
            host_identity,
            &readiness,
            execution_policy,
            started_at,
        )?;
        let context = model::admission(
            IdempotentOperation::Run,
            started_at,
            &command.identity,
            &self.process_identity,
        )?;
        let outcome = {
            let mut storage = self.lock_storage()?;
            let outcome = storage
                .begin_session(&initial, &context)
                .map_err(model::storage_failure)?;
            if let AdmissionOutcome::Execute { session, .. } = &outcome {
                self.publish_committed_turn(session, &turn_id);
            }
            outcome
        };
        self.finish_admission(
            command.host,
            command.prompt,
            command.execution_mode,
            command.dispatch,
            outcome,
        )
    }

    fn steer(
        self: &Arc<Self>,
        command: SteerCommand<'_>,
        readiness: AdapterReadiness,
    ) -> Result<RuntimeTurnOutcome, SatelleError> {
        self.persist_readiness(&readiness)?;
        // Preflight can outlive the retention observation made during replay
        // admission. Recheck at the authoritative Session load so a follow-up
        // cannot revive metadata that crossed the retention boundary meanwhile.
        self.maintain_session_retention(time::OffsetDateTime::now_utc())?;
        let existing = self
            .lock_storage()?
            .load_session(&command.session_id)
            .map_err(model::storage_failure)?
            .ok_or_else(|| SatelleError::session_not_found(&command.session_id))?;
        model::validate_follow_up_bindings(&existing, &readiness)?;
        let turn_id = TurnId::new();
        let started_at = model::monotonic_now(&existing);
        let execution_policy = readiness
            .execution_policy()
            .for_turn_mode(command.execution_mode);
        let context = model::admission(
            IdempotentOperation::Steer,
            started_at,
            &command.identity,
            &self.process_identity,
        )?;
        let outcome = {
            let mut storage = self.lock_storage()?;
            let outcome = storage
                .begin_follow_up(
                    &command.session_id,
                    existing.session_state_revision(),
                    turn_id.clone(),
                    execution_policy,
                    started_at,
                    &context,
                )
                .map_err(model::storage_failure)?;
            if let AdmissionOutcome::Execute { session, .. } = &outcome {
                self.publish_committed_turn(session, &turn_id);
            }
            outcome
        };
        self.finish_admission(
            LOCAL_DEMO_HOST,
            command.prompt,
            command.execution_mode,
            command.dispatch,
            outcome,
        )
    }

    fn persist_readiness(&self, readiness: &AdapterReadiness) -> Result<(), SatelleError> {
        self.lock_storage()?
            .store_preflight_successes(
                readiness.adapter(),
                readiness.desktop_binding(),
                readiness.execution_policy(),
                readiness.evidence(),
                readiness.provider_smoke_evidence(),
            )
            .map_err(model::storage_failure)
    }

    fn finish_admission(
        self: &Arc<Self>,
        host: &str,
        prompt: &str,
        execution_mode: satelle_core::session::TurnExecutionMode,
        dispatch_preference: request::DispatchPreference,
        outcome: AdmissionOutcome,
    ) -> Result<RuntimeTurnOutcome, SatelleError> {
        match outcome {
            AdmissionOutcome::InProgress(session) | AdmissionOutcome::Complete(session) => {
                Ok(model::turn_outcome(&session, Vec::new()))
            }
            AdmissionOutcome::Execute {
                session,
                recovery_subject,
            } => {
                let work = TurnWork {
                    session,
                    subject: recovery_subject,
                };
                let admitted = model::turn_outcome(&work.session, Vec::new());
                let plan = ExecutionPlan {
                    host: host.to_string(),
                    prompt: prompt.to_string(),
                    execution_mode,
                    work,
                };
                match dispatch_preference {
                    request::DispatchPreference::Inline => self.execute(plan),
                    request::DispatchPreference::Detached => {
                        self.schedule(plan)?;
                        Ok(admitted)
                    }
                }
            }
        }
    }

    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.maintain_session_retention(time::OffsetDateTime::now_utc())?;
        let session = self
            .lock_storage()?
            .load_session(session_id)
            .map_err(model::storage_failure)?
            .ok_or_else(|| SatelleError::session_not_found(session_id))?;
        Ok(session.to_public())
    }

    fn log_page(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        self.maintain_session_retention(time::OffsetDateTime::now_utc())?;
        match self.lock_storage()?.log_page(query) {
            Ok(page) => Ok(page),
            Err(LogPageStorageError::Storage(error)) => Err(model::storage_failure(error)),
            Err(LogPageStorageError::CursorExpired {
                earliest_available_cursor,
                resume_cursor,
            }) => Err(SatelleError::logs_cursor_expired(
                earliest_available_cursor
                    .map(|cursor| LogCursor::from_position(cursor).to_string()),
                LogCursor::from_position(resume_cursor).to_string(),
            )),
            Err(LogPageStorageError::CursorAhead) => Err(SatelleError::invalid_usage(
                "the Log Cursor is ahead of this Host log history",
            )),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn append_log_for_tests(
        &self,
        timestamp: time::OffsetDateTime,
        source: crate::LogSource,
        severity: crate::LogSeverity,
    ) -> Result<LogCursor, SatelleError> {
        let record = crate::storage::SafeLogRecord::new(
            timestamp,
            source,
            severity,
            crate::LogEvent::StoreOpened,
            crate::LogSubject::Host,
        )
        .map_err(model::storage_failure)?;
        self.lock_storage()?
            .append_safe_log(&record)
            .map(LogCursor::from_position)
            .map_err(model::storage_failure)
    }

    fn host_identity(&self) -> Result<satelle_core::session::HostIdentityRef, SatelleError> {
        self.lock_storage()?
            .host_identity()
            .map_err(model::storage_failure)
    }

    fn snapshot(&self) -> Result<RuntimeSnapshot, SatelleError> {
        self.maintain_session_retention(time::OffsetDateTime::now_utc())?;
        let storage = self.lock_storage()?;
        Ok(RuntimeSnapshot {
            host_identity: storage.host_identity().map_err(model::storage_failure)?,
            storage: storage.snapshot().map_err(model::storage_failure)?,
        })
    }

    fn reap_finished_workers(&self) -> Result<bool, SatelleError> {
        let mut workers = self.workers.lock().map_err(|_| {
            model::integrity_failure("the detached runtime worker registry was poisoned")
        })?;
        workers.reap_finished()?;
        Ok(workers.is_empty())
    }

    fn subscribe_live_events(&self) -> crate::LiveEventSubscription {
        self.live_events.subscribe()
    }

    fn maintain_session_retention(
        &self,
        observed_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.lock_storage()?
            .prune_expired_session_metadata(observed_at)
            .map_err(model::storage_failure)
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Storage>, SatelleError> {
        self.storage.lock().map_err(|_| {
            model::integrity_failure("the runtime storage lock was poisoned by a failed operation")
        })
    }
}

struct LazyRuntime {
    state_root: Result<PathBuf, SatelleError>,
    engine: Option<Arc<RuntimeEngine>>,
}

#[derive(Clone)]
pub(crate) struct RuntimeHandle {
    adapter: Arc<dyn ComputerUseAdapter>,
    lazy: Arc<Mutex<LazyRuntime>>,
}

impl std::fmt::Debug for RuntimeHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeHandle")
            .finish_non_exhaustive()
    }
}

impl RuntimeHandle {
    pub(crate) fn new<A: ComputerUseAdapter>(
        state_root: Result<PathBuf, SatelleError>,
        adapter: A,
    ) -> Self {
        Self {
            adapter: Arc::new(adapter),
            lazy: Arc::new(Mutex::new(LazyRuntime {
                state_root,
                engine: None,
            })),
        }
    }

    pub(crate) fn replay_admission_if_present(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
    ) -> Result<Option<RuntimeAdmissionReplay>, SatelleError> {
        let Some(engine) = self.existing_engine()? else {
            return Ok(None);
        };
        engine.replay_admission(operation, identity, expected_session_id)
    }

    pub(crate) fn run(
        &self,
        command: RunCommand<'_>,
    ) -> Result<RuntimeTurnOutcome, TurnAdmissionFailure> {
        if let Some(replay) = self
            .replay_admission_if_present(IdempotentOperation::Run, &command.identity, None)
            .map_err(TurnAdmissionFailure::admission_unknown)?
        {
            return Ok(replay.outcome);
        }
        let existing_engine = self
            .existing_engine()
            .map_err(TurnAdmissionFailure::admission_unknown)?;
        if let Err(error) = self.adapter.admit_operation(ControlPlaneOperation::Run) {
            return self.resolve_precommit_failure(
                IdempotentOperation::Run,
                &command.identity,
                None,
                error,
            );
        }
        let needs_persistent_replay = existing_engine.is_none();
        let engine = match self.engine() {
            Ok(engine) => engine,
            Err(error) => {
                return self.resolve_precommit_failure(
                    IdempotentOperation::Run,
                    &command.identity,
                    None,
                    error,
                );
            }
        };
        if needs_persistent_replay
            && let Some(replay) = engine
                .replay_admission(IdempotentOperation::Run, &command.identity, None)
                .map_err(TurnAdmissionFailure::admission_unknown)?
        {
            return Ok(replay.outcome);
        }
        if let Err(error) = engine.reconcile_before_admission() {
            return self.resolve_precommit_failure(
                IdempotentOperation::Run,
                &command.identity,
                None,
                error,
            );
        }
        let readiness = match self.adapter.preflight(command.host) {
            Ok(readiness) => readiness,
            Err(error) => {
                return self.resolve_precommit_failure(
                    IdempotentOperation::Run,
                    &command.identity,
                    None,
                    error,
                );
            }
        };
        let identity = command.identity.clone();
        match engine.run(command, readiness) {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(Self::classify_failed_admission(
                &engine,
                IdempotentOperation::Run,
                &identity,
                None,
                error,
            )),
        }
    }

    pub(crate) fn steer(
        &self,
        command: SteerCommand<'_>,
    ) -> Result<RuntimeTurnOutcome, TurnAdmissionFailure> {
        if let Some(replay) = self
            .replay_admission_if_present(
                IdempotentOperation::Steer,
                &command.identity,
                Some(&command.session_id),
            )
            .map_err(TurnAdmissionFailure::admission_unknown)?
        {
            return Ok(replay.outcome);
        }
        let existing_engine = self
            .existing_engine()
            .map_err(TurnAdmissionFailure::admission_unknown)?;
        if let Err(error) = self.adapter.admit_operation(ControlPlaneOperation::Steer) {
            return self.resolve_precommit_failure(
                IdempotentOperation::Steer,
                &command.identity,
                Some(&command.session_id),
                error,
            );
        }
        let needs_persistent_replay = existing_engine.is_none();
        let engine = match self.engine() {
            Ok(engine) => engine,
            Err(error) => {
                return self.resolve_precommit_failure(
                    IdempotentOperation::Steer,
                    &command.identity,
                    Some(&command.session_id),
                    error,
                );
            }
        };
        if needs_persistent_replay
            && let Some(replay) = engine
                .replay_admission(
                    IdempotentOperation::Steer,
                    &command.identity,
                    Some(&command.session_id),
                )
                .map_err(TurnAdmissionFailure::admission_unknown)?
        {
            return Ok(replay.outcome);
        }
        if let Err(error) = engine.reconcile_before_admission() {
            return self.resolve_precommit_failure(
                IdempotentOperation::Steer,
                &command.identity,
                Some(&command.session_id),
                error,
            );
        }
        let readiness = match self.adapter.preflight(LOCAL_DEMO_HOST) {
            Ok(readiness) => readiness,
            Err(error) => {
                return self.resolve_precommit_failure(
                    IdempotentOperation::Steer,
                    &command.identity,
                    Some(&command.session_id),
                    error,
                );
            }
        };
        let identity = command.identity.clone();
        let session_id = command.session_id.clone();
        match engine.steer(command, readiness) {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(Self::classify_failed_admission(
                &engine,
                IdempotentOperation::Steer,
                &identity,
                Some(&session_id),
                error,
            )),
        }
    }

    fn classify_failed_admission(
        engine: &RuntimeEngine,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
        error: SatelleError,
    ) -> TurnAdmissionFailure {
        match engine.replay_admission(operation, identity, expected_session_id) {
            Ok(Some(replay)) => {
                TurnAdmissionFailure::admitted(error, replay.outcome.session, replay.turn_id)
            }
            Ok(None) => TurnAdmissionFailure::not_admitted(error),
            Err(_) => TurnAdmissionFailure::admission_unknown(error),
        }
    }

    fn resolve_precommit_failure(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
        error: SatelleError,
    ) -> Result<RuntimeTurnOutcome, TurnAdmissionFailure> {
        let engine = match self.existing_engine() {
            Ok(Some(engine)) => engine,
            Ok(None) => return Err(TurnAdmissionFailure::not_admitted(error)),
            Err(_) => return Err(TurnAdmissionFailure::admission_unknown(error)),
        };
        match engine.replay_admission(operation, identity, expected_session_id) {
            Ok(Some(replay)) => Ok(replay.outcome),
            Ok(None) => Err(TurnAdmissionFailure::not_admitted(error)),
            Err(_) => Err(TurnAdmissionFailure::admission_unknown(error)),
        }
    }

    pub(crate) fn status(&self, session_id: SessionId) -> Result<PublicSession, SatelleError> {
        self.engine()?.status(&session_id)
    }

    pub(crate) fn log_page(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        self.engine()?.log_page(query)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn append_log_for_tests(
        &self,
        timestamp: time::OffsetDateTime,
        source: crate::LogSource,
        severity: crate::LogSeverity,
    ) -> Result<LogCursor, SatelleError> {
        self.engine()?
            .append_log_for_tests(timestamp, source, severity)
    }

    pub(crate) fn reconcile_and_snapshot(&self) -> Result<RuntimeSnapshot, SatelleError> {
        let engine = self.engine()?;
        engine.reconcile_pending()?;
        engine.snapshot()
    }

    pub(crate) fn snapshot(&self) -> Result<RuntimeSnapshot, SatelleError> {
        self.engine()?.snapshot()
    }

    pub(crate) fn daemon_workers_idle(&self) -> Result<bool, SatelleError> {
        self.engine()?.reap_finished_workers()
    }

    pub(crate) fn subscribe_live_events(
        &self,
    ) -> Result<crate::LiveEventSubscription, SatelleError> {
        Ok(self.engine()?.subscribe_live_events())
    }

    pub(crate) fn register_api_token(
        &self,
        registration: ApiTokenRegistration,
    ) -> Result<(), SatelleError> {
        self.engine()?
            .lock_storage()?
            .register_api_token(registration)
            .map_err(model::storage_failure)
    }

    pub(crate) fn authenticate_api_token(
        &self,
        token: &ApiBearerToken,
        at: time::OffsetDateTime,
    ) -> Result<Option<ApiPrincipal>, SatelleError> {
        self.engine()?
            .lock_storage()?
            .authenticate_api_token(token, at)
            .map_err(model::storage_failure)
    }

    pub(crate) fn api_principal_is_active(
        &self,
        principal: &ApiPrincipal,
        at: time::OffsetDateTime,
    ) -> Result<bool, SatelleError> {
        self.engine()?
            .lock_storage()?
            .api_principal_is_active(principal, at)
            .map_err(model::storage_failure)
    }

    pub(crate) fn rotate_api_token(
        &self,
        replacement: &ApiBearerToken,
        expected_credential_revision: u64,
        at: time::OffsetDateTime,
    ) -> Result<ApiPrincipal, SatelleError> {
        self.engine()?
            .lock_storage()?
            .rotate_api_token(replacement, expected_credential_revision, at)
            .map_err(model::storage_failure)
    }

    pub(crate) fn revoke_api_token(
        &self,
        token_id: &str,
        at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.engine()?
            .lock_storage()?
            .revoke_api_token(token_id, at)
            .map_err(model::storage_failure)
    }

    pub(crate) fn rotate_idempotency_hmac_key(&self) -> Result<u16, SatelleError> {
        self.engine()?
            .lock_storage()?
            .rotate_idempotency_hmac_key(time::OffsetDateTime::now_utc())
            .map_err(model::storage_failure)
    }

    pub(crate) fn authenticated_request_identity(
        &self,
        principal: &ApiPrincipal,
        operation: IdempotentOperation,
        idempotency_key: &str,
        canonical_payload: &[u8],
        digest_schema_version: u16,
    ) -> Result<RequestIdentity, SatelleError> {
        let engine = self.engine()?;
        let storage = engine.lock_storage()?;
        let key_version = storage
            .idempotency_hmac_key_version(principal.principal_ref(), operation, idempotency_key)
            .map_err(model::storage_failure)?;
        let digest: SensitiveRequestDigest = match key_version {
            Some(key_version) => storage
                .digest_idempotency_payload_with_key(canonical_payload, key_version)
                .map_err(model::storage_failure),
            None => storage
                .digest_idempotency_payload(canonical_payload)
                .map_err(model::storage_failure),
        }?;
        Ok(RequestIdentity::authenticated(
            principal.principal_ref(),
            idempotency_key,
            digest.hex(),
            digest_schema_version,
            digest.key_version(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn startup_state(&self) -> Result<RuntimeStartupState, SatelleError> {
        self.engine()?.startup_state()
    }

    #[cfg(test)]
    pub(crate) fn wait_for_background(&self) -> Result<(), SatelleError> {
        let engine = self.engine()?;
        worker::wait_for_background(&engine.workers)
    }

    #[cfg(test)]
    pub(crate) fn poison_worker_registry_for_tests(&self) -> Result<(), SatelleError> {
        let engine = self.engine()?;
        let poisoner = std::thread::spawn(move || {
            let _worker_registry = engine
                .workers
                .lock()
                .expect("the worker registry should be healthy before the test poisons it");
            panic!("poison the worker registry for deterministic dispatch failure");
        });
        assert!(poisoner.join().is_err());
        Ok(())
    }

    fn engine(&self) -> Result<Arc<RuntimeEngine>, SatelleError> {
        let engine = self.engine_without_restart_recovery()?;
        engine.initialize_restart_recovery()?;
        Ok(engine)
    }

    fn engine_without_restart_recovery(&self) -> Result<Arc<RuntimeEngine>, SatelleError> {
        let mut lazy = self.lazy.lock().map_err(|_| {
            model::integrity_failure("the lazy runtime lock was poisoned while opening storage")
        })?;
        if let Some(engine) = &lazy.engine {
            return Ok(Arc::clone(engine));
        }
        let state_root = lazy.state_root.clone()?;
        let engine = RuntimeEngine::open(&state_root, Arc::clone(&self.adapter))?;
        lazy.engine = Some(Arc::clone(&engine));
        Ok(engine)
    }

    fn existing_engine(&self) -> Result<Option<Arc<RuntimeEngine>>, SatelleError> {
        let state_root = {
            let lazy = self.lazy.lock().map_err(|_| {
                model::integrity_failure("the lazy runtime lock was poisoned while reading storage")
            })?;
            if let Some(engine) = &lazy.engine {
                return Ok(Some(Arc::clone(engine)));
            }
            lazy.state_root.clone()?
        };
        if !Storage::has_existing_state(&state_root).map_err(model::storage_failure)? {
            return Ok(None);
        }
        self.engine_without_restart_recovery().map(Some)
    }
}

fn ensure_local_host(host: &str) -> Result<(), SatelleError> {
    if host == LOCAL_DEMO_HOST {
        Ok(())
    } else {
        Err(SatelleError::not_implemented(format!(
            "host '{host}' is configured, but only local-demo execution is implemented"
        )))
    }
}

#[cfg(test)]
#[path = "runtime-retention-tests.rs"]
mod retention_tests;
#[cfg(test)]
#[path = "runtime-tests.rs"]
mod tests;
