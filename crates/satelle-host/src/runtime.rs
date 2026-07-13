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
#[path = "runtime-worker.rs"]
mod worker;

pub use adapter::{
    AdapterReadiness, AdapterSubject, ComputerUseAdapter, EvidenceError, ExecuteRequest,
    ExecuteResult, ProviderSmokeEvidence, ReadinessEvidence, RecoveryObservation,
};
pub(crate) use codex_adapter::ProductionComputerUseAdapter;
pub(crate) use request::{LogQuery, RequestIdentity, RunCommand, SteerCommand, StopCommand};
use worker::{ExecutionPlan, TurnWork, WorkerRegistry};

use crate::live_events::LiveEventHub;
use crate::process_identity::ProcessIdentity;
use crate::storage::{
    AdmissionOutcome, ApiTokenRegistration, BeginStopOutcome, IdempotentOperation,
    LogPageStorageError, SensitiveRequestDigest, StopCommitOutcome, Storage, StorageErrorKind,
    StorageSnapshot,
};
use crate::{ApiBearerToken, ApiPrincipal, DaemonLogPage, LogCursor, LogPageQuery};
use recovery::RecoveryQueue;
use satelle_core::session::{PublicSession, TurnState};
use satelle_core::{
    ControlPlaneOperation, LOCAL_DEMO_HOST, LogEntry, SatelleError, SatelleEvent, SessionId,
    SessionRecord, StopResult, TurnId,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug)]
pub(crate) struct RuntimeTurnOutcome {
    pub(crate) session: SessionRecord,
    pub(crate) events: Vec<SatelleEvent>,
    pub(crate) public_session: PublicSession,
}

impl RuntimeTurnOutcome {
    pub(crate) fn into_command_outcome(self) -> crate::TurnOutcome {
        crate::TurnOutcome {
            session: self.session,
            events: self.events,
        }
    }
}

pub(crate) fn storage_error(error: crate::storage::StorageError) -> SatelleError {
    model::storage_failure(error)
}

pub(crate) fn integrity_error(message: impl Into<String>) -> SatelleError {
    model::integrity_failure(message)
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

pub(crate) struct RuntimeStopOutcome {
    pub(crate) result: StopResult,
    pub(crate) session_state_revision: satelle_core::session::SessionStateRevision,
    pub(crate) turn_state_revision: satelle_core::session::TurnStateRevision,
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
    ) -> Result<Option<RuntimeTurnOutcome>, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        let idempotency = model::idempotency(operation, identity, requested_at)?;
        let replay = self
            .lock_storage()?
            .replay_admission_if_present(operation, &idempotency, expected_session_id)
            .map_err(model::storage_failure)?;
        replay
            .map(|outcome| match outcome {
                AdmissionOutcome::InProgress(session) | AdmissionOutcome::Complete(session) => {
                    model::turn_outcome(&session, Vec::new())
                }
                AdmissionOutcome::Execute { .. } => Err(model::integrity_failure(
                    "a stored idempotency replay requested new adapter execution",
                )),
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
                model::turn_outcome(&session, Vec::new())
            }
            AdmissionOutcome::Execute {
                session,
                recovery_subject,
            } => {
                let work = TurnWork {
                    session,
                    subject: recovery_subject,
                };
                let admitted = model::turn_outcome(&work.session, Vec::new())?;
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

    fn status(&self, session_id: &SessionId) -> Result<SessionRecord, SatelleError> {
        let session = self
            .lock_storage()?
            .load_session(session_id)
            .map_err(model::storage_failure)?
            .ok_or_else(|| SatelleError::session_not_found(session_id))?;
        model::session_record(&session)
    }

    fn status_public(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.lock_storage()?
            .load_session(session_id)
            .map_err(model::storage_failure)?
            .map(|session| session.to_public())
            .ok_or_else(|| SatelleError::session_not_found(session_id))
    }

    fn stop(&self, command: StopCommand) -> Result<RuntimeStopOutcome, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        let idempotency = model::stop_idempotency(requested_at, &command.identity)?;
        let outcome = loop {
            let target = self
                .lock_storage()?
                .stop_admission_target(&command.session_id, &idempotency)
                .map_err(|error| model::storage_failure_for_session(error, &command.session_id))?;
            if target.requires_control_plane() {
                self.adapter.admit_operation(ControlPlaneOperation::Stop)?;
            }
            let turn_id = target.turn_id().clone();
            match self
                .lock_storage()?
                .begin_stop(&command.session_id, &turn_id, &idempotency)
            {
                Ok(outcome) => break outcome,
                Err(error) if error.kind() == StorageErrorKind::StateConflict => continue,
                Err(error) => {
                    return Err(model::storage_failure_for_session(
                        error,
                        &command.session_id,
                    ));
                }
            }
        };
        let commit = match outcome {
            BeginStopOutcome::Complete(commit) => commit,
            BeginStopOutcome::Observe(claim) => {
                // Stop observation is external I/O and must not serialize
                // status, logs, or the terminal execution compare-and-swap.
                let observation = self
                    .adapter
                    .observe_stop(AdapterSubject::new(claim.recovery_subject()))?;
                let mut storage = self.lock_storage()?;
                let current = storage
                    .load_session(&command.session_id)
                    .map_err(model::storage_failure)?
                    .ok_or_else(|| SatelleError::session_not_found(&command.session_id))?;
                let confirmed_at = time::OffsetDateTime::now_utc().max(current.updated_at());
                let commit = storage
                    .confirm_stop(claim, observation, confirmed_at)
                    .map_err(model::storage_failure)?;
                let stop_committed = matches!(commit.outcome(), StopCommitOutcome::Stopped(_));
                drop(storage);
                if stop_committed {
                    self.adapter
                        .stop_committed(commit.session().id(), commit.turn_id());
                }
                if matches!(
                    commit.outcome(),
                    StopCommitOutcome::Stopped(_)
                        | StopCommitOutcome::NotConfirmed { changed: true, .. }
                ) {
                    self.publish_committed_turn(commit.session(), commit.turn_id());
                }
                commit
            }
        };
        let committed_turn = commit
            .session()
            .turn(commit.turn_id())
            .ok_or_else(|| model::integrity_failure("the stopped Turn is missing"))?;
        let session_state_revision = commit.session().session_state_revision();
        let turn_state_revision = committed_turn.turn_state_revision();
        if committed_turn.state() == TurnState::RecoveryPending {
            let subject = self
                .lock_storage()?
                .recovery_subject(&command.session_id, commit.turn_id())
                .map_err(model::storage_failure)?;
            self.enqueue_recovery_subject(subject)?;
        } else {
            self.remove_recovery_subject(&command.session_id, commit.turn_id())?;
        }
        Ok(RuntimeStopOutcome {
            result: model::stop_result(&commit, &command.session_id)?,
            session_state_revision,
            turn_state_revision,
        })
    }

    fn logs(&self, query: LogQuery<'_>) -> Result<Vec<LogEntry>, SatelleError> {
        ensure_local_host(query.host)?;
        self.lock_storage()?
            .logs_after(None, 10_000)
            .map_err(model::storage_failure)?
            .into_iter()
            .map(model::stored_log_entry)
            .collect()
    }

    fn log_page(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
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

    pub(crate) fn run(&self, command: RunCommand<'_>) -> Result<RuntimeTurnOutcome, SatelleError> {
        if let Some(engine) = self.existing_engine()?
            && let Some(replay) =
                engine.replay_admission(IdempotentOperation::Run, &command.identity, None)?
        {
            return Ok(replay);
        }
        self.adapter.admit_operation(ControlPlaneOperation::Run)?;
        let engine = self.engine()?;
        engine.reconcile_before_admission()?;
        let readiness = self.adapter.preflight(command.host)?;
        engine.run(command, readiness)
    }

    pub(crate) fn steer(
        &self,
        command: SteerCommand<'_>,
    ) -> Result<RuntimeTurnOutcome, SatelleError> {
        if let Some(engine) = self.existing_engine()?
            && let Some(replay) = engine.replay_admission(
                IdempotentOperation::Steer,
                &command.identity,
                Some(&command.session_id),
            )?
        {
            return Ok(replay);
        }
        self.adapter.admit_operation(ControlPlaneOperation::Steer)?;
        let engine = self.engine()?;
        engine.reconcile_before_admission()?;
        let readiness = self.adapter.preflight(LOCAL_DEMO_HOST)?;
        engine.steer(command, readiness)
    }

    pub(crate) fn status(&self, session_id: SessionId) -> Result<SessionRecord, SatelleError> {
        self.engine()?.status(&session_id)
    }

    pub(crate) fn status_public(
        &self,
        session_id: &SessionId,
    ) -> Result<PublicSession, SatelleError> {
        self.engine()?.status_public(session_id)
    }

    pub(crate) fn stop(&self, command: StopCommand) -> Result<StopResult, SatelleError> {
        self.stop_with_snapshot(command)
            .map(|outcome| outcome.result)
    }

    pub(crate) fn stop_with_snapshot(
        &self,
        command: StopCommand,
    ) -> Result<RuntimeStopOutcome, SatelleError> {
        self.engine()?.stop(command)
    }

    pub(crate) fn logs(&self, query: LogQuery<'_>) -> Result<Vec<LogEntry>, SatelleError> {
        self.engine()?.logs(query)
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
#[path = "runtime-tests.rs"]
mod tests;
