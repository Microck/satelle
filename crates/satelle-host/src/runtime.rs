#[path = "runtime-adapter.rs"]
mod adapter;
#[path = "runtime-codex-adapter.rs"]
mod codex_adapter;
#[path = "daemon-activity.rs"]
mod daemon_activity;
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
    AdapterPreflight, AdapterReadiness, AdapterSubject, ComputerUseAdapter, EvidenceError,
    ExecuteRequest, ExecuteResult, ProviderComputerUseIntent, ProviderSmokeEvidence,
    ProviderSmokeFailureEvidence, ProviderSmokeResult, ProviderSmokeSource, ReadinessCacheKey,
    ReadinessEvidence, ReadinessObservationState, RecoveryObservation,
};
pub(crate) use adapter::{NativeProbeResult, ReadinessProbeDriver, ReadinessSource};
pub(crate) use codex_adapter::{
    ProductionAdapterPolicy, ProductionComputerUseAdapter, validate_provider_endpoint,
};
pub use request::AdmissionCancellation;
pub(crate) use request::{
    AdmissionCancellationState, RequestIdentity, RunCommand, SteerCommand, StopCommand,
};
pub(crate) use stop::RuntimeStopOutcome;
use worker::{
    ExecutionPlan, LeaseHeartbeatGuard, MaintenanceOperationGuard, TurnWork, WorkerRegistry,
};

use daemon_activity::{DaemonActivity, DaemonActivityGuard};

use crate::live_events::LiveEventHub;
use crate::process_identity::ProcessIdentity;
use crate::storage::{
    AdmissionOutcome, ApiTokenRegistration, IdempotentOperation, LeaseOwner, LogPageStorageError,
    ObservedUpstreamRef, OperatorLogMirror, OperatorLogPolicy, ProviderBindingAuthorizationReplay,
    ProviderBindingDeletionReplay, ReadinessProbeKind, ReadinessProbeTerminal,
    SensitiveRequestDigest, SetupActionSkipReason, SetupRepairPlan, SetupRepairProbe, SetupRunPlan,
    SetupRunRecord, SetupRunStatus, Storage, StorageSnapshot,
};
use crate::{ApiBearerToken, ApiPrincipal, DaemonLogPage, LogCursor, LogPageQuery};
use recovery::RecoveryQueue;
pub(crate) use recovery::VerifiedSetupPostconditions;
#[cfg(test)]
pub(crate) use recovery::verify_setup_postconditions;
use satelle_core::session::{DesktopBindingRef, PublicSession, TurnAdmissionFailure};
use satelle_core::{
    ControlPlaneOperation, ErrorCode, LOCAL_DEMO_HOST, ProviderBindingAuthorization,
    ProviderBindingSource, PublicResolvedProviderBinding, ResolvedProviderBinding, SatelleError,
    SatelleEvent, SessionId, TurnId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_MAINTENANCE_START_AND_RETAIN: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[derive(Debug)]
pub(crate) struct RuntimeTurnOutcome {
    pub(crate) session: PublicSession,
    pub(crate) events: Vec<SatelleEvent>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
enum ProviderDescriptorValidationReplay {
    Completed(satelle_core::PublicProviderDescriptorValidation),
    Failed(SatelleError),
}

struct AdmissionExecution<'a> {
    host: &'a str,
    prompt: &'a str,
    execution_mode: satelle_core::session::TurnExecutionMode,
    dispatch_preference: request::DispatchPreference,
    provider_smoke_event: Option<satelle_core::SatelleEventBody>,
    resolved_provider_binding: Option<satelle_core::ResolvedProviderBinding>,
    attachments: crate::attachment::StagedAttachments,
}

/// Exclusive in-process authority for one live setup or repair operation.
///
/// The handle is intentionally non-Clone. Dropping it without a successful
/// terminal commit synchronously stops its heartbeat and retains the exact
/// durable owner as recovery_pending.
pub struct MaintenanceOperationHandle {
    operation_id: String,
    operation: Option<MaintenanceOperationGuard>,
    activity: Option<DaemonActivityGuard>,
}

impl MaintenanceOperationHandle {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    fn operation(&self) -> Result<&MaintenanceOperationGuard, crate::storage::StorageError> {
        self.operation
            .as_ref()
            .ok_or_else(crate::storage::StorageError::state_conflict)
    }

    fn disarm(&mut self) {
        if let Some(operation) = self.operation.as_mut() {
            operation.disarm();
        }
        drop(self.operation.take());
        drop(self.activity.take());
    }
}

impl std::fmt::Debug for MaintenanceOperationHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaintenanceOperationHandle")
            .finish_non_exhaustive()
    }
}

pub(crate) struct VerifiedMaintenancePostcheck {
    evidence: Option<ReadinessEvidence>,
    outcome: VerifiedMaintenancePostcheckOutcome,
}

#[derive(Clone, Copy)]
enum VerifiedMaintenancePostcheckOutcome {
    Passed,
    Failed {
        reason: &'static str,
        terminal: ReadinessProbeTerminal,
    },
    Unknown,
}

impl VerifiedMaintenancePostcheck {
    fn passed(evidence: ReadinessEvidence) -> Self {
        Self {
            evidence: Some(evidence),
            outcome: VerifiedMaintenancePostcheckOutcome::Passed,
        }
    }

    fn failed(
        evidence: ReadinessEvidence,
        reason: &'static str,
        terminal: ReadinessProbeTerminal,
    ) -> Self {
        Self {
            evidence: Some(evidence),
            outcome: VerifiedMaintenancePostcheckOutcome::Failed { reason, terminal },
        }
    }

    fn unknown() -> Self {
        Self {
            evidence: None,
            outcome: VerifiedMaintenancePostcheckOutcome::Unknown,
        }
    }

    pub(crate) fn evidence(&self) -> Option<&ReadinessEvidence> {
        self.evidence.as_ref()
    }

    pub(crate) const fn terminal(&self) -> Option<ReadinessProbeTerminal> {
        match self.outcome {
            VerifiedMaintenancePostcheckOutcome::Passed => None,
            VerifiedMaintenancePostcheckOutcome::Failed { terminal, .. } => Some(terminal),
            VerifiedMaintenancePostcheckOutcome::Unknown => {
                Some(ReadinessProbeTerminal::OutcomeUnknown)
            }
        }
    }

    pub(crate) const fn failure_reason(&self) -> Option<&'static str> {
        match self.outcome {
            VerifiedMaintenancePostcheckOutcome::Failed { reason, .. } => Some(reason),
            VerifiedMaintenancePostcheckOutcome::Passed
            | VerifiedMaintenancePostcheckOutcome::Unknown => None,
        }
    }

    pub(crate) const fn is_unknown(&self) -> bool {
        matches!(self.outcome, VerifiedMaintenancePostcheckOutcome::Unknown)
    }
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

pub(crate) enum RuntimeAdmissionState {
    Missing,
    Admitted(RuntimeAdmissionReplay),
    Cancelled,
    RecoveryPending,
}

impl RuntimeAdmissionReplay {
    pub(crate) fn into_parts(self) -> (PublicSession, TurnId) {
        (self.outcome.session, self.turn_id)
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

fn heartbeat_start_failure(error: std::io::Error) -> SatelleError {
    SatelleError {
        code: ErrorCode::HostUnreachable,
        message: format!("the Host lease heartbeat driver could not start: {error}"),
        recovery_command: Some("retry after verifying Host process resources".to_string()),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn start_maintenance_operation_guard(
    engine: &Arc<RuntimeEngine>,
    capability: crate::storage::MaintenanceLeaseCapability,
) -> Result<MaintenanceOperationGuard, SatelleError> {
    #[cfg(test)]
    if FAIL_NEXT_MAINTENANCE_START_AND_RETAIN.with(|fail| fail.replace(false)) {
        let operation_id = capability.operation_id().to_string();
        engine
            .lock_storage()?
            .force_bootstrap_retain_conflict_for_test(&operation_id)
            .map_err(model::storage_failure)?;
        return retain_after_heartbeat_start_failure(
            engine,
            std::io::Error::other("forced maintenance heartbeat startup failure"),
            capability,
        );
    }
    match MaintenanceOperationGuard::start(Arc::clone(&engine.storage), capability) {
        Ok(operation) => Ok(operation),
        Err((error, capability)) => retain_after_heartbeat_start_failure(engine, error, capability),
    }
}

fn retain_after_heartbeat_start_failure(
    engine: &Arc<RuntimeEngine>,
    heartbeat_error: std::io::Error,
    capability: crate::storage::MaintenanceLeaseCapability,
) -> Result<MaintenanceOperationGuard, SatelleError> {
    let owner = capability.lease_owner().clone();
    match engine.lock_storage()?.retain_lease_recovery(&owner) {
        Ok(()) => Err(heartbeat_start_failure(heartbeat_error)),
        Err(recovery_error) => Err(model::integrity_failure(format!(
            "the Host lease heartbeat driver could not start and the committed maintenance operation could not enter recovery_pending: heartbeat={heartbeat_error}; recovery={recovery_error}"
        ))),
    }
}

fn readiness_probe_terminal(
    error: &SatelleError,
    persistence_failed: bool,
    cancellation_detail: &str,
    timeout_code: Option<ErrorCode>,
) -> ReadinessProbeTerminal {
    if persistence_failed {
        return ReadinessProbeTerminal::OutcomeUnknown;
    }
    match error
        .details
        .get(cancellation_detail)
        .and_then(serde_json::Value::as_str)
    {
        Some("outcome_unknown" | "upstream_still_active") => ReadinessProbeTerminal::OutcomeUnknown,
        Some("confirmed") => ReadinessProbeTerminal::TimedOut,
        _ if timeout_code.is_some_and(|code| error.code == code) => {
            ReadinessProbeTerminal::TimedOut
        }
        _ => ReadinessProbeTerminal::Failed,
    }
}

fn probe_dispatch_possible(error: &SatelleError) -> bool {
    error
        .details
        .get("probe_dispatch_possible")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn readiness_probe_terminal_with_dispatch(
    error: &SatelleError,
    persistence_failed: bool,
    cancellation_detail: &str,
    timeout_code: Option<ErrorCode>,
    dispatch_possible: bool,
) -> ReadinessProbeTerminal {
    let cancellation_confirmed = error
        .details
        .get(cancellation_detail)
        .and_then(serde_json::Value::as_str)
        == Some("confirmed");
    if dispatch_possible && !cancellation_confirmed {
        return ReadinessProbeTerminal::OutcomeUnknown;
    }
    readiness_probe_terminal(error, persistence_failed, cancellation_detail, timeout_code)
}

pub(crate) fn verify_maintenance_postcheck(
    observation: NativeProbeResult,
    persistence_error: Option<SatelleError>,
) -> (VerifiedMaintenancePostcheck, Option<SatelleError>) {
    match (observation, persistence_error) {
        (NativeProbeResult::Passed(evidence), None) => {
            (VerifiedMaintenancePostcheck::passed(evidence), None)
        }
        (NativeProbeResult::Passed(_), Some(error)) => {
            (VerifiedMaintenancePostcheck::unknown(), Some(error))
        }
        (
            NativeProbeResult::Failed {
                evidence,
                reason,
                error,
                dispatch_possible,
            },
            persistence_error,
        ) => {
            let terminal = readiness_probe_terminal_with_dispatch(
                &error,
                persistence_error.is_some(),
                "native_readiness_cancellation",
                Some(ErrorCode::NativeReadinessTimeout),
                dispatch_possible,
            );
            if terminal == ReadinessProbeTerminal::OutcomeUnknown {
                (
                    VerifiedMaintenancePostcheck::unknown(),
                    Some(persistence_error.unwrap_or(error)),
                )
            } else {
                (
                    VerifiedMaintenancePostcheck::failed(evidence, reason, terminal),
                    Some(error),
                )
            }
        }
        (NativeProbeResult::UncachedFailure(error), _) => {
            (VerifiedMaintenancePostcheck::unknown(), Some(error))
        }
        (NativeProbeResult::Cancelled(observation), persistence_error) => {
            let error = persistence_error.unwrap_or_else(|| {
                if matches!(
                    observation,
                    satelle_core::session::StopObservation::CancellationConfirmed
                        | satelle_core::session::StopObservation::UpstreamInactiveConfirmed
                ) {
                    SatelleError::interrupted_attached_command()
                } else {
                    readiness_probe_recovery_pending(ReadinessProbeKind::Native)
                }
            });
            (VerifiedMaintenancePostcheck::unknown(), Some(error))
        }
    }
}

fn readiness_probe_recovery_pending(kind: ReadinessProbeKind) -> SatelleError {
    let mut error = SatelleError::computer_use_not_ready();
    error.details.insert(
        "reason".to_string(),
        serde_json::Value::String(format!("{}_recovery_pending", kind.owner_kind())),
    );
    error
}

fn model_provider_binding_missing(provider_intent: &ProviderComputerUseIntent) -> SatelleError {
    let mut details = BTreeMap::new();
    if let Some(model) = provider_intent.model() {
        details.insert(
            "requested_model_alias".to_string(),
            serde_json::Value::String(model.as_str().to_string()),
        );
    }
    if let Some(provider) = provider_intent.provider() {
        details.insert(
            "requested_provider_alias".to_string(),
            serde_json::Value::String(provider.as_str().to_string()),
        );
    }
    SatelleError {
        code: ErrorCode::ModelProviderBindingMissing,
        message: "the requested model and provider aliases have no exact authorized Host binding"
            .to_string(),
        recovery_command: Some(
            "authorize the exact model/provider pair through SSH bootstrap setup".to_string(),
        ),
        source_detail: None,
        details,
    }
}

fn provider_secret_source_missing(auth_source: &str) -> SatelleError {
    SatelleError {
        code: ErrorCode::ProviderSecretResolutionFailed,
        message: "the Host provider binding references an unavailable Secret Source".to_string(),
        recovery_command: Some(
            "repair the referenced provider_auth descriptor on the selected Host".to_string(),
        ),
        source_detail: None,
        details: BTreeMap::from([(
            "auth_source".to_string(),
            serde_json::Value::String(auth_source.to_string()),
        )]),
    }
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
    storage: Arc<Mutex<Storage>>,
    operator_log: Mutex<OperatorLogMirror>,
    adapter: Arc<dyn ComputerUseAdapter>,
    provider_policy: RuntimeProviderPolicy,
    readiness_probe_driver: Option<Arc<dyn ReadinessProbeDriver>>,
    recovery: Mutex<RecoveryQueue>,
    restart_recovery_initialized: Mutex<bool>,
    workers: Mutex<WorkerRegistry>,
    live_events: LiveEventHub,
    process_identity: ProcessIdentity,
    attachment_store: crate::attachment::AttachmentStore,
}

#[derive(Clone, Default)]
pub(crate) struct RuntimeProviderPolicy {
    provider_bindings: BTreeMap<String, BTreeMap<String, satelle_core::ProviderBindingConfig>>,
    provider_auth: BTreeMap<String, satelle_core::ProviderSecretSource>,
    experimental_provider_computer_use: Option<bool>,
    experimental_provider_computer_use_by_provider: BTreeMap<String, bool>,
}

impl RuntimeProviderPolicy {
    pub(crate) fn from_host_config(config: &satelle_core::HostConfig) -> Self {
        Self {
            provider_bindings: config.provider_bindings.clone(),
            provider_auth: config.provider_auth.clone(),
            experimental_provider_computer_use: config.experimental_provider_computer_use,
            experimental_provider_computer_use_by_provider: config
                .experimental_provider_computer_use_by_provider
                .clone(),
        }
    }
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
        operator_log_root: PathBuf,
        adapter: Arc<dyn ComputerUseAdapter>,
        readiness_probe_driver: Option<Arc<dyn ReadinessProbeDriver>>,
        provider_policy: RuntimeProviderPolicy,
    ) -> Result<Arc<Self>, SatelleError> {
        let process_identity =
            ProcessIdentity::current().map_err(model::process_identity_failure)?;
        let storage =
            Storage::open_without_restart_recovery(state_root).map_err(model::storage_failure)?;
        let attachment_store =
            crate::attachment::AttachmentStore::open(state_root.join("attachments"))?;
        let mirrored_cursor = storage
            .latest_log_cursor()
            .map_err(model::storage_failure)?;
        let engine = Arc::new(Self {
            storage: Arc::new(Mutex::new(storage)),
            operator_log: Mutex::new(OperatorLogMirror::new(
                OperatorLogPolicy::new(operator_log_root),
                mirrored_cursor,
            )),
            adapter,
            provider_policy,
            readiness_probe_driver,
            recovery: Mutex::new(RecoveryQueue::new(Vec::new())),
            restart_recovery_initialized: Mutex::new(false),
            workers: Mutex::new(WorkerRegistry::default()),
            live_events: LiveEventHub::new(),
            process_identity,
            attachment_store,
        });
        Ok(engine)
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

    fn resolve_admission_operation(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
    ) -> Result<RuntimeAdmissionState, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        self.maintain_session_retention(requested_at)?;
        let idempotency = model::idempotency(operation, identity, requested_at)?;
        let state = self
            .lock_storage()?
            .resolve_admission_operation(operation, &idempotency, expected_session_id, requested_at)
            .map_err(model::storage_failure)?;
        self.runtime_admission_state(state)
    }

    fn record_admission_cancellation(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
        outcome: crate::storage::DurableCancellationOutcome,
        reconciled: bool,
    ) -> Result<RuntimeAdmissionState, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        self.maintain_session_retention(requested_at)?;
        let idempotency = model::idempotency(operation, identity, requested_at)?;
        let mut storage = self.lock_storage()?;
        let state = if reconciled {
            storage.reconcile_admission_cancellation(
                operation,
                &idempotency,
                expected_session_id,
                outcome,
                requested_at,
            )
        } else {
            storage.record_admission_cancellation(
                operation,
                &idempotency,
                expected_session_id,
                outcome,
                requested_at,
            )
        }
        .map_err(model::storage_failure)?;
        self.runtime_admission_state(state)
    }

    fn runtime_admission_state(
        &self,
        state: crate::storage::DurableAdmissionState,
    ) -> Result<RuntimeAdmissionState, SatelleError> {
        match state {
            crate::storage::DurableAdmissionState::Missing => Ok(RuntimeAdmissionState::Missing),
            crate::storage::DurableAdmissionState::Cancelled => {
                Ok(RuntimeAdmissionState::Cancelled)
            }
            crate::storage::DurableAdmissionState::RecoveryPending => {
                Ok(RuntimeAdmissionState::RecoveryPending)
            }
            crate::storage::DurableAdmissionState::Admitted(replay) => {
                let (outcome, _session_id, turn_id) = (*replay).into_parts();
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
                Ok(RuntimeAdmissionState::Admitted(RuntimeAdmissionReplay {
                    outcome,
                    turn_id,
                }))
            }
        }
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
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let started_at = time::OffsetDateTime::now_utc();
        let host_identity = self.host_identity()?;
        let execution_policy = readiness
            .execution_policy()
            .for_turn(command.execution_mode, command.turn_execution_timeout);
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
        let attachments = self.attachment_store.stage(command.attachments)?;
        let (outcome, provider_smoke_event) =
            command
                .cancellation
                .with_commit_gate(session_id.clone(), turn_id.clone(), || {
                    let mut storage = self.lock_storage()?;
                    let outcome = storage
                        .begin_session(&initial, &context)
                        .map_err(model::storage_failure)?;
                    let mut provider_smoke_event = None;
                    if let AdmissionOutcome::Execute { session, .. } = &outcome {
                        self.publish_native_readiness(&readiness, session, &turn_id);
                        self.publish_committed_turn(session, &turn_id);
                        provider_smoke_event =
                            self.publish_provider_smoke(&readiness, session, &turn_id);
                    }
                    Ok((outcome, provider_smoke_event))
                })?;
        self.finish_admission(
            AdmissionExecution {
                host: command.host,
                prompt: command.prompt,
                execution_mode: command.execution_mode,
                dispatch_preference: command.dispatch,
                provider_smoke_event,
                resolved_provider_binding: readiness.resolved_provider_binding().cloned(),
                attachments,
            },
            outcome,
            context.lease_owner().clone(),
        )
    }

    fn steer(
        self: &Arc<Self>,
        command: SteerCommand<'_>,
        readiness: AdapterReadiness,
    ) -> Result<RuntimeTurnOutcome, SatelleError> {
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
            .for_turn(command.execution_mode, command.turn_execution_timeout);
        let context = model::admission(
            IdempotentOperation::Steer,
            started_at,
            &command.identity,
            &self.process_identity,
        )?;
        let attachments = self.attachment_store.stage(command.attachments)?;
        let (outcome, provider_smoke_event) = command.cancellation.with_commit_gate(
            command.session_id.clone(),
            turn_id.clone(),
            || {
                let mut storage = self.lock_storage()?;
                let outcome = storage
                    .begin_follow_up(
                        &command.session_id,
                        existing.session_state_revision(),
                        turn_id.clone(),
                        execution_policy,
                        started_at,
                        self.adapter.requires_upstream_thread_for_follow_up(),
                        &context,
                    )
                    .map_err(model::storage_failure)?;
                let mut provider_smoke_event = None;
                if let AdmissionOutcome::Execute { session, .. } = &outcome {
                    self.publish_native_readiness(&readiness, session, &turn_id);
                    self.publish_committed_turn(session, &turn_id);
                    provider_smoke_event =
                        self.publish_provider_smoke(&readiness, session, &turn_id);
                }
                Ok((outcome, provider_smoke_event))
            },
        )?;
        self.finish_admission(
            AdmissionExecution {
                host: LOCAL_DEMO_HOST,
                prompt: command.prompt,
                execution_mode: command.execution_mode,
                dispatch_preference: command.dispatch,
                provider_smoke_event,
                resolved_provider_binding: readiness.resolved_provider_binding().cloned(),
                attachments,
            },
            outcome,
            context.lease_owner().clone(),
        )
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
        cancellation: &AdmissionCancellation,
    ) -> Result<AdapterReadiness, SatelleError> {
        if cancellation.is_requested() {
            cancellation.finish(AdmissionCancellationState::Cancelled);
            return Err(SatelleError::interrupted_attached_command());
        }
        let provider_intent = self.authorize_provider_intent(provider_intent)?;
        let cache_key = self.adapter.readiness_cache_key(host, &provider_intent)?;
        let provider_smoke_enabled = cache_key.as_ref().is_some_and(|key| {
            key.execution_policy()
                .experimental_features()
                .provider_computer_use()
                == satelle_core::session::FeatureChoice::Enabled
        });
        if let (Some(key), Some(driver)) =
            (cache_key.as_ref(), self.readiness_probe_driver.as_ref())
        {
            self.reconcile_readiness_probe(key, driver.as_ref(), ReadinessProbeKind::Native)?;
            self.reconcile_readiness_probe(key, driver.as_ref(), ReadinessProbeKind::Provider)?;
        }
        let (mut cached, cached_provider) = if let Some(key) = cache_key.as_ref() {
            let now = time::OffsetDateTime::now_utc();
            let storage = self.lock_storage()?;
            let readiness = storage
                .load_reusable_readiness(key, now)
                .map_err(model::storage_failure)?;
            let provider = if provider_smoke_enabled && !provider_intent.refresh() {
                storage
                    .load_reusable_provider_smoke(key, now)
                    .map_err(model::storage_failure)?
            } else {
                None
            };
            (readiness, provider)
        } else {
            (None, None)
        };
        if cached.is_none()
            && let (Some(key), Some(driver)) =
                (cache_key.as_ref(), self.readiness_probe_driver.as_ref())
        {
            cached = Some(self.run_live_native_probe(key, driver.as_ref(), cancellation)?);
        }
        let requires_live_provider_probe =
            provider_smoke_enabled && (provider_intent.refresh() || cached_provider.is_none());
        let (provider_probe_ref, _provider_heartbeat) = if requires_live_provider_probe
            && self.readiness_probe_driver.is_some()
            && let Some(key) = cache_key.as_ref()
        {
            let provider_probe_ref = format!("provider-probe-{}", SessionId::new());
            let now = time::OffsetDateTime::now_utc();
            let owner = LeaseOwner::new(
                provider_probe_ref.clone(),
                self.process_identity.process_id(),
                self.process_identity.process_start_ref(),
                self.process_identity.boot_identity_ref(),
                now,
            )
            .map_err(model::storage_failure)?;
            self.lock_storage()?
                .begin_provider_probe(key, &provider_probe_ref, &owner)
                .map_err(model::storage_failure)?;
            let heartbeat = match LeaseHeartbeatGuard::start(Arc::clone(&self.storage), &owner) {
                Ok(heartbeat) => heartbeat,
                Err(error) => {
                    self.lock_storage()?
                        .retain_provider_probe_recovery(&provider_probe_ref)
                        .map_err(model::storage_failure)?;
                    cancellation.finish(AdmissionCancellationState::RecoveryPending);
                    return Err(heartbeat_start_failure(error));
                }
            };
            (Some(provider_probe_ref), Some(heartbeat))
        } else {
            (None, None)
        };

        let persistence_error = std::cell::RefCell::new(None);
        let preflight = {
            let mut persist_thread_ref = |value: &str| {
                self.lock_storage()
                    .and_then(|mut storage| {
                        storage
                            .persist_provider_probe_upstream_ref(
                                provider_probe_ref.as_deref().unwrap_or_default(),
                                ObservedUpstreamRef::thread(value)
                                    .map_err(model::storage_failure)?,
                            )
                            .map_err(model::storage_failure)
                    })
                    .map_err(|error| {
                        *persistence_error.borrow_mut() = Some(error);
                    })
            };
            let mut persist_turn_ref = |value: &str| {
                self.lock_storage()
                    .and_then(|mut storage| {
                        storage
                            .persist_provider_probe_upstream_ref(
                                provider_probe_ref.as_deref().unwrap_or_default(),
                                ObservedUpstreamRef::turn(value).map_err(model::storage_failure)?,
                            )
                            .map_err(model::storage_failure)
                    })
                    .map_err(|error| {
                        *persistence_error.borrow_mut() = Some(error);
                    })
            };
            match self.readiness_probe_driver.as_ref() {
                Some(driver) if provider_probe_ref.is_some() => driver
                    .preflight_terminal_with_provider_probe(
                        host,
                        cached,
                        cached_provider,
                        &provider_intent,
                        cancellation,
                        &mut persist_thread_ref,
                        &mut persist_turn_ref,
                    ),
                _ => {
                    self.adapter
                        .preflight_terminal(host, cached, cached_provider, &provider_intent)
                }
            }
        };
        let persistence_failed = persistence_error.into_inner().is_some();

        match preflight {
            AdapterPreflight::Cancelled(observation) => {
                let terminal = matches!(
                    observation,
                    satelle_core::session::StopObservation::CancellationConfirmed
                        | satelle_core::session::StopObservation::UpstreamInactiveConfirmed
                );
                if let Some(provider_probe_ref) = provider_probe_ref.as_deref() {
                    if terminal {
                        self.lock_storage()?
                            .release_provider_probe(provider_probe_ref)
                            .map_err(model::storage_failure)?;
                    } else {
                        self.lock_storage()?
                            .retain_provider_probe_recovery(provider_probe_ref)
                            .map_err(model::storage_failure)?;
                    }
                }
                cancellation.finish(if terminal {
                    AdmissionCancellationState::Cancelled
                } else {
                    AdmissionCancellationState::RecoveryPending
                });
                Err(adapter::admission_cancelled_error(observation))
            }
            AdapterPreflight::Ready(readiness) => {
                self.lock_storage()?
                    .store_preflight_successes(
                        readiness.adapter(),
                        readiness.desktop_binding(),
                        readiness.execution_policy(),
                        readiness.evidence(),
                        readiness.provider_smoke_evidence(),
                    )
                    .map_err(model::storage_failure)?;
                if let Some(provider_probe_ref) = provider_probe_ref.as_deref() {
                    self.lock_storage()?
                        .release_provider_probe(provider_probe_ref)
                        .map_err(model::storage_failure)?;
                }
                Ok(readiness)
            }
            AdapterPreflight::Failed {
                key,
                evidence,
                reason,
                error,
                dispatch_possible,
            } => {
                self.lock_storage()?
                    .store_preflight_failure(&key, &evidence, reason)
                    .map_err(model::storage_failure)?;
                if let Some(provider_probe_ref) = provider_probe_ref.as_deref() {
                    if dispatch_possible || persistence_failed {
                        self.lock_storage()?
                            .retain_provider_probe_recovery(provider_probe_ref)
                            .map_err(model::storage_failure)?;
                    } else {
                        self.lock_storage()?
                            .release_provider_probe(provider_probe_ref)
                            .map_err(model::storage_failure)?;
                    }
                }
                if dispatch_possible || persistence_failed {
                    cancellation.finish(AdmissionCancellationState::RecoveryPending);
                } else if cancellation.is_requested() {
                    cancellation.finish(AdmissionCancellationState::Cancelled);
                }
                Err(error)
            }
            AdapterPreflight::ProviderFailed {
                key,
                readiness,
                failure,
                error,
            } => {
                let terminal = readiness_probe_terminal_with_dispatch(
                    &error,
                    persistence_failed,
                    "provider_smoke_cancellation",
                    Some(ErrorCode::ProviderSmokeTestTimeout),
                    probe_dispatch_possible(&error),
                );
                if let Some(provider_probe_ref) = provider_probe_ref.as_deref() {
                    self.lock_storage()?
                        .finish_provider_probe_failure(
                            provider_probe_ref,
                            &key,
                            &readiness,
                            &failure,
                            terminal,
                        )
                        .map_err(model::storage_failure)?;
                } else {
                    self.lock_storage()?
                        .store_provider_smoke_failure(&key, &readiness, &failure)
                        .map_err(model::storage_failure)?;
                }
                if terminal == ReadinessProbeTerminal::OutcomeUnknown {
                    cancellation.finish(AdmissionCancellationState::RecoveryPending);
                } else if cancellation.is_requested() {
                    cancellation.finish(AdmissionCancellationState::Cancelled);
                }
                Err(error)
            }
            AdapterPreflight::UncachedFailure(error) => {
                let recovery_pending = probe_dispatch_possible(&error) || persistence_failed;
                if let Some(provider_probe_ref) = provider_probe_ref.as_deref() {
                    if recovery_pending {
                        self.lock_storage()?
                            .retain_provider_probe_recovery(provider_probe_ref)
                            .map_err(model::storage_failure)?;
                    } else {
                        self.lock_storage()?
                            .release_provider_probe(provider_probe_ref)
                            .map_err(model::storage_failure)?;
                    }
                }
                if recovery_pending {
                    cancellation.finish(AdmissionCancellationState::RecoveryPending);
                } else if cancellation.is_requested() {
                    cancellation.finish(AdmissionCancellationState::Cancelled);
                }
                Err(error)
            }
        }
    }

    fn cached_provider_smoke(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ProviderSmokeResult>, SatelleError> {
        let provider_intent = self.authorize_provider_intent(provider_intent)?;
        let Some(key) = self.adapter.readiness_cache_key(host, &provider_intent)? else {
            return Ok(None);
        };
        self.lock_storage()?
            .load_reusable_provider_smoke(&key, time::OffsetDateTime::now_utc())
            .map_err(model::storage_failure)
    }

    fn authorize_provider_intent(
        &self,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<ProviderComputerUseIntent, SatelleError> {
        let requested_pair = match (provider_intent.model(), provider_intent.provider()) {
            (None, None) => return Ok(provider_intent.clone()),
            (Some(model), Some(provider)) => (model.as_str(), provider.as_str()),
            _ => return Err(model_provider_binding_missing(provider_intent)),
        };
        let binding = match self.resolve_remote_host_binding(requested_pair.0, requested_pair.1)? {
            Some(binding) => binding,
            None => self
                .lock_storage()?
                .load_authorized_provider_binding(requested_pair.0, requested_pair.1)
                .map_err(model::storage_failure)?
                .ok_or_else(|| model_provider_binding_missing(provider_intent))?,
        };
        Ok(provider_intent
            .clone()
            .with_resolved_provider_binding(binding))
    }

    fn resolve_remote_host_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<Option<ResolvedProviderBinding>, SatelleError> {
        let Some(binding) = self
            .provider_policy
            .provider_bindings
            .get(provider_alias)
            .and_then(|models| models.get(model_alias))
        else {
            return Ok(None);
        };
        let mut authorization = ProviderBindingAuthorization::new(
            model_alias,
            provider_alias,
            &binding.model,
            &binding.model_provider,
        );
        if let Some(endpoint) = binding.endpoint.as_deref() {
            authorization = authorization.with_endpoint(endpoint);
        }
        if let Some(auth_source_name) = binding.auth_source.as_deref() {
            let descriptor = self
                .provider_policy
                .provider_auth
                .get(auth_source_name)
                .cloned()
                .ok_or_else(|| provider_secret_source_missing(auth_source_name))?;
            authorization = authorization.with_auth_source(descriptor);
        }
        let experimental = self
            .provider_policy
            .experimental_provider_computer_use_by_provider
            .get(provider_alias)
            .copied()
            .or(self.provider_policy.experimental_provider_computer_use)
            .unwrap_or(false);
        authorization = authorization.with_experimental_provider_computer_use(experimental);
        crate::validate_provider_binding_authorization(&authorization)?;
        Ok(Some(ResolvedProviderBinding::from_authorization(
            authorization,
            ProviderBindingSource::HostOwned,
        )))
    }

    fn resolve_provider_binding(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<ResolvedProviderBinding, SatelleError> {
        let provider_intent = self.authorize_provider_intent(provider_intent)?;
        if let Some(binding) = provider_intent.resolved_provider_binding() {
            return Ok(binding.clone());
        }
        self.adapter
            .resolve_provider_binding(host, &provider_intent)
    }

    pub(crate) fn authorize_provider_binding(
        &self,
        binding: &ResolvedProviderBinding,
    ) -> Result<(), SatelleError> {
        self.lock_storage()?
            .authorize_provider_binding(binding, time::OffsetDateTime::now_utc())
            .map_err(model::storage_failure)
    }

    pub(crate) fn delete_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, SatelleError> {
        self.lock_storage()?
            .delete_authorized_provider_binding(model_alias, provider_alias)
            .map_err(model::storage_failure)
    }

    fn run_live_native_probe(
        &self,
        key: &ReadinessCacheKey,
        driver: &dyn ReadinessProbeDriver,
        cancellation: &AdmissionCancellation,
    ) -> Result<ReadinessEvidence, SatelleError> {
        let native_probe_ref = format!("native-probe-{}", SessionId::new());
        let now = time::OffsetDateTime::now_utc();
        let owner = LeaseOwner::new(
            native_probe_ref.clone(),
            self.process_identity.process_id(),
            self.process_identity.process_start_ref(),
            self.process_identity.boot_identity_ref(),
            now,
        )
        .map_err(model::storage_failure)?;
        self.lock_storage()?
            .begin_native_probe(key, &native_probe_ref, &owner)
            .map_err(model::storage_failure)?;
        let _heartbeat = match LeaseHeartbeatGuard::start(Arc::clone(&self.storage), &owner) {
            Ok(heartbeat) => heartbeat,
            Err(error) => {
                self.lock_storage()?
                    .retain_native_probe_recovery(&native_probe_ref)
                    .map_err(model::storage_failure)?;
                cancellation.finish(AdmissionCancellationState::RecoveryPending);
                return Err(heartbeat_start_failure(error));
            }
        };

        let persistence_error = std::cell::RefCell::new(None);
        let probe = {
            let mut persist_thread_ref = |value: &str| {
                self.lock_storage()
                    .and_then(|mut storage| {
                        storage
                            .persist_native_probe_upstream_ref(
                                &native_probe_ref,
                                ObservedUpstreamRef::thread(value)
                                    .map_err(model::storage_failure)?,
                            )
                            .map_err(model::storage_failure)
                    })
                    .map_err(|error| {
                        *persistence_error.borrow_mut() = Some(error);
                    })
            };
            let mut persist_turn_ref = |value: &str| {
                self.lock_storage()
                    .and_then(|mut storage| {
                        storage
                            .persist_native_probe_upstream_ref(
                                &native_probe_ref,
                                ObservedUpstreamRef::turn(value).map_err(model::storage_failure)?,
                            )
                            .map_err(model::storage_failure)
                    })
                    .map_err(|error| {
                        *persistence_error.borrow_mut() = Some(error);
                    })
            };
            driver.run_native_probe(
                key,
                cancellation,
                &mut persist_thread_ref,
                &mut persist_turn_ref,
            )
        };
        let persistence_failed = persistence_error.into_inner().is_some();

        match probe {
            NativeProbeResult::Cancelled(observation) => {
                let terminal = matches!(
                    observation,
                    satelle_core::session::StopObservation::CancellationConfirmed
                        | satelle_core::session::StopObservation::UpstreamInactiveConfirmed
                );
                if terminal {
                    self.lock_storage()?
                        .release_native_probe(&native_probe_ref)
                        .map_err(model::storage_failure)?;
                } else {
                    self.lock_storage()?
                        .retain_native_probe_recovery(&native_probe_ref)
                        .map_err(model::storage_failure)?;
                }
                cancellation.finish(if terminal {
                    AdmissionCancellationState::Cancelled
                } else {
                    AdmissionCancellationState::RecoveryPending
                });
                Err(adapter::admission_cancelled_error(observation))
            }
            NativeProbeResult::Passed(evidence) if !persistence_failed => {
                self.lock_storage()?
                    .finish_native_probe_success(&native_probe_ref, key, &evidence)
                    .map_err(model::storage_failure)?;
                Ok(evidence)
            }
            NativeProbeResult::Passed(_) => {
                self.lock_storage()?
                    .retain_native_probe_recovery(&native_probe_ref)
                    .map_err(model::storage_failure)?;
                cancellation.finish(AdmissionCancellationState::RecoveryPending);
                Err(readiness_probe_recovery_pending(ReadinessProbeKind::Native))
            }
            NativeProbeResult::Failed {
                evidence,
                reason,
                error,
                dispatch_possible,
            } => {
                let terminal = readiness_probe_terminal_with_dispatch(
                    &error,
                    persistence_failed,
                    "native_readiness_cancellation",
                    Some(ErrorCode::NativeReadinessTimeout),
                    dispatch_possible,
                );
                self.lock_storage()?
                    .finish_native_probe_failure(
                        &native_probe_ref,
                        key,
                        &evidence,
                        reason,
                        terminal,
                    )
                    .map_err(model::storage_failure)?;
                if terminal == ReadinessProbeTerminal::OutcomeUnknown {
                    cancellation.finish(AdmissionCancellationState::RecoveryPending);
                } else if cancellation.is_requested() {
                    cancellation.finish(AdmissionCancellationState::Cancelled);
                }
                Err(error)
            }
            NativeProbeResult::UncachedFailure(error) => {
                self.lock_storage()?
                    .release_native_probe(&native_probe_ref)
                    .map_err(model::storage_failure)?;
                if cancellation.is_requested() {
                    cancellation.finish(AdmissionCancellationState::Cancelled);
                }
                Err(error)
            }
        }
    }

    fn reconcile_readiness_probe(
        &self,
        key: &ReadinessCacheKey,
        driver: &dyn ReadinessProbeDriver,
        kind: ReadinessProbeKind,
    ) -> Result<(), SatelleError> {
        let subject = {
            let storage = self.lock_storage()?;
            let host_identity = storage.host_identity().map_err(model::storage_failure)?;
            match kind {
                ReadinessProbeKind::Native => storage
                    .pending_native_probe(&host_identity, key.desktop_binding())
                    .map_err(model::storage_failure)?,
                ReadinessProbeKind::Provider => storage
                    .pending_provider_probe(&host_identity, key.desktop_binding())
                    .map_err(model::storage_failure)?,
            }
        };
        let Some(subject) = subject else {
            return Ok(());
        };
        debug_assert_eq!(kind, subject.probe_kind());
        if !subject.is_recovery_pending() {
            return Err(readiness_probe_recovery_pending(kind));
        }
        match driver.observe_readiness_probe(&subject) {
            RecoveryObservation::Completed
            | RecoveryObservation::Blocked
            | RecoveryObservation::Failed => {
                let mut storage = self.lock_storage()?;
                match kind {
                    ReadinessProbeKind::Native => storage
                        .release_reconciled_native_probe(subject.probe_ref())
                        .map_err(model::storage_failure),
                    ReadinessProbeKind::Provider => storage
                        .release_reconciled_provider_probe(subject.probe_ref())
                        .map_err(model::storage_failure),
                }
            }
            RecoveryObservation::Running | RecoveryObservation::Unknown => {
                Err(readiness_probe_recovery_pending(kind))
            }
        }
    }

    fn has_reusable_readiness(&self, host: &str) -> Result<bool, SatelleError> {
        let intent = ProviderComputerUseIntent::host_default();
        let key = match self.adapter.readiness_cache_key(host, &intent) {
            Ok(Some(key)) => key,
            Ok(None) => return Ok(false),
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::ComputerUseNotReady | ErrorCode::IncompatibleControlPlane
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        self.lock_storage()?
            .load_reusable_readiness(&key, time::OffsetDateTime::now_utc())
            .map(|result| result.is_some())
            .map_err(model::storage_failure)
    }

    fn finish_admission(
        self: &Arc<Self>,
        execution: AdmissionExecution<'_>,
        outcome: AdmissionOutcome,
        lease_owner: LeaseOwner,
    ) -> Result<RuntimeTurnOutcome, SatelleError> {
        match outcome {
            AdmissionOutcome::InProgress(session) | AdmissionOutcome::Complete(session) => {
                Ok(model::turn_outcome(&session, Vec::new()))
            }
            AdmissionOutcome::Execute {
                session,
                recovery_subject,
            } => {
                let heartbeat =
                    match LeaseHeartbeatGuard::start(Arc::clone(&self.storage), &lease_owner) {
                        Ok(heartbeat) => heartbeat,
                        Err(error) => {
                            self.preserve_unknown_execution(&recovery_subject)?;
                            return Err(heartbeat_start_failure(error));
                        }
                    };
                let work = TurnWork {
                    session,
                    subject: recovery_subject,
                    _heartbeat: heartbeat,
                };
                let admitted = model::turn_outcome(&work.session, Vec::new());
                let plan = ExecutionPlan {
                    host: execution.host.to_string(),
                    prompt: execution.prompt.to_string(),
                    execution_mode: execution.execution_mode,
                    work,
                    provider_smoke_event: execution.provider_smoke_event,
                    resolved_provider_binding: execution.resolved_provider_binding,
                    attachments: execution.attachments,
                };
                match execution.dispatch_preference {
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

    fn lock_storage(&self) -> Result<RuntimeStorageGuard<'_>, SatelleError> {
        self.storage
            .lock()
            .map(|storage| RuntimeStorageGuard {
                storage,
                operator_log: &self.operator_log,
            })
            .map_err(|_| {
                model::integrity_failure(
                    "the runtime storage lock was poisoned by a failed operation",
                )
            })
    }
}

struct RuntimeStorageGuard<'a> {
    storage: MutexGuard<'a, Storage>,
    operator_log: &'a Mutex<OperatorLogMirror>,
}

impl Deref for RuntimeStorageGuard<'_> {
    type Target = Storage;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

impl DerefMut for RuntimeStorageGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.storage
    }
}

impl Drop for RuntimeStorageGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut operator_log) = self.operator_log.lock() {
            operator_log.flush_committed(&self.storage);
        }
    }
}

struct LazyRuntime {
    state_root: Result<PathBuf, SatelleError>,
    operator_log_root: Result<PathBuf, SatelleError>,
    engine: Option<Arc<RuntimeEngine>>,
    provider_policy: RuntimeProviderPolicy,
}

#[derive(Clone)]
pub(crate) struct RuntimeHandle {
    adapter: Arc<dyn ComputerUseAdapter>,
    readiness_probe_driver: Option<Arc<dyn ReadinessProbeDriver>>,
    activity: Arc<DaemonActivity>,
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
    pub(crate) fn begin_setup_run(
        &self,
        plan: &SetupRunPlan,
    ) -> Result<MaintenanceOperationHandle, SatelleError> {
        self.begin_maintenance_operation(plan, Storage::begin_setup_run)
    }

    pub(crate) fn begin_bootstrap_maintenance(
        &self,
        plan: &SetupRunPlan,
    ) -> Result<MaintenanceOperationHandle, SatelleError> {
        self.begin_maintenance_operation(plan, Storage::begin_bootstrap_maintenance)
    }

    fn begin_maintenance_operation(
        &self,
        plan: &SetupRunPlan,
        begin: impl FnOnce(
            &mut Storage,
            &SetupRunPlan,
            LeaseOwner,
        ) -> Result<
            crate::storage::MaintenanceLeaseCapability,
            crate::storage::StorageError,
        >,
    ) -> Result<MaintenanceOperationHandle, SatelleError> {
        let activity = self.activity.begin();
        let engine = self.engine()?;
        let capability = {
            let mut storage = engine.lock_storage()?;
            let acquired_at = time::OffsetDateTime::now_utc();
            let owner = LeaseOwner::new(
                plan.run_id(),
                engine.process_identity.process_id(),
                engine.process_identity.process_start_ref(),
                engine.process_identity.boot_identity_ref(),
                acquired_at,
            )
            .map_err(model::storage_failure)?;
            begin(&mut storage, plan, owner).map_err(model::storage_failure)?
        };
        let operation = start_maintenance_operation_guard(&engine, capability)?;
        Ok(MaintenanceOperationHandle {
            operation_id: plan.run_id().to_string(),
            operation: Some(operation),
            activity: Some(activity),
        })
    }

    pub(crate) fn adopt_recovery_maintenance(
        &self,
        operation_id: &str,
    ) -> Result<MaintenanceOperationHandle, SatelleError> {
        let activity = self.activity.begin();
        let engine = self.engine()?;
        let capability = {
            let mut storage = engine.lock_storage()?;
            let acquired_at = time::OffsetDateTime::now_utc();
            let owner = LeaseOwner::new(
                operation_id,
                engine.process_identity.process_id(),
                engine.process_identity.process_start_ref(),
                engine.process_identity.boot_identity_ref(),
                acquired_at,
            )
            .map_err(model::storage_failure)?;
            storage
                .adopt_recovery_maintenance(operation_id, owner)
                .map_err(model::storage_failure)?
        };
        let operation = start_maintenance_operation_guard(&engine, capability)?;
        Ok(MaintenanceOperationHandle {
            operation_id: operation_id.to_string(),
            operation: Some(operation),
            activity: Some(activity),
        })
    }

    pub(crate) fn start_setup_action(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        started_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.with_maintenance_operation(operation, |storage, capability| {
            storage.start_setup_action(capability, action_id, started_at)
        })
    }

    pub(crate) fn complete_setup_action_after_verified_postcondition(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        completed_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.with_maintenance_operation(operation, |storage, capability| {
            storage.complete_setup_action_after_verified_postcondition(
                capability,
                action_id,
                completed_at,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn fail_setup_action(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        error_code: &str,
        exit_status: Option<i64>,
        recovery_hint: Option<&str>,
        failed_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.with_maintenance_operation(operation, |storage, capability| {
            storage.fail_setup_action(
                capability,
                action_id,
                error_code,
                exit_status,
                recovery_hint,
                failed_at,
            )
        })
    }

    pub(crate) fn skip_setup_action(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        reason: SetupActionSkipReason,
        skipped_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.with_maintenance_operation(operation, |storage, capability| {
            storage.skip_setup_action(capability, action_id, reason, skipped_at)
        })
    }

    pub(crate) fn run_maintenance_postcheck(
        &self,
        operation: &mut MaintenanceOperationHandle,
        key: &ReadinessCacheKey,
        postcheck_action_id: &str,
    ) -> Result<SetupRunStatus, SatelleError> {
        let driver = self.readiness_probe_driver.as_ref().ok_or_else(|| {
            model::integrity_failure("the maintenance postcheck observer is unavailable")
        })?;
        let native_probe_ref = format!("maintenance-postcheck-{}", SessionId::new());
        self.with_maintenance_operation(operation, |storage, capability| {
            storage.begin_maintenance_postcheck(
                key,
                &native_probe_ref,
                postcheck_action_id,
                capability,
            )
        })?;

        let persistence_error = std::cell::RefCell::new(None);
        let observation = {
            let mut persist_thread_ref = |value: &str| {
                self.engine()
                    .and_then(|engine| {
                        let mut storage = engine.lock_storage()?;
                        storage
                            .persist_native_probe_upstream_ref(
                                &native_probe_ref,
                                ObservedUpstreamRef::thread(value)
                                    .map_err(model::storage_failure)?,
                            )
                            .map_err(model::storage_failure)
                    })
                    .map_err(|error| {
                        *persistence_error.borrow_mut() = Some(error);
                    })
            };
            let mut persist_turn_ref = |value: &str| {
                self.engine()
                    .and_then(|engine| {
                        let mut storage = engine.lock_storage()?;
                        storage
                            .persist_native_probe_upstream_ref(
                                &native_probe_ref,
                                ObservedUpstreamRef::turn(value).map_err(model::storage_failure)?,
                            )
                            .map_err(model::storage_failure)
                    })
                    .map_err(|error| {
                        *persistence_error.borrow_mut() = Some(error);
                    })
            };
            driver.run_native_probe(
                key,
                &AdmissionCancellation::new(),
                &mut persist_thread_ref,
                &mut persist_turn_ref,
            )
        };
        let persistence_error = persistence_error.into_inner();
        let (verified, terminal_error) =
            verify_maintenance_postcheck(observation, persistence_error);
        let engine = self.engine()?;
        let guard = operation.operation().map_err(model::storage_failure)?;
        let status = engine
            .lock_storage()?
            .finish_maintenance_postcheck(
                guard.capability(),
                &native_probe_ref,
                postcheck_action_id,
                key,
                &verified,
            )
            .map_err(model::storage_failure)?;
        operation.disarm();
        if let Some(error) = terminal_error {
            return Err(error);
        }
        status.ok_or_else(|| {
            model::integrity_failure("a passed maintenance postcheck was not terminal")
        })
    }

    pub(crate) fn finish_setup_run(
        &self,
        operation: &mut MaintenanceOperationHandle,
        finished_at: time::OffsetDateTime,
    ) -> Result<SetupRunStatus, SatelleError> {
        let engine = self.engine()?;
        let guard = operation.operation().map_err(model::storage_failure)?;
        let status = engine
            .lock_storage()?
            .finish_setup_run_and_release_maintenance(guard.capability(), finished_at)
            .map_err(model::storage_failure)?;
        operation.disarm();
        Ok(status)
    }

    pub(crate) fn complete_bootstrap_maintenance(
        &self,
        operation: &mut MaintenanceOperationHandle,
        finished_at: time::OffsetDateTime,
    ) -> Result<SetupRunStatus, SatelleError> {
        let engine = self.engine()?;
        let guard = operation.operation().map_err(model::storage_failure)?;
        let status = engine
            .lock_storage()?
            .complete_bootstrap_maintenance(guard.capability(), finished_at)
            .map_err(model::storage_failure)?;
        operation.disarm();
        Ok(status)
    }

    fn with_maintenance_operation<T>(
        &self,
        operation: &MaintenanceOperationHandle,
        mutate: impl FnOnce(
            &mut Storage,
            &crate::storage::MaintenanceLeaseCapability,
        ) -> Result<T, crate::storage::StorageError>,
    ) -> Result<T, SatelleError> {
        let engine = self.engine()?;
        let operation = operation.operation().map_err(model::storage_failure)?;
        let mut storage = engine.lock_storage()?;
        mutate(&mut storage, operation.capability()).map_err(model::storage_failure)
    }

    pub(crate) fn load_setup_run(
        &self,
        run_id: &str,
    ) -> Result<Option<SetupRunRecord>, SatelleError> {
        self.engine()?
            .lock_storage()?
            .load_setup_run(run_id)
            .map_err(model::storage_failure)
    }

    pub(crate) fn plan_setup_repair(
        &self,
        desktop_binding: Option<&DesktopBindingRef>,
        probes: &[SetupRepairProbe],
    ) -> Result<SetupRepairPlan, SatelleError> {
        self.engine()?
            .lock_storage()?
            .plan_setup_repair(desktop_binding, probes)
            .map_err(model::storage_failure)
    }

    pub(crate) fn reconcile_setup_maintenance(
        &self,
        observer: &mut dyn crate::SetupPostconditionObserver,
    ) -> Result<Option<SetupRunStatus>, SatelleError> {
        self.engine()?.reconcile_maintenance(observer)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new<A: ComputerUseAdapter>(
        state_root: Result<PathBuf, SatelleError>,
        adapter: A,
    ) -> Self {
        let operator_log_root = state_root
            .as_ref()
            .map(|root| root.join("logs"))
            .map_err(Clone::clone);
        Self {
            adapter: Arc::new(adapter),
            readiness_probe_driver: None,
            activity: Arc::new(DaemonActivity::default()),
            lazy: Arc::new(Mutex::new(LazyRuntime {
                state_root,
                operator_log_root,
                engine: None,
                provider_policy: RuntimeProviderPolicy::default(),
            })),
        }
    }

    pub(crate) fn new_production(
        state_root: Result<PathBuf, SatelleError>,
        operator_log_root: Result<PathBuf, SatelleError>,
        adapter: ProductionComputerUseAdapter,
        provider_policy: RuntimeProviderPolicy,
    ) -> Self {
        let adapter = Arc::new(adapter);
        let computer_use_adapter: Arc<dyn ComputerUseAdapter> = adapter.clone();
        let readiness_probe_driver: Arc<dyn ReadinessProbeDriver> = adapter;
        Self {
            adapter: computer_use_adapter,
            readiness_probe_driver: Some(readiness_probe_driver),
            activity: Arc::new(DaemonActivity::default()),
            lazy: Arc::new(Mutex::new(LazyRuntime {
                state_root,
                operator_log_root,
                engine: None,
                provider_policy,
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_readiness_probe_driver<A, D>(
        state_root: Result<PathBuf, SatelleError>,
        adapter: A,
        readiness_probe_driver: D,
    ) -> Self
    where
        A: ComputerUseAdapter,
        D: ReadinessProbeDriver,
    {
        let operator_log_root = state_root
            .as_ref()
            .map(|root| root.join("logs"))
            .map_err(Clone::clone);
        Self {
            adapter: Arc::new(adapter),
            readiness_probe_driver: Some(Arc::new(readiness_probe_driver)),
            activity: Arc::new(DaemonActivity::default()),
            lazy: Arc::new(Mutex::new(LazyRuntime {
                state_root,
                operator_log_root,
                engine: None,
                provider_policy: RuntimeProviderPolicy::default(),
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

    pub(crate) fn resolve_admission_operation(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
    ) -> Result<RuntimeAdmissionState, SatelleError> {
        self.engine()?
            .resolve_admission_operation(operation, identity, expected_session_id)
    }

    pub(crate) fn record_admission_cancellation(
        &self,
        operation: IdempotentOperation,
        identity: &RequestIdentity,
        expected_session_id: Option<&SessionId>,
        outcome: crate::storage::DurableCancellationOutcome,
        reconciled: bool,
    ) -> Result<RuntimeAdmissionState, SatelleError> {
        self.engine()?.record_admission_cancellation(
            operation,
            identity,
            expected_session_id,
            outcome,
            reconciled,
        )
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
        let readiness = match engine.preflight(
            command.host,
            &command.provider_intent,
            &command.cancellation,
        ) {
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
        let readiness = match engine.preflight(
            LOCAL_DEMO_HOST,
            &command.provider_intent,
            &command.cancellation,
        ) {
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

    pub(crate) fn has_reusable_readiness(&self, host: &str) -> Result<bool, SatelleError> {
        self.engine()?.has_reusable_readiness(host)
    }

    /// Runs readiness preflight without admitting a Session or Turn. Doctor
    /// uses this path so a provider refresh updates the normal Host cache but
    /// can never cross into prompt execution.
    pub(crate) fn refresh_provider_smoke(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        let _activity = self.activity.begin();
        self.engine()?
            .preflight(host, provider_intent, &AdmissionCancellation::new())
    }

    pub(crate) fn resolve_provider_binding(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<satelle_core::ResolvedProviderBinding, SatelleError> {
        self.engine()?
            .resolve_provider_binding(host, provider_intent)
    }

    pub(crate) fn authorize_provider_binding(
        &self,
        binding: &ResolvedProviderBinding,
    ) -> Result<(), SatelleError> {
        self.engine()?.authorize_provider_binding(binding)
    }

    pub(crate) fn delete_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, SatelleError> {
        self.engine()?
            .delete_provider_binding(model_alias, provider_alias)
    }

    pub(crate) fn cached_provider_smoke(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ProviderSmokeResult>, SatelleError> {
        self.engine()?.cached_provider_smoke(host, provider_intent)
    }

    pub(crate) fn daemon_workers_idle(&self) -> Result<bool, SatelleError> {
        self.engine()?.reap_finished_workers()
    }

    pub(crate) fn daemon_activity_snapshot(&self) -> Result<(bool, u64), SatelleError> {
        let workers_idle = self.engine()?.reap_finished_workers()?;
        let activity = self.activity.snapshot();
        Ok((workers_idle && activity.is_idle(), activity.generation()))
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

    pub(crate) fn authenticate_pending_setup_api_token(
        &self,
        token: &ApiBearerToken,
        at: time::OffsetDateTime,
    ) -> Result<Option<ApiPrincipal>, SatelleError> {
        self.engine()?
            .lock_storage()?
            .authenticate_pending_setup_api_token(token, at)
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

    pub(crate) fn activate_api_token(
        &self,
        token_id: &str,
        at: time::OffsetDateTime,
    ) -> Result<ApiPrincipal, SatelleError> {
        self.engine()?
            .lock_storage()?
            .activate_api_token(token_id, at)
            .map_err(model::storage_failure)
    }

    pub(crate) fn abort_setup_api_token(
        &self,
        token_id: &str,
        at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.engine()?
            .lock_storage()?
            .abort_setup_api_token(token_id, at)
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

    pub(crate) fn claim_provider_descriptor_validation(
        &self,
        identity: &RequestIdentity,
    ) -> Result<Option<satelle_core::PublicProviderDescriptorValidation>, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        let idempotency = model::idempotency(
            IdempotentOperation::ProviderDescriptorValidation,
            identity,
            requested_at,
        )?;
        let replay = self
            .engine()?
            .lock_storage()?
            .claim_provider_descriptor_validation(&idempotency)
            .map_err(model::storage_failure)?;
        match replay
            .map(|json| {
                serde_json::from_str(&json).map_err(|_| {
                    integrity_error("stored provider validation replay is not valid canonical JSON")
                })
            })
            .transpose()?
        {
            Some(ProviderDescriptorValidationReplay::Completed(result)) => Ok(Some(result)),
            Some(ProviderDescriptorValidationReplay::Failed(error)) => Err(error),
            None => Ok(None),
        }
    }

    pub(crate) fn complete_provider_descriptor_validation(
        &self,
        identity: &RequestIdentity,
        result: &satelle_core::PublicProviderDescriptorValidation,
    ) -> Result<(), SatelleError> {
        let completed_at = time::OffsetDateTime::now_utc();
        let idempotency = model::idempotency(
            IdempotentOperation::ProviderDescriptorValidation,
            identity,
            completed_at,
        )?;
        let result_json = serde_json::to_string(&ProviderDescriptorValidationReplay::Completed(
            result.clone(),
        ))
        .map_err(|_| {
            integrity_error("provider validation result could not be serialized for durable replay")
        })?;
        self.engine()?
            .lock_storage()?
            .complete_provider_descriptor_validation(
                &idempotency,
                &result_json,
                false,
                completed_at,
            )
            .map_err(model::storage_failure)
    }

    pub(crate) fn fail_provider_descriptor_validation(
        &self,
        identity: &RequestIdentity,
        error: &SatelleError,
    ) -> Result<(), SatelleError> {
        let completed_at = time::OffsetDateTime::now_utc();
        let idempotency = model::idempotency(
            IdempotentOperation::ProviderDescriptorValidation,
            identity,
            completed_at,
        )?;
        let result_json =
            serde_json::to_string(&ProviderDescriptorValidationReplay::Failed(error.clone()))
                .map_err(|_| {
                    integrity_error(
                        "provider validation failure could not be serialized for durable replay",
                    )
                })?;
        self.engine()?
            .lock_storage()?
            .complete_provider_descriptor_validation(&idempotency, &result_json, true, completed_at)
            .map_err(model::storage_failure)
    }

    pub(crate) fn authorize_provider_binding_idempotent<F>(
        &self,
        identity: &RequestIdentity,
        validate: F,
    ) -> Result<PublicResolvedProviderBinding, SatelleError>
    where
        F: FnOnce() -> Result<ResolvedProviderBinding, SatelleError>,
    {
        let completed_at = time::OffsetDateTime::now_utc();
        let idempotency = model::idempotency(
            IdempotentOperation::ProviderBindingAuthorization,
            identity,
            completed_at,
        )?;
        let replay = self
            .engine()?
            .lock_storage()?
            .authorize_provider_binding_idempotent(
                &idempotency,
                completed_at,
                validate,
                model::storage_failure_ref,
            )
            .map_err(model::storage_failure)?;
        match replay {
            ProviderBindingAuthorizationReplay::Completed(binding) => Ok(binding),
            ProviderBindingAuthorizationReplay::Failed(error) => Err(error),
        }
    }

    pub(crate) fn delete_provider_binding_idempotent<F>(
        &self,
        identity: &RequestIdentity,
        model_alias: &str,
        provider_alias: &str,
        validate: F,
    ) -> Result<bool, SatelleError>
    where
        F: FnOnce() -> Result<(), SatelleError>,
    {
        let completed_at = time::OffsetDateTime::now_utc();
        let idempotency = model::idempotency(
            IdempotentOperation::ProviderBindingDeletion,
            identity,
            completed_at,
        )?;
        let replay = self
            .engine()?
            .lock_storage()?
            .delete_provider_binding_idempotent(
                &idempotency,
                model_alias,
                provider_alias,
                completed_at,
                validate,
                model::storage_failure_ref,
            )
            .map_err(model::storage_failure)?;
        match replay {
            ProviderBindingDeletionReplay::Completed(deleted) => Ok(deleted),
            ProviderBindingDeletionReplay::Failed(error) => Err(error),
        }
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

    #[cfg(test)]
    pub(crate) fn fail_next_maintenance_start_and_retain_for_tests(&self) {
        FAIL_NEXT_MAINTENANCE_START_AND_RETAIN.with(|fail| {
            assert!(
                !fail.replace(true),
                "maintenance failpoint was already armed"
            );
        });
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
        let operator_log_root = lazy.operator_log_root.clone()?;
        let engine = RuntimeEngine::open(
            &state_root,
            operator_log_root,
            Arc::clone(&self.adapter),
            self.readiness_probe_driver.clone(),
            lazy.provider_policy.clone(),
        )?;
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

#[cfg(any(test, feature = "test-support"))]
pub(crate) use self::codex_adapter::resolve_provider_child_secret as resolve_provider_child_secret_for_test;

#[cfg(test)]
#[path = "runtime-retention-tests.rs"]
mod retention_tests;
#[cfg(test)]
#[path = "runtime-tests.rs"]
mod tests;
