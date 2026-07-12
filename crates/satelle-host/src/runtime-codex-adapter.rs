use super::adapter::{
    AdapterReadiness, AdapterSubject, ComputerUseAdapter, ExecuteRequest, ExecuteResult,
    RecoveryObservation,
};
use crate::codex_session::{
    CodexApprovalPolicy, CodexSandboxPolicy, CodexSessionControl, CodexSessionError,
    CodexSessionFailure, CodexSessionRequest, CodexSessionTerminal, CodexTurnReadRequest,
    CodexTurnStatus, read_codex_turn, run_codex_session,
};
use satelle_core::session::{
    ApprovalPolicy, SandboxPolicy, StopObservation, TurnState, TurnTransition,
};
use satelle_core::{ControlPlaneOperation, ErrorCode, SatelleError};
use serde_json::Value;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// The production adapter owns the private Codex app-server boundary. Native
/// execution remains gated by preflight evidence; no caller can reach execute
/// merely because the protocol session itself is implemented.
#[derive(Clone)]
pub(crate) struct ProductionComputerUseAdapter {
    snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>,
    working_directory: Result<PathBuf, SatelleError>,
    active_execution: Arc<Mutex<Option<ActiveCodexExecution>>>,
}

#[derive(Clone)]
struct ActiveCodexExecution {
    session_id: satelle_core::SessionId,
    turn_id: satelle_core::TurnId,
    control: CodexSessionControl,
}

struct ActiveExecutionGuard {
    registry: Arc<Mutex<Option<ActiveCodexExecution>>>,
    session_id: satelle_core::SessionId,
    turn_id: satelle_core::TurnId,
}

impl Drop for ActiveExecutionGuard {
    fn drop(&mut self) {
        let Ok(mut active) = self.registry.lock() else {
            return;
        };
        if active.as_ref().is_some_and(|execution| {
            execution.session_id == self.session_id && execution.turn_id == self.turn_id
        }) {
            *active = None;
        }
    }
}

impl ProductionComputerUseAdapter {
    pub(crate) fn new(
        snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>,
        working_directory: Result<PathBuf, SatelleError>,
    ) -> Self {
        Self {
            snapshot,
            working_directory,
            active_execution: Arc::new(Mutex::new(None)),
        }
    }

    fn blocked<T>(&self) -> Result<T, SatelleError> {
        let snapshot = crate::read_production_snapshot(&self.snapshot)?;
        Err(crate::execution_blocker(&snapshot.verdict))
    }

    fn ensure_platform_admitted(&self) -> Result<(), SatelleError> {
        let snapshot = crate::read_production_snapshot(&self.snapshot)?;
        if snapshot.verdict.is_supported() {
            Ok(())
        } else {
            Err(crate::execution_blocker(&snapshot.verdict))
        }
    }

    fn register_execution(
        &self,
        subject: AdapterSubject<'_>,
        control: CodexSessionControl,
    ) -> Result<ActiveExecutionGuard, SatelleError> {
        let mut active = self
            .active_execution
            .lock()
            .map_err(|_| adapter_failure("control_registry_unavailable"))?;
        if active.is_some() {
            return Err(adapter_failure("desktop_owner_conflict"));
        }
        let execution = ActiveCodexExecution {
            session_id: subject.session_id().clone(),
            turn_id: subject.turn_id().clone(),
            control,
        };
        let guard = ActiveExecutionGuard {
            registry: Arc::clone(&self.active_execution),
            session_id: execution.session_id.clone(),
            turn_id: execution.turn_id.clone(),
        };
        *active = Some(execution);
        Ok(guard)
    }

    fn active_control(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<Option<CodexSessionControl>, SatelleError> {
        let active = self
            .active_execution
            .lock()
            .map_err(|_| adapter_failure("control_registry_unavailable"))?;
        Ok(active
            .as_ref()
            .filter(|execution| {
                execution.session_id == *subject.session_id()
                    && execution.turn_id == *subject.turn_id()
            })
            .map(|execution| execution.control.clone()))
    }

    fn read_persisted_turn(&self, subject: AdapterSubject<'_>) -> Option<CodexTurnStatus> {
        // No transport or protocol failure proves ownership inactive. Collapse
        // every uncertain read to None so callers retain the Control Lease.
        let (Some(thread_ref), Some(turn_ref)) =
            (subject.upstream_thread_ref(), subject.upstream_turn_ref())
        else {
            return None;
        };
        let working_directory = self
            .working_directory
            .as_ref()
            .ok()
            .and_then(|path| prepare_working_directory(path).ok())?;
        let deadline = Instant::now().checked_add(Duration::from_secs(5))?;
        read_codex_turn(
            crate::codex_capabilities::installed_app_server_command(),
            CodexTurnReadRequest {
                working_directory: &working_directory,
                thread_ref,
                turn_ref,
                deadline,
            },
        )
        .ok()
    }
}

impl ComputerUseAdapter for ProductionComputerUseAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        crate::read_production_snapshot(&self.snapshot)?
            .control_plane_admission
            .admit(operation)
    }

    fn preflight(&self, _host: &str) -> Result<AdapterReadiness, SatelleError> {
        self.blocked()
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.ensure_platform_admitted()?;
        let policy = request.execution_policy();
        let approval_policy = codex_approval_policy(policy.approval_policy())?;
        let sandbox_policy = codex_sandbox_policy(policy.sandbox_policy());
        let timeout = Duration::from_secs(u64::from(policy.timeout_policy().seconds()));
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| adapter_failure("timeout_unrepresentable"))?;
        let working_directory = self
            .working_directory
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|path| prepare_working_directory(path))?;
        let control = CodexSessionControl::new(deadline);
        let _active_execution = self.register_execution(request.subject(), control.clone())?;

        // Preserve the original storage failure outside the protocol layer so
        // a private-reference conflict is not misclassified as transport I/O.
        let persistence_error = RefCell::new(None);
        let mut persist_thread_ref = |value: &str| {
            request.persist_upstream_thread_ref(value).map_err(|error| {
                *persistence_error.borrow_mut() = Some(error);
            })
        };
        let mut persist_turn_ref = |value: &str| {
            request.persist_upstream_turn_ref(value).map_err(|error| {
                *persistence_error.borrow_mut() = Some(error);
            })
        };
        let result = run_codex_session(
            crate::codex_capabilities::installed_app_server_command(),
            CodexSessionRequest {
                working_directory: &working_directory,
                prompt: request.prompt(),
                existing_thread_ref: request.upstream_thread_ref(),
                model: policy.effective_model().as_str(),
                model_provider: policy.provider_binding().as_str(),
                approval_policy,
                sandbox_policy,
                deadline,
                persist_thread_ref: &mut persist_thread_ref,
                persist_turn_ref: &mut persist_turn_ref,
                control: Some(control),
            },
        );
        finish_execution(result, persistence_error.into_inner())
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        if let Some(control) = self.active_control(subject)? {
            return Ok(control.interrupt());
        }
        Ok(stop_observation(
            subject.turn_state(),
            subject.has_upstream_references(),
            self.read_persisted_turn(subject),
        ))
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(recovery_observation(self.read_persisted_turn(subject)))
    }

    fn stop_committed(&self, session_id: &satelle_core::SessionId, turn_id: &satelle_core::TurnId) {
        let control = self.active_execution.lock().ok().and_then(|mut active| {
            let matching = active.as_ref().is_some_and(|execution| {
                execution.session_id == *session_id && execution.turn_id == *turn_id
            });
            matching
                .then(|| active.take().map(|execution| execution.control))
                .flatten()
        });
        if let Some(control) = control {
            control.stop_committed();
        }
    }
}

fn stop_observation(
    turn_state: TurnState,
    has_upstream_references: bool,
    status: Option<CodexTurnStatus>,
) -> StopObservation {
    // The worker must durably enter Running before calling execute, so a
    // Starting Turn with no private references cannot have reached Codex.
    // Running and recovery_pending remain ambiguous without exact evidence.
    if turn_state == TurnState::Starting && !has_upstream_references {
        return StopObservation::UpstreamInactiveConfirmed;
    }
    match status {
        Some(CodexTurnStatus::InProgress) => StopObservation::UpstreamStillActive,
        Some(
            CodexTurnStatus::Completed | CodexTurnStatus::Interrupted | CodexTurnStatus::Failed,
        ) => StopObservation::UpstreamInactiveConfirmed,
        None => StopObservation::OutcomeUnknown,
    }
}

fn recovery_observation(status: Option<CodexTurnStatus>) -> RecoveryObservation {
    match status {
        Some(CodexTurnStatus::InProgress) => RecoveryObservation::Running,
        Some(CodexTurnStatus::Completed) => RecoveryObservation::Completed,
        Some(CodexTurnStatus::Interrupted | CodexTurnStatus::Failed) => RecoveryObservation::Failed,
        None => RecoveryObservation::Unknown,
    }
}

fn prepare_working_directory(path: &Path) -> Result<PathBuf, SatelleError> {
    if !path.is_absolute()
        || path.ancestors().any(|ancestor| {
            std::fs::symlink_metadata(ancestor.join(".git")).is_ok()
                || std::fs::symlink_metadata(ancestor.join(".satelle/config.toml")).is_ok()
        })
    {
        return Err(adapter_failure("unsafe_working_directory"));
    }

    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => return Err(adapter_failure("working_directory_unavailable")),
    };
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| adapter_failure("working_directory_unavailable"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(adapter_failure("unsafe_working_directory"));
    }

    // Resolve configured parent links before enforcing the project boundary.
    // Returning this canonical path also prevents the child from traversing a
    // different ancestor chain than the one inspected here.
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| adapter_failure("working_directory_unavailable"))?;
    if canonical.ancestors().any(|ancestor| {
        std::fs::symlink_metadata(ancestor.join(".git")).is_ok()
            || std::fs::symlink_metadata(ancestor.join(".satelle/config.toml")).is_ok()
    }) {
        if created {
            let _ = std::fs::remove_dir(path);
        }
        return Err(adapter_failure("unsafe_working_directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(adapter_failure("unsafe_working_directory"));
        }
    }
    Ok(canonical)
}

fn codex_approval_policy(policy: ApprovalPolicy) -> Result<CodexApprovalPolicy, SatelleError> {
    match policy {
        ApprovalPolicy::Untrusted => Ok(CodexApprovalPolicy::Untrusted),
        ApprovalPolicy::OnRequest => Ok(CodexApprovalPolicy::OnRequest),
        ApprovalPolicy::Never => Ok(CodexApprovalPolicy::Never),
        ApprovalPolicy::OnFailure => Err(adapter_failure("approval_policy_unsupported")),
    }
}

fn codex_sandbox_policy(policy: SandboxPolicy) -> CodexSandboxPolicy {
    match policy {
        SandboxPolicy::ReadOnly => CodexSandboxPolicy::ReadOnly,
        SandboxPolicy::WorkspaceWrite => CodexSandboxPolicy::WorkspaceWrite,
        SandboxPolicy::DangerFullAccess => CodexSandboxPolicy::DangerFullAccess,
    }
}

fn terminal_result(
    result: Result<CodexSessionTerminal, CodexSessionFailure>,
) -> Result<ExecuteResult, SatelleError> {
    match result {
        Ok(CodexSessionTerminal::Completed) => {
            Ok(ExecuteResult::new(TurnTransition::Completed, Vec::new()))
        }
        // A matching terminal interruption proves that upstream execution no
        // longer owns the desktop. The normal stop path wins its own CAS race;
        // an unsolicited interruption is a truthful failed execution.
        Ok(CodexSessionTerminal::Interrupted | CodexSessionTerminal::Failed) => {
            Ok(ExecuteResult::new(TurnTransition::Failed, Vec::new()))
        }
        Ok(CodexSessionTerminal::StoppedByControl) => Ok(ExecuteResult::stopped_by_control()),
        // A cleanup failure is never an ordinary terminal outcome. Even when
        // no turn was dispatched, the daemon has not proven that its private
        // app-server process group stopped.
        Err(failure) if failure.error() == CodexSessionError::Containment => {
            Err(session_failure(CodexSessionError::Containment))
        }
        // Before turn/start is written, there is no possible upstream desktop
        // owner to recover. Commit a terminal failure instead of leaking a
        // recovery_pending Turn that no upstream execution can reconcile.
        Err(failure) if !failure.turn_dispatch_attempted() => {
            Ok(ExecuteResult::new(TurnTransition::Failed, Vec::new()))
        }
        Err(failure) => Err(session_failure(failure.error())),
    }
}

fn finish_execution(
    result: Result<CodexSessionTerminal, CodexSessionFailure>,
    persistence_error: Option<SatelleError>,
) -> Result<ExecuteResult, SatelleError> {
    if let (Err(failure), Some(error)) = (result, persistence_error)
        && failure.turn_dispatch_attempted()
    {
        return Err(error);
    }
    terminal_result(result)
}

fn session_failure(error: CodexSessionError) -> SatelleError {
    let reason = match error {
        CodexSessionError::Spawn => "spawn_failed",
        CodexSessionError::Write => "write_failed",
        CodexSessionError::MalformedMessage => "malformed_message",
        CodexSessionError::OversizedMessage => "oversized_message",
        CodexSessionError::UnexpectedResponse => "unexpected_response",
        CodexSessionError::DuplicateResponse => "duplicate_response",
        CodexSessionError::ResponseError => "response_error",
        CodexSessionError::ConflictingIdentity => "conflicting_identity",
        CodexSessionError::PrematureExit => "premature_exit",
        CodexSessionError::Timeout => "timeout",
        CodexSessionError::Persistence => "persistence_failed",
        CodexSessionError::Containment => "containment_failed",
        CodexSessionError::Control => "control_failed",
    };
    adapter_failure(reason)
}

fn adapter_failure(reason: &'static str) -> SatelleError {
    let mut details = std::collections::BTreeMap::new();
    details.insert("reason".to_string(), Value::String(reason.to_string()));
    SatelleError {
        code: ErrorCode::RemoteExecution,
        message: "the private Codex app-server execution failed".to_string(),
        recovery_command: None,
        source_detail: None,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_policy_has_one_exact_protocol_mapping() {
        assert_eq!(
            codex_approval_policy(ApprovalPolicy::Untrusted).unwrap(),
            CodexApprovalPolicy::Untrusted
        );
        assert_eq!(
            codex_approval_policy(ApprovalPolicy::OnRequest).unwrap(),
            CodexApprovalPolicy::OnRequest
        );
        assert_eq!(
            codex_approval_policy(ApprovalPolicy::Never).unwrap(),
            CodexApprovalPolicy::Never
        );
        let unsupported = codex_approval_policy(ApprovalPolicy::OnFailure).unwrap_err();
        assert_eq!(unsupported.code, ErrorCode::RemoteExecution);
        assert_eq!(
            unsupported.details["reason"],
            Value::String("approval_policy_unsupported".to_string())
        );

        assert_eq!(
            codex_sandbox_policy(SandboxPolicy::ReadOnly),
            CodexSandboxPolicy::ReadOnly
        );
        assert_eq!(
            codex_sandbox_policy(SandboxPolicy::WorkspaceWrite),
            CodexSandboxPolicy::WorkspaceWrite
        );
        assert_eq!(
            codex_sandbox_policy(SandboxPolicy::DangerFullAccess),
            CodexSandboxPolicy::DangerFullAccess
        );
    }

    #[test]
    fn terminal_mapping_releases_known_terminal_ownership() {
        assert_eq!(
            terminal_result(Ok(CodexSessionTerminal::Completed))
                .unwrap()
                .transition(),
            Some(TurnTransition::Completed)
        );
        for terminal in [
            CodexSessionTerminal::Interrupted,
            CodexSessionTerminal::Failed,
        ] {
            assert_eq!(
                terminal_result(Ok(terminal)).unwrap().transition(),
                Some(TurnTransition::Failed)
            );
        }
        assert!(
            terminal_result(Ok(CodexSessionTerminal::StoppedByControl))
                .unwrap()
                .transition()
                .is_none()
        );
    }

    #[test]
    fn durable_turn_status_has_closed_stop_and_recovery_meanings() {
        assert_eq!(
            stop_observation(TurnState::Running, true, Some(CodexTurnStatus::InProgress)),
            StopObservation::UpstreamStillActive
        );
        assert_eq!(
            recovery_observation(Some(CodexTurnStatus::InProgress)),
            RecoveryObservation::Running
        );
        assert_eq!(
            recovery_observation(Some(CodexTurnStatus::Completed)),
            RecoveryObservation::Completed
        );
        for terminal in [
            CodexTurnStatus::Completed,
            CodexTurnStatus::Interrupted,
            CodexTurnStatus::Failed,
        ] {
            assert_eq!(
                stop_observation(TurnState::RecoveryPending, true, Some(terminal)),
                StopObservation::UpstreamInactiveConfirmed
            );
        }
        for failed in [CodexTurnStatus::Interrupted, CodexTurnStatus::Failed] {
            assert_eq!(
                recovery_observation(Some(failed)),
                RecoveryObservation::Failed
            );
        }
        assert_eq!(
            stop_observation(TurnState::Starting, false, None),
            StopObservation::UpstreamInactiveConfirmed
        );
        assert_eq!(
            stop_observation(TurnState::Running, false, None),
            StopObservation::OutcomeUnknown
        );
        assert_eq!(
            stop_observation(TurnState::RecoveryPending, false, None),
            StopObservation::OutcomeUnknown
        );
        assert_eq!(recovery_observation(None), RecoveryObservation::Unknown);
    }

    #[test]
    fn durable_stop_synchronously_releases_the_active_registry_entry() {
        let adapter = ProductionComputerUseAdapter::new(
            Arc::new(RwLock::new(crate::ProductionCapabilitySnapshot::collect())),
            Ok(tempfile::tempdir().unwrap().path().join("codex-work")),
        );
        let session_id = satelle_core::SessionId::new();
        let turn_id = satelle_core::TurnId::new();
        let control = CodexSessionControl::new(Instant::now() + Duration::from_secs(1));
        *adapter.active_execution.lock().unwrap() = Some(ActiveCodexExecution {
            session_id: session_id.clone(),
            turn_id: turn_id.clone(),
            control,
        });

        adapter.stop_committed(&session_id, &turn_id);

        assert!(adapter.active_execution.lock().unwrap().is_none());
    }

    #[test]
    fn original_persistence_failure_wins_over_the_protocol_wrapper() {
        let original = SatelleError::invalid_usage("PRIVATE_PERSISTENCE_ERROR_CANARY");
        let returned = match finish_execution(
            Err(CodexSessionFailure::after_exchange(
                CodexSessionError::Persistence,
                true,
            )),
            Some(original.clone()),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a persistence failure must win over protocol completion"),
        };
        assert_eq!(
            serde_json::to_value(returned).unwrap(),
            serde_json::to_value(original).unwrap()
        );
    }

    #[test]
    fn failure_ownership_only_requires_recovery_after_turn_dispatch() {
        let before_dispatch = terminal_result(Err(CodexSessionFailure::after_exchange(
            CodexSessionError::Timeout,
            false,
        )))
        .unwrap();
        assert_eq!(before_dispatch.transition(), Some(TurnTransition::Failed));

        let after_dispatch = match terminal_result(Err(CodexSessionFailure::after_exchange(
            CodexSessionError::Timeout,
            true,
        ))) {
            Err(error) => error,
            Ok(_) => panic!("an uncertain dispatched turn must require recovery"),
        };
        assert_eq!(after_dispatch.code, ErrorCode::RemoteExecution);
        assert_eq!(after_dispatch.details["reason"], "timeout");

        let uncontained_before_dispatch = match terminal_result(Err(
            CodexSessionFailure::after_exchange(CodexSessionError::Containment, false),
        )) {
            Err(error) => error,
            Ok(_) => panic!("an uncontained process group must surface as an error"),
        };
        assert_eq!(
            uncontained_before_dispatch.details["reason"],
            "containment_failed"
        );

        let original = SatelleError::invalid_usage("PRIVATE_THREAD_PERSISTENCE_CANARY");
        let persisted_before_dispatch = finish_execution(
            Err(CodexSessionFailure::after_exchange(
                CodexSessionError::Persistence,
                false,
            )),
            Some(original),
        )
        .unwrap();
        assert_eq!(
            persisted_before_dispatch.transition(),
            Some(TurnTransition::Failed)
        );
    }

    #[test]
    fn app_server_working_directory_is_private_and_outside_projects() {
        let state = tempfile::tempdir().unwrap();
        let working = state.path().join("codex-app-server-work");
        assert_eq!(
            prepare_working_directory(&working).unwrap(),
            std::fs::canonicalize(&working).unwrap()
        );

        let metadata = std::fs::symlink_metadata(&working).unwrap();
        assert!(metadata.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(metadata.permissions().mode() & 0o077, 0);
        }

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        let nested = project.path().join("state/codex-app-server-work");
        let error = prepare_working_directory(&nested).unwrap_err();
        assert_eq!(error.details["reason"], "unsafe_working_directory");
        assert!(!nested.exists());
    }

    #[cfg(unix)]
    #[test]
    fn app_server_working_directory_rejects_links_and_shared_access() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let state = tempfile::tempdir().unwrap();
        let shared = state.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o750)).unwrap();
        let shared_error = prepare_working_directory(&shared).unwrap_err();
        assert_eq!(shared_error.details["reason"], "unsafe_working_directory");

        let target = state.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let linked = state.path().join("linked");
        symlink(&target, &linked).unwrap();
        let link_error = prepare_working_directory(&linked).unwrap_err();
        assert_eq!(link_error.details["reason"], "unsafe_working_directory");

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        let real_state = project.path().join("hidden-state");
        std::fs::create_dir(&real_state).unwrap();
        let aliases = tempfile::tempdir().unwrap();
        let project_alias = aliases.path().join("hidden-project");
        symlink(&real_state, &project_alias).unwrap();
        let hidden_working = project_alias.join("codex-app-server-work");
        let hidden_error = prepare_working_directory(&hidden_working).unwrap_err();
        assert_eq!(hidden_error.details["reason"], "unsafe_working_directory");
        assert!(!real_state.join("codex-app-server-work").exists());
    }

    #[test]
    fn protocol_failures_expose_only_closed_sanitized_reasons() {
        for error in [
            CodexSessionError::Spawn,
            CodexSessionError::Write,
            CodexSessionError::MalformedMessage,
            CodexSessionError::OversizedMessage,
            CodexSessionError::UnexpectedResponse,
            CodexSessionError::DuplicateResponse,
            CodexSessionError::ResponseError,
            CodexSessionError::ConflictingIdentity,
            CodexSessionError::PrematureExit,
            CodexSessionError::Timeout,
            CodexSessionError::Persistence,
            CodexSessionError::Containment,
            CodexSessionError::Control,
        ] {
            let public = session_failure(error);
            assert_eq!(public.code, ErrorCode::RemoteExecution);
            assert_eq!(public.details.len(), 1);
            assert!(public.details["reason"].is_string());
            let serialized = serde_json::to_string(&public).unwrap();
            assert!(!serialized.contains("PRIVATE_RAW_PROTOCOL_CANARY"));
        }
    }
}
