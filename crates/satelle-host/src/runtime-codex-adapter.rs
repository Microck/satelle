use super::adapter::{
    AdapterPreflight, AdapterReadiness, AdapterSubject, ComputerUseAdapter, EvidenceError,
    ExecuteRequest, ExecuteResult, NativeProbeResult, NativeReadinessCheck,
    NativeReadinessCheckKind, NativeReadinessCheckStatus, ProviderComputerUseIntent,
    ProviderSmokeEvidence, ProviderSmokeFailureEvidence, ProviderSmokeResult, ProviderSmokeSource,
    ReadinessCacheKey, ReadinessEvidence, ReadinessObservationState, ReadinessProbeDriver,
    ReadinessSource, RecoveryObservation,
};
use crate::READINESS_CANCELLATION_GRACE;
use crate::codex_session::{
    CodexApprovalPolicy, CodexSandboxPolicy, CodexSessionControl, CodexSessionError,
    CodexSessionFailure, CodexSessionRequest, CodexSessionTerminal, CodexTurnReadRequest,
    CodexTurnStatus, TimedCodexSessionRun, read_codex_turn,
    run_codex_session_with_timeout_cancellation,
};
use command_group::{CommandGroup, GroupChild};
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, SandboxPolicy, StopObservation,
    TimeoutPolicy, TurnExecutionMode, TurnState, TurnTransition,
};
use satelle_core::{
    ControlPlaneOperation, DesktopSelectionPolicy, ErrorCode, SatelleError,
    resolve_desktop_session_for,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;

const DEFAULT_MODEL_BINDING: &str = "codex-default";
const DEFAULT_PROVIDER_BINDING: &str = "codex-default";
const NATIVE_ADAPTER: &str = "codex-native-computer-use";

#[derive(Debug)]
struct ProviderSmokeAttemptFailure {
    evidence: Option<ProviderSmokeFailureEvidence>,
    error: Box<SatelleError>,
}

struct NativeSmokeFailure {
    reason: &'static str,
    error: Box<SatelleError>,
    dispatch_possible: bool,
}

struct ProviderProbePersistence<'a> {
    persist_thread_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
    persist_turn_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
}

fn supported_execution_version(
    snapshot: &crate::ProductionCapabilitySnapshot,
) -> Result<crate::codex_capabilities::CodexVersion, SatelleError> {
    let version = match snapshot.evidence.codex_version {
        crate::codex_capabilities::CodexVersionEvidence::Detected { version }
            if version == crate::codex_capabilities::REQUIRED_CODEX_VERSION =>
        {
            version
        }
        _ => return Err(crate::execution_blocker(&snapshot.verdict)),
    };
    if !snapshot
        .evidence
        .host_platform
        .supports_native_computer_use()
        || !snapshot.verdict.is_supported()
    {
        return Err(crate::execution_blocker(&snapshot.verdict));
    }
    Ok(version)
}

/// The production adapter owns the private Codex app-server boundary. Native
/// execution remains gated by preflight evidence; no caller can reach execute
/// merely because the protocol session itself is implemented.
#[derive(Clone)]
pub(crate) struct ProductionComputerUseAdapter {
    snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>,
    working_directory: Result<PathBuf, SatelleError>,
    active_execution: Arc<Mutex<Option<ActiveCodexExecution>>>,
    native_readiness_timeout: Duration,
    native_readiness_ttl: time::Duration,
    provider_smoke_timeout: Duration,
    provider_smoke_success_ttl: time::Duration,
    provider_smoke_failure_ttl: time::Duration,
    desktop_selection: DesktopSelectionPolicy,
}

pub(crate) struct ProductionAdapterPolicy {
    pub(crate) native_readiness_timeout: Duration,
    pub(crate) native_readiness_ttl: time::Duration,
    pub(crate) provider_smoke_timeout: Duration,
    pub(crate) provider_smoke_success_ttl: time::Duration,
    pub(crate) provider_smoke_failure_ttl: time::Duration,
    pub(crate) desktop_selection: DesktopSelectionPolicy,
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
    #[cfg(test)]
    pub(crate) fn new(
        snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>,
        working_directory: Result<PathBuf, SatelleError>,
    ) -> Self {
        Self {
            snapshot,
            working_directory,
            active_execution: Arc::new(Mutex::new(None)),
            native_readiness_timeout: crate::DEFAULT_NATIVE_READINESS_TIMEOUT,
            native_readiness_ttl: crate::DEFAULT_NATIVE_READINESS_TTL,
            provider_smoke_timeout: Duration::from_secs(120),
            provider_smoke_success_ttl: crate::DEFAULT_PROVIDER_SMOKE_SUCCESS_TTL,
            provider_smoke_failure_ttl: crate::DEFAULT_PROVIDER_SMOKE_FAILURE_TTL,
            desktop_selection: DesktopSelectionPolicy {
                desktop_user: None,
                preference: None,
                native_selector: None,
            },
        }
    }

    pub(crate) fn with_readiness_policy(
        snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>,
        working_directory: Result<PathBuf, SatelleError>,
        policy: ProductionAdapterPolicy,
    ) -> Self {
        Self {
            snapshot,
            working_directory,
            active_execution: Arc::new(Mutex::new(None)),
            native_readiness_timeout: policy.native_readiness_timeout,
            native_readiness_ttl: policy.native_readiness_ttl,
            provider_smoke_timeout: policy.provider_smoke_timeout,
            provider_smoke_success_ttl: policy.provider_smoke_success_ttl,
            provider_smoke_failure_ttl: policy.provider_smoke_failure_ttl,
            desktop_selection: policy.desktop_selection,
        }
    }

    fn native_readiness_key(
        &self,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<ReadinessCacheKey, SatelleError> {
        let snapshot = crate::read_production_snapshot(&self.snapshot)?;
        snapshot
            .control_plane_admission
            .admit(ControlPlaneOperation::Run)?;
        let version = supported_execution_version(&snapshot)?;
        let app_policy_surface = snapshot.evidence.capabilities.approval_observation.surface;
        drop(snapshot);

        let desktops = crate::desktop_sessions::discover()?;
        let platform = crate::codex_capabilities::HostPlatform::current().as_str();
        let desktop = resolve_desktop_session_for(platform, &desktops, &self.desktop_selection)?;
        let observations = native_prerequisite_observations(platform, desktop, app_policy_surface);
        let desktop_binding = DesktopBindingRef::new(desktop.desktop_user.clone())
            .map_err(|_| adapter_failure("desktop_binding_invalid"))?;
        let effective_model = provider_intent
            .model()
            .cloned()
            .map_or_else(|| EffectiveModelRef::new(DEFAULT_MODEL_BINDING), Ok)
            .map_err(|_| adapter_failure("model_binding_invalid"))?;
        let provider_binding = provider_intent
            .provider()
            .cloned()
            .map_or_else(|| ProviderBindingRef::new(DEFAULT_PROVIDER_BINDING), Ok)
            .map_err(|_| adapter_failure("provider_binding_invalid"))?;
        let execution_policy = ExecutionPolicy::new(
            effective_model,
            provider_binding,
            DesktopTarget::new(desktop_binding.clone(), desktop.session_id.clone()),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            host_turn_timeout_ceiling()?,
            ExperimentalFeatureChoices::new(
                FeatureChoice::Enabled,
                if provider_intent.experimental() {
                    FeatureChoice::Enabled
                } else {
                    FeatureChoice::Disabled
                },
            ),
        );
        let codex_version = version.to_string();
        let native_runtime_version = format!("codex-native-{codex_version}");
        ReadinessCacheKey::new(
            NATIVE_ADAPTER,
            desktop_binding,
            execution_policy,
            codex_version,
            native_runtime_version,
            None::<String>,
            readiness_fingerprint(
                "os-permission",
                platform,
                &desktop.session_id,
                observations.os_permission_state,
                &observations.os_fingerprint_material,
            ),
            readiness_fingerprint(
                "app-approval",
                platform,
                &desktop.session_id,
                observations.app_approval_state,
                &observations.app_fingerprint_material,
            ),
            observations.os_permission_state,
            observations.app_approval_state,
        )
        .map_err(|_| adapter_failure("readiness_key_invalid"))
    }

    #[allow(clippy::too_many_arguments)]
    fn readiness_from_evidence(
        &self,
        key: &ReadinessCacheKey,
        evidence: ReadinessEvidence,
        source: ReadinessSource,
        cached_provider: Option<ProviderSmokeResult>,
        refresh_provider: bool,
        provider_smoke_timeout: Option<Duration>,
        cancellation: Option<&super::request::AdmissionCancellation>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> AdapterPreflight {
        match self.run_required_provider_smoke(
            key,
            cached_provider,
            refresh_provider,
            provider_smoke_timeout,
            cancellation,
            persistence,
        ) {
            Ok(provider_smoke_evidence) => {
                native_readiness_from_evidence(key, evidence, provider_smoke_evidence, source)
                    .map_or_else(
                        |_| {
                            AdapterPreflight::UncachedFailure(adapter_failure(
                                "readiness_evidence_invalid",
                            ))
                        },
                        AdapterPreflight::Ready,
                    )
            }
            Err(ProviderSmokeAttemptFailure {
                evidence: Some(failure),
                error,
            }) => AdapterPreflight::ProviderFailed {
                key: key.clone(),
                readiness: evidence,
                failure,
                error: *error,
            },
            Err(ProviderSmokeAttemptFailure {
                evidence: None,
                error,
            }) => AdapterPreflight::UncachedFailure(*error),
        }
    }

    fn live_native_preflight(
        &self,
        key: ReadinessCacheKey,
        cached_provider: Option<ProviderSmokeResult>,
        refresh_provider: bool,
        provider_smoke_timeout: Option<Duration>,
        cancellation: Option<&super::request::AdmissionCancellation>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> AdapterPreflight {
        let observed_at = time::OffsetDateTime::now_utc();
        let Some(expires_at) = observed_at.checked_add(self.native_readiness_ttl) else {
            return AdapterPreflight::UncachedFailure(adapter_failure("readiness_ttl_invalid"));
        };
        let evidence = match key.evidence(
            format!("native-readiness-{}", satelle_core::SessionId::new()),
            observed_at,
            expires_at,
        ) {
            Ok(evidence) => evidence,
            Err(_) => {
                return AdapterPreflight::UncachedFailure(adapter_failure(
                    "readiness_evidence_invalid",
                ));
            }
        };
        if let Some(error) = native_observation_blocker(&key) {
            return AdapterPreflight::Failed {
                key,
                evidence,
                reason: "native_readiness_manual_action_required",
                error,
                dispatch_possible: false,
            };
        }
        let mut persist_thread_ref = |_value: &str| Ok(());
        let mut persist_turn_ref = |_value: &str| Ok(());
        tracing::debug!(
            adapter = NATIVE_ADAPTER,
            "starting native Computer Use readiness smoke test"
        );
        match self.run_native_smoke(cancellation, &mut persist_thread_ref, &mut persist_turn_ref) {
            Ok(()) => self.readiness_from_evidence(
                &key,
                evidence,
                ReadinessSource::Live,
                cached_provider,
                refresh_provider,
                provider_smoke_timeout,
                cancellation,
                persistence,
            ),
            Err(failure) => AdapterPreflight::Failed {
                key,
                evidence,
                reason: failure.reason,
                error: mark_probe_dispatch_possible(*failure.error, failure.dispatch_possible),
                dispatch_possible: failure.dispatch_possible,
            },
        }
    }

    fn run_native_smoke(
        &self,
        cancellation: Option<&super::request::AdmissionCancellation>,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> Result<(), NativeSmokeFailure> {
        let nonce = format!("SATELLE-{}", satelle_core::TurnId::new());
        let deadline = Instant::now()
            .checked_add(self.native_readiness_timeout)
            .ok_or_else(|| native_smoke_failure("native_readiness_timeout_invalid"))?;
        let mut target = NativeActionTarget::spawn(&nonce, self.native_readiness_timeout)
            .map_err(native_smoke_failure)?;
        std::thread::sleep(Duration::from_millis(200));
        let working_directory = self
            .working_directory
            .as_ref()
            .map_err(|_| native_smoke_failure("working_directory_unavailable"))
            .and_then(|path| {
                prepare_working_directory(path)
                    .map_err(|_| native_smoke_failure("working_directory_unavailable"))
            })?;
        let prompt = native_readiness_prompt(&nonce);
        let command =
            crate::codex_capabilities::installed_app_server_command().map_err(|error| {
                NativeSmokeFailure {
                    reason: "managed_codex_receipt_invalid",
                    error: Box::new(error),
                    dispatch_possible: false,
                }
            })?;
        let run = run_codex_session_with_timeout_cancellation(
            command,
            CodexSessionRequest {
                working_directory: &working_directory,
                prompt: &prompt,
                existing_thread_ref: None,
                model: None,
                model_provider: None,
                execution_mode: TurnExecutionMode::Standard,
                approval_policy: CodexApprovalPolicy::OnRequest,
                sandbox_policy: CodexSandboxPolicy::WorkspaceWrite,
                deadline,
                persist_thread_ref,
                persist_turn_ref,
                control: None,
                goal_set_supported: false,
                image_input_mode: crate::codex_capabilities::CodexImageInputMode::Unsupported,
                attachments: &[],
            },
            READINESS_CANCELLATION_GRACE,
            cancellation.cloned(),
        );
        let terminal = classify_native_probe_run(run)?;
        if terminal != CodexSessionTerminal::Completed {
            return Err(native_smoke_failure("native_readiness_session_failed"));
        }
        target
            .wait_for_success(deadline)
            .map_err(native_smoke_failure)
    }

    fn run_required_provider_smoke(
        &self,
        key: &ReadinessCacheKey,
        cached_provider: Option<ProviderSmokeResult>,
        refresh: bool,
        timeout_override: Option<Duration>,
        cancellation: Option<&super::request::AdmissionCancellation>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> Result<Option<ProviderSmokeEvidence>, ProviderSmokeAttemptFailure> {
        if key
            .execution_policy()
            .experimental_features()
            .provider_computer_use()
            != FeatureChoice::Enabled
        {
            return Ok(None);
        }
        match cached_provider {
            Some(ProviderSmokeResult::Passed(evidence)) => return Ok(Some(evidence)),
            Some(ProviderSmokeResult::Failed(failure)) => {
                return Err(ProviderSmokeAttemptFailure {
                    evidence: None,
                    error: Box::new(provider_smoke_error_from_failure(&failure)),
                });
            }
            None => {}
        }

        let source = if refresh {
            ProviderSmokeSource::Refresh
        } else {
            ProviderSmokeSource::Live
        };
        self.run_live_provider_smoke(key, source, timeout_override, cancellation, persistence)
            .map(Some)
            .map_err(|error| {
                let observed_at = time::OffsetDateTime::now_utc();
                let evidence = observed_at
                    .checked_add(self.provider_smoke_failure_ttl)
                    .and_then(|expires_at| {
                        ProviderSmokeFailureEvidence::new(
                            format!("provider-smoke-{}", satelle_core::SessionId::new()),
                            key.provider_config_fingerprint(),
                            error.code,
                            error
                                .details
                                .get("reason")
                                .and_then(Value::as_str)
                                .unwrap_or_else(|| error.code.as_str()),
                            observed_at,
                            expires_at,
                        )
                        .map(|evidence| evidence.with_source(source))
                        .ok()
                    });
                let error = match evidence.as_ref() {
                    Some(evidence) => annotate_provider_smoke_error(
                        error,
                        evidence.source(),
                        evidence.observed_at(),
                        evidence.expires_at(),
                    ),
                    None => error,
                };
                ProviderSmokeAttemptFailure {
                    evidence,
                    error: Box::new(error),
                }
            })
    }

    fn run_live_provider_smoke(
        &self,
        key: &ReadinessCacheKey,
        source: ProviderSmokeSource,
        timeout_override: Option<Duration>,
        cancellation: Option<&super::request::AdmissionCancellation>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> Result<ProviderSmokeEvidence, SatelleError> {
        let timeout = timeout_override.unwrap_or(self.provider_smoke_timeout);
        let probe = crate::provider_probe::ProviderProbeSurface::start(timeout)
            .map_err(|error| mark_probe_dispatch_possible(provider_smoke_failure(error), false))?;
        let page_url = probe.page_url().to_string();
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            mark_probe_dispatch_possible(
                provider_smoke_failure(crate::provider_probe::ProviderProbeError::TimedOut),
                false,
            )
        })?;
        let working_directory = self
            .working_directory
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|path| prepare_working_directory(path))
            .map_err(|error| mark_probe_dispatch_possible(error, false))?;
        let prompt = format!(
            "Use native Computer Use only to open {page_url} in the approved visible browser. Read the nonce shown on the page, drag the marker into the drop target, and stop. Do not use shell, file, or network tools."
        );
        let run = run_codex_session_with_timeout_cancellation(
            preserve_managed_codex_error(crate::codex_capabilities::installed_app_server_command())?,
            CodexSessionRequest {
                working_directory: &working_directory,
                prompt: &prompt,
                existing_thread_ref: None,
                model: model_override(key.execution_policy().effective_model().as_str()),
                model_provider: provider_override(
                    key.execution_policy().provider_binding().as_str(),
                ),
                execution_mode: TurnExecutionMode::Standard,
                approval_policy: CodexApprovalPolicy::OnRequest,
                sandbox_policy: CodexSandboxPolicy::WorkspaceWrite,
                deadline,
                persist_thread_ref: persistence.persist_thread_ref,
                persist_turn_ref: persistence.persist_turn_ref,
                control: None,
                goal_set_supported: false,
                image_input_mode: crate::codex_capabilities::CodexImageInputMode::Unsupported,
                attachments: &[],
            },
            READINESS_CANCELLATION_GRACE,
            cancellation.cloned(),
        );
        let terminal = classify_provider_probe_run(run)?;
        if terminal != CodexSessionTerminal::Completed {
            return Err(mark_probe_dispatch_possible(
                provider_smoke_session_failure(CodexSessionError::ResponseError),
                false,
            ));
        }
        probe
            .wait_for_completion()
            .map_err(|error| mark_probe_dispatch_possible(provider_smoke_failure(error), false))?;

        let observed_at = time::OffsetDateTime::now_utc();
        let expires_at = observed_at + self.provider_smoke_success_ttl;
        ProviderSmokeEvidence::new(
            format!("provider-smoke-{}", satelle_core::SessionId::new()),
            key.provider_config_fingerprint(),
            observed_at,
            expires_at,
        )
        .map(|evidence| evidence.with_source(source))
        .map_err(|_| adapter_failure("provider_smoke_evidence_invalid"))
    }

    fn resolve_configured_desktop_target(&self) -> Result<DesktopTarget, SatelleError> {
        self.native_readiness_key(&ProviderComputerUseIntent::host_default())
            .map(|key| key.execution_policy().desktop_target().clone())
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
            crate::codex_capabilities::installed_app_server_command().ok()?,
            CodexTurnReadRequest {
                working_directory: &working_directory,
                thread_ref,
                turn_ref,
                deadline,
            },
        )
        .ok()
    }

    fn read_readiness_probe_turn(
        &self,
        subject: &crate::storage::ProbeRecoverySubject,
    ) -> Option<CodexTurnStatus> {
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
            crate::codex_capabilities::installed_app_server_command().ok()?,
            CodexTurnReadRequest {
                working_directory: &working_directory,
                thread_ref,
                turn_ref,
                deadline,
            },
        )
        .ok()
    }

    fn preflight_terminal_inner(
        &self,
        provider_intent: &ProviderComputerUseIntent,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        cancellation: Option<&super::request::AdmissionCancellation>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> AdapterPreflight {
        let key = match self.native_readiness_key(provider_intent) {
            Ok(key) => key,
            Err(error) => return AdapterPreflight::UncachedFailure(error),
        };
        let cached_provider =
            provider_cache_for_preflight(cached_provider, provider_intent.refresh());
        let cached = matching_cached_evidence(&key, cached);
        match cached {
            Some(evidence) => {
                let source = evidence.source();
                self.readiness_from_evidence(
                    &key,
                    evidence,
                    source,
                    cached_provider,
                    provider_intent.refresh(),
                    provider_intent.provider_smoke_timeout(),
                    cancellation,
                    persistence,
                )
            }
            None => self.live_native_preflight(
                key,
                cached_provider,
                provider_intent.refresh(),
                provider_intent.provider_smoke_timeout(),
                cancellation,
                persistence,
            ),
        }
    }
}

fn native_readiness_from_evidence(
    key: &ReadinessCacheKey,
    evidence: ReadinessEvidence,
    provider_smoke_evidence: Option<ProviderSmokeEvidence>,
    source: ReadinessSource,
) -> Result<AdapterReadiness, EvidenceError> {
    AdapterReadiness::ready(
        key.adapter(),
        "native Computer Use passed the Host action-path smoke test",
        key.desktop_binding().clone(),
        key.execution_policy().clone(),
        evidence,
        provider_smoke_evidence,
    )
    .map(|readiness| readiness.with_source(source))
}

struct NativeActionTarget {
    child: GroupChild,
}

impl NativeActionTarget {
    fn spawn(nonce: &str, timeout: Duration) -> Result<Self, &'static str> {
        let mut command = native_action_command(nonce, timeout)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
            .group_spawn()
            .map(|child| Self { child })
            .map_err(|_| "native_readiness_target_unavailable")
    }

    fn wait_for_success(&mut self, deadline: Instant) -> Result<(), &'static str> {
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) => return Err("native_readiness_action_not_observed"),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => return Err("native_readiness_timed_out"),
                Err(_) => return Err("native_readiness_target_failed"),
            }
        }
    }
}

impl Drop for NativeActionTarget {
    fn drop(&mut self) {
        let _ = crate::codex_capabilities::terminate_group(&mut self.child);
    }
}

#[cfg(windows)]
fn native_action_command(nonce: &str, _timeout: Duration) -> Result<Command, &'static str> {
    let script = windows_native_readiness_target_source(nonce);
    let mut command = Command::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-STA", "-Command", &script]);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn native_action_command(nonce: &str, timeout: Duration) -> Result<Command, &'static str> {
    let script = macos_native_readiness_target_source(nonce);
    let mut command = Command::new("/usr/bin/osascript");
    command.args([
        "-l",
        "JavaScript",
        "-e",
        &format!(
            "const readinessTimeoutSeconds = {};\n{script}",
            timeout.as_secs().max(1)
        ),
    ]);
    Ok(command)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn native_action_command(_nonce: &str, _timeout: Duration) -> Result<Command, &'static str> {
    Err("unsupported_host_platform")
}

fn native_readiness_prompt(nonce: &str) -> String {
    format!(
        "Use native Computer Use, not shell or file tools, in the private topmost 'Satelle Native Readiness' window. Independently click the button labeled {nonce}, then drag the 'Drag from here' control into the 'Drop here' target. Stop only after both actions are complete."
    )
}

#[cfg(any(test, windows))]
fn windows_native_readiness_target_source(nonce: &str) -> String {
    r#"
$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationFramework
$window=New-Object Windows.Window
$window.Title='Satelle Native Readiness'
$window.Width=640
$window.Height=300
$window.Topmost=$true
$window.ShowInTaskbar=$false
$window.WindowStartupLocation='CenterScreen'
$window.Tag='failed'

$clickConfirmed=$false
$dragConfirmed=$false
$dragStarted=$false
$dragMoved=$false

$grid=New-Object Windows.Controls.Grid
$grid.Margin=20
1..3 | ForEach-Object {
    $row=New-Object Windows.Controls.RowDefinition
    $row.Height='*'
    [void]$grid.RowDefinitions.Add($row)
}

$instructions=New-Object Windows.Controls.TextBlock
$instructions.Text='Complete both independent pointer actions'
$instructions.FontSize=18
$instructions.HorizontalAlignment='Center'
[Windows.Controls.Grid]::SetRow($instructions,0)
[void]$grid.Children.Add($instructions)

$clickButton=New-Object Windows.Controls.Button
$clickButton.Name='pointer_click_confirmed'
$clickButton.Content='__NONCE__'
$clickButton.FontSize=22
$clickButton.Margin=8
$clickButton.Add_Click({
    $script:clickConfirmed=$true
    if ($clickConfirmed -and $dragConfirmed) {
        $window.Tag='passed'
        $window.Close()
    }
})
[Windows.Controls.Grid]::SetRow($clickButton,1)
[void]$grid.Children.Add($clickButton)

$dragGrid=New-Object Windows.Controls.Grid
1..2 | ForEach-Object {
    $column=New-Object Windows.Controls.ColumnDefinition
    $column.Width='*'
    [void]$dragGrid.ColumnDefinitions.Add($column)
}
$dragSource=New-Object Windows.Controls.Button
$dragSource.Content='Drag from here'
$dragSource.Margin=12
$dragSource.Add_MouseDown({
    $script:dragStarted=$true
    $script:dragMoved=$false
    [void]$dragSource.CaptureMouse()
})
$dragSource.Add_MouseMove({
    param($sender,$event)
    if ($dragStarted -and $event.LeftButton -eq 'Pressed') {
        $script:dragMoved=$true
    }
})
$dragSource.Add_MouseUp({
    param($sender,$event)
    $point=$event.GetPosition($dropTarget)
    $inside=$point.X -ge 0 -and $point.Y -ge 0 -and
        $point.X -le $dropTarget.ActualWidth -and $point.Y -le $dropTarget.ActualHeight
    $dragSource.ReleaseMouseCapture()
    if ($dragStarted -and $dragMoved -and $inside) {
        $script:dragConfirmed=$true
    }
    $script:dragStarted=$false
    if ($clickConfirmed -and $dragConfirmed) {
        $window.Tag='passed'
        $window.Close()
    }
})
[Windows.Controls.Grid]::SetColumn($dragSource,0)
[void]$dragGrid.Children.Add($dragSource)

$dropTarget=New-Object Windows.Controls.Border
$dropTarget.Name='pointer_drag_confirmed'
$dropTarget.BorderBrush='DarkGreen'
$dropTarget.BorderThickness=3
$dropTarget.CornerRadius=8
$dropTarget.Margin=12
$dropLabel=New-Object Windows.Controls.TextBlock
$dropLabel.Text='Drop here'
$dropLabel.FontSize=20
$dropLabel.HorizontalAlignment='Center'
$dropLabel.VerticalAlignment='Center'
$dropTarget.Child=$dropLabel
[Windows.Controls.Grid]::SetColumn($dropTarget,1)
[void]$dragGrid.Children.Add($dropTarget)

[Windows.Controls.Grid]::SetRow($dragGrid,2)
[void]$grid.Children.Add($dragGrid)
$window.Content=$grid
[void]$window.ShowDialog()
if ($window.Tag -eq 'passed') { exit 0 } else { exit 1 }
"#
    .replace("__NONCE__", nonce)
}

#[cfg(any(test, target_os = "macos"))]
fn macos_native_readiness_target_source(nonce: &str) -> String {
    r#"
ObjC.import('Cocoa')
ObjC.import('stdlib')

const app = $.NSApplication.sharedApplication
app.setActivationPolicy($.NSApplicationActivationPolicyAccessory)
const style = $.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable
const panel = $.NSPanel.alloc.initWithContentRectStyleMaskBackingDefer(
    $.NSMakeRect(0, 0, 640, 300),
    style,
    $.NSBackingStoreBuffered,
    false
)
panel.title = 'Satelle Native Readiness'
panel.level = $.NSFloatingWindowLevel
panel.hidesOnDeactivate = false
panel.center

function makeButton(title, frame) {
    const button = $.NSButton.alloc.initWithFrame(frame)
    button.title = title
    button.bezelStyle = $.NSBezelStyleRounded
    panel.contentView.addSubview(button)
    return button
}

const clickButton = makeButton('__NONCE__', $.NSMakeRect(170, 170, 300, 60))
clickButton.identifier = 'pointer_click_confirmed'
const dragSource = makeButton('Drag from here', $.NSMakeRect(70, 55, 200, 65))
const dropTarget = makeButton('Drop here', $.NSMakeRect(370, 55, 200, 65))
dropTarget.identifier = 'pointer_drag_confirmed'

panel.orderFrontRegardless
app.activateIgnoringOtherApps(true)

let clickConfirmed = false
let dragConfirmed = false
let clickStarted = false
let dragStarted = false
let dragMoved = false
const deadline = Date.now() + readinessTimeoutSeconds * 1000

function contains(rect, point) {
    return point.x >= rect.origin.x &&
        point.y >= rect.origin.y &&
        point.x <= rect.origin.x + rect.size.width &&
        point.y <= rect.origin.y + rect.size.height
}

const eventMask = $.NSEventMaskLeftMouseDown |
    $.NSEventMaskLeftMouseDragged |
    $.NSEventMaskLeftMouseUp
const localHandler = ObjC.block(['id', ['id']], function(event) {
    if (Number(event.window.windowNumber) !== Number(panel.windowNumber)) {
        return event
    }
    const point = event.locationInWindow
    const eventType = Number(event.type)
    if (eventType === Number($.NSEventTypeLeftMouseDown)) {
        clickStarted = contains(clickButton.frame, point)
        dragStarted = contains(dragSource.frame, point)
        dragMoved = false
    } else if (eventType === Number($.NSEventTypeLeftMouseDragged) && dragStarted) {
        dragMoved = true
    } else if (eventType === Number($.NSEventTypeLeftMouseUp)) {
        clickConfirmed = clickConfirmed || (clickStarted && contains(clickButton.frame, point))
        dragConfirmed = dragConfirmed ||
            (dragStarted && dragMoved && contains(dropTarget.frame, point))
        clickStarted = false
        dragStarted = false
    }
    return event
})
const localMonitor = $.NSEvent.addLocalMonitorForEventsMatchingMaskHandler(
    eventMask,
    localHandler
)

while (Date.now() < deadline && !(clickConfirmed && dragConfirmed)) {
    $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.01))
}

$.NSEvent.removeMonitor(localMonitor)
panel.close
$.exit(clickConfirmed && dragConfirmed ? 0 : 1)
"#
    .replace("__NONCE__", nonce)
}

struct NativePrerequisiteObservations {
    os_permission_state: ReadinessObservationState,
    app_approval_state: ReadinessObservationState,
    os_fingerprint_material: String,
    app_fingerprint_material: String,
}

fn native_prerequisite_observations(
    platform: &str,
    desktop: &satelle_core::DesktopSessionRecord,
    app_policy_surface: crate::codex_capabilities::EvidenceSurface,
) -> NativePrerequisiteObservations {
    let os_permission_state = if platform == "windows" {
        // Desktop resolution already proved this exact session is active,
        // visible, and has one unambiguous console/remote ownership mode.
        ReadinessObservationState::Granted
    } else {
        // macOS preflight APIs describe the calling Host process, not the
        // managed Codex process that drives the desktop. Reporting that value
        // as Codex permission would create a false grant or false denial.
        ReadinessObservationState::Unknown
    };
    NativePrerequisiteObservations {
        os_permission_state,
        app_approval_state: ReadinessObservationState::Unknown,
        os_fingerprint_material: format!(
            "{}:{}:{}:{}",
            desktop.state, desktop.session_kind, desktop.is_console, desktop.is_remote
        ),
        app_fingerprint_material: app_policy_fingerprint_material(platform, app_policy_surface),
    }
}

fn app_policy_fingerprint_material(
    platform: &str,
    observed: crate::codex_capabilities::EvidenceSurface,
) -> String {
    if platform != "windows" {
        return "app_policy:not_observable".to_string();
    }
    let classified = match observed {
        crate::codex_capabilities::EvidenceSurface::Stable => "stable",
        crate::codex_capabilities::EvidenceSurface::Absent => "absent",
        crate::codex_capabilities::EvidenceSurface::Incomplete => "incomplete",
        _ => "incomplete",
    };
    format!("windows_app_policy:{classified}")
}

fn readiness_fingerprint(
    domain: &str,
    platform: &str,
    desktop: &str,
    state: ReadinessObservationState,
    observation: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"satelle-native-readiness-v2\0");
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(platform.as_bytes());
    digest.update([0]);
    digest.update(desktop.as_bytes());
    digest.update([0]);
    digest.update(state.as_str().as_bytes());
    digest.update([0]);
    digest.update(observation.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn model_override(value: &str) -> Option<&str> {
    (value != DEFAULT_MODEL_BINDING).then_some(value)
}

fn provider_override(value: &str) -> Option<&str> {
    (value != DEFAULT_PROVIDER_BINDING).then_some(value)
}

fn provider_cache_for_preflight(
    cached: Option<ProviderSmokeResult>,
    refresh: bool,
) -> Option<ProviderSmokeResult> {
    if refresh { None } else { cached }
}

fn matching_cached_evidence(
    key: &ReadinessCacheKey,
    cached: Option<ReadinessEvidence>,
) -> Option<ReadinessEvidence> {
    cached.filter(|evidence| !key_has_denied_observation(key) && key.matches_evidence(evidence))
}

fn native_readiness_failure(reason: &'static str) -> SatelleError {
    let mut details = std::collections::BTreeMap::new();
    details.insert("reason".to_string(), Value::String(reason.to_string()));
    details.insert(
        "native_readiness".to_string(),
        serde_json::json!({
            "source": "live",
            "status": NativeReadinessCheckStatus::Failed.as_str(),
            "checks": [
                readiness_check(
                    NativeReadinessCheckKind::CodexRuntime,
                    NativeReadinessCheckStatus::Passed,
                    "codex_runtime_available",
                ),
                readiness_check(
                    NativeReadinessCheckKind::Authentication,
                    NativeReadinessCheckStatus::Passed,
                    "authentication_available",
                ),
                readiness_check(
                    NativeReadinessCheckKind::NativeComputerUse,
                    NativeReadinessCheckStatus::Passed,
                    "native_computer_use_available",
                ),
                readiness_check(
                    NativeReadinessCheckKind::OsPermissions,
                    NativeReadinessCheckStatus::NotEvaluated,
                    "live_proof_not_completed",
                ),
                readiness_check(
                    NativeReadinessCheckKind::AppApproval,
                    NativeReadinessCheckStatus::NotEvaluated,
                    "live_proof_not_completed",
                ),
                readiness_check(
                    NativeReadinessCheckKind::ControlPlane,
                    NativeReadinessCheckStatus::Passed,
                    "control_plane_admitted",
                ),
                readiness_check(
                    NativeReadinessCheckKind::PointerClick,
                    NativeReadinessCheckStatus::Failed,
                    reason,
                ),
                readiness_check(
                    NativeReadinessCheckKind::PointerDrag,
                    NativeReadinessCheckStatus::Failed,
                    reason,
                ),
                readiness_check(
                    NativeReadinessCheckKind::FileManagement,
                    NativeReadinessCheckStatus::NotEvaluated,
                    "not_required_for_prompt_admission",
                ),
            ],
        }),
    );
    SatelleError {
        code: ErrorCode::ComputerUseNotReady,
        message: "native Computer Use did not pass the Host action-path smoke test".to_string(),
        recovery_command: Some("satelle doctor --scope computer-use --refresh --json".to_string()),
        source_detail: None,
        details,
    }
}

fn native_readiness_manual_action_failure(
    os_permission_state: ReadinessObservationState,
    app_approval_state: ReadinessObservationState,
) -> SatelleError {
    let os_status = observation_check_status(os_permission_state);
    let app_status = observation_check_status(app_approval_state);
    let checks = serde_json::json!([
        readiness_check(
            NativeReadinessCheckKind::CodexRuntime,
            NativeReadinessCheckStatus::Passed,
            "codex_runtime_available",
        ),
        readiness_check(
            NativeReadinessCheckKind::Authentication,
            NativeReadinessCheckStatus::Passed,
            "authentication_available",
        ),
        readiness_check(
            NativeReadinessCheckKind::NativeComputerUse,
            NativeReadinessCheckStatus::Passed,
            "native_computer_use_available",
        ),
        readiness_check(
            NativeReadinessCheckKind::OsPermissions,
            os_status.0,
            os_status.1
        ),
        readiness_check(
            NativeReadinessCheckKind::AppApproval,
            app_status.0,
            app_status.1
        ),
        readiness_check(
            NativeReadinessCheckKind::ControlPlane,
            NativeReadinessCheckStatus::Passed,
            "control_plane_admitted",
        ),
        readiness_check(
            NativeReadinessCheckKind::PointerClick,
            NativeReadinessCheckStatus::NotEvaluated,
            "blocked_by_prerequisite",
        ),
        readiness_check(
            NativeReadinessCheckKind::PointerDrag,
            NativeReadinessCheckStatus::NotEvaluated,
            "blocked_by_prerequisite",
        ),
        readiness_check(
            NativeReadinessCheckKind::FileManagement,
            NativeReadinessCheckStatus::NotEvaluated,
            "not_required_for_prompt_admission",
        ),
    ]);
    let mut details = std::collections::BTreeMap::new();
    details.insert(
        "reason".to_string(),
        Value::String("native_readiness_manual_action_required".to_string()),
    );
    details.insert(
        "native_readiness".to_string(),
        serde_json::json!({
            "source": "live",
            "status": NativeReadinessCheckStatus::ManualActionRequired.as_str(),
            "checks": checks,
        }),
    );
    SatelleError {
        code: ErrorCode::ComputerUseNotReady,
        message: "native Computer Use requires a manual permission or app approval change"
            .to_string(),
        recovery_command: Some("satelle doctor --scope computer-use --refresh --json".to_string()),
        source_detail: None,
        details,
    }
}

fn key_has_denied_observation(key: &ReadinessCacheKey) -> bool {
    key.os_permission_state() == ReadinessObservationState::Denied
        || key.app_approval_state() == ReadinessObservationState::Denied
}

fn native_observation_blocker(key: &ReadinessCacheKey) -> Option<SatelleError> {
    key_has_denied_observation(key).then(|| {
        native_readiness_manual_action_failure(key.os_permission_state(), key.app_approval_state())
    })
}

fn denied_native_probe_result(
    key: &ReadinessCacheKey,
    evidence: &ReadinessEvidence,
) -> Option<NativeProbeResult> {
    native_observation_blocker(key).map(|error| NativeProbeResult::Failed {
        evidence: evidence.clone(),
        reason: "native_readiness_manual_action_required",
        error,
        dispatch_possible: false,
    })
}

fn observation_check_status(
    state: ReadinessObservationState,
) -> (NativeReadinessCheckStatus, &'static str) {
    match state {
        ReadinessObservationState::Granted => {
            (NativeReadinessCheckStatus::Passed, "observation_granted")
        }
        ReadinessObservationState::Denied => (
            NativeReadinessCheckStatus::ManualActionRequired,
            "observation_denied",
        ),
        ReadinessObservationState::Unknown => (
            NativeReadinessCheckStatus::NotEvaluated,
            "observation_unknown",
        ),
    }
}

fn readiness_check(
    kind: NativeReadinessCheckKind,
    status: NativeReadinessCheckStatus,
    reason: &'static str,
) -> Value {
    let check = NativeReadinessCheck::new(kind, status, reason);
    serde_json::json!({
        "kind": check.kind().as_str(),
        "status": check.status().as_str(),
        "reason": check.reason(),
    })
}

fn native_smoke_failure(reason: &'static str) -> NativeSmokeFailure {
    NativeSmokeFailure {
        reason,
        error: Box::new(native_readiness_failure(reason)),
        dispatch_possible: false,
    }
}

fn native_smoke_session_failure(failure: CodexSessionFailure) -> NativeSmokeFailure {
    let reason = match failure.error() {
        CodexSessionError::Timeout => "native_readiness_timed_out",
        CodexSessionError::Persistence => "native_readiness_persistence_failed",
        _ => "native_readiness_session_failed",
    };
    NativeSmokeFailure {
        reason,
        error: Box::new(native_readiness_failure(reason)),
        dispatch_possible: failure.turn_dispatch_attempted(),
    }
}

fn classify_native_probe_run(
    run: crate::codex_session::TimedCodexSessionRun,
) -> Result<CodexSessionTerminal, NativeSmokeFailure> {
    if let Err(failure) = &run.result
        && !failure.turn_dispatch_attempted()
    {
        return Err(native_smoke_session_failure(*failure));
    }
    if let Some(observation) = run.cancellation {
        return Err(native_readiness_timeout_after_cancellation(observation));
    }
    run.result.map_err(native_smoke_session_failure)
}

fn native_readiness_timeout_after_cancellation(observation: StopObservation) -> NativeSmokeFailure {
    let reason = "native_readiness_timed_out";
    let mut error = SatelleError::native_readiness_timeout();
    error
        .details
        .insert("reason".to_string(), Value::String(reason.to_string()));
    let cancellation = match observation {
        StopObservation::CancellationConfirmed | StopObservation::UpstreamInactiveConfirmed => {
            "confirmed"
        }
        StopObservation::UpstreamStillActive => "upstream_still_active",
        StopObservation::OutcomeUnknown => "outcome_unknown",
    };
    error.details.insert(
        "native_readiness_cancellation".to_string(),
        Value::String(cancellation.to_string()),
    );
    NativeSmokeFailure {
        reason,
        error: Box::new(error),
        dispatch_possible: true,
    }
}

fn mark_probe_dispatch_possible(mut error: SatelleError, possible: bool) -> SatelleError {
    error
        .details
        .insert("probe_dispatch_possible".to_string(), Value::Bool(possible));
    error
}

fn probe_dispatch_possible(error: &SatelleError) -> bool {
    error
        .details
        .get("probe_dispatch_possible")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn probe_cancellation_observation(
    dispatch_possible: bool,
    error: &SatelleError,
    cancellation_detail: &str,
) -> StopObservation {
    if dispatch_possible {
        stop_observation_from_detail(error, cancellation_detail)
    } else {
        StopObservation::UpstreamInactiveConfirmed
    }
}

fn preflight_cancellation_observation(result: &AdapterPreflight) -> StopObservation {
    match result {
        AdapterPreflight::ProviderFailed { error, .. }
        | AdapterPreflight::UncachedFailure(error) => probe_cancellation_observation(
            probe_dispatch_possible(error),
            error,
            "provider_smoke_cancellation",
        ),
        AdapterPreflight::Failed {
            error,
            dispatch_possible,
            ..
        } => probe_cancellation_observation(
            *dispatch_possible,
            error,
            "native_readiness_cancellation",
        ),
        AdapterPreflight::Cancelled(observation) => *observation,
        AdapterPreflight::Ready(_) => StopObservation::UpstreamInactiveConfirmed,
    }
}

fn provider_smoke_session_failure(error: CodexSessionError) -> SatelleError {
    let (code, reason) = match error {
        CodexSessionError::Timeout => (
            ErrorCode::ProviderSmokeTestTimeout,
            "provider_smoke_test_timed_out",
        ),
        CodexSessionError::ResponseError => (
            ErrorCode::UnsupportedProviderComputerUse,
            "provider_smoke_provider_rejected",
        ),
        CodexSessionError::Spawn => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_spawn_failed",
        ),
        CodexSessionError::Write => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_write_failed",
        ),
        CodexSessionError::MalformedMessage => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_malformed_message",
        ),
        CodexSessionError::OversizedMessage => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_oversized_message",
        ),
        CodexSessionError::UnexpectedResponse => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_unexpected_response",
        ),
        CodexSessionError::DuplicateResponse => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_duplicate_response",
        ),
        CodexSessionError::ConflictingIdentity => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_conflicting_identity",
        ),
        CodexSessionError::PrematureExit => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_premature_exit",
        ),
        CodexSessionError::Persistence => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_persistence_failed",
        ),
        CodexSessionError::Containment => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_containment_failed",
        ),
        CodexSessionError::Control => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_control_failed",
        ),
    };
    provider_smoke_error(code, reason)
}

fn provider_probe_session_failure(failure: CodexSessionFailure) -> SatelleError {
    mark_probe_dispatch_possible(
        provider_smoke_session_failure(failure.error()),
        failure.turn_dispatch_attempted(),
    )
}

fn classify_provider_probe_run(
    run: crate::codex_session::TimedCodexSessionRun,
) -> Result<CodexSessionTerminal, SatelleError> {
    if let Err(failure) = &run.result
        && !failure.turn_dispatch_attempted()
    {
        return Err(provider_probe_session_failure(*failure));
    }
    if let Some(observation) = run.cancellation {
        return Err(provider_smoke_timeout_after_cancellation(observation));
    }
    run.result.map_err(provider_probe_session_failure)
}

fn provider_smoke_timeout_after_cancellation(observation: StopObservation) -> SatelleError {
    let mut error = provider_smoke_session_failure(CodexSessionError::Timeout);
    let cancellation = match observation {
        StopObservation::CancellationConfirmed | StopObservation::UpstreamInactiveConfirmed => {
            "confirmed"
        }
        StopObservation::UpstreamStillActive => "upstream_still_active",
        StopObservation::OutcomeUnknown => "outcome_unknown",
    };
    error.details.insert(
        "provider_smoke_cancellation".to_string(),
        Value::String(cancellation.to_string()),
    );
    mark_probe_dispatch_possible(error, true)
}

fn provider_smoke_failure(error: crate::provider_probe::ProviderProbeError) -> SatelleError {
    let (code, reason) = match error {
        crate::provider_probe::ProviderProbeError::TimedOut => (
            ErrorCode::ProviderSmokeTestTimeout,
            "provider_smoke_test_timed_out",
        ),
        crate::provider_probe::ProviderProbeError::InvalidRequest => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_callback_invalid",
        ),
        crate::provider_probe::ProviderProbeError::Cancelled => {
            (ErrorCode::ComputerUseNotReady, "provider_smoke_cancelled")
        }
        crate::provider_probe::ProviderProbeError::Bind(_)
        | crate::provider_probe::ProviderProbeError::Random(_)
        | crate::provider_probe::ProviderProbeError::Io(_)
        | crate::provider_probe::ProviderProbeError::WorkerSpawn(_)
        | crate::provider_probe::ProviderProbeError::WorkerStopped => (
            ErrorCode::ComputerUseNotReady,
            "provider_smoke_surface_unavailable",
        ),
    };
    provider_smoke_error(code, reason)
}

fn provider_smoke_error(code: ErrorCode, reason: &str) -> SatelleError {
    let mut details = std::collections::BTreeMap::new();
    details.insert("reason".to_string(), Value::String(reason.to_string()));
    SatelleError {
        code,
        message: "the selected provider did not pass the live Computer Use smoke test".to_string(),
        recovery_command: Some(
            "rerun the original satelle run or steer command with --refresh-provider-smoke-test"
                .to_string(),
        ),
        source_detail: None,
        details,
    }
}

fn provider_smoke_error_from_failure(failure: &ProviderSmokeFailureEvidence) -> SatelleError {
    annotate_provider_smoke_error(
        provider_smoke_error(failure.error_code(), failure.failure_reason()),
        failure.source(),
        failure.observed_at(),
        failure.expires_at(),
    )
}

fn annotate_provider_smoke_error(
    mut error: SatelleError,
    source: ProviderSmokeSource,
    observed_at: time::OffsetDateTime,
    expires_at: time::OffsetDateTime,
) -> SatelleError {
    let age_ms = (time::OffsetDateTime::now_utc() - observed_at)
        .whole_milliseconds()
        .clamp(0, i128::from(u64::MAX)) as u64;
    error.details.extend([
        (
            "provider_smoke_status".to_string(),
            Value::String("failed".to_string()),
        ),
        (
            "provider_smoke_source".to_string(),
            Value::String(source.as_str().to_string()),
        ),
        (
            "provider_smoke_observed_at".to_string(),
            Value::String(
                observed_at
                    .format(&Rfc3339)
                    .expect("provider evidence timestamp is RFC 3339 representable"),
            ),
        ),
        (
            "provider_smoke_expires_at".to_string(),
            Value::String(
                expires_at
                    .format(&Rfc3339)
                    .expect("provider evidence expiry is RFC 3339 representable"),
            ),
        ),
        ("provider_smoke_age_ms".to_string(), Value::from(age_ms)),
    ]);
    error
}

impl ComputerUseAdapter for ProductionComputerUseAdapter {
    fn admit_operation(&self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        let snapshot = crate::read_production_snapshot(&self.snapshot)?;
        // Preserve the operation-specific control-plane diagnosis before the
        // broader native execution verdict. Stop and status intentionally end
        // here so recovery remains available after execution readiness is lost.
        snapshot.control_plane_admission.admit(operation)?;
        if matches!(
            operation,
            ControlPlaneOperation::Run | ControlPlaneOperation::Steer
        ) {
            supported_execution_version(&snapshot)?;
        }
        Ok(())
    }

    fn requires_upstream_thread_for_follow_up(&self) -> bool {
        true
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.preflight_terminal(host, None, None, provider_intent)
            .into_result()
    }

    fn readiness_cache_key(
        &self,
        _host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ReadinessCacheKey>, SatelleError> {
        self.native_readiness_key(provider_intent).map(Some)
    }

    fn preflight_terminal(
        &self,
        _host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
    ) -> AdapterPreflight {
        let mut persist_thread_ref = |_value: &str| Ok(());
        let mut persist_turn_ref = |_value: &str| Ok(());
        let mut persistence = ProviderProbePersistence {
            persist_thread_ref: &mut persist_thread_ref,
            persist_turn_ref: &mut persist_turn_ref,
        };
        self.preflight_terminal_inner(
            provider_intent,
            cached,
            cached_provider,
            None,
            &mut persistence,
        )
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        let policy = request.execution_policy();
        dispatch_with_configured_desktop_target(
            policy,
            || self.resolve_configured_desktop_target(),
            || {
                let approval_policy = codex_approval_policy(policy.approval_policy())?;
                let sandbox_policy = codex_sandbox_policy(policy.sandbox_policy());
                let timeout = Duration::from_secs(u64::from(policy.timeout_policy().seconds()));
                let deadline = Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(|| adapter_failure("timeout_unrepresentable"))?;
                let cancellation_deadline = deadline
                    .checked_add(READINESS_CANCELLATION_GRACE)
                    .unwrap_or(deadline);
                let working_directory = self
                    .working_directory
                    .as_ref()
                    .map_err(Clone::clone)
                    .and_then(|path| prepare_working_directory(path))?;
                let control = CodexSessionControl::new(cancellation_deadline);
                let _active_execution =
                    self.register_execution(request.subject(), control.clone())?;
                tracing::debug!(
                    session_id = %request.subject().session_id(),
                    turn_id = %request.subject().turn_id(),
                    "starting Codex native Computer Use execution"
                );

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
                let snapshot = crate::read_production_snapshot(&self.snapshot)?;
                let goal_set_supported = snapshot.goal_set_supported();
                let image_input_mode = snapshot.image_input_mode();
                if !request.attachments().is_empty()
                    && matches!(
                        image_input_mode,
                        crate::codex_capabilities::CodexImageInputMode::Unsupported
                    )
                {
                    return Err(SatelleError::invalid_usage(
                        "the selected Codex protocol does not support image input",
                    ));
                }
                let run = run_codex_session_with_timeout_cancellation(
                    preserve_managed_codex_error(
                        crate::codex_capabilities::installed_app_server_command(),
                    )?,
                    CodexSessionRequest {
                        working_directory: &working_directory,
                        prompt: request.prompt(),
                        existing_thread_ref: request.upstream_thread_ref(),
                        model: model_override(policy.effective_model().as_str()),
                        model_provider: provider_override(policy.provider_binding().as_str()),
                        execution_mode: request.execution_mode(),
                        approval_policy,
                        sandbox_policy,
                        deadline,
                        persist_thread_ref: &mut persist_thread_ref,
                        persist_turn_ref: &mut persist_turn_ref,
                        control: Some(control),
                        goal_set_supported,
                        image_input_mode,
                        attachments: request.attachments(),
                    },
                    READINESS_CANCELLATION_GRACE,
                    None,
                );
                finish_timed_turn_execution(run, persistence_error.into_inner())
            },
        )
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

impl ReadinessProbeDriver for ProductionComputerUseAdapter {
    fn run_native_probe(
        &self,
        key: &ReadinessCacheKey,
        cancellation: &super::request::AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> NativeProbeResult {
        let observed_at = time::OffsetDateTime::now_utc();
        let Some(expires_at) = observed_at.checked_add(self.native_readiness_ttl) else {
            return NativeProbeResult::UncachedFailure(adapter_failure("readiness_ttl_invalid"));
        };
        let evidence = match key.evidence(
            format!("native-readiness-{}", satelle_core::SessionId::new()),
            observed_at,
            expires_at,
        ) {
            Ok(evidence) => evidence,
            Err(_) => {
                return NativeProbeResult::UncachedFailure(adapter_failure(
                    "readiness_evidence_invalid",
                ));
            }
        };
        if let Some(result) = denied_native_probe_result(key, &evidence) {
            return result;
        }
        match self.run_native_smoke(Some(cancellation), persist_thread_ref, persist_turn_ref) {
            Ok(()) => NativeProbeResult::Passed(evidence),
            Err(failure) if cancellation.is_requested() => {
                let observation = probe_cancellation_observation(
                    failure.dispatch_possible,
                    &failure.error,
                    "native_readiness_cancellation",
                );
                NativeProbeResult::Cancelled(observation)
            }
            Err(failure) => NativeProbeResult::Failed {
                evidence,
                reason: failure.reason,
                error: *failure.error,
                dispatch_possible: failure.dispatch_possible,
            },
        }
    }

    fn preflight_terminal_with_provider_probe(
        &self,
        _host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
        cancellation: &super::request::AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        let mut persistence = ProviderProbePersistence {
            persist_thread_ref,
            persist_turn_ref,
        };
        let result = self.preflight_terminal_inner(
            provider_intent,
            cached,
            cached_provider,
            Some(cancellation),
            &mut persistence,
        );
        if cancellation.is_requested() {
            AdapterPreflight::Cancelled(preflight_cancellation_observation(&result))
        } else {
            result
        }
    }

    fn observe_readiness_probe(
        &self,
        subject: &crate::storage::ProbeRecoverySubject,
    ) -> RecoveryObservation {
        match self.read_readiness_probe_turn(subject) {
            Some(CodexTurnStatus::InProgress) => RecoveryObservation::Running,
            Some(
                CodexTurnStatus::Completed | CodexTurnStatus::Interrupted | CodexTurnStatus::Failed,
            ) => RecoveryObservation::Completed,
            None => RecoveryObservation::Unknown,
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

fn stop_observation_from_detail(error: &SatelleError, field: &str) -> StopObservation {
    match error.details.get(field).and_then(Value::as_str) {
        Some("confirmed") => StopObservation::CancellationConfirmed,
        Some("upstream_still_active") => StopObservation::UpstreamStillActive,
        Some("outcome_unknown") | None => StopObservation::OutcomeUnknown,
        Some(_) => StopObservation::OutcomeUnknown,
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

fn dispatch_with_configured_desktop_target<T>(
    policy: &ExecutionPolicy,
    resolve_configured: impl FnOnce() -> Result<DesktopTarget, SatelleError>,
    dispatch: impl FnOnce() -> Result<T, SatelleError>,
) -> Result<T, SatelleError> {
    let configured = resolve_configured()?;
    if policy.desktop_target() != &configured {
        return Err(SatelleError::desktop_session_unavailable(Some(
            policy.desktop_target().binding().as_str(),
        )));
    }
    dispatch()
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

fn finish_timed_turn_execution(
    run: TimedCodexSessionRun,
    persistence_error: Option<SatelleError>,
) -> Result<ExecuteResult, SatelleError> {
    let Some(cancellation) = run.cancellation else {
        return finish_execution(run.result, persistence_error);
    };
    if let (Err(failure), Some(error)) = (&run.result, persistence_error)
        && failure.turn_dispatch_attempted()
    {
        return Err(error);
    }
    if matches!(
        &run.result,
        Err(failure) if failure.error() == CodexSessionError::Containment
    ) {
        return Err(session_failure(CodexSessionError::Containment));
    }
    match run.result {
        result @ Ok(
            CodexSessionTerminal::Completed
            | CodexSessionTerminal::Interrupted
            | CodexSessionTerminal::Failed,
        ) => terminal_result(result),
        Ok(CodexSessionTerminal::StoppedByControl) | Err(_)
            if matches!(
                cancellation,
                StopObservation::CancellationConfirmed | StopObservation::UpstreamInactiveConfirmed
            ) =>
        {
            Ok(ExecuteResult::terminal_failure(session_failure(
                CodexSessionError::Timeout,
            )))
        }
        Ok(CodexSessionTerminal::StoppedByControl) | Err(_) => {
            Err(session_failure(CodexSessionError::Timeout))
        }
    }
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

fn preserve_managed_codex_error(
    command: Result<Command, SatelleError>,
) -> Result<Command, SatelleError> {
    command
}

fn host_turn_timeout_ceiling() -> Result<TimeoutPolicy, SatelleError> {
    TimeoutPolicy::bounded_seconds((satelle_core::MAX_TURN_EXECUTION_TIMEOUT_MS / 1_000) as u32)
        .map_err(|_| adapter_failure("timeout_policy_invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution_policy_for(desktop_binding: &str, desktop_session_id: &str) -> ExecutionPolicy {
        ExecutionPolicy::new(
            EffectiveModelRef::new(DEFAULT_MODEL_BINDING).unwrap(),
            ProviderBindingRef::new(DEFAULT_PROVIDER_BINDING).unwrap(),
            DesktopTarget::new(
                DesktopBindingRef::new(desktop_binding).unwrap(),
                desktop_session_id,
            ),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
        )
    }

    fn native_readiness_test_key(
        desktop_session_id: &str,
        os_permission_state: ReadinessObservationState,
        app_approval_state: ReadinessObservationState,
    ) -> ReadinessCacheKey {
        let desktop_binding = DesktopBindingRef::new("readiness-test-desktop").unwrap();
        ReadinessCacheKey::new(
            NATIVE_ADAPTER,
            desktop_binding.clone(),
            execution_policy_for(desktop_binding.as_str(), desktop_session_id),
            "0.144.0",
            "codex-native-0.144.0",
            None::<String>,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            os_permission_state,
            app_approval_state,
        )
        .unwrap()
    }

    #[test]
    fn configured_desktop_mismatch_is_rejected_before_codex_dispatch() {
        let dispatch_attempted = std::cell::Cell::new(false);
        let error = dispatch_with_configured_desktop_target(
            &execution_policy_for("admitted-desktop", "admitted-session"),
            || {
                Ok(DesktopTarget::new(
                    DesktopBindingRef::new("configured-desktop").unwrap(),
                    "configured-session",
                ))
            },
            || {
                dispatch_attempted.set(true);
                Ok(())
            },
        )
        .expect_err("a changed Desktop Binding must block Codex dispatch");

        assert_eq!(error.code, ErrorCode::DesktopSessionUnavailable);
        assert_eq!(error.details["desktop_user"], "admitted-desktop");
        assert!(
            !dispatch_attempted.get(),
            "Desktop Binding enforcement must run before Codex dispatch"
        );
    }

    #[test]
    fn configured_desktop_session_mismatch_is_rejected_before_codex_dispatch() {
        let dispatch_attempted = std::cell::Cell::new(false);
        let error = dispatch_with_configured_desktop_target(
            &execution_policy_for("configured-desktop", "admitted-session"),
            || {
                Ok(DesktopTarget::new(
                    DesktopBindingRef::new("configured-desktop").unwrap(),
                    "different-session",
                ))
            },
            || {
                dispatch_attempted.set(true);
                Ok(())
            },
        )
        .expect_err("a changed Desktop Session must block Codex dispatch");

        assert_eq!(error.code, ErrorCode::DesktopSessionUnavailable);
        assert_eq!(error.details["desktop_user"], "configured-desktop");
        assert!(
            !dispatch_attempted.get(),
            "Desktop Session enforcement must run before Codex dispatch"
        );
    }

    #[test]
    fn exact_configured_desktop_target_dispatches() {
        let dispatch_attempted = std::cell::Cell::new(false);
        dispatch_with_configured_desktop_target(
            &execution_policy_for("configured-desktop", "configured-session"),
            || {
                Ok(DesktopTarget::new(
                    DesktopBindingRef::new("configured-desktop").unwrap(),
                    "configured-session",
                ))
            },
            || {
                dispatch_attempted.set(true);
                Ok(())
            },
        )
        .expect("an unchanged Desktop Target must dispatch");

        assert!(dispatch_attempted.get());
    }

    #[test]
    fn production_adapter_preserves_managed_codex_integrity_errors() {
        let integrity_error = SatelleError {
            code: ErrorCode::StorageIntegrityFailed,
            message: "managed Codex integrity failed".to_string(),
            recovery_command: None,
            source_detail: None,
            details: std::collections::BTreeMap::from([(
                "reason".to_string(),
                Value::String("immutable_binary_digest_mismatch".to_string()),
            )]),
        };

        let propagated = preserve_managed_codex_error(Err(integrity_error))
            .expect_err("the adapter must not replace an integrity error");

        assert_eq!(propagated.code, ErrorCode::StorageIntegrityFailed);
        assert_eq!(
            propagated.details["reason"],
            Value::String("immutable_binary_digest_mismatch".to_string())
        );
    }

    #[test]
    fn production_host_timeout_ceiling_allows_resolved_limits_through_24_hours() {
        assert_eq!(host_turn_timeout_ceiling().unwrap().seconds(), 24 * 60 * 60);
    }

    #[test]
    fn native_probe_pre_dispatch_result_wins_simultaneous_watchdog_cancellation() {
        let failure = classify_native_probe_run(crate::codex_session::TimedCodexSessionRun {
            result: Err(CodexSessionFailure::before_turn_dispatch_for_test(
                CodexSessionError::Persistence,
            )),
            cancellation: Some(StopObservation::OutcomeUnknown),
        })
        .expect_err("known pre-dispatch failure must win the watchdog race");

        assert_eq!(failure.reason, "native_readiness_persistence_failed");
        assert!(!failure.dispatch_possible);
    }

    #[test]
    fn provider_probe_pre_dispatch_result_wins_simultaneous_watchdog_cancellation() {
        let failure = classify_provider_probe_run(crate::codex_session::TimedCodexSessionRun {
            result: Err(CodexSessionFailure::before_turn_dispatch_for_test(
                CodexSessionError::Persistence,
            )),
            cancellation: Some(StopObservation::OutcomeUnknown),
        })
        .expect_err("known pre-dispatch failure must win the watchdog race");

        assert_eq!(
            failure.details["probe_dispatch_possible"],
            serde_json::Value::Bool(false)
        );
        assert!(
            !failure.details.contains_key("provider_smoke_cancellation"),
            "the unconfirmed watchdog observation must not replace terminal startup evidence"
        );
    }

    #[test]
    fn control_plane_failure_precedes_execution_readiness_for_run_and_steer() {
        let evidence = crate::codex_capabilities::Phase0CapabilityEvidence {
            codex_version: crate::codex_capabilities::CodexVersionEvidence::Detected {
                version: crate::codex_capabilities::REQUIRED_CODEX_VERSION,
            },
            host_platform: crate::codex_capabilities::HostPlatform::Windows,
            capabilities: crate::codex_capabilities::CapabilityMatrix::unproven(),
        };
        let snapshot = Arc::new(RwLock::new(crate::ProductionCapabilitySnapshot {
            evidence,
            verdict: crate::evaluate_phase0_support(evidence),
            control_plane_admission: crate::codex_capabilities::ControlPlaneAdmission::unavailable(
                satelle_core::ControlPlaneFailureReason::HandshakeUnavailable,
            ),
            started_at: "2026-07-17T00:00:00Z".to_string(),
            finished_at: "2026-07-17T00:00:01Z".to_string(),
            duration_ms: 1_000,
        }));
        let adapter = ProductionComputerUseAdapter::new(
            Arc::clone(&snapshot),
            Ok(tempfile::tempdir().unwrap().path().join("codex-work")),
        );

        for operation in [ControlPlaneOperation::Run, ControlPlaneOperation::Steer] {
            let error = adapter
                .admit_operation(operation)
                .expect_err("control-plane admission must precede native readiness");
            assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
            assert_eq!(error.details["operation"], operation.as_str());
        }
        for operation in [ControlPlaneOperation::Stop, ControlPlaneOperation::Status] {
            let error = adapter
                .admit_operation(operation)
                .expect_err("recovery operations must retain control-plane admission");
            assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
            assert_eq!(error.details["operation"], operation.as_str());
        }

        snapshot.write().unwrap().control_plane_admission =
            crate::codex_capabilities::ControlPlaneAdmission::not_applicable();
        for operation in [ControlPlaneOperation::Run, ControlPlaneOperation::Steer] {
            let error = adapter
                .admit_operation(operation)
                .expect_err("execution readiness must still gate run and steer");
            assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
            assert!(error.details.is_empty());
        }
        for operation in [ControlPlaneOperation::Stop, ControlPlaneOperation::Status] {
            adapter
                .admit_operation(operation)
                .expect("recovery operations must remain available without execution readiness");
        }
    }

    #[test]
    fn every_supported_policy_has_one_exact_protocol_mapping() {
        assert_eq!(model_override(DEFAULT_MODEL_BINDING), None);
        assert_eq!(model_override("explicit-model"), Some("explicit-model"));
        assert_eq!(provider_override(DEFAULT_PROVIDER_BINDING), None);
        assert_eq!(
            provider_override("explicit-provider"),
            Some("explicit-provider")
        );
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
    fn provider_smoke_timeout_and_incompatibility_remain_distinct() {
        let timeout = provider_smoke_session_failure(CodexSessionError::Timeout);
        assert_eq!(timeout.code, ErrorCode::ProviderSmokeTestTimeout);
        let unsupported = provider_smoke_session_failure(CodexSessionError::ResponseError);
        assert_eq!(unsupported.code, ErrorCode::UnsupportedProviderComputerUse);
        for failure in [&timeout, &unsupported] {
            assert_eq!(
                failure.recovery_command.as_deref(),
                Some(
                    "rerun the original satelle run or steer command with --refresh-provider-smoke-test"
                )
            );
        }
        for local_failure in [
            CodexSessionError::Spawn,
            CodexSessionError::Write,
            CodexSessionError::MalformedMessage,
            CodexSessionError::OversizedMessage,
            CodexSessionError::UnexpectedResponse,
            CodexSessionError::DuplicateResponse,
            CodexSessionError::ConflictingIdentity,
            CodexSessionError::PrematureExit,
            CodexSessionError::Persistence,
            CodexSessionError::Containment,
            CodexSessionError::Control,
        ] {
            assert_eq!(
                provider_smoke_session_failure(local_failure).code,
                ErrorCode::ComputerUseNotReady
            );
        }
    }

    #[test]
    fn native_readiness_timeout_is_typed_for_every_cancellation_outcome() {
        for (observation, expected_cancellation) in [
            (StopObservation::CancellationConfirmed, "confirmed"),
            (StopObservation::UpstreamInactiveConfirmed, "confirmed"),
            (
                StopObservation::UpstreamStillActive,
                "upstream_still_active",
            ),
            (StopObservation::OutcomeUnknown, "outcome_unknown"),
        ] {
            let failure = native_readiness_timeout_after_cancellation(observation);
            assert_eq!(failure.error.code, ErrorCode::NativeReadinessTimeout);
            assert_eq!(failure.reason, "native_readiness_timed_out");
            assert_eq!(
                failure.error.details["reason"],
                "native_readiness_timed_out"
            );
            assert_eq!(
                failure.error.details["native_readiness_cancellation"],
                expected_cancellation
            );
        }
    }

    #[test]
    fn probe_cancellation_distinguishes_prelaunch_and_postdispatch_failures() {
        let native_prelaunch = native_smoke_session_failure(CodexSessionFailure::after_exchange(
            CodexSessionError::Spawn,
            false,
        ));
        assert_eq!(
            probe_cancellation_observation(
                native_prelaunch.dispatch_possible,
                &native_prelaunch.error,
                "native_readiness_cancellation",
            ),
            StopObservation::UpstreamInactiveConfirmed
        );

        let native_postdispatch = native_smoke_session_failure(
            CodexSessionFailure::after_exchange(CodexSessionError::Write, true),
        );
        assert_eq!(
            probe_cancellation_observation(
                native_postdispatch.dispatch_possible,
                &native_postdispatch.error,
                "native_readiness_cancellation",
            ),
            StopObservation::OutcomeUnknown
        );

        let provider_prelaunch = provider_probe_session_failure(
            CodexSessionFailure::after_exchange(CodexSessionError::Spawn, false),
        );
        assert_eq!(
            probe_cancellation_observation(
                probe_dispatch_possible(&provider_prelaunch),
                &provider_prelaunch,
                "provider_smoke_cancellation",
            ),
            StopObservation::UpstreamInactiveConfirmed
        );

        let provider_postdispatch = provider_probe_session_failure(
            CodexSessionFailure::after_exchange(CodexSessionError::Write, true),
        );
        assert_eq!(
            probe_cancellation_observation(
                probe_dispatch_possible(&provider_postdispatch),
                &provider_postdispatch,
                "provider_smoke_cancellation",
            ),
            StopObservation::OutcomeUnknown
        );

        let native_cancelled_before_dispatch =
            native_readiness_timeout_after_cancellation(StopObservation::UpstreamInactiveConfirmed);
        assert_eq!(
            probe_cancellation_observation(
                native_cancelled_before_dispatch.dispatch_possible,
                &native_cancelled_before_dispatch.error,
                "native_readiness_cancellation",
            ),
            StopObservation::CancellationConfirmed
        );
        let native_cancelled_after_dispatch =
            native_readiness_timeout_after_cancellation(StopObservation::OutcomeUnknown);
        assert_eq!(
            probe_cancellation_observation(
                native_cancelled_after_dispatch.dispatch_possible,
                &native_cancelled_after_dispatch.error,
                "native_readiness_cancellation",
            ),
            StopObservation::OutcomeUnknown
        );

        let provider_cancelled_before_dispatch =
            provider_smoke_timeout_after_cancellation(StopObservation::UpstreamInactiveConfirmed);
        assert_eq!(
            probe_cancellation_observation(
                probe_dispatch_possible(&provider_cancelled_before_dispatch),
                &provider_cancelled_before_dispatch,
                "provider_smoke_cancellation",
            ),
            StopObservation::CancellationConfirmed
        );
        let provider_cancelled_after_dispatch =
            provider_smoke_timeout_after_cancellation(StopObservation::OutcomeUnknown);
        assert_eq!(
            probe_cancellation_observation(
                probe_dispatch_possible(&provider_cancelled_after_dispatch),
                &provider_cancelled_after_dispatch,
                "provider_smoke_cancellation",
            ),
            StopObservation::OutcomeUnknown
        );
    }

    #[test]
    fn cancelled_native_preflight_uses_native_terminal_detail() {
        let desktop_binding = DesktopBindingRef::new("desktop-native-cancellation").unwrap();
        let policy = ExecutionPolicy::new(
            EffectiveModelRef::new("model-native-cancellation").unwrap(),
            ProviderBindingRef::new("provider-native-cancellation").unwrap(),
            DesktopTarget::new(desktop_binding.clone(), "native-cancellation-session"),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Enabled),
        );
        let key = ReadinessCacheKey::new(
            NATIVE_ADAPTER,
            desktop_binding,
            policy,
            "0.144.0",
            "codex-native-0.144.0",
            None::<String>,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ReadinessObservationState::Unknown,
            ReadinessObservationState::Unknown,
        )
        .unwrap();
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        let evidence = key
            .evidence(
                "native-readiness-cancelled",
                observed_at,
                observed_at + time::Duration::hours(24),
            )
            .unwrap();
        let failure =
            native_readiness_timeout_after_cancellation(StopObservation::CancellationConfirmed);
        let result = AdapterPreflight::Failed {
            key,
            evidence,
            reason: failure.reason,
            error: mark_probe_dispatch_possible(*failure.error, failure.dispatch_possible),
            dispatch_possible: failure.dispatch_possible,
        };

        assert_eq!(
            preflight_cancellation_observation(&result),
            StopObservation::CancellationConfirmed
        );
    }

    #[test]
    fn matching_provider_smoke_results_skip_or_block_without_a_live_probe() {
        let adapter = ProductionComputerUseAdapter::new(
            Arc::new(RwLock::new(crate::ProductionCapabilitySnapshot::collect(
                None,
            ))),
            Ok(tempfile::tempdir().unwrap().path().join("codex-work")),
        );
        let desktop_binding = DesktopBindingRef::new("desktop-provider-cache").unwrap();
        let policy = ExecutionPolicy::new(
            EffectiveModelRef::new("model-provider-cache").unwrap(),
            ProviderBindingRef::new("provider-cache").unwrap(),
            DesktopTarget::new(desktop_binding.clone(), "provider-cache-session"),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120).unwrap(),
            ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Enabled),
        );
        let key = ReadinessCacheKey::new(
            NATIVE_ADAPTER,
            desktop_binding,
            policy,
            "0.144.0",
            "codex-native-0.144.0",
            None::<String>,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ReadinessObservationState::Unknown,
            ReadinessObservationState::Unknown,
        )
        .unwrap();
        let observed_at = time::OffsetDateTime::now_utc();
        let provider = ProviderSmokeEvidence::new(
            "provider-smoke-cached",
            key.provider_config_fingerprint(),
            observed_at,
            observed_at + time::Duration::hours(24),
        )
        .unwrap()
        .with_source(ProviderSmokeSource::Cache);
        let mut persist_thread_ref = |_value: &str| Ok(());
        let mut persist_turn_ref = |_value: &str| Ok(());
        let mut persistence = ProviderProbePersistence {
            persist_thread_ref: &mut persist_thread_ref,
            persist_turn_ref: &mut persist_turn_ref,
        };

        assert_eq!(
            adapter
                .run_required_provider_smoke(
                    &key,
                    Some(ProviderSmokeResult::Passed(provider.clone())),
                    false,
                    None,
                    None,
                    &mut persistence,
                )
                .unwrap(),
            Some(provider)
        );

        let provider_failure = ProviderSmokeFailureEvidence::new(
            "provider-smoke-failed",
            key.provider_config_fingerprint(),
            ErrorCode::UnsupportedProviderComputerUse,
            "provider_smoke_provider_rejected",
            observed_at,
            observed_at + adapter.provider_smoke_failure_ttl,
        )
        .unwrap()
        .with_source(ProviderSmokeSource::Cache);
        let cached_failure = adapter
            .run_required_provider_smoke(
                &key,
                Some(ProviderSmokeResult::Failed(provider_failure.clone())),
                false,
                None,
                None,
                &mut persistence,
            )
            .expect_err("a cached provider failure remains a preflight blocker");
        assert!(cached_failure.evidence.is_none());
        assert_eq!(
            cached_failure.error.code,
            ErrorCode::UnsupportedProviderComputerUse
        );
        assert_eq!(
            cached_failure.error.details["provider_smoke_source"],
            "cache"
        );
        assert_eq!(
            cached_failure.error.details["provider_smoke_status"],
            "failed"
        );
        assert!(cached_failure.error.details["provider_smoke_observed_at"].is_string());
        assert!(cached_failure.error.details["provider_smoke_expires_at"].is_string());
        assert!(cached_failure.error.details["provider_smoke_age_ms"].is_u64());

        let refreshed_pass = ProviderSmokeResult::Passed(
            ProviderSmokeEvidence::new(
                "provider-smoke-refresh-pass",
                key.provider_config_fingerprint(),
                observed_at,
                observed_at + time::Duration::hours(24),
            )
            .unwrap(),
        );
        assert!(provider_cache_for_preflight(Some(refreshed_pass), true).is_none());
        assert!(
            provider_cache_for_preflight(
                Some(ProviderSmokeResult::Failed(provider_failure)),
                true,
            )
            .is_none()
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
    fn timed_turn_preserves_terminal_results_and_returns_confirmed_timeout_error() {
        let confirmed = finish_timed_turn_execution(
            TimedCodexSessionRun {
                result: Ok(CodexSessionTerminal::StoppedByControl),
                cancellation: Some(StopObservation::UpstreamInactiveConfirmed),
            },
            None,
        )
        .expect("confirmed timeout cancellation is terminal");
        assert_eq!(confirmed.transition(), Some(TurnTransition::Failed));
        let timeout = confirmed
            .terminal_error()
            .expect("confirmed deadline cancellation must remain typed");
        assert_eq!(timeout.code, ErrorCode::RemoteExecution);
        assert_eq!(timeout.details["reason"], serde_json::json!("timeout"));

        let completed = finish_timed_turn_execution(
            TimedCodexSessionRun {
                result: Ok(CodexSessionTerminal::Completed),
                cancellation: Some(StopObservation::CancellationConfirmed),
            },
            None,
        )
        .expect("a definitive completion wins the cancellation race");
        assert_eq!(completed.transition(), Some(TurnTransition::Completed));
        assert!(completed.terminal_error().is_none());

        let error = match finish_timed_turn_execution(
            TimedCodexSessionRun {
                result: Ok(CodexSessionTerminal::StoppedByControl),
                cancellation: Some(StopObservation::OutcomeUnknown),
            },
            None,
        ) {
            Err(error) => error,
            Ok(_) => panic!("unconfirmed timeout cancellation must enter recovery"),
        };
        assert_eq!(error.details["reason"], serde_json::json!("timeout"));
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
            Arc::new(RwLock::new(crate::ProductionCapabilitySnapshot::collect(
                None,
            ))),
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
    fn readiness_failures_use_codex_dispatch_attempt_consistently() {
        for attempted in [false, true] {
            let failure =
                CodexSessionFailure::after_exchange(CodexSessionError::PrematureExit, attempted);
            assert_eq!(
                native_smoke_session_failure(failure).dispatch_possible,
                attempted
            );
            assert_eq!(
                probe_dispatch_possible(&provider_probe_session_failure(failure)),
                attempted
            );
        }

        assert!(
            !native_smoke_failure("native_readiness_action_not_observed").dispatch_possible,
            "terminal native smoke evidence must not retain possible upstream dispatch"
        );
        let terminal_provider = mark_probe_dispatch_possible(
            provider_smoke_session_failure(CodexSessionError::ResponseError),
            false,
        );
        assert!(!probe_dispatch_possible(&terminal_provider));
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

    #[test]
    fn native_readiness_targets_require_independent_click_and_drag_confirmation() {
        let windows = windows_native_readiness_target_source("readiness-nonce");
        assert!(windows.contains("Topmost"));
        assert!(windows.contains("ShowInTaskbar"));
        assert!(windows.contains("MouseDown"));
        assert!(windows.contains("MouseMove"));
        assert!(windows.contains("MouseUp"));
        assert!(windows.contains("pointer_click_confirmed"));
        assert!(windows.contains("pointer_drag_confirmed"));
        assert!(windows.contains("$clickConfirmed -and $dragConfirmed"));

        let macos = macos_native_readiness_target_source("readiness-nonce");
        assert!(macos.contains("NSFloatingWindowLevel"));
        assert!(macos.contains("addLocalMonitorForEventsMatchingMaskHandler"));
        assert!(macos.contains("event.window.windowNumber"));
        assert!(macos.contains("NSEventTypeLeftMouseDown"));
        assert!(macos.contains("NSEventTypeLeftMouseDragged"));
        assert!(macos.contains("NSEventTypeLeftMouseUp"));
        assert!(!macos.contains("NSEvent.mouseLocation"));
        assert!(!macos.contains("NSEvent.pressedMouseButtons"));
        assert!(macos.contains("pointer_click_confirmed"));
        assert!(macos.contains("pointer_drag_confirmed"));
        assert!(macos.contains("clickConfirmed && dragConfirmed"));
    }

    #[test]
    fn mismatched_cached_native_evidence_becomes_one_live_branch_miss() {
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        let current = native_readiness_test_key(
            "current-session",
            ReadinessObservationState::Granted,
            ReadinessObservationState::Unknown,
        );
        let stale = native_readiness_test_key(
            "stale-session",
            ReadinessObservationState::Granted,
            ReadinessObservationState::Unknown,
        );
        let stale_evidence = stale
            .evidence(
                "stale-readiness",
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap();

        assert!(matching_cached_evidence(&current, Some(stale_evidence)).is_none());
        let live_evidence = current
            .evidence(
                "live-readiness",
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap();
        let live =
            native_readiness_from_evidence(&current, live_evidence, None, ReadinessSource::Live)
                .unwrap();
        assert_eq!(live.source(), ReadinessSource::Live);

        let matching_evidence = current
            .evidence(
                "current-readiness",
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap()
            .with_source(ReadinessSource::Cache);
        let matching_evidence = matching_cached_evidence(&current, Some(matching_evidence))
            .expect("an exact cache hit must remain on the single cached branch");
        let cached = native_readiness_from_evidence(
            &current,
            matching_evidence,
            None,
            ReadinessSource::Cache,
        )
        .unwrap();
        assert_eq!(cached.source(), ReadinessSource::Cache);
    }

    #[test]
    fn denied_observation_keeps_the_exact_key_and_retained_failure_evidence() {
        let key = native_readiness_test_key(
            "denied-session",
            ReadinessObservationState::Denied,
            ReadinessObservationState::Unknown,
        );
        let observed_at = time::OffsetDateTime::UNIX_EPOCH;
        let evidence = key
            .evidence(
                "denied-readiness",
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .unwrap();

        let result = denied_native_probe_result(&key, &evidence)
            .expect("a denied observation must become a retained live failure");
        let NativeProbeResult::Failed {
            evidence: retained,
            reason,
            error,
            dispatch_possible,
        } = result
        else {
            panic!("denied readiness must not dispatch or become uncached");
        };
        assert!(retained == evidence);
        assert_eq!(reason, "native_readiness_manual_action_required");
        assert!(!dispatch_possible);
        assert_eq!(
            error.details["native_readiness"]["status"],
            "manual_action_required"
        );
    }

    #[test]
    fn windows_app_policy_fingerprint_uses_only_the_existing_closed_surface() {
        use crate::codex_capabilities::EvidenceSurface;

        let desktop = satelle_core::DesktopSessionRecord {
            session_id: "PRIVATE_SESSION_ID_CANARY".to_string(),
            desktop_user: "operator".to_string(),
            state: "active".to_string(),
            session_kind: "visible_desktop".to_string(),
            is_console: true,
            is_remote: false,
            display_summary: "PRIVATE_DISPLAY_CANARY".to_string(),
            portable_selectors: vec!["active".to_string(), "console".to_string()],
            native_selectors: vec!["PRIVATE_NATIVE_SELECTOR_CANARY".to_string()],
            selected_by_current_config: true,
        };
        let stable = native_prerequisite_observations("windows", &desktop, EvidenceSurface::Stable);
        let absent = native_prerequisite_observations("windows", &desktop, EvidenceSurface::Absent);
        let incomplete =
            native_prerequisite_observations("windows", &desktop, EvidenceSurface::Incomplete);
        let private =
            native_prerequisite_observations("windows", &desktop, EvidenceSurface::Private);

        assert_eq!(stable.app_fingerprint_material, "windows_app_policy:stable");
        assert_eq!(absent.app_fingerprint_material, "windows_app_policy:absent");
        assert_eq!(
            incomplete.app_fingerprint_material,
            "windows_app_policy:incomplete"
        );
        assert_eq!(
            private.app_fingerprint_material,
            "windows_app_policy:incomplete"
        );
        for material in [
            &stable.app_fingerprint_material,
            &absent.app_fingerprint_material,
            &incomplete.app_fingerprint_material,
        ] {
            assert!(!material.contains("PRIVATE_"));
        }
        let fingerprint = |material: &str| {
            readiness_fingerprint(
                "app-approval",
                "windows",
                &desktop.session_id,
                ReadinessObservationState::Unknown,
                material,
            )
        };
        assert_ne!(
            fingerprint(&stable.app_fingerprint_material),
            fingerprint(&absent.app_fingerprint_material)
        );
        assert_ne!(
            fingerprint(&absent.app_fingerprint_material),
            fingerprint(&incomplete.app_fingerprint_material)
        );
    }

    #[test]
    fn native_readiness_prompt_names_both_required_actions_and_private_target() {
        let prompt = native_readiness_prompt("readiness-nonce");

        assert!(prompt.contains("private"));
        assert!(prompt.contains("click"));
        assert!(prompt.contains("drag"));
        assert!(prompt.contains("readiness-nonce"));
    }
}
