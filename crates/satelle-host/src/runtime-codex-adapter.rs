use super::adapter::{
    AdapterPreflight, AdapterReadiness, AdapterSubject, ComputerUseAdapter, ExecuteRequest,
    ExecuteResult, ProviderComputerUseIntent, ProviderProbeDriver, ProviderSmokeEvidence,
    ProviderSmokeFailureEvidence, ProviderSmokeResult, ProviderSmokeSource, ReadinessCacheKey,
    ReadinessEvidence, RecoveryObservation,
};
use crate::codex_session::{
    CodexApprovalPolicy, CodexSandboxPolicy, CodexSessionControl, CodexSessionError,
    CodexSessionFailure, CodexSessionRequest, CodexSessionTerminal, CodexTurnReadRequest,
    CodexTurnStatus, read_codex_turn, run_codex_session,
    run_codex_session_with_timeout_cancellation,
};
use command_group::{CommandGroup, GroupChild};
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, SandboxPolicy, StopObservation,
    TimeoutPolicy, TurnExecutionMode, TurnState, TurnTransition,
};
use satelle_core::{ControlPlaneOperation, ErrorCode, SatelleError};
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
const PROVIDER_SMOKE_CANCELLATION_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct ProviderSmokeAttemptFailure {
    evidence: Option<ProviderSmokeFailureEvidence>,
    error: Box<SatelleError>,
}

struct ProviderProbePersistence<'a> {
    persist_thread_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
    persist_turn_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
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
        }
    }

    pub(crate) fn with_readiness_policy(
        snapshot: Arc<RwLock<crate::ProductionCapabilitySnapshot>>,
        working_directory: Result<PathBuf, SatelleError>,
        timeout: Duration,
        ttl: time::Duration,
        provider_smoke_timeout: Duration,
        provider_smoke_success_ttl: time::Duration,
        provider_smoke_failure_ttl: time::Duration,
    ) -> Self {
        Self {
            snapshot,
            working_directory,
            active_execution: Arc::new(Mutex::new(None)),
            native_readiness_timeout: timeout,
            native_readiness_ttl: ttl,
            provider_smoke_timeout,
            provider_smoke_success_ttl,
            provider_smoke_failure_ttl,
        }
    }

    fn native_readiness_key(
        &self,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<ReadinessCacheKey, SatelleError> {
        let snapshot = crate::read_production_snapshot(&self.snapshot)?;
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
        {
            return Err(crate::execution_blocker(&snapshot.verdict));
        }
        snapshot
            .control_plane_admission
            .admit(ControlPlaneOperation::Run)?;
        drop(snapshot);

        let desktop = crate::desktop_sessions::discover()?
            .into_iter()
            .next()
            .ok_or_else(SatelleError::computer_use_not_ready)?;
        let desktop_binding = DesktopBindingRef::new(desktop.session_id.clone())
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
            DesktopTarget::new(desktop_binding.clone()),
            ApprovalPolicy::OnRequest,
            SandboxPolicy::WorkspaceWrite,
            TimeoutPolicy::bounded_seconds(120)
                .map_err(|_| adapter_failure("timeout_policy_invalid"))?,
            ExperimentalFeatureChoices::new(
                FeatureChoice::Enabled,
                if provider_intent.experimental() {
                    FeatureChoice::Enabled
                } else {
                    FeatureChoice::Disabled
                },
            ),
        );
        let platform = crate::codex_capabilities::HostPlatform::current().as_str();
        let codex_version = version.to_string();
        let native_runtime_version = format!("codex-native-{codex_version}");
        ReadinessCacheKey::new(
            NATIVE_ADAPTER,
            desktop_binding,
            execution_policy,
            codex_version,
            native_runtime_version,
            None::<String>,
            readiness_fingerprint("os-permission", platform, &desktop.session_id),
            readiness_fingerprint("app-approval", platform, &desktop.session_id),
        )
        .map_err(|_| adapter_failure("readiness_key_invalid"))
    }

    fn readiness_from_evidence(
        &self,
        key: &ReadinessCacheKey,
        evidence: ReadinessEvidence,
        cached_provider: Option<ProviderSmokeResult>,
        refresh_provider: bool,
        provider_smoke_timeout: Option<Duration>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> AdapterPreflight {
        match self.run_required_provider_smoke(
            key,
            cached_provider,
            refresh_provider,
            provider_smoke_timeout,
            persistence,
        ) {
            Ok(provider_smoke_evidence) => AdapterReadiness::ready(
                key.adapter(),
                "native Computer Use passed the Host action-path smoke test",
                key.desktop_binding().clone(),
                key.execution_policy().clone(),
                evidence,
                provider_smoke_evidence,
            )
            .map_or_else(
                |_| {
                    AdapterPreflight::UncachedFailure(adapter_failure("readiness_evidence_invalid"))
                },
                AdapterPreflight::Ready,
            ),
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
        match self.run_native_smoke(&key) {
            Ok(()) => self.readiness_from_evidence(
                &key,
                evidence,
                cached_provider,
                refresh_provider,
                provider_smoke_timeout,
                persistence,
            ),
            Err(reason) => AdapterPreflight::Failed {
                key,
                evidence,
                reason,
                error: native_readiness_failure(reason),
            },
        }
    }

    fn run_native_smoke(&self, _key: &ReadinessCacheKey) -> Result<(), &'static str> {
        let nonce = format!("SATELLE-{}", satelle_core::TurnId::new());
        let deadline = Instant::now()
            .checked_add(self.native_readiness_timeout)
            .ok_or("native_readiness_timeout_invalid")?;
        let mut target = NativeActionTarget::spawn(&nonce, self.native_readiness_timeout)?;
        std::thread::sleep(Duration::from_millis(200));
        let working_directory = self
            .working_directory
            .as_ref()
            .map_err(|_| "working_directory_unavailable")
            .and_then(|path| {
                prepare_working_directory(path).map_err(|_| "working_directory_unavailable")
            })?;
        let prompt = format!(
            "Use native Computer Use, not shell or file tools, to click the button labeled {nonce} in the visible 'Satelle Native Readiness' window. Stop after clicking it."
        );
        let mut persist_thread = |_value: &str| Ok(());
        let mut persist_turn = |_value: &str| Ok(());
        let terminal = run_codex_session(
            crate::codex_capabilities::installed_app_server_command(),
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
                persist_thread_ref: &mut persist_thread,
                persist_turn_ref: &mut persist_turn,
                control: None,
            },
        )
        .map_err(|failure| match failure.error() {
            CodexSessionError::Timeout => "native_readiness_timed_out",
            _ => "native_readiness_session_failed",
        })?;
        if terminal != CodexSessionTerminal::Completed {
            return Err("native_readiness_session_failed");
        }
        target.wait_for_success(deadline)
    }

    fn run_required_provider_smoke(
        &self,
        key: &ReadinessCacheKey,
        cached_provider: Option<ProviderSmokeResult>,
        refresh: bool,
        timeout_override: Option<Duration>,
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
        self.run_live_provider_smoke(key, source, timeout_override, persistence)
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
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> Result<ProviderSmokeEvidence, SatelleError> {
        let timeout = timeout_override.unwrap_or(self.provider_smoke_timeout);
        let probe = crate::provider_probe::ProviderProbeSurface::start(timeout)
            .map_err(provider_smoke_failure)?;
        let page_url = probe.page_url().to_string();
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            provider_smoke_failure(crate::provider_probe::ProviderProbeError::TimedOut)
        })?;
        let working_directory = self
            .working_directory
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|path| prepare_working_directory(path))?;
        let prompt = format!(
            "Use native Computer Use only to open {page_url} in the approved visible browser. Read the nonce shown on the page, drag the marker into the drop target, and stop. Do not use shell, file, or network tools."
        );
        let run = run_codex_session_with_timeout_cancellation(
            crate::codex_capabilities::installed_app_server_command(),
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
            },
            PROVIDER_SMOKE_CANCELLATION_GRACE,
        );
        if let Some(observation) = run.cancellation {
            return Err(provider_smoke_timeout_after_cancellation(observation));
        }
        let terminal = run
            .result
            .map_err(|failure| provider_smoke_session_failure(failure.error()))?;
        if terminal != CodexSessionTerminal::Completed {
            return Err(provider_smoke_session_failure(
                CodexSessionError::ResponseError,
            ));
        }
        probe
            .wait_for_completion()
            .map_err(provider_smoke_failure)?;

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

    fn ensure_platform_admitted(&self) -> Result<(), SatelleError> {
        self.native_readiness_key(&ProviderComputerUseIntent::host_default())
            .map(|_| ())
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

    fn read_provider_probe_turn(
        &self,
        subject: &crate::storage::ProviderProbeRecoverySubject,
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

    fn preflight_terminal_inner(
        &self,
        provider_intent: &ProviderComputerUseIntent,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        persistence: &mut ProviderProbePersistence<'_>,
    ) -> AdapterPreflight {
        let key = match self.native_readiness_key(provider_intent) {
            Ok(key) => key,
            Err(error) => return AdapterPreflight::UncachedFailure(error),
        };
        let cached_provider =
            provider_cache_for_preflight(cached_provider, provider_intent.refresh());
        match cached {
            Some(evidence) => self.readiness_from_evidence(
                &key,
                evidence,
                cached_provider,
                provider_intent.refresh(),
                provider_intent.provider_smoke_timeout(),
                persistence,
            ),
            None => self.live_native_preflight(
                key,
                cached_provider,
                provider_intent.refresh(),
                provider_intent.provider_smoke_timeout(),
                persistence,
            ),
        }
    }
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
    let script = format!(
        "$ErrorActionPreference='Stop'; Add-Type -AssemblyName PresentationFramework; \
         $window=New-Object Windows.Window; $window.Title='Satelle Native Readiness'; \
         $window.Width=520; $window.Height=180; $window.Topmost=$true; \
         $button=New-Object Windows.Controls.Button; $button.Content='{nonce}'; \
         $button.FontSize=24; $button.Margin=20; \
         $button.Add_Click({{$window.Tag='passed'; $window.Close()}}); \
         $window.Content=$button; [void]$window.ShowDialog(); \
         if ($window.Tag -eq 'passed') {{ exit 0 }} else {{ exit 1 }}"
    );
    let mut command = Command::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-STA", "-Command", &script]);
    Ok(command)
}

#[cfg(target_os = "macos")]
fn native_action_command(nonce: &str, timeout: Duration) -> Result<Command, &'static str> {
    let timeout = timeout.as_secs().max(1);
    let script = format!(
        "tell application \"System Events\" to set probeResult to display dialog \"Click the readiness button\" with title \"Satelle Native Readiness\" buttons {{\"Cancel\", \"{nonce}\"}} default button \"{nonce}\" cancel button \"Cancel\" giving up after {timeout}\n\
         if gave up of probeResult then error \"native readiness timed out\" number 1\n\
         if button returned of probeResult is not \"{nonce}\" then error \"native readiness action not observed\" number 2"
    );
    let mut command = Command::new("/usr/bin/osascript");
    command.args(["-e", &script]);
    Ok(command)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn native_action_command(_nonce: &str, _timeout: Duration) -> Result<Command, &'static str> {
    Err("unsupported_host_platform")
}

fn readiness_fingerprint(domain: &str, platform: &str, desktop: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"satelle-native-readiness-v1\0");
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(platform.as_bytes());
    digest.update([0]);
    digest.update(desktop.as_bytes());
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

fn native_readiness_failure(reason: &'static str) -> SatelleError {
    let mut details = std::collections::BTreeMap::new();
    details.insert("reason".to_string(), Value::String(reason.to_string()));
    SatelleError {
        code: ErrorCode::ComputerUseNotReady,
        message: "native Computer Use did not pass the Host action-path smoke test".to_string(),
        recovery_command: Some("satelle doctor --scope computer-use --refresh --json".to_string()),
        source_detail: None,
        details,
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
    error
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
        crate::read_production_snapshot(&self.snapshot)?
            .control_plane_admission
            .admit(operation)
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
        self.preflight_terminal_inner(provider_intent, cached, cached_provider, &mut persistence)
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
                model: model_override(policy.effective_model().as_str()),
                model_provider: provider_override(policy.provider_binding().as_str()),
                execution_mode: request.execution_mode(),
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

impl ProviderProbeDriver for ProductionComputerUseAdapter {
    fn preflight_terminal_with_provider_probe(
        &self,
        _host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        let mut persistence = ProviderProbePersistence {
            persist_thread_ref,
            persist_turn_ref,
        };
        self.preflight_terminal_inner(provider_intent, cached, cached_provider, &mut persistence)
    }

    fn observe_provider_probe(
        &self,
        subject: &crate::storage::ProviderProbeRecoverySubject,
    ) -> RecoveryObservation {
        match self.read_provider_probe_turn(subject) {
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
            DesktopTarget::new(desktop_binding.clone()),
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
