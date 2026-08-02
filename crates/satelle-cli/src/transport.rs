use crate::{CliFailure, SelectedHost, bootstrap_lock, failure, on_demand_idle_timeout};
use satelle_core::daemon_service::{
    DaemonArtifactPlan, DaemonServicePlan, DaemonServicePlatform, PersistentHostStoragePolicy,
    PersistentServiceDecision, SetupModeSelection, WindowsServiceConfigV4, WindowsTaskDefinition,
};
use satelle_core::doctor::DoctorScopeSelection;
use satelle_core::session::{HostIdentityRef, PublicSession, TurnAdmissionFailure};
use satelle_core::{
    ApiTokenSource, DaemonPathOverrides, DirectHostBinding, DoctorOptions, DoctorReport, ErrorCode,
    HostSessionsReport, HostSessionsSchemaVersion, LOCAL_DEMO_HOST, SatelleError, SatelleEvent,
    SecureFileError, SessionId, SetupReadinessSummary, SetupReport, SetupRequiredInput,
    SetupSchemaVersion, SshHostBinding, StopResult, TransportKind, TurnId,
    open_or_create_owner_only_directory, open_or_create_owner_only_file,
    persist_new_owner_only_secret_file, read_owner_only_secret_file, read_trusted_ca_bundle_file,
};
use satelle_host::{
    AdmissionCancellation, ApiBearerToken, ApiScopes, ControllerTransportProbe, DaemonLogPage,
    DoctorExecutionFailure, DoctorExecutionResult, HostService, HostStatus, LogCursor,
    LogPageQuery, TurnIntent, TurnOutcome, admission_request_timeout,
};
use satelle_transport::{
    ApiError, ApiErrorCode, DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError,
    DaemonServer, DaemonServerConfig, DaemonShutdownHandle, TurnRequest,
};
use std::collections::BTreeSet;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, path::Path};
use uuid::Uuid;
use zeroize::Zeroizing;

const SSH_DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_DAEMON_LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_DAEMON_LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const HOST_UPDATE_ACTIONS: [&str; 5] = [
    "install-host-artifact",
    "publish-host-service",
    "restart-host-daemon",
    "invalidate-readiness-caches",
    "host-update-postcheck",
];
type InterruptFuture<'a> = Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + 'a>>;

trait InterruptSource: Send + Sync {
    fn arm(&self) -> InterruptFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn wait(&self) -> InterruptFuture<'_>;
}

#[derive(Default)]
struct ProcessInterrupt {
    inner: Arc<ProcessInterruptInner>,
}

#[derive(Default)]
struct ProcessInterruptInner {
    started: AtomicBool,
    armed: AtomicBool,
    result: Mutex<Option<Result<(), Arc<std::io::Error>>>>,
    armed_changed: tokio::sync::Notify,
    changed: tokio::sync::Notify,
}

impl InterruptSource for ProcessInterrupt {
    fn arm(&self) -> InterruptFuture<'_> {
        Box::pin(async move {
            if !self.inner.started.swap(true, Ordering::AcqRel) {
                let inner = Arc::clone(&self.inner);
                tokio::spawn(async move {
                    let mut signal = Box::pin(tokio::signal::ctrl_c());
                    let first_poll =
                        std::future::poll_fn(|context| match signal.as_mut().poll(context) {
                            std::task::Poll::Ready(result) => std::task::Poll::Ready(Some(result)),
                            std::task::Poll::Pending => std::task::Poll::Ready(None),
                        })
                        .await;
                    inner.armed.store(true, Ordering::Release);
                    inner.armed_changed.notify_waiters();
                    let result = match first_poll {
                        Some(result) => result,
                        None => signal.await,
                    }
                    .map_err(Arc::new);
                    *inner
                        .result
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(result);
                    inner.changed.notify_waiters();
                });
            }
            loop {
                let armed = self.inner.armed_changed.notified();
                if self.inner.armed.load(Ordering::Acquire) {
                    return Ok(());
                }
                armed.await;
            }
        })
    }

    fn wait(&self) -> InterruptFuture<'_> {
        Box::pin(async move {
            self.arm().await?;
            loop {
                let changed = self.inner.changed.notified();
                let result = self
                    .inner
                    .result
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if let Some(result) = result {
                    return result
                        .map_err(|error| std::io::Error::new(error.kind(), error.to_string()));
                }
                changed.await;
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum SshBootstrapScope {
    Read,
    Control,
    Admin,
}

impl SshBootstrapScope {
    pub(crate) const fn api_scopes(self) -> ApiScopes {
        match self {
            Self::Read => ApiScopes::READ,
            Self::Control => ApiScopes::CONTROL,
            Self::Admin => ApiScopes::ADMIN,
        }
    }

    const fn as_cli_value(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Control => "control",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshDaemonLaunchPolicy {
    Never,
    DurableOnly,
    Bootstrap(SshBootstrapScope),
}

impl SshDaemonLaunchPolicy {
    const fn bootstrap_scope(self) -> Option<SshBootstrapScope> {
        match self {
            Self::Bootstrap(scope) => Some(scope),
            Self::Never | Self::DurableOnly => None,
        }
    }

    const fn allows_durable_relaunch(self) -> bool {
        !matches!(self, Self::Never)
    }
}

#[path = "direct-attached.rs"]
mod direct_attached;
#[path = "ssh-bootstrap.rs"]
mod ssh_bootstrap;
#[path = "ssh-tunnel.rs"]
mod ssh_tunnel;

pub(crate) use ssh_bootstrap::CacheCleanupReport;
use ssh_bootstrap::SshBootstrapProcess;
use ssh_tunnel::SshTunnel;

pub(crate) fn probe_tailscale_serve(
    alias: &str,
    destination: &str,
    daemon_path_overrides: &DaemonPathOverrides,
) -> Result<(Vec<u8>, Vec<u8>), SatelleError> {
    ssh_bootstrap::probe_tailscale_serve(destination, daemon_path_overrides)
        .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))
}

pub(crate) fn apply_tailscale_serve(alias: &str, destination: &str) -> Result<(), SatelleError> {
    ssh_bootstrap::apply_tailscale_serve(destination)
        .map_err(|error| map_tailscale_serve_error(alias, error))
}

fn map_tailscale_serve_error(alias: &str, error: ssh_bootstrap::SshBootstrapError) -> SatelleError {
    if matches!(
        error,
        ssh_bootstrap::SshBootstrapError::HostKeyVerificationRequired
    ) {
        SatelleError::ssh_host_key_verification_required(alias)
    } else {
        SatelleError {
            code: ErrorCode::RemoteExecution,
            message: format!("remote Tailscale Serve setup failed for host '{alias}'"),
            recovery_command: Some(format!(
                "verify system OpenSSH access, then run satelle doctor --host {alias} --scope transport --json"
            )),
            source_detail: None,
            details: std::collections::BTreeMap::from([(
                "host".to_string(),
                serde_json::Value::String(alias.to_string()),
            )]),
        }
    }
}

#[cfg(feature = "test-support")]
const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

pub(crate) struct AttachedTurnOutcome {
    pub(crate) session: PublicSession,
    pub(crate) turn_id: TurnId,
    pub(crate) provider_smoke: Option<serde_json::Value>,
}

pub(crate) struct ProviderDescriptorValidationReport {
    pub(crate) resolved_binding: satelle_core::PublicResolvedProviderBinding,
    pub(crate) validation: satelle_core::ProviderAuthValidationResult,
}

fn setup_provider_intent(
    request: &satelle_transport::SetupVerificationRequest,
) -> Result<satelle_host::ProviderComputerUseIntent, SatelleError> {
    let provider_intent = match (request.model_alias(), request.provider_alias()) {
        (None, None) => satelle_host::ProviderComputerUseIntent::host_default(),
        (Some(model_alias), Some(provider_alias)) => satelle_host::ProviderComputerUseIntent::new(
            Some(
                satelle_core::session::EffectiveModelRef::new(model_alias)
                    .map_err(|error| SatelleError::invalid_usage(error.to_string()))?,
            ),
            Some(
                satelle_core::session::ProviderBindingRef::new(provider_alias)
                    .map_err(|error| SatelleError::invalid_usage(error.to_string()))?,
            ),
            true,
        )
        .with_project_selection_provenance(
            request.model_from_project(),
            request.provider_from_project(),
        ),
        _ => {
            return Err(SatelleError::invalid_usage(
                "setup verification model and provider aliases must be supplied together",
            ));
        }
    };
    Ok(provider_intent
        .with_experimental_provider_computer_use(request.experimental_provider_computer_use()))
}

/// The command surface is intentionally exhaustive. A new transport operation
/// must be implemented or explicitly rejected by every backend.
pub(crate) trait TransportClient: Send {
    fn log_target_identity(&self) -> Result<String, SatelleError>;

    fn supported_image_media_types(&self) -> Result<Vec<String>, SatelleError> {
        Ok(Vec::new())
    }
    fn setup(
        &self,
        dry_run: bool,
        setup_mode: SetupModeSelection,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError>;
    fn doctor(
        &self,
        scope_selection: &DoctorScopeSelection,
        transport_probe: Arc<dyn ControllerTransportProbe>,
        options: DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> DoctorExecutionResult;
    fn verify_setup(
        &self,
        request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<DoctorReport, SatelleError>;
    fn plan_setup_repair(
        &self,
        run_id: Option<&str>,
        probes: &[satelle_transport::SetupRepairProbe],
    ) -> Result<RepairLedgerPlan, SatelleError>;
    fn invalidate_native_readiness(
        &self,
        request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<u64, SatelleError>;
    fn authorize_provider_binding(
        &self,
        authorization: &satelle_core::ProviderBindingAuthorization,
    ) -> Result<satelle_core::PublicResolvedProviderBinding, SatelleError>;
    fn preview_provider_secret_provisioning(
        &self,
        metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningPreviewResponse, SatelleError>;
    fn provision_provider_secret(
        &self,
        preview: &satelle_transport::ProviderSecretProvisioningPreviewResponse,
        metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        secret: Zeroizing<Vec<u8>>,
        idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningResponse, SatelleError>;
    fn validate_provider_descriptor(
        &self,
        model_alias: &str,
        provider_alias: &str,
        model_alias_from_project: bool,
        provider_alias_from_project: bool,
        mode: satelle_core::ProviderAuthValidationMode,
        experimental_provider_computer_use: bool,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError>;
    fn host_status(&self) -> Result<HostStatus, SatelleError>;
    fn host_paths(
        &self,
    ) -> Result<satelle_core::daemon_service::DaemonResolvedPathSet, SatelleError>;
    fn host_sessions(&self, no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError>;
    fn run(
        &self,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure>;
    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError>;
    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure>;
    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError>;
    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError>;
    fn task_artifacts(&self, session_id: &SessionId) -> Result<TaskArtifacts, SatelleError>;
    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError>;
    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError>;
}

pub(crate) struct TaskArtifacts {
    pub(crate) plan: String,
    pub(crate) worklog: String,
    pub(crate) goal: String,
}

impl TaskArtifacts {
    fn from_host(artifacts: satelle_host::TaskArtifactSet) -> Self {
        Self {
            plan: artifacts.plan().to_string(),
            worklog: artifacts.worklog().to_string(),
            goal: artifacts.goal().to_string(),
        }
    }

    fn from_response(artifacts: satelle_transport::TaskArtifactsResponse) -> Self {
        Self {
            plan: artifacts.plan().to_string(),
            worklog: artifacts.worklog().to_string(),
            goal: artifacts.goal().to_string(),
        }
    }
}

pub(crate) struct RepairLedgerPlan {
    pub(crate) available: bool,
    pub(crate) automatic_action_ids: Vec<String>,
    pub(crate) selected_operation_kind: Option<satelle_transport::SetupRepairOperationKind>,
    pub(crate) selected_run_status: Option<satelle_transport::SetupRepairRunStatus>,
    pub(crate) host_update_recovery_identity:
        Option<satelle_core::host_update::HostUpdateRecoveryIdentity>,
}

struct LocalTransport {
    alias: String,
    service: HostService,
    desktop_binding: Option<satelle_core::session::DesktopBindingRef>,
    provider_secret_bridge: Mutex<Option<LocalProviderSecretBridge>>,
}

impl LocalTransport {
    fn new(alias: String, service: HostService) -> Self {
        Self {
            alias,
            service,
            desktop_binding: None,
            provider_secret_bridge: Mutex::new(None),
        }
    }

    fn for_selected_host(host: &SelectedHost, service: HostService) -> Self {
        let desktop_binding = host.config.desktop_user.as_deref().map(|desktop_user| {
            satelle_core::session::DesktopBindingRef::new(desktop_user)
                .expect("resolved Host configuration contains a validated desktop binding")
        });
        Self {
            alias: host.alias.clone(),
            service,
            desktop_binding,
            provider_secret_bridge: Mutex::new(None),
        }
    }

    fn attached(
        &self,
        session_id: Option<SessionId>,
        intent: TurnIntent,
        detach_on_interrupt: bool,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        let interrupt = ProcessInterrupt::default();
        self.attached_with_interrupt(session_id, intent, detach_on_interrupt, &interrupt)
    }

    fn attached_with_interrupt(
        &self,
        session_id: Option<SessionId>,
        intent: TurnIntent,
        detach_on_interrupt: bool,
        interrupt: &dyn InterruptSource,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        if detach_on_interrupt {
            return Err(TurnAdmissionFailure::not_admitted(
                SatelleError::invalid_usage(
                    "--detach-on-interrupt requires a remote Host transport",
                ),
            ));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                TurnAdmissionFailure::not_admitted(SatelleError::host_unreachable(&format!(
                    "{} ({error})",
                    self.alias
                )))
            })?;
        runtime.block_on(interrupt.arm()).map_err(|error| {
            TurnAdmissionFailure::not_admitted(SatelleError::host_unreachable(&format!(
                "{} ({error})",
                self.alias
            )))
        })?;
        let service = self.service.clone();
        let operation_service = service.clone();
        let alias = self.alias.clone();
        let operation_alias = alias.clone();
        let cancellation = AdmissionCancellation::new();
        let operation_cancellation = cancellation.clone();
        let (operation_sender, mut operation) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("satelle-local-attached".to_string())
            .spawn(move || {
                let result = match session_id {
                    Some(session_id) => operation_service.steer_with_cancellation(
                        &session_id,
                        &intent,
                        operation_cancellation,
                    ),
                    None => operation_service.run_with_cancellation(
                        &operation_alias,
                        &intent,
                        operation_cancellation,
                    ),
                };
                let _ = operation_sender.send(result);
            })
            .map_err(|error| {
                TurnAdmissionFailure::not_admitted(SatelleError::host_unreachable(&format!(
                    "{alias} ({error})"
                )))
            })?;
        runtime.block_on(async move {
            tokio::select! {
                biased;
                signal = interrupt.wait() => {
                    if let Err(error) = signal {
                        cancellation.request();
                        let wait_error =
                            SatelleError::host_unreachable(&format!("{alias} ({error})"));
                        let result = operation.await.map_err(|_| {
                            TurnAdmissionFailure::admission_unknown(wait_error.clone())
                        })?;
                        return Err(match result {
                            Ok(outcome) => match cancellation.admitted_handle() {
                                Some((_, turn_id)) => TurnAdmissionFailure::admitted(
                                    wait_error,
                                    outcome.session,
                                    turn_id,
                                ),
                                None => TurnAdmissionFailure::admission_unknown(wait_error),
                            },
                            Err(TurnAdmissionFailure::NotAdmitted(_)) => {
                                TurnAdmissionFailure::not_admitted(wait_error)
                            }
                            Err(TurnAdmissionFailure::AdmissionUnknown(_)) => {
                                TurnAdmissionFailure::admission_unknown(wait_error)
                            }
                            Err(TurnAdmissionFailure::Admitted {
                                session, turn_id, ..
                            }) => TurnAdmissionFailure::admitted(
                                wait_error,
                                *session,
                                turn_id,
                            ),
                        });
                    }
                    cancellation.request();
                    let Some((admitted_session_id, turn_id)) = cancellation.admitted_handle() else {
                        let result = operation.await.map_err(|_| {
                            TurnAdmissionFailure::admission_unknown(
                                interrupted_admission_race_error(&alias),
                            )
                        })?;
                        return match result {
                            Ok(_) => Err(TurnAdmissionFailure::admission_unknown(
                                interrupted_admission_race_error(&alias),
                            )),
                            Err(failure) => Err(local_interrupted_admission_failure(failure)),
                        };
                    };
                    let interruption = if detach_on_interrupt {
                        SatelleError::interrupted_attached_command()
                    } else {
                        match service.stop_expected_turn(&admitted_session_id, &turn_id) {
                            Ok(_) => SatelleError::interrupted_attached_command(),
                            Err(error) => unconfirmed_interrupt_error(
                                &alias,
                                &admitted_session_id,
                                error,
                            ),
                        }
                    };
                    let session = service.status(&admitted_session_id).map_err(|status_error| {
                        TurnAdmissionFailure::admission_unknown(
                            interrupted_status_error(
                                &alias,
                                &admitted_session_id,
                                interruption.clone(),
                                status_error,
                            ),
                        )
                    })?;
                    Err(TurnAdmissionFailure::admitted(
                        interruption,
                        session,
                        turn_id,
                    ))
                }
                result = &mut operation => result.map_err(|error| {
                    TurnAdmissionFailure::not_admitted(SatelleError::host_unreachable(
                        &format!("{alias} ({error})"),
                    ))
                })?,
            }
        })
    }
}

fn local_interrupted_admission_failure(failure: TurnAdmissionFailure) -> TurnAdmissionFailure {
    match failure {
        TurnAdmissionFailure::NotAdmitted(error) => {
            TurnAdmissionFailure::not_admitted(local_pre_admission_interruption(*error))
        }
        TurnAdmissionFailure::AdmissionUnknown(error) => {
            TurnAdmissionFailure::admission_unknown(local_pre_admission_interruption(*error))
        }
        failure @ TurnAdmissionFailure::Admitted { .. } => failure,
    }
}

fn unconfirmed_interrupt_error(
    alias: &str,
    session_id: &SessionId,
    stop_error: SatelleError,
) -> SatelleError {
    let status_command = format!("satelle status {session_id} --host {alias}");
    let mut error = SatelleError::interrupted_attached_command();
    error.message = format!(
        "attached command was interrupted, but stop could not be confirmed for Session {session_id}"
    );
    error.recovery_command = Some(status_command.clone());
    error.details.insert(
        "session_id".to_string(),
        serde_json::Value::String(session_id.to_string()),
    );
    error.details.insert(
        "status_command".to_string(),
        serde_json::Value::String(status_command),
    );
    error.details.insert(
        "stop_error_code".to_string(),
        serde_json::Value::String(stop_error.code.as_str().to_string()),
    );
    for (key, value) in stop_error.details {
        error.details.insert(key, value);
    }
    error
}

fn interrupted_status_error(
    alias: &str,
    session_id: &SessionId,
    mut interruption: SatelleError,
    status_error: SatelleError,
) -> SatelleError {
    let status_command = format!("satelle status {session_id} --host {alias}");
    interruption.message = format!(
        "{}; status could not be read for Session {session_id}",
        interruption.message
    );
    interruption.recovery_command = Some(status_command.clone());
    interruption.details.insert(
        "session_id".to_string(),
        serde_json::Value::String(session_id.to_string()),
    );
    interruption.details.insert(
        "status_command".to_string(),
        serde_json::Value::String(status_command),
    );
    interruption.details.insert(
        "status_error_code".to_string(),
        serde_json::Value::String(status_error.code.as_str().to_string()),
    );
    interruption
}

fn local_pre_admission_interruption(source: SatelleError) -> SatelleError {
    let mut error = SatelleError::interrupted_attached_command();
    if let Some(ownership) = source.details.get("ownership") {
        error
            .details
            .insert("ownership".to_string(), ownership.clone());
    }
    error
}

fn interrupted_admission_race_error(alias: &str) -> SatelleError {
    let mut error = SatelleError::interrupted_attached_command();
    error.message =
        "attached command was interrupted, but local admission state could not be reconciled"
            .to_string();
    error.recovery_command = Some(format!("satelle host sessions --host {alias}"));
    error
}

impl TransportClient for LocalTransport {
    fn log_target_identity(&self) -> Result<String, SatelleError> {
        self.service
            .daemon_runtime_status()
            .map(|status| status.host_identity().to_string())
    }

    fn supported_image_media_types(&self) -> Result<Vec<String>, SatelleError> {
        let capabilities = self.service.daemon_runtime_capabilities()?;
        Ok(if capabilities.image_attachments() {
            satelle_transport::SUPPORTED_IMAGE_MEDIA_TYPES
                .iter()
                .map(|value| (*value).to_string())
                .collect()
        } else {
            Vec::new()
        })
    }

    fn setup(
        &self,
        dry_run: bool,
        setup_mode: SetupModeSelection,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        validate_local_daemon_path_overrides(&daemon_path_overrides)?;
        self.service.setup(
            &self.alias,
            dry_run,
            setup_mode.mode.as_str().to_string(),
            setup_components,
            daemon_path_overrides.clone(),
        )
    }

    fn doctor(
        &self,
        scope_selection: &DoctorScopeSelection,
        transport_probe: Arc<dyn ControllerTransportProbe>,
        options: DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> DoctorExecutionResult {
        self.service.doctor_with_provider_intent(
            &self.alias,
            scope_selection,
            transport_probe,
            options,
            provider_intent,
        )
    }

    fn verify_setup(
        &self,
        request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<DoctorReport, SatelleError> {
        let provider_intent = setup_provider_intent(request)?;
        self.service.verify_setup(&self.alias, &provider_intent)
    }

    fn plan_setup_repair(
        &self,
        run_id: Option<&str>,
        probes: &[satelle_transport::SetupRepairProbe],
    ) -> Result<RepairLedgerPlan, SatelleError> {
        let probes = probes
            .iter()
            .map(|probe| {
                satelle_host::SetupRepairProbe::new(
                    &probe.action_id,
                    &probe.label,
                    probe.retry_safe,
                    match probe.postcondition {
                        satelle_transport::SetupRepairPostcondition::Satisfied => {
                            satelle_host::SetupRepairPostcondition::Satisfied
                        }
                        satelle_transport::SetupRepairPostcondition::Unsatisfied => {
                            satelle_host::SetupRepairPostcondition::Unsatisfied
                        }
                        satelle_transport::SetupRepairPostcondition::Unknown => {
                            satelle_host::SetupRepairPostcondition::Unknown
                        }
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let plan =
            self.service
                .plan_setup_repair(self.desktop_binding.as_ref(), run_id, &probes)?;
        Ok(RepairLedgerPlan {
            available: plan.selected_operation_kind().is_some()
                || plan
                    .actions()
                    .iter()
                    .any(|action| action.previous_run_id().is_some()),
            automatic_action_ids: plan
                .automatic_actions()
                .map(|action| action.action_id().to_string())
                .collect(),
            selected_operation_kind: plan.selected_operation_kind().map(|kind| match kind {
                satelle_host::SetupOperationKind::Setup => {
                    satelle_transport::SetupRepairOperationKind::Setup
                }
                satelle_host::SetupOperationKind::Repair => {
                    satelle_transport::SetupRepairOperationKind::Repair
                }
                satelle_host::SetupOperationKind::HostUpdate => {
                    satelle_transport::SetupRepairOperationKind::HostUpdate
                }
                satelle_host::SetupOperationKind::StorageMigration => {
                    satelle_transport::SetupRepairOperationKind::StorageMigration
                }
                satelle_host::SetupOperationKind::ServiceStop => {
                    satelle_transport::SetupRepairOperationKind::ServiceStop
                }
                satelle_host::SetupOperationKind::ServiceRestart => {
                    satelle_transport::SetupRepairOperationKind::ServiceRestart
                }
            }),
            selected_run_status: plan.selected_run_status().map(|status| match status {
                satelle_host::SetupRunStatus::Running => {
                    satelle_transport::SetupRepairRunStatus::Running
                }
                satelle_host::SetupRunStatus::Completed => {
                    satelle_transport::SetupRepairRunStatus::Completed
                }
                satelle_host::SetupRunStatus::Failed => {
                    satelle_transport::SetupRepairRunStatus::Failed
                }
                satelle_host::SetupRunStatus::PartialFailure => {
                    satelle_transport::SetupRepairRunStatus::PartialFailure
                }
                satelle_host::SetupRunStatus::OutcomeUnknown => {
                    satelle_transport::SetupRepairRunStatus::OutcomeUnknown
                }
            }),
            host_update_recovery_identity: plan.host_update_recovery_identity().cloned(),
        })
    }

    fn invalidate_native_readiness(
        &self,
        request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<u64, SatelleError> {
        let provider_intent = setup_provider_intent(request)?;
        self.service
            .invalidate_native_readiness(&self.alias, &provider_intent)
    }

    fn validate_provider_descriptor(
        &self,
        model_alias: &str,
        provider_alias: &str,
        model_alias_from_project: bool,
        provider_alias_from_project: bool,
        mode: satelle_core::ProviderAuthValidationMode,
        experimental_provider_computer_use: bool,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError> {
        let validation = self.service.validate_provider_descriptor(
            &self.alias,
            model_alias,
            provider_alias,
            satelle_host::ProviderDescriptorValidationOptions::new(
                mode,
                model_alias_from_project,
                provider_alias_from_project,
                experimental_provider_computer_use,
            ),
        )?;
        Ok(ProviderDescriptorValidationReport {
            resolved_binding: satelle_core::PublicResolvedProviderBinding::from(
                validation.resolved_binding(),
            ),
            validation: validation.validation(),
        })
    }

    fn authorize_provider_binding(
        &self,
        authorization: &satelle_core::ProviderBindingAuthorization,
    ) -> Result<satelle_core::PublicResolvedProviderBinding, SatelleError> {
        self.service
            .authorize_provider_binding(
                &self.alias,
                authorization.requested_model_alias(),
                authorization.requested_provider_alias(),
                authorization.clone(),
            )
            .map(|binding| satelle_core::PublicResolvedProviderBinding::from(&binding))
    }

    fn preview_provider_secret_provisioning(
        &self,
        metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningPreviewResponse, SatelleError> {
        let bridge = LocalProviderSecretBridge::start(&self.alias, self.service.clone())?;
        let preview = bridge
            .client
            .preview_provider_secret_provisioning(metadata, idempotency_key)
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        *self
            .provider_secret_bridge
            .lock()
            .map_err(|_| SatelleError::host_unreachable(&self.alias))? = Some(bridge);
        Ok(preview)
    }

    fn provision_provider_secret(
        &self,
        preview: &satelle_transport::ProviderSecretProvisioningPreviewResponse,
        metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        secret: Zeroizing<Vec<u8>>,
        idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningResponse, SatelleError> {
        let bridge = self
            .provider_secret_bridge
            .lock()
            .map_err(|_| SatelleError::host_unreachable(&self.alias))?
            .take()
            .ok_or_else(SatelleError::state_conflict)?;
        bridge
            .client
            .provision_provider_secret(preview, metadata, secret, idempotency_key)
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        self.service.host_status()
    }

    fn host_paths(
        &self,
    ) -> Result<satelle_core::daemon_service::DaemonResolvedPathSet, SatelleError> {
        self.service.daemon_resolved_paths()
    }

    fn host_sessions(&self, no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        self.service.host_sessions(&self.alias, no_bootstrap)
    }

    fn run(
        &self,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let intent = local_turn_intent(request).map_err(TurnAdmissionFailure::not_admitted)?;
        let outcome = self.attached(None, intent, detach_on_interrupt)?;
        let turn_id = outcome
            .session
            .turns()
            .last()
            .expect("an admitted local run always contains its target Turn")
            .turn_id()
            .clone();
        let mut provider_smoke = None;
        for event in outcome.events {
            if event.event_type() == satelle_core::EventType::ProviderSmoke {
                provider_smoke = Some(event.data().clone());
            }
            on_event(event).map_err(|error| {
                TurnAdmissionFailure::admitted(error, outcome.session.clone(), turn_id.clone())
            })?;
        }
        Ok(AttachedTurnOutcome {
            session: outcome.session,
            turn_id,
            provider_smoke,
        })
    }

    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError> {
        self.service
            .run_detached(&self.alias, &local_turn_intent(request)?)
    }

    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let intent = local_turn_intent(request).map_err(TurnAdmissionFailure::not_admitted)?;
        let outcome = self.attached(Some(session_id.clone()), intent, detach_on_interrupt)?;
        let turn_id = outcome
            .session
            .turns()
            .last()
            .expect("an admitted local steer always contains its target Turn")
            .turn_id()
            .clone();
        let mut provider_smoke = None;
        for event in outcome.events {
            if event.event_type() == satelle_core::EventType::ProviderSmoke {
                provider_smoke = Some(event.data().clone());
            }
            on_event(event).map_err(|error| {
                TurnAdmissionFailure::admitted(error, outcome.session.clone(), turn_id.clone())
            })?;
        }
        Ok(AttachedTurnOutcome {
            session: outcome.session,
            turn_id,
            provider_smoke,
        })
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError> {
        self.service
            .steer_detached(session_id, &local_turn_intent(request)?)
    }

    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.service.status(session_id)
    }

    fn task_artifacts(&self, session_id: &SessionId) -> Result<TaskArtifacts, SatelleError> {
        self.service
            .task_artifacts(session_id)
            .map(TaskArtifacts::from_host)
    }

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.service.stop(session_id)
    }

    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        if self.alias != LOCAL_DEMO_HOST {
            return Err(SatelleError::host_not_found(self.alias.clone()));
        }
        self.service.daemon_log_page(query)
    }
}

struct LocalProviderSecretBridge {
    client: DaemonClient,
    shutdown: DaemonShutdownHandle,
    server_thread: Option<thread::JoinHandle<()>>,
}

fn local_provider_secret_bridge_startup_channel<T>() -> (mpsc::SyncSender<T>, mpsc::Receiver<T>) {
    // A rendezvous makes successful send the exact ownership handoff. Once a
    // timed-out receiver drops, a late server cannot enter its wait loop.
    mpsc::sync_channel(0)
}

impl LocalProviderSecretBridge {
    fn start(alias: &str, service: HostService) -> Result<Self, SatelleError> {
        let token =
            ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(alias))?;
        let host_identity = service.initialize_daemon()?.host_identity().to_string();
        let service = service.with_ephemeral_bootstrap_auth(
            &token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
        let (started_tx, started_rx) = local_provider_secret_bridge_startup_channel();
        let server_thread = thread::Builder::new()
            .name("satelle-local-provider-secret".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = started_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let server = match DaemonServer::bind(
                        service,
                        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                    )
                    .await
                    {
                        Ok(server) => server,
                        Err(error) => {
                            let _ = started_tx.send(Err(format!("{} ({error})", error.code())));
                            return;
                        }
                    };
                    let started =
                        started_tx.send(Ok((server.local_addr(), server.shutdown_handle())));
                    if started.is_ok() {
                        let _ = server.wait().await;
                    }
                });
            })
            .map_err(|_| SatelleError::host_unreachable(alias))?;
        let (address, shutdown) = started_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| SatelleError::host_unreachable(alias))?
            .map_err(|detail| SatelleError::host_unreachable(&format!("{alias} ({detail})")))?;
        let client = match DaemonClient::loopback(address, token, host_identity) {
            Ok(client) => client,
            Err(error) => {
                shutdown.request_shutdown();
                let _ = server_thread.join();
                return Err(direct_transport_error(alias, error));
            }
        };
        Ok(Self {
            client,
            shutdown,
            server_thread: Some(server_thread),
        })
    }
}

impl Drop for LocalProviderSecretBridge {
    fn drop(&mut self) {
        self.shutdown.request_shutdown();
        if let Some(server_thread) = self.server_thread.take() {
            let _ = server_thread.join();
        }
    }
}

fn validate_local_daemon_path_overrides(
    daemon_path_overrides: &DaemonPathOverrides,
) -> Result<(), SatelleError> {
    for entry in daemon_path_overrides.entries() {
        let path = Path::new(&entry.value);
        if path.is_absolute() && !path.starts_with("~") {
            continue;
        }
        let name = if entry.source == "setup_flag" {
            match entry.environment_variable.as_str() {
                "SATELLE_HOME" => "--daemon-home",
                "SATELLE_CONFIG_FILE" => "--daemon-config-file",
                "SATELLE_STATE_DIR" => "--daemon-state-dir",
                "SATELLE_CACHE_DIR" => "--daemon-cache-dir",
                "SATELLE_LOG_DIR" => "--daemon-log-dir",
                _ => entry.environment_variable.as_str(),
            }
        } else {
            entry.environment_variable.as_str()
        };
        return Err(SatelleError::daemon_path_override_not_absolute(
            name,
            entry.value,
        ));
    }
    Ok(())
}

fn map_ssh_daemon_bootstrap_error(
    alias: &str,
    error: ssh_bootstrap::SshBootstrapError,
) -> SatelleError {
    match error {
        ssh_bootstrap::SshBootstrapError::HostKeyVerificationRequired => {
            SatelleError::ssh_host_key_verification_required(alias)
        }
        ssh_bootstrap::SshBootstrapError::DaemonPathOverrideNotAbsolute { name, value } => {
            SatelleError::daemon_path_override_not_absolute(name, value)
        }
        ssh_bootstrap::SshBootstrapError::OfflineStorageMaintenanceFailed(source) => *source,
        ssh_bootstrap::SshBootstrapError::VerifiedRelease {
            version,
            target,
            source,
        } if source.release_artifact_is_unavailable() => {
            SatelleError::host_artifact_unavailable(&version, target.id())
        }
        ssh_bootstrap::SshBootstrapError::VerifiedRelease {
            version,
            target,
            source,
        } => {
            let mut error = (*source).into_satelle_error();
            error
                .details
                .insert("cli_version".to_string(), serde_json::json!(version));
            error.details.insert(
                "remote_platform".to_string(),
                serde_json::json!(target.id()),
            );
            error
        }
        _ => SatelleError::host_unreachable(alias),
    }
}

fn map_remote_target_error(alias: &str, error: ssh_bootstrap::SshBootstrapError) -> SatelleError {
    match error {
        ssh_bootstrap::SshBootstrapError::UnsupportedPlatform { platform } => {
            SatelleError::host_artifact_unavailable(env!("CARGO_PKG_VERSION"), &platform)
        }
        error => map_ssh_daemon_bootstrap_error(alias, error),
    }
}

fn local_turn_intent(request: &TurnRequest) -> Result<satelle_host::TurnIntent, SatelleError> {
    let attachments = request
        .attachments()
        .iter()
        .map(|attachment| {
            satelle_host::AttachmentUpload::new(
                attachment.media_type(),
                attachment.size_bytes(),
                attachment.sha256(),
                attachment.data_base64(),
            )
        })
        .collect();
    satelle_host::TurnIntent::new(request.prompt(), request.execution_mode())
        .and_then(|intent| {
            let intent = intent.with_provider_intent(
                request.model().map(str::to_string),
                request.provider().map(str::to_string),
                request.refresh_provider_smoke_test(),
            )?;
            Ok(intent.with_project_selection_provenance(
                request.model_from_project(),
                request.provider_from_project(),
            ))
        })
        .map(|intent| {
            intent.with_experimental_provider_computer_use(
                request.experimental_provider_computer_use(),
            )
        })
        .and_then(|intent| {
            intent.with_turn_execution_timeout_ms(request.turn_execution_timeout_ms())
        })
        .and_then(|intent| intent.with_attachments(attachments))
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))
}

struct DirectTransport {
    alias: String,
    mode: &'static str,
    host_identity: String,
    client: Arc<DaemonClient>,
    event_client: DaemonEventClient,
    event_runtime: tokio::runtime::Runtime,
    // Fields drop in declaration order, so the tunnel outlives both clients.
    _tunnel: Option<SshTunnel>,
    // A bootstrapped daemon remains attached to this owned SSH child until all
    // tunneled clients have been dropped.
    _bootstrap: Option<SshBootstrapProcess>,
}

impl DirectTransport {
    fn unsupported(&self, operation: &str) -> SatelleError {
        SatelleError::not_implemented(format!(
            "{} transport for host '{}' does not yet support {operation}",
            self.mode, self.alias
        ))
    }

    fn idempotency_key() -> String {
        Uuid::now_v7().hyphenated().to_string()
    }

    pub(super) fn run_event_error(&self, error: DaemonEventError) -> SatelleError {
        if self.mode == "direct" {
            direct_run_event_error(&self.alias, error)
        } else {
            direct_event_error(&self.alias, error)
        }
    }

    pub(super) fn run_admission_error(
        &self,
    ) -> fn(&str, DaemonClientError) -> TurnAdmissionFailure {
        if self.mode == "direct" {
            direct_run_admission_error
        } else {
            direct_admission_error
        }
    }

    fn run_transport_error(&self, error: DaemonClientError) -> SatelleError {
        if self.mode == "direct" {
            direct_run_transport_error(&self.alias, error)
        } else {
            direct_transport_error(&self.alias, error)
        }
    }
}

struct SshSetupTransport {
    alias: String,
    binding: SshHostBinding,
    host_config: satelle_core::HostConfig,
    requires_first_trust: bool,
    remote_target: Option<ssh_bootstrap::RemoteTarget>,
    remote_directories: Option<ssh_bootstrap::RemoteUserDirectories>,
    release_artifact: Option<ssh_bootstrap::ReleaseArtifactMetadata>,
    current_daemon_artifact: Option<CurrentDaemonArtifactObservation>,
}

#[derive(Debug, Eq, PartialEq)]
enum ExistingTokenVerification {
    Reusable,
    ActivatedPending,
    AuthenticationRejected { token_id: String },
}

#[derive(Debug, Eq, PartialEq)]
enum ExistingTokenInspection {
    Reusable,
    RequiresActivation,
}

#[derive(Clone, Copy)]
enum SetupApplication {
    Planned { existing_token_file: bool },
    AppliedNewToken,
    AppliedReusableToken,
    AppliedPendingActivation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentSetupAction {
    BootstrapHandoff,
    PathSetDirectories,
    ServiceConfig,
    ServiceRegistration,
    ServiceStartOrRestart,
}

const PERSISTENT_SERVICE_ACTIONS: [PersistentSetupAction; 5] = [
    PersistentSetupAction::BootstrapHandoff,
    PersistentSetupAction::PathSetDirectories,
    PersistentSetupAction::ServiceConfig,
    PersistentSetupAction::ServiceRegistration,
    PersistentSetupAction::ServiceStartOrRestart,
];

impl PersistentSetupAction {
    const fn id(self) -> &'static str {
        match self {
            Self::BootstrapHandoff => "bootstrap-handoff",
            Self::PathSetDirectories => "path-set-directories",
            Self::ServiceConfig => "service-config",
            Self::ServiceRegistration => "service-registration",
            Self::ServiceStartOrRestart => "service-start-or-restart",
        }
    }

    const fn is_pre_start(self) -> bool {
        !matches!(self, Self::ServiceStartOrRestart)
    }
}

trait PersistentSetupExecution {
    type Output;

    fn begin(&mut self) -> Result<(), SatelleError>;
    fn start(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError>;
    fn apply(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError>;
    fn complete(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError>;
    fn fail(&mut self, action: PersistentSetupAction, source: SatelleError) -> SatelleError;
    fn finish(&mut self) -> Result<Self::Output, SatelleError>;
}

fn coordinate_persistent_setup(
    execution: &mut impl PersistentSetupExecution<Output = SetupApplication>,
) -> Result<SetupApplication, SatelleError> {
    execution.begin()?;
    for action in PERSISTENT_SERVICE_ACTIONS {
        execution.start(action)?;
        if let Err(source) = execution.apply(action) {
            return if action.is_pre_start() {
                Err(execution.fail(action, source))
            } else {
                // Once service startup has been attempted the bootstrap daemon
                // is gone. Preserve the lock as recovery-pending rather than
                // claiming a definitive failure through an unavailable daemon.
                Err(source)
            };
        }
        execution.complete(action)?;
    }
    execution.finish()
}

enum PreparedPersistentService {
    Windows {
        task: Box<WindowsTaskDefinition>,
        config: Box<WindowsServiceConfigV4>,
    },
    Launchd(ssh_bootstrap::LaunchdServiceDefinition),
}

impl PreparedPersistentService {
    fn definition_parent(&self) -> String {
        let path = match self {
            Self::Windows { task, .. } => task.service_config_path.as_str(),
            Self::Launchd(definition) => definition.plist_path(),
        };
        path.rfind(['/', '\\']).map_or_else(
            || path.to_string(),
            |separator| path[..separator].to_string(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SshPersistentServiceLifecycle {
    Stop,
    Restart,
}

impl SshPersistentServiceLifecycle {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }

    pub(crate) const fn prompt_verb(self) -> &'static str {
        match self {
            Self::Stop => "Stop",
            Self::Restart => "Restart",
        }
    }

    const fn action_id(self) -> &'static str {
        match self {
            Self::Stop => "service-stop",
            Self::Restart => "service-restart",
        }
    }

    const fn bootstrap_operation(self) -> bootstrap_lock::OperationKind {
        match self {
            Self::Stop => bootstrap_lock::OperationKind::ServiceStop,
            Self::Restart => bootstrap_lock::OperationKind::ServiceRestart,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(crate) struct PersistentServiceLifecycleReport {
    pub(crate) host: String,
    pub(crate) action: String,
    pub(crate) status: String,
    pub(crate) service_manager: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CurrentDaemonArtifactObservation {
    current_version: Option<String>,
    minimum_host_version: Option<String>,
    protocol_compatible: bool,
    codex_update_evidence: Option<satelle_core::host_update::CodexUpdateEvidence>,
    #[cfg(test)]
    validated_host_identity: Option<String>,
}

trait CurrentDaemonObservationContract {
    fn daemon_version(&self) -> &str;
    fn minimum_host_version(&self) -> &str;
    #[cfg(test)]
    fn host_identity(&self) -> &str;
    fn codex_update_evidence(&self) -> Option<&satelle_core::host_update::CodexUpdateEvidence>;
}

impl CurrentDaemonObservationContract for satelle_transport::CapabilitiesResponse {
    fn daemon_version(&self) -> &str {
        self.daemon_version()
    }

    fn minimum_host_version(&self) -> &str {
        self.minimum_host_version()
    }

    #[cfg(test)]
    fn host_identity(&self) -> &str {
        self.host_identity()
    }

    fn codex_update_evidence(&self) -> Option<&satelle_core::host_update::CodexUpdateEvidence> {
        None
    }
}

impl CurrentDaemonObservationContract for satelle_transport::MaintenanceUpdateEvidenceResponse {
    fn daemon_version(&self) -> &str {
        self.daemon_version()
    }

    fn minimum_host_version(&self) -> &str {
        self.minimum_host_version()
    }

    #[cfg(test)]
    fn host_identity(&self) -> &str {
        self.host_identity()
    }

    fn codex_update_evidence(&self) -> Option<&satelle_core::host_update::CodexUpdateEvidence> {
        Some(self.codex_update_evidence())
    }
}

impl SshSetupTransport {
    fn new(host: &SelectedHost) -> Result<Self, SatelleError> {
        let requires_first_trust = host.config.expected_host_id.is_none();
        let mut binding_config = host.config.clone();
        if requires_first_trust {
            // A fresh probe identity lets planning validate the SSH Binding
            // without treating any observed daemon identity as trusted.
            binding_config.expected_host_id = Some(format!("setup-discovery-{}", Uuid::now_v7()));
        }
        let binding = SshHostBinding::from_host_config_for_bootstrap(&binding_config)
            .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
        let test_target = cfg!(test).then_some(ssh_bootstrap::RemoteTarget::LinuxX64Gnu);
        Ok(Self {
            alias: host.alias.clone(),
            binding,
            host_config: host.config.clone(),
            requires_first_trust,
            remote_target: test_target,
            remote_directories: test_target.map(ssh_bootstrap::RemoteUserDirectories::for_tests),
            release_artifact: if cfg!(test) {
                Some(ssh_bootstrap::ReleaseArtifactMetadata::from_digest(
                    [0xaa; 32],
                ))
            } else {
                None
            },
            current_daemon_artifact: cfg!(test).then_some(CurrentDaemonArtifactObservation {
                current_version: None,
                minimum_host_version: None,
                protocol_compatible: true,
                codex_update_evidence: None,
                #[cfg(test)]
                validated_host_identity: None,
            }),
        })
    }

    fn new_for_maintenance(host: &SelectedHost) -> Result<Self, SatelleError> {
        // Maintenance can reuse bootstrap transport mechanics only after the
        // Host identity has already crossed the explicit setup trust boundary.
        SshHostBinding::from_host_config_for_bootstrap(&host.config)
            .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
        Self::new(host)
    }

    fn unsupported(&self, operation: &str) -> SatelleError {
        SatelleError::not_implemented(format!(
            "SSH setup transport for host '{}' does not support {operation}",
            self.alias
        ))
    }

    fn validate_setup_request(&self, setup_components: &[String]) -> Result<(), SatelleError> {
        if setup_components != ["transport"] {
            return Err(self.unsupported(
                "components other than the on-demand transport token handoff; rerun with --on-demand --component transport",
            ));
        }
        Ok(())
    }

    fn remote_target(&self) -> Result<ssh_bootstrap::RemoteTarget, SatelleError> {
        self.remote_target.map_or_else(
            || {
                ssh_bootstrap::RemoteTarget::probe(self.binding.destination())
                    .map_err(|error| map_remote_target_error(&self.alias, error))
            },
            Ok,
        )
    }

    fn release_artifact(
        &self,
        target: ssh_bootstrap::RemoteTarget,
        version: &str,
    ) -> Result<ssh_bootstrap::ReleaseArtifactMetadata, SatelleError> {
        self.release_artifact.map_or_else(
            || {
                ssh_bootstrap::ReleaseArtifactMetadata::fetch(target, version)
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))
            },
            Ok,
        )
    }

    fn remote_directories(
        &self,
        target: ssh_bootstrap::RemoteTarget,
    ) -> Result<ssh_bootstrap::RemoteUserDirectories, SatelleError> {
        self.remote_directories.clone().map_or_else(
            || {
                ssh_bootstrap::RemoteUserDirectories::probe(self.binding.destination(), target)
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))
            },
            Ok,
        )
    }

    fn observe_current_daemon_artifact(
        &self,
        existing_token_file: bool,
    ) -> Result<CurrentDaemonArtifactObservation, SatelleError> {
        if let Some(observation) = self.current_daemon_artifact.as_ref() {
            return Ok(observation.clone());
        }
        let tunnel = SshTunnel::open(self.binding.destination()).map_err(|error| match error {
            ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(&self.alias)
            }
            _ => SatelleError::host_unreachable(&self.alias),
        })?;
        let token = if existing_token_file {
            self.read_configured_durable_token()?
        } else {
            ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(&self.alias))?
        };
        self.observe_current_daemon_at(tunnel.local_addr(), token)
    }

    fn observe_maintenance_daemon_artifact(
        &self,
        existing_token_file: bool,
    ) -> Result<CurrentDaemonArtifactObservation, SatelleError> {
        if let Some(observation) = self.current_daemon_artifact.as_ref() {
            return Ok(observation.clone());
        }
        let tunnel = SshTunnel::open(self.binding.destination()).map_err(|error| match error {
            ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(&self.alias)
            }
            _ => SatelleError::host_unreachable(&self.alias),
        })?;
        let token = if existing_token_file {
            self.read_configured_durable_token()?
        } else {
            ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(&self.alias))?
        };
        let client = DaemonClient::loopback_with_timeout(
            tunnel.local_addr(),
            token,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;
        self.current_daemon_observation(client.maintenance_update_evidence())
    }

    fn observe_current_daemon_at(
        &self,
        address: std::net::SocketAddr,
        token: ApiBearerToken,
    ) -> Result<CurrentDaemonArtifactObservation, SatelleError> {
        let first_trust_token = self.requires_first_trust.then(|| token.expose());
        let client = DaemonClient::loopback_with_timeout(
            address,
            token,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;
        if self.requires_first_trust {
            let discovered_identity =
                client
                    .discover_host_identity()
                    .map_err(|error| match error {
                        DaemonClientError::Api { status: _, error }
                            if matches!(
                                error.code(),
                                ApiErrorCode::AuthenticationFailed
                                    | ApiErrorCode::HostIdentityMismatch
                            ) =>
                        {
                            self.unauthenticated_daemon_version_error()
                        }
                        error => direct_transport_error(&self.alias, error),
                    })?;
            let token = ApiBearerToken::parse(
                first_trust_token
                    .expect("first-trust probing retains its typed credential")
                    .as_str(),
            )
            .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
            let client = DaemonClient::loopback_with_timeout(
                address,
                token,
                discovered_identity,
                SSH_DAEMON_REQUEST_TIMEOUT,
            )
            .map_err(|error| direct_transport_error(&self.alias, error))?;
            return self.current_daemon_observation(client.capabilities());
        }
        self.current_daemon_observation(client.capabilities())
    }

    fn current_daemon_observation<T: CurrentDaemonObservationContract>(
        &self,
        response: Result<T, DaemonClientError>,
    ) -> Result<CurrentDaemonArtifactObservation, SatelleError> {
        match response {
            Ok(response) => Ok(CurrentDaemonArtifactObservation {
                current_version: Some(response.daemon_version().to_string()),
                minimum_host_version: Some(response.minimum_host_version().to_string()),
                protocol_compatible: true,
                codex_update_evidence: response.codex_update_evidence().cloned(),
                #[cfg(test)]
                validated_host_identity: Some(response.host_identity().to_string()),
            }),
            Err(DaemonClientError::ProtocolResponseMismatch) => {
                Ok(CurrentDaemonArtifactObservation {
                    current_version: None,
                    minimum_host_version: None,
                    protocol_compatible: false,
                    codex_update_evidence: None,
                    #[cfg(test)]
                    validated_host_identity: None,
                })
            }
            Err(DaemonClientError::Api { status: _, error })
                if error.code() == ApiErrorCode::IncompatibleProtocol =>
            {
                let current_version = error
                    .details()
                    .and_then(|details| details.get("daemon_version"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        SatelleError::config_error(
                            "the protocol-incompatible Host did not report its current version",
                            None,
                        )
                    })?;
                Ok(CurrentDaemonArtifactObservation {
                    current_version: Some(current_version),
                    minimum_host_version: None,
                    protocol_compatible: false,
                    codex_update_evidence: None,
                    #[cfg(test)]
                    validated_host_identity: None,
                })
            }
            Err(DaemonClientError::Api { status: _, error })
                if matches!(
                    error.code(),
                    ApiErrorCode::AuthenticationFailed | ApiErrorCode::HostIdentityMismatch
                ) =>
            {
                Err(self.unauthenticated_daemon_version_error())
            }
            Err(DaemonClientError::Transport(error)) if error.is_connect() => {
                Ok(CurrentDaemonArtifactObservation {
                    current_version: None,
                    minimum_host_version: None,
                    protocol_compatible: true,
                    codex_update_evidence: None,
                    #[cfg(test)]
                    validated_host_identity: None,
                })
            }
            Err(error) => Err(direct_transport_error(&self.alias, error)),
        }
    }

    fn unauthenticated_daemon_version_error(&self) -> SatelleError {
        SatelleError::config_error(
            format!(
                "host '{}' has a reachable Host Daemon whose version cannot be authenticated; restore its durable credential or stop it before replacing the Host artifact",
                self.alias
            ),
            None,
        )
    }

    #[cfg(test)]
    fn with_remote_target_for_tests(mut self, target: ssh_bootstrap::RemoteTarget) -> Self {
        self.remote_target = Some(target);
        self.remote_directories = Some(ssh_bootstrap::RemoteUserDirectories::for_tests(target));
        self
    }

    #[allow(clippy::too_many_arguments)]
    fn setup_report_for_target(
        &self,
        dry_run: bool,
        setup_mode: SetupModeSelection,
        target: ssh_bootstrap::RemoteTarget,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
        application: SetupApplication,
        current_daemon: &CurrentDaemonArtifactObservation,
    ) -> Result<SetupReport, SatelleError> {
        let decision = PersistentServiceDecision::resolve(setup_mode, target.service_platform());
        if decision.explicit_persistent_unsupported {
            return Err(SatelleError::persistent_service_unsupported(
                target.service_platform().as_str(),
            ));
        }
        let mut report = self.setup_report(
            dry_run,
            decision.setup_mode.as_str().to_string(),
            setup_components,
            daemon_path_overrides.clone(),
            application,
        );
        report.service_persistent = decision.service_persistent;
        report.service_scope.clone_from(&decision.service_scope);
        report.fallback_reason.clone_from(&decision.fallback_reason);
        report.target_platform = Some(target.id().to_string());
        report.service_plan = Some(DaemonServicePlan::from_decision(&decision));
        let remote_directories = self.remote_directories(target)?;
        let default_paths = remote_directories.resolved_path_set();
        let current_overrides = DaemonPathOverrides {
            home: self.host_config.daemon_home.clone(),
            config_file: self.host_config.daemon_config_file.clone(),
            state_dir: self.host_config.daemon_state_dir.clone(),
            cache_dir: self.host_config.daemon_cache_dir.clone(),
            log_dir: self.host_config.daemon_log_dir.clone(),
            ..DaemonPathOverrides::default()
        };
        let current_paths = default_paths.with_service_overrides(&current_overrides);
        let planned_paths = current_paths.with_service_overrides(&daemon_path_overrides);
        report.current_daemon_paths = Some(current_paths);
        report.planned_daemon_paths = Some(planned_paths);
        let release = self.release_artifact(target, env!("CARGO_PKG_VERSION"))?;
        report.host_artifact = Some(
            DaemonArtifactPlan::new(
                current_daemon.current_version.as_deref(),
                current_daemon.protocol_compatible,
                env!("CARGO_PKG_VERSION"),
                target.id(),
                &release.digest_hex(),
                target
                    .planned_install_path(&remote_directories, &release.digest())
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?,
                decision.service_persistent,
            )
            .map_err(|error| match error {
                satelle_core::daemon_service::DaemonArtifactPlanError::NewerHostVersion => {
                    SatelleError::host_binary_newer_than_cli(
                        current_daemon
                            .current_version
                            .as_deref()
                            .expect("newer-version evidence includes the observed Host version"),
                        env!("CARGO_PKG_VERSION"),
                    )
                }
                error => SatelleError::config_error(
                    format!("could not construct the Host artifact plan: {error}"),
                    None,
                ),
            })?,
        );
        if decision.service_persistent {
            report.planned_actions.push(format!(
                "install or reconcile the unprivileged {} Host service for {} scope, then require authenticated loopback readiness for the expected Host Identity",
                decision.service_manager.as_str(),
                decision.service_scope,
            ));
            if !matches!(application, SetupApplication::Planned { .. }) {
                report.applied_actions.push(format!(
                    "reconciled the unprivileged {} Host service and verified authenticated loopback readiness",
                    decision.service_manager.as_str(),
                ));
            }
        }
        Ok(report)
    }

    fn setup_report(
        &self,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
        application: SetupApplication,
    ) -> SetupReport {
        let action = match application {
            SetupApplication::AppliedPendingActivation => {
                "activate the existing pending durable control-scoped API token"
            }
            SetupApplication::Planned {
                existing_token_file: true,
            }
            | SetupApplication::AppliedReusableToken => {
                "validate and reuse the existing durable control-scoped API token, or recover an interrupted pending handoff"
            }
            SetupApplication::Planned {
                existing_token_file: false,
            }
            | SetupApplication::AppliedNewToken => {
                "issue, persist, and activate a durable control-scoped API token"
            }
        }
        .to_string();
        let applied = !matches!(application, SetupApplication::Planned { .. });
        let missing_token_file = self.binding.api_token().is_none();
        let path_override_entries = daemon_path_overrides.entries();
        let existing_token_rebind_required = matches!(
            application,
            SetupApplication::Planned {
                existing_token_file: true
            }
        ) && !path_override_entries.is_empty();
        let mut required_input = missing_token_file
            .then(|| SetupRequiredInput {
                component: "transport".to_string(),
                input_kind: "api_token_file_descriptor".to_string(),
                reason: "SSH setup needs an absolute owner-only token-file destination; bearer tokens are never stored inline in config".to_string(),
                recovery_command: format!(
                    "add [hosts.{}.api_token] kind = \"file\" with an absolute path to user-level config, then rerun satelle setup --host {} --on-demand --component transport",
                    self.alias, self.alias
                ),
            })
            .into_iter()
            .collect::<Vec<_>>();
        if existing_token_rebind_required {
            required_input.push(SetupRequiredInput {
                component: "transport".to_string(),
                input_kind: "daemon_path_override_token_rebind_required".to_string(),
                reason: "the existing durable token may belong to the previous remote path set; Satelle will not reuse it for a selected path set or replace the local credential automatically".to_string(),
                recovery_command: format!(
                    "configure a new unused file-backed api_token path for host {}, preserve the existing token file for the old path set, then rerun satelle setup --host {} --on-demand --component transport",
                    self.alias, self.alias
                ),
            });
        }
        let input_required = !required_input.is_empty();
        let recovery_commands = required_input
            .iter()
            .map(|input| input.recovery_command.clone())
            .collect();
        let next_command = required_input.first().map_or_else(
            || format!("satelle run --host {} \"<prompt>\"", self.alias),
            |input| input.recovery_command.clone(),
        );
        let status = if input_required {
            "input_required"
        } else if applied {
            "applied"
        } else {
            "planned"
        };
        let service_persistent = setup_mode == "persistent";
        let mut planned_actions = vec![
            "allow SSH setup to stop the running Host daemon; active Host work may be interrupted"
                .to_string(),
            format!(
                "probe the remote OS, architecture, and runtime family, then upload or verify the invoking CLI v{} matching verified Host artifact for the detected remote platform without requiring a host binary URL or path; do not register a persistent service",
                env!("CARGO_PKG_VERSION")
            ),
        ];
        if self.requires_first_trust {
            planned_actions
                .push("discover and explicitly trust the reachable Host Identity".to_string());
        }
        planned_actions.push(action.clone());
        if !path_override_entries.is_empty() {
            planned_actions.push(if service_persistent {
                "persist daemon path overrides in Satelle-owned service configuration, create or verify every planned daemon directory before restart, preserve old storage directories without migration, and record each override in the setup action ledger"
                    .to_string()
            } else {
                "apply daemon path overrides only to the on-demand Host process; do not persist remote service configuration or migrate storage, preserve old storage directories, and warn that previous sessions may be invisible until the old path is restored"
                    .to_string()
            });
        }
        let mut applied_actions = Vec::new();
        if applied {
            applied_actions.push(
                "probed the remote platform and uploaded or verified the invoking CLI's matching integrity-checked Host artifact"
                    .to_string(),
            );
            applied_actions.push(action);
            if !path_override_entries.is_empty() {
                applied_actions.push(if service_persistent {
                    "persisted explicit daemon path overrides in Satelle-owned service configuration after verifying every planned directory"
                        .to_string()
                } else {
                    "applied explicit daemon path overrides only to the on-demand Host process without persisting service configuration or migrating storage"
                        .to_string()
                });
            }
        }
        SetupReport {
            schema_version: SetupSchemaVersion::V2,
            host: self.alias.clone(),
            dry_run,
            status: status.to_string(),
            cancellation_reason: None,
            verification: None,
            setup_mode,
            service_persistent,
            service_scope: if service_persistent {
                "user".to_string()
            } else {
                "on_demand".to_string()
            },
            fallback_reason: None,
            target_platform: None,
            host_artifact: None,
            service_plan: None,
            current_daemon_paths: None,
            planned_daemon_paths: None,
            setup_components,
            planned_actions,
            applied_actions,
            required_input,
            recovery_commands,
            readiness_summary: SetupReadinessSummary {
                transport: if applied {
                    "ready".to_string()
                } else if input_required {
                    "input_required".to_string()
                } else {
                    "planned".to_string()
                },
                host_daemon: if applied {
                    "durable_auth_ready".to_string()
                } else {
                    "not_checked".to_string()
                },
                codex_runtime: "not_checked".to_string(),
                native_computer_use: "not_checked".to_string(),
                provider_auth: "not_checked".to_string(),
            },
            descriptor_configured: false,
            secret_provisioned: false,
            validation_status: "not_checked".to_string(),
            provider_smoke_test_status: "not_checked".to_string(),
            daemon_path_overrides: path_override_entries,
            changed: applied
                && (service_persistent
                    || matches!(
                        application,
                        SetupApplication::AppliedNewToken
                            | SetupApplication::AppliedPendingActivation
                    )),
            mutated: applied
                && (service_persistent
                    || matches!(
                        application,
                        SetupApplication::AppliedNewToken
                            | SetupApplication::AppliedPendingActivation
                    )),
            mutation_planned: true,
            native_computer_use_readiness: "not_checked".to_string(),
            next_command,
        }
    }

    fn host_config_with_overrides(
        &self,
        daemon_path_overrides: &DaemonPathOverrides,
    ) -> satelle_core::HostConfig {
        let mut host_config = self.host_config.clone();
        host_config.daemon_home = daemon_path_overrides.home.clone();
        host_config.daemon_config_file = daemon_path_overrides.config_file.clone();
        host_config.daemon_state_dir = daemon_path_overrides.state_dir.clone();
        host_config.daemon_cache_dir = daemon_path_overrides.cache_dir.clone();
        host_config.daemon_log_dir = daemon_path_overrides.log_dir.clone();
        host_config
    }

    fn token_file_exists(&self) -> Result<bool, SatelleError> {
        let Some(ApiTokenSource::File { path }) = self.binding.api_token() else {
            return Ok(false);
        };
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(SatelleError::config_error(
                format!(
                    "could not inspect the durable API token path '{}': {error}",
                    path.display()
                ),
                None,
            )),
        }
    }

    fn verify_existing_token(
        &self,
        host_config: &satelle_core::HostConfig,
        bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    ) -> Result<ExistingTokenVerification, SatelleError> {
        let ApiTokenSource::File { path } = self
            .binding
            .api_token()
            .expect("existing token verification requires a file descriptor");
        let raw_token =
            read_owner_only_secret_file(path).map_err(|error| token_file_error(path, error))?;
        let http_token = ApiBearerToken::parse(raw_token.as_str())
            .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
        let token_id = http_token.token_id().to_string();
        let activation_idempotency_key = Uuid::now_v7().to_string();
        // An existing durable token belongs to the canonical daemon. Verify it
        // there before entering bootstrap, because launching an ephemeral Host
        // may release the canonical state owner even when that daemon is healthy.
        let tunnel = SshTunnel::open(self.binding.destination()).map_err(|error| match error {
            ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(&self.alias)
            }
            _ => SatelleError::host_unreachable(&self.alias),
        })?;
        let durable_client = DaemonClient::loopback_with_timeout(
            tunnel.local_addr(),
            http_token,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;

        self.verify_existing_token_with_bootstrap_fallback(
            &durable_client,
            &token_id,
            &activation_idempotency_key,
            bootstrap_lock,
            |bootstrap_lock| {
                let http_token = ApiBearerToken::parse(raw_token.as_str())
                    .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
                let (bootstrap_client, bootstrap_tunnel, _bootstrap, _handoff_token) =
                    setup_bootstrap_client(
                        &self.alias,
                        self.binding.destination(),
                        &self.binding.expected_host_identity().to_string(),
                        &self.host_config,
                        host_config,
                        SshBootstrapScope::Read,
                        bootstrap_lock,
                    )?;
                let durable_client = DaemonClient::loopback_with_timeout(
                    bootstrap_tunnel.local_addr(),
                    http_token,
                    self.binding.expected_host_identity().to_string(),
                    SSH_DAEMON_REQUEST_TIMEOUT,
                )
                .map_err(|error| direct_transport_error(&self.alias, error))?;
                let verification =
                    match inspect_durable_setup_token(&durable_client, token_id.as_str())
                        .map_err(|error| direct_transport_error(&self.alias, error))?
                    {
                        ExistingTokenInspection::Reusable => ExistingTokenVerification::Reusable,
                        ExistingTokenInspection::RequiresActivation => {
                            bootstrap_lock
                                .mark_mutation_started("durable_token_verification")
                                .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
                            let verification = activate_durable_setup_token(
                                &durable_client,
                                token_id.clone(),
                                &activation_idempotency_key,
                            )
                            .map_err(|error| direct_transport_error(&self.alias, error))?;
                            // Both activation and an explicit authentication rejection
                            // are known terminal outcomes for this exact attempt.
                            commit_verified_bootstrap_mutation(&self.alias, bootstrap_lock)?;
                            verification
                        }
                    };
                if !matches!(
                    verification,
                    ExistingTokenVerification::AuthenticationRejected { .. }
                ) {
                    complete_bootstrap_handoff(&self.alias, &bootstrap_client, bootstrap_lock)?;
                }
                Ok(verification)
            },
        )
    }

    fn verify_existing_token_with_bootstrap_fallback(
        &self,
        durable_client: &DaemonClient,
        token_id: &str,
        activation_idempotency_key: &str,
        bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
        bootstrap_verification: impl FnOnce(
            &mut ssh_bootstrap::SshBootstrapLock,
        ) -> Result<ExistingTokenVerification, SatelleError>,
    ) -> Result<ExistingTokenVerification, SatelleError> {
        match inspect_durable_setup_token(durable_client, token_id) {
            Ok(ExistingTokenInspection::Reusable) => Ok(ExistingTokenVerification::Reusable),
            Ok(ExistingTokenInspection::RequiresActivation) => {
                bootstrap_lock
                    .mark_mutation_started("durable_token_verification")
                    .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
                let verification = activate_durable_setup_token(
                    durable_client,
                    token_id.to_string(),
                    activation_idempotency_key,
                )
                .map_err(|error| direct_transport_error(&self.alias, error))?;
                // An explicit rejection proves that this activation attempt did
                // not mutate the daemon. Commit that known outcome before the
                // bootstrap fallback opens its next fenced phase.
                commit_verified_bootstrap_mutation(&self.alias, bootstrap_lock)?;
                match verification {
                    ExistingTokenVerification::AuthenticationRejected { .. } => {
                        bootstrap_verification(bootstrap_lock)
                    }
                    verification => Ok(verification),
                }
            }
            Err(DaemonClientError::Transport(_)) => bootstrap_verification(bootstrap_lock),
            Err(error) => Err(direct_transport_error(&self.alias, error)),
        }
    }

    fn recover_interrupted_token(
        &self,
        token_id: &str,
        host_config: &satelle_core::HostConfig,
        bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    ) -> Result<(), SatelleError> {
        let ApiTokenSource::File { path } = self
            .binding
            .api_token()
            .expect("setup recovery requires a file descriptor");
        let (bootstrap_client, _tunnel, _bootstrap, _handoff_token) = setup_bootstrap_client(
            &self.alias,
            self.binding.destination(),
            &self.binding.expected_host_identity().to_string(),
            &self.host_config,
            host_config,
            SshBootstrapScope::Admin,
            bootstrap_lock,
        )?;
        rollback_setup_token(
            &bootstrap_client,
            token_id,
            path,
            &self.alias,
            &Uuid::now_v7().to_string(),
        )
    }

    fn provision_token(
        &self,
        host_config: &satelle_core::HostConfig,
        bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    ) -> Result<(), SatelleError> {
        let ApiTokenSource::File { path } = self
            .binding
            .api_token()
            .expect("setup apply follows a plan with a token-file descriptor");
        let (bootstrap_client, tunnel, _bootstrap, _handoff_token) = setup_bootstrap_client(
            &self.alias,
            self.binding.destination(),
            &self.binding.expected_host_identity().to_string(),
            &self.host_config,
            host_config,
            SshBootstrapScope::Admin,
            bootstrap_lock,
        )?;
        let issuance_idempotency_key = Uuid::now_v7().to_string();
        let issuance = bootstrap_client
            .issue_durable_setup_token(&issuance_idempotency_key)
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        let token_id = issuance.token_id().to_string();
        let abort_idempotency_key = Uuid::now_v7().to_string();
        if time::OffsetDateTime::parse(
            issuance.pending_expires_at(),
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        {
            let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_idempotency_key);
            return Err(SatelleError::host_unreachable(&self.alias));
        }
        let Some(raw_token) = issuance.into_bearer_token() else {
            let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_idempotency_key);
            return Err(SatelleError::host_unreachable(&self.alias));
        };
        let verification_token = match ApiBearerToken::parse(raw_token.as_str()) {
            Ok(token) => token,
            Err(_) => {
                let _ =
                    bootstrap_client.abort_durable_setup_token(&token_id, &abort_idempotency_key);
                return Err(SatelleError::host_unreachable(&self.alias));
            }
        };
        if verification_token.token_id() != token_id {
            let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_idempotency_key);
            return Err(SatelleError::host_unreachable(&self.alias));
        }
        if let Err(error) = persist_new_owner_only_secret_file(path, raw_token.as_str()) {
            // A published file that could not be removed still contains the
            // pending recovery credential. Keep its remote token recoverable;
            // aborting would strand a revoked file at the no-replace path.
            if error != SecureFileError::PublishedCleanupFailed {
                let _ =
                    bootstrap_client.abort_durable_setup_token(&token_id, &abort_idempotency_key);
            }
            return Err(token_file_error(path, error));
        }

        let activation_idempotency_key = Uuid::now_v7().to_string();
        let activated = bootstrap_client
            .activate_durable_setup_token(&token_id, &activation_idempotency_key)
            .map_err(|error| direct_transport_error(&self.alias, error))
            .map_err(|error| {
                rollback_setup_token(
                    &bootstrap_client,
                    &token_id,
                    path,
                    &self.alias,
                    &abort_idempotency_key,
                )
                .err()
                .unwrap_or(error)
            })?;
        if !activated.active() || activated.token_id() != token_id {
            let error = SatelleError::host_unreachable(&self.alias);
            return Err(rollback_setup_token(
                &bootstrap_client,
                &token_id,
                path,
                &self.alias,
                &abort_idempotency_key,
            )
            .err()
            .unwrap_or(error));
        }
        let durable_client = DaemonClient::loopback_with_timeout(
            tunnel.local_addr(),
            verification_token,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))
        .map_err(|error| {
            rollback_setup_token(
                &bootstrap_client,
                &token_id,
                path,
                &self.alias,
                &abort_idempotency_key,
            )
            .err()
            .unwrap_or(error)
        })?;
        if let Err(error) = durable_client.capabilities() {
            let error = direct_transport_error(&self.alias, error);
            return Err(rollback_setup_token(
                &bootstrap_client,
                &token_id,
                path,
                &self.alias,
                &abort_idempotency_key,
            )
            .err()
            .unwrap_or(error));
        }
        complete_bootstrap_handoff(&self.alias, &bootstrap_client, bootstrap_lock)
    }
}

impl SshSetupTransport {
    fn issue_persistent_durable_token(
        &self,
        bootstrap_client: &DaemonClient,
        tunnel_addr: std::net::SocketAddr,
    ) -> Result<ApiBearerToken, SatelleError> {
        let ApiTokenSource::File { path } = self
            .binding
            .api_token()
            .expect("persistent setup follows a plan with a token-file descriptor");
        let issuance = bootstrap_client
            .issue_durable_setup_token(&Uuid::now_v7().to_string())
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        let token_id = issuance.token_id().to_string();
        let abort_key = Uuid::now_v7().to_string();
        if time::OffsetDateTime::parse(
            issuance.pending_expires_at(),
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        {
            let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_key);
            return Err(SatelleError::host_unreachable(&self.alias));
        }
        let Some(raw_token) = issuance.into_bearer_token() else {
            let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_key);
            return Err(SatelleError::host_unreachable(&self.alias));
        };
        let verification_token = ApiBearerToken::parse(raw_token.as_str())
            .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
        if verification_token.token_id() != token_id {
            let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_key);
            return Err(SatelleError::host_unreachable(&self.alias));
        }
        if let Err(error) = persist_new_owner_only_secret_file(path, raw_token.as_str()) {
            if error != SecureFileError::PublishedCleanupFailed {
                let _ = bootstrap_client.abort_durable_setup_token(&token_id, &abort_key);
            }
            return Err(token_file_error(path, error));
        }
        let activated = bootstrap_client
            .activate_durable_setup_token(&token_id, &Uuid::now_v7().to_string())
            .map_err(|error| direct_transport_error(&self.alias, error))
            .map_err(|error| {
                rollback_setup_token(bootstrap_client, &token_id, path, &self.alias, &abort_key)
                    .err()
                    .unwrap_or(error)
            })?;
        if !activated.active() || activated.token_id() != token_id {
            let error = SatelleError::host_unreachable(&self.alias);
            return Err(rollback_setup_token(
                bootstrap_client,
                &token_id,
                path,
                &self.alias,
                &abort_key,
            )
            .err()
            .unwrap_or(error));
        }
        let durable_client = DaemonClient::loopback_with_timeout(
            tunnel_addr,
            ApiBearerToken::parse(raw_token.as_str())
                .map_err(|_| SatelleError::host_unreachable(&self.alias))?,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;
        durable_client
            .capabilities()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(verification_token)
    }

    fn persistent_durable_token(
        &self,
        bootstrap_client: &DaemonClient,
        tunnel_addr: std::net::SocketAddr,
        existing_token_file: bool,
    ) -> Result<(SetupApplication, ApiBearerToken), SatelleError> {
        if !existing_token_file {
            return self
                .issue_persistent_durable_token(bootstrap_client, tunnel_addr)
                .map(|token| (SetupApplication::AppliedNewToken, token));
        }
        let ApiTokenSource::File { path } = self
            .binding
            .api_token()
            .expect("persistent setup follows a plan with a token-file descriptor");
        let raw_token =
            read_owner_only_secret_file(path).map_err(|error| token_file_error(path, error))?;
        let token = ApiBearerToken::parse(raw_token.as_str())
            .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
        let token_id = token.token_id().to_string();
        let durable_client = DaemonClient::loopback_with_timeout(
            tunnel_addr,
            ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;
        match inspect_durable_setup_token(&durable_client, &token_id)
            .map_err(|error| direct_transport_error(&self.alias, error))?
        {
            ExistingTokenInspection::Reusable => {
                Ok((SetupApplication::AppliedReusableToken, token))
            }
            ExistingTokenInspection::RequiresActivation => match activate_durable_setup_token(
                &durable_client,
                token_id.clone(),
                &Uuid::now_v7().to_string(),
            )
            .map_err(|error| direct_transport_error(&self.alias, error))?
            {
                ExistingTokenVerification::ActivatedPending => {
                    Ok((SetupApplication::AppliedPendingActivation, token))
                }
                ExistingTokenVerification::AuthenticationRejected { .. } => {
                    rollback_setup_token(
                        bootstrap_client,
                        &token_id,
                        path,
                        &self.alias,
                        &Uuid::now_v7().to_string(),
                    )?;
                    self.issue_persistent_durable_token(bootstrap_client, tunnel_addr)
                        .map(|token| (SetupApplication::AppliedNewToken, token))
                }
                ExistingTokenVerification::Reusable => {
                    Err(SatelleError::host_unreachable(&self.alias))
                }
            },
        }
    }

    fn prepare_persistent_service(
        &self,
        target: ssh_bootstrap::RemoteTarget,
        artifact: &ssh_bootstrap::UploadedHostArtifact,
        daemon_path_overrides: &DaemonPathOverrides,
        remote: &ssh_bootstrap::PersistentServiceRemote<'_>,
    ) -> Result<PreparedPersistentService, SatelleError> {
        let storage_policy = PersistentHostStoragePolicy::from_host_config(&self.host_config);
        match target.service_platform() {
            DaemonServicePlatform::Windows => {
                let task = remote
                    .prepare_windows_task(
                        &self.binding.expected_host_identity().to_string(),
                        artifact,
                    )
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
                let config = WindowsServiceConfigV4::new(
                    "127.0.0.1:3001",
                    daemon_path_overrides,
                    storage_policy,
                )
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
                Ok(PreparedPersistentService::Windows {
                    task: Box::new(task),
                    config: Box::new(config),
                })
            }
            DaemonServicePlatform::Macos => remote
                .launchd_definition(artifact, daemon_path_overrides, storage_policy)
                .map(PreparedPersistentService::Launchd)
                .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error)),
            DaemonServicePlatform::Linux => Err(SatelleError::persistent_service_unsupported(
                target.service_platform().as_str(),
            )),
        }
    }

    fn apply_persistent_setup(
        &self,
        target: ssh_bootstrap::RemoteTarget,
        host_config: &satelle_core::HostConfig,
        daemon_path_overrides: &DaemonPathOverrides,
        existing_token_file: bool,
        required_directories: Vec<String>,
        bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    ) -> Result<SetupApplication, SatelleError> {
        let directories = self.remote_directories(target)?;
        let (bootstrap_client, bootstrap_tunnel, bootstrap_process, _handoff_token) =
            setup_bootstrap_client(
                &self.alias,
                self.binding.destination(),
                &self.binding.expected_host_identity().to_string(),
                &self.host_config,
                host_config,
                SshBootstrapScope::Admin,
                bootstrap_lock,
            )?;
        let mut execution = RemotePersistentSetupExecution {
            transport: self,
            target,
            daemon_path_overrides,
            required_directories,
            bootstrap_lock,
            directories,
            bootstrap_client: Some(bootstrap_client),
            bootstrap_tunnel: Some(bootstrap_tunnel),
            bootstrap_process: Some(bootstrap_process),
            existing_token_file,
            application: None,
            active_token: None,
            artifact: None,
            service: None,
            previous_observation: None,
            durable_tunnel: None,
            durable_client: None,
        };
        coordinate_persistent_setup(&mut execution)
    }

    fn read_configured_durable_token(&self) -> Result<ApiBearerToken, SatelleError> {
        let Some(ApiTokenSource::File { path }) = self.binding.api_token() else {
            return Err(SatelleError::config_error(
                format!(
                    "host '{}' requires an absolute file-backed durable API token before persistent service lifecycle commands can run",
                    self.alias
                ),
                None,
            ));
        };
        let raw_token =
            read_owner_only_secret_file(path).map_err(|error| token_file_error(path, error))?;
        ApiBearerToken::parse(raw_token.as_str())
            .map_err(|error| SatelleError::config_error(error.to_string(), None))
    }

    fn durable_service_client(&self) -> Result<(SshTunnel, DaemonClient), SatelleError> {
        let tunnel = SshTunnel::open(self.binding.destination()).map_err(|error| match error {
            ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(&self.alias)
            }
            _ => SatelleError::host_unreachable(&self.alias),
        })?;
        let client = DaemonClient::loopback_with_timeout(
            tunnel.local_addr(),
            self.read_configured_durable_token()?,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok((tunnel, client))
    }
}

struct RemotePersistentSetupExecution<'a> {
    transport: &'a SshSetupTransport,
    target: ssh_bootstrap::RemoteTarget,
    daemon_path_overrides: &'a DaemonPathOverrides,
    required_directories: Vec<String>,
    bootstrap_lock: &'a mut ssh_bootstrap::SshBootstrapLock,
    directories: ssh_bootstrap::RemoteUserDirectories,
    bootstrap_client: Option<Arc<DaemonClient>>,
    bootstrap_tunnel: Option<SshTunnel>,
    bootstrap_process: Option<SshBootstrapProcess>,
    existing_token_file: bool,
    application: Option<SetupApplication>,
    active_token: Option<ApiBearerToken>,
    artifact: Option<ssh_bootstrap::UploadedHostArtifact>,
    service: Option<PreparedPersistentService>,
    previous_observation: Option<ssh_bootstrap::PersistentServiceObservation>,
    durable_tunnel: Option<SshTunnel>,
    durable_client: Option<DaemonClient>,
}

impl RemotePersistentSetupExecution<'_> {
    fn bootstrap_client(&self) -> &DaemonClient {
        self.bootstrap_client
            .as_deref()
            .expect("the bootstrap daemon remains available before service startup")
    }

    fn apply_bootstrap_handoff(&mut self) -> Result<(), SatelleError> {
        let tunnel_addr = self
            .bootstrap_tunnel
            .as_ref()
            .expect("the bootstrap tunnel remains available during handoff")
            .local_addr();
        let (application, active_token) = self.transport.persistent_durable_token(
            self.bootstrap_client(),
            tunnel_addr,
            self.existing_token_file,
        )?;
        let artifact = {
            let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
                self.transport.binding.destination(),
                self.target,
                &self.directories,
                self.bootstrap_lock,
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
            remote
                .install_current_host_artifact()
                .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?
        };
        let service = {
            let remote = ssh_bootstrap::PersistentServiceRemote::new(
                self.transport.binding.destination(),
                self.target,
                &self.directories,
                self.bootstrap_lock,
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
            self.transport.prepare_persistent_service(
                self.target,
                &artifact,
                self.daemon_path_overrides,
                &remote,
            )?
        };
        // Artifact staging can contain several terminal fenced substeps. The
        // final publication attempt is the logical action mutation and must be
        // committed exactly once before the ledger action can complete.
        commit_verified_bootstrap_mutation(&self.transport.alias, self.bootstrap_lock)?;
        self.required_directories.push(service.definition_parent());
        self.required_directories.sort();
        self.required_directories.dedup();
        self.application = Some(application);
        self.active_token = Some(active_token);
        self.artifact = Some(artifact);
        self.service = Some(service);
        Ok(())
    }

    fn apply_directories(&mut self) -> Result<(), SatelleError> {
        let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
            self.transport.binding.destination(),
            self.target,
            &self.directories,
            self.bootstrap_lock,
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        remote
            .ensure_owner_only_directories(&self.required_directories)
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        commit_verified_bootstrap_mutation(&self.transport.alias, self.bootstrap_lock)
    }

    fn apply_service_config(&mut self) -> Result<(), SatelleError> {
        let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
            self.transport.binding.destination(),
            self.target,
            &self.directories,
            self.bootstrap_lock,
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        match self
            .service
            .as_ref()
            .expect("artifact action prepares service")
        {
            PreparedPersistentService::Windows { task, config } => {
                remote.publish_windows_service_config(task, config)
            }
            PreparedPersistentService::Launchd(definition) => {
                remote.publish_launchd_definition(definition)
            }
        }
        .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        commit_verified_bootstrap_mutation(&self.transport.alias, self.bootstrap_lock)
    }

    fn apply_service_registration(&mut self) -> Result<(), SatelleError> {
        let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
            self.transport.binding.destination(),
            self.target,
            &self.directories,
            self.bootstrap_lock,
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        let service = self
            .service
            .as_ref()
            .expect("artifact action prepares service");
        let (observed, reconciled) = (|| {
            let observed = match service {
                PreparedPersistentService::Windows { task, .. } => {
                    remote.observe_windows_task(task)?
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.observe_launchd(definition)?
                }
            };
            match service {
                PreparedPersistentService::Windows { task, .. } => {
                    remote.register_windows_task(task)?
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.register_launchd(definition)?
                }
            }
            let reconciled = match service {
                PreparedPersistentService::Windows { task, .. } => {
                    remote.observe_windows_task(task)?
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.observe_launchd(definition)?
                }
            };
            Ok::<_, ssh_bootstrap::SshBootstrapError>((observed, reconciled))
        })()
        .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        if reconciled != ssh_bootstrap::PersistentServiceObservation::Matching {
            return Err(SatelleError::host_unreachable(&self.transport.alias));
        }
        commit_verified_bootstrap_mutation(&self.transport.alias, self.bootstrap_lock)?;
        self.previous_observation = Some(observed);
        Ok(())
    }

    fn apply_service_start(&mut self) -> Result<(), SatelleError> {
        drop(self.bootstrap_process.take());
        drop(self.bootstrap_client.take());
        drop(self.bootstrap_tunnel.take());
        {
            let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
                self.transport.binding.destination(),
                self.target,
                &self.directories,
                self.bootstrap_lock,
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
            let restart = self.previous_observation
                != Some(ssh_bootstrap::PersistentServiceObservation::Absent);
            match (
                self.service
                    .as_ref()
                    .expect("artifact action prepares service"),
                restart,
            ) {
                (PreparedPersistentService::Windows { task, .. }, false) => {
                    remote.start_windows_task(task)
                }
                (PreparedPersistentService::Windows { task, .. }, true) => {
                    remote.restart_windows_task(task)
                }
                (PreparedPersistentService::Launchd(_), false) => remote.kickstart_launchd(),
                (PreparedPersistentService::Launchd(_), true) => remote.restart_launchd(),
            }
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))?;
        }
        let durable_tunnel =
            SshTunnel::open(self.transport.binding.destination()).map_err(|error| match error {
                ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                    SatelleError::ssh_host_key_verification_required(&self.transport.alias)
                }
                _ => SatelleError::host_unreachable(&self.transport.alias),
            })?;
        let durable_client = DaemonClient::loopback_with_timeout(
            durable_tunnel.local_addr(),
            self.transport.read_configured_durable_token()?,
            self.transport.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.transport.alias, error))?;
        wait_for_durable_daemon(&self.transport.alias, || durable_client.capabilities())?;
        commit_verified_bootstrap_mutation(&self.transport.alias, self.bootstrap_lock)?;
        begin_persistent_maintenance(&self.transport.alias, &durable_client, self.bootstrap_lock)?;
        self.durable_tunnel = Some(durable_tunnel);
        self.durable_client = Some(durable_client);
        Ok(())
    }
}

impl PersistentSetupExecution for RemotePersistentSetupExecution<'_> {
    type Output = SetupApplication;

    fn begin(&mut self) -> Result<(), SatelleError> {
        let client = self
            .bootstrap_client
            .as_deref()
            .expect("the bootstrap daemon remains available before service startup");
        begin_persistent_maintenance(&self.transport.alias, client, self.bootstrap_lock)
    }

    fn start(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError> {
        let client = self
            .durable_client
            .as_ref()
            .or(self.bootstrap_client.as_deref())
            .expect("maintenance requires a live bootstrap or durable daemon");
        start_persistent_action(
            &self.transport.alias,
            client,
            self.bootstrap_lock,
            action.id(),
        )
    }

    fn apply(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError> {
        match action {
            PersistentSetupAction::BootstrapHandoff => self.apply_bootstrap_handoff(),
            PersistentSetupAction::PathSetDirectories => self.apply_directories(),
            PersistentSetupAction::ServiceConfig => self.apply_service_config(),
            PersistentSetupAction::ServiceRegistration => self.apply_service_registration(),
            PersistentSetupAction::ServiceStartOrRestart => self.apply_service_start(),
        }
    }

    fn complete(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError> {
        let client = self
            .durable_client
            .as_ref()
            .or(self.bootstrap_client.as_deref())
            .expect("maintenance requires a live bootstrap or durable daemon");
        complete_persistent_action(
            &self.transport.alias,
            client,
            self.bootstrap_lock,
            action.id(),
        )
    }

    fn fail(&mut self, action: PersistentSetupAction, source: SatelleError) -> SatelleError {
        let Some(client) = self.bootstrap_client.as_deref() else {
            return source;
        };
        let _ = record_persistent_action_failure(
            &self.transport.alias,
            client,
            self.bootstrap_lock,
            action.id(),
            "remote_command_failed",
        )
        .and_then(|()| {
            finish_persistent_maintenance(&self.transport.alias, client, self.bootstrap_lock)
        })
        .and_then(|()| {
            self.bootstrap_lock
                .release_committed_handoff()
                .map_err(|_| SatelleError::host_unreachable(&self.transport.alias))
        });
        // The original error remains the user-facing cause. Any failure to
        // close the known partial run leaves the same operation and fence
        // recovery-pending rather than claiming cleanup succeeded.
        source
    }

    fn finish(&mut self) -> Result<Self::Output, SatelleError> {
        finish_persistent_maintenance(
            &self.transport.alias,
            self.durable_client
                .as_ref()
                .expect("authenticated readiness establishes the durable daemon"),
            self.bootstrap_lock,
        )?;
        self.bootstrap_lock
            .release_committed_handoff()
            .map_err(|_| SatelleError::host_unreachable(&self.transport.alias))?;
        self.application
            .ok_or_else(|| SatelleError::host_unreachable(&self.transport.alias))
    }
}

pub(crate) fn manage_ssh_persistent_service(
    host: &SelectedHost,
    lifecycle: SshPersistentServiceLifecycle,
) -> Result<PersistentServiceLifecycleReport, SatelleError> {
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::invalid_usage(format!(
            "host '{}' must have a trusted expected Host Identity before persistent service lifecycle commands can run",
            transport.alias
        )));
    }
    let target = transport.remote_target()?;
    if target.service_platform() == DaemonServicePlatform::Linux {
        return Err(SatelleError::persistent_service_unsupported(
            target.service_platform().as_str(),
        ));
    }
    let directories = transport.remote_directories(target)?;
    let operation_id = format!("service-lifecycle-{}", Uuid::now_v7());
    let (durable_tunnel, durable_client) = transport.durable_service_client()?;
    durable_client
        .capabilities()
        .map_err(|error| direct_transport_error(&transport.alias, error))?;
    let mut bootstrap_lock = acquire_bootstrap_lock_for_operation(
        &transport.alias,
        transport.binding.destination(),
        operation_id,
        lifecycle.bootstrap_operation(),
    )?;
    confirm_bootstrap_lock(&transport.alias, &mut bootstrap_lock)?;

    // Finish all read-only validation before occupying the Host maintenance
    // slot. A missing or drifted definition can then fail without stranding a
    // live daemon behind an operation that no retry can adopt.
    let prerequisites = (|| {
        let remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        )?;
        let expected_host_id = transport.binding.expected_host_identity().to_string();
        let overrides = remote.observe_canonical_daemon_path_overrides(&expected_host_id)?;
        let windows_task = if target.service_platform() == DaemonServicePlatform::Windows {
            Some(remote.registered_windows_task(&expected_host_id)?)
        } else {
            None
        };
        Ok::<_, ssh_bootstrap::SshBootstrapError>((overrides, windows_task))
    })();
    let (persisted_overrides, windows_task) = match prerequisites {
        Ok(prerequisites) => prerequisites,
        Err(error) => {
            bootstrap_lock
                .release_unmodified()
                .map_err(|_| SatelleError::host_unreachable(&transport.alias))?;
            return Err(map_ssh_daemon_bootstrap_error(&transport.alias, error));
        }
    };

    begin_service_lifecycle_maintenance(
        &transport.alias,
        &durable_client,
        &mut bootstrap_lock,
        lifecycle,
    )?;
    start_persistent_action(
        &transport.alias,
        &durable_client,
        &mut bootstrap_lock,
        lifecycle.action_id(),
    )?;

    let lifecycle_result = match lifecycle {
        SshPersistentServiceLifecycle::Restart => restart_persistent_service(
            &transport,
            target,
            &directories,
            windows_task.as_ref(),
            &mut bootstrap_lock,
        ),
        SshPersistentServiceLifecycle::Stop => stop_persistent_service(
            &transport,
            target,
            &directories,
            &persisted_overrides,
            windows_task.as_ref(),
            &mut bootstrap_lock,
        ),
    };
    if let Err(source) = lifecycle_result {
        if durable_client.capabilities().is_ok()
            && record_persistent_action_failure(
                &transport.alias,
                &durable_client,
                &mut bootstrap_lock,
                lifecycle.action_id(),
                "remote_command_failed",
            )
            .and_then(|()| {
                finish_persistent_maintenance(
                    &transport.alias,
                    &durable_client,
                    &mut bootstrap_lock,
                )
            })
            .and_then(|()| {
                bootstrap_lock
                    .release_committed_handoff()
                    .map_err(|_| SatelleError::host_unreachable(&transport.alias))
            })
            .is_ok()
        {
            drop(durable_client);
            drop(durable_tunnel);
        }
        return Err(source);
    }
    drop(durable_client);
    drop(durable_tunnel);
    bootstrap_lock
        .release_committed_handoff()
        .map_err(|_| SatelleError::host_unreachable(&transport.alias))?;

    let service_manager = match target.service_platform() {
        DaemonServicePlatform::Windows => "task_scheduler",
        DaemonServicePlatform::Macos => "launchd",
        DaemonServicePlatform::Linux => unreachable!("Linux returned before service mutation"),
    };
    Ok(PersistentServiceLifecycleReport {
        host: transport.alias,
        action: lifecycle.as_str().to_string(),
        status: if lifecycle == SshPersistentServiceLifecycle::Stop {
            "stopped"
        } else {
            "running"
        }
        .to_string(),
        service_manager: service_manager.to_string(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SshStorageMaintenance {
    Restore,
    BackupCleanup,
    StoreReset,
}

impl SshStorageMaintenance {
    const fn token(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::BackupCleanup => "backup-cleanup",
            Self::StoreReset => "store-reset",
        }
    }

    const fn action_id(self) -> &'static str {
        match self {
            Self::Restore => "restore-storage-backup",
            Self::BackupCleanup => "cleanup-storage-backups",
            Self::StoreReset => "reset-host-store",
        }
    }

    fn recovery_command(
        self,
        host: &str,
        backup: Option<&Path>,
        delete_recordings: bool,
    ) -> String {
        let host = crate::shell_argument(host);
        match self {
            Self::Restore => format!(
                "satelle host storage restore --host {host} --backup {} --no-input --yes",
                crate::shell_argument(
                    &backup
                        .expect("restore maintenance has a backup")
                        .display()
                        .to_string()
                )
            ),
            Self::BackupCleanup => {
                format!("satelle host storage backup cleanup --host {host} --no-input --yes")
            }
            Self::StoreReset => format!(
                "satelle host store reset --host {host}{} --no-input --yes",
                if delete_recordings {
                    " --delete-recordings"
                } else {
                    ""
                }
            ),
        }
    }

    fn completion_recovery_command(self, host: &str, operation_id: &str) -> String {
        format!(
            "satelle host storage-completion-recovery --host {} --operation {} \
             --operation-id {} --no-input --yes",
            crate::shell_argument(host),
            self.token(),
            crate::shell_argument(operation_id),
        )
    }
}

fn is_remote_storage_completion_failure(source: &SatelleError) -> bool {
    source.code == ErrorCode::SetupPartiallyApplied
        && source
            .details
            .get("failed_action")
            .and_then(serde_json::Value::as_str)
            == Some("record-storage-maintenance-ledger-completion")
}

fn bind_remote_storage_completion_recovery(
    mut source: SatelleError,
    recovery_command: &str,
) -> SatelleError {
    if is_remote_storage_completion_failure(&source) {
        source.recovery_command = Some(recovery_command.to_string());
        source.details.insert(
            "recovery_command".to_string(),
            serde_json::Value::String(recovery_command.to_string()),
        );
    }
    source
}

fn storage_maintenance_partial_error(
    host: &str,
    completed_actions: &[String],
    failed_action: &str,
    skipped_actions: &[String],
    recovery_command: &str,
    source: SatelleError,
) -> SatelleError {
    // A remote completion failure already owns a durable operation and
    // returns its exact reconciliation command. Other source errors can carry
    // generic advice, so only this phase overrides the public retry fallback.
    let recovery_command = if source.code == ErrorCode::SetupPartiallyApplied
        && source
            .details
            .get("failed_action")
            .and_then(serde_json::Value::as_str)
            == Some("record-storage-maintenance-ledger-completion")
    {
        source
            .recovery_command
            .clone()
            .unwrap_or_else(|| recovery_command.to_string())
    } else {
        recovery_command.to_string()
    };
    let mut error = if completed_actions.is_empty() {
        let mut error = SatelleError::setup_action_failed(
            host,
            failed_action,
            skipped_actions,
            source.to_string(),
        );
        error.recovery_command = Some(recovery_command.clone());
        error.details.insert(
            "recovery_command".to_string(),
            serde_json::Value::String(recovery_command),
        );
        error
    } else {
        SatelleError::storage_maintenance_partially_applied(
            completed_actions,
            failed_action,
            skipped_actions,
            &recovery_command,
            source.to_string(),
        )
    };
    copy_storage_maintenance_evidence(&mut error, &source);
    error
}

fn copy_storage_maintenance_evidence(error: &mut SatelleError, source: &SatelleError) {
    // The remote mutation can fail after deleting only part of the approved
    // set. Keep those exact identities in every later service-recovery error.
    for key in [
        "removed_backup_file_names",
        "removed_metadata_file_names",
        "recordings_deleted",
    ] {
        if let Some(value) = source.details.get(key) {
            error.details.insert(key.to_string(), value.clone());
        }
    }
}

fn copy_pending_storage_mutation(mut error: SatelleError, source: &SatelleError) -> SatelleError {
    copy_storage_maintenance_evidence(&mut error, source);
    if is_remote_storage_completion_failure(source)
        && let Some(recovery_command) = source.recovery_command.as_ref()
    {
        error.recovery_command = Some(recovery_command.clone());
        error.details.insert(
            "recovery_command".to_string(),
            serde_json::Value::String(recovery_command.clone()),
        );
    }
    error
}

fn preserve_pending_storage_mutation(
    error: SatelleError,
    mutation: &Result<serde_json::Value, SatelleError>,
) -> SatelleError {
    match mutation {
        Ok(_) => error,
        Err(source) => copy_pending_storage_mutation(error, source),
    }
}

pub(crate) fn preflight_ssh_storage_maintenance(host: &SelectedHost) -> Result<(), SatelleError> {
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::invalid_usage(format!(
            "host '{}' must have a trusted expected Host Identity before storage maintenance can run",
            transport.alias
        )));
    }
    let target = transport.remote_target()?;
    if target.service_platform() == DaemonServicePlatform::Linux {
        return Err(SatelleError::persistent_service_unsupported(
            target.service_platform().as_str(),
        ));
    }
    transport.remote_directories(target)?;
    Ok(())
}

fn resolved_persistent_storage_policy(
    config: &satelle_core::HostConfig,
) -> PersistentHostStoragePolicy {
    PersistentHostStoragePolicy::from_host_config(config)
}

pub(crate) fn preview_ssh_storage_restore(
    host: &SelectedHost,
    backup: &Path,
) -> Result<(), SatelleError> {
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::invalid_usage(format!(
            "host '{}' must have a trusted expected Host Identity before storage maintenance can run",
            transport.alias
        )));
    }
    let target = transport.remote_target()?;
    if target.service_platform() == DaemonServicePlatform::Linux {
        return Err(SatelleError::persistent_service_unsupported(
            target.service_platform().as_str(),
        ));
    }
    let directories = transport.remote_directories(target)?;
    let path_overrides = DaemonPathOverrides {
        home: host.config.daemon_home.clone(),
        config_file: host.config.daemon_config_file.clone(),
        state_dir: host.config.daemon_state_dir.clone(),
        cache_dir: host.config.daemon_cache_dir.clone(),
        log_dir: host.config.daemon_log_dir.clone(),
        ..DaemonPathOverrides::default()
    };
    let host_id = transport.binding.expected_host_identity().as_str();
    let service_asset_path = directories
        .persistent_service_asset_path(host_id)
        .ok_or_else(|| SatelleError::persistent_service_unsupported("unknown"))?;
    let executable = directories
        .probe_managed_service_executable(
            transport.binding.destination(),
            &service_asset_path,
            host_id,
            &path_overrides,
            resolved_persistent_storage_policy(&host.config),
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?
        .ok_or_else(SatelleError::state_conflict)?;
    let state_root = directories
        .resolved_path_set()
        .with_service_overrides(&path_overrides)
        .state_root;
    ssh_bootstrap::preview_offline_storage_restore(
        transport.binding.destination(),
        target,
        executable.path(),
        &state_root,
        &backup.display().to_string(),
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))
}

pub(crate) fn plan_ssh_storage_backup_cleanup(
    host: &SelectedHost,
) -> Result<(satelle_host::StorageBackupCleanupPlan, bool), SatelleError> {
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::invalid_usage(format!(
            "host '{}' must have a trusted expected Host Identity before storage maintenance can run",
            transport.alias
        )));
    }
    let target = transport.remote_target()?;
    if target.service_platform() == DaemonServicePlatform::Linux {
        return Err(SatelleError::persistent_service_unsupported(
            target.service_platform().as_str(),
        ));
    }
    let directories = transport.remote_directories(target)?;
    let service_recovery_required = match transport.durable_service_client() {
        Ok((_tunnel, client)) => {
            classify_storage_service_recovery(&transport.alias, client.capabilities())?
        }
        Err(error) if error.code == ErrorCode::HostUnreachable => true,
        Err(error) => return Err(error),
    };
    let path_overrides = DaemonPathOverrides {
        home: host.config.daemon_home.clone(),
        config_file: host.config.daemon_config_file.clone(),
        state_dir: host.config.daemon_state_dir.clone(),
        cache_dir: host.config.daemon_cache_dir.clone(),
        log_dir: host.config.daemon_log_dir.clone(),
        ..DaemonPathOverrides::default()
    };
    let host_id = transport.binding.expected_host_identity().as_str();
    let service_asset_path = directories
        .persistent_service_asset_path(host_id)
        .ok_or_else(|| SatelleError::persistent_service_unsupported("unknown"))?;
    let executable = directories
        .probe_managed_service_executable(
            transport.binding.destination(),
            &service_asset_path,
            host_id,
            &path_overrides,
            resolved_persistent_storage_policy(&host.config),
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?
        .ok_or_else(SatelleError::state_conflict)?;
    let state_root = directories
        .resolved_path_set()
        .with_service_overrides(&path_overrides)
        .state_root;
    let eligible_backup_file_names = ssh_bootstrap::plan_offline_storage_backup_cleanup(
        transport.binding.destination(),
        target,
        executable.path(),
        &state_root,
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
    Ok((
        satelle_host::StorageBackupCleanupPlan {
            eligible_backup_file_names,
        },
        service_recovery_required,
    ))
}

fn classify_storage_service_recovery(
    alias: &str,
    response: Result<satelle_transport::CapabilitiesResponse, DaemonClientError>,
) -> Result<bool, SatelleError> {
    match response {
        Ok(_) => Ok(false),
        Err(DaemonClientError::ProtocolResponseMismatch) => Ok(false),
        Err(DaemonClientError::Api { status: _, error })
            if error.code() == ApiErrorCode::IncompatibleProtocol =>
        {
            Ok(false)
        }
        Err(DaemonClientError::Transport(error)) if error.is_connect() || error.is_timeout() => {
            Ok(true)
        }
        Err(error) => Err(direct_transport_error(alias, error)),
    }
}

pub(crate) fn apply_ssh_storage_maintenance(
    host: &SelectedHost,
    maintenance: SshStorageMaintenance,
    backup: Option<&Path>,
    delete_recordings: bool,
    approved_backup_file_names: &[String],
    completion_recovery_operation_id: Option<&str>,
) -> Result<serde_json::Value, SatelleError> {
    if completion_recovery_operation_id.is_some()
        && (backup.is_some() || delete_recordings || !approved_backup_file_names.is_empty())
    {
        return Err(SatelleError::invalid_usage(
            "SSH storage completion recovery accepts only the exact operation identity",
        ));
    }
    if maintenance != SshStorageMaintenance::BackupCleanup && !approved_backup_file_names.is_empty()
    {
        return Err(SatelleError::invalid_usage(
            "only SSH backup cleanup accepts approved backup identities",
        ));
    }
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::invalid_usage(format!(
            "host '{}' must have a trusted expected Host Identity before storage maintenance can run",
            transport.alias
        )));
    }
    let target = transport.remote_target()?;
    if target.service_platform() == DaemonServicePlatform::Linux {
        return Err(SatelleError::persistent_service_unsupported(
            target.service_platform().as_str(),
        ));
    }
    let directories = transport.remote_directories(target)?;
    let operation_id = completion_recovery_operation_id.map_or_else(
        || format!("storage-maintenance-{}", Uuid::now_v7()),
        ToString::to_string,
    );
    let recovery_command = if completion_recovery_operation_id.is_some() {
        maintenance.completion_recovery_command(&transport.alias, &operation_id)
    } else {
        maintenance.recovery_command(&transport.alias, backup, delete_recordings)
    };
    let mut bootstrap_lock = acquire_bootstrap_lock_for_operation(
        &transport.alias,
        transport.binding.destination(),
        operation_id.clone(),
        bootstrap_lock::OperationKind::StorageMaintenance,
    )?;
    confirm_bootstrap_lock(&transport.alias, &mut bootstrap_lock)?;

    let prerequisites = (|| {
        let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        )?;
        let expected_host_id = transport.binding.expected_host_identity().to_string();
        let overrides = remote.observe_canonical_daemon_path_overrides(&expected_host_id)?;
        let windows_task = if target.service_platform() == DaemonServicePlatform::Windows {
            Some(remote.registered_windows_task(&expected_host_id)?)
        } else {
            None
        };
        let artifact = remote.install_current_host_artifact()?;
        if artifact.cache_changed() {
            bootstrap_lock.commit_current_mutation()?;
        }
        Ok::<_, ssh_bootstrap::SshBootstrapError>((overrides, windows_task, artifact))
    })();
    let (persisted_overrides, windows_task, artifact) = match prerequisites {
        Ok(prerequisites) => prerequisites,
        Err(error) => {
            // A failed fenced upload retains recovery ownership. Only a
            // wholly read-only prerequisite failure may release the claim as
            // unmodified.
            if !bootstrap_lock.has_mutation_attempt() {
                bootstrap_lock
                    .release_unmodified()
                    .map_err(|_| SatelleError::host_unreachable(&transport.alias))?;
            }
            return Err(map_ssh_daemon_bootstrap_error(&transport.alias, error));
        }
    };
    let state_root = persisted_overrides
        .state_dir
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| directories.resolved_path_set().state_root);
    let backup = backup.map(|path| path.display().to_string());

    stop_persistent_service(
        &transport,
        target,
        &directories,
        &persisted_overrides,
        windows_task.as_ref(),
        &mut bootstrap_lock,
    )
    .map_err(|source| {
        storage_maintenance_partial_error(
            &transport.alias,
            &[],
            "stop-host-api-service",
            &[
                maintenance.action_id().to_string(),
                "restart-host-api-service".to_string(),
                "verify-host-api-service".to_string(),
            ],
            &recovery_command,
            source,
        )
    })?;
    let mut completed_actions = vec!["stop-host-api-service".to_string()];
    let mutation = {
        match ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        ) {
            Ok(mut remote) => remote
                .run_offline_storage_maintenance(
                    &artifact,
                    &ssh_bootstrap::OfflineStorageMaintenanceRequest {
                        operation: maintenance.token(),
                        identity: ssh_bootstrap::OfflineStorageMaintenanceIdentity {
                            host: &transport.alias,
                            operation_id: &operation_id,
                        },
                        state_root: &state_root,
                        backup: backup.as_deref(),
                        delete_recordings,
                        approved_backup_file_names,
                        reconcile_completion: completion_recovery_operation_id.is_some(),
                    },
                )
                .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error)),
            Err(error) => Err(map_ssh_daemon_bootstrap_error(&transport.alias, error)),
        }
    };
    let mutation = mutation
        .map_err(|source| bind_remote_storage_completion_recovery(source, &recovery_command));
    if mutation.is_ok() {
        completed_actions.push(maintenance.action_id().to_string());
    }
    {
        let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        )
        .map_err(|error| {
            preserve_pending_storage_mutation(
                storage_maintenance_partial_error(
                    &transport.alias,
                    &completed_actions,
                    "restart-host-api-service",
                    &["verify-host-api-service".to_string()],
                    &recovery_command,
                    map_ssh_daemon_bootstrap_error(&transport.alias, error),
                ),
                &mutation,
            )
        })?;
        match target.service_platform() {
            DaemonServicePlatform::Windows => remote.restart_registered_windows_task(
                windows_task
                    .as_ref()
                    .expect("Windows storage preflight provides the registered task"),
            ),
            DaemonServicePlatform::Macos => remote.restart_launchd(),
            DaemonServicePlatform::Linux => unreachable!("Linux storage maintenance is rejected"),
        }
        .map_err(|error| {
            preserve_pending_storage_mutation(
                storage_maintenance_partial_error(
                    &transport.alias,
                    &completed_actions,
                    "restart-host-api-service",
                    &["verify-host-api-service".to_string()],
                    &recovery_command,
                    map_ssh_daemon_bootstrap_error(&transport.alias, error),
                ),
                &mutation,
            )
        })?;
        completed_actions.push("restart-host-api-service".to_string());
        wait_for_service_observation(
            &transport.alias,
            || match target.service_platform() {
                DaemonServicePlatform::Windows => remote.observe_registered_windows_task(
                    windows_task
                        .as_ref()
                        .expect("Windows storage preflight provides the registered task"),
                ),
                DaemonServicePlatform::Macos => remote.observe_launchd_runtime(),
                DaemonServicePlatform::Linux => {
                    unreachable!("Linux storage maintenance is rejected")
                }
            },
            ssh_bootstrap::PersistentServiceObservation::Running,
        )
        .map_err(|error| {
            preserve_pending_storage_mutation(
                storage_maintenance_partial_error(
                    &transport.alias,
                    &completed_actions,
                    "verify-host-api-service",
                    &[],
                    &recovery_command,
                    error,
                ),
                &mutation,
            )
        })?;
        completed_actions.push("verify-host-api-service".to_string());
    }
    let (verification_tunnel, verification_client) =
        transport.durable_service_client().map_err(|error| {
            preserve_pending_storage_mutation(
                storage_maintenance_partial_error(
                    &transport.alias,
                    &completed_actions,
                    "verify-host-api-service",
                    &[],
                    &recovery_command,
                    error,
                ),
                &mutation,
            )
        })?;
    wait_for_durable_daemon(&transport.alias, || verification_client.capabilities()).map_err(
        |error| {
            preserve_pending_storage_mutation(
                storage_maintenance_partial_error(
                    &transport.alias,
                    &completed_actions,
                    "verify-host-api-service",
                    &[],
                    &recovery_command,
                    error,
                ),
                &mutation,
            )
        },
    )?;
    commit_verified_bootstrap_mutation(&transport.alias, &mut bootstrap_lock).map_err(|error| {
        preserve_pending_storage_mutation(
            storage_maintenance_partial_error(
                &transport.alias,
                &completed_actions,
                "commit-storage-maintenance-fence",
                &[],
                &recovery_command,
                error,
            ),
            &mutation,
        )
    })?;
    let result = match mutation {
        Ok(result) => result,
        Err(source) => {
            bootstrap_lock.release_committed_handoff().map_err(|_| {
                copy_pending_storage_mutation(
                    storage_maintenance_partial_error(
                        &transport.alias,
                        &completed_actions,
                        "release-storage-maintenance-fence",
                        &[],
                        &recovery_command,
                        SatelleError::host_unreachable(&transport.alias),
                    ),
                    &source,
                )
            })?;
            return Err(storage_maintenance_partial_error(
                &transport.alias,
                &completed_actions,
                maintenance.action_id(),
                &[],
                &recovery_command,
                source,
            ));
        }
    };
    let response = verification_client
        .plan_setup_repair(
            &satelle_transport::SetupRepairPlanRequest::new(
                Some(operation_id.clone()),
                vec![satelle_transport::SetupRepairProbe {
                    action_id: maintenance.action_id().to_string(),
                    label: maintenance.action_id().replace('-', " "),
                    retry_safe: true,
                    postcondition: satelle_transport::SetupRepairPostcondition::Satisfied,
                }],
            ),
            &format!("storage-maintenance-proof-{}", Uuid::now_v7()),
        )
        .map_err(|error| {
            storage_maintenance_partial_error(
                &transport.alias,
                &completed_actions,
                "verify-storage-maintenance-ledger",
                &[],
                &recovery_command,
                direct_transport_error(&transport.alias, error),
            )
        })?;
    if !response.ledger_available() {
        return Err(storage_maintenance_partial_error(
            &transport.alias,
            &completed_actions,
            "verify-storage-maintenance-ledger",
            &[],
            &recovery_command,
            SatelleError::setup_ledger_unavailable(&operation_id),
        ));
    }
    drop(verification_client);
    drop(verification_tunnel);
    bootstrap_lock.release_committed_handoff().map_err(|_| {
        storage_maintenance_partial_error(
            &transport.alias,
            &completed_actions,
            "release-storage-maintenance-fence",
            &[],
            &recovery_command,
            SatelleError::host_unreachable(&transport.alias),
        )
    })?;
    Ok(result)
}

struct HostUpdateArtifactResolver(Option<crate::host_update::VerifiedHostArtifact>);

impl crate::host_update::VerifiedHostArtifactResolver for HostUpdateArtifactResolver {
    fn resolve_exact_cli_artifact(
        &self,
        _cli_version: &str,
        _remote_platform: &str,
    ) -> Result<
        Option<crate::host_update::VerifiedHostArtifact>,
        crate::host_update::HostUpdatePlanError,
    > {
        Ok(self.0.clone())
    }
}

struct HostMaintenanceInspection {
    current_version: Option<String>,
    minimum_host_version: Option<String>,
    protocol_compatible: bool,
    relation_to_cli: crate::host_update::HostVersionRelation,
    remote_platform: String,
    artifact: Option<crate::host_update::VerifiedHostArtifact>,
    service_inspection: Option<crate::host_update::HostUpdateServiceInspection>,
    codex_evidence: Option<satelle_core::host_update::CodexUpdateEvidence>,
    host_automation_is_safe: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostMaintenancePlanKind {
    CodexOnly,
    HostUpdate,
    HostUpdateRecovery,
    Repair,
}

fn inspects_persistent_service(
    kind: HostMaintenancePlanKind,
    setup_mode: Option<satelle_core::SetupMode>,
) -> bool {
    matches!(
        kind,
        HostMaintenancePlanKind::HostUpdate
            | HostMaintenancePlanKind::HostUpdateRecovery
            | HostMaintenancePlanKind::Repair
    ) && setup_mode == Some(satelle_core::SetupMode::Persistent)
}

fn host_release_artifact_required(relation: crate::host_update::HostVersionRelation) -> bool {
    matches!(
        relation,
        crate::host_update::HostVersionRelation::Missing
            | crate::host_update::HostVersionRelation::OlderThanCli
    )
}

fn maintenance_release_artifact_required(
    kind: HostMaintenancePlanKind,
    relation: crate::host_update::HostVersionRelation,
    protocol_compatible: bool,
    service_relation: Option<crate::host_update::HostVersionRelation>,
) -> bool {
    match kind {
        HostMaintenancePlanKind::CodexOnly => false,
        HostMaintenancePlanKind::HostUpdate => {
            host_release_artifact_required(relation)
                || service_relation.is_some_and(host_release_artifact_required)
        }
        HostMaintenancePlanKind::HostUpdateRecovery => true,
        HostMaintenancePlanKind::Repair => {
            relation == crate::host_update::HostVersionRelation::Missing
                || (!protocol_compatible
                    && matches!(
                        relation,
                        crate::host_update::HostVersionRelation::OlderThanCli
                            | crate::host_update::HostVersionRelation::MatchesCli
                    ))
        }
    }
}

fn host_service_inspection_from_executable(
    target: ssh_bootstrap::RemoteTarget,
    directories: &ssh_bootstrap::RemoteUserDirectories,
    destination: &str,
    executable: Option<ssh_bootstrap::ManagedServiceExecutableObservation>,
    cli_version: &str,
    expected_current_release_digest: Option<[u8; 32]>,
) -> Result<crate::host_update::HostUpdateServiceInspection, SatelleError> {
    let Some(executable) = executable else {
        return Ok(crate::host_update::HostUpdateServiceInspection {
            current_version: None,
            relation_to_cli: crate::host_update::HostVersionRelation::Missing,
            destination: destination.to_string(),
        });
    };
    let current_version = ssh_bootstrap::managed_service_executable_version(
        target,
        directories,
        &executable,
        expected_current_release_digest,
    );
    let relation_to_cli = match current_version.as_deref() {
        Some(current_version) => {
            host_version_relation(Some(current_version), true, None, cli_version)?
        }
        // A canonical managed executable exists, but its path does not expose
        // a version. Keep it distinct from an absent service and plan a safe
        // replacement with the exact invoking CLI artifact.
        None => crate::host_update::HostVersionRelation::OlderThanCli,
    };
    Ok(crate::host_update::HostUpdateServiceInspection {
        current_version,
        relation_to_cli,
        destination: destination.to_string(),
    })
}

fn inspect_host_maintenance(
    host: &SelectedHost,
    kind: HostMaintenancePlanKind,
    cli_version: &str,
) -> Result<HostMaintenanceInspection, SatelleError> {
    match host.config.transport {
        TransportKind::Local => {
            let service = local_host_service(&host.config).map_err(|failure| failure.error)?;
            let codex_evidence = service.maintenance_codex_update_evidence()?;
            let (_, platform) = canonical_remote_platform(
                &satelle_core::host_update::current_host_artifact_platform(),
            );
            Ok(HostMaintenanceInspection {
                current_version: Some(cli_version.to_string()),
                minimum_host_version: Some(cli_version.to_string()),
                protocol_compatible: true,
                relation_to_cli: crate::host_update::HostVersionRelation::MatchesCli,
                remote_platform: platform,
                artifact: None,
                service_inspection: None,
                codex_evidence: Some(codex_evidence),
                // The local transport has no production mutation backend.
                host_automation_is_safe: false,
            })
        }
        TransportKind::Direct => {
            let transport = direct_transport(host)?;
            let observation = read_direct_maintenance_evidence(&host.alias, &transport)?;
            match observation {
                DirectMaintenanceEvidence::Compatible(evidence) => {
                    let (target, platform) = canonical_remote_platform(evidence.platform_target());
                    let relation_to_cli = host_version_relation(
                        Some(evidence.daemon_version()),
                        true,
                        Some(evidence.minimum_host_version()),
                        cli_version,
                    )?;
                    let artifact = if kind == HostMaintenancePlanKind::HostUpdate {
                        match target {
                            Some(target) => verified_host_update_artifact(
                                &host.alias,
                                cli_version,
                                maintenance_release_artifact_required(
                                    kind,
                                    relation_to_cli,
                                    true,
                                    None,
                                ),
                                target,
                                None,
                                None,
                            )?,
                            None => None,
                        }
                    } else {
                        None
                    };
                    Ok(HostMaintenanceInspection {
                        current_version: Some(evidence.daemon_version().to_string()),
                        minimum_host_version: Some(evidence.minimum_host_version().to_string()),
                        protocol_compatible: true,
                        relation_to_cli,
                        remote_platform: platform,
                        artifact,
                        service_inspection: None,
                        codex_evidence: Some(evidence.codex_update_evidence().clone()),
                        // Direct maintenance mutation is not implemented in the current transport.
                        host_automation_is_safe: false,
                    })
                }
                DirectMaintenanceEvidence::ProtocolIncompatible { current_version } => {
                    let relation_to_cli = host_version_relation(
                        current_version.as_deref(),
                        false,
                        None,
                        cli_version,
                    )?;
                    Ok(HostMaintenanceInspection {
                        current_version,
                        minimum_host_version: None,
                        protocol_compatible: false,
                        relation_to_cli,
                        // The authenticated protocol error cannot expose a
                        // current-schema platform value. Keep automation
                        // disabled instead of guessing the remote target.
                        remote_platform: "unknown".to_string(),
                        artifact: None,
                        service_inspection: None,
                        codex_evidence: None,
                        host_automation_is_safe: false,
                    })
                }
            }
        }
        TransportKind::Ssh => {
            let transport = SshSetupTransport::new_for_maintenance(host)?;
            let target = transport.remote_target()?;
            let current =
                transport.observe_maintenance_daemon_artifact(transport.token_file_exists()?)?;
            let relation_to_cli = host_version_relation(
                current.current_version.as_deref(),
                current.protocol_compatible,
                current.minimum_host_version.as_deref(),
                cli_version,
            )?;
            let inspect_service = inspects_persistent_service(kind, host.config.setup_mode);
            let initial_artifact_required = maintenance_release_artifact_required(
                kind,
                relation_to_cli,
                current.protocol_compatible,
                None,
            );
            let remote_directories = (inspect_service || initial_artifact_required)
                .then(|| transport.remote_directories(target))
                .transpose()?;
            let mut service_release_artifact = None;
            let service_inspection = if inspect_service {
                let directories = remote_directories
                    .as_ref()
                    .expect("persistent Host inspection requests remote directories");
                let expected_path_overrides = DaemonPathOverrides {
                    home: host.config.daemon_home.clone(),
                    config_file: host.config.daemon_config_file.clone(),
                    state_dir: host.config.daemon_state_dir.clone(),
                    cache_dir: host.config.daemon_cache_dir.clone(),
                    log_dir: host.config.daemon_log_dir.clone(),
                    ..DaemonPathOverrides::default()
                };
                let host_id = transport.binding.expected_host_identity().as_str();
                let service_path = directories.persistent_service_asset_path(host_id);
                match service_path {
                    Some(destination) => {
                        let executable = directories
                            .probe_managed_service_executable(
                                transport.binding.destination(),
                                &destination,
                                host_id,
                                &expected_path_overrides,
                                resolved_persistent_storage_policy(&host.config),
                            )
                            .map_err(|error| {
                                map_ssh_daemon_bootstrap_error(&transport.alias, error)
                            })?;
                        if executable.is_some() {
                            // Current service state is trustworthy only when
                            // the observed executable content matches the
                            // invoking release manifest.
                            service_release_artifact =
                                Some(transport.release_artifact(target, cli_version)?);
                        }
                        Some(host_service_inspection_from_executable(
                            target,
                            directories,
                            &destination,
                            executable,
                            cli_version,
                            service_release_artifact.map(|metadata| metadata.digest()),
                        )?)
                    }
                    None => None,
                }
            } else {
                None
            };
            let needs_host_release_artifact = maintenance_release_artifact_required(
                kind,
                relation_to_cli,
                current.protocol_compatible,
                service_inspection
                    .as_ref()
                    .map(|service| service.relation_to_cli),
            );
            let release_artifact = if needs_host_release_artifact {
                Some(match service_release_artifact {
                    Some(metadata) => metadata,
                    None => transport.release_artifact(target, cli_version)?,
                })
            } else {
                None
            };
            let install_path = match (remote_directories.as_ref(), release_artifact.as_ref()) {
                (Some(directories), Some(metadata)) => Some(
                    target
                        .planned_install_path(directories, &metadata.digest())
                        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?,
                ),
                _ => None,
            };
            let artifact = if kind != HostMaintenancePlanKind::CodexOnly {
                verified_host_update_artifact(
                    &host.alias,
                    cli_version,
                    needs_host_release_artifact,
                    target,
                    install_path,
                    release_artifact,
                )?
            } else {
                None
            };
            let host_automation_is_safe = host.config.setup_mode
                == Some(satelle_core::SetupMode::Persistent)
                && target.service_platform() != DaemonServicePlatform::Linux
                && service_inspection.is_some();
            Ok(HostMaintenanceInspection {
                current_version: current.current_version,
                minimum_host_version: current.minimum_host_version,
                protocol_compatible: current.protocol_compatible,
                relation_to_cli,
                remote_platform: target.id().to_string(),
                artifact,
                service_inspection,
                codex_evidence: current.codex_update_evidence,
                host_automation_is_safe,
            })
        }
    }
}

fn validate_host_update_recovery_artifact(
    inspection: &HostMaintenanceInspection,
    recovery_identity: &satelle_core::host_update::HostUpdateRecoveryIdentity,
) -> Result<(), SatelleError> {
    let artifact = inspection.artifact.as_ref().ok_or_else(|| {
        SatelleError::host_artifact_unavailable(
            recovery_identity.target_version(),
            &inspection.remote_platform,
        )
    })?;
    if artifact.version != recovery_identity.target_version() {
        return Err(SatelleError::host_update_recovery_identity_mismatch(
            "target_version",
            recovery_identity.target_version(),
            &artifact.version,
        ));
    }
    if artifact.digest != recovery_identity.artifact_digest() {
        return Err(SatelleError::host_update_recovery_identity_mismatch(
            "artifact_digest",
            recovery_identity.artifact_digest(),
            &artifact.digest,
        ));
    }
    Ok(())
}

enum DirectMaintenanceEvidence {
    Compatible(Box<satelle_transport::MaintenanceUpdateEvidenceResponse>),
    ProtocolIncompatible { current_version: Option<String> },
}

fn classify_direct_maintenance_evidence(
    host: &str,
    evidence: Result<satelle_transport::MaintenanceUpdateEvidenceResponse, DaemonClientError>,
) -> Result<DirectMaintenanceEvidence, SatelleError> {
    match evidence {
        Ok(evidence) => Ok(DirectMaintenanceEvidence::Compatible(Box::new(evidence))),
        Err(DaemonClientError::Api { error, .. })
            if error.code() == ApiErrorCode::IncompatibleProtocol =>
        {
            let current_version = error
                .details()
                .and_then(|details| details.get("daemon_version"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    SatelleError::config_error(
                        "the protocol-incompatible Host did not report its current version",
                        None,
                    )
                })?;
            Ok(DirectMaintenanceEvidence::ProtocolIncompatible {
                current_version: Some(current_version),
            })
        }
        Err(DaemonClientError::ProtocolResponseMismatch) => {
            Ok(DirectMaintenanceEvidence::ProtocolIncompatible {
                current_version: None,
            })
        }
        Err(error) => Err(direct_transport_error(host, error)),
    }
}

fn read_direct_maintenance_evidence(
    host: &str,
    transport: &DirectTransport,
) -> Result<DirectMaintenanceEvidence, SatelleError> {
    classify_direct_maintenance_evidence(host, transport.client.maintenance_update_evidence())
}

pub(crate) fn plan_host_update(
    host: &SelectedHost,
    cli_version: &str,
    components: &[satelle_core::host_update::HostUpdateComponent],
    includes_all: bool,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    plan_host_update_internal(host, cli_version, components, includes_all, None)
}

fn plan_host_update_recovery(
    host: &SelectedHost,
    recovery_identity: &satelle_core::host_update::HostUpdateRecoveryIdentity,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    plan_host_update_internal(
        host,
        recovery_identity.target_version(),
        &[satelle_core::host_update::HostUpdateComponent::Host],
        false,
        Some(recovery_identity),
    )
}

fn plan_host_update_internal(
    host: &SelectedHost,
    cli_version: &str,
    components: &[satelle_core::host_update::HostUpdateComponent],
    includes_all: bool,
    recovery_identity: Option<&satelle_core::host_update::HostUpdateRecoveryIdentity>,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    let needs_host_artifact = includes_all
        || components.is_empty()
        || components.contains(&satelle_core::host_update::HostUpdateComponent::Host);
    let kind = if recovery_identity.is_some() {
        HostMaintenancePlanKind::HostUpdateRecovery
    } else if needs_host_artifact {
        HostMaintenancePlanKind::HostUpdate
    } else {
        HostMaintenancePlanKind::CodexOnly
    };
    let inspection = inspect_host_maintenance(host, kind, cli_version)?;
    if let Some(recovery_identity) = recovery_identity {
        validate_host_update_recovery_artifact(&inspection, recovery_identity)?;
    }
    let host_automation_is_safe = inspection.host_automation_is_safe;
    let service_inspection = inspection.service_inspection;

    let host_inspection = crate::host_update::HostUpdateInspection {
        relation_to_cli: if recovery_identity.is_some() {
            crate::host_update::HostVersionRelation::OlderThanCli
        } else {
            inspection.relation_to_cli
        },
        current_version: inspection.current_version,
        remote_platform: inspection.remote_platform,
    };
    let codex_inspections = match inspection.codex_evidence {
        Some(codex_evidence) => {
            crate::host_update::codex_inspections_from_evidence(&codex_evidence)
        }
        None => {
            crate::host_update::unavailable_codex_inspections(&HostService::required_codex_version())
        }
    };
    let mut report = crate::host_update::build_host_update_plan(
        crate::host_update::HostUpdatePlanRequest {
            host: &host.alias,
            cli_version,
            components,
            includes_all,
            host_inspection: &host_inspection,
            service_inspection: service_inspection.as_ref(),
            codex_inspections: &codex_inspections,
        },
        &HostUpdateArtifactResolver(inspection.artifact),
    )
    .map_err(map_host_update_plan_error)?;
    if !host_automation_is_safe {
        for target in &mut report.targets {
            if matches!(
                target.target,
                satelle_core::host_update::HostUpdateTarget::HostDaemon
                    | satelle_core::host_update::HostUpdateTarget::HostDaemonService
            ) && target.requires_mutation()
            {
                target.disposition = satelle_core::host_update::HostUpdateDisposition::Skipped;
            }
        }
        report = satelle_core::host_update::HostUpdateReport::new(
            report.host,
            report.checked_components,
            report.targets,
        );
    }
    Ok(report)
}

pub(crate) fn apply_host_update(
    host: &SelectedHost,
    cli_version: &str,
    report: satelle_core::host_update::HostUpdateReport,
    components: &[satelle_core::host_update::HostUpdateComponent],
    includes_all: bool,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    apply_host_update_with_operation(
        host,
        cli_version,
        report,
        HostUpdateOperation::Update,
        HostReplacementEntry::ReachableDaemon,
        None,
        || plan_host_update(host, cli_version, components, includes_all),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostUpdateOperation {
    Update,
    Repair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostReplacementEntry {
    ReachableDaemon,
    Bootstrap,
}

fn apply_host_update_with_operation(
    host: &SelectedHost,
    cli_version: &str,
    mut report: satelle_core::host_update::HostUpdateReport,
    operation: HostUpdateOperation,
    entry: HostReplacementEntry,
    existing_operation_id: Option<&str>,
    revalidate: impl FnOnce() -> Result<satelle_core::host_update::HostUpdateReport, SatelleError>,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    use satelle_core::host_update::{HostUpdatePostcheck, HostUpdateTarget};

    if host.config.transport != TransportKind::Ssh || !report.confirmation_required {
        return Err(SatelleError::invalid_usage(
            "the selected Host update has no supported automatic SSH mutation plan",
        ));
    }

    let expected_artifact_path = report
        .targets
        .iter()
        .find_map(|target| {
            target
                .remote_mutations
                .iter()
                .find(|mutation| mutation.operation == "install-host-artifact")
                .and_then(|mutation| {
                    mutation
                        .remote_path
                        .clone()
                        .zip(target.artifact_digest.clone())
                })
        })
        .ok_or_else(|| {
            SatelleError::invalid_usage(
                "the Host update plan lacks an exact verified artifact destination",
            )
        })?;
    let (expected_artifact_path, expected_artifact_digest) = expected_artifact_path;
    let recovery_identity = host_update_recovery_identity(&report)?;
    let publish_service = report.targets.iter().any(|target| {
        target.target == HostUpdateTarget::HostDaemonService && target.requires_mutation()
    });

    let operation_id = existing_operation_id
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "{}-{}",
                match operation {
                    HostUpdateOperation::Update => "host-update",
                    HostUpdateOperation::Repair => "repair",
                },
                Uuid::now_v7()
            )
        });
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::ssh_host_key_verification_required(
            &transport.alias,
        ));
    }
    let target = transport.remote_target()?;
    let directories = transport.remote_directories(target)?;
    let mut revalidate = Some(revalidate);
    let old_connection = if entry == HostReplacementEntry::ReachableDaemon {
        let connection = transport.durable_service_client()?;
        let old_capabilities = connection
            .1
            .capabilities()
            .map_err(|error| direct_transport_error(&transport.alias, error))?;
        if old_capabilities.host_identity() != transport.binding.expected_host_identity().as_str() {
            return Err(SatelleError::host_identity_mismatch(&transport.alias));
        }
        report = begin_host_update_maintenance_with_revalidation(
            &transport.alias,
            &connection.1,
            &operation_id,
            operation,
            &report,
            revalidate
                .take()
                .expect("Host replacement revalidation runs exactly once"),
        )?;
        Some(connection)
    } else {
        None
    };
    let old_client = old_connection.as_ref().map(|(_, client)| client);

    let mut bootstrap_lock = match acquire_bootstrap_lock_for_operation(
        &transport.alias,
        transport.binding.destination(),
        operation_id.clone(),
        match entry {
            HostReplacementEntry::ReachableDaemon => {
                bootstrap_lock::OperationKind::HostBinaryReplacement
            }
            HostReplacementEntry::Bootstrap => bootstrap_lock::OperationKind::MissingDaemonRepair,
        },
    ) {
        Ok(lock) => lock,
        Err(error) => {
            return Err(match old_client {
                Some(old_client) => close_unmodified_host_update_or_recovery_pending(
                    &transport.alias,
                    old_client,
                    &operation_id,
                    error,
                ),
                None => error,
            });
        }
    };
    if let Err(error) = confirm_bootstrap_lock(&transport.alias, &mut bootstrap_lock) {
        let error = match old_client {
            Some(old_client) => close_unmodified_host_update_or_recovery_pending(
                &transport.alias,
                old_client,
                &operation_id,
                error,
            ),
            None => error,
        };
        let _ = bootstrap_lock.release_unmodified();
        return Err(error);
    }
    if entry == HostReplacementEntry::Bootstrap {
        let current = match revalidate
            .take()
            .expect("Host replacement revalidation runs exactly once")()
        {
            Ok(current) => current,
            Err(source) => {
                return Err(release_unmodified_bootstrap_repair(
                    &transport.alias,
                    &mut bootstrap_lock,
                    source,
                ));
            }
        };
        if current != report {
            return Err(release_unmodified_bootstrap_repair(
                &transport.alias,
                &mut bootstrap_lock,
                SatelleError::state_conflict(),
            ));
        }
        report = current;
    }
    report.recovery_command = Some(format!(
        "satelle repair --host {} --run {} --no-input --yes",
        crate::shell_argument(&report.host),
        crate::shell_argument(&operation_id)
    ));

    // A compatible daemon owns Maintenance before this read-only preflight.
    // A missing or protocol-incompatible daemon instead enters under
    // Bootstrap Lock and hands the completed replacement actions to the new
    // daemon before releasing that lock.
    let daemon_path_overrides = match (|| {
        let remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        )?;
        remote.observe_canonical_daemon_path_overrides(
            transport.binding.expected_host_identity().as_str(),
        )
    })() {
        Ok(overrides) => overrides,
        Err(error) => {
            let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
            return Err(match old_client {
                Some(old_client) => close_locked_unmodified_host_update_or_recovery_pending(
                    &transport.alias,
                    old_client,
                    &mut bootstrap_lock,
                    source,
                ),
                None => fail_pre_adoption_host_replacement(
                    &transport.alias,
                    None,
                    &mut bootstrap_lock,
                    &mut report,
                    "install-host-artifact",
                    source,
                ),
            });
        }
    };

    if let Some(old_client) = old_client
        && let Err(source) = start_persistent_action(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            "install-host-artifact",
        )
    {
        return Err(recover_failed_first_host_update_action_start(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            source,
        ));
    }
    let artifact = {
        let remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        );
        let mut remote = match remote {
            Ok(remote) => remote,
            Err(error) => {
                let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
                return Err(fail_pre_adoption_host_replacement(
                    &transport.alias,
                    old_client,
                    &mut bootstrap_lock,
                    &mut report,
                    "install-host-artifact",
                    source,
                ));
            }
        };
        match remote.install_verified_host_artifact(cli_version, &expected_artifact_digest) {
            Ok(artifact) => artifact,
            Err(error) => {
                let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
                return Err(fail_pre_adoption_host_replacement(
                    &transport.alias,
                    old_client,
                    &mut bootstrap_lock,
                    &mut report,
                    "install-host-artifact",
                    source,
                ));
            }
        }
    };
    // The verified artifact publication changed remote state even if the
    // following fence commit cannot be confirmed.
    report.changed = true;
    report
        .applied_actions
        .push("install-host-artifact".to_string());
    if let Err(source) = commit_verified_bootstrap_mutation(&transport.alias, &mut bootstrap_lock) {
        return Err(host_update_recovery_pending(
            &mut report,
            "install-host-artifact",
            &operation_id,
            source,
        ));
    }
    if artifact.remote_path() != expected_artifact_path {
        let source = SatelleError::state_conflict();
        return Err(fail_pre_adoption_host_replacement(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            &mut report,
            "install-host-artifact",
            source,
        ));
    }
    let service_remote = ssh_bootstrap::PersistentServiceRemote::new(
        transport.binding.destination(),
        target,
        &directories,
        &mut bootstrap_lock,
    );
    let service_remote = match service_remote {
        Ok(remote) => remote,
        Err(error) => {
            let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
            return Err(fail_pre_adoption_host_replacement(
                &transport.alias,
                old_client,
                &mut bootstrap_lock,
                &mut report,
                "install-host-artifact",
                source,
            ));
        }
    };
    let service = match transport.prepare_persistent_service(
        target,
        &artifact,
        &daemon_path_overrides,
        &service_remote,
    ) {
        Ok(service) => service,
        Err(source) => {
            return Err(fail_pre_adoption_host_replacement(
                &transport.alias,
                old_client,
                &mut bootstrap_lock,
                &mut report,
                "install-host-artifact",
                source,
            ));
        }
    };
    if let Some(old_client) = old_client
        && let Err(source) = complete_persistent_action(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            "install-host-artifact",
        )
    {
        return Err(host_update_recovery_pending(
            &mut report,
            "install-host-artifact",
            &operation_id,
            source,
        ));
    }

    if publish_service {
        if let Some(old_client) = old_client
            && let Err(source) = start_persistent_action(
                &transport.alias,
                old_client,
                &mut bootstrap_lock,
                "publish-host-service",
            )
        {
            return Err(recover_later_host_update_action_start(
                &transport.alias,
                old_client,
                &mut bootstrap_lock,
                &mut report,
                "publish-host-service",
                source,
            ));
        }
        let publish_result = {
            let remote = ssh_bootstrap::PersistentServiceRemote::new(
                transport.binding.destination(),
                target,
                &directories,
                &mut bootstrap_lock,
            );
            let mut remote = match remote {
                Ok(remote) => remote,
                Err(error) => {
                    let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
                    return Err(fail_pre_adoption_host_replacement(
                        &transport.alias,
                        old_client,
                        &mut bootstrap_lock,
                        &mut report,
                        "publish-host-service",
                        source,
                    ));
                }
            };
            match &service {
                PreparedPersistentService::Windows { task, config } => {
                    remote.publish_windows_service_config(task, config)
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.publish_launchd_definition(definition)
                }
            }
        };
        if let Err(error) = publish_result {
            let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
            return Err(fail_pre_adoption_host_replacement(
                &transport.alias,
                old_client,
                &mut bootstrap_lock,
                &mut report,
                "publish-host-service",
                source,
            ));
        }
        if let Err(source) =
            commit_verified_bootstrap_mutation(&transport.alias, &mut bootstrap_lock)
        {
            return Err(host_update_recovery_pending(
                &mut report,
                "publish-host-service",
                &operation_id,
                source,
            ));
        }
        let register_result = {
            let remote = ssh_bootstrap::PersistentServiceRemote::new(
                transport.binding.destination(),
                target,
                &directories,
                &mut bootstrap_lock,
            );
            let mut remote = match remote {
                Ok(remote) => remote,
                Err(error) => {
                    let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
                    return Err(fail_pre_adoption_host_replacement(
                        &transport.alias,
                        old_client,
                        &mut bootstrap_lock,
                        &mut report,
                        "publish-host-service",
                        source,
                    ));
                }
            };
            match &service {
                PreparedPersistentService::Windows { task, .. } => {
                    remote.register_windows_task(task)
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.register_launchd(definition)
                }
            }
        };
        if let Err(error) = register_result {
            let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
            return Err(fail_pre_adoption_host_replacement(
                &transport.alias,
                old_client,
                &mut bootstrap_lock,
                &mut report,
                "publish-host-service",
                source,
            ));
        }
        if let Err(source) =
            finish_confirmed_host_update_action(&mut report, "publish-host-service", || {
                commit_verified_bootstrap_mutation(&transport.alias, &mut bootstrap_lock)?;
                old_client.map_or(Ok(()), |old_client| {
                    complete_persistent_action(
                        &transport.alias,
                        old_client,
                        &mut bootstrap_lock,
                        "publish-host-service",
                    )
                })
            })
        {
            return Err(host_update_recovery_pending(
                &mut report,
                "publish-host-service",
                &operation_id,
                source,
            ));
        }
    } else if let Some(old_client) = old_client
        && let Err(source) = skip_maintenance_action(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            "publish-host-service",
        )
    {
        return Err(host_update_recovery_pending(
            &mut report,
            "publish-host-service",
            &operation_id,
            source,
        ));
    }

    if let Some(old_client) = old_client
        && let Err(source) = start_persistent_action(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            "restart-host-daemon",
        )
    {
        return Err(recover_later_host_update_action_start(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            &mut report,
            "restart-host-daemon",
            source,
        ));
    }
    let restart_result = {
        let remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            &directories,
            &mut bootstrap_lock,
        );
        let mut remote = match remote {
            Ok(remote) => remote,
            Err(error) => {
                let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
                return Err(fail_pre_adoption_host_replacement(
                    &transport.alias,
                    old_client,
                    &mut bootstrap_lock,
                    &mut report,
                    "restart-host-daemon",
                    source,
                ));
            }
        };
        match &service {
            PreparedPersistentService::Windows { task, .. } => remote.restart_windows_task(task),
            PreparedPersistentService::Launchd(_) => remote.restart_launchd(),
        }
    };
    if let Err(error) = restart_result {
        let source = map_ssh_daemon_bootstrap_error(&transport.alias, error);
        return Err(fail_pre_adoption_host_replacement(
            &transport.alias,
            old_client,
            &mut bootstrap_lock,
            &mut report,
            "restart-host-daemon",
            source,
        ));
    }
    if let Err(source) = commit_verified_bootstrap_mutation(&transport.alias, &mut bootstrap_lock) {
        return Err(host_update_recovery_pending(
            &mut report,
            "restart-host-daemon",
            &operation_id,
            source,
        ));
    }
    drop(old_connection);

    let (new_tunnel, new_client) = match transport.durable_service_client() {
        Ok(connection) => connection,
        Err(source) => {
            return Err(host_update_recovery_pending(
                &mut report,
                "restart-host-daemon",
                &operation_id,
                source,
            ));
        }
    };
    let new_capabilities =
        match wait_for_durable_daemon(&transport.alias, || new_client.capabilities()) {
            Ok(capabilities) => capabilities,
            Err(source) => {
                return Err(host_update_recovery_pending(
                    &mut report,
                    "restart-host-daemon",
                    &operation_id,
                    source,
                ));
            }
        };
    if new_capabilities.host_identity() != transport.binding.expected_host_identity().as_str() {
        let source = SatelleError::host_identity_mismatch(&transport.alias);
        return Err(host_update_recovery_pending(
            &mut report,
            "restart-host-daemon",
            &operation_id,
            source,
        ));
    }
    if new_capabilities.daemon_version() != cli_version {
        return Err(host_update_recovery_pending(
            &mut report,
            "restart-host-daemon",
            &operation_id,
            SatelleError::state_conflict(),
        ));
    }
    if entry == HostReplacementEntry::Bootstrap {
        if let Err(source) = adopt_bootstrap_repair_actions(
            &transport.alias,
            &new_client,
            &mut bootstrap_lock,
            &recovery_identity,
            publish_service,
        ) {
            return Err(host_update_daemon_adoption_error(
                &mut report,
                &operation_id,
                source,
            ));
        }
    } else {
        let adopted = match operation {
            HostUpdateOperation::Update => {
                new_client.begin_host_update_maintenance(&operation_id, &recovery_identity)
            }
            HostUpdateOperation::Repair => {
                new_client.begin_repair_maintenance(&operation_id, &recovery_identity)
            }
        };
        let adopted = match adopted {
            Ok(adopted) => adopted,
            Err(error) => {
                let source = direct_transport_error(&transport.alias, error);
                return Err(host_update_daemon_adoption_error(
                    &mut report,
                    &operation_id,
                    source,
                ));
            }
        };
        if let Err(source) = validate_persistent_maintenance_response(
            &transport.alias,
            &operation_id,
            adopted.reconciled(),
            adopted.operation_id(),
        ) {
            return Err(host_update_recovery_pending(
                &mut report,
                "restart-host-daemon",
                &operation_id,
                source,
            ));
        }
    }
    if let Err(source) =
        finish_confirmed_host_update_action(&mut report, "restart-host-daemon", || {
            complete_persistent_action(
                &transport.alias,
                &new_client,
                &mut bootstrap_lock,
                "restart-host-daemon",
            )
        })
    {
        return Err(host_update_recovery_pending(
            &mut report,
            "restart-host-daemon",
            &operation_id,
            source,
        ));
    }

    if let Err(source) = start_persistent_action(
        &transport.alias,
        &new_client,
        &mut bootstrap_lock,
        "invalidate-readiness-caches",
    ) {
        return Err(recover_later_host_update_action_start(
            &transport.alias,
            &new_client,
            &mut bootstrap_lock,
            &mut report,
            "invalidate-readiness-caches",
            source,
        ));
    }
    let invalidation = satelle_transport::NativeReadinessInvalidationRequest::host();
    if let Err(error) = new_client.invalidate_native_readiness(&invalidation, &operation_id) {
        let source = direct_transport_error(&transport.alias, error);
        return Err(host_update_recovery_pending(
            &mut report,
            "invalidate-readiness-caches",
            &operation_id,
            source,
        ));
    }
    // Cache deletion is the side effect. Record it before completing the
    // ledger action so an uncertain completion response cannot hide it from
    // recovery output.
    report
        .invalidated_caches
        .push("native_computer_use".to_string());
    if let Err(source) = complete_persistent_action(
        &transport.alias,
        &new_client,
        &mut bootstrap_lock,
        "invalidate-readiness-caches",
    ) {
        return Err(host_update_recovery_pending(
            &mut report,
            "invalidate-readiness-caches",
            &operation_id,
            source,
        ));
    }
    report
        .applied_actions
        .push("invalidate-readiness-caches".to_string());

    // A replacement daemon serves authenticated capabilities only after it
    // opens the Host store and completes startup migrations. Those three
    // postconditions are therefore proven before the native readiness probe.
    for (check_id, summary) in [
        ("host-api-reachable", "Authenticated Host API is reachable"),
        (
            "host-version-aligned",
            "Host version matches the invoking CLI",
        ),
        (
            "storage-migrations-current",
            "Host storage opened with current migrations",
        ),
    ] {
        report = report.with_postcheck(HostUpdatePostcheck::passed(check_id, summary));
    }
    if let Err(source) = start_persistent_action(
        &transport.alias,
        &new_client,
        &mut bootstrap_lock,
        "host-update-postcheck",
    ) {
        return Err(recover_later_host_update_action_start(
            &transport.alias,
            &new_client,
            &mut bootstrap_lock,
            &mut report,
            "host-update-postcheck",
            source,
        ));
    }
    let postcheck = new_client.run_maintenance_postcheck(&operation_id, "host-update-postcheck");
    if let Err(error) = postcheck {
        let terminal = match &error {
            DaemonClientError::Api { error, .. } => {
                maintenance_postcheck_is_terminal(error.details())
            }
            _ => false,
        };
        let source = direct_transport_error(&transport.alias, error);
        if !terminal {
            return Err(host_update_recovery_pending(
                &mut report,
                "host-update-postcheck",
                &operation_id,
                source,
            ));
        }
        let error =
            finish_terminal_failed_host_update_postcheck(report, &operation_id, source, || {
                bootstrap_lock
                    .release_committed_handoff()
                    .map_err(|_| SatelleError::host_unreachable(&transport.alias))
            });
        drop(new_client);
        drop(new_tunnel);
        return Err(error);
    }
    report = finish_successful_host_update_postcheck(report, &operation_id, || {
        bootstrap_lock
            .release_committed_handoff()
            .map_err(|_| SatelleError::host_unreachable(&transport.alias))
    })?;
    drop(new_client);
    drop(new_tunnel);

    Ok(report.finish_postchecks())
}

fn adopt_bootstrap_repair_actions(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    recovery_identity: &satelle_core::host_update::HostUpdateRecoveryIdentity,
    published_service: bool,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    let adopted = client
        .begin_repair_maintenance(&operation_id, recovery_identity)
        .map_err(|error| direct_transport_error(host, error))?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        adopted.reconciled(),
        adopted.operation_id(),
    )?;

    for action_id in ["install-host-artifact", "publish-host-service"] {
        if action_id == "publish-host-service" && !published_service {
            skip_maintenance_action(host, client, bootstrap_lock, action_id)?;
        } else {
            start_persistent_action(host, client, bootstrap_lock, action_id)?;
            complete_persistent_action(host, client, bootstrap_lock, action_id)?;
        }
    }
    start_persistent_action(host, client, bootstrap_lock, "restart-host-daemon")
}

fn finish_confirmed_host_update_action(
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_id: &str,
    reconcile_action: impl FnOnce() -> Result<(), SatelleError>,
) -> Result<(), SatelleError> {
    // The remote outcome is already confirmed. Record it before the fence or
    // ledger reconciliation that follows so an uncertain response cannot
    // erase a mutation that recovery must preserve.
    report.applied_actions.push(action_id.to_string());
    reconcile_action()
}

fn finish_terminal_failed_host_update_postcheck(
    mut report: satelle_core::host_update::HostUpdateReport,
    operation_id: &str,
    source: SatelleError,
    release_bootstrap_lock: impl FnOnce() -> Result<(), SatelleError>,
) -> SatelleError {
    // The Host finalized the failed postcheck and released its leases. Record
    // that terminal outcome before the independent Bootstrap Lock release.
    report = report.with_postcheck(satelle_core::host_update::HostUpdatePostcheck::failed(
        "native-computer-use-ready",
        "Native Computer Use readiness smoke test failed",
    ));
    report.preserved_state =
        Some("completed Host update actions and the replacement daemon were preserved".into());
    report.recovery_command = Some(format!(
        "satelle doctor --host {} --scope computer-use --refresh --json",
        crate::shell_argument(&report.host)
    ));
    report.status = satelle_core::host_update::HostUpdateStatus::PostcheckFailed;
    if let Err(release_source) = release_bootstrap_lock() {
        return host_update_recovery_pending(
            &mut report,
            "release-bootstrap-lock",
            operation_id,
            release_source,
        );
    }
    SatelleError::host_update_postcheck_failed(&report, source.to_string())
}

fn finish_successful_host_update_postcheck(
    mut report: satelle_core::host_update::HostUpdateReport,
    operation_id: &str,
    release_bootstrap_lock: impl FnOnce() -> Result<(), SatelleError>,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    // The Host has already persisted the successful postcheck and released
    // its leases. Preserve that authoritative outcome even if the later
    // Bootstrap Lock release cannot be confirmed.
    report
        .applied_actions
        .push("host-update-postcheck".to_string());
    report = report.with_postcheck(satelle_core::host_update::HostUpdatePostcheck::passed(
        "native-computer-use-ready",
        "Native Computer Use readiness smoke test passed",
    ));
    if let Err(source) = release_bootstrap_lock() {
        return Err(host_update_recovery_pending(
            &mut report,
            "release-bootstrap-lock",
            operation_id,
            source,
        ));
    }
    Ok(report)
}

fn maintenance_postcheck_is_terminal(details: Option<&serde_json::Value>) -> bool {
    details
        .and_then(serde_json::Value::as_object)
        .and_then(|details| details.get("maintenance_postcheck_terminal"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}

fn finish_unmodified_host_update(
    host: &str,
    client: &DaemonClient,
    operation_id: &str,
) -> Result<(), SatelleError> {
    for action_id in HOST_UPDATE_ACTIONS {
        let response = client
            .skip_maintenance_action(operation_id, action_id)
            .map_err(|error| direct_transport_error(host, error))?;
        validate_persistent_maintenance_response(
            host,
            operation_id,
            response.reconciled(),
            response.operation_id(),
        )?;
    }
    let response = client
        .finish_maintenance_plan(operation_id)
        .map_err(|error| direct_transport_error(host, error))?;
    validate_persistent_maintenance_response(
        host,
        operation_id,
        response.reconciled(),
        response.operation_id(),
    )
}

fn close_unmodified_host_update_or_recovery_pending(
    host: &str,
    client: &DaemonClient,
    operation_id: &str,
    source: SatelleError,
) -> SatelleError {
    match finish_unmodified_host_update(host, client, operation_id) {
        Ok(()) => source,
        Err(cleanup) => {
            unmodified_host_update_recovery_pending(host, operation_id, source, cleanup)
        }
    }
}

fn unmodified_host_update_recovery_pending(
    host: &str,
    operation_id: &str,
    source: SatelleError,
    cleanup: SatelleError,
) -> SatelleError {
    SatelleError::host_update_recovery_pending(
        host,
        operation_id,
        format!("Host update stopped: {source}; maintenance cleanup failed: {cleanup}"),
    )
}

fn begin_host_update_maintenance_with_revalidation(
    host: &str,
    client: &DaemonClient,
    operation_id: &str,
    operation: HostUpdateOperation,
    accepted: &satelle_core::host_update::HostUpdateReport,
    revalidate: impl FnOnce() -> Result<satelle_core::host_update::HostUpdateReport, SatelleError>,
) -> Result<satelle_core::host_update::HostUpdateReport, SatelleError> {
    let begin = match operation {
        HostUpdateOperation::Update => client
            .begin_host_update_maintenance(operation_id, &host_update_recovery_identity(accepted)?),
        HostUpdateOperation::Repair => {
            client.begin_repair_maintenance(operation_id, &host_update_recovery_identity(accepted)?)
        }
    }
    .map_err(|error| host_update_maintenance_begin_error(host, operation_id, error))?;
    if let Err(source) = validate_persistent_maintenance_response(
        host,
        operation_id,
        begin.reconciled(),
        begin.operation_id(),
    ) {
        // A success response proves the request reached the Host. If that
        // response cannot be authenticated against the requested operation,
        // the caller cannot safely assume that Maintenance was not acquired.
        return Err(SatelleError::host_update_recovery_pending(
            host,
            operation_id,
            source.to_string(),
        ));
    }

    // The accepted plan is rebuilt only after Maintenance excludes every
    // competing Host mutation. Drift invalidates consent and closes the
    // still-unmodified action plan before Bootstrap Lock acquisition.
    let current = match revalidate() {
        Ok(current) => current,
        Err(source) => {
            return Err(close_unmodified_host_update_or_recovery_pending(
                host,
                client,
                operation_id,
                source,
            ));
        }
    };
    if &current != accepted {
        return Err(close_unmodified_host_update_or_recovery_pending(
            host,
            client,
            operation_id,
            SatelleError::state_conflict(),
        ));
    }
    Ok(current)
}

fn host_update_recovery_identity(
    report: &satelle_core::host_update::HostUpdateReport,
) -> Result<satelle_core::host_update::HostUpdateRecoveryIdentity, SatelleError> {
    let target = report
        .targets
        .iter()
        .find(|target| {
            target.target == satelle_core::host_update::HostUpdateTarget::HostDaemon
                && target.requires_mutation()
        })
        .ok_or_else(|| {
            SatelleError::invalid_usage("the Host update plan lacks a mutating Host daemon target")
        })?;
    let artifact_digest = target.artifact_digest.as_deref().ok_or_else(|| {
        SatelleError::invalid_usage("the Host update plan lacks a verified artifact digest")
    })?;
    Ok(satelle_core::host_update::HostUpdateRecoveryIdentity::new(
        &target.target_version,
        artifact_digest,
    ))
}

fn host_update_maintenance_begin_error(
    host: &str,
    operation_id: &str,
    error: DaemonClientError,
) -> SatelleError {
    let outcome_is_uncertain = matches!(
        &error,
        DaemonClientError::Transport(_)
            | DaemonClientError::InvalidResponse(_)
            | DaemonClientError::UnexpectedSuccessStatus { .. }
            | DaemonClientError::ResponseRequestIdMismatch
            | DaemonClientError::ResponseHostIdentityMismatch
            | DaemonClientError::ResponseContractViolation
    );
    if outcome_is_uncertain {
        SatelleError::host_update_recovery_pending(host, operation_id, error.to_string())
    } else {
        // Local request construction, TLS negotiation, protocol rejection, and
        // typed API rejection all prove that this mutation did not succeed.
        direct_transport_error(host, error)
    }
}

fn finish_locked_unmodified_host_update(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    for action_id in HOST_UPDATE_ACTIONS {
        skip_maintenance_action(host, client, bootstrap_lock, action_id)?;
    }
    finish_persistent_maintenance(host, client, bootstrap_lock)?;
    bootstrap_lock
        .release_committed_handoff()
        .map_err(|_| SatelleError::host_unreachable(host))
}

fn close_locked_unmodified_host_update_or_recovery_pending(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    source: SatelleError,
) -> SatelleError {
    let operation_id = bootstrap_lock.operation_id().to_string();
    match finish_locked_unmodified_host_update(host, client, bootstrap_lock) {
        Ok(()) => source,
        Err(cleanup) => {
            unmodified_host_update_recovery_pending(host, &operation_id, source, cleanup)
        }
    }
}

fn finish_unmodified_after_uncertain_first_action_start(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    let first_action_was_failed = match client.fail_maintenance_action(
        &operation_id,
        "install-host-artifact",
        "remote_command_failed",
    ) {
        Ok(response) => {
            validate_persistent_maintenance_response(
                host,
                &operation_id,
                response.reconciled(),
                response.operation_id(),
            )?;
            // A successful failure transition proves the Host received the
            // start and atomically skips its dependent planned actions.
            commit_verified_bootstrap_mutation(host, bootstrap_lock)?;
            true
        }
        Err(error) if maintenance_action_is_still_planned(&error) => {
            // The exact state conflict proves the lost start request did not
            // leave the first action started. Commit an unresolved transport
            // attempt now; a known pre-mutation rejection already committed
            // it, and the local fence makes that repeat a no-op.
            commit_verified_bootstrap_mutation(host, bootstrap_lock)?;
            skip_maintenance_action(host, client, bootstrap_lock, "install-host-artifact")?;
            false
        }
        Err(error) => return Err(direct_transport_error(host, error)),
    };

    if !first_action_was_failed {
        for action_id in HOST_UPDATE_ACTIONS.iter().skip(1) {
            skip_maintenance_action(host, client, bootstrap_lock, action_id)?;
        }
    }
    finish_persistent_maintenance(host, client, bootstrap_lock)?;
    bootstrap_lock
        .release_committed_handoff()
        .map_err(|_| SatelleError::host_unreachable(host))
}

fn recover_failed_first_host_update_action_start(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    source: SatelleError,
) -> SatelleError {
    let operation_id = bootstrap_lock.operation_id().to_string();
    match finish_unmodified_after_uncertain_first_action_start(host, client, bootstrap_lock) {
        Ok(()) => source,
        Err(cleanup) => {
            unmodified_host_update_recovery_pending(host, &operation_id, source, cleanup)
        }
    }
}

fn maintenance_action_is_still_planned(error: &DaemonClientError) -> bool {
    matches!(
        error,
        DaemonClientError::Api { status, error }
            if status.as_u16() == 409 && error.code() == ApiErrorCode::StateConflict
    )
}

fn fail_host_update_action(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_id: &str,
    source: SatelleError,
) -> SatelleError {
    let operation_id = bootstrap_lock.operation_id().to_string();
    let action_index = HOST_UPDATE_ACTIONS
        .iter()
        .position(|candidate| *candidate == action_id)
        .expect("failed Host update actions belong to the ordered maintenance plan");
    let recorded_failure = record_persistent_action_failure(
        host,
        client,
        bootstrap_lock,
        action_id,
        "remote_command_failed",
    );
    if recorded_failure.is_ok() {
        report.skipped_actions.extend(
            HOST_UPDATE_ACTIONS
                .iter()
                .skip(action_index + 1)
                .map(|action| (*action).to_string()),
        );
    }
    let cleanup = recorded_failure
        .and_then(|()| finish_persistent_maintenance(host, client, bootstrap_lock))
        .and_then(|()| {
            bootstrap_lock
                .release_committed_handoff()
                .map_err(|_| SatelleError::host_unreachable(host))
        });
    match cleanup {
        Ok(()) => host_update_recovery_pending(report, action_id, &operation_id, source),
        Err(cleanup) if !report.changed => {
            unmodified_host_update_recovery_pending(host, &operation_id, source, cleanup)
        }
        Err(cleanup) => {
            let failure_detail =
                format!("Host update stopped: {source}; maintenance cleanup failed: {cleanup}");
            let mut error = host_update_recovery_pending(report, action_id, &operation_id, source);
            error.source_detail = Some(failure_detail);
            error
        }
    }
}

fn fail_pre_adoption_host_replacement(
    host: &str,
    client: Option<&DaemonClient>,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_id: &str,
    source: SatelleError,
) -> SatelleError {
    if let Some(client) = client {
        return fail_host_update_action(host, client, bootstrap_lock, report, action_id, source);
    }

    let operation_id = bootstrap_lock.operation_id().to_string();
    if report.changed || bootstrap_lock.has_mutation_attempt() {
        // A lock-first repair has no daemon ledger until the replacement
        // starts. Preserve the operation claim whenever the remote mutation
        // outcome is known or uncertain so a later repair can reconcile it.
        report.changed = true;
        return operation_scoped_partial_host_update(
            report,
            action_id,
            &operation_id,
            source,
            None,
        );
    }
    release_unmodified_bootstrap_repair(host, bootstrap_lock, source)
}

fn release_unmodified_bootstrap_repair(
    host: &str,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    source: SatelleError,
) -> SatelleError {
    let operation_id = bootstrap_lock.operation_id().to_string();
    match bootstrap_lock.release_unmodified() {
        Ok(()) => source,
        Err(_) => SatelleError::host_update_recovery_pending(
            host,
            &operation_id,
            format!("Host repair stopped: {source}; Bootstrap Lock release failed"),
        ),
    }
}

fn recover_later_host_update_action_start(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_id: &str,
    source: SatelleError,
) -> SatelleError {
    let operation_id = bootstrap_lock.operation_id().to_string();
    if bootstrap_lock.current_mutation_is_committed() {
        let action_index = HOST_UPDATE_ACTIONS
            .iter()
            .position(|candidate| *candidate == action_id)
            .expect("later Host update actions belong to the ordered maintenance plan");
        let cleanup = (|| {
            skip_remaining_host_update_actions(report, action_index, |remaining| {
                skip_maintenance_action(host, client, bootstrap_lock, remaining)
            })?;
            finish_persistent_maintenance(host, client, bootstrap_lock)?;
            bootstrap_lock
                .release_committed_handoff()
                .map_err(|_| SatelleError::host_unreachable(host))
        })();
        if cleanup.is_ok() {
            return host_update_recovery_pending(report, action_id, &operation_id, source);
        }
        return operation_scoped_partial_host_update(
            report,
            action_id,
            &operation_id,
            source,
            cleanup.err(),
        );
    }

    operation_scoped_partial_host_update(report, action_id, &operation_id, source, None)
}

fn skip_remaining_host_update_actions(
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_index: usize,
    mut skip_action: impl FnMut(&str) -> Result<(), SatelleError>,
) -> Result<(), SatelleError> {
    for remaining in &HOST_UPDATE_ACTIONS[action_index..] {
        skip_action(remaining)?;
        report.skipped_actions.push((*remaining).to_string());
    }
    Ok(())
}

fn operation_scoped_partial_host_update(
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_id: &str,
    operation_id: &str,
    source: SatelleError,
    cleanup: Option<SatelleError>,
) -> SatelleError {
    let failure_detail = cleanup.as_ref().map(|cleanup| {
        format!("Host update stopped: {source}; maintenance cleanup failed: {cleanup}")
    });
    let mut error = host_update_recovery_pending(report, action_id, operation_id, source);
    if let Some(failure_detail) = failure_detail {
        error.source_detail = Some(failure_detail);
    }
    error
}

fn host_update_daemon_adoption_error(
    report: &mut satelle_core::host_update::HostUpdateReport,
    operation_id: &str,
    source: SatelleError,
) -> SatelleError {
    report.changed = true;
    report
        .applied_actions
        .push("restart-host-daemon".to_string());
    operation_scoped_partial_host_update(report, "restart-host-daemon", operation_id, source, None)
}

fn host_update_recovery_pending(
    report: &mut satelle_core::host_update::HostUpdateReport,
    action_id: &str,
    operation_id: &str,
    source: SatelleError,
) -> SatelleError {
    if !report.changed {
        return source;
    }
    report.status = satelle_core::host_update::HostUpdateStatus::PartialFailure;
    report.preserved_state = Some("completed Host update actions were preserved".to_string());
    report.recovery_command = Some(format!(
        "satelle repair --host {} --run {} --no-input --yes",
        crate::shell_argument(&report.host),
        crate::shell_argument(operation_id)
    ));
    let mut error =
        SatelleError::host_update_partially_applied(report, action_id, source.to_string());
    error.details.insert(
        "operation_id".to_string(),
        serde_json::Value::String(operation_id.to_string()),
    );
    error
}

fn selected_repair_run(
    host: &SelectedHost,
    run_id: Option<&str>,
    recovery_authorized: bool,
) -> Result<Option<RepairLedgerPlan>, SatelleError> {
    let Some(run_id) = run_id else {
        return Ok(None);
    };
    let launch_policy =
        selected_repair_initial_launch_policy(host.config.transport.clone(), Some(run_id));
    match transport_for_with_ssh_launch_policy(host, launch_policy) {
        Ok(transport) => transport.plan_setup_repair(Some(run_id), &[]).map(Some),
        Err(failure)
            if host.config.transport == TransportKind::Ssh
                && recovery_authorized
                && is_daemon_reachability_failure(&failure.error) =>
        {
            recover_selected_repair_daemon(host, run_id)?;
            transport_for_with_ssh_launch_policy(host, SshDaemonLaunchPolicy::Never)
                .map_err(|failure| failure.error)?
                .plan_setup_repair(Some(run_id), &[])
                .map(Some)
        }
        Err(failure) => Err(failure.error),
    }
}

const fn selected_repair_initial_launch_policy(
    transport: TransportKind,
    run_id: Option<&str>,
) -> SshDaemonLaunchPolicy {
    if matches!(transport, TransportKind::Ssh) && run_id.is_some() {
        SshDaemonLaunchPolicy::Never
    } else {
        SshDaemonLaunchPolicy::DurableOnly
    }
}

fn recover_selected_repair_daemon(
    host: &SelectedHost,
    operation_id: &str,
) -> Result<(), SatelleError> {
    let transport = SshSetupTransport::new(host)?;
    if transport.requires_first_trust {
        return Err(SatelleError::ssh_host_key_verification_required(
            &transport.alias,
        ));
    }
    let target = transport.remote_target()?;
    if target.service_platform() == DaemonServicePlatform::Linux {
        return Err(SatelleError::persistent_service_unsupported(
            target.service_platform().as_str(),
        ));
    }
    let directories = transport.remote_directories(target)?;
    let (durable_tunnel, durable_client) = transport.durable_service_client()?;
    let mut bootstrap_lock = acquire_bootstrap_lock_for_operation(
        &transport.alias,
        transport.binding.destination(),
        operation_id.to_string(),
        bootstrap_lock::OperationKind::HostBinaryReplacement,
    )?;

    let relaunched = match relaunch_durable_daemon_under_lock(
        DurableRelaunchTarget {
            host: &transport.alias,
            expected_host_identity: transport.binding.expected_host_identity().as_str(),
        },
        &mut bootstrap_lock,
        |lock| confirm_bootstrap_lock(&transport.alias, lock),
        || observe_remote_durable_readiness(durable_client.capabilities()),
        |lock| {
            let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
                transport.binding.destination(),
                target,
                &directories,
                lock,
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
            let expected_host_id = transport.binding.expected_host_identity().to_string();
            remote
                .observe_canonical_daemon_path_overrides(&expected_host_id)
                .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
            let windows_task = if target.service_platform() == DaemonServicePlatform::Windows {
                Some(
                    remote
                        .registered_windows_task(&expected_host_id)
                        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?,
                )
            } else {
                None
            };
            match target.service_platform() {
                DaemonServicePlatform::Windows => remote.restart_registered_windows_task(
                    windows_task
                        .as_ref()
                        .expect("Windows recovery preflight provides the registered task"),
                ),
                DaemonServicePlatform::Macos => remote.restart_launchd(),
                DaemonServicePlatform::Linux => unreachable!("Linux recovery is rejected"),
            }
            .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
            wait_for_service_observation(
                &transport.alias,
                || match target.service_platform() {
                    DaemonServicePlatform::Windows => remote.observe_registered_windows_task(
                        windows_task
                            .as_ref()
                            .expect("Windows recovery preflight provides the registered task"),
                    ),
                    DaemonServicePlatform::Macos => remote.observe_launchd_runtime(),
                    DaemonServicePlatform::Linux => unreachable!("Linux recovery is rejected"),
                },
                ssh_bootstrap::PersistentServiceObservation::Running,
            )
        },
        || observe_remote_durable_readiness(durable_client.capabilities()),
        Instant::now() + SSH_DAEMON_LAUNCH_TIMEOUT,
    ) {
        Ok(relaunched) => relaunched,
        Err(error) => {
            if bootstrap_lock.has_mutation_attempt() {
                // A fenced restart may have executed even when its response or
                // readiness proof failed. Keep the exact operation claim for
                // stale recovery instead of falsely releasing it as unmodified.
                return Err(error);
            }
            bootstrap_lock
                .release_unmodified()
                .map_err(|_| SatelleError::host_unreachable(&transport.alias))?;
            return Err(error);
        }
    };
    if relaunched {
        commit_verified_bootstrap_mutation(&transport.alias, &mut bootstrap_lock)?;
        bootstrap_lock
            .release_committed_handoff()
            .map_err(|_| SatelleError::host_unreachable(&transport.alias))?;
    } else {
        bootstrap_lock
            .release_unmodified()
            .map_err(|_| SatelleError::host_unreachable(&transport.alias))?;
    }
    drop(durable_client);
    drop(durable_tunnel);
    Ok(())
}

fn selected_host_replacement_operation(
    selected_run: Option<&RepairLedgerPlan>,
) -> Option<HostUpdateOperation> {
    let run = selected_run?;
    if !matches!(
        run.selected_run_status,
        Some(
            satelle_transport::SetupRepairRunStatus::Running
                | satelle_transport::SetupRepairRunStatus::OutcomeUnknown
        )
    ) || run.host_update_recovery_identity.is_none()
    {
        return None;
    }
    match run.selected_operation_kind {
        Some(satelle_transport::SetupRepairOperationKind::HostUpdate) => {
            Some(HostUpdateOperation::Update)
        }
        Some(satelle_transport::SetupRepairOperationKind::Repair) => {
            Some(HostUpdateOperation::Repair)
        }
        _ => None,
    }
}

fn repair_host_replacement_entry(
    repair: &satelle_core::host_update::RepairUpgradeReport,
    resumes_host_replacement: bool,
) -> HostReplacementEntry {
    use satelle_core::host_update::{
        HostUpdateTarget, RepairCompatibilityReason, RepairUpgradeDisposition,
    };

    if !resumes_host_replacement
        && repair.actions.iter().any(|action| {
            action.target == HostUpdateTarget::HostDaemon
                && action.disposition == RepairUpgradeDisposition::Required
                && matches!(
                    action.compatibility_reason,
                    Some(
                        RepairCompatibilityReason::Missing
                            | RepairCompatibilityReason::ControlPlaneIncompatible
                    )
                )
        })
    {
        HostReplacementEntry::Bootstrap
    } else {
        HostReplacementEntry::ReachableDaemon
    }
}

fn repair_plan_reads_daemon_ledger(
    repair: &satelle_core::host_update::RepairUpgradeReport,
    run_id: Option<&str>,
) -> bool {
    run_id.is_some()
        || (repair.requires_mutation()
            && repair_host_replacement_entry(repair, false)
                == HostReplacementEntry::ReachableDaemon)
}

pub(crate) fn plan_repair_upgrades(
    host: &SelectedHost,
    run_id: Option<&str>,
    recovery_authorized: bool,
) -> Result<satelle_core::host_update::RepairUpgradeReport, SatelleError> {
    use satelle_core::host_update::{
        HostUpdateTarget, HostUpdateVersionSource, RepairCompatibilityReason,
    };

    let selected_run = selected_repair_run(host, run_id, recovery_authorized)?;
    let resumes_host_replacement =
        selected_host_replacement_operation(selected_run.as_ref()).is_some();
    let target_version = if resumes_host_replacement {
        selected_run
            .as_ref()
            .and_then(|run| run.host_update_recovery_identity.as_ref())
            .map(|identity| identity.target_version())
            .ok_or_else(SatelleError::state_conflict)?
    } else {
        env!("CARGO_PKG_VERSION")
    };
    let inspection = inspect_host_maintenance(
        host,
        if resumes_host_replacement {
            HostMaintenancePlanKind::HostUpdateRecovery
        } else {
            HostMaintenancePlanKind::Repair
        },
        target_version,
    )?;
    if resumes_host_replacement {
        validate_host_update_recovery_artifact(
            &inspection,
            selected_run
                .as_ref()
                .and_then(|run| run.host_update_recovery_identity.as_ref())
                .ok_or_else(SatelleError::state_conflict)?,
        )?;
    }
    let cli_release = parse_release_version(target_version)?;
    let current_host_release = inspection
        .current_version
        .as_deref()
        .map(parse_release_version)
        .transpose()?;
    if current_host_release.is_some_and(|current| current > cli_release) {
        return Err(SatelleError::host_binary_newer_than_cli(
            inspection
                .current_version
                .as_deref()
                .expect("parsed Host version retains its source value"),
            target_version,
        ));
    }
    let minimum_host_release = inspection
        .minimum_host_version
        .as_deref()
        .map(parse_release_version)
        .transpose()?;
    let minimum_exceeds_cli = minimum_host_release.is_some_and(|minimum| minimum > cli_release);
    let host_reason = if resumes_host_replacement {
        Some(RepairCompatibilityReason::Corrupted)
    } else if inspection.current_version.is_none() {
        Some(RepairCompatibilityReason::Missing)
    } else if minimum_exceeds_cli {
        Some(RepairCompatibilityReason::BelowMinimumVersion)
    } else if !inspection.protocol_compatible {
        Some(RepairCompatibilityReason::ControlPlaneIncompatible)
    } else {
        None
    };
    let host_target_version = if minimum_exceeds_cli {
        inspection
            .minimum_host_version
            .clone()
            .expect("minimum-version comparison retains its source value")
    } else {
        target_version.to_string()
    };
    let host_version_source = if minimum_exceeds_cli {
        HostUpdateVersionSource::HostCompatibilityRequirement
    } else {
        HostUpdateVersionSource::InvokingCliRelease
    };
    let mut repair_inspections = vec![crate::host_update::RepairUpgradeInspection {
        target: HostUpdateTarget::HostDaemon,
        current_version: inspection.current_version.clone(),
        target_version: host_target_version,
        compatibility_reason: host_reason,
        version_source: host_version_source,
        automation_is_safe: inspection.host_automation_is_safe
            && inspection
                .artifact
                .as_ref()
                .and_then(|artifact| artifact.daemon_destination.as_ref())
                .is_some()
            && !minimum_exceeds_cli,
        newer_compatible_version_available: host_reason.is_none()
            && current_host_release.is_some_and(|current| current < cli_release),
    }];

    append_codex_repair_inspections(&mut repair_inspections, inspection.codex_evidence)?;

    let mut report =
        crate::host_update::build_repair_upgrade_plan(&host.alias, &repair_inspections);
    if repair_plan_reads_daemon_ledger(&report, run_id) {
        let probes = report
            .planned_actions
            .iter()
            .map(|action_id| satelle_transport::SetupRepairProbe {
                action_id: action_id.clone(),
                label: action_id.replace('-', " "),
                retry_safe: true,
                postcondition: satelle_transport::SetupRepairPostcondition::Unsatisfied,
            })
            .collect::<Vec<_>>();
        let ledger = transport_for(host)
            .map_err(|failure| failure.error)?
            .plan_setup_repair(run_id, &probes)?;
        if ledger.available {
            report.ledger_status = satelle_core::host_update::RepairLedgerStatus::Available;
            report.plan_source = satelle_core::host_update::RepairPlanSource::SetupLedger;
            let unattended_retry_safe = report
                .planned_actions
                .iter()
                .all(|action| ledger.automatic_action_ids.contains(action));
            if !unattended_retry_safe {
                for action in &mut report.actions {
                    if action.disposition
                        == satelle_core::host_update::RepairUpgradeDisposition::Required
                    {
                        action.disposition =
                            satelle_core::host_update::RepairUpgradeDisposition::ManualActionRequired;
                    }
                }
                let ledger_status = report.ledger_status;
                let plan_source = report.plan_source;
                report = satelle_core::host_update::RepairUpgradeReport::new(
                    report.host,
                    report.actions,
                );
                report.ledger_status = ledger_status;
                report.plan_source = plan_source;
            }
        }
    }
    Ok(report)
}

fn append_codex_repair_inspections(
    repair_inspections: &mut Vec<crate::host_update::RepairUpgradeInspection>,
    codex: Option<satelle_core::host_update::CodexUpdateEvidence>,
) -> Result<(), SatelleError> {
    use satelle_core::host_update::{
        CodexComponentOwnership, HostUpdateTarget, HostUpdateVersionSource,
    };

    // A missing or unreachable Host cannot provide authenticated Codex
    // evidence. Keep the derived Host repair actionable without inventing
    // Codex ownership or proposing an unobserved Codex mutation.
    let Some(codex) = codex else {
        return Ok(());
    };
    if codex.availability
        == satelle_core::host_update::CodexUpdateAvailability::UnsupportedHostPlatform
    {
        return Ok(());
    }
    let codex_inspections = [
        (
            HostUpdateTarget::CodexRuntime,
            codex.runtime_ownership,
            codex.runtime_current_version,
            codex.runtime_compatibility_reason,
        ),
        (
            HostUpdateTarget::CodexNativeComputerUse,
            codex.native_component_ownership,
            codex.native_component_current_version,
            codex.native_component_compatibility_reason,
        ),
    ];
    for (target, ownership, current_version, compatibility_reason) in codex_inspections {
        if ownership != CodexComponentOwnership::CodexOwned {
            return Err(SatelleError::ambiguous_codex_component_ownership(&format!(
                "{target:?}"
            )));
        }
        repair_inspections.push(crate::host_update::RepairUpgradeInspection {
            target,
            current_version,
            target_version: codex.required_version.clone(),
            compatibility_reason,
            version_source: HostUpdateVersionSource::CodexCompatibilityRequirement,
            // No current transport owns an automatic Codex replacement executor.
            automation_is_safe: false,
            newer_compatible_version_available: false,
        });
    }

    Ok(())
}

pub(crate) fn apply_repair_upgrades(
    host: &SelectedHost,
    mut repair: satelle_core::host_update::RepairUpgradeReport,
    recovery_run_id: Option<&str>,
) -> Result<satelle_core::host_update::RepairUpgradeReport, SatelleError> {
    use satelle_core::host_update::HostUpdateComponent;

    if !repair.requires_mutation() {
        return Ok(repair);
    }
    let selected_run = selected_repair_run(host, recovery_run_id, false)?;
    let resumed_operation = selected_host_replacement_operation(selected_run.as_ref());
    let recovery_identity = resumed_operation
        .is_some()
        .then(|| {
            selected_run
                .as_ref()
                .and_then(|run| run.host_update_recovery_identity.as_ref())
                .cloned()
                .ok_or_else(SatelleError::state_conflict)
        })
        .transpose()?;
    let target_version = recovery_identity.as_ref().map_or(
        env!("CARGO_PKG_VERSION"),
        satelle_core::host_update::HostUpdateRecoveryIdentity::target_version,
    );
    let components = [HostUpdateComponent::Host];
    let host_update = if let Some(recovery_identity) = recovery_identity.as_ref() {
        plan_host_update_recovery(host, recovery_identity)?
    } else {
        plan_host_update(host, target_version, &components, false)?
    };
    let operation = resumed_operation.unwrap_or(HostUpdateOperation::Repair);
    let entry = repair_host_replacement_entry(&repair, resumed_operation.is_some());
    let source = match apply_host_update_with_operation(
        host,
        target_version,
        host_update,
        operation,
        entry,
        recovery_run_id.filter(|_| resumed_operation.is_some()),
        || {
            if let Some(recovery_identity) = recovery_identity.as_ref() {
                plan_host_update_recovery(host, recovery_identity)
            } else {
                plan_host_update(host, target_version, &components, false)
            }
        },
    ) {
        Ok(applied) => return Ok(repair.applied(applied.applied_actions)),
        Err(source) => source,
    };
    let completed_actions = source
        .details
        .get("completed_actions")
        .or_else(|| source.details.get("applied_actions"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let failed_action = source
        .details
        .get("failed_action")
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || {
                repair
                    .planned_actions
                    .iter()
                    .find(|action| !completed_actions.contains(action))
                    .cloned()
                    .unwrap_or_else(|| "host-update-postcheck".to_string())
            },
            str::to_string,
        );
    let failed_index = repair
        .planned_actions
        .iter()
        .position(|action| action == &failed_action)
        .unwrap_or(repair.planned_actions.len());
    for skipped in repair.planned_actions.iter().skip(failed_index + 1) {
        if !repair.skipped_actions.contains(skipped) {
            repair.skipped_actions.push(skipped.clone());
        }
    }
    if completed_actions.is_empty() {
        return Err(setup_action_failure_with_source_recovery(
            &repair.host,
            &failed_action,
            &repair.skipped_actions,
            &source,
        ));
    }
    let mut partial = repair.partial_failure(completed_actions, &failed_action);
    if source.recovery_command.is_some() {
        partial
            .recovery_command
            .clone_from(&source.recovery_command);
    }
    Err(SatelleError::setup_partially_applied(
        &partial,
        &failed_action,
        source.to_string(),
    ))
}

fn setup_action_failure_with_source_recovery(
    host: &str,
    failed_action: &str,
    skipped_actions: &[String],
    source: &SatelleError,
) -> SatelleError {
    let mut error =
        SatelleError::setup_action_failed(host, failed_action, skipped_actions, source.to_string());
    if let Some(recovery_command) = &source.recovery_command {
        error.recovery_command = Some(recovery_command.clone());
        error.details.insert(
            "recovery_command".to_string(),
            serde_json::Value::String(recovery_command.clone()),
        );
    }
    error
}

fn canonical_remote_platform(platform: &str) -> (Option<ssh_bootstrap::RemoteTarget>, String) {
    (
        ssh_bootstrap::RemoteTarget::from_id(platform),
        platform.to_string(),
    )
}

fn verified_host_update_artifact(
    host: &str,
    version: &str,
    required: bool,
    target: ssh_bootstrap::RemoteTarget,
    install_path: Option<String>,
    known_metadata: Option<ssh_bootstrap::ReleaseArtifactMetadata>,
) -> Result<Option<crate::host_update::VerifiedHostArtifact>, SatelleError> {
    if !required {
        return Ok(None);
    }
    let metadata = known_metadata.map_or_else(
        || ssh_bootstrap::ReleaseArtifactMetadata::fetch(target, version),
        Ok,
    );
    verified_host_update_artifact_from_metadata(host, version, target, install_path, metadata)
        .map(Some)
}

fn verified_host_update_artifact_from_metadata(
    host: &str,
    version: &str,
    target: ssh_bootstrap::RemoteTarget,
    install_path: Option<String>,
    metadata: Result<ssh_bootstrap::ReleaseArtifactMetadata, ssh_bootstrap::SshBootstrapError>,
) -> Result<crate::host_update::VerifiedHostArtifact, SatelleError> {
    let metadata = metadata.map_err(|error| map_ssh_daemon_bootstrap_error(host, error))?;
    Ok(crate::host_update::VerifiedHostArtifact {
        version: version.to_string(),
        remote_platform: target.id().to_string(),
        digest: metadata.digest_hex(),
        daemon_destination: install_path,
    })
}

fn host_version_relation(
    current: Option<&str>,
    protocol_compatible: bool,
    minimum_host_version: Option<&str>,
    cli: &str,
) -> Result<crate::host_update::HostVersionRelation, SatelleError> {
    let Some(current) = current else {
        return Ok(crate::host_update::HostVersionRelation::Missing);
    };
    let cli = parse_release_version(cli)?;
    let current = parse_release_version(current)?;
    if current > cli {
        return Ok(crate::host_update::HostVersionRelation::NewerThanCli);
    }
    if minimum_host_version
        .map(parse_release_version)
        .transpose()?
        .is_some_and(|minimum| minimum > cli)
    {
        return Ok(crate::host_update::HostVersionRelation::RequiresNewerCli);
    }
    Ok(if current < cli || !protocol_compatible {
        crate::host_update::HostVersionRelation::OlderThanCli
    } else {
        crate::host_update::HostVersionRelation::MatchesCli
    })
}

fn parse_release_version(value: &str) -> Result<(u64, u64, u64), SatelleError> {
    let mut parts = value.split('.');
    let version = (
        parts.next().and_then(|part| part.parse().ok()),
        parts.next().and_then(|part| part.parse().ok()),
        parts.next().and_then(|part| part.parse().ok()),
    );
    match version {
        (Some(major), Some(minor), Some(patch)) if parts.next().is_none() => {
            Ok((major, minor, patch))
        }
        _ => Err(SatelleError::config_error(
            "the authenticated Host reported a non-release version",
            None,
        )),
    }
}

fn map_host_update_plan_error(error: crate::host_update::HostUpdatePlanError) -> SatelleError {
    use crate::host_update::HostUpdatePlanError;
    match error {
        HostUpdatePlanError::ComponentSelectionConflict => {
            SatelleError::component_selection_conflict()
        }
        HostUpdatePlanError::HostBinaryNewerThanCli {
            host_version,
            cli_version,
        } => SatelleError::host_binary_newer_than_cli(&host_version, &cli_version),
        HostUpdatePlanError::HostArtifactUnavailable {
            cli_version,
            remote_platform,
        } => SatelleError::host_artifact_unavailable(&cli_version, &remote_platform),
        HostUpdatePlanError::HostUpdateRequiresCliUpgrade { cli_version } => {
            SatelleError::host_update_requires_cli_upgrade(&cli_version)
        }
        HostUpdatePlanError::AmbiguousCodexComponentOwnership { target } => {
            SatelleError::ambiguous_codex_component_ownership(&format!("{target:?}"))
        }
        HostUpdatePlanError::UnsupportedCodexTarget { .. } => {
            SatelleError::computer_use_not_ready()
        }
        HostUpdatePlanError::InvalidArtifact { .. }
        | HostUpdatePlanError::InvalidCodexTarget { .. } => {
            SatelleError::config_error("Host update planning produced invalid typed evidence", None)
        }
    }
}

fn restart_persistent_service(
    transport: &SshSetupTransport,
    target: ssh_bootstrap::RemoteTarget,
    directories: &ssh_bootstrap::RemoteUserDirectories,
    windows_task: Option<&ssh_bootstrap::RegisteredWindowsTask>,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    {
        let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
            transport.binding.destination(),
            target,
            directories,
            bootstrap_lock,
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
        match target.service_platform() {
            DaemonServicePlatform::Windows => remote.restart_registered_windows_task(
                windows_task.expect("Windows lifecycle preflight provides the registered task"),
            ),
            DaemonServicePlatform::Macos => remote.restart_launchd(),
            DaemonServicePlatform::Linux => unreachable!("Linux lifecycle is rejected"),
        }
        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
        wait_for_service_observation(
            &transport.alias,
            || match target.service_platform() {
                DaemonServicePlatform::Windows => remote.observe_registered_windows_task(
                    windows_task.expect("Windows lifecycle preflight provides the registered task"),
                ),
                DaemonServicePlatform::Macos => remote.observe_launchd_runtime(),
                DaemonServicePlatform::Linux => unreachable!("Linux lifecycle is rejected"),
            },
            ssh_bootstrap::PersistentServiceObservation::Running,
        )?;
    }
    let (durable_tunnel, durable_client) = transport.durable_service_client()?;
    wait_for_durable_daemon(&transport.alias, || durable_client.capabilities())?;
    commit_verified_bootstrap_mutation(&transport.alias, bootstrap_lock)?;
    begin_service_lifecycle_maintenance(
        &transport.alias,
        &durable_client,
        bootstrap_lock,
        SshPersistentServiceLifecycle::Restart,
    )?;
    complete_persistent_action(
        &transport.alias,
        &durable_client,
        bootstrap_lock,
        SshPersistentServiceLifecycle::Restart.action_id(),
    )?;
    finish_persistent_maintenance(&transport.alias, &durable_client, bootstrap_lock)?;
    drop(durable_client);
    drop(durable_tunnel);
    Ok(())
}

fn stop_persistent_service(
    transport: &SshSetupTransport,
    target: ssh_bootstrap::RemoteTarget,
    directories: &ssh_bootstrap::RemoteUserDirectories,
    persisted_overrides: &DaemonPathOverrides,
    windows_task: Option<&ssh_bootstrap::RegisteredWindowsTask>,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    let expected_host_id = transport.binding.expected_host_identity().to_string();
    verify_stopped_service_postconditions(
        transport,
        target,
        directories,
        bootstrap_lock,
        windows_task,
        true,
    )?;
    commit_verified_bootstrap_mutation(&transport.alias, bootstrap_lock)?;

    let service_host_config = transport.host_config_with_overrides(persisted_overrides);
    let (bootstrap_client, bootstrap_tunnel, bootstrap_process, _handoff_token) =
        setup_bootstrap_client(
            &transport.alias,
            transport.binding.destination(),
            &expected_host_id,
            &transport.host_config,
            &service_host_config,
            SshBootstrapScope::Admin,
            bootstrap_lock,
        )?;
    begin_service_lifecycle_maintenance(
        &transport.alias,
        &bootstrap_client,
        bootstrap_lock,
        SshPersistentServiceLifecycle::Stop,
    )?;
    verify_stopped_service_postconditions(
        transport,
        target,
        directories,
        bootstrap_lock,
        windows_task,
        false,
    )?;
    complete_persistent_action(
        &transport.alias,
        &bootstrap_client,
        bootstrap_lock,
        SshPersistentServiceLifecycle::Stop.action_id(),
    )?;
    finish_persistent_maintenance(&transport.alias, &bootstrap_client, bootstrap_lock)?;
    drop(bootstrap_process);
    drop(bootstrap_client);
    drop(bootstrap_tunnel);
    Ok(())
}

fn verify_stopped_service_postconditions(
    transport: &SshSetupTransport,
    target: ssh_bootstrap::RemoteTarget,
    directories: &ssh_bootstrap::RemoteUserDirectories,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    windows_task: Option<&ssh_bootstrap::RegisteredWindowsTask>,
    perform_stop: bool,
) -> Result<(), SatelleError> {
    let mut remote = ssh_bootstrap::PersistentServiceRemote::new(
        transport.binding.destination(),
        target,
        directories,
        bootstrap_lock,
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
    if perform_stop {
        match target.service_platform() {
            DaemonServicePlatform::Windows => remote.stop_registered_windows_task(
                windows_task.expect("Windows lifecycle preflight provides the registered task"),
            ),
            DaemonServicePlatform::Macos => remote.bootout_launchd(),
            DaemonServicePlatform::Linux => unreachable!("Linux lifecycle is rejected"),
        }
        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
    }
    let expected_manager = match target.service_platform() {
        DaemonServicePlatform::Windows => ssh_bootstrap::PersistentServiceObservation::Stopped,
        DaemonServicePlatform::Macos => ssh_bootstrap::PersistentServiceObservation::Absent,
        DaemonServicePlatform::Linux => unreachable!("Linux lifecycle is rejected"),
    };
    wait_for_service_observation(
        &transport.alias,
        || match target.service_platform() {
            DaemonServicePlatform::Windows => remote.observe_registered_windows_task(
                windows_task.expect("Windows lifecycle preflight provides the registered task"),
            ),
            DaemonServicePlatform::Macos => remote.observe_launchd_runtime(),
            DaemonServicePlatform::Linux => unreachable!("Linux lifecycle is rejected"),
        },
        expected_manager,
    )?;
    wait_for_loopback_listener_absence(&transport.alias, || remote.observe_loopback_listener())
}

fn wait_for_service_observation(
    host: &str,
    mut observe: impl FnMut() -> Result<
        ssh_bootstrap::PersistentServiceObservation,
        ssh_bootstrap::SshBootstrapError,
    >,
    expected: ssh_bootstrap::PersistentServiceObservation,
) -> Result<(), SatelleError> {
    let deadline = Instant::now() + SSH_DAEMON_LAUNCH_TIMEOUT;
    loop {
        let observed = observe().map_err(|error| map_ssh_daemon_bootstrap_error(host, error))?;
        if observed == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SatelleError::remote_api_error(
                host,
                "persistent-service-postcondition-unsatisfied",
            ));
        }
        std::thread::sleep(SSH_DAEMON_LAUNCH_POLL_INTERVAL);
    }
}

fn wait_for_loopback_listener_absence(
    host: &str,
    mut observe: impl FnMut() -> Result<
        ssh_bootstrap::LoopbackListenerObservation,
        ssh_bootstrap::SshBootstrapError,
    >,
) -> Result<(), SatelleError> {
    let deadline = Instant::now() + SSH_DAEMON_LAUNCH_TIMEOUT;
    loop {
        let observed = observe().map_err(|error| map_ssh_daemon_bootstrap_error(host, error))?;
        if observed == ssh_bootstrap::LoopbackListenerObservation::Absent {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SatelleError::remote_api_error(
                host,
                "persistent-service-listener-still-reachable",
            ));
        }
        std::thread::sleep(SSH_DAEMON_LAUNCH_POLL_INTERVAL);
    }
}

fn begin_service_lifecycle_maintenance(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    lifecycle: SshPersistentServiceLifecycle,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("service_lifecycle_maintenance_begin")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = reconcile_bootstrap_maintenance_response(
        host,
        match lifecycle {
            SshPersistentServiceLifecycle::Stop => {
                client.begin_persistent_host_stop_maintenance(&operation_id)
            }
            SshPersistentServiceLifecycle::Restart => {
                client.begin_persistent_host_restart_maintenance(&operation_id)
            }
        },
        bootstrap_lock,
    )?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn begin_persistent_maintenance(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("persistent_maintenance_begin")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = reconcile_bootstrap_maintenance_response(
        host,
        client.begin_persistent_service_maintenance(
            &operation_id,
            bootstrap_lock.operation_kind().as_str(),
        ),
        bootstrap_lock,
    )?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn start_persistent_action(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    action_id: &str,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("persistent_action_start")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = reconcile_bootstrap_maintenance_response(
        host,
        client.start_maintenance_action(&operation_id, action_id),
        bootstrap_lock,
    )?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn complete_persistent_action(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    action_id: &str,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("persistent_action_complete")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = reconcile_bootstrap_maintenance_response(
        host,
        client.complete_maintenance_action(&operation_id, action_id),
        bootstrap_lock,
    )?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn skip_maintenance_action(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    action_id: &str,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("persistent_action_skip")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = reconcile_bootstrap_maintenance_response(
        host,
        client.skip_maintenance_action(&operation_id, action_id),
        bootstrap_lock,
    )?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn finish_persistent_maintenance(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("persistent_maintenance_finish")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = reconcile_bootstrap_maintenance_response(
        host,
        client.finish_maintenance_plan(&operation_id),
        bootstrap_lock,
    )?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn validate_persistent_maintenance_response(
    host: &str,
    operation_id: &str,
    reconciled: bool,
    response_operation_id: &str,
) -> Result<(), SatelleError> {
    if reconciled && response_operation_id == operation_id {
        Ok(())
    } else {
        Err(SatelleError::remote_api_error(
            host,
            "invalid-persistent-maintenance-response",
        ))
    }
}

fn record_persistent_action_failure(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
    action_id: &str,
    failure_kind: &str,
) -> Result<(), SatelleError> {
    commit_verified_bootstrap_mutation(host, bootstrap_lock)?;
    let operation_id = bootstrap_lock.operation_id().to_string();
    bootstrap_lock
        .mark_mutation_started("persistent_action_fail")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let response = client
        .fail_maintenance_action(&operation_id, action_id, failure_kind)
        .map_err(|error| direct_transport_error(host, error))?;
    validate_persistent_maintenance_response(
        host,
        &operation_id,
        response.reconciled(),
        response.operation_id(),
    )?;
    commit_verified_bootstrap_mutation(host, bootstrap_lock)
}

fn rollback_setup_token(
    client: &DaemonClient,
    token_id: &str,
    token_path: &Path,
    host: &str,
    idempotency_key: &str,
) -> Result<(), SatelleError> {
    let aborted = client
        .abort_durable_setup_token(token_id, idempotency_key)
        .map_err(|_| uncertain_setup_rollback(host, token_path))?;
    if aborted.active() || aborted.token_id() != token_id {
        return Err(uncertain_setup_rollback(host, token_path));
    }
    fs::remove_file(token_path).map_err(|error| {
        SatelleError::config_error(
            format!(
                "the setup token was revoked, but its file '{}' could not be removed: {error}",
                token_path.display()
            ),
            None,
        )
    })
}

fn acquire_setup_token_lock(token_path: &Path) -> Result<fs::File, SatelleError> {
    let lock = open_setup_token_lock(token_path)?;
    lock.lock()
        .map_err(|error| setup_token_lock_error(token_path, error))?;
    Ok(lock)
}

fn open_setup_token_lock(token_path: &Path) -> Result<fs::File, SatelleError> {
    let parent = token_path.parent().ok_or_else(|| {
        setup_token_lock_error(token_path, "the token path has no parent directory")
    })?;
    let file_name = token_path
        .file_name()
        .ok_or_else(|| setup_token_lock_error(token_path, "the token path has no file name"))?;
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(file_name);
    lock_name.push(".satelle-setup.lock");
    let lock_path = parent.join(lock_name);

    // The stable sidecar inode must remain in place after unlock. Removing it
    // would let a new setup lock a replacement inode while an existing waiter
    // still blocks on the old one.
    drop(
        open_or_create_owner_only_directory(parent)
            .map_err(|error| setup_token_lock_error(token_path, error))?,
    );
    open_or_create_owner_only_file(&lock_path)
        .map_err(|error| setup_token_lock_error(token_path, error))
}

fn inspect_durable_setup_token(
    client: &DaemonClient,
    token_id: &str,
) -> Result<ExistingTokenInspection, DaemonClientError> {
    match client.confirm_durable_setup_token() {
        Ok(confirmation)
            if confirmation.token_id() == token_id
                && confirmation.setup_active()
                && confirmation.control_scoped() =>
        {
            Ok(ExistingTokenInspection::Reusable)
        }
        Ok(_) => Err(DaemonClientError::ResponseContractViolation),
        Err(DaemonClientError::Api { error, .. })
            if error.code() == ApiErrorCode::AuthenticationFailed =>
        {
            Ok(ExistingTokenInspection::RequiresActivation)
        }
        Err(error) => Err(error),
    }
}

fn activate_durable_setup_token(
    client: &DaemonClient,
    token_id: String,
    activation_idempotency_key: &str,
) -> Result<ExistingTokenVerification, DaemonClientError> {
    // A pending setup credential is rejected everywhere except exact
    // self-activation. The caller fences this mutating request separately from
    // the read-only inspection above.
    let activation =
        match client.activate_durable_setup_token(token_id.as_str(), activation_idempotency_key) {
            Ok(activation) => activation,
            Err(DaemonClientError::Api { error, .. })
                if error.code() == ApiErrorCode::AuthenticationFailed =>
            {
                return Ok(ExistingTokenVerification::AuthenticationRejected { token_id });
            }
            Err(error) => return Err(error),
        };
    if !activation.active() || activation.token_id() != token_id {
        return Err(DaemonClientError::ResponseContractViolation);
    }
    let confirmation = client.confirm_durable_setup_token()?;
    if confirmation.token_id() == token_id
        && confirmation.setup_active()
        && confirmation.control_scoped()
    {
        Ok(ExistingTokenVerification::ActivatedPending)
    } else {
        Err(DaemonClientError::ResponseContractViolation)
    }
}

fn wait_for_durable_daemon<T>(
    host: &str,
    mut operation: impl FnMut() -> Result<T, DaemonClientError>,
) -> Result<T, SatelleError> {
    let deadline = Instant::now() + SSH_DAEMON_LAUNCH_TIMEOUT;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error @ DaemonClientError::Transport(_)) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(direct_transport_error(host, error));
                }
                std::thread::sleep(SSH_DAEMON_LAUNCH_POLL_INTERVAL.min(deadline - now));
            }
            Err(error) => return Err(direct_transport_error(host, error)),
        }
    }
}

fn uncertain_setup_rollback(host: &str, token_path: &Path) -> SatelleError {
    SatelleError::config_error(
        format!(
            "could not confirm setup-token revocation on host '{host}'; retained '{}' for explicit recovery",
            token_path.display()
        ),
        None,
    )
}

fn token_file_error(path: &Path, error: satelle_core::SecureFileError) -> SatelleError {
    SatelleError::config_error(
        format!(
            "could not persist the durable API token at '{}': {error}",
            path.display()
        ),
        None,
    )
}

fn setup_token_lock_error(path: &Path, error: impl std::fmt::Display) -> SatelleError {
    SatelleError::config_error(
        format!(
            "could not serialize setup for the durable API token path '{}': {error}",
            path.display()
        ),
        None,
    )
}

impl TransportClient for SshSetupTransport {
    fn log_target_identity(&self) -> Result<String, SatelleError> {
        Ok(self.binding.expected_host_identity().to_string())
    }

    fn setup(
        &self,
        dry_run: bool,
        setup_mode: SetupModeSelection,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        self.validate_setup_request(&setup_components)?;
        let target = self.remote_target()?;
        let host_config = self.host_config_with_overrides(&daemon_path_overrides);
        let existing_token_file = self.token_file_exists()?;
        let current_daemon = self.observe_current_daemon_artifact(existing_token_file)?;
        let plan = self.setup_report_for_target(
            dry_run,
            setup_mode,
            target,
            setup_components.clone(),
            daemon_path_overrides.clone(),
            SetupApplication::Planned {
                existing_token_file,
            },
            &current_daemon,
        )?;
        if dry_run || !plan.required_input.is_empty() {
            return Ok(plan);
        }
        if self.requires_first_trust {
            return Err(SatelleError::invalid_usage(
                "first-time SSH setup must trust the discovered Host identity before applying token setup",
            ));
        }
        let ApiTokenSource::File { path } = self
            .binding
            .api_token()
            .expect("setup apply follows a plan with a token-file descriptor");
        let _token_lock = acquire_setup_token_lock(path)?;
        let mut bootstrap_lock = acquire_bootstrap_lock(
            &self.alias,
            self.binding.destination(),
            LockFirstOperationKind::InitialSetup,
        )?;
        confirm_bootstrap_lock(&self.alias, &mut bootstrap_lock)?;
        if plan.service_persistent {
            let locked_current_daemon =
                match self.observe_current_daemon_artifact(existing_token_file) {
                    Ok(observation) => observation,
                    Err(error) => {
                        bootstrap_lock
                            .release_unmodified()
                            .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
                        return Err(error);
                    }
                };
            if locked_current_daemon != current_daemon {
                bootstrap_lock
                    .release_unmodified()
                    .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
                return Err(SatelleError::config_error(
                    format!(
                        "host '{}' changed after setup confirmation; rerun setup to review the current Host version before mutation",
                        self.alias
                    ),
                    None,
                ));
            }
            let required_directories = plan
                .planned_daemon_paths
                .as_ref()
                .expect("persistent setup reports its resolved path set")
                .required_directories();
            let application = self.apply_persistent_setup(
                target,
                &host_config,
                &daemon_path_overrides,
                existing_token_file,
                required_directories,
                &mut bootstrap_lock,
            )?;
            return self.setup_report_for_target(
                false,
                setup_mode,
                target,
                setup_components,
                daemon_path_overrides,
                application,
                &current_daemon,
            );
        }
        // Planning intentionally does not lock or mutate. Re-read only after
        // acquiring both the token-path lock and the remote Host lock so another
        // completed setup is reused and a rollback cannot delete that process's
        // replacement credential.
        let existing_token_file = self.token_file_exists()?;
        let application = if existing_token_file {
            match self.verify_existing_token(&host_config, &mut bootstrap_lock)? {
                ExistingTokenVerification::Reusable => SetupApplication::AppliedReusableToken,
                ExistingTokenVerification::ActivatedPending => {
                    SetupApplication::AppliedPendingActivation
                }
                ExistingTokenVerification::AuthenticationRejected { token_id } => {
                    // The owner-local release handshake stops any daemon that
                    // still owns the canonical store before admin recovery.
                    self.recover_interrupted_token(&token_id, &host_config, &mut bootstrap_lock)?;
                    self.provision_token(&host_config, &mut bootstrap_lock)?;
                    SetupApplication::AppliedNewToken
                }
            }
        } else {
            self.provision_token(&host_config, &mut bootstrap_lock)?;
            SetupApplication::AppliedNewToken
        };
        confirm_bootstrap_lock(&self.alias, &mut bootstrap_lock)?;
        bootstrap_lock
            .release_committed_handoff()
            .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
        self.setup_report_for_target(
            false,
            setup_mode,
            target,
            setup_components,
            daemon_path_overrides,
            application,
            &current_daemon,
        )
    }

    fn doctor(
        &self,
        _scope_selection: &DoctorScopeSelection,
        _transport_probe: Arc<dyn ControllerTransportProbe>,
        _options: DoctorOptions,
        _provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> DoctorExecutionResult {
        Err(DoctorExecutionFailure::from(self.unsupported("doctor")))
    }

    fn verify_setup(
        &self,
        _request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<DoctorReport, SatelleError> {
        // Setup uses this transport only while bootstrapping. Live verification
        // must rebuild the configured Host transport after setup so it cannot
        // depend on the temporary bootstrap daemon or credential.
        Err(SatelleError::state_conflict())
    }

    fn plan_setup_repair(
        &self,
        _run_id: Option<&str>,
        _probes: &[satelle_transport::SetupRepairProbe],
    ) -> Result<RepairLedgerPlan, SatelleError> {
        Err(self.unsupported("setup repair planning"))
    }

    fn invalidate_native_readiness(
        &self,
        _request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<u64, SatelleError> {
        // The caller must rebuild the configured Host transport after setup
        // before invalidating Host-owned readiness state.
        Err(SatelleError::state_conflict())
    }

    fn validate_provider_descriptor(
        &self,
        _model_alias: &str,
        _provider_alias: &str,
        _model_alias_from_project: bool,
        _provider_alias_from_project: bool,
        _mode: satelle_core::ProviderAuthValidationMode,
        _experimental_provider_computer_use: bool,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError> {
        Err(self.unsupported("provider descriptor validation"))
    }

    fn authorize_provider_binding(
        &self,
        _authorization: &satelle_core::ProviderBindingAuthorization,
    ) -> Result<satelle_core::PublicResolvedProviderBinding, SatelleError> {
        Err(self.unsupported("provider binding authorization"))
    }

    fn preview_provider_secret_provisioning(
        &self,
        _metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        _idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningPreviewResponse, SatelleError> {
        Err(self.unsupported("provider secret provisioning preview"))
    }

    fn provision_provider_secret(
        &self,
        _preview: &satelle_transport::ProviderSecretProvisioningPreviewResponse,
        _metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        _secret: Zeroizing<Vec<u8>>,
        _idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningResponse, SatelleError> {
        Err(self.unsupported("provider secret provisioning"))
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        Err(self.unsupported("host status"))
    }

    fn host_paths(
        &self,
    ) -> Result<satelle_core::daemon_service::DaemonResolvedPathSet, SatelleError> {
        Err(self.unsupported("host paths"))
    }

    fn host_sessions(&self, _no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        Err(self.unsupported("host sessions"))
    }

    fn run(
        &self,
        _request: &TurnRequest,
        _detach_on_interrupt: bool,
        _on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        Err(TurnAdmissionFailure::not_admitted(self.unsupported("run")))
    }

    fn run_detached(&self, _request: &TurnRequest) -> Result<PublicSession, SatelleError> {
        Err(self.unsupported("detached run"))
    }

    fn steer(
        &self,
        _session_id: &SessionId,
        _request: &TurnRequest,
        _detach_on_interrupt: bool,
        _on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        Err(TurnAdmissionFailure::not_admitted(
            self.unsupported("steer"),
        ))
    }

    fn steer_detached(
        &self,
        _session_id: &SessionId,
        _request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError> {
        Err(self.unsupported("detached steer"))
    }

    fn status(&self, _session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        Err(self.unsupported("session status"))
    }

    fn task_artifacts(&self, _session_id: &SessionId) -> Result<TaskArtifacts, SatelleError> {
        Err(self.unsupported("task artifact export"))
    }

    fn stop(&self, _session_id: &SessionId) -> Result<StopResult, SatelleError> {
        Err(self.unsupported("session stop"))
    }

    fn logs(&self, _query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        Err(self.unsupported("logs"))
    }
}

impl TransportClient for DirectTransport {
    fn log_target_identity(&self) -> Result<String, SatelleError> {
        Ok(self.host_identity.clone())
    }

    fn supported_image_media_types(&self) -> Result<Vec<String>, SatelleError> {
        Ok(self
            .client
            .capabilities()
            .map_err(|error| direct_transport_error(&self.alias, error))?
            .supported_attachment_media_types()
            .to_vec())
    }

    fn setup(
        &self,
        _dry_run: bool,
        _setup_mode: SetupModeSelection,
        _setup_components: Vec<String>,
        _daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        Err(self.unsupported("setup"))
    }

    fn doctor(
        &self,
        _scope_selection: &DoctorScopeSelection,
        _transport_probe: Arc<dyn ControllerTransportProbe>,
        _options: DoctorOptions,
        _provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> DoctorExecutionResult {
        Err(DoctorExecutionFailure::from(self.unsupported("doctor")))
    }

    fn verify_setup(
        &self,
        request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<DoctorReport, SatelleError> {
        self.client
            .verify_setup(request, &format!("setup-verification-{}", Uuid::now_v7()))
            .map(|response| response.verification().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn plan_setup_repair(
        &self,
        run_id: Option<&str>,
        probes: &[satelle_transport::SetupRepairProbe],
    ) -> Result<RepairLedgerPlan, SatelleError> {
        let response = self
            .client
            .plan_setup_repair(
                &satelle_transport::SetupRepairPlanRequest::new(
                    run_id.map(str::to_string),
                    probes.to_vec(),
                ),
                &format!("setup-repair-plan-{}", Uuid::now_v7()),
            )
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(RepairLedgerPlan {
            available: response.ledger_available(),
            automatic_action_ids: response
                .actions()
                .iter()
                .filter(|action| {
                    action.decision == satelle_transport::SetupRepairDecision::RetryAutomatically
                })
                .map(|action| action.action_id.clone())
                .collect(),
            selected_operation_kind: response.selected_operation_kind(),
            selected_run_status: response.selected_run_status(),
            host_update_recovery_identity: response.host_update_recovery_identity().cloned(),
        })
    }

    fn invalidate_native_readiness(
        &self,
        request: &satelle_transport::SetupVerificationRequest,
    ) -> Result<u64, SatelleError> {
        let invalidation = satelle_transport::NativeReadinessInvalidationRequest::new(
            request.model_alias().map(str::to_owned),
            request.provider_alias().map(str::to_owned),
            request.model_from_project(),
            request.provider_from_project(),
            request.experimental_provider_computer_use(),
        )
        .map_err(SatelleError::invalid_usage)?;
        self.client
            .invalidate_native_readiness(
                &invalidation,
                &format!("native-readiness-invalidation-{}", Uuid::now_v7()),
            )
            .map(|response| response.deleted())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn validate_provider_descriptor(
        &self,
        model_alias: &str,
        provider_alias: &str,
        model_alias_from_project: bool,
        provider_alias_from_project: bool,
        mode: satelle_core::ProviderAuthValidationMode,
        experimental_provider_computer_use: bool,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError> {
        let response = self
            .client
            .validate_provider_descriptor(
                provider_alias,
                model_alias,
                &satelle_transport::ProviderDescriptorValidationRequest::new(
                    mode,
                    model_alias_from_project,
                    provider_alias_from_project,
                )
                .with_experimental_provider_computer_use(experimental_provider_computer_use),
                &format!("provider-validation-{}", Uuid::now_v7()),
            )
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(ProviderDescriptorValidationReport {
            resolved_binding: response.resolved_binding().clone(),
            validation: response.validation(),
        })
    }

    fn authorize_provider_binding(
        &self,
        authorization: &satelle_core::ProviderBindingAuthorization,
    ) -> Result<satelle_core::PublicResolvedProviderBinding, SatelleError> {
        self.client
            .authorize_provider_binding(
                authorization.requested_provider_alias(),
                authorization.requested_model_alias(),
                &satelle_transport::ProviderBindingAuthorizationRequest::new(authorization.clone()),
                &format!("provider-authorization-{}", Uuid::now_v7()),
            )
            .map(|response| response.binding().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn preview_provider_secret_provisioning(
        &self,
        metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningPreviewResponse, SatelleError> {
        self.client
            .preview_provider_secret_provisioning(metadata, idempotency_key)
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn provision_provider_secret(
        &self,
        preview: &satelle_transport::ProviderSecretProvisioningPreviewResponse,
        metadata: &satelle_transport::ProviderSecretProvisioningMetadata,
        secret: Zeroizing<Vec<u8>>,
        idempotency_key: &str,
    ) -> Result<satelle_transport::ProviderSecretProvisioningResponse, SatelleError> {
        self.client
            .provision_provider_secret(preview, metadata, secret, idempotency_key)
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        let response = self
            .client
            .host_status()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(HostStatus {
            running: true,
            mode: self.mode.to_string(),
            sessions: response.session_count(),
        })
    }

    fn host_paths(
        &self,
    ) -> Result<satelle_core::daemon_service::DaemonResolvedPathSet, SatelleError> {
        self.client
            .host_paths()
            .map(|response| response.paths().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn host_sessions(&self, _no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        // The desktop-session envelope intentionally excludes the daemon version.
        // Read the canonical capabilities envelope instead of reporting the CLI version.
        let bootstrapped = self._bootstrap.is_some();
        let capabilities = self
            .client
            .capabilities()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        let desktop_sessions = self
            .client
            .desktop_sessions()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(HostSessionsReport {
            schema_version: HostSessionsSchemaVersion::V1,
            host: self.alias.clone(),
            detected_platform: capabilities.platform().to_string(),
            connection_mode: self.mode.to_string(),
            bootstrapped,
            bootstrap_actions: if bootstrapped {
                vec!["start_on_demand".to_string()]
            } else {
                Vec::new()
            },
            host_daemon_version: capabilities.daemon_version().to_string(),
            sessions: desktop_sessions.sessions().to_vec(),
        })
    }

    fn run(
        &self,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        self.event_runtime
            .block_on(self.run_attached(request, detach_on_interrupt, on_event))
    }

    fn run_detached(&self, request: &TurnRequest) -> Result<PublicSession, SatelleError> {
        self.client
            .create_session(request, &Self::idempotency_key())
            .map(|response| response.session().clone())
            .map_err(|error| self.run_transport_error(error))
    }

    fn steer(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        self.event_runtime.block_on(self.steer_attached(
            session_id,
            request,
            detach_on_interrupt,
            on_event,
        ))
    }

    fn steer_detached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
    ) -> Result<PublicSession, SatelleError> {
        self.client
            .create_turn(session_id, request, &Self::idempotency_key())
            .map(|response| response.session().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.client
            .read_session(session_id)
            .map(|response| response.session().clone())
            .map_err(|error| direct_session_resource_error(&self.alias, session_id, error))
    }

    fn task_artifacts(&self, session_id: &SessionId) -> Result<TaskArtifacts, SatelleError> {
        self.client
            .read_task_artifacts(session_id)
            .map(TaskArtifacts::from_response)
            .map_err(|error| direct_session_resource_error(&self.alias, session_id, error))
    }

    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.client
            .stop_session(session_id, &Self::idempotency_key())
            .map(|response| response.result().clone())
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        self.client
            .logs(query)
            .map(|response| response.page().clone())
            .map_err(|error| direct_logs_error(&self.alias, error))
    }
}

fn direct_transport(host: &SelectedHost) -> Result<DirectTransport, SatelleError> {
    let binding = DirectHostBinding::from_host_config(&host.config)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ApiTokenSource::File { path } = binding.api_token();
    let raw_token = read_owner_only_secret_file(path)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let http_token = ApiBearerToken::parse(raw_token.as_str())
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let event_token = ApiBearerToken::parse(raw_token.as_str())
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ca_bundle = binding
        .ca_bundle()
        .map(read_trusted_ca_bundle_file)
        .transpose()
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ca_bundle = ca_bundle.as_deref().map(str::as_bytes);
    let client = Arc::new(
        DaemonClient::https(&binding, http_token, ca_bundle)
            .map_err(|error| direct_transport_error(&host.alias, error))?
            .with_admission_timeout(admission_request_timeout(&host.config)),
    );
    let event_client = DaemonEventClient::wss(&binding, event_token, ca_bundle)
        .map_err(|error| direct_event_error(&host.alias, error))?;
    let event_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    Ok(DirectTransport {
        alias: host.alias.clone(),
        mode: "direct",
        host_identity: binding.expected_host_identity().to_string(),
        client,
        event_client,
        event_runtime,
        _tunnel: None,
        _bootstrap: None,
    })
}

fn ssh_transport(
    host: &SelectedHost,
    launch_policy: SshDaemonLaunchPolicy,
) -> Result<DirectTransport, SatelleError> {
    let admission_timeout = admission_request_timeout(&host.config);
    let bootstrap_scope = launch_policy.bootstrap_scope();
    let binding = if bootstrap_scope.is_some() {
        SshHostBinding::from_host_config_for_bootstrap(&host.config)
    } else {
        SshHostBinding::from_host_config(&host.config)
    }
    .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let durable_tokens = match binding.api_token() {
        Some(ApiTokenSource::File { path }) => {
            let raw_token = read_owner_only_secret_file(path)
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            let http_token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            let event_token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            let fallback_http_token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            let fallback_event_token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
            Some((
                http_token,
                event_token,
                fallback_http_token,
                fallback_event_token,
            ))
        }
        None => None,
    };
    let tunnel = SshTunnel::open(binding.destination()).map_err(|error| match error {
        ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
            SatelleError::ssh_host_key_verification_required(&host.alias)
        }
        _ => SatelleError::host_unreachable(&host.alias),
    })?;
    let expected_host_identity = binding.expected_host_identity().to_string();
    let (client, event_client, bootstrap) = match durable_tokens {
        Some((http_token, event_token, fallback_http_token, fallback_event_token)) => {
            let durable_client = Arc::new(
                DaemonClient::loopback_with_timeout(
                    tunnel.local_addr(),
                    http_token,
                    &expected_host_identity,
                    SSH_DAEMON_REQUEST_TIMEOUT,
                )
                .map_err(|error| direct_transport_error(&host.alias, error))?
                .with_admission_timeout(admission_timeout),
            );
            match durable_client.capabilities() {
                Ok(_) => {
                    let event_client = DaemonEventClient::loopback(
                        tunnel.local_addr(),
                        event_token,
                        expected_host_identity.clone(),
                    )
                    .map_err(|error| direct_event_error(&host.alias, error))?;
                    (durable_client, event_client, None)
                }
                Err(DaemonClientError::Transport(error)) => {
                    // Ordinary commands may relaunch with the already-persisted credential,
                    // but the explicit no-bootstrap policy forbids every remote daemon launch.
                    if !launch_policy.allows_durable_relaunch() {
                        return Err(direct_transport_error(
                            &host.alias,
                            DaemonClientError::Transport(error),
                        ));
                    }
                    let (client, event_client) = durable_ssh_clients(
                        &host.alias,
                        binding.destination(),
                        tunnel.local_addr(),
                        &expected_host_identity,
                        admission_timeout,
                        &host.config,
                        (fallback_http_token, fallback_event_token),
                    )?;
                    (client, event_client, None)
                }
                Err(error) => return Err(direct_transport_error(&host.alias, error)),
            }
        }
        None => {
            let Some(bootstrap_scope) = bootstrap_scope else {
                return Err(SatelleError::host_daemon_unreachable(&host.alias));
            };
            let (client, event_client, bootstrap) = bootstrap_ssh_clients(
                &host.alias,
                binding.destination(),
                tunnel.local_addr(),
                &expected_host_identity,
                admission_timeout,
                &host.config,
                bootstrap_scope,
            )?;
            (client, event_client, Some(bootstrap))
        }
    };
    let event_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    Ok(DirectTransport {
        alias: host.alias.clone(),
        mode: "ssh",
        host_identity: expected_host_identity,
        client,
        event_client,
        event_runtime,
        _tunnel: Some(tunnel),
        _bootstrap: bootstrap,
    })
}

fn durable_ssh_clients(
    alias: &str,
    destination: &str,
    tunnel_addr: std::net::SocketAddr,
    expected_host_identity: &str,
    admission_timeout: Duration,
    host_config: &satelle_core::HostConfig,
    tokens: (ApiBearerToken, ApiBearerToken),
) -> Result<(Arc<DaemonClient>, DaemonEventClient), SatelleError> {
    let (http_token, event_token) = tokens;
    let client = Arc::new(
        DaemonClient::loopback_with_timeout(
            tunnel_addr,
            http_token,
            expected_host_identity,
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(alias, error))?
        .with_admission_timeout(admission_timeout),
    );
    let mut bootstrap_lock = acquire_bootstrap_lock(
        alias,
        destination,
        LockFirstOperationKind::MissingDaemonRepair,
    )?;
    match probe_durable_daemon_under_lock(
        alias,
        || confirm_bootstrap_lock(alias, &mut bootstrap_lock),
        || observe_remote_durable_readiness(client.capabilities()),
    )? {
        DurableDaemonProbe::Ready(readiness) => {
            require_exact_durable_readiness(alias, expected_host_identity, &readiness)?;
            bootstrap_lock
                .release_unmodified()
                .map_err(|_| SatelleError::host_unreachable(alias))?;
        }
        DurableDaemonProbe::Missing => {
            let bootstrap_token =
                ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(alias))?;
            let raw_bootstrap_token = bootstrap_token.expose();
            SshBootstrapProcess::launch_durable(
                destination,
                &bootstrap_token,
                on_demand_idle_timeout(host_config),
                host_config,
                &mut bootstrap_lock,
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
            let bootstrap_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
                .map_err(|_| SatelleError::host_unreachable(alias))?;
            let bootstrap_client = DaemonClient::loopback_with_timeout(
                tunnel_addr,
                bootstrap_token,
                expected_host_identity,
                SSH_DAEMON_REQUEST_TIMEOUT,
            )
            .map_err(|error| direct_transport_error(alias, error))?;
            finish_durable_daemon_launch(
                alias,
                expected_host_identity,
                &client,
                &bootstrap_client,
                &mut bootstrap_lock,
            )?;
        }
    }
    let event_client =
        DaemonEventClient::loopback(tunnel_addr, event_token, expected_host_identity)
            .map_err(|error| direct_event_error(alias, error))?;
    Ok((client, event_client))
}

fn finish_durable_daemon_launch(
    alias: &str,
    expected_host_identity: &str,
    durable_client: &DaemonClient,
    bootstrap_client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    // The daemon was launched with the operation-bound bootstrap credential.
    // Prove that exact authority and Host identity before committing daemon_start;
    // a stale durable credential cannot safely prove the launch it did not own.
    wait_for_durable_daemon(alias, || bootstrap_client.capabilities())?;
    commit_verified_bootstrap_mutation(alias, bootstrap_lock)?;
    complete_bootstrap_handoff(alias, bootstrap_client, bootstrap_lock)?;
    bootstrap_lock
        .release_committed_handoff()
        .map_err(|_| SatelleError::host_unreachable(alias))?;

    // Only after the launch and maintenance handoff are terminal do we surface
    // the durable credential's independent authentication or scope result.
    authenticate_durable_with_confirmation(
        alias,
        expected_host_identity,
        || Ok(()),
        || observe_remote_durable_readiness(durable_client.capabilities()),
        Instant::now() + SSH_DAEMON_LAUNCH_TIMEOUT,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableReadinessSnapshot {
    daemon_version: String,
    host_identity: String,
}

trait DurableReadiness {
    fn daemon_version(&self) -> &str;
    fn host_identity(&self) -> &str;
}

impl DurableReadiness for satelle_transport::CapabilitiesResponse {
    fn daemon_version(&self) -> &str {
        self.daemon_version()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }
}

impl DurableReadiness for DurableReadinessSnapshot {
    fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

enum DurableReadinessObservation {
    Ready(DurableReadinessSnapshot),
    ConnectFailure,
    Failure(DaemonClientError),
}

fn observe_remote_durable_readiness<T: DurableReadiness>(
    readiness: Result<T, DaemonClientError>,
) -> DurableReadinessObservation {
    match readiness {
        Ok(capabilities) => DurableReadinessObservation::Ready(DurableReadinessSnapshot {
            daemon_version: capabilities.daemon_version().to_string(),
            host_identity: capabilities.host_identity().to_string(),
        }),
        Err(DaemonClientError::Transport(error)) if error.is_connect() => {
            DurableReadinessObservation::ConnectFailure
        }
        Err(error) => DurableReadinessObservation::Failure(error),
    }
}

enum DurableDaemonProbe {
    Ready(DurableReadinessSnapshot),
    Missing,
}

fn probe_durable_daemon_under_lock(
    host: &str,
    mut confirm_lock_ownership: impl FnMut() -> Result<(), SatelleError>,
    readiness: impl FnOnce() -> DurableReadinessObservation,
) -> Result<DurableDaemonProbe, SatelleError> {
    confirm_lock_ownership()?;
    let readiness = readiness();
    confirm_lock_ownership()?;
    match readiness {
        DurableReadinessObservation::Ready(readiness) => Ok(DurableDaemonProbe::Ready(readiness)),
        DurableReadinessObservation::ConnectFailure => Ok(DurableDaemonProbe::Missing),
        DurableReadinessObservation::Failure(error) => Err(direct_transport_error(host, error)),
    }
}

fn require_exact_durable_readiness(
    host: &str,
    expected_host_identity: &str,
    readiness: &DurableReadinessSnapshot,
) -> Result<(), SatelleError> {
    if readiness.daemon_version != env!("CARGO_PKG_VERSION") {
        return Err(SatelleError::remote_api_error(
            host,
            "unexpected-durable-daemon-version",
        ));
    }
    if readiness.host_identity != expected_host_identity {
        return Err(SatelleError::host_identity_mismatch(host));
    }
    Ok(())
}

fn authenticate_durable_with_confirmation(
    host: &str,
    expected_host_identity: &str,
    mut confirm_lock_ownership: impl FnMut() -> Result<(), SatelleError>,
    mut readiness: impl FnMut() -> DurableReadinessObservation,
    deadline: Instant,
) -> Result<(), SatelleError> {
    loop {
        confirm_lock_ownership()?;
        let observation = readiness();
        confirm_lock_ownership()?;
        match observation {
            DurableReadinessObservation::Ready(readiness) => {
                return require_exact_durable_readiness(host, expected_host_identity, &readiness);
            }
            DurableReadinessObservation::Failure(error) => {
                return Err(direct_transport_error(host, error));
            }
            DurableReadinessObservation::ConnectFailure => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(SatelleError::host_unreachable(host));
                }
                std::thread::sleep(SSH_DAEMON_LAUNCH_POLL_INTERVAL.min(deadline - now));
            }
        }
    }
}

#[derive(Clone, Copy)]
struct DurableRelaunchTarget<'a> {
    host: &'a str,
    expected_host_identity: &'a str,
}

fn relaunch_durable_daemon_under_lock<C>(
    target: DurableRelaunchTarget<'_>,
    context: &mut C,
    mut confirm_lock_ownership: impl FnMut(&mut C) -> Result<(), SatelleError>,
    initial_readiness: impl FnOnce() -> DurableReadinessObservation,
    launch: impl FnOnce(&mut C) -> Result<(), SatelleError>,
    final_readiness: impl FnMut() -> DurableReadinessObservation,
    deadline: Instant,
) -> Result<bool, SatelleError> {
    match probe_durable_daemon_under_lock(
        target.host,
        || confirm_lock_ownership(context),
        initial_readiness,
    )? {
        DurableDaemonProbe::Ready(readiness) => {
            require_exact_durable_readiness(
                target.host,
                target.expected_host_identity,
                &readiness,
            )?;
            Ok(false)
        }
        DurableDaemonProbe::Missing => {
            launch(context)?;
            authenticate_durable_with_confirmation(
                target.host,
                target.expected_host_identity,
                || confirm_lock_ownership(context),
                final_readiness,
                deadline,
            )?;
            Ok(true)
        }
    }
}

fn confirm_bootstrap_lock(
    host: &str,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    bootstrap_lock
        .confirm_ownership()
        .map_err(|_| SatelleError::host_unreachable(host))
}

fn commit_verified_bootstrap_mutation(
    host: &str,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    bootstrap_lock
        .commit_current_mutation()
        .map_err(|_| SatelleError::host_unreachable(host))
}

fn bootstrap_maintenance_rejection_precedes_mutation(error: &DaemonClientError) -> bool {
    let DaemonClientError::Api { status, error } = error else {
        return false;
    };
    matches!(
        (status.as_u16(), error.code()),
        (401, ApiErrorCode::AuthenticationFailed)
            | (403, ApiErrorCode::AuthorizationInsufficientScope)
            | (409, ApiErrorCode::HostIdentityMismatch)
            | (400 | 408, ApiErrorCode::InvalidRequest)
            | (413, ApiErrorCode::PayloadTooLarge)
            | (426, ApiErrorCode::IncompatibleProtocol)
            | (429, ApiErrorCode::RateLimited)
            | (409, ApiErrorCode::StateConflict)
            | (503, ApiErrorCode::CapacityExceeded)
    )
}

fn reconcile_bootstrap_maintenance_response<T>(
    host: &str,
    response: Result<T, DaemonClientError>,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<T, SatelleError> {
    match response {
        Ok(response) => Ok(response),
        Err(error) => {
            // These exact status/code pairs are emitted only before the
            // maintenance handler reaches its ledger mutation. Commit the
            // known nonmutation outcome so lock recovery can close this exact
            // attempt. Every transport, response, and handler error remains
            // uncommitted because its mutation outcome is not proven.
            if bootstrap_maintenance_rejection_precedes_mutation(&error) {
                commit_verified_bootstrap_mutation(host, bootstrap_lock)?;
            }
            Err(direct_transport_error(host, error))
        }
    }
}

fn complete_bootstrap_handoff(
    host: &str,
    client: &DaemonClient,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<(), SatelleError> {
    bootstrap_lock
        .mark_mutation_started("maintenance_handoff_begin")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let begun = reconcile_bootstrap_maintenance_response(
        host,
        client.begin_bootstrap_maintenance(
            bootstrap_lock.operation_id(),
            bootstrap_lock.operation_kind().as_str(),
        ),
        bootstrap_lock,
    )?;
    if !begun.reconciled() || begun.operation_id() != bootstrap_lock.operation_id() {
        return Err(SatelleError::remote_api_error(
            host,
            "invalid-bootstrap-maintenance-handoff",
        ));
    }
    bootstrap_lock
        .commit_current_mutation()
        .map_err(|_| SatelleError::host_unreachable(host))?;
    bootstrap_lock
        .mark_mutation_started("maintenance_handoff_complete")
        .map_err(|_| SatelleError::host_unreachable(host))?;
    let handoff = reconcile_bootstrap_maintenance_response(
        host,
        client.complete_bootstrap_maintenance(bootstrap_lock.operation_id()),
        bootstrap_lock,
    )?;
    if !handoff.reconciled() || handoff.operation_id() != bootstrap_lock.operation_id() {
        return Err(SatelleError::remote_api_error(
            host,
            "invalid-bootstrap-maintenance-handoff",
        ));
    }
    bootstrap_lock
        .commit_current_mutation()
        .map_err(|_| SatelleError::host_unreachable(host))?;
    confirm_bootstrap_lock(host, bootstrap_lock)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LockFirstOperationKind {
    InitialSetup,
    MissingDaemonRepair,
}

impl LockFirstOperationKind {
    const fn operation_kind(self) -> bootstrap_lock::OperationKind {
        match self {
            Self::InitialSetup => bootstrap_lock::OperationKind::InitialSetup,
            Self::MissingDaemonRepair => bootstrap_lock::OperationKind::MissingDaemonRepair,
        }
    }
}

fn acquire_bootstrap_lock(
    alias: &str,
    destination: &str,
    operation_kind: LockFirstOperationKind,
) -> Result<ssh_bootstrap::SshBootstrapLock, SatelleError> {
    let operation_id = Uuid::now_v7().hyphenated().to_string();
    acquire_bootstrap_lock_for_operation(
        alias,
        destination,
        operation_id,
        operation_kind.operation_kind(),
    )
}

fn acquire_bootstrap_lock_for_operation(
    alias: &str,
    destination: &str,
    operation_id: String,
    operation_kind: bootstrap_lock::OperationKind,
) -> Result<ssh_bootstrap::SshBootstrapLock, SatelleError> {
    let controller_identity = Some(format!("controller-pid-{}", std::process::id()));
    let request = bootstrap_lock::Request::new(operation_id, operation_kind, controller_identity)
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
    ssh_bootstrap::SshBootstrapLock::acquire(destination, request).map_err(|error| match error {
        ssh_bootstrap::SshBootstrapError::HostKeyVerificationRequired => {
            SatelleError::ssh_host_key_verification_required(alias)
        }
        ssh_bootstrap::SshBootstrapError::BootstrapBusy => {
            SatelleError::bootstrap_busy(alias, None)
        }
        _ => SatelleError::host_unreachable(alias),
    })
}

fn bootstrap_ssh_clients(
    alias: &str,
    destination: &str,
    tunnel_addr: std::net::SocketAddr,
    expected_host_identity: &str,
    admission_timeout: Duration,
    host_config: &satelle_core::HostConfig,
    bootstrap_scope: SshBootstrapScope,
) -> Result<(Arc<DaemonClient>, DaemonEventClient, SshBootstrapProcess), SatelleError> {
    let mut bootstrap_lock = acquire_bootstrap_lock(
        alias,
        destination,
        LockFirstOperationKind::MissingDaemonRepair,
    )?;
    confirm_bootstrap_lock(alias, &mut bootstrap_lock)?;
    let bootstrap_token =
        ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(alias))?;
    let raw_bootstrap_token = bootstrap_token.expose();
    let bootstrap = SshBootstrapProcess::launch(
        destination,
        &bootstrap_token,
        host_config,
        bootstrap_scope,
        &mut bootstrap_lock,
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
    let http_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let event_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let client = Arc::new(
        DaemonClient::loopback_with_timeout(
            tunnel_addr,
            http_token,
            expected_host_identity,
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(alias, error))?
        .with_admission_timeout(admission_timeout),
    );
    client
        .capabilities()
        .map_err(|error| direct_transport_error(alias, error))?;
    commit_verified_bootstrap_mutation(alias, &mut bootstrap_lock)?;
    complete_bootstrap_handoff(alias, &client, &mut bootstrap_lock)?;
    bootstrap_lock
        .release_committed_handoff()
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let event_client =
        DaemonEventClient::loopback(tunnel_addr, event_token, expected_host_identity)
            .map_err(|error| direct_event_error(alias, error))?;
    Ok((client, event_client, bootstrap))
}

fn setup_bootstrap_client(
    alias: &str,
    destination: &str,
    expected_host_identity: &str,
    previous_host_config: &satelle_core::HostConfig,
    host_config: &satelle_core::HostConfig,
    bootstrap_scope: SshBootstrapScope,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<
    (
        Arc<DaemonClient>,
        SshTunnel,
        SshBootstrapProcess,
        ApiBearerToken,
    ),
    SatelleError,
> {
    let bootstrap_token =
        ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(alias))?;
    let raw_bootstrap_token = bootstrap_token.expose();
    // Setup administration is isolated from the durable daemon. Binding the
    // foreground bootstrap to an ephemeral remote port lets recovery proceed
    // even when port 3001 is occupied by a daemon rejecting the durable token.
    let bootstrap = SshBootstrapProcess::launch_ephemeral(
        destination,
        &bootstrap_token,
        host_config,
        previous_host_config,
        bootstrap_scope,
        bootstrap_lock,
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
    // launch_ephemeral returns only after the fenced process publishes and
    // validates its ready address. Commit that verified daemon_start before
    // tunnel/client/token work creates a new Controller-loss window.
    commit_verified_bootstrap_mutation(alias, bootstrap_lock)?;
    let tunnel =
        SshTunnel::open_to(destination, bootstrap.remote_port()).map_err(|error| match error {
            ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(alias)
            }
            _ => SatelleError::host_unreachable(alias),
        })?;
    let http_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let handoff_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let client = Arc::new(
        DaemonClient::loopback_with_timeout(
            tunnel.local_addr(),
            http_token,
            expected_host_identity,
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(alias, error))?
        .with_admission_timeout(admission_request_timeout(previous_host_config)),
    );
    Ok((client, tunnel, bootstrap, handoff_token))
}

fn setup_fresh_bootstrap_client(
    alias: &str,
    destination: &str,
    previous_host_config: &satelle_core::HostConfig,
    host_config: &satelle_core::HostConfig,
    identity_commit: ssh_bootstrap::InitialHostIdentityCommit<'_>,
    remote_binary: &str,
    bootstrap_lock: &mut ssh_bootstrap::SshBootstrapLock,
) -> Result<
    (
        Arc<DaemonClient>,
        SshTunnel,
        SshBootstrapProcess,
        HostSessionsReport,
    ),
    SatelleError,
> {
    let bootstrap_token =
        ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(alias))?;
    let raw_bootstrap_token = bootstrap_token.expose();
    let bootstrap = SshBootstrapProcess::launch_fresh(
        destination,
        &bootstrap_token,
        host_config,
        SshBootstrapScope::Admin,
        identity_commit,
        remote_binary,
        bootstrap_lock,
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
    commit_verified_bootstrap_mutation(alias, bootstrap_lock)?;
    let tunnel =
        SshTunnel::open_to(destination, bootstrap.remote_port()).map_err(|error| match error {
            ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(alias)
            }
            _ => SatelleError::host_unreachable(alias),
        })?;
    let token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
        .map_err(|_| SatelleError::host_unreachable(alias))?;
    let client = Arc::new(
        DaemonClient::loopback_with_timeout(
            tunnel.local_addr(),
            token,
            identity_commit.host_identity.as_str(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(alias, error))?
        .with_admission_timeout(admission_request_timeout(previous_host_config)),
    );
    client
        .capabilities()
        .map_err(|error| direct_transport_error(alias, error))
        .and_then(|capabilities| {
            client
                .desktop_sessions()
                .map_err(|error| direct_transport_error(alias, error))
                .map(|desktop_sessions| HostSessionsReport {
                    schema_version: HostSessionsSchemaVersion::V1,
                    host: alias.to_string(),
                    detected_platform: capabilities.platform().to_string(),
                    connection_mode: "ssh-bootstrap".to_string(),
                    bootstrapped: true,
                    bootstrap_actions: vec![
                        "committed the accepted Host Identity and started an authenticated temporary Host Daemon"
                            .to_string(),
                    ],
                    host_daemon_version: capabilities.daemon_version().to_string(),
                    sessions: desktop_sessions.sessions().to_vec(),
                })
        })
        .map(|sessions| (client, tunnel, bootstrap, sessions))
}

#[cfg(all(test, unix))]
fn discovered_bootstrap_client(
    alias: &str,
    tunnel_addr: std::net::SocketAddr,
    bootstrap_token: ApiBearerToken,
    discovered_host_identity: &str,
) -> Result<DaemonClient, SatelleError> {
    // Identity discovery intentionally starts with a false probe pin. Rebuild
    // the client with the authenticated identity learned from that mismatch;
    // reusing the probe client would make the maintenance response fail its
    // Host identity contract.
    DaemonClient::loopback_with_timeout(
        tunnel_addr,
        bootstrap_token,
        discovered_host_identity,
        SSH_DAEMON_REQUEST_TIMEOUT,
    )
    .map_err(|error| direct_transport_error(alias, error))
}

fn direct_event_error(host: &str, error: DaemonEventError) -> SatelleError {
    match error {
        DaemonEventError::Handshake { error, .. } => api_code_error(host, error.code()),
        DaemonEventError::HostIdentityMismatch => SatelleError::host_identity_mismatch(host),
        DaemonEventError::CertificateUntrusted(_) => SatelleError::certificate_untrusted(host),
        DaemonEventError::CertificateHostnameMismatch(_) => {
            SatelleError::certificate_hostname_mismatch(host)
        }
        DaemonEventError::CertificateExpired(_) => SatelleError::certificate_expired(host),
        DaemonEventError::TlsVersionUnsupported(_) => SatelleError::tls_version_unsupported(host),
        DaemonEventError::TlsHandshake(_) => SatelleError::tls_handshake_failed(host),
        DaemonEventError::InvalidHeader
        | DaemonEventError::InvalidCaBundle
        | DaemonEventError::EmptyCaBundle
        | DaemonEventError::TlsConfiguration(_) => {
            SatelleError::config_error(error.to_string(), None)
        }
        DaemonEventError::Closed {
            control: Some(control),
            ..
        } => api_code_error(host, control.code()),
        DaemonEventError::HandshakeTimeout
        | DaemonEventError::StreamIdleTimeout
        | DaemonEventError::AdmissionEventBufferOverflow
        | DaemonEventError::Connect(_)
        | DaemonEventError::Transport(_)
        | DaemonEventError::Closed { control: None, .. }
        | DaemonEventError::Disconnected => SatelleError::host_unreachable(host),
        DaemonEventError::NonLoopbackPlaintextEndpoint
        | DaemonEventError::InvalidSubscriptions
        | DaemonEventError::InvalidHandshakeResponse
        | DaemonEventError::Encode(_)
        | DaemonEventError::InvalidControl(_)
        | DaemonEventError::InvalidEvent(_)
        | DaemonEventError::ControlWithoutClose(_)
        | DaemonEventError::CloseContractMismatch { .. }
        | DaemonEventError::RequestIdMismatch
        | DaemonEventError::SubscriptionMismatch
        | DaemonEventError::SequenceDidNotAdvance
        | DaemonEventError::UnexpectedFrame => {
            SatelleError::remote_api_error(host, "invalid-daemon-response")
        }
    }
}

// A direct run requires its daemon to be reachable before admission begins.
// Keep this context-specific so steer and post-admission stream loss retain
// the broader host-unreachable contract.
fn direct_run_event_error(host: &str, error: DaemonEventError) -> SatelleError {
    // A typed server control remains authoritative even when its close reason
    // also describes a recoverable connection loss, such as a slow consumer.
    if matches!(
        &error,
        DaemonEventError::Closed {
            control: Some(_),
            ..
        }
    ) {
        return direct_event_error(host, error);
    }
    if error.is_recoverable_disconnect() {
        SatelleError::direct_daemon_unreachable(host)
    } else {
        direct_event_error(host, error)
    }
}

fn direct_transport_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Api { error, .. } => map_api_error(host, &error),
        DaemonClientError::ResponseHostIdentityMismatch => {
            SatelleError::host_identity_mismatch(host)
        }
        DaemonClientError::CertificateUntrusted(_) => SatelleError::certificate_untrusted(host),
        DaemonClientError::CertificateHostnameMismatch(_) => {
            SatelleError::certificate_hostname_mismatch(host)
        }
        DaemonClientError::CertificateExpired(_) => SatelleError::certificate_expired(host),
        DaemonClientError::TlsVersionUnsupported(_) => SatelleError::tls_version_unsupported(host),
        DaemonClientError::TlsHandshake(_) => SatelleError::tls_handshake_failed(host),
        DaemonClientError::ProtocolResponseMismatch => {
            api_code_error(host, ApiErrorCode::IncompatibleProtocol)
        }
        DaemonClientError::Transport(_) => SatelleError::host_unreachable(host),
        DaemonClientError::InvalidHostIdentityHeader
        | DaemonClientError::InvalidProviderBindingAlias
        | DaemonClientError::InvalidCaBundle(_)
        | DaemonClientError::EmptyCaBundle => SatelleError::config_error(error.to_string(), None),
        DaemonClientError::NonLoopbackPlaintextEndpoint
        | DaemonClientError::InvalidTokenHeader
        | DaemonClientError::InvalidIdempotencyKeyHeader
        | DaemonClientError::InvalidResponse(_)
        | DaemonClientError::UnexpectedSuccessStatus { .. }
        | DaemonClientError::ResponseRequestIdMismatch
        | DaemonClientError::ResponseContractViolation => {
            SatelleError::remote_api_error(host, "invalid-daemon-response")
        }
    }
}

fn direct_session_resource_error(
    host: &str,
    session_id: &SessionId,
    error: DaemonClientError,
) -> SatelleError {
    if matches!(
        &error,
        DaemonClientError::Api { error, .. } if error.code() == ApiErrorCode::SessionNotFound
    ) {
        SatelleError::session_not_found(session_id)
    } else {
        direct_transport_error(host, error)
    }
}

fn direct_run_transport_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Transport(error) if error.is_connect() => {
            SatelleError::direct_daemon_unreachable(host)
        }
        error => direct_transport_error(host, error),
    }
}

fn direct_logs_error(host: &str, error: DaemonClientError) -> SatelleError {
    match error {
        DaemonClientError::Api { error, .. } if error.code() == ApiErrorCode::InvalidRequest => {
            SatelleError::invalid_usage("the Host rejected the logs query")
        }
        error => direct_transport_error(host, error),
    }
}

// Cursor expiry is the one API failure whose details are required to resume
// safely. Validate that recovery boundary at the transport boundary instead
// of collapsing it into the generic remote API error used for other codes.
fn map_api_error(host: &str, error: &ApiError) -> SatelleError {
    if error.code() == ApiErrorCode::StopNotConfirmed {
        return map_stop_not_confirmed_api_error(host, error);
    }
    if matches!(
        error.code(),
        ApiErrorCode::DesktopBindingRequired
            | ApiErrorCode::DesktopSessionUnavailable
            | ApiErrorCode::DesktopSessionAmbiguous
            | ApiErrorCode::DesktopSessionPreferenceUnmatched
            | ApiErrorCode::DesktopSessionConsoleUnavailable
            | ApiErrorCode::DesktopSessionNativeSelectorWrongPlatform
            | ApiErrorCode::DesktopSessionNativeSelectorUnmatched
    ) {
        return map_desktop_selection_api_error(host, error);
    }
    if error.code() != ApiErrorCode::LogsCursorExpired {
        return api_code_error(host, error.code());
    }

    let Some(details) = error.details().and_then(serde_json::Value::as_object) else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    let earliest_available_cursor = match details.get("earliest_available_cursor") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(cursor)) => match LogCursor::parse(cursor) {
            Ok(cursor) => Some(cursor),
            Err(_) => return SatelleError::remote_api_error(host, "invalid-daemon-response"),
        },
        _ => return SatelleError::remote_api_error(host, "invalid-daemon-response"),
    };
    let Some(resume_cursor) = details
        .get("resume_cursor")
        .and_then(serde_json::Value::as_str)
        .and_then(|cursor| LogCursor::parse(cursor).ok())
    else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    if earliest_available_cursor.is_some_and(|earliest| earliest <= resume_cursor) {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    }

    SatelleError::logs_cursor_expired(
        earliest_available_cursor.map(|cursor| cursor.to_string()),
        resume_cursor.to_string(),
    )
}

fn map_desktop_selection_api_error(host: &str, error: &ApiError) -> SatelleError {
    let invalid = || SatelleError::remote_api_error(host, "invalid-daemon-response");
    let details = match error.details() {
        Some(details) => match details.as_object() {
            Some(details) => details,
            None => return invalid(),
        },
        None if error.code() == ApiErrorCode::DesktopSessionUnavailable => {
            return SatelleError::desktop_session_unavailable(None);
        }
        None => return invalid(),
    };
    let exact_string = |key: &str, expected_len: usize| {
        (details.len() == expected_len)
            .then(|| details.get(key)?.as_str())
            .flatten()
            .filter(|value| !value.is_empty())
    };

    match error.code() {
        ApiErrorCode::DesktopBindingRequired => {
            if details.len() != 1 {
                return invalid();
            }
            let Some(users) = details
                .get("candidate_desktop_users")
                .and_then(serde_json::Value::as_array)
            else {
                return invalid();
            };
            let users = users
                .iter()
                .map(|user| user.as_str().filter(|user| !user.is_empty()))
                .collect::<Option<BTreeSet<_>>>();
            match users {
                Some(users) if users.len() >= 2 => SatelleError::desktop_binding_required(&users),
                _ => invalid(),
            }
        }
        ApiErrorCode::DesktopSessionUnavailable if details.is_empty() => {
            SatelleError::desktop_session_unavailable(None)
        }
        ApiErrorCode::DesktopSessionUnavailable => exact_string("desktop_user", 1)
            .map(|user| SatelleError::desktop_session_unavailable(Some(user)))
            .unwrap_or_else(invalid),
        ApiErrorCode::DesktopSessionAmbiguous => exact_string("desktop_user", 1)
            .map(SatelleError::desktop_session_ambiguous)
            .unwrap_or_else(invalid),
        ApiErrorCode::DesktopSessionPreferenceUnmatched => {
            if details.len() != 2 {
                return invalid();
            }
            match (
                details
                    .get("desktop_user")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty()),
                details
                    .get("desktop_session_preference")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| matches!(*value, "only" | "console")),
            ) {
                (Some(user), Some(preference)) => {
                    SatelleError::desktop_session_preference_unmatched(user, preference)
                }
                _ => invalid(),
            }
        }
        ApiErrorCode::DesktopSessionConsoleUnavailable => {
            if details.len() != 2
                || details
                    .get("desktop_session_preference")
                    .and_then(serde_json::Value::as_str)
                    != Some("console")
            {
                return invalid();
            }
            details
                .get("desktop_user")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(SatelleError::desktop_session_console_unavailable)
                .unwrap_or_else(invalid)
        }
        ApiErrorCode::DesktopSessionNativeSelectorWrongPlatform => {
            if details.len() != 2 {
                return invalid();
            }
            match (
                details
                    .get("configured_platform")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty()),
                details
                    .get("detected_platform")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty()),
            ) {
                (Some(configured), Some(detected)) => {
                    SatelleError::desktop_session_native_selector_wrong_platform(
                        configured, detected,
                    )
                }
                _ => invalid(),
            }
        }
        ApiErrorCode::DesktopSessionNativeSelectorUnmatched => {
            exact_string("desktop_session_native_selector", 1)
                .map(SatelleError::desktop_session_native_selector_unmatched)
                .unwrap_or_else(invalid)
        }
        _ => invalid(),
    }
}

fn map_stop_not_confirmed_api_error(host: &str, error: &ApiError) -> SatelleError {
    let Some(details) = error.details().and_then(serde_json::Value::as_object) else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    if details.len() != 7 {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    }
    let Some(session_id) = details
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| SessionId::parse(value).ok())
    else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    let Some(_turn_id) = details
        .get("turn_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| TurnId::parse(value).ok())
    else {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    };
    if !matches!(
        details.get("ownership").and_then(serde_json::Value::as_str),
        Some("active" | "recovery_pending")
    ) || details
        .get("state_changed")
        .and_then(serde_json::Value::as_bool)
        .is_none()
        || details
            .get("session_state_revision")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| satelle_core::session::SessionStateRevision::new(value).ok())
            .is_none()
        || details
            .get("turn_state_revision")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| satelle_core::session::TurnStateRevision::new(value).ok())
            .is_none()
        || details
            .get("retryable")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return SatelleError::remote_api_error(host, "invalid-daemon-response");
    }
    SatelleError {
        code: ErrorCode::StopNotConfirmed,
        message: "stop was not confirmed; Satelle retained control of the Turn".to_string(),
        recovery_command: Some(format!(
            "satelle status {} --host {host}",
            session_id.as_str()
        )),
        source_detail: None,
        details: details.clone().into_iter().collect(),
    }
}

fn direct_admission_error(host: &str, error: DaemonClientError) -> TurnAdmissionFailure {
    // Only failures enforced before the daemon calls Host admission are
    // definitive. Runtime, storage, and internal API errors can occur after
    // the Turn commits and carry no durable handles in this protocol version.
    let definitively_not_admitted = matches!(
        &error,
        DaemonClientError::NonLoopbackPlaintextEndpoint
            | DaemonClientError::InvalidTokenHeader
            | DaemonClientError::InvalidHostIdentityHeader
            | DaemonClientError::InvalidIdempotencyKeyHeader
            | DaemonClientError::InvalidCaBundle(_)
            | DaemonClientError::EmptyCaBundle
            | DaemonClientError::CertificateUntrusted(_)
            | DaemonClientError::CertificateHostnameMismatch(_)
            | DaemonClientError::CertificateExpired(_)
            | DaemonClientError::TlsVersionUnsupported(_)
            | DaemonClientError::TlsHandshake(_)
    ) || matches!(
        &error,
        DaemonClientError::Api { error, .. }
            if api_error_is_definitively_not_admitted(error.code())
    );
    let error = direct_transport_error(host, error);
    if definitively_not_admitted {
        TurnAdmissionFailure::not_admitted(error)
    } else {
        TurnAdmissionFailure::admission_unknown(error)
    }
}

fn direct_run_admission_error(host: &str, error: DaemonClientError) -> TurnAdmissionFailure {
    // reqwest connect failures happen before the create-session request can
    // reach the daemon, so this run is definitively not admitted. Every later
    // transport phase retains the generic admission-unknown classification.
    if matches!(&error, DaemonClientError::Transport(error) if error.is_connect()) {
        return TurnAdmissionFailure::not_admitted(SatelleError::direct_daemon_unreachable(host));
    }
    direct_admission_error(host, error)
}

fn api_error_is_definitively_not_admitted(code: ApiErrorCode) -> bool {
    matches!(
        code,
        ApiErrorCode::AuthenticationFailed
            | ApiErrorCode::AuthorizationInsufficientScope
            | ApiErrorCode::HostIdentityMismatch
            | ApiErrorCode::InvalidRequest
            | ApiErrorCode::UnsupportedSchema
            | ApiErrorCode::UnsupportedContentType
            | ApiErrorCode::PayloadTooLarge
            | ApiErrorCode::IdempotencyKeyConflict
            | ApiErrorCode::SessionNotFound
            | ApiErrorCode::HostBusy
            | ApiErrorCode::IncompatibleProtocol
            | ApiErrorCode::IncompatibleControlPlane
            | ApiErrorCode::ComputerUseNotReady
            | ApiErrorCode::YoloNotSupported
            | ApiErrorCode::YoloBlockedByNativeApproval
            | ApiErrorCode::DesktopBindingRequired
            | ApiErrorCode::DesktopSessionUnavailable
            | ApiErrorCode::DesktopSessionAmbiguous
            | ApiErrorCode::DesktopSessionPreferenceUnmatched
            | ApiErrorCode::DesktopSessionConsoleUnavailable
            | ApiErrorCode::DesktopSessionNativeSelectorWrongPlatform
            | ApiErrorCode::DesktopSessionNativeSelectorUnmatched
            | ApiErrorCode::NativeReadinessTimeout
            | ApiErrorCode::ProviderSmokeTestTimeout
            | ApiErrorCode::UnsupportedProviderComputerUse
            | ApiErrorCode::ExperimentalProviderOptInRequired
            | ApiErrorCode::ModelProviderBindingMissing
            | ApiErrorCode::ProjectProviderSelectionNotAllowed
            | ApiErrorCode::ProviderSecretSourceRequired
            | ApiErrorCode::ProviderSecretProvisioningRequired
            | ApiErrorCode::ProviderSecretOverwriteRequired
            | ApiErrorCode::ProviderSecretResolutionFailed
            | ApiErrorCode::ExperimentalProviderNotValidated
            | ApiErrorCode::CapacityExceeded
            | ApiErrorCode::RateLimited
            | ApiErrorCode::RouteNotFound
            | ApiErrorCode::MethodNotAllowed
    )
}

fn api_code_error(host: &str, code: ApiErrorCode) -> SatelleError {
    match code {
        ApiErrorCode::AuthenticationFailed => SatelleError::authentication_failed(host),
        ApiErrorCode::AuthorizationInsufficientScope => {
            SatelleError::authorization_insufficient_scope(host)
        }
        ApiErrorCode::HostIdentityMismatch => SatelleError::host_identity_mismatch(host),
        ApiErrorCode::HostUnreachable => SatelleError::host_unreachable(host),
        ApiErrorCode::StateConflict => SatelleError::state_conflict(),
        ApiErrorCode::NativeReadinessTimeout => SatelleError::native_readiness_timeout(),
        ApiErrorCode::YoloNotSupported => SatelleError::yolo_not_supported(),
        ApiErrorCode::YoloBlockedByNativeApproval => {
            SatelleError::yolo_blocked_by_native_approval()
        }
        ApiErrorCode::ProviderSmokeTestTimeout => SatelleError::provider_smoke_test_timeout(),
        ApiErrorCode::UnsupportedProviderComputerUse => {
            SatelleError::unsupported_provider_computer_use()
        }
        ApiErrorCode::ExperimentalProviderOptInRequired => provider_api_error(
            ErrorCode::ExperimentalProviderOptInRequired,
            "experimental provider Computer Use is not enabled",
        ),
        ApiErrorCode::ModelProviderBindingMissing => provider_api_error(
            ErrorCode::ModelProviderBindingMissing,
            "the requested model and provider binding is not configured",
        ),
        ApiErrorCode::ProjectProviderSelectionNotAllowed => provider_api_error(
            ErrorCode::ProjectProviderSelectionNotAllowed,
            "the project is not allowed to select this provider binding",
        ),
        ApiErrorCode::ProviderSecretResolutionFailed => provider_secret_api_error(
            host,
            ErrorCode::ProviderSecretResolutionFailed,
            "the Host could not resolve provider authentication",
        ),
        ApiErrorCode::ProviderSecretSourceRequired => provider_secret_api_error(
            host,
            ErrorCode::ProviderSecretSourceRequired,
            "provider authentication requires a Secret Source descriptor",
        ),
        ApiErrorCode::ProviderSecretProvisioningRequired => provider_secret_api_error(
            host,
            ErrorCode::ProviderSecretProvisioningRequired,
            "provider authentication requires interactive secret provisioning",
        ),
        ApiErrorCode::ProviderSecretOverwriteRequired => provider_secret_api_error(
            host,
            ErrorCode::ProviderSecretOverwriteRequired,
            "provider secret replacement requires explicit confirmation",
        ),
        ApiErrorCode::ExperimentalProviderNotValidated => provider_api_error(
            ErrorCode::ExperimentalProviderNotValidated,
            "the selected provider did not pass live validation",
        ),
        code => SatelleError::remote_api_error(host, code.as_str()),
    }
}

fn provider_api_error(code: ErrorCode, message: &str) -> SatelleError {
    SatelleError {
        code,
        message: message.to_string(),
        recovery_command: Some("run satelle doctor --scope provider --refresh --json".to_string()),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn provider_secret_api_error(host: &str, code: ErrorCode, message: &str) -> SatelleError {
    SatelleError {
        code,
        message: message.to_string(),
        recovery_command: Some(format!(
            "satelle setup --host {host} --component provider-auth"
        )),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn local_host_service(host_config: &satelle_core::HostConfig) -> Result<HostService, CliFailure> {
    #[cfg(feature = "test-support")]
    match std::env::var(TEST_SUPPORT_ADAPTER_ENV) {
        Ok(value) if value == "fake" => {
            return HostService::local_demo_for_tests().map_err(failure);
        }
        Ok(value) if value == "pending" => {
            return HostService::pending_local_demo_for_tests().map_err(failure);
        }
        Ok(value) if value == "failing" => {
            return HostService::failing_local_demo_for_tests().map_err(failure);
        }
        Ok(value) if value == "readiness-failing" => {
            return HostService::readiness_failing_local_demo_for_tests().map_err(failure);
        }
        Ok(value) if value == "resolved-secret-canary" => {
            return HostService::resolved_secret_canary_local_demo_for_tests().map_err(failure);
        }
        Ok(_) => {
            return Err(failure(SatelleError::invalid_usage(
                "SATELLE_TEST_SUPPORT_ADAPTER must be exactly 'fake', 'pending', 'failing', 'readiness-failing', 'resolved-secret-canary', or unset",
            )));
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(failure(SatelleError::invalid_usage(
                "SATELLE_TEST_SUPPORT_ADAPTER must contain valid UTF-8",
            )));
        }
        Err(std::env::VarError::NotPresent) => {}
    }

    Ok(HostService::production_for_host(host_config))
}

pub(crate) fn transport_for(host: &SelectedHost) -> Result<Box<dyn TransportClient>, CliFailure> {
    transport_for_with_ssh_launch_policy(host, SshDaemonLaunchPolicy::DurableOnly)
}

pub(crate) fn transport_for_setup(
    host: &SelectedHost,
) -> Result<Box<dyn TransportClient>, CliFailure> {
    if host.config.transport == TransportKind::Ssh {
        return SshSetupTransport::new(host)
            .map(|transport| Box::new(transport) as Box<dyn TransportClient>)
            .map_err(failure);
    }
    transport_for(host)
}

pub(crate) fn transport_for_with_ssh_bootstrap(
    host: &SelectedHost,
    bootstrap_scope: Option<SshBootstrapScope>,
) -> Result<Box<dyn TransportClient>, CliFailure> {
    let launch_policy = bootstrap_scope.map_or(
        SshDaemonLaunchPolicy::Never,
        SshDaemonLaunchPolicy::Bootstrap,
    );
    transport_for_with_ssh_launch_policy(host, launch_policy)
}

fn is_daemon_reachability_failure(error: &SatelleError) -> bool {
    matches!(
        error.code,
        ErrorCode::HostUnreachable | ErrorCode::DirectDaemonUnreachable
    )
}

fn ssh_bootstrap_host(host: &SelectedHost) -> Result<SelectedHost, SatelleError> {
    let settings = host
        .config
        .ssh_bootstrap
        .as_ref()
        .ok_or_else(|| SatelleError::ssh_bootstrap_unavailable(&host.alias))?;
    let mut config = host.config.clone();
    config.transport = TransportKind::Ssh;
    config.address = Some(settings.address.clone());
    config.network = None;
    config.ca_bundle = None;
    // The direct daemon already proved this durable credential unreachable. The SSH leg must
    // select the tokenless read-bootstrap branch instead of retrying the same credential.
    config.api_token = None;
    config.ssh_bootstrap = None;
    Ok(SelectedHost {
        alias: host.alias.clone(),
        config,
        from_project: host.from_project,
    })
}

fn direct_inspection_fallback(
    host: &SelectedHost,
    no_bootstrap: bool,
) -> Result<DirectTransport, SatelleError> {
    if no_bootstrap {
        return Err(SatelleError::host_daemon_unreachable(&host.alias));
    }
    let bootstrap_host = ssh_bootstrap_host(host)?;
    ssh_transport(
        &bootstrap_host,
        SshDaemonLaunchPolicy::Bootstrap(SshBootstrapScope::Read),
    )
}

pub(crate) fn host_sessions_for_inspection(
    host: &SelectedHost,
    no_bootstrap: bool,
) -> Result<HostSessionsReport, CliFailure> {
    let result = match host.config.transport {
        TransportKind::Direct => match direct_transport(host)
            .and_then(|transport| transport.host_sessions(no_bootstrap))
        {
            Ok(report) => Ok(report),
            Err(error) if is_daemon_reachability_failure(&error) => {
                direct_inspection_fallback(host, no_bootstrap)
                    .and_then(|transport| transport.host_sessions(no_bootstrap))
            }
            Err(error) => Err(error),
        },
        TransportKind::Ssh => {
            if no_bootstrap && host.config.api_token.is_none() {
                Err(SatelleError::host_daemon_unreachable(&host.alias))
            } else {
                let bootstrap_scope = (!no_bootstrap).then_some(SshBootstrapScope::Read);
                let launch_policy = bootstrap_scope.map_or(
                    SshDaemonLaunchPolicy::Never,
                    SshDaemonLaunchPolicy::Bootstrap,
                );
                ssh_transport(host, launch_policy)
                    .and_then(|transport| transport.host_sessions(no_bootstrap))
            }
        }
        TransportKind::Local => local_host_service(&host.config)
            .map_err(|failure| failure.error)
            .and_then(|service| {
                LocalTransport::new(host.alias.clone(), service).host_sessions(no_bootstrap)
            }),
    };
    result
        .map_err(|error| {
            if no_bootstrap && is_daemon_reachability_failure(&error) {
                SatelleError::host_daemon_unreachable(&host.alias)
            } else {
                error
            }
        })
        .map_err(failure)
}

pub(crate) fn host_paths_for_inspection(
    host: &SelectedHost,
) -> Result<satelle_core::daemon_service::DaemonResolvedPathSet, CliFailure> {
    let result = match host.config.transport {
        TransportKind::Direct => match direct_transport(host)
            .and_then(|transport| transport.host_paths())
        {
            Ok(paths) => Ok(paths),
            Err(error) if is_daemon_reachability_failure(&error) => {
                direct_inspection_fallback(host, false).and_then(|transport| transport.host_paths())
            }
            Err(error) => Err(error),
        },
        TransportKind::Ssh => ssh_transport(
            host,
            SshDaemonLaunchPolicy::Bootstrap(SshBootstrapScope::Read),
        )
        .and_then(|transport| transport.host_paths()),
        TransportKind::Local => local_host_service(&host.config)
            .map_err(|failure| failure.error)
            .and_then(|service| LocalTransport::new(host.alias.clone(), service).host_paths()),
    };
    result.map_err(failure)
}

fn transport_for_with_ssh_launch_policy(
    host: &SelectedHost,
    launch_policy: SshDaemonLaunchPolicy,
) -> Result<Box<dyn TransportClient>, CliFailure> {
    match host.config.transport {
        TransportKind::Local => local_host_service(&host.config)
            .map(|service| Box::new(LocalTransport::for_selected_host(host, service)) as _),
        TransportKind::Direct => direct_transport(host)
            .map(|transport| Box::new(transport) as _)
            .map_err(failure),
        TransportKind::Ssh => ssh_transport(host, launch_policy)
            .map(|transport| Box::new(transport) as _)
            .map_err(failure),
    }
}

pub(crate) fn discover_direct_host_identity(host: &SelectedHost) -> Result<String, SatelleError> {
    if host.config.transport != TransportKind::Direct {
        return Err(SatelleError::invalid_usage(
            "host trust currently requires a direct HTTPS Host Binding",
        ));
    }
    let mut probe_config = host.config.clone();
    probe_config.expected_host_id = Some(format!("trust-probe-{}", Uuid::now_v7()));
    let binding = DirectHostBinding::from_host_config(&probe_config)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ApiTokenSource::File { path } = binding.api_token();
    let raw_token = read_owner_only_secret_file(path)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let token = ApiBearerToken::parse(raw_token.as_str())
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let ca_bundle = binding
        .ca_bundle()
        .map(read_trusted_ca_bundle_file)
        .transpose()
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let client = DaemonClient::https(&binding, token, ca_bundle.as_deref().map(str::as_bytes))
        .map_err(|error| direct_transport_error(&host.alias, error))?;
    client
        .discover_host_identity()
        .map_err(|error| direct_transport_error(&host.alias, error))
}

pub(crate) fn cleanup_ssh_host_cache(
    host: &SelectedHost,
) -> Result<CacheCleanupReport, SatelleError> {
    if host.config.transport != TransportKind::Ssh {
        return Err(SatelleError::invalid_usage(
            "host cleanup requires an SSH Host Binding",
        ));
    }
    let mut binding_config = host.config.clone();
    if binding_config.expected_host_id.is_none() {
        binding_config.expected_host_id = Some(format!("cleanup-{}", Uuid::now_v7()));
    }
    let binding = SshHostBinding::from_host_config_for_bootstrap(&binding_config)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    ssh_bootstrap::cleanup_host_cache(binding.destination())
        .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))
}

pub(crate) struct SshHostDiscovery {
    pub(crate) identity: String,
    pub(crate) authenticated_user: String,
    pub(crate) sessions: HostSessionsReport,
    finalization: Option<SshTrustFinalization>,
}

impl SshHostDiscovery {
    pub(crate) fn finalize_after_binding(&mut self) -> Result<(), SatelleError> {
        let Some(mut finalization) = self.finalization.take() else {
            return Ok(());
        };
        let finalized = (|| {
            complete_bootstrap_handoff(
                &finalization.alias,
                &finalization.client,
                &mut finalization.bootstrap_lock,
            )?;
            finalization
                .target
                .cleanup_identity_operation_artifact(
                    &finalization.destination,
                    &finalization.record,
                    &mut finalization.bootstrap_lock,
                )
                .map_err(|error| map_ssh_daemon_bootstrap_error(&finalization.alias, error))?;
            finalization
                .bootstrap_lock
                .release_committed_handoff()
                .map_err(|_| SatelleError::host_unreachable(&finalization.alias))
        })();
        if finalized.is_err() {
            // Keep the exact operation cleanup capability retryable. Host
            // completion is idempotent; once it deleted the record, a retry
            // can only remove the orphaned artifact and release this lock.
            self.finalization = Some(finalization);
        }
        finalized
    }
}

pub(crate) enum PendingSshTrust {
    Live(Box<PendingLiveSshTrustCandidate>),
    Fresh(Box<PendingSshTrustCandidate>),
}

impl PendingSshTrust {
    pub(crate) fn identity(&self) -> &str {
        match self {
            Self::Live(candidate) => candidate.identity.as_str(),
            Self::Fresh(candidate) => candidate.identity.as_str(),
        }
    }

    pub(crate) fn accept(self) -> Result<SshHostDiscovery, SatelleError> {
        match self {
            Self::Live(candidate) => (*candidate).accept(),
            Self::Fresh(candidate) => (*candidate).accept(),
        }
    }
}

pub(crate) struct PendingLiveSshTrustCandidate {
    alias: String,
    identity: String,
    authenticated_user: String,
    client: Arc<DaemonClient>,
    _tunnel: SshTunnel,
}

impl PendingLiveSshTrustCandidate {
    fn accept(self) -> Result<SshHostDiscovery, SatelleError> {
        let capabilities = self
            .client
            .capabilities()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        let desktop_sessions = self
            .client
            .desktop_sessions()
            .map_err(|error| direct_transport_error(&self.alias, error))?;
        Ok(SshHostDiscovery {
            identity: self.identity,
            authenticated_user: self.authenticated_user,
            sessions: HostSessionsReport {
                schema_version: HostSessionsSchemaVersion::V1,
                host: self.alias,
                detected_platform: capabilities.platform().to_string(),
                connection_mode: "ssh".to_string(),
                bootstrapped: false,
                bootstrap_actions: Vec::new(),
                host_daemon_version: capabilities.daemon_version().to_string(),
                sessions: desktop_sessions.sessions().to_vec(),
            },
            finalization: None,
        })
    }
}

enum IdentityOperationState {
    Fresh,
    Pending(satelle_core::SshIdentityCommitRecord),
}

struct SshTrustFinalization {
    alias: String,
    destination: String,
    target: ssh_bootstrap::RemoteTarget,
    record: satelle_core::SshIdentityCommitRecord,
    client: Arc<DaemonClient>,
    _tunnel: SshTunnel,
    _bootstrap: SshBootstrapProcess,
    bootstrap_lock: ssh_bootstrap::SshBootstrapLock,
}

pub(crate) struct PendingSshTrustCandidate {
    alias: String,
    destination: String,
    authenticated_user: String,
    previous_host_config: satelle_core::HostConfig,
    host_config: satelle_core::HostConfig,
    target: ssh_bootstrap::RemoteTarget,
    state: IdentityOperationState,
    identity: HostIdentityRef,
    operation_id: String,
}

impl PendingSshTrustCandidate {
    fn accept(self) -> Result<SshHostDiscovery, SatelleError> {
        let observed_target = ssh_bootstrap::RemoteTarget::probe(&self.destination)
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
        if observed_target != self.target {
            return Err(SatelleError::host_identity_mismatch(&self.alias));
        }
        let observed_directories =
            ssh_bootstrap::RemoteUserDirectories::probe(&self.destination, observed_target)
                .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
        if observed_directories.authenticated_user() != self.authenticated_user {
            return Err(SatelleError::host_identity_mismatch(&self.alias));
        }
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation(
            &self.alias,
            &self.destination,
            self.operation_id.clone(),
            LockFirstOperationKind::InitialSetup.operation_kind(),
        )?;
        confirm_bootstrap_lock(&self.alias, &mut bootstrap_lock)?;
        let observed_state = self
            .target
            .inspect_initial_host_state(&self.destination, &observed_directories, &self.host_config)
            .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
        let record = match (&self.state, observed_state) {
            (IdentityOperationState::Fresh, ssh_bootstrap::InitialHostState::Fresh) => {
                let prepared = self
                    .target
                    .prepare_identity_operation(
                        &observed_directories,
                        &self.host_config,
                        &self.operation_id,
                        &self.identity,
                    )
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
                let record = prepared.record().clone();
                if let Err(error) = self.target.begin_identity_operation(
                    &self.destination,
                    &prepared,
                    &mut bootstrap_lock,
                ) {
                    let _ = self.target.cleanup_identity_operation_artifact(
                        &self.destination,
                        &record,
                        &mut bootstrap_lock,
                    );
                    return Err(map_ssh_daemon_bootstrap_error(&self.alias, error));
                }
                record
            }
            (
                IdentityOperationState::Pending(expected),
                ssh_bootstrap::InitialHostState::PendingIdentityCommit(observed),
            ) if expected == &observed => {
                self.target
                    .validate_pending_identity_operation(&self.destination, &observed)
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
                observed
            }
            _ => return Err(SatelleError::host_identity_mismatch(&self.alias)),
        };
        // These guards stay bound through the authenticated handoff so neither
        // the SSH tunnel nor its bootstrap daemon can end between requests.
        let setup = setup_fresh_bootstrap_client(
            &self.alias,
            &self.destination,
            &self.previous_host_config,
            &self.host_config,
            ssh_bootstrap::InitialHostIdentityCommit {
                host_identity: &self.identity,
                operation_id: &self.operation_id,
                record: &record,
            },
            record.exact_remote_path(),
            &mut bootstrap_lock,
        );
        let (client, tunnel, bootstrap, sessions) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                // Cleanup is allowed only while the Host record is absent. If
                // Host reached its durable commit, this command refuses to
                // remove the artifact and preserves an exact pending resume.
                let _ = self.target.cleanup_identity_operation_artifact(
                    &self.destination,
                    &record,
                    &mut bootstrap_lock,
                );
                return Err(error);
            }
        };
        Ok(SshHostDiscovery {
            identity: self.identity.as_str().to_string(),
            authenticated_user: self.authenticated_user,
            sessions,
            finalization: Some(SshTrustFinalization {
                alias: self.alias,
                destination: self.destination,
                target: self.target,
                record,
                client,
                _tunnel: tunnel,
                _bootstrap: bootstrap,
                bootstrap_lock,
            }),
        })
    }
}

pub(crate) fn authenticated_ssh_bootstrap_user(
    host: &SelectedHost,
) -> Result<String, SatelleError> {
    let transport = SshSetupTransport::new(host)?;
    let target = transport.remote_target()?;
    Ok(transport
        .remote_directories(target)?
        .authenticated_user()
        .to_string())
}

pub(crate) fn discover_ssh_host(
    host: &SelectedHost,
    daemon_path_overrides: &DaemonPathOverrides,
    requested_identity: Option<&str>,
) -> Result<PendingSshTrust, SatelleError> {
    if host.config.transport != TransportKind::Ssh {
        return Err(SatelleError::invalid_usage(
            "SSH Host identity discovery requires an SSH Host Binding",
        ));
    }
    let probe_identity = format!("trust-probe-{}", Uuid::now_v7());
    let mut probe_config = host.config.clone();
    probe_config.expected_host_id = Some(probe_identity.clone());
    let binding = SshHostBinding::from_host_config_for_bootstrap(&probe_config)
        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
    let target = ssh_bootstrap::RemoteTarget::probe(binding.destination())
        .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))?;
    let directories = ssh_bootstrap::RemoteUserDirectories::probe(binding.destination(), target)
        .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))?;
    let authenticated_user = directories.authenticated_user().to_string();
    let tunnel = SshTunnel::open(binding.destination()).map_err(|error| match error {
        ssh_tunnel::SshTunnelError::HostKeyVerificationRequired => {
            SatelleError::ssh_host_key_verification_required(&host.alias)
        }
        _ => SatelleError::host_unreachable(&host.alias),
    })?;
    let liveness_token =
        ApiBearerToken::generate().map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    let liveness_client = DaemonClient::loopback_with_timeout(
        tunnel.local_addr(),
        liveness_token,
        &probe_identity,
        SSH_DAEMON_REQUEST_TIMEOUT,
    )
    .map_err(|error| direct_transport_error(&host.alias, error))?;
    match liveness_client.live() {
        Ok(_) => {
            let setup_transport = SshSetupTransport::new(host)?;
            let token = setup_transport.read_configured_durable_token()?;
            let raw_token = token.expose();
            let discovery_client = DaemonClient::loopback_with_timeout(
                tunnel.local_addr(),
                token,
                &probe_identity,
                SSH_DAEMON_REQUEST_TIMEOUT,
            )
            .map_err(|error| direct_transport_error(&host.alias, error))?;
            let identity =
                discovery_client
                    .discover_host_identity()
                    .map_err(|error| match error {
                        DaemonClientError::Api { status: _, error }
                            if matches!(
                                error.code(),
                                ApiErrorCode::AuthenticationFailed
                                    | ApiErrorCode::HostIdentityMismatch
                            ) =>
                        {
                            setup_transport.unauthenticated_daemon_version_error()
                        }
                        error => direct_transport_error(&host.alias, error),
                    })?;
            let token = ApiBearerToken::parse(raw_token.as_str())
                .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
            let client = DaemonClient::loopback_with_timeout(
                tunnel.local_addr(),
                token,
                &identity,
                SSH_DAEMON_REQUEST_TIMEOUT,
            )
            .map_err(|error| direct_transport_error(&host.alias, error))?;
            return Ok(PendingSshTrust::Live(Box::new(
                PendingLiveSshTrustCandidate {
                    alias: host.alias.clone(),
                    identity,
                    authenticated_user,
                    client: Arc::new(client),
                    _tunnel: tunnel,
                },
            )));
        }
        Err(DaemonClientError::Transport(error)) if error.is_connect() => {}
        Err(error) => return Err(direct_transport_error(&host.alias, error)),
    }
    drop(tunnel);
    let mut selected_host_config = host.config.clone();
    selected_host_config.daemon_home = daemon_path_overrides.home.clone();
    selected_host_config.daemon_config_file = daemon_path_overrides.config_file.clone();
    selected_host_config.daemon_state_dir = daemon_path_overrides.state_dir.clone();
    selected_host_config.daemon_cache_dir = daemon_path_overrides.cache_dir.clone();
    selected_host_config.daemon_log_dir = daemon_path_overrides.log_dir.clone();
    let pending_resume = match target
        .inspect_initial_host_state(binding.destination(), &directories, &selected_host_config)
        .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))?
    {
        ssh_bootstrap::InitialHostState::Fresh => None,
        ssh_bootstrap::InitialHostState::Existing => {
            return Err(SatelleError::config_error(
                format!(
                    "host '{}' has existing stopped Host state; start its canonical Host Daemon and retry with the configured durable credential",
                    host.alias
                ),
                None,
            ));
        }
        ssh_bootstrap::InitialHostState::PendingIdentityCommit(record) => {
            if requested_identity
                .is_some_and(|expected| expected != record.candidate_host_identity().as_str())
            {
                return Err(SatelleError::host_identity_mismatch(&host.alias));
            }
            Some(record)
        }
    };
    let (operation_id, identity, state) = match pending_resume {
        Some(record) => (
            record.operation_id().to_string(),
            record.candidate_host_identity().clone(),
            IdentityOperationState::Pending(record),
        ),
        None => {
            let identity = requested_identity.map_or_else(
                || {
                    Ok(
                        HostIdentityRef::new(format!("host-{}", Uuid::now_v7().hyphenated()))
                            .expect("a generated UUIDv7 Host Identity is valid"),
                    )
                },
                |identity| {
                    HostIdentityRef::new(identity.to_string()).map_err(|_| {
                        SatelleError::invalid_usage(
                            "--expected-host-id must be a valid Host Identity",
                        )
                    })
                },
            )?;
            (
                Uuid::now_v7().hyphenated().to_string(),
                identity,
                IdentityOperationState::Fresh,
            )
        }
    };
    Ok(PendingSshTrust::Fresh(Box::new(PendingSshTrustCandidate {
        alias: host.alias.clone(),
        destination: binding.destination().to_string(),
        authenticated_user,
        previous_host_config: host.config.clone(),
        host_config: selected_host_config,
        target,
        state,
        identity,
        operation_id,
    })))
}

#[cfg(test)]
mod bootstrap_ordering_tests {
    use super::*;

    #[derive(Default)]
    struct InMemoryPersistentSetupExecution {
        events: Vec<String>,
        mutation_attempts: usize,
        fence_commits: usize,
        fail_during: Option<PersistentSetupAction>,
        readiness_uncertain: bool,
        partial_failure: bool,
        recovery_pending: bool,
        mutation_pending: bool,
    }

    impl PersistentSetupExecution for InMemoryPersistentSetupExecution {
        type Output = SetupApplication;

        fn begin(&mut self) -> Result<(), SatelleError> {
            self.events.push("begin".to_string());
            Ok(())
        }

        fn start(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError> {
            self.events.push(format!("start:{}", action.id()));
            Ok(())
        }

        fn apply(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError> {
            self.events.push(format!("mutate:{}", action.id()));
            self.mutation_attempts += 1;
            self.mutation_pending = true;
            if action == PersistentSetupAction::ServiceStartOrRestart {
                self.events.push("authenticated-readiness".to_string());
                if self.readiness_uncertain {
                    self.recovery_pending = true;
                    return Err(SatelleError::host_unreachable("remote"));
                }
            }
            if self.fail_during == Some(action) {
                return Err(SatelleError::host_unreachable("remote"));
            }
            self.fence_commits += 1;
            self.mutation_pending = false;
            Ok(())
        }

        fn complete(&mut self, action: PersistentSetupAction) -> Result<(), SatelleError> {
            self.events.push(format!("complete:{}", action.id()));
            Ok(())
        }

        fn fail(&mut self, action: PersistentSetupAction, source: SatelleError) -> SatelleError {
            if self.mutation_pending {
                self.fence_commits += 1;
                self.mutation_pending = false;
            }
            self.partial_failure = true;
            self.events.push(format!("failed:{}", action.id()));
            source
        }

        fn finish(&mut self) -> Result<Self::Output, SatelleError> {
            self.events.push("finish".to_string());
            Ok(SetupApplication::AppliedReusableToken)
        }
    }

    fn setup_transport_for_report() -> SshSetupTransport {
        let mut config = satelle_core::SatelleConfig::defaults()
            .hosts
            .remove(LOCAL_DEMO_HOST)
            .expect("built-in Host config");
        config.transport = TransportKind::Ssh;
        config.address = Some("host.example.test".to_string());
        config.expected_host_id = Some("host-setup-test".to_string());
        config.api_token = Some(ApiTokenSource::File {
            path: std::env::temp_dir().join("satelle-report-observation.token"),
        });
        SshSetupTransport::new(&SelectedHost {
            alias: "remote".to_string(),
            config,
            from_project: false,
        })
        .expect("construct setup transport")
        .with_remote_target_for_tests(ssh_bootstrap::RemoteTarget::WindowsX64Msvc)
    }

    #[test]
    fn lock_first_acquisition_is_closed_to_setup_and_missing_daemon_repair() {
        assert_eq!(
            LockFirstOperationKind::InitialSetup.operation_kind(),
            bootstrap_lock::OperationKind::InitialSetup
        );
        assert_eq!(
            LockFirstOperationKind::MissingDaemonRepair.operation_kind(),
            bootstrap_lock::OperationKind::MissingDaemonRepair
        );
    }

    #[test]
    fn persistent_setup_driver_runs_exact_actions_and_commits_each_mutation_once() {
        let mut execution = InMemoryPersistentSetupExecution::default();

        coordinate_persistent_setup(&mut execution).expect("coordinate persistent setup");

        let mutations = execution
            .events
            .iter()
            .filter_map(|event| event.strip_prefix("mutate:"))
            .collect::<Vec<_>>();
        assert_eq!(
            mutations,
            PERSISTENT_SERVICE_ACTIONS
                .iter()
                .map(|action| action.id())
                .collect::<Vec<_>>()
        );
        assert_eq!(execution.mutation_attempts, 5);
        assert_eq!(execution.fence_commits, 5);
        assert_eq!(execution.events.last().map(String::as_str), Some("finish"));
        let start = execution
            .events
            .iter()
            .position(|event| event == "mutate:service-start-or-restart")
            .expect("service start mutation");
        let readiness = execution
            .events
            .iter()
            .position(|event| event == "authenticated-readiness")
            .expect("authenticated readiness");
        let finish = execution
            .events
            .iter()
            .position(|event| event == "finish")
            .expect("maintenance finish");
        assert!(start < readiness && readiness < finish);
    }

    #[test]
    fn persistent_setup_driver_records_pre_start_failure_as_partial() {
        let mut execution = InMemoryPersistentSetupExecution {
            fail_during: Some(PersistentSetupAction::ServiceConfig),
            ..InMemoryPersistentSetupExecution::default()
        };

        assert!(coordinate_persistent_setup(&mut execution).is_err());

        assert!(execution.partial_failure);
        assert!(!execution.recovery_pending);
        assert_eq!(execution.mutation_attempts, 3);
        assert_eq!(execution.fence_commits, 3);
        assert_eq!(
            execution.events.last().map(String::as_str),
            Some("failed:service-config")
        );
    }

    #[test]
    fn persistent_setup_driver_keeps_post_start_readiness_uncertainty_recovery_pending() {
        let mut execution = InMemoryPersistentSetupExecution {
            readiness_uncertain: true,
            ..InMemoryPersistentSetupExecution::default()
        };

        assert!(coordinate_persistent_setup(&mut execution).is_err());

        assert!(!execution.partial_failure);
        assert!(execution.recovery_pending);
        assert_eq!(execution.mutation_attempts, 5);
        assert_eq!(execution.fence_commits, 4);
        assert!(!execution.events.iter().any(|event| event == "finish"));
        assert!(
            !execution
                .events
                .iter()
                .any(|event| event == "failed:service-start-or-restart")
        );
    }

    #[test]
    fn setup_report_uses_older_pre_mutation_daemon_observation() {
        let transport = setup_transport_for_report();
        let observation = CurrentDaemonArtifactObservation {
            current_version: Some("0.0.0".to_string()),
            minimum_host_version: None,
            protocol_compatible: true,
            codex_update_evidence: None,
            validated_host_identity: None,
        };

        let report = transport
            .setup_report_for_target(
                true,
                SetupModeSelection::new(
                    satelle_core::SetupMode::Persistent,
                    satelle_core::daemon_service::SetupModeSource::SetupFlag,
                ),
                ssh_bootstrap::RemoteTarget::WindowsX64Msvc,
                vec!["transport".to_string()],
                DaemonPathOverrides::default(),
                SetupApplication::Planned {
                    existing_token_file: true,
                },
                &observation,
            )
            .expect("build setup report");
        let artifact = report.host_artifact.expect("artifact plan");
        assert_eq!(artifact.current_version.as_deref(), Some("0.0.0"));
        assert_eq!(
            artifact.action,
            satelle_core::daemon_service::DaemonArtifactAction::UpdateOlder
        );
    }

    #[test]
    fn setup_reports_newer_host_and_missing_release_artifact_with_typed_errors() {
        let transport = setup_transport_for_report();
        let newer = CurrentDaemonArtifactObservation {
            current_version: Some("999.0.0".to_string()),
            minimum_host_version: None,
            protocol_compatible: true,
            codex_update_evidence: None,
            validated_host_identity: None,
        };
        let newer_error = transport
            .setup_report_for_target(
                true,
                SetupModeSelection::new(
                    satelle_core::SetupMode::Persistent,
                    satelle_core::daemon_service::SetupModeSource::SetupFlag,
                ),
                ssh_bootstrap::RemoteTarget::WindowsX64Msvc,
                vec!["transport".to_string()],
                DaemonPathOverrides::default(),
                SetupApplication::Planned {
                    existing_token_file: true,
                },
                &newer,
            )
            .expect_err("setup must not downgrade a newer Host");
        assert_eq!(
            newer_error.code,
            satelle_core::ErrorCode::HostBinaryNewerThanCli
        );

        let target = ssh_bootstrap::RemoteTarget::DarwinArm64;
        let release_error = |error| {
            map_ssh_daemon_bootstrap_error(
                "remote",
                ssh_bootstrap::SshBootstrapError::verified_release("1.2.3", target, error),
            )
        };
        let missing_error =
            release_error(crate::self_update::SelfUpdateError::ManifestEntryMissing);
        assert_eq!(
            missing_error.code,
            satelle_core::ErrorCode::HostArtifactUnavailable
        );
        assert_eq!(
            missing_error.details["remote_platform"],
            serde_json::json!("darwin-arm64")
        );
        assert_eq!(
            missing_error.details["cli_version"],
            serde_json::json!("1.2.3")
        );

        let oversized_manifest_error =
            release_error(crate::self_update::SelfUpdateError::ResponseTooLarge);
        assert_eq!(
            oversized_manifest_error.code,
            satelle_core::ErrorCode::HostArtifactUnavailable
        );
        assert_eq!(
            oversized_manifest_error.details["remote_platform"],
            serde_json::json!("darwin-arm64")
        );

        let malformed = release_error(crate::self_update::SelfUpdateError::ManifestInvalid);
        assert_eq!(
            malformed.code,
            satelle_core::ErrorCode::HostArtifactUnavailable
        );

        let verifier_unavailable =
            release_error(crate::self_update::SelfUpdateError::GhUnavailable);
        assert_eq!(
            verifier_unavailable.code,
            satelle_core::ErrorCode::ReleaseVerifierUnavailable
        );
        assert_eq!(
            verifier_unavailable.details["cli_version"],
            serde_json::json!("1.2.3")
        );
        assert_eq!(
            verifier_unavailable.details["remote_platform"],
            serde_json::json!("darwin-arm64")
        );
    }

    #[test]
    fn unsupported_codex_platform_is_a_readiness_error_not_invalid_usage() {
        let error = map_host_update_plan_error(
            crate::host_update::HostUpdatePlanError::UnsupportedCodexTarget {
                target: satelle_core::host_update::HostUpdateTarget::CodexRuntime,
            },
        );

        assert_eq!(error.code, satelle_core::ErrorCode::ComputerUseNotReady);
        assert_eq!(error.code.exit_code(), 75);
    }

    #[test]
    fn unsupported_detected_platform_is_typed_artifact_unavailability() {
        let unsupported = map_remote_target_error(
            "office",
            ssh_bootstrap::SshBootstrapError::UnsupportedPlatform {
                platform: "linux-x64-musl".to_string(),
            },
        );

        assert_eq!(
            unsupported.code,
            satelle_core::ErrorCode::HostArtifactUnavailable
        );
        assert_eq!(
            unsupported.details["remote_platform"],
            serde_json::json!("linux-x64-musl")
        );
    }

    #[test]
    fn host_update_metadata_failures_keep_the_typed_error_and_real_host_alias() {
        let missing = verified_host_update_artifact_from_metadata(
            "office",
            "1.2.3",
            ssh_bootstrap::RemoteTarget::DarwinArm64,
            None,
            Err(ssh_bootstrap::SshBootstrapError::verified_release(
                "1.2.3",
                ssh_bootstrap::RemoteTarget::DarwinArm64,
                crate::self_update::SelfUpdateError::ManifestEntryMissing,
            )),
        )
        .expect_err("missing integrity metadata must block the update plan");
        assert_eq!(
            missing.code,
            satelle_core::ErrorCode::HostArtifactUnavailable
        );

        let unreachable = verified_host_update_artifact_from_metadata(
            "office",
            "1.2.3",
            ssh_bootstrap::RemoteTarget::DarwinArm64,
            None,
            Err(ssh_bootstrap::SshBootstrapError::InvalidServiceObservation),
        )
        .expect_err("release metadata transport failures must retain the Host alias");
        assert_eq!(unreachable.code, satelle_core::ErrorCode::HostUnreachable);
        assert_eq!(unreachable.details["host"], serde_json::json!("office"));
    }

    #[test]
    fn only_missing_or_older_hosts_require_release_artifact_metadata() {
        use crate::host_update::HostVersionRelation;

        assert!(host_release_artifact_required(HostVersionRelation::Missing));
        assert!(host_release_artifact_required(
            HostVersionRelation::OlderThanCli
        ));
        assert!(!host_release_artifact_required(
            HostVersionRelation::MatchesCli
        ));
        assert!(!host_release_artifact_required(
            HostVersionRelation::NewerThanCli
        ));
        assert!(!host_release_artifact_required(
            HostVersionRelation::RequiresNewerCli
        ));
    }

    #[test]
    fn repair_recommendations_do_not_resolve_release_artifacts() {
        use crate::host_update::HostVersionRelation;

        assert!(!maintenance_release_artifact_required(
            HostMaintenancePlanKind::Repair,
            HostVersionRelation::OlderThanCli,
            true,
            None,
        ));
        assert!(maintenance_release_artifact_required(
            HostMaintenancePlanKind::Repair,
            HostVersionRelation::OlderThanCli,
            false,
            None,
        ));
        assert!(maintenance_release_artifact_required(
            HostMaintenancePlanKind::Repair,
            HostVersionRelation::Missing,
            false,
            None,
        ));
    }

    #[test]
    fn persistent_repair_inspects_the_service_before_automation() {
        assert!(inspects_persistent_service(
            HostMaintenancePlanKind::Repair,
            Some(satelle_core::SetupMode::Persistent),
        ));
        assert!(!inspects_persistent_service(
            HostMaintenancePlanKind::Repair,
            Some(satelle_core::SetupMode::OnDemand),
        ));
    }

    #[test]
    fn absent_persistent_service_is_a_missing_service_target() {
        let directories = ssh_bootstrap::RemoteUserDirectories::for_tests(
            ssh_bootstrap::RemoteTarget::DarwinArm64,
        );
        let inspection = host_service_inspection_from_executable(
            ssh_bootstrap::RemoteTarget::DarwinArm64,
            &directories,
            "/Users/operator/Library/LaunchAgents/dev.microck.satelle.host.plist",
            None,
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("an absent definition is a known missing service target");

        assert_eq!(inspection.current_version, None);
        assert_eq!(
            inspection.relation_to_cli,
            crate::host_update::HostVersionRelation::Missing
        );
        assert_eq!(
            inspection.destination,
            "/Users/operator/Library/LaunchAgents/dev.microck.satelle.host.plist"
        );
    }

    #[test]
    fn managed_service_with_an_unparseable_version_remains_an_update_target() {
        let directories = ssh_bootstrap::RemoteUserDirectories::for_tests(
            ssh_bootstrap::RemoteTarget::WindowsX64Msvc,
        );
        let inspection = host_service_inspection_from_executable(
            ssh_bootstrap::RemoteTarget::WindowsX64Msvc,
            &directories,
            r"C:\Users\operator\AppData\Local\Satelle\service\host-office.json",
            Some(
                ssh_bootstrap::ManagedServiceExecutableObservation::for_tests(
                    r"C:\Program Files\Satelle\satelle.exe",
                    [0xaa; 32],
                ),
            ),
            env!("CARGO_PKG_VERSION"),
            Some([0xaa; 32]),
        )
        .expect("a verified managed executable remains observable without a versioned cache path");

        assert_eq!(inspection.current_version, None);
        assert_eq!(
            inspection.relation_to_cli,
            crate::host_update::HostVersionRelation::OlderThanCli
        );
    }

    #[test]
    fn current_host_artifact_resolution_does_not_fetch_release_metadata() {
        let artifact = verified_host_update_artifact(
            "remote",
            "1.2.3",
            false,
            ssh_bootstrap::RemoteTarget::LinuxX64Gnu,
            None,
            None,
        )
        .expect("current Host artifact resolution is self-contained");

        assert_eq!(artifact, None);
    }

    #[test]
    fn host_update_artifact_preserves_the_requested_release_version() {
        let artifact = verified_host_update_artifact_from_metadata(
            "remote",
            "9.8.7",
            ssh_bootstrap::RemoteTarget::DarwinArm64,
            Some("/tmp/satelle".to_string()),
            Ok(ssh_bootstrap::ReleaseArtifactMetadata::from_digest(
                [0x4d; 32],
            )),
        )
        .expect("build the version-exact Host artifact");

        assert_eq!(artifact.version, "9.8.7");
        assert_eq!(artifact.remote_platform, "darwin-arm64");
        assert_eq!(artifact.digest, "4d".repeat(32));
    }

    #[test]
    fn setup_report_uses_protocol_incompatible_pre_mutation_daemon_observation() {
        let transport = setup_transport_for_report();
        let observation = transport
            .current_daemon_observation::<satelle_transport::CapabilitiesResponse>(Err(
                DaemonClientError::ProtocolResponseMismatch,
            ))
            .expect("map an authenticated protocol mismatch to the planning observation");

        assert_eq!(observation.current_version, None);
        assert!(!observation.protocol_compatible);
        assert_eq!(observation.validated_host_identity, None);

        let report = transport
            .setup_report_for_target(
                true,
                SetupModeSelection::new(
                    satelle_core::SetupMode::Persistent,
                    satelle_core::daemon_service::SetupModeSource::SetupFlag,
                ),
                ssh_bootstrap::RemoteTarget::WindowsX64Msvc,
                vec!["transport".to_string()],
                DaemonPathOverrides::default(),
                SetupApplication::Planned {
                    existing_token_file: true,
                },
                &observation,
            )
            .expect("build setup report");
        let artifact = report.host_artifact.expect("artifact plan");
        assert_eq!(
            artifact.action,
            satelle_core::daemon_service::DaemonArtifactAction::UpdateProtocolIncompatible
        );
    }

    #[test]
    fn applied_setup_report_retains_pre_mutation_daemon_observation() {
        let transport = setup_transport_for_report();
        let observation = CurrentDaemonArtifactObservation {
            current_version: Some("0.0.0".to_string()),
            minimum_host_version: None,
            protocol_compatible: true,
            codex_update_evidence: None,
            validated_host_identity: None,
        };

        let report = transport
            .setup_report_for_target(
                false,
                SetupModeSelection::new(
                    satelle_core::SetupMode::Persistent,
                    satelle_core::daemon_service::SetupModeSource::SetupFlag,
                ),
                ssh_bootstrap::RemoteTarget::WindowsX64Msvc,
                vec!["transport".to_string()],
                DaemonPathOverrides::default(),
                SetupApplication::AppliedReusableToken,
                &observation,
            )
            .expect("build applied setup report");
        let artifact = report.host_artifact.expect("artifact plan");
        assert_eq!(artifact.current_version.as_deref(), Some("0.0.0"));
        assert_eq!(
            artifact.action,
            satelle_core::daemon_service::DaemonArtifactAction::UpdateOlder
        );
        assert!(!report.applied_actions.is_empty());
        assert!(report.mutated);
    }
}

#[cfg(test)]
#[path = "transport-tests.rs"]
mod tests;
