use crate::{CliFailure, SelectedHost, bootstrap_lock, failure, on_demand_idle_timeout};
use satelle_core::daemon_service::{
    DaemonArtifactPlan, DaemonServicePlan, DaemonServicePlatform, PersistentServiceDecision,
    SetupModeSelection, WindowsServiceConfigV1, WindowsTaskDefinition,
};
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    ApiTokenSource, DaemonPathOverrides, DirectHostBinding, DoctorOptions, DoctorReport, ErrorCode,
    HostSessionsReport, HostSessionsSchemaVersion, LOCAL_DEMO_HOST, SatelleError, SatelleEvent,
    SecureFileError, SessionId, SetupReadinessSummary, SetupReport, SetupRequiredInput,
    SetupSchemaVersion, SshHostBinding, StopResult, TransportKind, TurnId,
    open_or_create_owner_only_directory, open_or_create_owner_only_file,
    persist_new_owner_only_secret_file, read_owner_only_secret_file, read_trusted_ca_bundle_file,
};
use satelle_host::{
    AdmissionCancellation, ApiBearerToken, ApiScopes, DaemonLogPage, HostService, HostStatus,
    LogCursor, LogPageQuery, TurnIntent, TurnOutcome, admission_request_timeout,
};
use satelle_transport::{
    ApiError, ApiErrorCode, DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError,
    TurnRequest,
};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, path::Path};
use uuid::Uuid;

const SSH_DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_DAEMON_LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_DAEMON_LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(100);
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

/// The command surface is intentionally exhaustive. A new transport operation
/// must be implemented or explicitly rejected by every backend.
pub(crate) trait TransportClient {
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
        scope: Option<&str>,
        options: DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError>;
    fn authorize_provider_binding(
        &self,
        authorization: &satelle_core::ProviderBindingAuthorization,
    ) -> Result<satelle_core::PublicResolvedProviderBinding, SatelleError>;
    fn delete_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, SatelleError>;
    fn validate_provider_descriptor(
        &self,
        model_alias: &str,
        provider_alias: &str,
        mode: satelle_core::ProviderAuthValidationMode,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError>;
    fn host_status(&self) -> Result<HostStatus, SatelleError>;
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
    fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError>;
    fn logs(&self, query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError>;
}

struct LocalTransport {
    alias: String,
    service: HostService,
}

impl LocalTransport {
    fn new(alias: String, service: HostService) -> Self {
        Self { alias, service }
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
        scope: Option<&str>,
        options: DoctorOptions,
        provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        self.service
            .doctor_with_provider_intent(&self.alias, scope, options, provider_intent)
    }

    fn validate_provider_descriptor(
        &self,
        model_alias: &str,
        provider_alias: &str,
        mode: satelle_core::ProviderAuthValidationMode,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError> {
        let validation = self.service.validate_provider_descriptor(
            &self.alias,
            model_alias,
            provider_alias,
            mode,
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

    fn delete_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, SatelleError> {
        self.service
            .delete_provider_binding(model_alias, provider_alias)
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        self.service.host_status()
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
        _ => SatelleError::host_unreachable(alias),
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
            Ok(intent)
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
        config: Box<WindowsServiceConfigV1>,
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
    protocol_compatible: bool,
    #[cfg(test)]
    validated_host_identity: Option<String>,
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
                protocol_compatible: true,
                #[cfg(test)]
                validated_host_identity: None,
            }),
        })
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
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))
            },
            Ok,
        )
    }

    fn release_artifact(
        &self,
        target: ssh_bootstrap::RemoteTarget,
    ) -> Result<ssh_bootstrap::ReleaseArtifactMetadata, SatelleError> {
        self.release_artifact.map_or_else(
            || {
                ssh_bootstrap::ReleaseArtifactMetadata::fetch(target)
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

    fn observe_current_daemon_at(
        &self,
        address: std::net::SocketAddr,
        token: ApiBearerToken,
    ) -> Result<CurrentDaemonArtifactObservation, SatelleError> {
        // Keep a zeroizing copy only when first trust may need to reconstruct
        // the non-Clone token for a client bound to the discovered identity.
        let exposed_token = self.requires_first_trust.then(|| token.expose());
        let client = DaemonClient::loopback_with_timeout(
            address,
            token,
            self.binding.expected_host_identity().to_string(),
            SSH_DAEMON_REQUEST_TIMEOUT,
        )
        .map_err(|error| direct_transport_error(&self.alias, error))?;
        let capabilities = match client.capabilities() {
            Err(DaemonClientError::Api { status: _, error })
                if self.requires_first_trust
                    && error.code() == ApiErrorCode::HostIdentityMismatch =>
            {
                // Identity discovery validates the structured mismatch but does
                // not persist trust. The configured credential still has to
                // authenticate the rebound capabilities request.
                let observed_identity =
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
                    exposed_token
                        .as_ref()
                        .expect("first trust retains the configured probe token")
                        .as_str(),
                )
                .map_err(|_| SatelleError::host_unreachable(&self.alias))?;
                let rebound_client = DaemonClient::loopback_with_timeout(
                    address,
                    token,
                    observed_identity,
                    SSH_DAEMON_REQUEST_TIMEOUT,
                )
                .map_err(|error| direct_transport_error(&self.alias, error))?;
                rebound_client.capabilities()
            }
            capabilities => capabilities,
        };
        self.current_daemon_observation_from_capabilities(capabilities)
    }

    fn current_daemon_observation_from_capabilities(
        &self,
        capabilities: Result<satelle_transport::CapabilitiesResponse, DaemonClientError>,
    ) -> Result<CurrentDaemonArtifactObservation, SatelleError> {
        match capabilities {
            Ok(capabilities) => Ok(CurrentDaemonArtifactObservation {
                current_version: Some(capabilities.daemon_version().to_string()),
                protocol_compatible: true,
                #[cfg(test)]
                validated_host_identity: Some(capabilities.host_identity().to_string()),
            }),
            Err(DaemonClientError::CapabilitiesProtocolMismatch) => {
                Ok(CurrentDaemonArtifactObservation {
                    current_version: None,
                    protocol_compatible: false,
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
                    protocol_compatible: false,
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
                    protocol_compatible: true,
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
        let release = self.release_artifact(target)?;
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
            .map_err(|error| {
                SatelleError::config_error(
                    format!("could not construct the Host artifact plan: {error}"),
                    None,
                )
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
            schema_version: SetupSchemaVersion::V1,
            host: self.alias.clone(),
            dry_run,
            status: status.to_string(),
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
            daemon_path_overrides: path_override_entries,
            mutated: applied
                && (service_persistent
                    || matches!(
                        application,
                        SetupApplication::AppliedNewToken
                            | SetupApplication::AppliedPendingActivation
                    )),
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
        match target.service_platform() {
            DaemonServicePlatform::Windows => {
                let task = remote
                    .prepare_windows_task(
                        &self.binding.expected_host_identity().to_string(),
                        artifact,
                    )
                    .map_err(|error| map_ssh_daemon_bootstrap_error(&self.alias, error))?;
                let config =
                    WindowsServiceConfigV1::new("127.0.0.1:3001", daemon_path_overrides)
                        .map_err(|error| SatelleError::config_error(error.to_string(), None))?;
                Ok(PreparedPersistentService::Windows {
                    task: Box::new(task),
                    config: Box::new(config),
                })
            }
            DaemonServicePlatform::Macos => remote
                .launchd_definition(artifact, daemon_path_overrides)
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
            Some(remote.current_windows_task_definition(&expected_host_id)?)
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

fn restart_persistent_service(
    transport: &SshSetupTransport,
    target: ssh_bootstrap::RemoteTarget,
    directories: &ssh_bootstrap::RemoteUserDirectories,
    windows_task: Option<&ssh_bootstrap::VerifiedCurrentWindowsTask>,
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
            DaemonServicePlatform::Windows => remote.restart_current_windows_task(
                windows_task.expect("Windows lifecycle preflight provides an exact task"),
            ),
            DaemonServicePlatform::Macos => remote.restart_launchd(),
            DaemonServicePlatform::Linux => unreachable!("Linux lifecycle is rejected"),
        }
        .map_err(|error| map_ssh_daemon_bootstrap_error(&transport.alias, error))?;
        wait_for_service_observation(
            &transport.alias,
            || match target.service_platform() {
                DaemonServicePlatform::Windows => remote.observe_current_windows_task(
                    windows_task.expect("Windows lifecycle preflight provides an exact task"),
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
    windows_task: Option<&ssh_bootstrap::VerifiedCurrentWindowsTask>,
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
    windows_task: Option<&ssh_bootstrap::VerifiedCurrentWindowsTask>,
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
            DaemonServicePlatform::Windows => remote.stop_current_windows_task(
                windows_task.expect("Windows lifecycle preflight provides an exact task"),
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
            DaemonServicePlatform::Windows => remote.observe_current_windows_task(
                windows_task.expect("Windows lifecycle preflight provides an exact task"),
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
        client.start_persistent_service_action(&operation_id, action_id),
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
        client.complete_persistent_service_action(&operation_id, action_id),
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
        client.finish_persistent_service_maintenance(&operation_id),
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
        .fail_persistent_service_action(&operation_id, action_id, failure_kind)
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
        _scope: Option<&str>,
        _options: DoctorOptions,
        _provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        Err(self.unsupported("doctor"))
    }

    fn validate_provider_descriptor(
        &self,
        _model_alias: &str,
        _provider_alias: &str,
        _mode: satelle_core::ProviderAuthValidationMode,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError> {
        Err(self.unsupported("provider descriptor validation"))
    }

    fn authorize_provider_binding(
        &self,
        _authorization: &satelle_core::ProviderBindingAuthorization,
    ) -> Result<satelle_core::PublicResolvedProviderBinding, SatelleError> {
        Err(self.unsupported("provider binding authorization"))
    }

    fn delete_provider_binding(
        &self,
        _model_alias: &str,
        _provider_alias: &str,
    ) -> Result<bool, SatelleError> {
        Err(self.unsupported("provider binding deletion"))
    }

    fn host_status(&self) -> Result<HostStatus, SatelleError> {
        Err(self.unsupported("host status"))
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

    fn stop(&self, _session_id: &SessionId) -> Result<StopResult, SatelleError> {
        Err(self.unsupported("session stop"))
    }

    fn logs(&self, _query: &LogPageQuery) -> Result<DaemonLogPage, SatelleError> {
        Err(self.unsupported("logs"))
    }
}

impl TransportClient for DirectTransport {
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
        _scope: Option<&str>,
        _options: DoctorOptions,
        _provider_intent: &satelle_host::ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        Err(self.unsupported("doctor"))
    }

    fn validate_provider_descriptor(
        &self,
        model_alias: &str,
        provider_alias: &str,
        mode: satelle_core::ProviderAuthValidationMode,
    ) -> Result<ProviderDescriptorValidationReport, SatelleError> {
        let response = self
            .client
            .validate_provider_descriptor(
                provider_alias,
                model_alias,
                &satelle_transport::ProviderDescriptorValidationRequest::new(mode),
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

    fn delete_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, SatelleError> {
        self.client
            .delete_provider_binding(
                provider_alias,
                model_alias,
                &format!("provider-deletion-{}", Uuid::now_v7()),
            )
            .map(|response| response.deleted())
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

    fn host_sessions(&self, _no_bootstrap: bool) -> Result<HostSessionsReport, SatelleError> {
        // The desktop-session envelope intentionally excludes the daemon version.
        // Read the canonical capabilities envelope instead of reporting the CLI version.
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
            bootstrapped: false,
            bootstrap_actions: Vec::new(),
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
            .map_err(|error| direct_transport_error(&self.alias, error))
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
            let (client, event_client, bootstrap) = bootstrap_ssh_clients(
                &host.alias,
                binding.destination(),
                tunnel.local_addr(),
                &expected_host_identity,
                admission_timeout,
                &host.config,
                bootstrap_scope.expect("tokenless SSH transport requires bootstrap scope"),
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
    confirm_bootstrap_lock(alias, &mut bootstrap_lock)?;
    match client.capabilities() {
        Ok(_) => {
            bootstrap_lock
                .release_unmodified()
                .map_err(|_| SatelleError::host_unreachable(alias))?;
        }
        Err(DaemonClientError::Transport(_)) => {
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
            finish_durable_daemon_launch(alias, &client, &bootstrap_client, &mut bootstrap_lock)?;
        }
        Err(error) => return Err(direct_transport_error(alias, error)),
    }
    let event_client =
        DaemonEventClient::loopback(tunnel_addr, event_token, expected_host_identity)
            .map_err(|error| direct_event_error(alias, error))?;
    Ok((client, event_client))
}

fn finish_durable_daemon_launch(
    alias: &str,
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
    durable_client
        .capabilities()
        .map(|_| ())
        .map_err(|error| direct_transport_error(alias, error))
}

#[cfg(test)]
fn relaunch_durable_daemon_under_lock<T>(
    host: &str,
    mut confirm_lock_ownership: impl FnMut() -> Result<(), SatelleError>,
    mut readiness: impl FnMut() -> Result<T, DaemonClientError>,
    launch: impl FnOnce() -> Result<(), SatelleError>,
) -> Result<T, SatelleError> {
    // Another Controller may have completed startup while this Controller
    // waited for the remote lock. Recheck before launching to avoid a second
    // daemon and retain the lock until the selected daemon is authenticated.
    confirm_lock_ownership()?;
    let ready = match readiness() {
        Ok(ready) => Ok(ready),
        Err(DaemonClientError::Transport(_)) => {
            launch()?;
            wait_for_durable_daemon(host, readiness)
        }
        Err(error) => return Err(direct_transport_error(host, error)),
    }?;
    confirm_lock_ownership()?;
    Ok(ready)
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
    let operation_id = format!("bootstrap-{}", Uuid::now_v7());
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
        DaemonClientError::CapabilitiesProtocolMismatch => {
            api_code_error(host, ApiErrorCode::IncompatibleProtocol)
        }
        DaemonClientError::Transport(_) => SatelleError::host_unreachable(host),
        DaemonClientError::InvalidHostIdentityHeader
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
        ApiErrorCode::ProviderSecretResolutionFailed => provider_api_error(
            ErrorCode::ProviderSecretResolutionFailed,
            "the Host could not resolve provider authentication",
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
        Ok(value) if value == "resolved-secret-canary" => {
            return HostService::resolved_secret_canary_local_demo_for_tests().map_err(failure);
        }
        Ok(_) => {
            return Err(failure(SatelleError::invalid_usage(
                "SATELLE_TEST_SUPPORT_ADAPTER must be exactly 'fake', 'pending', 'failing', 'resolved-secret-canary', or unset",
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

fn transport_for_with_ssh_launch_policy(
    host: &SelectedHost,
    launch_policy: SshDaemonLaunchPolicy,
) -> Result<Box<dyn TransportClient>, CliFailure> {
    match host.config.transport {
        TransportKind::Local => local_host_service(&host.config)
            .map(|service| Box::new(LocalTransport::new(host.alias.clone(), service)) as _),
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
) -> Result<SshHostDiscovery, SatelleError> {
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
    let authenticated_user =
        ssh_bootstrap::RemoteUserDirectories::probe(binding.destination(), target)
            .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))?
            .authenticated_user()
            .to_string();
    let mut bootstrap_lock = acquire_bootstrap_lock(
        &host.alias,
        binding.destination(),
        LockFirstOperationKind::InitialSetup,
    )?;
    confirm_bootstrap_lock(&host.alias, &mut bootstrap_lock)?;
    let mut selected_host_config = host.config.clone();
    selected_host_config.daemon_home = daemon_path_overrides.home.clone();
    selected_host_config.daemon_config_file = daemon_path_overrides.config_file.clone();
    selected_host_config.daemon_state_dir = daemon_path_overrides.state_dir.clone();
    selected_host_config.daemon_cache_dir = daemon_path_overrides.cache_dir.clone();
    selected_host_config.daemon_log_dir = daemon_path_overrides.log_dir.clone();
    let (client, tunnel, _bootstrap, handoff_token) = setup_bootstrap_client(
        &host.alias,
        binding.destination(),
        &probe_identity,
        &host.config,
        &selected_host_config,
        SshBootstrapScope::Admin,
        &mut bootstrap_lock,
    )?;
    let identity = client
        .discover_host_identity()
        .map_err(|error| direct_transport_error(&host.alias, error))?;
    let authenticated_client =
        discovered_bootstrap_client(&host.alias, tunnel.local_addr(), handoff_token, &identity)?;
    let capabilities = authenticated_client
        .capabilities()
        .map_err(|error| direct_transport_error(&host.alias, error))?;
    let desktop_sessions = authenticated_client
        .desktop_sessions()
        .map_err(|error| direct_transport_error(&host.alias, error))?;
    let sessions = HostSessionsReport {
        schema_version: HostSessionsSchemaVersion::V1,
        host: host.alias.clone(),
        detected_platform: capabilities.platform().to_string(),
        connection_mode: "ssh-bootstrap".to_string(),
        bootstrapped: true,
        bootstrap_actions: vec![
            "started an authenticated temporary Host Daemon for first-trust inspection".to_string(),
        ],
        host_daemon_version: capabilities.daemon_version().to_string(),
        sessions: desktop_sessions.sessions().to_vec(),
    };
    complete_bootstrap_handoff(&host.alias, &authenticated_client, &mut bootstrap_lock)?;
    bootstrap_lock
        .release_committed_handoff()
        .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
    Ok(SshHostDiscovery {
        identity,
        authenticated_user,
        sessions,
    })
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
            protocol_compatible: true,
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
    fn setup_report_uses_protocol_incompatible_pre_mutation_daemon_observation() {
        let transport = setup_transport_for_report();
        let observation = transport
            .current_daemon_observation_from_capabilities(Err(
                DaemonClientError::CapabilitiesProtocolMismatch,
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
            protocol_compatible: true,
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
