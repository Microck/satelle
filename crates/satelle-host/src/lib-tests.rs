use super::*;
use crate::codex_capabilities::{
    CapabilityMatrix, CodexVersionEvidence, HostPlatform, Phase0CapabilityEvidence,
    REQUIRED_CODEX_VERSION,
};
use base64::Engine as _;
use satelle_core::session::TurnExecutionMode;
use satelle_core::session::{StopObservation, TurnState, TurnTransition};
use satelle_core::{ErrorCode, SatelleError};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use std::sync::Condvar;
use std::time::Duration;

fn turn_intent(prompt: &str) -> TurnIntent {
    TurnIntent::new(prompt, TurnExecutionMode::Standard).expect("valid test Turn intent")
}

fn doctor_selection(scopes: &[&str]) -> DoctorScopeSelection {
    DoctorScopeSelection::parse(
        &scopes
            .iter()
            .map(|scope| (*scope).to_string())
            .collect::<Vec<_>>(),
    )
    .expect("valid Doctor test scopes")
}

struct ReadyTestTransportProbe;

impl ControllerTransportProbe for ReadyTestTransportProbe {
    fn execute(&self, _context: &DoctorProbeExecutionContext) -> ControllerTransportProbeOutcome {
        ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::ready(None))
    }
}

fn ready_transport() -> ReadyTestTransportProbe {
    ReadyTestTransportProbe
}

struct BlockingTestTransportProbe {
    started: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl ControllerTransportProbe for BlockingTestTransportProbe {
    fn execute(&self, _context: &DoctorProbeExecutionContext) -> ControllerTransportProbeOutcome {
        self.started.send(()).expect("signal transport start");
        self.release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv()
            .expect("release blocking transport");
        ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::ready(None))
    }
}

struct RecordingTestTransportProbe {
    started: std::sync::mpsc::Sender<()>,
}

impl ControllerTransportProbe for RecordingTestTransportProbe {
    fn execute(&self, _context: &DoctorProbeExecutionContext) -> ControllerTransportProbeOutcome {
        self.started.send(()).expect("signal transport start");
        ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::ready(None))
    }
}

#[derive(Clone)]
struct RecordingTurnExtrasAdapter {
    observations: Arc<Mutex<Vec<TurnExtrasObservation>>>,
}

#[derive(Debug, Eq, PartialEq)]
struct TurnExtrasObservation {
    attachments: Vec<AttachmentObservation>,
    timeout_seconds: u32,
}

#[derive(Debug, Eq, PartialEq)]
struct AttachmentObservation {
    path: PathBuf,
    media_type: String,
    size_bytes: usize,
}

#[derive(Clone, Copy)]
#[cfg(unix)]
struct SecretBoundaryAdapter;

#[cfg(unix)]
impl ComputerUseAdapter for SecretBoundaryAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        let binding = provider_intent
            .resolved_provider_binding()
            .expect("Host must inject the authoritative provider binding");
        drop(crate::runtime::resolve_provider_child_secret_for_test(
            binding,
        )?);
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Copy)]
#[cfg(unix)]
struct FailedProviderSmokeAdapter;

#[cfg(unix)]
impl ComputerUseAdapter for FailedProviderSmokeAdapter {
    fn preflight(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        let mut error = SatelleError::computer_use_not_ready();
        error.details.insert(
            "provider_smoke_status".to_string(),
            serde_json::Value::String("failed".to_string()),
        );
        Err(error)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone)]
#[cfg(unix)]
struct TamperingProviderProvisioningAdapter {
    staging_path: PathBuf,
    native_probe_calls: Arc<std::sync::atomic::AtomicUsize>,
    provider_probe_calls: Arc<std::sync::atomic::AtomicUsize>,
    tamper_calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(unix)]
impl ComputerUseAdapter for TamperingProviderProvisioningAdapter {
    fn preflight(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.tamper_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Use real filesystem I/O to make the candidate evidence fail closed.
        // This represents a concurrent local actor rather than mocking the
        // secure-file implementation.
        std::fs::write(&self.staging_path, "tampered-staged-secret")
            .map_err(|_| SatelleError::state_conflict())?;
        Err(SatelleError::computer_use_not_ready())
    }

    fn readiness_cache_key(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ReadinessCacheKey>, SatelleError> {
        Ok(Some(FakeComputerUseAdapter::readiness_contract()?.2))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[cfg(unix)]
impl crate::runtime::ReadinessProbeDriver for TamperingProviderProvisioningAdapter {
    fn run_native_probe(
        &self,
        key: &ReadinessCacheKey,
        _cancellation: &AdmissionCancellation,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> crate::runtime::NativeProbeResult {
        self.native_probe_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let observed_at = time::OffsetDateTime::now_utc();
        crate::runtime::NativeProbeResult::Passed(
            key.evidence(
                format!("native-probe-{}", satelle_core::SessionId::new()),
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .expect("validated readiness key produces native evidence"),
        )
    }

    fn preflight_terminal_with_provider_probe(
        &self,
        host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
        _provider_secret: Option<crate::provider_auth::ResolvedProviderSecret>,
        _cancellation: &AdmissionCancellation,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        self.provider_probe_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.preflight_terminal(host, cached, cached_provider, provider_intent)
    }

    fn observe_readiness_probe(
        &self,
        _subject: &crate::storage::ProbeRecoverySubject,
    ) -> RecoveryObservation {
        RecoveryObservation::Completed
    }
}

#[derive(Clone, Copy)]
#[cfg(unix)]
enum ProviderProvisioningProbeOutcome {
    Ready,
    UpstreamStillActive,
    OutcomeUnknown,
    PersistenceFailure,
}

#[derive(Clone)]
#[cfg(unix)]
struct ClassifiedProviderProvisioningAdapter {
    outcome: ProviderProvisioningProbeOutcome,
    native_probe_calls: Arc<std::sync::atomic::AtomicUsize>,
    provider_probe_calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(unix)]
impl ComputerUseAdapter for ClassifiedProviderProvisioningAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn readiness_cache_key(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ReadinessCacheKey>, SatelleError> {
        Ok(Some(FakeComputerUseAdapter::readiness_contract()?.2))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[cfg(unix)]
impl crate::runtime::ReadinessProbeDriver for ClassifiedProviderProvisioningAdapter {
    fn run_native_probe(
        &self,
        key: &ReadinessCacheKey,
        _cancellation: &AdmissionCancellation,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> crate::runtime::NativeProbeResult {
        self.native_probe_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let observed_at = time::OffsetDateTime::now_utc();
        crate::runtime::NativeProbeResult::Passed(
            key.evidence(
                format!("native-probe-{}", satelle_core::SessionId::new()),
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .expect("validated readiness key produces native evidence"),
        )
    }

    fn preflight_terminal_with_provider_probe(
        &self,
        host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
        _provider_secret: Option<crate::provider_auth::ResolvedProviderSecret>,
        _cancellation: &AdmissionCancellation,
        persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        self.provider_probe_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.outcome {
            ProviderProvisioningProbeOutcome::Ready => {
                self.preflight_terminal(host, cached, cached_provider, provider_intent)
            }
            ProviderProvisioningProbeOutcome::UpstreamStillActive => {
                AdapterPreflight::Cancelled(StopObservation::UpstreamStillActive)
            }
            ProviderProvisioningProbeOutcome::OutcomeUnknown => {
                AdapterPreflight::Cancelled(StopObservation::OutcomeUnknown)
            }
            ProviderProvisioningProbeOutcome::PersistenceFailure => {
                assert!(
                    persist_thread_ref("").is_err(),
                    "invalid upstream identity must fail durable persistence"
                );
                AdapterPreflight::Cancelled(StopObservation::CancellationConfirmed)
            }
        }
    }

    fn observe_readiness_probe(
        &self,
        _subject: &crate::storage::ProbeRecoverySubject,
    ) -> RecoveryObservation {
        RecoveryObservation::Completed
    }
}

/// Keeps phase-aware Doctor coverage isolated from the shared fake's deliberate
/// no-cache behavior, which other admission tests use as part of their setup.
#[derive(Clone, Copy)]
struct DoctorRefreshAdapter;

impl ComputerUseAdapter for DoctorRefreshAdapter {
    fn resolve_provider_binding(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<satelle_core::ResolvedProviderBinding, SatelleError> {
        FakeComputerUseAdapter.resolve_provider_binding(host, provider_intent)
    }

    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn readiness_cache_key(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<Option<ReadinessCacheKey>, SatelleError> {
        Ok(Some(FakeComputerUseAdapter::readiness_contract()?.2))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

impl crate::runtime::ReadinessProbeDriver for DoctorRefreshAdapter {
    fn run_native_probe(
        &self,
        key: &ReadinessCacheKey,
        _cancellation: &AdmissionCancellation,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> crate::runtime::NativeProbeResult {
        let observed_at = time::OffsetDateTime::now_utc();
        crate::runtime::NativeProbeResult::Passed(
            key.evidence(
                format!("native-probe-{}", satelle_core::SessionId::new()),
                observed_at,
                observed_at + time::Duration::minutes(5),
            )
            .expect("validated Doctor readiness key produces valid evidence"),
        )
    }

    fn preflight_terminal_with_provider_probe(
        &self,
        host: &str,
        cached: Option<ReadinessEvidence>,
        cached_provider: Option<ProviderSmokeResult>,
        provider_intent: &ProviderComputerUseIntent,
        _provider_secret: Option<crate::provider_auth::ResolvedProviderSecret>,
        _cancellation: &AdmissionCancellation,
        _persist_thread_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
        _persist_turn_ref: &mut dyn FnMut(&str) -> Result<(), ()>,
    ) -> AdapterPreflight {
        self.preflight_terminal(host, cached, cached_provider, provider_intent)
    }

    fn observe_readiness_probe(
        &self,
        _subject: &crate::storage::ProbeRecoverySubject,
    ) -> RecoveryObservation {
        RecoveryObservation::Completed
    }
}

#[derive(Clone)]
struct HostBusyProviderPreflightAdapter {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl ComputerUseAdapter for HostBusyProviderPreflightAdapter {
    fn preflight(
        &self,
        _host: &str,
        _provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(SatelleError::host_busy(
            LOCAL_DEMO_HOST,
            &satelle_core::SessionId::new(),
        ))
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

impl ComputerUseAdapter for RecordingTurnExtrasAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        self.observations
            .lock()
            .expect("lock observations")
            .push(TurnExtrasObservation {
                attachments: request
                    .attachments()
                    .iter()
                    .map(|attachment| AttachmentObservation {
                        path: attachment.path().to_path_buf(),
                        media_type: attachment.media_type().to_string(),
                        size_bytes: attachment.bytes().len(),
                    })
                    .collect(),
                timeout_seconds: request.execution_policy().timeout_policy().seconds(),
            });
        Ok(ExecuteResult::new(TurnTransition::Completed, Vec::new()))
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Default)]
struct ProviderPreflightGate {
    state: Arc<(Mutex<ProviderPreflightGateState>, Condvar)>,
}

#[derive(Default)]
struct ProviderPreflightGateState {
    started: bool,
    released: bool,
}

impl ProviderPreflightGate {
    fn signal_started_and_wait(&self) -> Result<(), SatelleError> {
        let (state, changed) = &*self.state;
        let mut state = state.lock().expect("provider preflight gate lock");
        state.started = true;
        changed.notify_all();

        let (state, _) = changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !state.released)
            .expect("provider preflight gate wait");
        if !state.released {
            return Err(SatelleError::config_error(
                "provider preflight test gate timed out",
                None,
            ));
        }
        Ok(())
    }

    fn wait_for_started(&self, timeout: Duration) -> bool {
        let (state, changed) = &*self.state;
        let state = state.lock().expect("provider preflight gate lock");
        let (state, _) = changed
            .wait_timeout_while(state, timeout, |state| !state.started)
            .expect("provider preflight start wait");
        state.started
    }

    fn release(&self) {
        let (state, changed) = &*self.state;
        let mut state = state.lock().expect("provider preflight gate lock");
        state.released = true;
        changed.notify_all();
    }
}

#[derive(Clone)]
struct ProviderPreflightCounter {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    gate: Option<ProviderPreflightGate>,
}

impl ComputerUseAdapter for ProviderPreflightCounter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.signal_started_and_wait()?;
        }
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

fn provider_intent_with_missing_descriptor() -> ProviderComputerUseIntent {
    ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("review")
                .expect("valid requested model alias"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("openai")
                .expect("valid requested provider alias"),
        ),
        false,
    )
}

fn provider_descriptor_config(auth_source: Option<String>) -> satelle_core::HostConfig {
    let mut config = satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST].clone();
    config.provider_bindings.insert(
        "openai".to_string(),
        std::collections::BTreeMap::from([(
            "review".to_string(),
            satelle_core::ProviderBindingConfig {
                model: "provider-model".to_string(),
                model_provider: "openai".to_string(),
                endpoint: None,
                auth_source,
                allow_project_selection: false,
            },
        )]),
    );
    config
}

fn service_with_provider_descriptor<A: ComputerUseAdapter>(
    state_root: PathBuf,
    adapter: A,
    auth_source: Option<String>,
) -> HostService {
    let config = provider_descriptor_config(auth_source);
    HostService {
        runtime: RuntimeHandle::new_with_provider_policy(
            Ok(state_root),
            adapter,
            crate::runtime::RuntimeProviderPolicy::from_host_config(&config),
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(&config),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    }
}

#[cfg(unix)]
fn service_with_provider_descriptor_and_readiness_probe<A>(
    state_root: PathBuf,
    adapter: A,
    auth_source: Option<String>,
) -> HostService
where
    A: ComputerUseAdapter + crate::runtime::ReadinessProbeDriver + Clone,
{
    let config = provider_descriptor_config(auth_source);
    HostService {
        runtime: RuntimeHandle::new_with_provider_policy_and_readiness_probe_driver(
            Ok(state_root),
            adapter.clone(),
            adapter,
            crate::runtime::RuntimeProviderPolicy::from_host_config(&config),
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(&config),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    }
}

#[cfg(unix)]
fn provider_file_authorization(path: PathBuf) -> ProviderBindingAuthorization {
    ProviderBindingAuthorization::new("review", "openai", "provider-model", "openai")
        .with_auth_source(satelle_core::ProviderSecretSource::File { path })
        .with_experimental_provider_computer_use(true)
}

#[cfg(unix)]
fn service_with_classified_provider_probe(
    state_root: PathBuf,
    outcome: ProviderProvisioningProbeOutcome,
) -> (
    HostService,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let config = satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST].clone();
    let native_probe_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider_probe_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let adapter = ClassifiedProviderProvisioningAdapter {
        outcome,
        native_probe_calls: Arc::clone(&native_probe_calls),
        provider_probe_calls: Arc::clone(&provider_probe_calls),
    };
    let service = HostService {
        runtime: RuntimeHandle::new_with_readiness_probe_driver(
            Ok(state_root),
            adapter.clone(),
            adapter,
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(&config),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    (service, native_probe_calls, provider_probe_calls)
}

#[cfg(unix)]
fn assert_provider_provisioning_recovery_owned(state: &TestStateDir, operation_id: &str) {
    let connection = rusqlite::Connection::open(state.path().join("satelle.sqlite3"))
        .expect("open Host SQLite state");
    let (phase, lease_state): (String, String) = connection
        .query_row(
            "SELECT journal.phase, lease.lease_state
             FROM provider_secret_provisioning_journal AS journal
             JOIN control_leases AS lease
               ON lease.operation_id = journal.operation_id
              AND lease.provider_probe_ref = journal.provider_probe_ref
             WHERE journal.operation_id = ?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("load retained provider provisioning ownership");
    assert_eq!(phase, "rollback_pending");
    assert_eq!(lease_state, "active");
}

#[cfg(unix)]
#[test]
fn ordinary_post_t0_destination_failure_terminalizes_for_same_daemon_replay() {
    use std::os::unix::fs::symlink;

    let state = TestStateDir::new().expect("temporary Host state");
    let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
    let destination = secret_directory.path().join("provider-token");
    let unrelated_target = secret_directory.path().join("unrelated-target");
    std::fs::write(&unrelated_target, "unrelated").expect("write unrelated symlink target");
    symlink(&unrelated_target, &destination).expect("create unsafe destination symlink");
    let service =
        service_with_provider_descriptor(state.path().to_path_buf(), DoctorRefreshAdapter, None);
    service.initialize_daemon().expect("initialize Host daemon");
    let identity = RequestIdentity::new("provider-secret-planned-failure", "a".repeat(64));
    let authorization = provider_file_authorization(destination);

    let first = service
        .provision_provider_secret(
            LOCAL_DEMO_HOST,
            authorization.clone(),
            Zeroizing::new("candidate-provider-secret".to_string()),
            false,
            &identity,
        )
        .expect_err("unsafe destination must fail after T0");
    let replay = service
        .provision_provider_secret(
            LOCAL_DEMO_HOST,
            authorization,
            Zeroizing::new("candidate-provider-secret".to_string()),
            false,
            &identity,
        )
        .expect_err("same-daemon retry must replay the terminal failure");

    assert_ne!(first.code, ErrorCode::StateConflict);
    assert_eq!(first.code, replay.code);
    assert_eq!(first.message, replay.message);
    assert_eq!(first.recovery_command, replay.recovery_command);
    assert_eq!(first.details, replay.details);
}

#[cfg(unix)]
#[test]
fn existing_provider_secret_requires_typed_overwrite_and_preserves_prior_value() {
    use std::os::unix::fs::PermissionsExt;

    let state = TestStateDir::new().expect("temporary Host state");
    let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
    let destination = secret_directory.path().join("provider-token");
    let prior_secret = "prior-provider-secret";
    std::fs::write(&destination, prior_secret).expect("write prior provider secret");
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
        .expect("make prior provider secret owner-only");
    let service = service_with_provider_descriptor_and_readiness_probe(
        state.path().to_path_buf(),
        DoctorRefreshAdapter,
        None,
    );
    service.initialize_daemon().expect("initialize Host daemon");
    let identity = RequestIdentity::new("provider-secret-overwrite-required", "c".repeat(64));

    let error = service
        .provision_provider_secret(
            LOCAL_DEMO_HOST,
            provider_file_authorization(destination.clone()),
            Zeroizing::new("replacement-provider-secret".to_string()),
            false,
            &identity,
        )
        .expect_err("existing destination requires explicit overwrite authority");

    assert_eq!(error.code, ErrorCode::ProviderSecretOverwriteRequired);
    assert_eq!(
        std::fs::read_to_string(destination).expect("read preserved prior provider secret"),
        prior_secret
    );
}

#[cfg(unix)]
#[test]
fn newline_terminated_provider_secrets_can_be_replaced_atomically() {
    use std::os::unix::fs::PermissionsExt;

    for (suffix, prior_secret) in [
        ("lf", "prior-provider-secret\n"),
        ("crlf", "prior-provider-secret\r\n"),
    ] {
        let state = TestStateDir::new().expect("temporary Host state");
        let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
        std::fs::set_permissions(
            secret_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make provider secret directory owner-only");
        let destination = secret_directory.path().join("provider-token");
        std::fs::write(&destination, prior_secret).expect("write prior provider secret");
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
            .expect("make prior provider secret owner-only");
        let (service, _native_probe_calls, provider_probe_calls) =
            service_with_classified_provider_probe(
                state.path().to_path_buf(),
                ProviderProvisioningProbeOutcome::Ready,
            );
        service.initialize_daemon().expect("initialize Host daemon");
        let identity =
            RequestIdentity::new(format!("provider-secret-newline-{suffix}"), "f".repeat(64));

        let result = service
            .provision_provider_secret(
                LOCAL_DEMO_HOST,
                provider_file_authorization(destination.clone()),
                Zeroizing::new("replacement-provider-secret".to_string()),
                true,
                &identity,
            )
            .expect("replace newline-terminated provider secret");

        assert!(result.overwritten());
        assert_eq!(
            std::fs::read_to_string(&destination).expect("read replacement provider secret"),
            "replacement-provider-secret"
        );
        assert_eq!(
            provider_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let residue = std::fs::read_dir(secret_directory.path())
            .expect("read provider secret directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".staged.") || name.contains(".backup."))
            .collect::<Vec<_>>();
        assert!(
            residue.is_empty(),
            "unexpected replacement residue: {residue:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn provider_secret_publication_preserves_candidate_terminal_line_endings() {
    use std::os::unix::fs::PermissionsExt;

    for (suffix, candidate) in [
        ("lf", "replacement-provider-secret\n"),
        ("crlf", "replacement-provider-secret\r\n"),
    ] {
        let state = TestStateDir::new().expect("temporary Host state");
        let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
        std::fs::set_permissions(
            secret_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make provider secret directory owner-only");
        let destination = secret_directory.path().join("provider-token");
        let (service, _native_probe_calls, provider_probe_calls) =
            service_with_classified_provider_probe(
                state.path().to_path_buf(),
                ProviderProvisioningProbeOutcome::Ready,
            );
        service.initialize_daemon().expect("initialize Host daemon");
        let identity = RequestIdentity::new(
            format!("provider-secret-candidate-{suffix}"),
            "e".repeat(64),
        );

        let result = service
            .provision_provider_secret(
                LOCAL_DEMO_HOST,
                provider_file_authorization(destination.clone()),
                Zeroizing::new(candidate.to_string()),
                false,
                &identity,
            )
            .expect("publish the exact newline-terminated candidate");

        assert!(!result.overwritten());
        assert_eq!(
            std::fs::read(&destination).expect("read published provider secret"),
            candidate.as_bytes()
        );
        assert_eq!(
            provider_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }
}

#[cfg(unix)]
#[test]
fn typed_unknown_provider_outcomes_retain_recovery_ownership() {
    use std::os::unix::fs::PermissionsExt;

    for (suffix, outcome, expected_cancellation) in [
        (
            "upstream-still-active",
            ProviderProvisioningProbeOutcome::UpstreamStillActive,
            "upstream_still_active",
        ),
        (
            "outcome-unknown",
            ProviderProvisioningProbeOutcome::OutcomeUnknown,
            "outcome_unknown",
        ),
        (
            "persistence-failure",
            ProviderProvisioningProbeOutcome::PersistenceFailure,
            "confirmed",
        ),
    ] {
        let state = TestStateDir::new().expect("temporary Host state");
        let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
        std::fs::set_permissions(
            secret_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make provider secret directory owner-only");
        let destination = secret_directory.path().join("provider-token");
        let operation_id = format!("provider-secret-{suffix}");
        let identity = RequestIdentity::new(&operation_id, "d".repeat(64));
        let (service, native_probe_calls, provider_probe_calls) =
            service_with_classified_provider_probe(state.path().to_path_buf(), outcome);
        service.initialize_daemon().expect("initialize Host daemon");

        let failure = service
            .provision_provider_secret(
                LOCAL_DEMO_HOST,
                provider_file_authorization(destination),
                Zeroizing::new("candidate-provider-secret".to_string()),
                false,
                &identity,
            )
            .expect_err("unknown provider outcome must stay recovery-owned");
        assert_eq!(failure.code, ErrorCode::Interrupted);
        assert_eq!(
            failure
                .details
                .get("admission_cancellation")
                .and_then(serde_json::Value::as_str),
            Some(expected_cancellation),
        );
        assert_eq!(
            native_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
        );
        assert_eq!(
            provider_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
        );

        assert_provider_provisioning_recovery_owned(&state, &operation_id);
    }

    let state = TestStateDir::new().expect("temporary Host state");
    let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make provider secret directory owner-only");
    let destination = secret_directory.path().join("provider-token");
    let identity = RequestIdentity::new("provider-secret-ready", "e".repeat(64));
    let (service, native_probe_calls, provider_probe_calls) =
        service_with_classified_provider_probe(
            state.path().to_path_buf(),
            ProviderProvisioningProbeOutcome::Ready,
        );
    service.initialize_daemon().expect("initialize Host daemon");

    service
        .provision_provider_secret(
            LOCAL_DEMO_HOST,
            provider_file_authorization(destination),
            Zeroizing::new("candidate-provider-secret".to_string()),
            false,
            &identity,
        )
        .expect("clean-state provider secret provisioning must complete");
    assert_eq!(
        native_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
    );
    assert_eq!(
        provider_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
    );
}

#[cfg(unix)]
#[test]
fn failed_staged_rollback_retains_pending_journal_and_active_lease() {
    use std::os::unix::fs::PermissionsExt;

    let state = TestStateDir::new().expect("temporary Host state");
    let secret_directory = tempfile::tempdir().expect("temporary provider secret directory");
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make provider secret directory owner-only");
    let destination = secret_directory.path().join("provider-token");
    let identity = RequestIdentity::new("provider-secret-rollback-pending", "b".repeat(64));
    let paths = storage::provider_secret_file_paths(&destination, identity.key())
        .expect("deterministic provider secret paths");
    let native_probe_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider_probe_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tamper_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = service_with_provider_descriptor_and_readiness_probe(
        state.path().to_path_buf(),
        TamperingProviderProvisioningAdapter {
            staging_path: paths.staging().to_path_buf(),
            native_probe_calls: Arc::clone(&native_probe_calls),
            provider_probe_calls: Arc::clone(&provider_probe_calls),
            tamper_calls: Arc::clone(&tamper_calls),
        },
        None,
    );
    service.initialize_daemon().expect("initialize Host daemon");
    let authorization = provider_file_authorization(destination);

    let failure = service
        .provision_provider_secret(
            LOCAL_DEMO_HOST,
            authorization.clone(),
            Zeroizing::new("candidate-provider-secret".to_string()),
            false,
            &identity,
        )
        .expect_err("tampered staging must prevent rollback terminalization");
    assert_eq!(failure.code, ErrorCode::StateConflict);
    assert_eq!(
        native_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
    );
    assert_eq!(
        provider_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
    );
    assert_eq!(tamper_calls.load(std::sync::atomic::Ordering::SeqCst), 1,);

    let connection = rusqlite::Connection::open(state.path().join("satelle.sqlite3"))
        .expect("open Host SQLite state");
    let retained_state: (String, String) = connection
        .query_row(
            "SELECT journal.phase, lease.lease_state
             FROM provider_secret_provisioning_journal AS journal
             JOIN control_leases AS lease
               ON lease.operation_id = journal.operation_id
              AND lease.provider_probe_ref = journal.provider_probe_ref
             WHERE journal.operation_id = ?1",
            [identity.key()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("load retained provider provisioning ownership");
    assert_eq!(
        retained_state,
        ("rollback_pending".to_string(), "active".to_string()),
    );

    let retry = service
        .provision_provider_secret(
            LOCAL_DEMO_HOST,
            authorization,
            Zeroizing::new("candidate-provider-secret".to_string()),
            false,
            &identity,
        )
        .expect_err("pending recovery must not start a second operation");
    assert_eq!(retry.code, ErrorCode::StateConflict);
    assert_eq!(
        native_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
    );
    assert_eq!(
        provider_probe_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
    );
    assert_eq!(tamper_calls.load(std::sync::atomic::Ordering::SeqCst), 1,);
    let retry_retained_state: (String, String) = connection
        .query_row(
            "SELECT journal.phase, lease.lease_state
             FROM provider_secret_provisioning_journal AS journal
             JOIN control_leases AS lease
               ON lease.operation_id = journal.operation_id
              AND lease.provider_probe_ref = journal.provider_probe_ref
             WHERE journal.operation_id = ?1",
            [identity.key()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("reload retained provider provisioning ownership");
    assert_eq!(retry_retained_state, retained_state);
}

fn turn_intent_with_extras(prompt: &str, timeout_seconds: u64) -> TurnIntent {
    let bytes = b"\x89PNG\r\n\x1a\n";
    let digest = Sha256::digest(bytes);
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    turn_intent(prompt)
        .with_turn_execution_timeout_ms(Some(timeout_seconds * 1_000))
        .expect("valid Turn timeout")
        .with_attachments(vec![AttachmentUpload::new(
            "image/png",
            u64::try_from(bytes.len()).expect("image size fits u64"),
            sha256,
            base64::engine::general_purpose::STANDARD.encode(bytes),
        )])
        .expect("valid image attachment")
}

#[test]
fn local_host_run_and_steer_forward_attachments_and_host_clamped_timeout() {
    let state = TestStateDir::new().expect("temporary state directory");
    let observations = Arc::new(Mutex::new(Vec::new()));
    let service = HostService {
        runtime: RuntimeHandle::new(
            Ok(state.path().to_path_buf()),
            RecordingTurnExtrasAdapter {
                observations: Arc::clone(&observations),
            },
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    }
    .with_turn_execution_timeout_for_tests(5);

    let session = service
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent_with_extras("local run extras", 3),
        )
        .expect("run local Turn")
        .session;
    service
        .steer(
            session.session_id(),
            &turn_intent_with_extras("local steer extras", 7),
        )
        .expect("steer local Turn");

    let observations = observations.lock().expect("lock observations");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].timeout_seconds, 3);
    assert_eq!(observations[1].timeout_seconds, 5);
    for observation in observations.iter() {
        assert_eq!(observation.attachments.len(), 1);
        let attachment = &observation.attachments[0];
        assert_eq!(attachment.media_type, "image/png");
        assert_eq!(attachment.size_bytes, 8);
        assert!(
            attachment
                .path
                .starts_with(state.path().join("attachments"))
        );
        assert!(
            attachment
                .path
                .file_name()
                .expect("staged image path has a file name")
                .to_string_lossy()
                .starts_with("satelle-image-")
        );
        assert!(
            !attachment.path.exists(),
            "terminal run and steer must both delete staged images"
        );
    }
    assert_ne!(
        observations[0].attachments[0].path, observations[1].attachments[0].path,
        "run and steer must receive separate generated staging names"
    );
}

#[test]
fn unsupported_image_capability_rejects_direct_run_and_steer_before_admission() {
    let state = TestStateDir::new().expect("temporary state directory");
    let observations = Arc::new(Mutex::new(Vec::new()));
    let service = HostService {
        runtime: RuntimeHandle::new(
            Ok(state.path().to_path_buf()),
            RecordingTurnExtrasAdapter {
                observations: Arc::clone(&observations),
            },
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: false,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    let image_intent = turn_intent_with_extras("unsupported image", 3);

    let run_failure = service
        .run(LOCAL_DEMO_HOST, &image_intent)
        .expect_err("attached image run must be rejected");
    assert!(matches!(
        run_failure,
        TurnAdmissionFailure::NotAdmitted(error) if error.code == ErrorCode::InvalidUsage
    ));
    let detached_run_error = service
        .run_detached(LOCAL_DEMO_HOST, &image_intent)
        .expect_err("detached image run must be rejected");
    assert_eq!(detached_run_error.code, ErrorCode::InvalidUsage);
    assert!(
        !state.path().join("attachments").exists(),
        "unsupported images must be rejected before the attachment store opens"
    );
    assert!(observations.lock().expect("lock observations").is_empty());

    let initial = service
        .run(LOCAL_DEMO_HOST, &turn_intent("image-free run"))
        .expect("image-free run remains supported")
        .session;
    let steer_failure = service
        .steer(initial.session_id(), &image_intent)
        .expect_err("attached image steer must be rejected");
    assert!(matches!(
        steer_failure,
        TurnAdmissionFailure::NotAdmitted(error) if error.code == ErrorCode::InvalidUsage
    ));
    let detached_steer_error = service
        .steer_detached(initial.session_id(), &image_intent)
        .expect_err("detached image steer must be rejected");
    assert_eq!(detached_steer_error.code, ErrorCode::InvalidUsage);

    let status = service
        .status(initial.session_id())
        .expect("seed Session remains readable");
    assert_eq!(status.turns().len(), 1);
    assert_eq!(observations.lock().expect("lock observations").len(), 1);
}

#[test]
fn admission_request_timeout_tracks_both_configured_readiness_phases() {
    let mut config = satelle_core::SatelleConfig::defaults()
        .hosts
        .remove(LOCAL_DEMO_HOST)
        .expect("built-in Host config exists");
    assert_eq!(
        admission_request_timeout(&config),
        std::time::Duration::from_secs(250)
    );

    config.timeouts = Some(satelle_core::TimeoutConfig {
        native_readiness: satelle_core::ExplicitDuration::parse("2s"),
        provider_smoke_test: satelle_core::ExplicitDuration::parse("3s"),
        turn_execution: None,
    });
    assert_eq!(
        admission_request_timeout(&config),
        std::time::Duration::from_secs(15)
    );
}

#[test]
fn configured_remote_alias_reaches_execution_and_session_keeps_host_identity() {
    const REMOTE_HOST_ALIAS: &str = "studio-workstation";

    let state = TestStateDir::new().expect("temporary state directory should exist");
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };

    let outcome = service
        .run(
            REMOTE_HOST_ALIAS,
            &turn_intent("exercise configured remote Host routing"),
        )
        .expect("the Host Daemon should accept its validated configured alias");
    assert!(
        outcome
            .events
            .iter()
            .filter(|event| event.event_type() != satelle_core::EventType::ProviderSmoke)
            .all(|event| event.host() == REMOTE_HOST_ALIAS),
        "the configured alias must reach adapter execution events"
    );
    let public_session = outcome.session;
    assert_eq!(
        service
            .status(public_session.session_id())
            .expect("the admitted Session should remain publicly readable"),
        public_session
    );

    // The Controller-local alias selects this daemon, but durable ownership
    // remains bound to the daemon's stable Host Identity.
    drop(service);
    let (storage, _) = crate::storage::Storage::open(state.path())
        .expect("the authoritative Host store should reopen");
    let stored_session = storage
        .load_session(public_session.session_id())
        .expect("the admitted Session should be readable from storage")
        .expect("the admitted Session should be durable");
    assert_eq!(
        stored_session.host_identity(),
        &storage
            .host_identity()
            .expect("the Host Identity should be durable")
    );
    assert_eq!(stored_session.to_public(), public_session);
}

#[test]
fn configured_remote_alias_is_accepted_by_host_diagnostics() {
    const REMOTE_HOST_ALIAS: &str = "studio-workstation";

    let state = TestStateDir::new().expect("temporary state directory should exist");
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    let doctor = service
        .doctor(
            REMOTE_HOST_ALIAS,
            &doctor_selection(&[]),
            DoctorOptions::default(),
        )
        .expect("doctor should diagnose the already-routed Host alias");
    assert_eq!(doctor.host, REMOTE_HOST_ALIAS);

    let sessions = service
        .host_sessions(REMOTE_HOST_ALIAS, false)
        .expect("desktop Session discovery should accept the routed Host alias");
    assert_eq!(sessions.host, REMOTE_HOST_ALIAS);
    assert_eq!(
        sessions.bootstrap_actions,
        ["direct studio-workstation Host daemon already reachable"]
    );

    let setup = service
        .setup(
            REMOTE_HOST_ALIAS,
            true,
            "full".to_string(),
            Vec::new(),
            DaemonPathOverrides::default(),
        )
        .expect("setup planning should accept the routed Host alias");
    assert_eq!(setup.host, REMOTE_HOST_ALIAS);
}

#[derive(Clone, Copy)]
struct FailingExecutionAdapter;

impl ComputerUseAdapter for FailingExecutionAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &crate::ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        Err(SatelleError::host_unreachable(LOCAL_DEMO_HOST))
    }

    fn observe_stop(&self, subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[test]
fn unsupported_or_unproven_production_execution_is_blocked_without_state_admission() {
    for (name, evidence, control_plane_admission) in [
        (
            "unsupported-linux-host",
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: HostPlatform::Linux,
                capabilities: CapabilityMatrix::unproven(),
            },
            codex_capabilities::ControlPlaneAdmission::not_applicable(),
        ),
        (
            "supported-windows-host-with-unproven-native-readiness",
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Detected {
                    version: REQUIRED_CODEX_VERSION,
                },
                host_platform: HostPlatform::Windows,
                capabilities: CapabilityMatrix::unproven(),
            },
            codex_capabilities::ControlPlaneAdmission::not_applicable(),
        ),
    ] {
        let state = TestStateDir::new().expect("temporary state directory should exist");
        let mut production_snapshot = capability_snapshot(evidence, 7);
        production_snapshot.control_plane_admission = control_plane_admission;
        let snapshot = Arc::new(RwLock::new(production_snapshot));
        let adapter = ProductionComputerUseAdapter::new(
            Arc::clone(&snapshot),
            Ok(state.path().join("codex-app-server-work")),
        );
        let service = HostService {
            runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: crate::configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::Production { snapshot },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        };
        let session_id = SessionId::new();

        let assert_blocked_error = |operation: &str, error: &SatelleError| {
            assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
            assert!(
                error.details.is_empty(),
                "{name} {operation} must remain a native readiness failure"
            );

            let serialized =
                serde_json::to_string(error).expect("closed capability blocker must serialize");
            assert!(!serialized.contains("PRIVATE_PRODUCTION_PROMPT"));
            assert!(!serialized.contains("fake"));
        };

        for (operation, failure) in [
            (
                "run",
                service
                    .run(LOCAL_DEMO_HOST, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("attached run must be blocked"),
            ),
            (
                "steer",
                service
                    .steer(&session_id, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("attached steer must be blocked before session lookup"),
            ),
        ] {
            assert!(matches!(failure, TurnAdmissionFailure::NotAdmitted(_)));
            assert_blocked_error(operation, failure.error());
        }

        for (operation, error) in [
            (
                "run",
                service
                    .run_detached(LOCAL_DEMO_HOST, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("detached run must be blocked"),
            ),
            (
                "steer",
                service
                    .steer_detached(&session_id, &turn_intent("PRIVATE_PRODUCTION_PROMPT"))
                    .expect_err("detached steer must be blocked before session lookup"),
            ),
        ] {
            assert_blocked_error(operation, &error);
        }

        let stop_error = service
            .stop(&session_id)
            .expect_err("stop should remain available without adapter readiness");
        assert_eq!(stop_error.code, ErrorCode::SessionNotFound);

        let status_error = service
            .status(&session_id)
            .expect_err("read-only status should open storage without adapter readiness");
        assert_eq!(status_error.code, ErrorCode::SessionNotFound);

        let runtime_status = service
            .daemon_runtime_status()
            .expect("blocked production execution must leave runtime status readable");
        assert_eq!(
            (
                runtime_status.session_count(),
                runtime_status.active_turn_count(),
                runtime_status.recovery_pending_turn_count(),
            ),
            (0, 0, 0),
            "{name} must not durably admit a Session or Turn"
        );
    }
}

#[test]
fn blocked_control_plane_precedes_capability_and_live_desktop_checks() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let evidence = Phase0CapabilityEvidence {
        codex_version: CodexVersionEvidence::Detected {
            version: REQUIRED_CODEX_VERSION,
        },
        host_platform: HostPlatform::Windows,
        capabilities: CapabilityMatrix::unproven(),
    };
    let mut production_snapshot = capability_snapshot(evidence, 7);
    production_snapshot.control_plane_admission =
        codex_capabilities::ControlPlaneAdmission::unavailable(
            satelle_core::ControlPlaneFailureReason::HandshakeUnavailable,
        );
    let adapter = ProductionComputerUseAdapter::new(
        Arc::new(RwLock::new(production_snapshot)),
        Ok(state.path().join("codex-app-server-work")),
    );
    let intent = turn_intent("PRIVATE_PRODUCTION_PROMPT");

    let error = match adapter.preflight(LOCAL_DEMO_HOST, intent.provider_intent()) {
        Ok(_) => panic!("a blocked control plane must stop before live readiness"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
}

#[test]
fn attached_adapter_failures_return_exact_durable_run_and_steer_handles() {
    let run_state = TestStateDir::new().expect("temporary run state directory should exist");
    let run_service = HostService {
        runtime: RuntimeHandle::new(Ok(run_state.path().to_path_buf()), FailingExecutionAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    let run_failure = run_service
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_FAIL_AFTER_RUN_COMMIT"),
        )
        .expect_err("the deterministic adapter must fail after run admission");
    let (run_failure_session, run_turn_id) = match run_failure {
        TurnAdmissionFailure::Admitted {
            session, turn_id, ..
        } => (*session, turn_id),
        other => panic!("postcommit run failure had the wrong phase: {other:?}"),
    };
    let run_session_id = run_failure_session.session_id().clone();
    let run_status = run_service
        .status(&run_session_id)
        .expect("the admitted run must remain readable");
    let durable_run = run_status
        .turns()
        .last()
        .expect("the admitted run must retain its Turn");
    assert_eq!(durable_run.turn_id(), &run_turn_id);
    assert_eq!(durable_run.state(), TurnState::RecoveryPending);
    assert_eq!(run_failure_session, run_status);

    let steer_state = TestStateDir::new().expect("temporary steer state directory should exist");
    let seeded = HostService {
        runtime: RuntimeHandle::new(Ok(steer_state.path().to_path_buf()), FakeComputerUseAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    let initial = seeded
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_SUCCESSFUL_INITIAL_RUN"),
        )
        .expect("the initial run should complete");
    let steer_session_id = initial.session.session_id().clone();
    drop(seeded);
    let steer_service = HostService {
        runtime: RuntimeHandle::new(
            Ok(steer_state.path().to_path_buf()),
            FailingExecutionAdapter,
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    let steer_failure = steer_service
        .steer(
            &steer_session_id,
            &turn_intent("PRIVATE_FAIL_AFTER_STEER_COMMIT"),
        )
        .expect_err("the deterministic adapter must fail after steer admission");
    let steer_turn_id = match steer_failure {
        TurnAdmissionFailure::Admitted {
            session, turn_id, ..
        } => {
            assert_eq!(session.session_id(), &steer_session_id);
            assert_eq!(session.turns().len(), 2);
            assert_eq!(
                session.turns().last().map(|turn| turn.state()),
                Some(TurnState::RecoveryPending)
            );
            turn_id
        }
        other => panic!("postcommit steer failure had the wrong phase: {other:?}"),
    };
    let steer_status = steer_service
        .status(&steer_session_id)
        .expect("the admitted steer must remain readable");
    assert_eq!(steer_status.turns().len(), 2);
    let durable_steer = steer_status
        .turns()
        .last()
        .expect("the admitted steer must retain its Turn");
    assert_eq!(durable_steer.turn_id(), &steer_turn_id);
    assert_eq!(durable_steer.state(), TurnState::RecoveryPending);
}

#[test]
fn refreshed_production_snapshot_updates_admission_surfaces_but_not_desktop_discovery() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let initial = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Detected {
                version: REQUIRED_CODEX_VERSION,
            },
            host_platform: HostPlatform::Windows,
            capabilities: CapabilityMatrix::unproven(),
        },
        7,
    );
    let snapshot = Arc::new(RwLock::new(initial));
    let adapter = ProductionComputerUseAdapter::new(
        Arc::clone(&snapshot),
        Ok(state.path().join("codex-app-server-work")),
    );
    let shared_snapshot = Arc::clone(&snapshot);
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::Production { snapshot },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    let clone = service.clone();

    let initial_error = service
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_BEFORE_CONTROL_PLANE_REFRESH"),
        )
        .expect_err("the supported snapshot should reach the native execution blocker");
    assert!(matches!(
        initial_error,
        TurnAdmissionFailure::NotAdmitted(_)
    ));
    assert_eq!(initial_error.error().code, ErrorCode::ComputerUseNotReady);
    assert!(
        service
            .daemon_runtime_capabilities()
            .unwrap()
            .codex_runtime()
    );

    let mut refreshed = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Missing,
            host_platform: HostPlatform::Windows,
            capabilities: CapabilityMatrix::unproven(),
        },
        11,
    );
    refreshed.control_plane_admission = codex_capabilities::ControlPlaneAdmission::unavailable(
        satelle_core::ControlPlaneFailureReason::RuntimeMissing,
    );
    replace_production_snapshot(&shared_snapshot, refreshed)
        .expect("doctor refresh should atomically replace the shared snapshot");

    let refreshed_error = clone
        .run(
            LOCAL_DEMO_HOST,
            &turn_intent("PRIVATE_AFTER_CONTROL_PLANE_REFRESH"),
        )
        .expect_err("the cloned service must use refreshed execution readiness");
    assert!(matches!(
        refreshed_error,
        TurnAdmissionFailure::NotAdmitted(_)
    ));
    assert_eq!(
        refreshed_error.error().code,
        ErrorCode::IncompatibleControlPlane
    );
    assert!(!clone.daemon_runtime_capabilities().unwrap().codex_runtime());
    let sessions = clone
        .host_sessions(LOCAL_DEMO_HOST, false)
        .expect("desktop discovery must remain available for readiness diagnosis");
    assert_eq!(sessions.schema_version, HostSessionsSchemaVersion::V1);
    assert_eq!(sessions.host, LOCAL_DEMO_HOST);
    let doctor = clone
        .doctor(
            LOCAL_DEMO_HOST,
            &doctor_selection(&["codex"]),
            DoctorOptions::default(),
        )
        .expect("non-refresh doctor must read the refreshed snapshot");
    assert!(doctor.findings.iter().any(|finding| {
        finding
            .evidence
            .contains(&"reason=missing_codex_runtime".to_string())
    }));
}

fn production_doctor_test_service(state: &TestStateDir) -> HostService {
    let evidence = Phase0CapabilityEvidence {
        codex_version: CodexVersionEvidence::Detected {
            version: REQUIRED_CODEX_VERSION,
        },
        host_platform: HostPlatform::Linux,
        capabilities: CapabilityMatrix::unproven(),
    };
    let snapshot = Arc::new(RwLock::new(capability_snapshot(evidence, 1)));
    let adapter = ProductionComputerUseAdapter::new(
        Arc::clone(&snapshot),
        Ok(state.path().join("codex-app-server-work")),
    );
    HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), adapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::Production { snapshot },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    }
}

#[test]
fn queued_probe_receives_its_full_timeout_after_resource_admission() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let service = production_doctor_test_service(&state);
    let selection = doctor_selection(&["transport"]);
    let intent = ProviderComputerUseIntent::host_default();
    let (first_started_tx, first_started_rx) = std::sync::mpsc::channel();
    let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
    let first_service = service.clone();
    let first_selection = selection.clone();
    let first_intent = intent.clone();
    let (first_result_tx, first_result_rx) = std::sync::mpsc::channel();
    let first = std::thread::spawn(move || {
        let report = first_service.doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &first_selection,
            Arc::new(BlockingTestTransportProbe {
                started: first_started_tx,
                release: Mutex::new(release_first_rx),
            }),
            DoctorOptions::new(false, Some(Duration::from_millis(500)))
                .expect("positive timeout is valid"),
            &first_intent,
        );
        first_result_tx
            .send(report)
            .expect("send first Doctor result");
    });
    first_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first transport started");

    let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
    let (second_result_tx, second_result_rx) = std::sync::mpsc::channel();
    let second_service = service.clone();
    let second_selection = selection.clone();
    let second_intent = intent.clone();
    let second = std::thread::spawn(move || {
        let report = second_service.doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &second_selection,
            Arc::new(RecordingTestTransportProbe {
                started: second_started_tx,
            }),
            DoctorOptions::new(false, Some(Duration::from_millis(100)))
                .expect("positive timeout is valid"),
            &second_intent,
        );
        second_result_tx
            .send(report)
            .expect("send second Doctor result");
    });

    assert!(
        second_result_rx
            .recv_timeout(Duration::from_millis(60))
            .is_err(),
        "queue wait must not consume the second probe's own timeout"
    );
    release_first_tx
        .send(())
        .expect("release the first active transport");
    first_result_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first Doctor completes")
        .expect("first Doctor succeeds");
    first.join().expect("join first Doctor");
    second_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("second transport starts after the resource is released");
    let second_report = second_result_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("second Doctor completes")
        .expect("second Doctor succeeds");
    second.join().expect("join second Doctor");
    assert_eq!(
        second_report
            .probe_results
            .iter()
            .find(|probe| probe.scope == "transport")
            .expect("second transport result")
            .status,
        "passed"
    );
}

#[test]
fn cleanup_only_probe_bounds_later_admission_with_a_typed_failure() {
    let state = TestStateDir::new().expect("temporary state directory should exist");
    let service = production_doctor_test_service(&state);
    let selection = doctor_selection(&["transport"]);
    let intent = ProviderComputerUseIntent::host_default();
    let options = DoctorOptions::new(false, Some(Duration::from_millis(100)))
        .expect("positive timeout is valid");
    let (first_started_tx, first_started_rx) = std::sync::mpsc::channel();
    let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();
    let first = service
        .doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &selection,
            Arc::new(BlockingTestTransportProbe {
                started: first_started_tx,
                release: Mutex::new(release_first_rx),
            }),
            options,
            &intent,
        )
        .expect("the first Doctor call publishes its typed probe timeout");
    first_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("first transport started");
    assert_eq!(
        first
            .probe_results
            .iter()
            .find(|probe| probe.scope == "transport")
            .expect("first transport result")
            .status,
        "timed_out"
    );

    let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
    let (second_result_tx, second_result_rx) = std::sync::mpsc::channel();
    let second_service = service.clone();
    let second_selection = selection.clone();
    let second_intent = intent.clone();
    let second = std::thread::spawn(move || {
        let report = second_service.doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &second_selection,
            Arc::new(RecordingTestTransportProbe {
                started: second_started_tx,
            }),
            options,
            &second_intent,
        );
        second_result_tx
            .send(report)
            .expect("send blocked Doctor result");
    });
    let error = second_result_rx
        .recv_timeout(Duration::from_millis(250))
        .expect("cleanup-only ownership must bound later admission")
        .expect_err("cleanup-only ownership must bound later admission");
    assert_eq!(error.code, ErrorCode::StateConflict);
    assert!(
        second_started_rx.try_recv().is_err(),
        "the blocked probe must not start before cleanup releases its lock"
    );
    release_first_tx
        .send(())
        .expect("release the cleanup-only transport");
    second.join().expect("join blocked Doctor");
}

#[test]
fn production_doctor_uses_blocked_probe_results_and_closed_evidence() {
    let snapshot = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Malformed,
            host_platform: HostPlatform::Windows,
            capabilities: CapabilityMatrix::unproven(),
        },
        17,
    );
    let report = production_doctor_report(LOCAL_DEMO_HOST, Some("codex"), &snapshot);
    let serialized = serde_json::to_string(&report).expect("doctor report should serialize");

    assert!(!report.ready);
    assert_eq!(report.duration_ms, 17);
    assert_eq!(report.probe_results[0].duration_ms, 17);
    assert!(
        report
            .probe_results
            .iter()
            .all(|probe| probe.status == "blocked")
    );
    assert!(report.findings.iter().any(|finding| {
        finding
            .evidence
            .contains(&"reason=malformed_codex_version".to_string())
    }));
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.scope == "codex")
    );
    assert!(!serialized.contains("fake"));
    assert!(!serialized.contains("codex-cli"));
}

#[test]
fn production_doctor_identifies_the_missing_private_native_execution_path() {
    let mut capabilities = CapabilityMatrix::unproven();
    capabilities.handshake = codex_capabilities::CapabilityEvidence::new(
        codex_capabilities::EvidenceSurface::Stable,
        codex_capabilities::LiveProofStatus::NotRequired,
    );
    let snapshot = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Detected {
                version: REQUIRED_CODEX_VERSION,
            },
            host_platform: HostPlatform::Windows,
            capabilities,
        },
        19,
    );

    let report = production_doctor_report(LOCAL_DEMO_HOST, Some("computer-use"), &snapshot);
    let finding = report
        .findings
        .iter()
        .find(|finding| {
            finding
                .evidence
                .contains(&"reason=native_execution_path_unavailable".to_string())
        })
        .expect("doctor must identify an absent native path on the private app-server");

    assert_eq!(finding.scope, "computer-use");
    assert_eq!(
        finding.summary,
        "the private Codex app-server exposes no stable native Computer Use path"
    );
    assert_eq!(finding.readiness_impact, "blocked");
    assert!(!report.ready);
}

#[test]
fn production_doctor_filters_requested_scopes_without_relabeling_blockers() {
    let snapshot = capability_snapshot(
        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Malformed,
            host_platform: HostPlatform::Linux,
            capabilities: CapabilityMatrix::unproven(),
        },
        23,
    );

    let transport = production_doctor_report(LOCAL_DEMO_HOST, Some("transport"), &snapshot);
    assert!(transport.ready);
    assert_eq!(transport.scopes, ["transport"]);
    assert!(transport.findings.is_empty());
    assert_eq!(transport.probe_results[0].status, "passed");
    assert_eq!(transport.probe_results[0].duration_ms, 0);
    let blocked_transport = DoctorTransportObservation::blocked(DoctorFinding {
        finding_id: "transport.selected.failed".to_string(),
        scope: "transport".to_string(),
        severity: "error".to_string(),
        fixability: DoctorFixability::ManualActionRequired,
        readiness_impact: "blocked".to_string(),
        summary: "the selected transport failed its live observation".to_string(),
        evidence: vec!["reason=selected_transport_failed".to_string()],
        recovery_command: None,
    });
    let transport_selection = doctor_selection(&["transport"]);
    let blocked_transport_report = production_doctor_report_with_selection(
        LOCAL_DEMO_HOST,
        &transport_selection,
        &blocked_transport,
        DoctorOptions::default(),
        &snapshot,
    );
    assert!(!blocked_transport_report.ready);
    assert_eq!(blocked_transport_report.probe_results[0].status, "blocked");
    assert_eq!(
        blocked_transport_report.findings[0].finding_id,
        "transport.selected.failed"
    );

    let provider = production_doctor_report(LOCAL_DEMO_HOST, Some("provider"), &snapshot);
    assert!(!provider.ready);
    assert_eq!(provider.scopes, ["provider"]);
    assert_eq!(provider.findings.len(), 1);
    assert_eq!(provider.findings[0].scope, "provider");

    let config = production_doctor_report(LOCAL_DEMO_HOST, Some("config"), &snapshot);
    assert!(config.ready);
    assert_eq!(config.scopes, ["config"]);
    assert!(config.findings.is_empty());
    assert_eq!(config.probe_results[0].status, "passed");

    let codex = production_doctor_report(LOCAL_DEMO_HOST, Some("codex"), &snapshot);
    assert!(!codex.ready);
    assert!(codex.findings.is_empty());
    assert_eq!(codex.probe_results[0].status, "blocked");
    assert_eq!(codex.probe_results[0].dependency_status, "blocked");

    let computer_use = production_doctor_report(LOCAL_DEMO_HOST, Some("computer-use"), &snapshot);
    assert!(!computer_use.ready);
    assert!(
        computer_use
            .findings
            .iter()
            .all(|finding| finding.scope == "computer-use")
    );
    assert!(!computer_use.findings.iter().any(|finding| {
        finding
            .evidence
            .contains(&"reason=malformed_codex_version".to_string())
    }));

    let all = production_doctor_report(LOCAL_DEMO_HOST, Some("all"), &snapshot);
    assert!(!all.ready);
    assert_eq!(
        all.scopes,
        ["codex", "computer-use", "config", "provider", "transport"]
    );
    assert!(all.findings.iter().all(|finding| finding.scope != "all"));
}

#[test]
fn doctor_provider_refresh_updates_cache_without_admitting_prompt_work() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let config = satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST].clone();
    let service = HostService {
        runtime: RuntimeHandle::new_with_readiness_probe_driver(
            Ok(state.path().to_path_buf()),
            DoctorRefreshAdapter,
            DoctorRefreshAdapter,
        ),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(&config),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    service
        .runtime
        .authorize_provider_binding(&satelle_core::ResolvedProviderBinding::from_authorization(
            satelle_core::ProviderBindingAuthorization::new(
                "provider-doctor-model",
                "provider-doctor-binding",
                "provider-doctor-model",
                "provider-doctor-binding",
            )
            .with_auth_source(satelle_core::ProviderSecretSource::Environment {
                variable: "SATELLE_PROVIDER_DOCTOR_TOKEN".to_string(),
            })
            .with_experimental_provider_computer_use(true),
            satelle_core::ProviderBindingSource::UserConfig,
        ))
        .expect("authorize the persisted UserConfig provider binding");
    let intent = ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("provider-doctor-model")
                .expect("valid model"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("provider-doctor-binding")
                .expect("valid provider"),
        ),
        true,
    )
    .with_experimental_provider_computer_use(true);

    let report = service
        .doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &doctor_selection(&["provider"]),
            Arc::new(ready_transport()),
            DoctorOptions::new(true, Some(std::time::Duration::from_secs(5)))
                .expect("positive timeout"),
            &intent,
        )
        .expect("provider doctor refresh should complete");

    assert!(report.ready);
    assert!(report.changed);
    assert_eq!(report.cache_updates, ["provider_smoke"]);
    assert_eq!(report.probe_results.len(), 1);
    assert_eq!(report.probe_results[0].probe_id, "provider.smoke.refresh");
    assert_eq!(report.probe_results[0].cache_status, "refreshed");
    assert!(
        report.findings[0]
            .evidence
            .contains(&"source=refresh".to_string())
    );
    let default_report = service
        .doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &doctor_selection(&[]),
            Arc::new(ready_transport()),
            DoctorOptions::new(true, Some(std::time::Duration::from_secs(5)))
                .expect("positive timeout"),
            &intent,
        )
        .expect("default all-scope doctor refresh should include provider refresh");
    assert!(
        default_report
            .cache_updates
            .iter()
            .any(|update| update == "provider_smoke")
    );
    assert!(default_report.probe_results.iter().any(|probe| {
        probe.probe_id == "provider.smoke.refresh" && probe.cache_status == "refreshed"
    }));
    assert_eq!(service.host_status().unwrap().sessions, 0);
}

#[test]
fn endpointless_auth_sources_are_reserved_for_builtin_openai() {
    let openai = satelle_core::ProviderBindingAuthorization::new(
        "openai-model",
        "openai-provider",
        "gpt-test",
        "openai",
    )
    .with_auth_source(satelle_core::ProviderSecretSource::Environment {
        variable: "SATELLE_OPENAI_API_KEY".to_string(),
    });
    validate_provider_binding_authorization(&openai)
        .expect("the built-in OpenAI provider may use a Host auth source");

    let custom = satelle_core::ProviderBindingAuthorization::new(
        "custom-model",
        "custom-provider",
        "custom-model",
        "custom-provider",
    )
    .with_auth_source(satelle_core::ProviderSecretSource::Environment {
        variable: "SATELLE_CUSTOM_PROVIDER_API_KEY".to_string(),
    })
    .with_experimental_provider_computer_use(true);
    let error = validate_provider_binding_authorization(&custom)
        .expect_err("a custom provider auth source requires a custom endpoint");
    assert!(
        error
            .message
            .contains("supported only for the built-in OpenAI provider")
    );
}

#[test]
fn implicit_codex_default_alias_pair_is_reserved_from_provider_authorization() {
    let reserved = satelle_core::ProviderBindingAuthorization::new(
        DEFAULT_MODEL_BINDING,
        DEFAULT_PROVIDER_BINDING,
        "gpt-test",
        "openai",
    );
    let error = validate_provider_binding_authorization(&reserved)
        .expect_err("the implicit Codex default pair must not name an exact binding");
    assert_eq!(error.code, satelle_core::ErrorCode::ConfigError);
    assert!(
        error
            .message
            .contains("reserved for implicit Codex defaults")
    );

    for (model_alias, provider_alias) in [
        (DEFAULT_MODEL_BINDING, "openai"),
        ("review", DEFAULT_PROVIDER_BINDING),
    ] {
        validate_provider_binding_authorization(&satelle_core::ProviderBindingAuthorization::new(
            model_alias,
            provider_alias,
            "gpt-test",
            "openai",
        ))
        .expect("only the exact implicit default pair is reserved");
    }
}

#[test]
fn production_adapter_accepts_host_authorized_binding_without_resolving_auth() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let host_auth = satelle_core::ProviderSecretSource::Environment {
        variable: "SATELLE_HOST_OWNED_PROVIDER_SECRET_MISSING".to_string(),
    };
    let adapter = ProductionComputerUseAdapter::with_readiness_policy(
        Arc::new(RwLock::new(capability_snapshot(
            Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Malformed,
                host_platform: HostPlatform::Linux,
                capabilities: CapabilityMatrix::unproven(),
            },
            0,
        ))),
        Ok(state.path().to_path_buf()),
        crate::runtime::ProductionAdapterPolicy {
            native_readiness_timeout: std::time::Duration::from_secs(1),
            native_readiness_ttl: time::Duration::minutes(5),
            provider_smoke_timeout: std::time::Duration::from_secs(1),
            provider_smoke_success_ttl: time::Duration::hours(24),
            provider_smoke_failure_ttl: time::Duration::minutes(10),
            desktop_selection: satelle_core::DesktopSelectionPolicy {
                desktop_user: None,
                preference: None,
                native_selector: None,
            },
        },
    );
    let binding = satelle_core::ResolvedProviderBinding::from_authorization(
        satelle_core::ProviderBindingAuthorization::new(
            "review",
            "openai",
            "host-model",
            "host-provider",
        )
        .with_endpoint("https://host-provider.invalid/v1")
        .with_auth_source(host_auth.clone()),
        satelle_core::ProviderBindingSource::HostOwned,
    );
    let intent = ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("review")
                .expect("valid requested model alias"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("openai")
                .expect("valid requested provider alias"),
        ),
        false,
    )
    .with_resolved_provider_binding(binding)
    .with_experimental_provider_computer_use(true);

    let resolved = ComputerUseAdapter::resolve_provider_binding(&adapter, LOCAL_DEMO_HOST, &intent)
        .expect("Host-owned binding resolution must not read its missing secret");

    assert_eq!(
        satelle_core::ProviderBindingSource::HostOwned,
        resolved.source()
    );
    assert_eq!("host-model", resolved.model());
    assert_eq!("host-provider", resolved.model_provider());
    assert_eq!(
        Some("https://host-provider.invalid/v1"),
        resolved.endpoint()
    );
    assert_eq!(Some(&host_auth), resolved.auth_source());
    assert!(resolved.experimental_provider_computer_use());
}

#[test]
fn unresolved_host_secret_maps_to_the_typed_public_error_without_descriptor_text() {
    let variable = format!(
        "SATELLE_PROVIDER_AUTH_MISSING_{}",
        uuid::Uuid::now_v7().simple()
    );
    let binding = satelle_core::ResolvedProviderBinding::from_authorization(
        satelle_core::ProviderBindingAuthorization::new(
            "review",
            "openai",
            "host-model",
            "host-provider",
        )
        .with_endpoint("https://host-provider.invalid/v1")
        .with_auth_source(satelle_core::ProviderSecretSource::Environment {
            variable: variable.clone(),
        }),
        satelle_core::ProviderBindingSource::HostOwned,
    );

    let error = crate::runtime::resolve_provider_child_secret_for_test(&binding)
        .expect_err("the missing Host environment secret must fail closed");

    assert_eq!(ErrorCode::ProviderSecretResolutionFailed, error.code);
    assert_eq!(error.details["reason"], "provider_auth_unresolved");
    let encoded = serde_json::to_string(&error).expect("serialize typed error");
    assert!(!encoded.contains(&variable));
}

#[cfg(unix)]
#[test]
fn provider_descriptor_validation_resolves_only_during_target_host_refresh() {
    use std::os::unix::fs::PermissionsExt;

    let state = TestStateDir::new().expect("temporary state directory");
    let secret_directory = tempfile::tempdir().expect("create provider secret directory");
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make provider secret directory owner-only");
    let secret_path = secret_directory.path().join("provider-token");
    let secret_canary = "PRIVATE_PROVIDER_REFRESH_SECRET_CANARY";
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), SecretBoundaryAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    service
        .runtime
        .authorize_provider_binding(&satelle_core::ResolvedProviderBinding::from_authorization(
            satelle_core::ProviderBindingAuthorization::new(
                "review",
                "openai",
                "host-model",
                "openai",
            )
            .with_endpoint("http://127.0.0.1:9")
            .with_auth_source(satelle_core::ProviderSecretSource::File {
                path: secret_path.clone(),
            })
            .with_experimental_provider_computer_use(true),
            satelle_core::ProviderBindingSource::UserConfig,
        ))
        .expect("seed the provider descriptor for validation");

    let cached = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::Cached,
                false,
                false,
                false,
            ),
        )
        .expect("cached validation remains observation-only");
    assert_eq!(
        cached.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret
    );
    assert_eq!(
        cached.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    assert!(!secret_path.exists());

    std::fs::write(&secret_path, secret_canary).expect("write provider secret canary");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("make provider secret owner-only");
    let refreshed = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
                false,
                false,
                false,
            ),
        )
        .expect("live validation resolves at the target Host");
    assert_eq!(
        refreshed.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::Resolved
    );
    assert_eq!(
        refreshed.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    let public = satelle_core::PublicProviderDescriptorValidation::from(&refreshed);
    let encoded = serde_json::to_string(&public).expect("serialize public validation");
    assert!(!encoded.contains(secret_canary));
    assert!(!encoded.contains(secret_path.to_string_lossy().as_ref()));

    let cached_after_pass = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::Cached,
                false,
                false,
                false,
            ),
        )
        .expect("cached validation remains deferred after a live pass");
    assert_eq!(
        cached_after_pass.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::ConfiguredDeferred
    );
    assert_eq!(
        cached_after_pass.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Deferred
    );

    std::fs::remove_file(&secret_path).expect("remove provider secret");
    let unresolved = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
                false,
                false,
                false,
            ),
        )
        .expect("live validation reports a closed unresolved outcome");
    assert_eq!(
        unresolved.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret
    );
    assert_eq!(
        unresolved.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    let encoded = serde_json::to_string(&satelle_core::PublicProviderDescriptorValidation::from(
        &unresolved,
    ))
    .expect("serialize unresolved public validation");
    assert!(!encoded.contains(secret_canary));
    assert!(!encoded.contains(secret_path.to_string_lossy().as_ref()));

    let cached_after_failure = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::Cached,
                false,
                false,
                false,
            ),
        )
        .expect("cached validation remains deferred after a live failure");
    assert_eq!(
        cached_after_failure.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret
    );
    assert_eq!(
        cached_after_failure.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
}

#[cfg(unix)]
#[test]
fn failed_upstream_validation_returns_only_the_closed_smoke_failed_outcome() {
    use std::os::unix::fs::PermissionsExt;

    let state = TestStateDir::new().expect("temporary state directory");
    let secret_directory = tempfile::tempdir().expect("create provider secret directory");
    std::fs::set_permissions(
        secret_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make provider secret directory owner-only");
    let secret_path = secret_directory.path().join("provider-token");
    std::fs::write(&secret_path, "provider-smoke-token").expect("write provider smoke secret");
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
        .expect("make provider smoke secret owner-only");
    let service = HostService {
        runtime: RuntimeHandle::new(Ok(state.path().to_path_buf()), FailedProviderSmokeAdapter),
        operation_capacity: Arc::new(OperationCapacity::default()),
        turn_execution_timeout: crate::configured_turn_execution_timeout(
            &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
        ),
        mode: HostMode::TestFake {
            image_attachments: true,
        },
        bootstrap_auth: None,
        bootstrap_maintenance: Arc::new(Mutex::new(None)),
        doctor_tasks: DoctorTaskRegistry::new(),
    };
    service
        .runtime
        .authorize_provider_binding(&satelle_core::ResolvedProviderBinding::from_authorization(
            satelle_core::ProviderBindingAuthorization::new(
                "review",
                "openai",
                "host-model",
                "openai",
            )
            .with_auth_source(satelle_core::ProviderSecretSource::File { path: secret_path }),
            satelle_core::ProviderBindingSource::UserConfig,
        ))
        .expect("seed provider binding before failed smoke");

    let validation = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
                false,
                false,
                false,
            ),
        )
        .expect("upstream smoke failure must become a closed validation outcome");
    assert_eq!(
        validation.validation().outcome(),
        satelle_core::ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed
    );
    assert_eq!(
        validation.validation().observation_source(),
        satelle_core::ProviderAuthObservationSource::Live
    );
    let public = satelle_core::PublicProviderDescriptorValidation::from(&validation);
    let encoded = serde_json::to_value(public).expect("serialize closed validation");
    assert_eq!(
        encoded["validation"]["outcome"],
        satelle_core::ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed.as_str()
    );
}

#[test]
fn provider_descriptor_refresh_replays_control_plane_errors_without_reclassifying_them() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = service_with_provider_descriptor(
        state.path().to_path_buf(),
        HostBusyProviderPreflightAdapter {
            calls: Arc::clone(&calls),
        },
        None,
    );
    service.initialize_daemon().expect("initialize daemon");

    let token = ApiBearerToken::generate().expect("generate token");
    let principal = service
        .register_api_token(
            &token,
            "provider-validation-host-busy",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register token");
    let authority = MutationAuthority::new(principal, "provider-validation-host-busy")
        .expect("construct mutation authority");
    let options = || {
        crate::ProviderDescriptorValidationOptions::new(
            satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
            false,
            false,
            true,
        )
    };

    let first = service
        .validate_provider_descriptor_idempotent(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            options(),
            &authority,
        )
        .expect_err("HostBusy must propagate instead of becoming a provider outcome");
    let replay = service
        .validate_provider_descriptor_idempotent(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            options(),
            &authority,
        )
        .expect_err("the exact HostBusy failure must replay");

    assert_eq!(first.code, ErrorCode::HostBusy);
    assert_eq!(replay.code, ErrorCode::HostBusy);
    assert_eq!(first.message, replay.message);
    assert_eq!(first.recovery_command, replay.recovery_command);
    assert_eq!(first.details, replay.details);
    assert_eq!(
        1,
        calls.load(std::sync::atomic::Ordering::SeqCst),
        "durable failure replay must not repeat preflight"
    );
}

#[test]
fn doctor_provider_and_default_scopes_report_closed_descriptor_status_without_secret_text() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let variable = format!(
        "SATELLE_DOCTOR_PROVIDER_SECRET_{}",
        uuid::Uuid::now_v7().simple()
    );
    service
        .runtime
        .authorize_provider_binding(&satelle_core::ResolvedProviderBinding::from_authorization(
            satelle_core::ProviderBindingAuthorization::new(
                "review",
                "openai",
                "provider-doctor-model",
                "provider-doctor-binding",
            )
            .with_auth_source(satelle_core::ProviderSecretSource::Environment {
                variable: variable.clone(),
            })
            .with_experimental_provider_computer_use(true),
            satelle_core::ProviderBindingSource::UserConfig,
        ))
        .expect("authorize the persisted UserConfig provider binding");
    let intent = ProviderComputerUseIntent::new(
        Some(
            satelle_core::session::EffectiveModelRef::new("review")
                .expect("valid requested model alias"),
        ),
        Some(
            satelle_core::session::ProviderBindingRef::new("openai")
                .expect("valid requested provider alias"),
        ),
        false,
    );

    for scope in [None, Some("provider"), Some("all")] {
        let scopes = scope.map_or_else(Vec::new, |scope| vec![scope]);
        let report = service
            .doctor_with_provider_intent(
                LOCAL_DEMO_HOST,
                &doctor_selection(&scopes),
                Arc::new(ready_transport()),
                DoctorOptions::new(false, None).expect("default timeout is valid"),
                &intent,
            )
            .expect("read-only doctor should classify its provider descriptor");
        let evidence = report
            .findings
            .iter()
            .flat_map(|finding| finding.evidence.iter())
            .cloned()
            .collect::<Vec<_>>();

        assert!(
            evidence.contains(&"provider_auth_outcome=configured_deferred".to_string()),
            "doctor must report the closed descriptor outcome"
        );
        assert!(
            evidence.contains(&"provider_auth_observation_source=deferred".to_string()),
            "doctor must distinguish deferred descriptor inspection from live resolution"
        );
        assert!(
            !serde_json::to_string(&report)
                .expect("serialize doctor report")
                .contains(&variable),
            "doctor output must not return environment variable names or secret material"
        );
    }
}

#[test]
fn named_missing_provider_descriptor_remains_observable_to_cached_validation() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = service_with_provider_descriptor(
        state.path().to_path_buf(),
        FakeComputerUseAdapter,
        Some("missing-provider-token".to_string()),
    );
    let intent = provider_intent_with_missing_descriptor();

    let resolution = service
        .resolve_provider_binding(LOCAL_DEMO_HOST, &intent)
        .expect("diagnostic binding resolution must preserve a missing descriptor");
    let ProviderBindingResolution::MissingDescriptor {
        binding,
        auth_source_name,
    } = resolution
    else {
        panic!("named missing descriptor must not be reported as ready");
    };
    assert_eq!("missing-provider-token", auth_source_name);
    assert_eq!("provider-model", binding.model());
    assert_eq!(None, binding.auth_source());

    let validation = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::Cached,
                false,
                false,
                false,
            ),
        )
        .expect("cached validation must classify the missing descriptor");
    assert_eq!(
        satelle_core::ProviderAuthValidationOutcome::MissingDescriptor,
        validation.validation().outcome()
    );
    assert_eq!(
        satelle_core::ProviderAuthObservationSource::Deferred,
        validation.validation().observation_source()
    );
}

#[test]
fn provider_binding_without_auth_source_is_resolved_by_cached_validation() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service =
        service_with_provider_descriptor(state.path().to_path_buf(), FakeComputerUseAdapter, None);

    let validation = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::Cached,
                false,
                false,
                false,
            ),
        )
        .expect("cached validation must accept a binding that requires no secret");
    assert_eq!(
        satelle_core::ProviderAuthValidationOutcome::Resolved,
        validation.validation().outcome()
    );
    assert_eq!(
        satelle_core::ProviderAuthObservationSource::Cached,
        validation.validation().observation_source(),
        "cached validation must not invoke secret resolution"
    );
}

#[test]
fn provider_binding_without_auth_source_runs_live_refresh_validation() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service =
        service_with_provider_descriptor(state.path().to_path_buf(), FakeComputerUseAdapter, None);

    let validation = service
        .validate_provider_descriptor(
            LOCAL_DEMO_HOST,
            "review",
            "openai",
            crate::ProviderDescriptorValidationOptions::new(
                satelle_core::ProviderAuthValidationMode::RefreshProviderSmoke,
                false,
                false,
                false,
            ),
        )
        .expect("refresh validation must run the live provider smoke");
    assert_eq!(
        satelle_core::ProviderAuthValidationOutcome::Resolved,
        validation.validation().outcome()
    );
    assert_eq!(
        satelle_core::ProviderAuthObservationSource::Live,
        validation.validation().observation_source()
    );
}

#[test]
fn doctor_reports_a_named_missing_provider_descriptor_without_resolving_it() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = service_with_provider_descriptor(
        state.path().to_path_buf(),
        FakeComputerUseAdapter,
        Some("missing-provider-token".to_string()),
    );

    let report = service
        .doctor_with_provider_intent(
            LOCAL_DEMO_HOST,
            &doctor_selection(&["provider"]),
            Arc::new(ready_transport()),
            DoctorOptions::new(false, None).expect("default timeout is valid"),
            &provider_intent_with_missing_descriptor(),
        )
        .expect("doctor must preserve the missing descriptor as diagnostic evidence");
    let evidence = report
        .findings
        .iter()
        .flat_map(|finding| finding.evidence.iter())
        .collect::<Vec<_>>();
    assert!(
        evidence
            .iter()
            .any(|value| value.as_str() == "provider_auth_outcome=missing_descriptor")
    );
    assert!(
        evidence
            .iter()
            .any(|value| value.as_str() == "provider_auth_observation_source=deferred")
    );
}

#[test]
fn strict_provider_smoke_rejects_a_missing_descriptor_before_adapter_preflight() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = service_with_provider_descriptor(
        state.path().to_path_buf(),
        ProviderPreflightCounter {
            calls: Arc::clone(&calls),
            gate: None,
        },
        Some("missing-provider-token".to_string()),
    );

    let error = service
        .runtime
        .refresh_provider_smoke(LOCAL_DEMO_HOST, &provider_intent_with_missing_descriptor())
        .expect_err("strict provider smoke must fail closed");
    assert_eq!(ErrorCode::ProviderSecretResolutionFailed, error.code);
    assert_eq!(error.details["auth_source"], "missing-provider-token");
    assert_eq!(
        0,
        calls.load(std::sync::atomic::Ordering::SeqCst),
        "the adapter must not receive preflight for a missing descriptor"
    );
}

#[test]
fn concurrent_provider_binding_authorization_retries_share_one_live_validation() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gate = ProviderPreflightGate::default();
    let service = Arc::new(service_with_provider_descriptor(
        state.path().to_path_buf(),
        ProviderPreflightCounter {
            calls: Arc::clone(&calls),
            gate: Some(gate.clone()),
        },
        None,
    ));
    service.initialize_daemon().expect("initialize daemon");

    let token = ApiBearerToken::generate().expect("generate token");
    let principal = service
        .register_api_token(
            &token,
            "provider-authorization-concurrency",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register token");
    let authority =
        MutationAuthority::new(principal, "provider-authorization-concurrency").expect("authority");
    let authorization = ProviderBindingAuthorization::new("vision", "open_ai", "gpt-5.6", "openai");

    let leader_service = Arc::clone(&service);
    let leader_authority = authority.clone();
    let leader_authorization = authorization.clone();
    let leader = std::thread::spawn(move || {
        leader_service.authorize_provider_binding_idempotent(
            LOCAL_DEMO_HOST,
            "vision",
            "open_ai",
            leader_authorization,
            &leader_authority,
        )
    });

    assert!(
        gate.wait_for_started(Duration::from_secs(5)),
        "leader validation did not start"
    );

    let follower_service = Arc::clone(&service);
    let follower_authority = authority.clone();
    let follower_authorization = authorization.clone();
    let follower = std::thread::spawn(move || {
        follower_service.authorize_provider_binding_idempotent(
            LOCAL_DEMO_HOST,
            "vision",
            "open_ai",
            follower_authorization,
            &follower_authority,
        )
    });

    let follower_registered = service
        .operation_capacity
        .wait_for_follower_registration(Duration::from_secs(5));
    let conflict = service
        .authorize_provider_binding_idempotent(
            LOCAL_DEMO_HOST,
            "vision",
            "open_ai",
            ProviderBindingAuthorization::new("vision", "open_ai", "gpt-conflict", "openai"),
            &authority,
        )
        .expect_err("changed authorization must conflict");
    let calls_before_release = calls.load(std::sync::atomic::Ordering::SeqCst);
    gate.release();

    assert!(follower_registered, "exact retry did not join the leader");
    assert_eq!(ErrorCode::IdempotencyKeyConflict, conflict.code);
    assert_eq!(
        1, calls_before_release,
        "concurrent requests performed duplicate live validation"
    );

    let leader_binding = leader
        .join()
        .expect("leader thread")
        .expect("leader authorization");
    let follower_binding = follower
        .join()
        .expect("follower thread")
        .expect("follower authorization");
    assert_eq!(
        leader_binding.binding_digest(),
        follower_binding.binding_digest()
    );

    let replay = service
        .authorize_provider_binding_idempotent(
            LOCAL_DEMO_HOST,
            "vision",
            "open_ai",
            authorization,
            &authority,
        )
        .expect("terminal replay");
    assert_eq!(leader_binding.binding_digest(), replay.binding_digest());
    assert_eq!(
        1,
        calls.load(std::sync::atomic::Ordering::SeqCst),
        "terminal replay repeated live validation"
    );
    assert_eq!(
        Some(leader_binding.binding_digest()),
        service
            .runtime
            .provider_binding_digest("vision", "open_ai")
            .expect("read persisted provider binding")
            .as_deref()
    );
}

fn capability_snapshot(
    evidence: Phase0CapabilityEvidence,
    duration_ms: u64,
) -> ProductionCapabilitySnapshot {
    ProductionCapabilitySnapshot {
        evidence,
        verdict: evaluate_phase0_support(evidence),
        control_plane_admission: codex_capabilities::ControlPlaneAdmission::not_applicable(),
        budget_failure: None,
        started_at: "2026-07-09T00:00:00Z".to_string(),
        finished_at: "2026-07-09T00:00:01Z".to_string(),
        duration_ms,
    }
}
