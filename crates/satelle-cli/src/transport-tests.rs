use super::*;
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, SandboxPolicy, SessionActivity,
    StopObservation, TimeoutPolicy, TurnAdmissionPhase, TurnState, TurnTransition,
};
use satelle_core::{
    ApiTokenSource, ErrorCode, EventSource, EventSubject, EventType, SatelleConfig,
    SatelleEventBody, TransportKind,
};
use satelle_host::{
    AdapterReadiness, AdapterSubject, ApiScopes, ComputerUseAdapter, ExecuteRequest, ExecuteResult,
    LogCursor, LogPageQuery, LogSeverity, LogSource, ProviderComputerUseIntent,
    ProviderSmokeEvidence, ReadinessEvidence, RecoveryObservation, test_support::TestStateDir,
};
use satelle_transport::{DaemonServer, DaemonServerConfig};
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::TcpStream;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Error as WebSocketError;
use tokio_tungstenite::tungstenite::error::ProtocolError;

fn setup_selection(mode: satelle_core::SetupMode) -> SetupModeSelection {
    SetupModeSelection::new(
        mode,
        satelle_core::daemon_service::SetupModeSource::SetupFlag,
    )
}

#[derive(Clone)]
struct RecordingProviderIntentAdapter {
    observed: Arc<Mutex<Option<ProviderComputerUseIntent>>>,
}

fn spawn_loopback_daemon(service: HostService) -> (tokio::runtime::Runtime, DaemonServer) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("construct daemon runtime");
    let server = runtime
        .block_on(DaemonServer::bind(
            service,
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        ))
        .expect("bind loopback daemon");
    (runtime, server)
}

#[derive(Clone, Default)]
struct TestInterrupt {
    signalled: Arc<AtomicBool>,
    changed: Arc<tokio::sync::Notify>,
}

impl TestInterrupt {
    fn signal(&self) {
        self.signalled.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}

impl InterruptSource for TestInterrupt {
    fn wait(&self) -> InterruptFuture<'_> {
        Box::pin(async move {
            loop {
                let notified = self.changed.notified();
                if self.signalled.load(Ordering::Acquire) {
                    return Ok(());
                }
                notified.await;
            }
        })
    }
}

struct FailingWaitInterrupt {
    operation_started: TestLatch,
}

impl InterruptSource for FailingWaitInterrupt {
    fn wait(&self) -> InterruptFuture<'_> {
        Box::pin(async move {
            self.operation_started.wait();
            Err(std::io::Error::other("injected interrupt listener failure"))
        })
    }
}

#[derive(Clone, Default)]
struct ArmOrderInterrupt {
    armed: Arc<AtomicBool>,
}

impl InterruptSource for ArmOrderInterrupt {
    fn arm(&self) -> InterruptFuture<'_> {
        Box::pin(async move {
            self.armed.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn wait(&self) -> InterruptFuture<'_> {
        Box::pin(async move {
            assert!(
                self.armed.load(Ordering::Acquire),
                "interrupt wait must never begin before synchronous arming completes"
            );
            std::future::pending().await
        })
    }
}

#[derive(Clone)]
struct ArmCheckingAdapter {
    armed: Arc<AtomicBool>,
}

impl ComputerUseAdapter for ArmCheckingAdapter {
    fn preflight(
        &self,
        _host: &str,
        _intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        assert!(
            self.armed.load(Ordering::Acquire),
            "the SIGINT source must be armed before the local admission thread starts"
        );
        lifecycle_readiness()
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        Ok(ExecuteResult::new(TurnTransition::Completed, Vec::new()))
    }

    fn observe_stop(&self, _subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(RecoveryObservation::Completed)
    }
}

#[derive(Clone, Default)]
struct TestLatch {
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl TestLatch {
    fn signal(&self) {
        let (lock, changed) = &*self.state;
        let mut state = lock.lock().expect("test latch lock");
        *state = true;
        changed.notify_all();
    }

    fn wait(&self) {
        let (lock, changed) = &*self.state;
        let state = lock.lock().expect("test latch lock");
        drop(
            changed
                .wait_while(state, |state| !*state)
                .expect("test latch wait"),
        );
    }

    fn wait_for(&self, timeout: Duration) -> bool {
        let (lock, changed) = &*self.state;
        let state = lock.lock().expect("test latch lock");
        let (state, _) = changed
            .wait_timeout_while(state, timeout, |state| !*state)
            .expect("test latch timed wait");
        *state
    }

    fn reset(&self) {
        let (lock, _) = &*self.state;
        *lock.lock().expect("test latch lock") = false;
    }
}

#[derive(Clone, Default)]
struct InterruptLifecycleAdapter {
    preflight_started: TestLatch,
    preflight_release: TestLatch,
    block_preflight: Arc<AtomicBool>,
    execute_started: TestLatch,
    execute_release: TestLatch,
    execute_finished: TestLatch,
    block_execute: Arc<AtomicBool>,
    stop_calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl InterruptLifecycleAdapter {
    fn block_preflight(&self) {
        self.block_preflight.store(true, Ordering::Release);
    }

    fn block_execute(&self) {
        self.block_execute.store(true, Ordering::Release);
    }
}

impl ComputerUseAdapter for InterruptLifecycleAdapter {
    fn preflight(
        &self,
        _host: &str,
        _intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        if self.block_preflight.swap(false, Ordering::AcqRel) {
            self.preflight_started.signal();
            self.preflight_release.wait();
        }
        lifecycle_readiness()
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        if self.block_execute.load(Ordering::Acquire) {
            self.execute_started.signal();
            self.execute_release.wait();
        }
        self.execute_finished.signal();
        Ok(ExecuteResult::new(TurnTransition::Completed, Vec::new()))
    }

    fn observe_stop(&self, _subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        self.execute_release.signal();
        Ok(StopObservation::CancellationConfirmed)
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(RecoveryObservation::Unknown)
    }
}

fn lifecycle_readiness() -> Result<AdapterReadiness, SatelleError> {
    let desktop_binding = DesktopBindingRef::new("interrupt-test-desktop")
        .map_err(|error| SatelleError::not_implemented(format!("test desktop binding: {error}")))?;
    let execution_policy = ExecutionPolicy::new(
        EffectiveModelRef::new("interrupt-test-model")
            .map_err(|error| SatelleError::not_implemented(format!("test model: {error}")))?,
        ProviderBindingRef::new("interrupt-test-provider")
            .map_err(|error| SatelleError::not_implemented(format!("test provider: {error}")))?,
        DesktopTarget::new(desktop_binding.clone()),
        ApprovalPolicy::OnRequest,
        SandboxPolicy::WorkspaceWrite,
        TimeoutPolicy::bounded_seconds(120)
            .map_err(|error| SatelleError::not_implemented(format!("test timeout: {error}")))?,
        ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Enabled),
    );
    let observed_at = time::OffsetDateTime::now_utc();
    let evidence = ReadinessEvidence::new(
        format!("interrupt-readiness-{}", SessionId::new()),
        "interrupt-test-codex",
        "interrupt-test-runtime",
        Some("interrupt-test-plugin"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        observed_at,
        observed_at + time::Duration::minutes(5),
    )
    .map_err(|error| SatelleError::not_implemented(format!("test evidence: {error}")))?;
    let provider_evidence = ProviderSmokeEvidence::new(
        format!("interrupt-provider-{}", SessionId::new()),
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        observed_at,
        observed_at + time::Duration::hours(1),
    )
    .map_err(|error| SatelleError::not_implemented(format!("test provider evidence: {error}")))?;
    AdapterReadiness::ready(
        "interrupt-test",
        "interrupt test readiness",
        desktop_binding,
        execution_policy,
        evidence,
        Some(provider_evidence),
    )
    .map_err(|error| SatelleError::not_implemented(format!("test readiness: {error}")))
}

fn ssh_setup_host(api_token: Option<ApiTokenSource>) -> SelectedHost {
    let mut config = SatelleConfig::defaults()
        .hosts
        .remove(LOCAL_DEMO_HOST)
        .expect("built-in Host config");
    config.transport = TransportKind::Ssh;
    config.address = Some("host.example.test".to_string());
    config.expected_host_id = Some("host-setup-test".to_string());
    config.api_token = api_token;
    SelectedHost {
        alias: "remote".to_string(),
        config,
    }
}

#[test]
fn ssh_setup_plan_reaches_explicit_trust_for_an_unpinned_host() {
    let state = TestStateDir::new().expect("temporary state directory");
    let mut host = ssh_setup_host(Some(ApiTokenSource::File {
        path: state.path().join("first-trust.token"),
    }));
    host.config.expected_host_id = None;

    let transport = SshSetupTransport::new(&host).expect("construct unpinned SSH setup");
    let report = transport
        .setup(
            true,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
        )
        .expect("plan first-trust SSH setup");

    assert_eq!(report.status, "planned");
    assert_eq!(
        report.planned_actions,
        [
            "allow SSH setup to stop the running Host daemon; active Host work may be interrupted",
            concat!(
                "probe the remote OS, architecture, and runtime family, then upload or verify the invoking CLI v",
                env!("CARGO_PKG_VERSION"),
                " matching verified Host artifact for the detected remote platform without requiring a host binary URL or path; do not register a persistent service"
            ),
            "discover and explicitly trust the reachable Host Identity",
            "issue, persist, and activate a durable control-scoped API token",
        ]
    );
    assert!(!report.mutated);
}

#[test]
fn ssh_setup_plan_requires_an_external_token_file_without_mutating() {
    let transport = SshSetupTransport::new(&ssh_setup_host(None)).expect("construct setup");
    let report = transport
        .setup(
            true,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
        )
        .expect("plan SSH setup");

    assert_eq!(report.status, "input_required");
    assert!(!report.mutated);
    assert!(report.applied_actions.is_empty());
    assert_eq!(report.required_input.len(), 1);
    assert_eq!(
        report.required_input[0].input_kind,
        "api_token_file_descriptor"
    );
}

#[test]
fn ordinary_ssh_commands_require_a_durable_token_descriptor() {
    let error = match transport_for(&ssh_setup_host(None)) {
        Ok(_) => panic!("ordinary SSH transport must reject tokenless bootstrap"),
        Err(error) => error,
    };

    assert_eq!(error.error.code, ErrorCode::ConfigError);
    assert!(error.error.message.contains("api_token"));
}

#[test]
fn ssh_setup_plan_declares_one_durable_token_handoff() {
    let state = TestStateDir::new().expect("temporary state directory");
    let path = state.path().join("satelle-setup-plan.token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File { path })))
        .expect("construct setup");
    let report = transport
        .setup(
            true,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
        )
        .expect("plan SSH setup");

    assert_eq!(report.status, "planned");
    assert!(report.required_input.is_empty());
    assert_eq!(
        report.planned_actions,
        [
            "allow SSH setup to stop the running Host daemon; active Host work may be interrupted",
            concat!(
                "probe the remote OS, architecture, and runtime family, then upload or verify the invoking CLI v",
                env!("CARGO_PKG_VERSION"),
                " matching verified Host artifact for the detected remote platform without requiring a host binary URL or path; do not register a persistent service"
            ),
            "issue, persist, and activate a durable control-scoped API token",
        ]
    );
    assert!(!report.mutated);
}

#[test]
fn ssh_setup_plan_declares_verified_release_bootstrap_without_storage_migration() {
    let state = TestStateDir::new().expect("temporary state directory");
    let path = state.path().join("satelle-setup-plan.token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File { path })))
        .expect("construct setup");
    let overrides = DaemonPathOverrides {
        state_dir: Some(state.path().join("remote-state")),
        ..DaemonPathOverrides::default()
    };

    let report = transport
        .setup(
            true,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            overrides,
        )
        .expect("plan SSH setup with transient paths");

    assert!(report.planned_actions.iter().any(|action| {
        action.contains("matching verified Host artifact")
            && action.contains(env!("CARGO_PKG_VERSION"))
            && action.contains("detected remote platform")
    }));
    assert!(report.planned_actions.iter().any(|action| {
        action.contains("on-demand Host process")
            && action.contains("do not persist remote service configuration")
            && action.contains("migrate storage")
            && action.contains("previous sessions may be invisible")
    }));
    assert_eq!(report.daemon_path_overrides.len(), 1);
    assert!(!report.mutated);
}

#[test]
fn unpinned_and_unauthenticated_bindings_cannot_open_ordinary_transports() {
    let mut unpinned_ssh = ssh_setup_host(Some(ApiTokenSource::File {
        path: PathBuf::from("/tmp/unread-token"),
    }));
    unpinned_ssh.config.expected_host_id = None;
    let ssh_error = match transport_for(&unpinned_ssh) {
        Ok(_) => panic!("ordinary SSH transport must reject an unpinned Host"),
        Err(error) => error,
    };
    assert_eq!(ssh_error.error.code, ErrorCode::ConfigError);

    let mut direct = unpinned_ssh;
    direct.config.transport = TransportKind::Direct;
    direct.config.address = Some("https://studio.example.test:3001".to_string());
    direct.config.network = Some(satelle_core::NetworkConfig::Tailscale {
        tailnet_name: Some("example.test".to_string()),
        hostname: Some("studio".to_string()),
    });
    direct.config.api_token = None;
    let direct_error = match transport_for(&direct) {
        Ok(_) => panic!("Tailscale reachability must not replace Host authentication"),
        Err(error) => error,
    };
    assert_eq!(direct_error.error.code, ErrorCode::ConfigError);
}

#[test]
fn setup_token_lock_serializes_processes_targeting_the_same_credential() {
    let state = TestStateDir::new().expect("temporary state directory");
    #[cfg(unix)]
    std::fs::set_permissions(
        state.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("make token directory owner-only");
    let token_path = state.path().join("serialized-setup.token");
    let first_lock = acquire_setup_token_lock(&token_path).expect("acquire first setup lock");
    let second_lock = open_setup_token_lock(&token_path).expect("open second setup lock");
    assert!(matches!(
        second_lock.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(first_lock);
    second_lock
        .try_lock()
        .expect("second setup acquires the released token path");
    second_lock.unlock().expect("release the second setup lock");
    assert!(
        token_path
            .parent()
            .expect("token parent")
            .join(".serialized-setup.token.satelle-setup.lock")
            .is_file(),
        "the stable lock inode remains for future setup processes"
    );
}

#[test]
fn ssh_setup_rerun_reuses_an_existing_secure_token_destination() {
    let temporary_root = tempfile::tempdir().expect("temporary root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            temporary_root.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make temporary root owner-only");
    }
    let token_directory = temporary_root.path().join("owner-only");
    drop(
        satelle_core::open_or_create_owner_only_directory(&token_directory)
            .expect("create owner-only token directory"),
    );
    let path = token_directory.join("satelle-existing-setup.token");
    let token = ApiBearerToken::generate().expect("generate existing API token");
    let raw_token = token.expose();
    persist_new_owner_only_secret_file(&path, raw_token.as_str())
        .expect("persist initial setup token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File {
        path: path.clone(),
    })))
    .expect("construct setup");

    let report = transport
        .setup(
            true,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
        )
        .expect("plan repeated SSH setup");

    assert_eq!(
        report.planned_actions,
        [
            "allow SSH setup to stop the running Host daemon; active Host work may be interrupted",
            concat!(
                "probe the remote OS, architecture, and runtime family, then upload or verify the invoking CLI v",
                env!("CARGO_PKG_VERSION"),
                " matching verified Host artifact for the detected remote platform without requiring a host binary URL or path; do not register a persistent service"
            ),
            "validate and reuse the existing durable control-scoped API token, or recover an interrupted pending handoff"
        ]
    );
    assert!(!report.mutated);
    assert_eq!(
        read_owner_only_secret_file(&path).expect("read retained token"),
        raw_token
    );
}

#[test]
fn persisted_pending_setup_token_self_activates_on_the_running_daemon() {
    let state = TestStateDir::new().expect("temporary state directory");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct Host service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::ADMIN,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let host_identity = initialized.host_identity().to_string();
    let (_runtime, server) = spawn_loopback_daemon(service);
    let address = server.local_addr();
    let bootstrap_client = DaemonClient::loopback(address, bootstrap_token, &host_identity)
        .expect("construct bootstrap client");

    let interrupted = bootstrap_client
        .issue_durable_setup_token("interrupted-setup-issue")
        .expect("issue pending token");
    let interrupted_id = interrupted.token_id().to_string();
    let interrupted_raw = interrupted
        .into_bearer_token()
        .expect("first issuance carries the secret");
    let token_path = state.path().join("interrupted-setup.token");
    persist_new_owner_only_secret_file(&token_path, interrupted_raw.as_str())
        .expect("persist token before simulated interruption");
    let pending_client = DaemonClient::loopback(
        address,
        ApiBearerToken::parse(interrupted_raw.as_str()).expect("parse pending token"),
        &host_identity,
    )
    .expect("construct pending-token client");

    assert!(matches!(
        pending_client.issue_durable_setup_token("pending-cannot-issue"),
        Err(DaemonClientError::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            ..
        })
    ));
    assert!(matches!(
        pending_client.abort_durable_setup_token(&interrupted_id, "pending-cannot-abort"),
        Err(DaemonClientError::Api {
            status: reqwest::StatusCode::UNAUTHORIZED,
            ..
        })
    ));

    assert_eq!(
        inspect_durable_setup_token(&pending_client, interrupted_id.as_str())
            .expect("inspect the persisted pending token"),
        ExistingTokenInspection::RequiresActivation
    );
    let verification = activate_durable_setup_token(
        &pending_client,
        interrupted_id.clone(),
        "interrupted-setup-activate",
    )
    .expect("activate the persisted pending token on the running daemon");
    assert_eq!(verification, ExistingTokenVerification::ActivatedPending);

    let report = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File {
        path: token_path.clone(),
    })))
    .expect("construct recovered SSH setup")
    .setup_report(
        false,
        "on_demand".to_string(),
        vec!["transport".to_string()],
        DaemonPathOverrides::default(),
        SetupApplication::AppliedPendingActivation,
    );
    assert!(report.mutated);
    assert_eq!(
        report.applied_actions,
        [
            "probed the remote platform and uploaded or verified the invoking CLI's matching integrity-checked Host artifact",
            "activate the existing pending durable control-scoped API token"
        ]
    );
    let confirmation = pending_client
        .confirm_durable_setup_token()
        .expect("the recovered token authenticates after self-activation");
    assert_eq!(confirmation.token_id(), interrupted_id);
    assert_eq!(
        read_owner_only_secret_file(&token_path).expect("read recovered setup token"),
        interrupted_raw
    );

    drop(server);
}

#[test]
fn durable_verification_and_bootstrap_handoff_use_distinct_clients() {
    let state = TestStateDir::new().expect("temporary state directory");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct Host service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::READ,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let host_identity = initialized.host_identity().to_string();
    let (durable_token, durable_principal) = service
        .issue_pending_api_token(
            ApiScopes::CONTROL,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )
        .expect("issue pending durable setup token");
    let durable_token_id = durable_principal.token_id().to_string();
    service
        .activate_api_token(&durable_token_id)
        .expect("activate durable setup token");
    let (_runtime, server) = spawn_loopback_daemon(service);
    let address = server.local_addr();
    let bootstrap_client = DaemonClient::loopback(address, bootstrap_token, &host_identity)
        .expect("construct operation-bound bootstrap client");
    let durable_client = DaemonClient::loopback(address, durable_token, &host_identity)
        .expect("construct durable verification client");

    let inspection = inspect_durable_setup_token(&durable_client, durable_token_id.as_str())
        .expect("durable client verifies its durable credential");
    assert_eq!(inspection, ExistingTokenInspection::Reusable);

    let durable_handoff_error = durable_client
        .begin_bootstrap_maintenance("distinct-client-handoff", "missing_daemon_repair")
        .expect_err("durable client cannot begin bootstrap maintenance");
    assert!(matches!(
        durable_handoff_error,
        DaemonClientError::Api { error, .. }
            if error.code() == ApiErrorCode::AuthorizationInsufficientScope
    ));

    let begun = bootstrap_client
        .begin_bootstrap_maintenance("distinct-client-handoff", "missing_daemon_repair")
        .expect("bootstrap client begins maintenance");
    assert!(begun.reconciled());
    let completed = bootstrap_client
        .complete_bootstrap_maintenance("distinct-client-handoff")
        .expect("bootstrap client completes maintenance");
    assert!(completed.reconciled());

    drop(server);
}

#[cfg(unix)]
#[test]
fn reusable_setup_token_keeps_the_healthy_durable_daemon_running_without_bootstrap() {
    with_bootstrap_handoff_test_context(|_, fake_ssh, _, _, _| {
        let state = TestStateDir::new().expect("temporary durable state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct durable Host service");
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let (durable_token, durable_principal) = service
            .issue_pending_api_token(
                ApiScopes::CONTROL,
                time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
            )
            .expect("issue durable setup token");
        let durable_token_id = durable_principal.token_id().to_string();
        service
            .activate_api_token(&durable_token_id)
            .expect("activate durable setup token");
        let raw_token = durable_token.expose();
        let token_path = state.path().join("reusable-setup.token");
        persist_new_owner_only_secret_file(&token_path, raw_token.as_str())
            .expect("persist reusable setup token");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("construct durable daemon runtime");
        let server = runtime
            .block_on(DaemonServer::bind(
                service,
                DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            ))
            .expect("bind durable loopback daemon");
        let durable_client = DaemonClient::loopback(
            server.local_addr(),
            ApiBearerToken::parse(raw_token.as_str()).expect("parse reusable setup token"),
            &host_identity,
        )
        .expect("construct durable setup client");
        let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File {
            path: token_path,
        })))
        .expect("construct SSH setup transport");
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "reusable-token-host",
            "fake-ssh-host",
            "verify-reusable-token-before-bootstrap".to_string(),
            bootstrap_lock::OperationKind::InitialSetup,
            fake_ssh,
        )
        .expect("acquire setup lock");
        let bootstrap_called = AtomicBool::new(false);

        let verification = transport
            .verify_existing_token_with_bootstrap_fallback(
                &durable_client,
                &durable_token_id,
                "verify-reusable-token",
                &mut bootstrap_lock,
                |_| {
                    bootstrap_called.store(true, Ordering::SeqCst);
                    Err(SatelleError::host_unreachable("reusable-token-host"))
                },
            )
            .expect("reuse the healthy durable daemon token");

        assert_eq!(verification, ExistingTokenVerification::Reusable);
        assert!(!bootstrap_called.load(Ordering::SeqCst));
        assert!(bootstrap_lock.exchanged_lock_lines().iter().all(|line| {
            !line.contains("maintenance_handoff") && !line.contains("daemon_start")
        }));
        bootstrap_lock
            .release_committed_handoff()
            .expect("release the committed durable verification");
        let report = transport.setup_report(
            false,
            "on_demand".to_string(),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
            SetupApplication::AppliedReusableToken,
        );
        assert_eq!(report.status, "applied");
        assert!(!report.mutated);
        durable_client
            .capabilities()
            .expect("the canonical durable daemon remains reachable after the report");

        drop(server);
    });
}

#[cfg(unix)]
#[test]
fn authentication_rejected_by_live_daemon_enters_bootstrap_fallback() {
    with_bootstrap_handoff_test_context(|bootstrap_client, fake_ssh, _, _, _| {
        let state = TestStateDir::new().expect("temporary durable state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct durable Host service");
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let (_runtime, server) = spawn_loopback_daemon(service);
        let unissued_token = ApiBearerToken::generate().expect("generate valid unissued token");
        let unissued_token_id = unissued_token.token_id().to_string();
        let unissued_client =
            DaemonClient::loopback(server.local_addr(), unissued_token, &host_identity)
                .expect("construct unissued-token client");
        let transport =
            SshSetupTransport::new(&ssh_setup_host(None)).expect("construct SSH setup transport");
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "bootstrap-required-host",
            "fake-ssh-host",
            "bootstrap-after-durable-rejection".to_string(),
            bootstrap_lock::OperationKind::InitialSetup,
            fake_ssh,
        )
        .expect("acquire setup lock");
        let bootstrap_called = AtomicBool::new(false);

        let verification = transport
            .verify_existing_token_with_bootstrap_fallback(
                &unissued_client,
                unissued_token_id.as_str(),
                "reject-bootstrap-token-as-durable",
                &mut bootstrap_lock,
                |bootstrap_lock| {
                    bootstrap_called.store(true, Ordering::SeqCst);
                    bootstrap_lock
                        .mark_mutation_started("daemon_start")
                        .map_err(|_| SatelleError::host_unreachable("bootstrap-required-host"))?;
                    commit_verified_bootstrap_mutation("bootstrap-required-host", bootstrap_lock)?;
                    complete_bootstrap_handoff(
                        "bootstrap-required-host",
                        bootstrap_client,
                        bootstrap_lock,
                    )?;
                    Ok(ExistingTokenVerification::Reusable)
                },
            )
            .expect("enter bootstrap after durable authentication rejection");

        assert_eq!(verification, ExistingTokenVerification::Reusable);
        assert!(bootstrap_called.load(Ordering::SeqCst));
        let durable_commit = format!(
            "{} durable_token_verification ",
            bootstrap_lock::MUTATION_COMMITTED
        );
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .any(|line| line.starts_with(&durable_commit)),
            "the live daemon's explicit rejection must close the activation attempt"
        );
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .any(|line| line.contains("maintenance_handoff_complete"))
        );
        bootstrap_lock
            .release_committed_handoff()
            .expect("release the completed bootstrap handoff");

        drop(server);
    });
}

#[cfg(unix)]
#[test]
fn durable_confirmation_transport_failure_falls_back_without_open_mutation() {
    with_bootstrap_handoff_test_context(|bootstrap_client, fake_ssh, _, _, _| {
        let transport =
            SshSetupTransport::new(&ssh_setup_host(None)).expect("construct SSH setup transport");
        let unavailable_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve unavailable durable daemon address");
        let unavailable_address = unavailable_listener
            .local_addr()
            .expect("read unavailable durable daemon address");
        drop(unavailable_listener);
        let unavailable_durable_client = DaemonClient::loopback_with_timeout(
            unavailable_address,
            ApiBearerToken::generate().expect("generate unavailable durable token"),
            "unavailable-durable-host-identity",
            Duration::from_secs(1),
        )
        .expect("construct unavailable durable client");
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "transport-fallback-host",
            "fake-ssh-host",
            "bootstrap-after-durable-transport".to_string(),
            bootstrap_lock::OperationKind::InitialSetup,
            fake_ssh,
        )
        .expect("acquire setup lock");

        let verification = transport
            .verify_existing_token_with_bootstrap_fallback(
                &unavailable_durable_client,
                "unavailable-durable-token-id",
                "transport-bootstrap-token",
                &mut bootstrap_lock,
                |bootstrap_lock| {
                    bootstrap_lock
                        .mark_mutation_started("daemon_start")
                        .map_err(|_| SatelleError::host_unreachable("transport-fallback-host"))?;
                    commit_verified_bootstrap_mutation("transport-fallback-host", bootstrap_lock)?;
                    complete_bootstrap_handoff(
                        "transport-fallback-host",
                        bootstrap_client,
                        bootstrap_lock,
                    )?;
                    Ok(ExistingTokenVerification::Reusable)
                },
            )
            .expect("enter bootstrap after read-only durable transport failure");

        assert_eq!(verification, ExistingTokenVerification::Reusable);
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .all(|line| { !line.contains("durable_token_verification") })
        );
        bootstrap_lock
            .release_committed_handoff()
            .expect("release the completed bootstrap handoff");
    });
}

#[cfg(unix)]
fn acquire_bootstrap_lock_for_operation_with_ssh(
    alias: &str,
    destination: &str,
    operation_id: String,
    operation_kind: bootstrap_lock::OperationKind,
    ssh_program: &std::path::Path,
) -> Result<ssh_bootstrap::SshBootstrapLock, SatelleError> {
    let controller_identity = Some(format!("controller-pid-{}", std::process::id()));
    let request = bootstrap_lock::Request::new(operation_id, operation_kind, controller_identity)
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))?;
    ssh_bootstrap::SshBootstrapLock::acquire_for_tests(destination, request, ssh_program).map_err(
        |error| match error {
            ssh_bootstrap::SshBootstrapError::HostKeyVerificationRequired => {
                SatelleError::ssh_host_key_verification_required(alias)
            }
            ssh_bootstrap::SshBootstrapError::BootstrapBusy => {
                SatelleError::bootstrap_busy(alias, None)
            }
            _ => SatelleError::host_unreachable(alias),
        },
    )
}

#[cfg(unix)]
fn with_bootstrap_handoff_test_context(
    test: impl FnOnce(&DaemonClient, &std::path::Path, SocketAddr, &str, &HostService),
) {
    use std::os::unix::fs::PermissionsExt as _;

    let state = TestStateDir::new().expect("temporary state directory");
    let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct Host service")
        .with_ssh_bootstrap_auth_for_tests(
            &bootstrap_token,
            ApiScopes::READ,
            time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
        );
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let host_identity = initialized.host_identity().to_string();
    let ledger = service.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("construct daemon runtime");
    let server = runtime
        .block_on(DaemonServer::bind(
            service,
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        ))
        .expect("bind loopback daemon");
    let client = DaemonClient::loopback(server.local_addr(), bootstrap_token, &host_identity)
        .expect("construct operation-bound bootstrap client");

    let fake_bin = state.path().join("fake-bin");
    std::fs::create_dir(&fake_bin).expect("create fake SSH directory");
    let fake_ssh = fake_bin.join("ssh");
    std::fs::write(
        &fake_ssh,
        format!(
            r#"#!/bin/sh
command=
for argument in "$@"; do command=$argument; done
case "$command" in
  cmd.exe*) exit 1 ;;
  *"uname -s"*) printf '%s\n' satelle-platform-v1 Linux x86_64 'glibc 2.31' ;;
  *) export SATELLE_STATE_DIR='{}'; exec sh -c "$command" ;;
esac
"#,
            state.path().display()
        ),
    )
    .expect("write fake SSH executable");
    let mut permissions = std::fs::metadata(&fake_ssh)
        .expect("read fake SSH metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fake_ssh, permissions).expect("make fake SSH executable");

    test(
        &client,
        &fake_ssh,
        server.local_addr(),
        &host_identity,
        &ledger,
    );

    drop(server);
}

#[cfg(unix)]
#[test]
fn rejected_durable_token_is_reported_after_launched_daemon_handoff_is_terminal() {
    with_bootstrap_handoff_test_context(
        |bootstrap_client, fake_ssh, daemon_address, host_identity, _| {
            let durable_client = DaemonClient::loopback(
                daemon_address,
                ApiBearerToken::generate().expect("generate valid unissued durable token"),
                host_identity,
            )
            .expect("construct rejected durable client");
            let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "rejected-post-launch-token-host",
                "fake-ssh-host",
                "rejected-durable-token-after-launch".to_string(),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("acquire bootstrap lock");
            bootstrap_lock
                .mark_mutation_started("daemon_start")
                .expect("record the simulated verified daemon launch");

            let error = finish_durable_daemon_launch(
                "rejected-post-launch-token-host",
                &durable_client,
                bootstrap_client,
                &mut bootstrap_lock,
            )
            .expect_err("the stale durable token remains rejected after safe handoff");

            assert_eq!(error.code, ErrorCode::AuthenticationFailed);
            for phase in [
                "daemon_start",
                "maintenance_handoff_begin",
                "maintenance_handoff_complete",
            ] {
                let committed = format!("{} {phase} ", bootstrap_lock::MUTATION_COMMITTED);
                assert_eq!(
                    bootstrap_lock
                        .exchanged_lock_lines()
                        .iter()
                        .filter(|line| line.starts_with(&committed))
                        .count(),
                    1,
                    "{phase} has one exact commit owner before auth failure is surfaced"
                );
            }
            assert_eq!(
                bootstrap_lock
                    .exchanged_lock_lines()
                    .iter()
                    .filter(|line| line.as_str() == bootstrap_lock::RELEASE)
                    .count(),
                1,
                "the completed handoff releases before durable authentication is reported"
            );

            let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "rejected-post-launch-token-host",
                "fake-ssh-host",
                "controller-after-rejected-durable-token".to_string(),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("durable authentication failure must not strand the bootstrap lock");
            recovered_lock
                .release_unmodified()
                .expect("release recovered bootstrap lock");
        },
    );
}

#[cfg(unix)]
#[test]
fn first_trust_path_rebind_handoff_uses_the_discovered_host_identity() {
    with_bootstrap_handoff_test_context(|_, fake_ssh, _, _, _| {
        let daemon_state = TestStateDir::new().expect("temporary first-trust daemon state");
        let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
        let service = HostService::local_demo_for_tests_at(daemon_state.path())
            .expect("construct first-trust Host service")
            .with_ssh_bootstrap_auth_for_tests(
                &bootstrap_token,
                ApiScopes::ADMIN,
                time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
            );
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let raw_bootstrap_token = bootstrap_token.expose();
        let (_runtime, server) = spawn_loopback_daemon(service);
        let probe_identity = "first-trust-path-rebind-probe";
        let probe_client = DaemonClient::loopback(
            server.local_addr(),
            ApiBearerToken::parse(raw_bootstrap_token.as_str())
                .expect("parse identity probe token"),
            probe_identity,
        )
        .expect("construct temporary identity probe client");
        let handoff_token = ApiBearerToken::parse(raw_bootstrap_token.as_str())
            .expect("parse identity-pinned handoff token");
        let discovered_identity = probe_client
            .discover_host_identity()
            .expect("discover the reachable Host identity through the false probe pin");
        assert_eq!(discovered_identity, host_identity);

        let operation_id = "first-trust-path-rebind-handoff";
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "first-trust-path-rebind-host",
            "fake-ssh-host",
            operation_id.to_string(),
            bootstrap_lock::OperationKind::InitialSetup,
            fake_ssh,
        )
        .expect("acquire first-trust bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record verified discovery daemon start");
        commit_verified_bootstrap_mutation("first-trust-path-rebind-host", &mut bootstrap_lock)
            .expect("commit discovery daemon start");

        let probe_error = probe_client
            .begin_bootstrap_maintenance(operation_id, "initial_setup")
            .expect_err("the false probe identity cannot perform maintenance");
        assert!(matches!(
            probe_error,
            DaemonClientError::Api { error, .. }
                if error.code() == ApiErrorCode::HostIdentityMismatch
        ));
        complete_discovered_bootstrap_handoff(
            "first-trust-path-rebind-host",
            server.local_addr(),
            handoff_token,
            &discovered_identity,
            &mut bootstrap_lock,
        )
        .expect("the learned identity completes the first-trust handoff");
        bootstrap_lock
            .release_committed_handoff()
            .expect("release completed first-trust handoff");

        for phase in ["maintenance_handoff_begin", "maintenance_handoff_complete"] {
            let committed = format!("{} {phase} ", bootstrap_lock::MUTATION_COMMITTED);
            assert_eq!(
                bootstrap_lock
                    .exchanged_lock_lines()
                    .iter()
                    .filter(|line| line.starts_with(&committed))
                    .count(),
                1,
                "{phase} commits under the discovered identity"
            );
        }
        drop(server);
    });
}

#[cfg(unix)]
#[test]
fn conflicting_maintenance_begin_is_terminal_for_the_exact_lock_attempt() {
    with_bootstrap_handoff_test_context(|bootstrap_client, fake_ssh, _, _, ledger| {
        let competing_operation = "already-active-maintenance";
        bootstrap_client
            .begin_bootstrap_maintenance(competing_operation, "missing_daemon_repair")
            .expect("begin competing maintenance operation");

        let operation_id = "state-conflict-maintenance-begin";
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "state-conflict-handoff-host",
            "fake-ssh-host",
            operation_id.to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("acquire bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record verified daemon start");
        commit_verified_bootstrap_mutation("state-conflict-handoff-host", &mut bootstrap_lock)
            .expect("commit verified daemon start");

        let error = complete_bootstrap_handoff(
            "state-conflict-handoff-host",
            bootstrap_client,
            &mut bootstrap_lock,
        )
        .expect_err("the active competing operation rejects this exact begin");

        assert_eq!(error.code, ErrorCode::StateConflict);
        assert!(
            ledger
                .load_setup_run(operation_id)
                .expect("read rejected operation ledger")
                .is_none(),
            "the conflicting exact operation must not mutate the ledger"
        );
        let begin_commit = format!(
            "{} maintenance_handoff_begin ",
            bootstrap_lock::MUTATION_COMMITTED
        );
        assert_eq!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .filter(|line| line.starts_with(&begin_commit))
                .count(),
            1,
            "the known StateConflict outcome closes the exact begin attempt"
        );
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .all(|line| !line.contains("maintenance_handoff_complete")),
            "a rejected begin must not open the complete phase"
        );
        drop(bootstrap_lock);

        let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "state-conflict-handoff-host",
            "fake-ssh-host",
            "controller-after-state-conflict".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("a new Controller acquires after the terminal conflict");
        recovered_lock
            .release_unmodified()
            .expect("release recovered bootstrap lock");
        bootstrap_client
            .complete_bootstrap_maintenance(competing_operation)
            .expect("complete competing maintenance fixture");
    });
}

#[cfg(unix)]
#[test]
fn connection_capacity_rejection_is_terminal_for_the_exact_lock_attempt() {
    with_bootstrap_handoff_test_context(|_, fake_ssh, _, _, _| {
        let daemon_state = TestStateDir::new().expect("temporary capacity daemon state");
        let bootstrap_token = ApiBearerToken::generate().expect("generate bootstrap token");
        let service = HostService::local_demo_for_tests_at(daemon_state.path())
            .expect("construct capacity Host service")
            .with_ssh_bootstrap_auth_for_tests(
                &bootstrap_token,
                ApiScopes::READ,
                time::OffsetDateTime::now_utc() + time::Duration::minutes(5),
            );
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let ledger = service.clone();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("construct capacity daemon runtime");
        let server = runtime
            .block_on(DaemonServer::bind(
                service,
                DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                    .with_max_connections(1),
            ))
            .expect("bind capacity-limited daemon");
        let capacity_client =
            DaemonClient::loopback(server.local_addr(), bootstrap_token, &host_identity)
                .expect("construct capacity-rejected bootstrap client");

        // Complete one real request on the sole admitted connection, then keep
        // that HTTP/1.1 socket open so the next connection enters the server's
        // bounded typed-rejection lane.
        let mut occupant = TcpStream::connect(server.local_addr())
            .expect("open the sole admitted Host connection");
        occupant
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound the occupancy probe read");
        occupant
            .write_all(
                b"GET /v1/live HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
            )
            .expect("send occupancy probe");
        let mut response_head = Vec::new();
        let mut chunk = [0_u8; 512];
        while !response_head.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = occupant.read(&mut chunk).expect("read occupancy response");
            assert!(count > 0, "occupancy response must contain HTTP headers");
            response_head.extend_from_slice(&chunk[..count]);
        }
        assert!(
            response_head.starts_with(b"HTTP/1.1 200"),
            "the held connection must consume normal server capacity"
        );

        let operation_id = "connection-capacity-maintenance-begin";
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "capacity-handoff-host",
            "fake-ssh-host",
            operation_id.to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("acquire bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record verified daemon start");
        commit_verified_bootstrap_mutation("capacity-handoff-host", &mut bootstrap_lock)
            .expect("commit verified daemon start");

        let error = complete_bootstrap_handoff(
            "capacity-handoff-host",
            &capacity_client,
            &mut bootstrap_lock,
        )
        .expect_err("HTTP connection capacity rejects maintenance before its handler");

        assert_eq!(error.code, ErrorCode::RemoteExecution);
        assert!(
            ledger
                .load_setup_run(operation_id)
                .expect("read capacity-rejected operation ledger")
                .is_none(),
            "capacity rejection must occur before maintenance ledger mutation"
        );
        let begin_commit = format!(
            "{} maintenance_handoff_begin ",
            bootstrap_lock::MUTATION_COMMITTED
        );
        assert_eq!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .filter(|line| line.starts_with(&begin_commit))
                .count(),
            1,
            "the exact capacity-rejected attempt has one terminal owner"
        );
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .all(|line| !line.contains("maintenance_handoff_complete")),
            "capacity-rejected begin must not open the complete phase"
        );
        drop(bootstrap_lock);

        let lock_state_root = fake_ssh
            .parent()
            .and_then(std::path::Path::parent)
            .expect("fake SSH state root");
        let terminal = std::fs::read_to_string(
            lock_state_root.join(format!("bootstrap-operation-{operation_id}.json")),
        )
        .expect("read capacity-rejected terminal record");
        assert!(terminal.contains("\"terminal_state\":\"reconciled_failed\""));
        let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "capacity-handoff-host",
            "fake-ssh-host",
            "controller-after-capacity-rejection".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("a new Controller acquires after terminal capacity rejection");
        recovered_lock
            .release_unmodified()
            .expect("release recovered bootstrap lock");

        drop(occupant);
        drop(server);
    });
}

#[cfg(unix)]
#[test]
fn prehandler_handoff_rejection_is_terminal_without_mutating_the_ledger() {
    with_bootstrap_handoff_test_context(|_, fake_ssh, _, _, _| {
        let daemon_state = TestStateDir::new().expect("temporary rejected daemon state");
        let service = HostService::local_demo_for_tests_at(daemon_state.path())
            .expect("construct rejected Host service");
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let ledger = service.clone();
        let (_runtime, server) = spawn_loopback_daemon(service);
        let rejected_client = DaemonClient::loopback(
            server.local_addr(),
            ApiBearerToken::generate().expect("generate unissued bootstrap token"),
            &host_identity,
        )
        .expect("construct rejected bootstrap client");
        let operation_id = "prehandler-rejected-handoff";
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "prehandler-rejected-host",
            "fake-ssh-host",
            operation_id.to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("acquire bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record verified daemon start");
        commit_verified_bootstrap_mutation("prehandler-rejected-host", &mut bootstrap_lock)
            .expect("commit verified daemon start");

        let error = complete_bootstrap_handoff(
            "prehandler-rejected-host",
            &rejected_client,
            &mut bootstrap_lock,
        )
        .expect_err("authentication middleware rejects the handoff");

        assert_eq!(error.code, ErrorCode::AuthenticationFailed);
        assert!(
            ledger
                .load_setup_run(operation_id)
                .expect("read maintenance ledger")
                .is_none(),
            "pre-handler rejection must not create a maintenance run"
        );
        let begin_commit = format!(
            "{} maintenance_handoff_begin ",
            bootstrap_lock::MUTATION_COMMITTED
        );
        assert_eq!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .filter(|line| line.starts_with(&begin_commit))
                .count(),
            1,
            "the exact rejected attempt must have one terminal owner"
        );
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .all(|line| !line.contains("maintenance_handoff_complete")),
            "begin rejection must not open the complete phase"
        );
        drop(bootstrap_lock);

        let lock_state_root = fake_ssh
            .parent()
            .and_then(std::path::Path::parent)
            .expect("fake SSH state root");
        let terminal = std::fs::read_to_string(
            lock_state_root.join(format!("bootstrap-operation-{operation_id}.json")),
        )
        .expect("read rejected handoff terminal record");
        assert!(terminal.contains("\"terminal_state\":\"reconciled_failed\""));
        let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "prehandler-rejected-host",
            "fake-ssh-host",
            "controller-after-prehandler-rejection".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("a new Controller acquires immediately after definite rejection");
        recovered_lock
            .release_unmodified()
            .expect("release recovered bootstrap lock");

        drop(server);
    });
}

#[cfg(unix)]
#[test]
fn prehandler_complete_rejection_does_not_complete_the_maintenance_ledger() {
    with_bootstrap_handoff_test_context(
        |bootstrap_client, fake_ssh, daemon_address, host_identity, ledger| {
            let rejected_client = DaemonClient::loopback(
                daemon_address,
                ApiBearerToken::generate().expect("generate unissued completion token"),
                host_identity,
            )
            .expect("construct rejected completion client");
            let operation_id = "prehandler-rejected-completion";
            let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "prehandler-complete-host",
                "fake-ssh-host",
                operation_id.to_string(),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("acquire bootstrap lock");
            bootstrap_lock
                .mark_mutation_started("daemon_start")
                .expect("record verified daemon start");
            commit_verified_bootstrap_mutation("prehandler-complete-host", &mut bootstrap_lock)
                .expect("commit verified daemon start");
            bootstrap_lock
                .mark_mutation_started("maintenance_handoff_begin")
                .expect("record maintenance begin");
            let begun = bootstrap_client
                .begin_bootstrap_maintenance(operation_id, "missing_daemon_repair")
                .expect("authorized client begins maintenance");
            assert!(begun.reconciled());
            commit_verified_bootstrap_mutation("prehandler-complete-host", &mut bootstrap_lock)
                .expect("commit accepted maintenance begin");
            bootstrap_lock
                .mark_mutation_started("maintenance_handoff_complete")
                .expect("record maintenance completion");

            let completion = rejected_client.complete_bootstrap_maintenance(operation_id);
            let error = reconcile_bootstrap_maintenance_response(
                "prehandler-complete-host",
                completion,
                &mut bootstrap_lock,
            )
            .expect_err("authentication middleware rejects completion");

            assert_eq!(error.code, ErrorCode::AuthenticationFailed);
            assert_eq!(
                ledger
                    .load_setup_run(operation_id)
                    .expect("read maintenance ledger")
                    .expect("maintenance run remains present")
                    .status(),
                satelle_host::SetupRunStatus::Running,
                "pre-handler rejection must not complete the maintenance run"
            );
            let completion_commit = format!(
                "{} maintenance_handoff_complete ",
                bootstrap_lock::MUTATION_COMMITTED
            );
            assert_eq!(
                bootstrap_lock
                    .exchanged_lock_lines()
                    .iter()
                    .filter(|line| line.starts_with(&completion_commit))
                    .count(),
                1,
                "the exact rejected completion has one terminal owner"
            );
            drop(bootstrap_lock);

            let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "prehandler-complete-host",
                "fake-ssh-host",
                "controller-after-prehandler-complete-rejection".to_string(),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("a new Controller acquires after definite completion rejection");
            recovered_lock
                .release_unmodified()
                .expect("release recovered bootstrap lock");
        },
    );
}

#[cfg(unix)]
#[test]
fn handoff_transport_uncertainty_remains_recovery_pending_and_fenced() {
    with_bootstrap_handoff_test_context(|_, fake_ssh, _, _, _| {
        assert!(
            !bootstrap_maintenance_rejection_precedes_mutation(
                &DaemonClientError::ResponseContractViolation
            ),
            "response-contract uncertainty must not be treated as pre-handler rejection"
        );
        let unavailable_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve unavailable handoff address");
        let unavailable_address = unavailable_listener
            .local_addr()
            .expect("read unavailable handoff address");
        drop(unavailable_listener);
        let unavailable_client = DaemonClient::loopback_with_timeout(
            unavailable_address,
            ApiBearerToken::generate().expect("generate unavailable bootstrap token"),
            "unavailable-handoff-host-identity",
            Duration::from_secs(1),
        )
        .expect("construct unavailable bootstrap client");
        let operation_id = "uncertain-handoff-transport";
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "uncertain-handoff-host",
            "fake-ssh-host",
            operation_id.to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("acquire bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record verified daemon start");
        commit_verified_bootstrap_mutation("uncertain-handoff-host", &mut bootstrap_lock)
            .expect("commit verified daemon start");

        let error = complete_bootstrap_handoff(
            "uncertain-handoff-host",
            &unavailable_client,
            &mut bootstrap_lock,
        )
        .expect_err("transport loss leaves the handoff outcome uncertain");

        assert_eq!(error.code, ErrorCode::HostUnreachable);
        let begin_commit = format!(
            "{} maintenance_handoff_begin ",
            bootstrap_lock::MUTATION_COMMITTED
        );
        assert!(
            bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .all(|line| !line.starts_with(&begin_commit)),
            "transport uncertainty must not be committed"
        );
        drop(bootstrap_lock);

        let lock_root = fake_ssh
            .parent()
            .and_then(std::path::Path::parent)
            .expect("fake SSH state root")
            .join("bootstrap.lock");
        let claim = std::fs::read_dir(&lock_root)
            .expect("read bootstrap lock root")
            .map(|entry| entry.expect("read bootstrap claim").path())
            .find(|path| {
                path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.starts_with("claim."))
            })
            .expect("uncertain claim remains");
        assert_eq!(
            std::fs::read_to_string(claim.join("state"))
                .expect("read uncertain claim state")
                .trim(),
            "recovery_pending"
        );
        let contender = acquire_bootstrap_lock_for_operation_with_ssh(
            "uncertain-handoff-host",
            "fake-ssh-host",
            "controller-during-uncertain-handoff".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        );
        let Err(contender) = contender else {
            panic!("a new Controller must remain fenced from an uncertain handoff");
        };
        assert_eq!(contender.code, ErrorCode::BootstrapBusy);
    });
}

#[cfg(unix)]
#[test]
fn completed_bootstrap_handoff_commit_allows_recovery_after_controller_loss() {
    with_bootstrap_handoff_test_context(|client, fake_ssh, _, _, _| {
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "crash-window-host",
            "fake-ssh-host",
            "completed-handoff-before-controller-loss".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("acquire the initial bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record the verified daemon start");
        commit_verified_bootstrap_mutation("crash-window-host", &mut bootstrap_lock)
            .expect("commit the verified daemon start");
        complete_bootstrap_handoff("crash-window-host", client, &mut bootstrap_lock)
            .expect("complete the bootstrap maintenance handoff");

        // Losing the Controller channel before RELEASE must reconcile the exact
        // completed attempt instead of leaving the remote fence permanently busy.
        drop(bootstrap_lock);
        let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "crash-window-host",
            "fake-ssh-host",
            "controller-after-completed-handoff".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("a new Controller can acquire after the completed handoff");
        recovered_lock
            .release_unmodified()
            .expect("release the recovered bootstrap lock");
    });
}

#[cfg(unix)]
#[test]
fn successful_bootstrap_handoff_release_does_not_repeat_the_completion_commit() {
    with_bootstrap_handoff_test_context(|client, fake_ssh, _, _, _| {
        let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "successful-release-host",
            "fake-ssh-host",
            "completed-handoff-before-release".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("acquire the bootstrap lock");
        bootstrap_lock
            .mark_mutation_started("daemon_start")
            .expect("record the verified daemon start");
        commit_verified_bootstrap_mutation("successful-release-host", &mut bootstrap_lock)
            .expect("commit the verified daemon start");
        complete_bootstrap_handoff("successful-release-host", client, &mut bootstrap_lock)
            .expect("complete and commit the bootstrap maintenance handoff");
        bootstrap_lock
            .release_committed_handoff()
            .expect("release without committing the completion attempt twice");

        let mut next_lock = acquire_bootstrap_lock_for_operation_with_ssh(
            "successful-release-host",
            "fake-ssh-host",
            "controller-after-successful-release".to_string(),
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            fake_ssh,
        )
        .expect("successful release removes the prior claim");
        next_lock
            .release_unmodified()
            .expect("release the next bootstrap lock");

        for phase in ["daemon_start", "maintenance_handoff_complete"] {
            let committed = format!("{} {phase} ", bootstrap_lock::MUTATION_COMMITTED);
            assert_eq!(
                bootstrap_lock
                    .exchanged_lock_lines()
                    .iter()
                    .filter(|line| line.starts_with(&committed))
                    .count(),
                1,
                "{phase} must have exactly one commit owner"
            );
        }
    });
}

#[cfg(unix)]
#[test]
fn prior_mutation_commit_precedes_maintenance_handoff_begin_for_both_phase_shapes() {
    with_bootstrap_handoff_test_context(|client, fake_ssh, _, _, _| {
        for (phase, operation_id) in [
            ("daemon_start", "ordered-daemon-start"),
            (
                "durable_token_verification",
                "ordered-durable-token-verification",
            ),
        ] {
            let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "ordered-handoff-host",
                "fake-ssh-host",
                operation_id.to_string(),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("acquire the bootstrap lock");
            bootstrap_lock
                .mark_mutation_started(phase)
                .expect("record the verified prior mutation");
            commit_verified_bootstrap_mutation("ordered-handoff-host", &mut bootstrap_lock)
                .expect("commit the verified prior mutation at its owner boundary");
            complete_bootstrap_handoff("ordered-handoff-host", client, &mut bootstrap_lock)
                .expect("complete the bootstrap maintenance handoff");
            bootstrap_lock
                .release_committed_handoff()
                .expect("release the committed handoff");

            let prior_commit = format!("{} {phase} ", bootstrap_lock::MUTATION_COMMITTED);
            let maintenance_begin = format!(
                "{} maintenance_handoff_begin ",
                bootstrap_lock::MUTATION_STARTED
            );
            let prior_commit_index = bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .position(|line| line.starts_with(&prior_commit))
                .expect("the prior mutation is committed");
            let maintenance_begin_index = bootstrap_lock
                .exchanged_lock_lines()
                .iter()
                .position(|line| line.starts_with(&maintenance_begin))
                .expect("the maintenance begin attempt is recorded");
            assert!(
                prior_commit_index < maintenance_begin_index,
                "{phase} must be committed before maintenance handoff begins"
            );
            assert_eq!(
                bootstrap_lock
                    .exchanged_lock_lines()
                    .iter()
                    .filter(|line| line.starts_with(&prior_commit))
                    .count(),
                1,
                "{phase} must not be committed again by maintenance handoff"
            );
        }
    });
}

#[cfg(unix)]
#[test]
fn committed_prior_mutation_recovers_after_controller_loss_for_both_phase_shapes() {
    with_bootstrap_handoff_test_context(|_, fake_ssh, _, _, _| {
        for (phase, operation_id) in [
            ("daemon_start", "lost-after-committed-daemon-start"),
            (
                "durable_token_verification",
                "lost-after-committed-durable-verification",
            ),
        ] {
            let mut bootstrap_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "prior-commit-recovery-host",
                "fake-ssh-host",
                operation_id.to_string(),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("acquire the bootstrap lock");
            bootstrap_lock
                .mark_mutation_started(phase)
                .expect("record the verified prior mutation");
            commit_verified_bootstrap_mutation("prior-commit-recovery-host", &mut bootstrap_lock)
                .expect("commit the verified prior mutation");
            if phase == "daemon_start" {
                let unavailable_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                    .expect("reserve unavailable post-launch daemon address");
                let unavailable_address = unavailable_listener
                    .local_addr()
                    .expect("read unavailable post-launch daemon address");
                drop(unavailable_listener);
                let unavailable_client = DaemonClient::loopback_with_timeout(
                    unavailable_address,
                    ApiBearerToken::generate().expect("generate post-launch probe token"),
                    "post-launch-host-identity",
                    Duration::from_secs(1),
                )
                .expect("construct post-launch daemon client");
                assert!(matches!(
                    unavailable_client.capabilities(),
                    Err(DaemonClientError::Transport(_))
                ));
            }
            drop(bootstrap_lock);

            let mut recovered_lock = acquire_bootstrap_lock_for_operation_with_ssh(
                "prior-commit-recovery-host",
                "fake-ssh-host",
                format!("controller-after-{operation_id}"),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                fake_ssh,
            )
            .expect("a new Controller can acquire after committed controller loss");
            recovered_lock
                .release_unmodified()
                .expect("release the recovered bootstrap lock");
        }
    });
}

#[test]
fn ssh_setup_rejects_unimplemented_components_before_mutating() {
    let path = std::env::temp_dir().join("satelle-unsupported-setup.token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File { path })))
        .expect("construct setup");

    for components in [
        vec!["all".to_string()],
        vec!["provider-auth".to_string()],
        vec!["transport".to_string(), "host".to_string()],
    ] {
        let error = transport
            .setup(
                false,
                setup_selection(satelle_core::SetupMode::OnDemand),
                components,
                DaemonPathOverrides::default(),
            )
            .expect_err("partial SSH setup must be rejected");

        assert_eq!(error.code, ErrorCode::NotImplemented);
    }
}

#[test]
fn ssh_setup_rejects_explicit_persistent_linux_before_mutating() {
    let path = std::env::temp_dir().join("satelle-persistent-setup.token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File { path })))
        .expect("construct setup");
    let error = transport
        .setup(
            false,
            setup_selection(satelle_core::SetupMode::Persistent),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
        )
        .expect_err("explicit persistent Linux setup must fail closed");

    assert_eq!(error.code, ErrorCode::PersistentServiceUnsupported);
    assert_eq!(
        error.details.get("platform"),
        Some(&serde_json::json!("linux"))
    );
    assert_eq!(
        error.details.get("mutated"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn ssh_setup_falls_back_only_for_inherited_persistent_linux() {
    let path = std::env::temp_dir().join("satelle-inherited-persistent-setup.token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File { path })))
        .expect("construct setup");
    let report = transport
        .setup(
            true,
            SetupModeSelection::new(
                satelle_core::SetupMode::Persistent,
                satelle_core::daemon_service::SetupModeSource::UserConfig,
            ),
            vec!["transport".to_string()],
            DaemonPathOverrides::default(),
        )
        .expect("inherited persistent Linux mode must produce an on-demand fallback plan");

    assert_eq!(report.setup_mode, "on_demand");
    assert!(!report.service_persistent);
    assert_eq!(report.service_scope, "on_demand");
    assert_eq!(report.target_platform.as_deref(), Some("linux-x64-gnu"));
    assert!(
        report
            .fallback_reason
            .is_some_and(|reason| reason.contains("unsupported"))
    );
}

#[test]
fn ssh_setup_plans_windows_task_scheduler_login_session_service() {
    let path = std::env::temp_dir().join("satelle-windows-persistent-setup.token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File { path })))
        .expect("construct setup")
        .with_remote_target_for_tests(ssh_bootstrap::RemoteTarget::WindowsX64Msvc);
    let report = transport
        .setup(
            true,
            setup_selection(satelle_core::SetupMode::Persistent),
            vec!["transport".to_string()],
            DaemonPathOverrides {
                state_dir: Some(PathBuf::from(r"C:\Satelle\state")),
                log_dir: Some(PathBuf::from(r"C:\Satelle\logs")),
                ..DaemonPathOverrides::default()
            },
        )
        .expect("Windows persistent setup must produce a service plan");

    assert_eq!(report.setup_mode, "persistent");
    assert!(report.service_persistent);
    assert_eq!(report.service_scope, "login_session");
    assert_eq!(report.target_platform.as_deref(), Some("win32-x64-msvc"));
    let service = report.service_plan.expect("service plan");
    assert_eq!(
        service.manager,
        satelle_core::daemon_service::DaemonServiceManager::WindowsTaskScheduler
    );
    assert!(!service.privileged);
    let artifact = report.host_artifact.expect("Host artifact plan");
    assert_eq!(artifact.current_version, None);
    assert_eq!(artifact.target_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(artifact.target_platform, "win32-x64-msvc");
    assert_eq!(
        artifact.artifact_digest,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(
        artifact
            .install_path
            .starts_with(r"C:\Users\operator\AppData\Local\Satelle\host")
    );
    assert!(artifact.install_path.ends_with(".exe"));
    assert!(artifact.restart_impact.contains("persistent Host Daemon"));
    let current_paths = report
        .current_daemon_paths
        .expect("current daemon Path Set");
    assert_eq!(
        current_paths.state_root,
        r"C:\Users\operator\AppData\Local\Microck\Satelle\data\state"
    );
    let planned_paths = report
        .planned_daemon_paths
        .expect("planned daemon Path Set");
    assert_eq!(planned_paths.state_root, r"C:\Satelle\state");
    assert_eq!(planned_paths.operator_log_root, r"C:\Satelle\logs");
    assert!(
        planned_paths
            .required_directories()
            .contains(&r"C:\Satelle\state".to_string())
    );
    assert!(report.planned_actions.iter().any(|action| {
        action.contains("windows_task_scheduler")
            && action.contains("authenticated loopback readiness")
    }));
}

#[test]
fn ssh_setup_path_overrides_wait_for_required_token_input_without_mutating() {
    let state = TestStateDir::new().expect("temporary state directory");
    let transport = SshSetupTransport::new(&ssh_setup_host(None)).expect("construct setup");
    let overrides = DaemonPathOverrides {
        state_dir: Some(state.path().join("remote-state")),
        ..DaemonPathOverrides::default()
    };

    let report = transport
        .setup(
            false,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            overrides,
        )
        .expect("missing token input must return a non-mutating setup report");

    assert_eq!(report.status, "input_required");
    assert_eq!(report.daemon_path_overrides.len(), 1);
    assert!(!report.mutated);
}

#[test]
fn remote_daemon_path_override_errors_preserve_the_typed_input_contract() {
    let error = map_ssh_daemon_bootstrap_error(
        "remote",
        ssh_bootstrap::SshBootstrapError::DaemonPathOverrideNotAbsolute {
            name: "SATELLE_STATE_DIR",
            value: "/srv/satelle/state".to_string(),
        },
    );

    assert_eq!(error.code, ErrorCode::DaemonPathOverrideNotAbsolute);
    assert_eq!(
        error.details.get("flag"),
        Some(&serde_json::json!("SATELLE_STATE_DIR"))
    );
    assert_eq!(
        error.details.get("value"),
        Some(&serde_json::json!("/srv/satelle/state"))
    );
}

#[test]
fn ssh_setup_path_change_does_not_reuse_an_existing_store_token() {
    let temporary_root = tempfile::tempdir().expect("temporary root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            temporary_root.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("make temporary root owner-only");
    }
    let token_directory = temporary_root.path().join("owner-only");
    drop(
        satelle_core::open_or_create_owner_only_directory(&token_directory)
            .expect("create owner-only token directory"),
    );
    let token_path = token_directory.join("existing-store.token");
    let token = ApiBearerToken::generate().expect("generate existing API token");
    let raw_token = token.expose();
    persist_new_owner_only_secret_file(&token_path, raw_token.as_str())
        .expect("persist existing store token");
    let transport = SshSetupTransport::new(&ssh_setup_host(Some(ApiTokenSource::File {
        path: token_path.clone(),
    })))
    .expect("construct setup");
    let overrides = DaemonPathOverrides {
        state_dir: Some(temporary_root.path().join("different-remote-state")),
        ..DaemonPathOverrides::default()
    };

    let report = transport
        .setup(
            false,
            setup_selection(satelle_core::SetupMode::OnDemand),
            vec!["transport".to_string()],
            overrides,
        )
        .expect("path change must require a distinct token binding before SSH mutation");

    assert_eq!(report.status, "input_required");
    assert_eq!(report.readiness_summary.transport, "input_required");
    assert!(report.required_input.iter().any(|input| {
        input.input_kind == "daemon_path_override_token_rebind_required"
            && input
                .recovery_command
                .contains("new unused file-backed api_token path")
    }));
    assert!(!report.mutated);
    assert_eq!(
        read_owner_only_secret_file(&token_path).expect("read preserved old-store token"),
        raw_token
    );
}

impl ComputerUseAdapter for RecordingProviderIntentAdapter {
    fn preflight(
        &self,
        _host: &str,
        intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        *self.observed.lock().unwrap() = Some(intent.clone());
        Err(SatelleError::unsupported_provider_computer_use())
    }

    fn execute(&self, _request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        unreachable!("failed preflight must prevent adapter execution")
    }

    fn observe_stop(&self, _subject: AdapterSubject<'_>) -> Result<StopObservation, SatelleError> {
        Ok(StopObservation::UpstreamInactiveConfirmed)
    }

    fn observe_recovery(
        &self,
        _subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        Ok(RecoveryObservation::Unknown)
    }
}

#[test]
fn local_turn_request_provider_intent_reaches_host_preflight() {
    let state = TestStateDir::new().unwrap();
    let observed = Arc::new(Mutex::new(None));
    let service = HostService::with_adapter_for_tests_at(
        state.path(),
        RecordingProviderIntentAdapter {
            observed: Arc::clone(&observed),
        },
    )
    .unwrap();
    let transport = LocalTransport::new(LOCAL_DEMO_HOST.to_string(), service);
    let request = TurnRequest::new("provider intent probe").with_provider_intent(
        Some("model-explicit".to_string()),
        Some("provider-explicit".to_string()),
        true,
        true,
    );

    let failure = match transport.run(&request, false, &mut |_| Ok(())) {
        Err(failure) => failure,
        Ok(_) => panic!("provider preflight should reject the recording adapter"),
    };

    assert_eq!(
        failure.error().code,
        ErrorCode::UnsupportedProviderComputerUse
    );
    let observed = observed.lock().unwrap();
    let observed = observed.as_ref().expect("adapter observed provider intent");
    assert_eq!(observed.model().unwrap().as_str(), "model-explicit");
    assert_eq!(observed.provider().unwrap().as_str(), "provider-explicit");
    assert!(observed.experimental());
    assert!(observed.refresh());
}

#[test]
fn process_interrupt_arm_returns_only_after_ctrl_c_listener_is_polled() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("construct signal test runtime");
    let interrupt = ProcessInterrupt::default();

    runtime
        .block_on(interrupt.arm())
        .expect("arm process interrupt");

    assert!(interrupt.inner.started.load(Ordering::Acquire));
    assert!(
        interrupt.inner.armed.load(Ordering::Acquire),
        "arm must not return until the ctrl_c future has completed its first poll"
    );
}

#[test]
fn local_attached_arms_interrupt_before_starting_admission_thread() {
    let state = TestStateDir::new().expect("temporary state directory");
    let interrupt = ArmOrderInterrupt::default();
    let service = HostService::with_adapter_for_tests_at(
        state.path(),
        ArmCheckingAdapter {
            armed: Arc::clone(&interrupt.armed),
        },
    )
    .expect("construct arm-order Host");
    let transport = LocalTransport::new(LOCAL_DEMO_HOST.to_string(), service);

    transport
        .attached_with_interrupt(
            None,
            TurnIntent::new(
                "prove interrupt arming order",
                satelle_core::session::TurnExecutionMode::Standard,
            )
            .expect("construct arm-order intent"),
            false,
            &interrupt,
        )
        .expect("attached operation must complete after the arm-order assertion");
}

#[test]
fn injected_interrupt_before_local_run_admission_cancels_without_creating_a_turn() {
    let state = TestStateDir::new().expect("temporary state directory");
    let adapter = InterruptLifecycleAdapter::default();
    adapter.block_preflight();
    let service = HostService::with_adapter_for_tests_at(state.path(), adapter.clone())
        .expect("construct interrupt lifecycle Host");
    let transport = LocalTransport::new(LOCAL_DEMO_HOST.to_string(), service.clone());
    let interrupt = TestInterrupt::default();
    let command_interrupt = interrupt.clone();
    let command = thread::spawn(move || {
        transport.attached_with_interrupt(
            None,
            TurnIntent::new(
                "cancel before local run admission",
                satelle_core::session::TurnExecutionMode::Standard,
            )
            .expect("construct run intent"),
            false,
            &command_interrupt,
        )
    });
    assert!(
        adapter.preflight_started.wait_for(Duration::from_secs(2)),
        "preflight must be active before interruption"
    );

    interrupt.signal();
    adapter.preflight_release.signal();
    let failure = match command.join().expect("command thread must not panic") {
        Err(failure) => failure,
        Ok(_) => panic!("pre-admission interruption must fail the attached command"),
    };
    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().exit_code(), 130);
    assert_eq!(
        service
            .daemon_runtime_status()
            .expect("read Host status")
            .session_count(),
        0
    );
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn local_interrupt_wait_failure_reconciles_the_spawned_operation() {
    let state = TestStateDir::new().expect("temporary state directory");
    let adapter = InterruptLifecycleAdapter::default();
    adapter.block_preflight();
    let service = HostService::with_adapter_for_tests_at(state.path(), adapter.clone())
        .expect("construct interrupt lifecycle Host");
    let transport = LocalTransport::new(LOCAL_DEMO_HOST.to_string(), service.clone());
    let interrupt = FailingWaitInterrupt {
        operation_started: adapter.preflight_started.clone(),
    };
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let command = thread::spawn(move || {
        let result = transport.attached_with_interrupt(
            None,
            TurnIntent::new(
                "reconcile failed local interrupt listener",
                satelle_core::session::TurnExecutionMode::Standard,
            )
            .expect("construct run intent"),
            false,
            &interrupt,
        );
        result_sender
            .send(result)
            .expect("test result receiver remains connected");
    });
    assert!(
        adapter.preflight_started.wait_for(Duration::from_secs(2)),
        "preflight must be active before the listener fails"
    );
    if let Ok(result) = result_receiver.recv_timeout(Duration::from_millis(100)) {
        adapter.preflight_release.signal();
        let _ = command.join();
        panic!("listener failure returned before reconciling the operation: {result:?}");
    }

    adapter.preflight_release.signal();
    let failure = result_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("operation must reconcile after preflight exits")
        .expect_err("listener failure must fail the attached command");
    command.join().expect("command thread must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::HostUnreachable);
    assert_eq!(
        service
            .daemon_runtime_status()
            .expect("read Host status")
            .session_count(),
        0,
        "failed interrupt observation must not leave a local Session running"
    );
}

#[test]
fn local_interruption_preserves_admission_unknown_phase() {
    let failure = local_interrupted_admission_failure(TurnAdmissionFailure::admission_unknown(
        SatelleError::host_unreachable("local"),
    ));

    assert_eq!(failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert!(failure.durable_handles().is_none());
}

#[test]
fn injected_interrupt_after_local_run_admission_confirms_stop_before_exit_130() {
    let state = TestStateDir::new().expect("temporary state directory");
    let adapter = InterruptLifecycleAdapter::default();
    adapter.block_execute();
    let service = HostService::with_adapter_for_tests_at(state.path(), adapter.clone())
        .expect("construct interrupt lifecycle Host");
    let transport = LocalTransport::new(LOCAL_DEMO_HOST.to_string(), service.clone());
    let interrupt = TestInterrupt::default();
    let command_interrupt = interrupt.clone();
    let command = thread::spawn(move || {
        transport.attached_with_interrupt(
            None,
            TurnIntent::new(
                "interrupt admitted local run",
                satelle_core::session::TurnExecutionMode::Standard,
            )
            .expect("construct run intent"),
            false,
            &command_interrupt,
        )
    });
    assert!(
        adapter.execute_started.wait_for(Duration::from_secs(2)),
        "execution must start after durable admission"
    );

    interrupt.signal();
    let failure = match command.join().expect("command thread must not panic") {
        Err(failure) => failure,
        Ok(_) => panic!("post-admission interruption must fail with exit 130"),
    };
    assert_eq!(failure.phase(), TurnAdmissionPhase::Admitted);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().exit_code(), 130);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 1);
    let (session_id, _) = failure
        .durable_handles()
        .expect("admitted interruption retains durable handles");
    let status = service
        .session_status(session_id)
        .expect("stopped Session remains readable");
    assert_eq!(status.activity(), &SessionActivity::Idle);
    assert!(
        status
            .turns()
            .last()
            .expect("interrupted run has its Turn")
            .state()
            .is_terminal()
    );
}

#[test]
fn local_transport_rejects_detach_on_interrupt_before_admission() {
    let state = TestStateDir::new().expect("temporary state directory");
    let adapter = InterruptLifecycleAdapter::default();
    let service = HostService::with_adapter_for_tests_at(state.path(), adapter.clone())
        .expect("construct interrupt lifecycle Host");
    let seed = service
        .run(
            LOCAL_DEMO_HOST,
            &TurnIntent::new(
                "seed local steer interruption",
                satelle_core::session::TurnExecutionMode::Standard,
            )
            .expect("construct seed intent"),
        )
        .expect("seed Session")
        .session;
    let turn_count = seed.turns().len();

    let transport = LocalTransport::new(LOCAL_DEMO_HOST.to_string(), service.clone());
    let interrupt = TestInterrupt::default();
    let failure = transport
        .attached_with_interrupt(
            Some(seed.session_id().clone()),
            TurnIntent::new(
                "reject local detach-on-interrupt",
                satelle_core::session::TurnExecutionMode::Standard,
            )
            .expect("construct steer intent"),
            true,
            &interrupt,
        )
        .expect_err("local transport cannot durably detach in-process work");
    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::InvalidUsage);
    assert_eq!(failure.error().exit_code(), 64);
    assert!(failure.durable_handles().is_none());
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        service
            .session_status(seed.session_id())
            .expect("seed Session remains readable")
            .turns()
            .len(),
        turn_count,
        "local rejection must happen before Turn admission"
    );
}

#[path = "transport-reconnect-tests.rs"]
mod reconnect;

fn register_client_tokens(
    service: &HostService,
    principal: &str,
) -> (ApiBearerToken, ApiBearerToken) {
    let generated = ApiBearerToken::generate().expect("generate API token");
    let exposed = generated.expose();
    let registry_token = ApiBearerToken::parse(exposed.as_str()).expect("parse registry token");
    let http_token = ApiBearerToken::parse(exposed.as_str()).expect("parse HTTP token");
    let event_token = ApiBearerToken::parse(exposed.as_str()).expect("parse event token");
    service
        .register_api_token(&registry_token, principal, ApiScopes::CONTROL, None)
        .expect("register API token");
    (http_token, event_token)
}

fn cursor_expiry_api_error(
    earliest_available_cursor: serde_json::Value,
    resume_cursor: &str,
) -> satelle_transport::ApiError {
    serde_json::from_value(serde_json::json!({
        "schema_version": "satelle.error.v1",
        "request_id": satelle_transport::RequestId::new().to_string(),
        "host_identity": "host-direct-test",
        "code": "logs-cursor-expired",
        "category": "not_found",
        "retryable": false,
        "message": "the Log Cursor is older than retained Host history",
        "details": {
            "earliest_available_cursor": earliest_available_cursor,
            "resume_cursor": resume_cursor,
        },
        "docs_url": null,
        "suggested_commands": []
    }))
    .expect("deserialize cursor-expiry API response")
}

struct DirectFixture {
    service: HostService,
    host_identity: String,
    address: SocketAddr,
    server: Option<DaemonServer>,
    server_runtime: tokio::runtime::Runtime,
    transport: Option<DirectTransport>,
    _state: TestStateDir,
}

impl DirectFixture {
    fn start() -> Self {
        let state = TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic Host service");
        Self::bind(state, service)
    }

    fn start_with_adapter(adapter: impl ComputerUseAdapter) -> Self {
        let state = TestStateDir::new().expect("temporary state directory");
        let service = HostService::with_adapter_for_tests_at(state.path(), adapter)
            .expect("construct adapter-backed Host service");
        Self::bind(state, service)
    }

    fn bind(state: TestStateDir, service: HostService) -> Self {
        let initialized = service.initialize_daemon().expect("initialize Host state");
        let host_identity = initialized.host_identity().to_string();
        let (http_token, event_token) =
            register_client_tokens(&service, "principal-cli-direct-test");
        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("construct daemon runtime");
        let server = server_runtime
            .block_on(DaemonServer::bind(
                service.clone(),
                DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            ))
            .expect("bind loopback daemon");
        let address = server.local_addr();
        let client = DaemonClient::loopback(address, http_token, &host_identity)
            .expect("construct loopback HTTP client");
        let event_client = DaemonEventClient::loopback(address, event_token, &host_identity)
            .expect("construct loopback event client");
        let event_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("construct event runtime");
        Self {
            service,
            host_identity,
            address,
            server: Some(server),
            server_runtime,
            transport: Some(DirectTransport {
                alias: "direct-test".to_string(),
                mode: "direct",
                client: Arc::new(client),
                event_client,
                event_runtime,
                _tunnel: None,
                _bootstrap: None,
            }),
            _state: state,
        }
    }

    fn transport(&self) -> &DirectTransport {
        self.transport
            .as_ref()
            .expect("fixture transport is present")
    }
}

impl Drop for DirectFixture {
    fn drop(&mut self) {
        drop(self.transport.take());
        if let Some(server) = self.server.take() {
            let shutdown = self.server_runtime.block_on(server.shutdown());
            if !std::thread::panicking() {
                shutdown.expect("shut down loopback daemon");
            }
        }
    }
}

fn install_silent_event_peer(
    fixture: &mut DirectFixture,
    interrupt: TestInterrupt,
) -> (TestLatch, thread::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind silent event listener");
    let address = listener.local_addr().expect("read silent event address");
    let release = TestLatch::default();
    let peer_release = release.clone();
    let peer = thread::spawn(move || {
        let (_socket, _) = listener.accept().expect("accept event connection");
        interrupt.signal();
        peer_release.wait();
    });
    let token = ApiBearerToken::generate().expect("generate silent event token");
    fixture
        .transport
        .as_mut()
        .expect("fixture transport is present")
        .event_client = DaemonEventClient::loopback(address, token, &fixture.host_identity)
        .expect("construct silent event client");
    (release, peer)
}

fn install_ambiguous_admission_peer(
    fixture: &mut DirectFixture,
    interrupt: TestInterrupt,
) -> thread::JoinHandle<()> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ambiguous admission listener");
    let address = listener
        .local_addr()
        .expect("read ambiguous admission address");
    let peer = thread::spawn(move || {
        let (admission, _) = listener.accept().expect("accept admission request");
        interrupt.signal();
        let (cancellation, _) = listener.accept().expect("accept cancellation request");
        drop(cancellation);
        drop(admission);
    });
    let token = ApiBearerToken::generate().expect("generate ambiguous admission token");
    let client = DaemonClient::loopback(address, token, &fixture.host_identity)
        .expect("construct ambiguous admission client");
    fixture
        .transport
        .as_mut()
        .expect("fixture transport is present")
        .client = Arc::new(client);
    peer
}

fn install_replay_admitted_status_failure_peer(
    fixture: &mut DirectFixture,
    interrupt: TestInterrupt,
    admission_path: String,
    session_id: satelle_core::SessionId,
    turn_id: satelle_core::TurnId,
) -> thread::JoinHandle<()> {
    fn read_headers(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound synthetic HTTP request read");
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0_u8; 1024];
            let count = stream
                .read(&mut chunk)
                .expect("read synthetic HTTP request");
            assert_ne!(count, 0, "request closed before headers completed");
            request.extend_from_slice(&chunk[..count]);
        }
        String::from_utf8(request).expect("synthetic request headers are UTF-8")
    }

    fn request_id(headers: &str) -> &str {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("satelle-request-id")
                    .then_some(value.trim())
            })
            .expect("request carries a request ID")
    }

    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind replay-admitted HTTP peer");
    let address = listener
        .local_addr()
        .expect("read replay-admitted HTTP address");
    let host_identity = fixture.host_identity.clone();
    let expected_stop_path = format!("/v1/sessions/{session_id}/stop");
    let expected_status_path = format!("/v1/sessions/{session_id}");
    let expected_turn_header = format!("satelle-expected-turn-id: {turn_id}");
    let peer = thread::spawn(move || {
        let (mut admission, _) = listener.accept().expect("accept admission request");
        let admission_headers = read_headers(&mut admission);
        assert!(
            admission_headers.starts_with(&format!("POST {admission_path} HTTP/1.1")),
            "unexpected admission request: {admission_headers}"
        );
        interrupt.signal();

        let (mut cancellation, _) = listener.accept().expect("accept cancellation request");
        let cancellation_headers = read_headers(&mut cancellation);
        assert!(
            cancellation_headers.starts_with(&format!("POST {admission_path} HTTP/1.1")),
            "unexpected cancellation request: {cancellation_headers}"
        );
        assert!(
            cancellation_headers
                .to_ascii_lowercase()
                .contains("satelle-admission-action: cancel")
        );
        let cancellation_request_id = request_id(&cancellation_headers);
        let body = serde_json::json!({
            "schema_version": "satelle.admission.cancel.v1",
            "request_id": cancellation_request_id,
            "host_identity": host_identity,
            "outcome": "admitted",
            "session_id": session_id,
            "turn_id": turn_id,
        })
        .to_string();
        write!(
            cancellation,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nsatelle-request-id: {}\r\nsatelle-host-identity: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            cancellation_request_id,
            host_identity,
            body,
        )
        .expect("write replay-admitted cancellation response");
        drop(cancellation);

        let (mut stop, _) = listener
            .accept()
            .expect("accept expected-Turn stop request");
        let stop_headers = read_headers(&mut stop);
        assert!(
            stop_headers.starts_with(&format!("POST {expected_stop_path} HTTP/1.1")),
            "stop must precede status read: {stop_headers}"
        );
        assert!(
            stop_headers
                .to_ascii_lowercase()
                .contains(&expected_turn_header),
            "stop must target the exact replayed Turn: {stop_headers}"
        );
        drop(stop);

        let (mut status, _) = listener.accept().expect("accept status request after stop");
        let status_headers = read_headers(&mut status);
        assert!(
            status_headers.starts_with(&format!("GET {expected_status_path} HTTP/1.1")),
            "status read must follow the stop attempt: {status_headers}"
        );
        drop(status);
        drop(admission);
    });
    let token = ApiBearerToken::generate().expect("generate replay-admitted token");
    let client = DaemonClient::loopback(address, token, &fixture.host_identity)
        .expect("construct replay-admitted HTTP client");
    fixture
        .transport
        .as_mut()
        .expect("fixture transport is present")
        .client = Arc::new(client);
    peer
}

#[test]
fn attached_run_reports_direct_daemon_unreachable_after_wss_subscription_succeeds() {
    let mut fixture = DirectFixture::start();
    let subscribed_stream = fixture
        .transport()
        .event_runtime
        .block_on(
            fixture
                .transport()
                .event_client
                .connect_events(vec![satelle_transport::EventSubscription::Host]),
        )
        .expect("prove the WSS Host subscription is reachable");
    let closed_listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve a closed HTTP endpoint");
    let closed_address = closed_listener
        .local_addr()
        .expect("read the closed HTTP endpoint");
    drop(closed_listener);

    let disconnected_token = ApiBearerToken::generate().expect("generate disconnected token");
    let disconnected_client =
        DaemonClient::loopback(closed_address, disconnected_token, &fixture.host_identity)
            .expect("construct disconnected HTTP client");
    fixture
        .transport
        .as_mut()
        .expect("fixture transport is present")
        .client = Arc::new(disconnected_client);

    let failure = match fixture.transport().run(
        &TurnRequest::new("must not be admitted"),
        false,
        &mut |_| panic!("an unadmitted run must not emit events"),
    ) {
        Ok(_) => panic!("the disconnected HTTP client must fail run admission"),
        Err(failure) => failure,
    };

    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::DirectDaemonUnreachable);
    assert!(failure.durable_handles().is_none());
    drop(subscribed_stream);
}

#[test]
fn direct_attached_arms_interrupt_before_event_connection() {
    let mut fixture = DirectFixture::start();
    let interrupt = ArmOrderInterrupt::default();
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind arm-order event listener");
    let address = listener.local_addr().expect("read arm-order event address");
    let armed = Arc::clone(&interrupt.armed);
    let peer = thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept event connection");
        assert!(
            armed.load(Ordering::Acquire),
            "interrupt arming must complete before direct event connection"
        );
        drop(socket);
    });
    let token = ApiBearerToken::generate().expect("generate arm-order event token");
    fixture
        .transport
        .as_mut()
        .expect("fixture transport is present")
        .event_client = DaemonEventClient::loopback(address, token, &fixture.host_identity)
        .expect("construct arm-order event client");

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().run_attached_with_interrupt(
            &TurnRequest::new("prove direct interrupt arm order"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Ok(_) => panic!("the synthetic event peer must close after checking arm order"),
        Err(failure) => failure,
    };
    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    peer.join().expect("arm-order event peer must not panic");
}

#[test]
fn interrupt_during_direct_run_event_connection_is_terminal_before_admission() {
    let mut fixture = DirectFixture::start();
    let interrupt = TestInterrupt::default();
    let (release, peer) = install_silent_event_peer(&mut fixture, interrupt.clone());

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().run_attached_with_interrupt(
            &TurnRequest::new("interrupt blocked event connection"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("connection-boundary interruption must terminate the command"),
    };
    release.signal();
    peer.join().expect("silent event peer must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().exit_code(), 130);
    assert!(failure.durable_handles().is_none());
    assert_eq!(
        fixture
            .service
            .daemon_runtime_status()
            .expect("read runtime status")
            .session_count(),
        0
    );
}

#[test]
fn interrupt_during_direct_steer_event_connection_is_terminal_before_admission() {
    let mut fixture = DirectFixture::start();
    let seed = fixture
        .transport()
        .run_detached(&TurnRequest::new("seed blocked steer connection"))
        .expect("seed Session");
    let interrupt = TestInterrupt::default();
    let (release, peer) = install_silent_event_peer(&mut fixture, interrupt.clone());

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().steer_attached_with_interrupt(
            seed.session_id(),
            &TurnRequest::new("interrupt blocked steer connection"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("steer connection-boundary interruption must terminate the command"),
    };
    release.signal();
    peer.join().expect("silent event peer must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::NotAdmitted);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().exit_code(), 130);
    assert!(failure.durable_handles().is_none());
    assert_eq!(
        fixture
            .service
            .session_status(seed.session_id())
            .expect("seed Session remains readable")
            .turns()
            .len(),
        1
    );
}

#[test]
fn direct_run_preserves_unknown_phase_when_admission_and_cancellation_disconnect() {
    let mut fixture = DirectFixture::start();
    let interrupt = TestInterrupt::default();
    let peer = install_ambiguous_admission_peer(&mut fixture, interrupt.clone());

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().run_attached_with_interrupt(
            &TurnRequest::new("ambiguous direct run interruption"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("disconnected admission and cancellation must remain ambiguous"),
    };
    peer.join()
        .expect("ambiguous admission peer must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert!(failure.durable_handles().is_none());
}

#[test]
fn direct_steer_preserves_unknown_phase_when_admission_and_cancellation_disconnect() {
    let mut fixture = DirectFixture::start();
    let seed = fixture
        .transport()
        .run_detached(&TurnRequest::new("seed ambiguous direct steer"))
        .expect("seed Session");
    let interrupt = TestInterrupt::default();
    let peer = install_ambiguous_admission_peer(&mut fixture, interrupt.clone());

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().steer_attached_with_interrupt(
            seed.session_id(),
            &TurnRequest::new("ambiguous direct steer interruption"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("disconnected steer admission and cancellation must remain ambiguous"),
    };
    peer.join()
        .expect("ambiguous admission peer must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert!(failure.durable_handles().is_none());
}

#[test]
fn replay_admitted_run_stops_exact_turn_before_failed_status_read() {
    let mut fixture = DirectFixture::start();
    let interrupt = TestInterrupt::default();
    let session_id = satelle_core::SessionId::new();
    let turn_id = satelle_core::TurnId::new();
    let peer = install_replay_admitted_status_failure_peer(
        &mut fixture,
        interrupt.clone(),
        "/v1/sessions".to_string(),
        session_id.clone(),
        turn_id,
    );

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().run_attached_with_interrupt(
            &TurnRequest::new("replay admitted run with failed status"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("lost admission response must remain interrupted"),
    };
    peer.join()
        .expect("replay-admitted run peer must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().details["session_id"], session_id.as_str());
    assert!(
        failure
            .error()
            .recovery_command
            .as_deref()
            .is_some_and(|command| command.contains(&format!("status {session_id}"))),
        "failed status read must preserve Session-scoped recovery guidance"
    );
}

#[test]
fn replay_admitted_steer_stops_exact_turn_before_failed_status_read() {
    let mut fixture = DirectFixture::start();
    let seed = fixture
        .transport()
        .run_detached(&TurnRequest::new("seed replay-admitted steer"))
        .expect("seed Session");
    let interrupt = TestInterrupt::default();
    let session_id = seed.session_id().clone();
    let turn_id = satelle_core::TurnId::new();
    let peer = install_replay_admitted_status_failure_peer(
        &mut fixture,
        interrupt.clone(),
        format!("/v1/sessions/{session_id}/turns"),
        session_id.clone(),
        turn_id,
    );

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().steer_attached_with_interrupt(
            &session_id,
            &TurnRequest::new("replay admitted steer with failed status"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("lost steer admission response must remain interrupted"),
    };
    peer.join()
        .expect("replay-admitted steer peer must not panic");

    assert_eq!(failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().details["session_id"], session_id.as_str());
    assert!(
        failure
            .error()
            .recovery_command
            .as_deref()
            .is_some_and(|command| command.contains(&format!("status {session_id}"))),
        "failed status read must preserve Session-scoped recovery guidance"
    );
}

#[test]
fn injected_interrupt_after_direct_run_admission_confirms_stop_before_exit_130() {
    let adapter = InterruptLifecycleAdapter::default();
    adapter.block_execute();
    let fixture = DirectFixture::start_with_adapter(adapter.clone());
    let interrupt = TestInterrupt::default();
    let coordinator_interrupt = interrupt.clone();
    let coordinator_adapter = adapter.clone();
    let coordinator = thread::spawn(move || {
        assert!(
            coordinator_adapter
                .execute_started
                .wait_for(Duration::from_secs(2)),
            "direct run must be durably admitted before interruption"
        );
        coordinator_interrupt.signal();
    });

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().run_attached_with_interrupt(
            &TurnRequest::new("interrupt admitted direct run"),
            false,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("post-admission interruption must preserve exit 130"),
    };
    coordinator
        .join()
        .expect("coordinator thread must not panic");
    assert_eq!(failure.phase(), TurnAdmissionPhase::Admitted);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().exit_code(), 130);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 1);
    let (session_id, _) = failure
        .durable_handles()
        .expect("direct interruption retains durable handles");
    assert_eq!(
        fixture
            .service
            .session_status(session_id)
            .expect("stopped direct Session remains readable")
            .activity(),
        &SessionActivity::Idle
    );
}

#[test]
fn injected_interrupt_after_direct_steer_admission_detaches_without_stop() {
    let adapter = InterruptLifecycleAdapter::default();
    let fixture = DirectFixture::start_with_adapter(adapter.clone());
    let seed = fixture
        .transport()
        .run_detached(&TurnRequest::new("seed direct steer interruption"))
        .expect("seed Session");
    assert!(
        adapter.execute_finished.wait_for(Duration::from_secs(2)),
        "seed direct Turn must finish before steer"
    );
    adapter.execute_finished.reset();
    adapter.block_execute();
    let interrupt = TestInterrupt::default();
    let coordinator_interrupt = interrupt.clone();
    let coordinator_adapter = adapter.clone();
    let coordinator = thread::spawn(move || {
        assert!(
            coordinator_adapter
                .execute_started
                .wait_for(Duration::from_secs(2)),
            "direct steer must be durably admitted before interruption"
        );
        coordinator_interrupt.signal();
    });

    let failure = match fixture.transport().event_runtime.block_on(
        fixture.transport().steer_attached_with_interrupt(
            seed.session_id(),
            &TurnRequest::new("detach admitted direct steer"),
            true,
            &mut |_| Ok(()),
            &interrupt,
        ),
    ) {
        Err(failure) => failure,
        Ok(_) => panic!("detach-on-interrupt must preserve exit 130"),
    };
    coordinator
        .join()
        .expect("coordinator thread must not panic");
    assert_eq!(failure.phase(), TurnAdmissionPhase::Admitted);
    assert_eq!(failure.error().code, ErrorCode::Interrupted);
    assert_eq!(failure.error().exit_code(), 130);
    assert_eq!(adapter.stop_calls.load(Ordering::SeqCst), 0);
    let (session_id, _) = failure
        .durable_handles()
        .expect("detached direct interruption retains durable handles");
    assert_ne!(
        fixture
            .service
            .session_status(session_id)
            .expect("detached direct Session remains readable")
            .activity(),
        &SessionActivity::Idle
    );

    adapter.execute_release.signal();
    assert!(
        adapter.execute_finished.wait_for(Duration::from_secs(2)),
        "detached direct worker must finish after explicit test release"
    );
}

#[test]
fn direct_host_sessions_read_daemon_metadata_without_bootstrap() {
    let fixture = DirectFixture::start();
    let local = fixture
        .service
        .host_sessions(LOCAL_DEMO_HOST, true)
        .expect("read local Host desktop sessions");

    let direct = fixture
        .transport()
        .host_sessions(true)
        .expect("read desktop sessions through direct transport");

    assert_eq!(direct.schema_version, HostSessionsSchemaVersion::V1);
    assert_eq!(direct.host, "direct-test");
    assert_eq!(direct.connection_mode, "direct");
    assert!(!direct.bootstrapped);
    assert!(direct.bootstrap_actions.is_empty());
    assert_eq!(direct.host_daemon_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(direct.sessions, local.sessions);
}

#[test]
fn durable_ssh_relaunch_policy_covers_read_and_stop_without_credential_bootstrap() {
    assert!(!SshDaemonLaunchPolicy::Never.allows_durable_relaunch());
    assert!(SshDaemonLaunchPolicy::DurableOnly.allows_durable_relaunch());
    for scope in [
        SshBootstrapScope::Read,
        SshBootstrapScope::Control,
        SshBootstrapScope::Admin,
    ] {
        let policy = SshDaemonLaunchPolicy::Bootstrap(scope);
        assert!(policy.allows_durable_relaunch());
        assert_eq!(policy.bootstrap_scope(), Some(scope));
    }
}

#[test]
fn serialized_durable_relaunch_rechecks_readiness_under_the_remote_lock() {
    struct BootstrapLockGuard(Arc<AtomicBool>);

    impl Drop for BootstrapLockGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    let lock_held = Arc::new(AtomicBool::new(true));
    let bootstrap_lock = BootstrapLockGuard(Arc::clone(&lock_held));
    let ready = relaunch_durable_daemon_under_lock(
        "remote",
        || {
            assert!(
                lock_held.load(Ordering::SeqCst),
                "the remote helper must confirm live lock ownership"
            );
            Ok(())
        },
        || {
            assert!(
                lock_held.load(Ordering::SeqCst),
                "readiness must be rechecked while the remote lock is held"
            );
            Ok("already started by the first Controller")
        },
        || -> Result<(), SatelleError> {
            panic!("a ready daemon must not be launched a second time")
        },
    )
    .expect("reuse daemon started by the first Controller");

    assert_eq!(ready, "already started by the first Controller");
    drop(bootstrap_lock);
    assert!(
        !lock_held.load(Ordering::SeqCst),
        "the remote lock is released only after readiness succeeds"
    );
}

#[test]
fn durable_relaunch_rejects_success_when_remote_lock_ownership_is_lost() {
    let lock_held = Arc::new(AtomicBool::new(true));
    let confirm_lock = Arc::clone(&lock_held);
    let readiness_lock = Arc::clone(&lock_held);
    let error = relaunch_durable_daemon_under_lock(
        "remote",
        || {
            if confirm_lock.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(SatelleError::host_unreachable("remote"))
            }
        },
        || {
            readiness_lock.store(false, Ordering::SeqCst);
            Ok("daemon became ready as the SSH lock disconnected")
        },
        || -> Result<(), SatelleError> { panic!("an already-ready daemon is not relaunched") },
    )
    .expect_err("stale lock ownership cannot report a serialized relaunch");

    assert_eq!(error.code, ErrorCode::HostUnreachable);
}

#[test]
fn local_and_direct_logs_return_the_same_authoritative_page() {
    let fixture = DirectFixture::start();
    let appended = fixture
        .service
        .append_daemon_log_for_tests(
            time::OffsetDateTime::now_utc(),
            LogSource::Storage,
            LogSeverity::Warning,
        )
        .expect("append a canonical Host log");
    let query = LogPageQuery::tail(1)
        .expect("construct canonical tail query")
        .with_sources([LogSource::Storage])
        .with_minimum_severity(LogSeverity::Warning);
    let local = LocalTransport::new("local-demo".to_string(), fixture.service.clone());

    let local_page = local
        .logs(&query)
        .expect("read logs through local transport");
    let direct_page = fixture
        .transport()
        .logs(&query)
        .expect("read logs through direct transport");

    assert_eq!(direct_page, local_page);
    assert_eq!(direct_page.entries().len(), 1);
    assert_eq!(direct_page.entries()[0].cursor(), appended);
    assert_eq!(direct_page.entries()[0].source(), LogSource::Storage);
    assert_eq!(direct_page.entries()[0].severity(), LogSeverity::Warning);
}

#[test]
fn local_logs_reject_a_non_local_demo_alias_before_reading_the_shared_store() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let local = LocalTransport::new("other-local".to_string(), service);
    let query = LogPageQuery::tail(1).expect("construct canonical tail query");

    let error = local
        .logs(&query)
        .expect_err("a non-local-demo alias must not read the shared local Host store");

    assert_eq!(error.code, ErrorCode::HostNotFound);
    assert_eq!(error.message, "host 'other-local' is not configured");
    assert_eq!(error.exit_code(), 66);
}

#[test]
fn local_and_direct_logs_report_cursor_ahead_as_invalid_usage() {
    let fixture = DirectFixture::start();
    let future_cursor = LogCursor::parse("slc1_7fffffffffffffff")
        .expect("the maximum supported Log Cursor is valid");
    let query =
        LogPageQuery::forward(Some(future_cursor), 1).expect("construct future-cursor query");
    let local = LocalTransport::new("local-demo".to_string(), fixture.service.clone());

    let local_error = local
        .logs(&query)
        .expect_err("local transport must reject a cursor above its high-water mark");
    let direct_error = fixture
        .transport()
        .logs(&query)
        .expect_err("direct transport must reject a cursor above its high-water mark");

    assert_eq!(local_error.code, ErrorCode::InvalidUsage);
    assert_eq!(direct_error.code, local_error.code);
    assert_eq!(direct_error.exit_code(), 64);
}

#[test]
fn direct_logs_preserve_typed_cursor_expiry_details() {
    let earliest = "slc1_0000000000000002";
    let resume = "slc1_0000000000000001";
    let api_error = cursor_expiry_api_error(serde_json::json!(earliest), resume);

    let error = direct_logs_error(
        "direct-test",
        DaemonClientError::Api {
            status: 410_u16.try_into().expect("410 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );

    assert_eq!(error.code, ErrorCode::LogsCursorExpired);
    assert_eq!(
        error.details.get("earliest_available_cursor"),
        Some(&serde_json::json!(earliest))
    );
    assert_eq!(
        error.details.get("resume_cursor"),
        Some(&serde_json::json!(resume))
    );

    let api_error = cursor_expiry_api_error(serde_json::Value::Null, resume);
    let error = direct_logs_error(
        "direct-test",
        DaemonClientError::Api {
            status: 410_u16.try_into().expect("410 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );
    assert_eq!(error.code, ErrorCode::LogsCursorExpired);
    assert_eq!(
        error.details.get("earliest_available_cursor"),
        Some(&serde_json::Value::Null)
    );
}

#[test]
fn direct_logs_reject_contradictory_cursor_expiry_details() {
    let resume = "slc1_0000000000000002";
    let api_error = cursor_expiry_api_error(serde_json::json!(resume), resume);

    let error = direct_logs_error(
        "direct-test",
        DaemonClientError::Api {
            status: 410_u16.try_into().expect("410 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );

    assert_eq!(error.code, ErrorCode::RemoteExecution);
    assert_eq!(
        error.details.get("remote_code"),
        Some(&serde_json::json!("invalid-daemon-response"))
    );
}

#[test]
fn direct_attached_run_and_steer_follow_committed_host_events() {
    let fixture = DirectFixture::start();
    let mut run_events = Vec::new();
    let run_outcome = fixture
        .transport()
        .run(&TurnRequest::new("first turn"), false, &mut |event| {
            run_events.push(event);
            Ok(())
        })
        .expect("run attached Turn");
    let run = &run_outcome.session;
    assert_eq!(
        run_events
            .iter()
            .map(SatelleEvent::event_type)
            .collect::<Vec<_>>(),
        [
            EventType::TurnStarted,
            EventType::ProviderSmoke,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert_eq!(
        run_outcome.provider_smoke.as_ref().unwrap()["source"],
        "live"
    );
    assert_eq!(
        run.turns().last().map(|turn| turn.state()),
        Some(TurnState::Completed)
    );
    assert_eq!(
        run.turns().last().map(|turn| turn.turn_id()),
        Some(&run_outcome.turn_id)
    );
    let admitted_failure = TurnAdmissionFailure::admitted(
        SatelleError::host_unreachable("direct-test"),
        run.clone(),
        run_outcome.turn_id.clone(),
    );
    assert_eq!(admitted_failure.phase(), TurnAdmissionPhase::Admitted);
    assert_eq!(
        admitted_failure.durable_handles(),
        Some((run.session_id(), &run_outcome.turn_id))
    );
    let reconciled = fixture
        .transport()
        .reconciled_terminal_event(
            run,
            run.turns().last().expect("run retains its Turn").turn_id(),
        )
        .expect("construct reconciled terminal event");
    assert_eq!(reconciled.source(), EventSource::Cli);
    assert_eq!(reconciled.event_type(), EventType::TurnCompleted);
    assert_eq!(reconciled.session_id(), Some(run.session_id()));
    let run_turn = run.turns().last().expect("run retains its Turn");
    let contradictory = SatelleEventBody::new(
        EventType::TurnFailed,
        EventSource::HostDaemon,
        run_turn.updated_at(),
        "direct-test",
        Some(EventSubject::Turn {
            session_id: run.session_id().clone(),
            turn_id: run_turn.turn_id().clone(),
            session_state_revision: run.session_state_revision(),
            turn_state_revision: run_turn.turn_state_revision(),
        }),
        "contradictory terminal fixture",
        serde_json::json!({}),
    )
    .and_then(|body| body.with_seq(1))
    .expect("construct contradictory event");
    assert!(
        fixture
            .transport()
            .validate_terminal_event(&contradictory, run, run_turn.turn_id())
            .is_err()
    );

    let mut steer_events = Vec::new();
    let steer_outcome = fixture
        .transport()
        .steer(
            run.session_id(),
            &TurnRequest::new("follow-up turn"),
            false,
            &mut |event| {
                steer_events.push(event);
                Ok(())
            },
        )
        .expect("steer attached Turn");
    let steer = &steer_outcome.session;
    assert_eq!(steer.turns().len(), 2);
    assert_eq!(
        steer.turns().last().map(|turn| turn.turn_id()),
        Some(&steer_outcome.turn_id)
    );
    assert_eq!(
        steer_events
            .iter()
            .map(SatelleEvent::event_type)
            .collect::<Vec<_>>(),
        [
            EventType::TurnStarted,
            EventType::ProviderSmoke,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert_eq!(
        steer_outcome.provider_smoke.as_ref().unwrap()["source"],
        "live"
    );
    assert!(steer_events.iter().all(|event| {
        event.session_id() == Some(steer.session_id())
            && event.turn_id() == steer.turns().last().map(|turn| turn.turn_id())
    }));
    let reconciled_first_turn = fixture
        .transport()
        .event_runtime
        .block_on(fixture.transport().reconcile(
            run.session_id(),
            run_turn.turn_id(),
            Some(run_turn.turn_state_revision()),
        ))
        .expect("reconcile the first Turn after a follow-up advanced the Session revision");
    assert!(reconciled_first_turn.is_some());
}

#[test]
fn mutation_idempotency_keys_are_fresh_uuid_v7_values() {
    let first = DirectTransport::idempotency_key();
    let second = DirectTransport::idempotency_key();
    assert_ne!(first, second);
    assert_eq!(
        Uuid::parse_str(&first)
            .expect("parse first idempotency key")
            .get_version_num(),
        7
    );
    assert_eq!(
        Uuid::parse_str(&second)
            .expect("parse second idempotency key")
            .get_version_num(),
        7
    );
}

#[test]
fn only_connection_loss_and_transient_http_outage_enter_retry_paths() {
    assert!(direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::HandshakeTimeout
    ));
    assert!(direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::Disconnected
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::SequenceDidNotAdvance
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::HostIdentityMismatch
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::SubscriptionMismatch
    ));
    assert!(!direct_attached::event_error_allows_reconciliation(
        &DaemonEventError::UnexpectedFrame
    ));
    assert!(direct_attached::reconciliation_error_allows_retry(
        &SatelleError::host_unreachable("direct-test")
    ));
    assert!(!direct_attached::reconciliation_error_allows_retry(
        &SatelleError::remote_api_error("direct-test", "invalid-daemon-response")
    ));
    assert_eq!(
        direct_event_error("direct-test", DaemonEventError::HandshakeTimeout).code,
        ErrorCode::HostUnreachable
    );
    assert_eq!(
        direct_run_event_error("direct-test", DaemonEventError::HandshakeTimeout).code,
        ErrorCode::DirectDaemonUnreachable
    );
    assert_eq!(
        direct_run_event_error("direct-test", DaemonEventError::HostIdentityMismatch).code,
        ErrorCode::HostIdentityMismatch,
        "run-specific reachability mapping must preserve trust failures"
    );
    assert_eq!(
        direct_run_event_error(
            "direct-test",
            DaemonEventError::Transport(WebSocketError::Protocol(ProtocolError::WrongHttpMethod)),
        )
        .code,
        ErrorCode::HostUnreachable,
        "run-specific reachability mapping must preserve generic protocol-failure handling"
    );
}

#[test]
fn direct_run_preserves_typed_recoverable_close_errors() {
    let control = serde_json::from_value(serde_json::json!({
        "schema_version": "satelle.ws.control.v1",
        "type": "error",
        "request_id": satelle_transport::RequestId::new(),
        "host_identity": "host-direct-test",
        "reason": "slow-consumer",
        "code": "capacity-exceeded",
        "category": "capacity",
        "retryable": false,
        "message": "the WebSocket subscriber could not keep up with live events",
        "details": null,
        "docs_url": null,
        "suggested_commands": []
    }))
    .expect("deserialize valid slow-consumer control error");

    assert_eq!(
        direct_run_event_error(
            "direct-test",
            DaemonEventError::Closed {
                control: Some(Box::new(control)),
                code: 1008,
                reason: satelle_transport::WsCloseReason::SlowConsumer,
            },
        )
        .code,
        ErrorCode::RemoteExecution,
        "typed close controls must remain authoritative during direct run admission"
    );
}

#[test]
fn admission_failures_preserve_definitive_and_ambiguous_phases() {
    for code in [
        ApiErrorCode::AuthenticationFailed,
        ApiErrorCode::AuthorizationInsufficientScope,
        ApiErrorCode::HostIdentityMismatch,
        ApiErrorCode::InvalidRequest,
        ApiErrorCode::UnsupportedSchema,
        ApiErrorCode::UnsupportedContentType,
        ApiErrorCode::PayloadTooLarge,
        ApiErrorCode::IdempotencyKeyConflict,
        ApiErrorCode::SessionNotFound,
        ApiErrorCode::HostBusy,
        ApiErrorCode::IncompatibleProtocol,
        ApiErrorCode::IncompatibleControlPlane,
        ApiErrorCode::ComputerUseNotReady,
        ApiErrorCode::NativeReadinessTimeout,
        ApiErrorCode::ProviderSmokeTestTimeout,
        ApiErrorCode::UnsupportedProviderComputerUse,
        ApiErrorCode::CapacityExceeded,
        ApiErrorCode::RateLimited,
        ApiErrorCode::RouteNotFound,
        ApiErrorCode::MethodNotAllowed,
    ] {
        assert!(api_error_is_definitively_not_admitted(code), "{code:?}");
    }
    for code in [
        ApiErrorCode::LogsCursorExpired,
        ApiErrorCode::HostUnreachable,
        ApiErrorCode::StoreInUse,
        ApiErrorCode::StateConflict,
        ApiErrorCode::StopNotConfirmed,
        ApiErrorCode::StorageBusy,
        ApiErrorCode::StorageIntegrityFailed,
        ApiErrorCode::RemoteExecutionFailed,
        ApiErrorCode::InternalError,
    ] {
        assert!(!api_error_is_definitively_not_admitted(code), "{code:?}");
    }

    let rejected = direct_admission_error("direct-test", DaemonClientError::InvalidTokenHeader);
    assert_eq!(rejected.phase(), TurnAdmissionPhase::NotAdmitted);
    assert!(rejected.durable_handles().is_none());
    let run_rejected =
        direct_run_admission_error("direct-test", DaemonClientError::InvalidTokenHeader);
    assert_eq!(run_rejected.phase(), rejected.phase());
    assert_eq!(run_rejected.error().code, rejected.error().code);

    assert_eq!(
        api_code_error("direct-test", ApiErrorCode::NativeReadinessTimeout).code,
        ErrorCode::NativeReadinessTimeout
    );
    assert_eq!(
        api_code_error("direct-test", ApiErrorCode::ProviderSmokeTestTimeout).code,
        ErrorCode::ProviderSmokeTestTimeout
    );
    assert_eq!(
        api_code_error("direct-test", ApiErrorCode::UnsupportedProviderComputerUse,).code,
        ErrorCode::UnsupportedProviderComputerUse
    );

    let ambiguous =
        direct_admission_error("direct-test", DaemonClientError::ResponseRequestIdMismatch);
    assert_eq!(ambiguous.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert!(ambiguous.durable_handles().is_none());
    let run_ambiguous =
        direct_run_admission_error("direct-test", DaemonClientError::ResponseRequestIdMismatch);
    assert_eq!(run_ambiguous.phase(), ambiguous.phase());
    assert_eq!(run_ambiguous.error().code, ambiguous.error().code);

    let api_error: satelle_transport::ApiError = serde_json::from_value(serde_json::json!({
        "schema_version": "satelle.error.v1",
        "request_id": satelle_transport::RequestId::new().to_string(),
        "host_identity": "host-direct-test",
        "code": "host-unreachable",
        "category": "remote_execution",
        "retryable": true,
        "message": "the configured execution runtime is unreachable",
        "details": null,
        "docs_url": null,
        "suggested_commands": []
    }))
    .expect("deserialize representative daemon API failure");
    let api_failure = direct_admission_error(
        "direct-test",
        DaemonClientError::Api {
            status: 503_u16.try_into().expect("503 is a valid HTTP status"),
            error: Box::new(api_error),
        },
    );
    assert_eq!(api_failure.phase(), TurnAdmissionPhase::AdmissionUnknown);
    assert!(api_failure.durable_handles().is_none());
}

#[test]
fn stop_not_confirmed_api_details_are_validated_and_preserved() {
    let session_id = SessionId::new();
    let turn_id = TurnId::new();
    let details = serde_json::json!({
        "session_id": session_id,
        "turn_id": turn_id,
        "ownership": "recovery_pending",
        "state_changed": true,
        "session_state_revision": 3,
        "turn_state_revision": 2,
        "retryable": true
    });
    let api_error = |details: serde_json::Value| {
        serde_json::from_value::<satelle_transport::ApiError>(serde_json::json!({
            "schema_version": "satelle.error.v1",
            "request_id": satelle_transport::RequestId::new().to_string(),
            "host_identity": "host-direct-test",
            "code": "stop-not-confirmed",
            "category": "conflict",
            "retryable": true,
            "message": "stop was not confirmed",
            "details": details,
            "docs_url": null,
            "suggested_commands": []
        }))
        .expect("deserialize stop-not-confirmed API error")
    };

    let mapped = map_api_error("direct-test", &api_error(details.clone()));
    assert_eq!(mapped.code, ErrorCode::StopNotConfirmed);
    assert_eq!(mapped.details["ownership"], "recovery_pending");
    assert_eq!(mapped.details["turn_id"], turn_id.as_str());
    assert_eq!(mapped.details["session_state_revision"], 3);
    assert_eq!(mapped.details["turn_state_revision"], 2);

    let mut malformed = Vec::new();
    let mut missing_revision = details.clone();
    missing_revision
        .as_object_mut()
        .expect("details object")
        .remove("turn_state_revision");
    malformed.push(missing_revision);
    let mut zero_revision = details.clone();
    zero_revision["session_state_revision"] = serde_json::json!(0);
    malformed.push(zero_revision);
    let mut bad_owner = details.clone();
    bad_owner["ownership"] = serde_json::json!("unknown");
    malformed.push(bad_owner);
    let mut extra = details;
    extra["private"] = serde_json::json!("must-not-cross");
    malformed.push(extra);

    for invalid in malformed {
        let mapped = map_api_error("direct-test", &api_error(invalid));
        assert_eq!(mapped.code, ErrorCode::RemoteExecution);
        assert_eq!(
            mapped.details.get("remote_code"),
            Some(&serde_json::json!("invalid-daemon-response"))
        );
    }
}

#[test]
fn failed_local_status_preserves_interrupt_exit_and_session_recovery_command() {
    let session_id = SessionId::new();
    let interrupted = unconfirmed_interrupt_error(
        "local-demo",
        &session_id,
        SatelleError::host_unreachable("local-demo"),
    );
    let error = interrupted_status_error(
        "local-demo",
        &session_id,
        interrupted,
        SatelleError::host_unreachable("local-demo"),
    );

    assert_eq!(error.code, ErrorCode::Interrupted);
    assert_eq!(error.exit_code(), 130);
    assert!(error.message.contains(session_id.as_str()));
    assert_eq!(
        error.recovery_command.as_deref(),
        Some(format!("satelle status {session_id} --host local-demo").as_str())
    );
    assert_eq!(error.details["session_id"], session_id.as_str());
    assert_eq!(error.details["status_error_code"], "host-unreachable");
}
