#[path = "api-auth.rs"]
mod api_auth;
mod attachment;
mod codex_capabilities;
#[path = "codex-install.rs"]
mod codex_install;
#[path = "codex-session.rs"]
mod codex_session;
mod daemon;
#[path = "desktop-sessions.rs"]
mod desktop_sessions;
#[path = "live-events.rs"]
mod live_events;
#[path = "log-page.rs"]
mod log_page;
#[path = "operation-capacity.rs"]
mod operation_capacity;
#[path = "process-identity.rs"]
mod process_identity;
#[path = "provider-auth.rs"]
pub(crate) mod provider_auth;
#[path = "provider-probe.rs"]
mod provider_probe;
mod runtime;
mod storage;
#[cfg(any(test, feature = "test-support"))]
#[path = "test-runtime.rs"]
mod test_runtime;

use api_auth::EphemeralApiAuthenticator;
pub use api_auth::{
    ApiBearerToken, ApiBearerTokenError, ApiPrincipal, ApiScopes, contains_api_bearer_token,
};
pub use attachment::AttachmentUpload;
use codex_capabilities::{
    BlockerReason, CodexVersionEvidence, Phase0CapabilityBlocker, Phase0SupportVerdict,
    RequiredCapability, discover_phase0, evaluate_phase0_support,
};
pub use daemon::{
    AdmissionCancellationResult, DaemonActivitySnapshot, DaemonRuntimeCapabilities,
    DaemonRuntimeStatus, DaemonSessionReconnect, MutationAuthority, MutationAuthorityError,
    StopAdmission, TurnIntent, TurnIntentError,
};
pub use live_events::{LiveEventReceiveError, LiveEventSubscription};
pub use log_page::{
    DaemonLogEntry, DaemonLogPage, LogCursor, LogCursorError, LogEvent, LogPageMode, LogPageQuery,
    LogPageQueryError, LogSeverity, LogSource, LogSubject,
};
use operation_capacity::OperationCapacity;
pub(crate) use runtime::ReadinessSource;
pub use runtime::{
    AdapterPreflight, AdapterReadiness, AdapterSubject, AdmissionCancellation, ComputerUseAdapter,
    EvidenceError, ExecuteRequest, ExecuteResult, MaintenanceOperationHandle,
    ProviderBindingResolution, ProviderComputerUseIntent, ProviderSmokeEvidence,
    ProviderSmokeFailureEvidence, ProviderSmokeResult, ProviderSmokeSource, ReadinessCacheKey,
    ReadinessEvidence, ReadinessObservationState, RecoveryObservation,
};
use runtime::{
    ProductionComputerUseAdapter, RequestIdentity, RunCommand, RuntimeHandle, SteerCommand,
    StopCommand,
};
use satelle_core::doctor::{
    DoctorDependentEvidence, DoctorProbe, DoctorProbeCachePolicy, DoctorProbeCompletion,
    DoctorProbeExecutionContext, DoctorProbeExecutionRecord, DoctorProbeLifecycle,
    DoctorProbeLifecycleEvent, DoctorProbeResource, DoctorProbeScheduleEvent, DoctorProbeScheduler,
    DoctorProbeState, DoctorProbeStatus, DoctorScope, DoctorScopeSelection,
};
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    DaemonPathOverrides, DoctorFinding, DoctorFixability, DoctorOptions, DoctorProbeResult,
    DoctorReport, DoctorSchemaVersion, DoctorSummary, DoctorTransportObservation, HostConfig,
    HostSessionsReport, HostSessionsSchemaVersion, LOCAL_DEMO_HOST, SatelleError, SatelleEvent,
    SessionId, SetupReadinessSummary, SetupReport, SetupSchemaVersion, StopResult, TurnId,
    object_value, utc_now,
};
pub use satelle_core::{
    ProviderBindingAuthorization, ProviderBindingSource, ProviderDescriptorValidation,
    ProviderSecretProvisioningPreview, ProviderSecretProvisioningResult,
    PublicResolvedProviderBinding, ResolvedProviderBinding,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockReadGuard, Weak};
use std::time::{Duration, Instant};
use storage::Storage;
pub use storage::{
    SetupActionPlan, SetupActionRecord, SetupActionSkipReason, SetupActionStatus,
    SetupOperationKind, SetupRepairAction, SetupRepairDecision, SetupRepairPlan,
    SetupRepairPostcondition, SetupRepairProbe, SetupRunPlan, SetupRunRecord, SetupRunStatus,
};
use zeroize::Zeroizing;

pub(crate) const DEFAULT_MODEL_BINDING: &str = "codex-default";
pub(crate) const DEFAULT_PROVIDER_BINDING: &str = "codex-default";

/// Behavior-changing inputs for one provider descriptor validation.
///
/// Keeping these values together makes the runtime validation and its
/// idempotency identity consume the same request contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderDescriptorValidationOptions {
    mode: satelle_core::ProviderAuthValidationMode,
    model_from_project: bool,
    provider_from_project: bool,
    experimental_provider_computer_use: bool,
}

impl ProviderDescriptorValidationOptions {
    pub const fn new(
        mode: satelle_core::ProviderAuthValidationMode,
        model_from_project: bool,
        provider_from_project: bool,
        experimental_provider_computer_use: bool,
    ) -> Self {
        Self {
            mode,
            model_from_project,
            provider_from_project,
            experimental_provider_computer_use,
        }
    }

    pub const fn mode(self) -> satelle_core::ProviderAuthValidationMode {
        self.mode
    }

    pub const fn model_from_project(self) -> bool {
        self.model_from_project
    }

    pub const fn provider_from_project(self) -> bool {
        self.provider_from_project
    }

    pub const fn experimental_provider_computer_use(self) -> bool {
        self.experimental_provider_computer_use
    }
}

/// Operation-specific observer used to reconcile an interrupted setup action.
///
/// Returning `Ok(true)` verifies the action's postcondition, `Ok(false)`
/// verifies that it is unsatisfied, and an error leaves ownership in
/// recovery_pending without any durable transition.
pub trait SetupPostconditionObserver {
    fn observe(&mut self, action: &SetupActionRecord) -> Result<bool, SatelleError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapMaintenancePlanKind {
    OnDemandHandoff,
    PersistentHostService,
    PersistentHostStop,
    PersistentHostRestart,
}

impl BootstrapMaintenancePlanKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnDemandHandoff => "on_demand_handoff",
            Self::PersistentHostService => "persistent_host_service",
            Self::PersistentHostStop => "persistent_host_stop",
            Self::PersistentHostRestart => "persistent_host_restart",
        }
    }

    pub fn parse(value: &str) -> Result<Self, SatelleError> {
        match value {
            "on_demand_handoff" => Ok(Self::OnDemandHandoff),
            "persistent_host_service" => Ok(Self::PersistentHostService),
            "persistent_host_stop" => Ok(Self::PersistentHostStop),
            "persistent_host_restart" => Ok(Self::PersistentHostRestart),
            _ => Err(SatelleError::invalid_usage(
                "invalid Bootstrap maintenance plan kind",
            )),
        }
    }

    fn actions(self) -> Result<Vec<SetupActionPlan>, SatelleError> {
        let actions = match self {
            Self::OnDemandHandoff => vec![SetupActionPlan::new(
                "bootstrap-handoff",
                "Bootstrap Lock handoff",
                true,
            )?],
            Self::PersistentHostService => vec![
                SetupActionPlan::new("bootstrap-handoff", "Bootstrap Lock handoff", true)?,
                SetupActionPlan::new(
                    "path-set-directories",
                    "Create the resolved daemon directories",
                    true,
                )?,
                SetupActionPlan::new(
                    "service-config",
                    "Publish the owner-only service configuration",
                    true,
                )?,
                SetupActionPlan::new(
                    "service-registration",
                    "Reconcile the user service registration",
                    true,
                )?,
                SetupActionPlan::new(
                    "service-start-or-restart",
                    "Start or restart the registered Host service",
                    true,
                )?,
            ],
            Self::PersistentHostStop => vec![SetupActionPlan::new(
                "service-stop",
                "Stop the registered Host service",
                true,
            )?],
            Self::PersistentHostRestart => vec![SetupActionPlan::new(
                "service-restart",
                "Restart the registered Host service",
                true,
            )?],
        };
        Ok(actions)
    }

    fn accepts_operation_kind(self, operation_kind: SetupOperationKind) -> bool {
        match self {
            Self::PersistentHostStop => operation_kind == SetupOperationKind::ServiceStop,
            Self::PersistentHostRestart => operation_kind == SetupOperationKind::ServiceRestart,
            Self::OnDemandHandoff | Self::PersistentHostService => !matches!(
                operation_kind,
                SetupOperationKind::ServiceStop | SetupOperationKind::ServiceRestart
            ),
        }
    }

    fn matches_run(self, run: &SetupRunRecord) -> Result<bool, SatelleError> {
        let expected = self.actions()?;
        Ok(run
            .actions()
            .iter()
            .map(SetupActionRecord::action_id)
            .eq(expected.iter().map(SetupActionPlan::action_id)))
    }
}

fn persistent_service_action(action_id: &str) -> bool {
    matches!(
        action_id,
        "bootstrap-handoff"
            | "path-set-directories"
            | "service-config"
            | "service-registration"
            | "service-start-or-restart"
            | "service-stop"
            | "service-restart"
    )
}
#[cfg(any(test, feature = "test-support"))]
use test_runtime::FakeComputerUseAdapter;
#[cfg(feature = "test-support")]
use test_runtime::{
    FailingComputerUseAdapter, PendingComputerUseAdapter, ReadinessFailingComputerUseAdapter,
};
use time::format_description::well_known::Rfc3339;

const DEFAULT_NATIVE_READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const DEFAULT_PROVIDER_SMOKE_TEST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);
pub(crate) const READINESS_CANCELLATION_GRACE: std::time::Duration =
    std::time::Duration::from_secs(5);
const ADMISSION_RESPONSE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const DEFAULT_NATIVE_READINESS_TTL: time::Duration = time::Duration::minutes(5);
const DEFAULT_PROVIDER_SMOKE_SUCCESS_TTL: time::Duration = time::Duration::hours(24);
const DEFAULT_PROVIDER_SMOKE_FAILURE_TTL: time::Duration = time::Duration::minutes(10);

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support {
    pub use crate::storage::TestStateDir;
    pub use crate::test_runtime::DETACHED_EXECUTION_TRACE_MARKER;
}

#[cfg(test)]
use test_support::TestStateDir;

#[cfg(test)]
#[path = "operation-capacity-tests.rs"]
mod operation_capacity_tests;

#[cfg(test)]
mod bootstrap_maintenance_tests {
    use super::*;

    fn bootstrap_plan(operation_id: &str, operation_kind: SetupOperationKind) -> SetupRunPlan {
        SetupRunPlan::new(
            operation_id,
            operation_kind,
            None,
            time::OffsetDateTime::now_utc(),
            vec![
                SetupActionPlan::new("bootstrap-handoff", "Bootstrap Lock handoff", true)
                    .expect("valid bootstrap action"),
            ],
        )
        .expect("valid bootstrap plan")
    }

    #[test]
    fn persistent_lifecycle_plans_require_their_exact_operation_kind() {
        let state = TestStateDir::new().expect("create state directory");
        let service =
            HostService::local_demo_for_tests_at(state.path()).expect("create Host service");

        for (operation_id, operation_kind, plan_kind, expected_action) in [
            (
                "persistent-host-stop",
                SetupOperationKind::ServiceStop,
                BootstrapMaintenancePlanKind::PersistentHostStop,
                "service-stop",
            ),
            (
                "persistent-host-restart",
                SetupOperationKind::ServiceRestart,
                BootstrapMaintenancePlanKind::PersistentHostRestart,
                "service-restart",
            ),
        ] {
            service
                .acquire_bootstrap_maintenance_plan(operation_id, operation_kind, plan_kind)
                .expect("acquire exact lifecycle plan");
            let planned = service
                .load_setup_run(operation_id)
                .expect("load lifecycle run")
                .expect("lifecycle run exists");
            assert_eq!(operation_kind, planned.operation_kind());
            assert_eq!(1, planned.actions().len());
            assert_eq!(expected_action, planned.actions()[0].action_id());
            assert_eq!(SetupActionStatus::Planned, planned.actions()[0].status());

            let mismatched_action = if expected_action == "service-stop" {
                "service-restart"
            } else {
                "service-stop"
            };
            assert!(
                service
                    .start_bootstrap_service_action(operation_id, mismatched_action)
                    .is_err(),
                "a lifecycle plan must reject the other lifecycle action"
            );
            service
                .start_bootstrap_service_action(operation_id, expected_action)
                .expect("start exact lifecycle action");
            service
                .complete_bootstrap_service_action(operation_id, expected_action)
                .expect("complete exact lifecycle action");
            service
                .finish_bootstrap_service_maintenance(operation_id)
                .expect("finish lifecycle plan");
            let completed = service
                .load_setup_run(operation_id)
                .expect("load completed lifecycle run")
                .expect("completed lifecycle run exists");
            assert_eq!(SetupRunStatus::Completed, completed.status());
        }

        assert!(
            service
                .acquire_bootstrap_maintenance_plan(
                    "stop-with-setup-kind",
                    SetupOperationKind::Setup,
                    BootstrapMaintenancePlanKind::PersistentHostStop,
                )
                .is_err(),
            "persistent Host stop must reject the setup operation kind"
        );
        assert!(
            service
                .acquire_bootstrap_maintenance_plan(
                    "stop-with-restart-kind",
                    SetupOperationKind::ServiceRestart,
                    BootstrapMaintenancePlanKind::PersistentHostStop,
                )
                .is_err(),
            "persistent Host stop must reject the restart operation kind"
        );
        assert!(
            service
                .acquire_bootstrap_maintenance_plan(
                    "restart-with-stop-kind",
                    SetupOperationKind::ServiceStop,
                    BootstrapMaintenancePlanKind::PersistentHostRestart,
                )
                .is_err(),
            "persistent Host restart must reject the stop operation kind"
        );
        assert!(
            service
                .acquire_bootstrap_maintenance_plan(
                    "service-restart-with-setup-plan",
                    SetupOperationKind::ServiceRestart,
                    BootstrapMaintenancePlanKind::PersistentHostService,
                )
                .is_err(),
            "service_restart must not admit the multi-action setup plan"
        );
    }

    #[test]
    fn bootstrap_maintenance_is_idempotent_and_completes_durably() {
        let state = TestStateDir::new().expect("create state directory");
        let service =
            HostService::local_demo_for_tests_at(state.path()).expect("create Host service");
        service
            .acquire_bootstrap_maintenance("bootstrap-operation-1", SetupOperationKind::Repair)
            .expect("acquire maintenance");
        service
            .acquire_bootstrap_maintenance("bootstrap-operation-1", SetupOperationKind::Repair)
            .expect("repeat same-operation handoff");
        assert!(
            service
                .acquire_bootstrap_maintenance("bootstrap-operation-2", SetupOperationKind::Repair,)
                .is_err()
        );
        service
            .complete_bootstrap_maintenance("bootstrap-operation-1")
            .expect("complete maintenance");
        service
            .complete_bootstrap_maintenance("bootstrap-operation-1")
            .expect("repeat completed handoff");
        service
            .acquire_bootstrap_maintenance("bootstrap-operation-1", SetupOperationKind::Repair)
            .expect("repeat completed acquisition");
        assert!(
            service
                .acquire_bootstrap_maintenance(
                    "bootstrap-operation-1",
                    SetupOperationKind::HostUpdate,
                )
                .is_err()
        );
        assert_eq!(
            service
                .load_setup_run("bootstrap-operation-1")
                .expect("load setup run")
                .expect("stored setup run")
                .status(),
            SetupRunStatus::Completed
        );
    }

    #[test]
    fn replacement_service_adopts_the_same_recovery_operation() {
        let state = TestStateDir::new().expect("create state directory");
        {
            let original =
                HostService::local_demo_for_tests_at(state.path()).expect("create original Host");
            original
                .acquire_bootstrap_maintenance(
                    "bootstrap-operation-recovery",
                    SetupOperationKind::HostUpdate,
                )
                .expect("acquire original maintenance");
        }
        let replacement =
            HostService::local_demo_for_tests_at(state.path()).expect("create replacement Host");
        replacement
            .acquire_bootstrap_maintenance(
                "bootstrap-operation-recovery",
                SetupOperationKind::HostUpdate,
            )
            .expect("adopt recovery maintenance");
        replacement
            .complete_bootstrap_maintenance("bootstrap-operation-recovery")
            .expect("complete adopted maintenance");
    }

    #[test]
    fn replacement_adopts_a_handoff_crashed_before_action_start() {
        let state = TestStateDir::new().expect("create state directory");
        let operation_id = "bootstrap-operation-planned-recovery";
        {
            let original =
                HostService::local_demo_for_tests_at(state.path()).expect("create original Host");
            let _operation = original
                .begin_setup_run(&bootstrap_plan(operation_id, SetupOperationKind::Repair))
                .expect("persist setup run before action start");
        }

        let replacement =
            HostService::local_demo_for_tests_at(state.path()).expect("create replacement Host");
        replacement
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("adopt planned bootstrap handoff");
        replacement
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("repeat adopted bootstrap handoff");
        let adopted = replacement
            .load_setup_run(operation_id)
            .expect("load adopted setup run")
            .expect("adopted setup run exists");
        assert_eq!(SetupRunStatus::Running, adopted.status());
        assert_eq!(SetupActionStatus::Started, adopted.actions()[0].status());

        replacement
            .complete_bootstrap_maintenance(operation_id)
            .expect("complete adopted bootstrap handoff");
        replacement
            .complete_bootstrap_maintenance(operation_id)
            .expect("repeat completed bootstrap handoff");
    }

    #[test]
    fn replacement_adopts_a_handoff_crashed_after_action_completion() {
        let state = TestStateDir::new().expect("create state directory");
        let operation_id = "bootstrap-operation-completed-recovery";
        {
            let original =
                HostService::local_demo_for_tests_at(state.path()).expect("create original Host");
            let operation = original
                .begin_setup_run(&bootstrap_plan(
                    operation_id,
                    SetupOperationKind::HostUpdate,
                ))
                .expect("persist setup run");
            original
                .start_setup_action(
                    &operation,
                    "bootstrap-handoff",
                    time::OffsetDateTime::now_utc(),
                )
                .expect("start bootstrap handoff");
            original
                .complete_setup_action_after_verified_postcondition(
                    &operation,
                    "bootstrap-handoff",
                    time::OffsetDateTime::now_utc(),
                )
                .expect("complete bootstrap handoff before crash");
        }

        let replacement =
            HostService::local_demo_for_tests_at(state.path()).expect("create replacement Host");
        replacement
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::HostUpdate)
            .expect("adopt completed bootstrap handoff");
        replacement
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::HostUpdate)
            .expect("repeat adopted bootstrap handoff");
        let adopted = replacement
            .load_setup_run(operation_id)
            .expect("load adopted setup run")
            .expect("adopted setup run exists");
        assert_eq!(SetupRunStatus::Running, adopted.status());
        assert_eq!(SetupActionStatus::Completed, adopted.actions()[0].status());

        replacement
            .complete_bootstrap_maintenance(operation_id)
            .expect("finish recovered completed handoff");
        replacement
            .complete_bootstrap_maintenance(operation_id)
            .expect("repeat completed bootstrap handoff");
    }

    #[test]
    fn active_bootstrap_retry_rejects_operation_kind_mismatch() {
        let state = TestStateDir::new().expect("create state directory");
        let service =
            HostService::local_demo_for_tests_at(state.path()).expect("create Host service");
        let operation_id = "bootstrap-operation-active-kind";
        service
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("acquire repair maintenance");
        service
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("same-kind active retry is idempotent");
        assert!(
            service
                .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::HostUpdate)
                .is_err(),
            "same operation id cannot change its persisted operation kind"
        );
        let run = service
            .load_setup_run(operation_id)
            .expect("load active setup run")
            .expect("active setup run exists");
        assert_eq!(SetupOperationKind::Repair, run.operation_kind());
        assert_eq!(SetupRunStatus::Running, run.status());
    }

    #[test]
    fn poisoned_bootstrap_maintenance_mutex_recovers_acquire_and_complete() {
        let state = TestStateDir::new().expect("create state directory");
        let service =
            HostService::local_demo_for_tests_at(state.path()).expect("create Host service");
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = service
                .bootstrap_maintenance
                .lock()
                .expect("bootstrap maintenance mutex starts healthy");
            panic!("poison bootstrap maintenance mutex");
        }));
        assert!(poisoned.is_err(), "test must poison the real shared mutex");

        let operation_id = "bootstrap-operation-poison-recovery";
        service
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("poisoned mutex must not prevent acquisition");
        service
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("same-operation retry remains idempotent after poison");
        service
            .complete_bootstrap_maintenance(operation_id)
            .expect("poisoned mutex must not prevent completion");
        service
            .complete_bootstrap_maintenance(operation_id)
            .expect("completed retry remains idempotent after poison");

        let run = service
            .load_setup_run(operation_id)
            .expect("load completed setup run")
            .expect("completed setup run exists");
        assert_eq!(SetupRunStatus::Completed, run.status());
        assert_eq!(SetupActionStatus::Completed, run.actions()[0].status());
    }

    #[test]
    fn bootstrap_heartbeat_recovery_transition_failure_is_nonterminal_and_recoverable() {
        let state = TestStateDir::new().expect("create state directory");
        let operation_id = "bootstrap-operation-heartbeat-retain-failure";
        {
            let original =
                HostService::local_demo_for_tests_at(state.path()).expect("create original Host");
            original
                .runtime
                .fail_next_maintenance_start_and_retain_for_tests();
            let error = original
                .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
                .expect_err("forced heartbeat and retain failure must reject acquisition");
            assert_eq!(satelle_core::ErrorCode::StorageIntegrityFailed, error.code);
            assert_ne!(satelle_core::ErrorCode::StateConflict, error.code);
            let run = original
                .load_setup_run(operation_id)
                .expect("load committed bootstrap run")
                .expect("committed bootstrap run exists");
            assert_eq!(SetupRunStatus::Running, run.status());
            assert_eq!(SetupActionStatus::Started, run.actions()[0].status());
        }

        {
            let replacement = HostService::local_demo_for_tests_at(state.path())
                .expect("create replacement Host");
            replacement
                .runtime
                .fail_next_maintenance_start_and_retain_for_tests();
            let error = replacement
                .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
                .expect_err("forced adoption heartbeat and retain failure must reject acquisition");
            assert_eq!(satelle_core::ErrorCode::StorageIntegrityFailed, error.code);
            assert_ne!(satelle_core::ErrorCode::StateConflict, error.code);
        }

        let final_service =
            HostService::local_demo_for_tests_at(state.path()).expect("create final Host");
        final_service
            .acquire_bootstrap_maintenance(operation_id, SetupOperationKind::Repair)
            .expect("adopt the retained operation after both failures");
        final_service
            .complete_bootstrap_maintenance(operation_id)
            .expect("complete the recovered bootstrap operation");
        let completed = final_service
            .load_setup_run(operation_id)
            .expect("load completed bootstrap run")
            .expect("completed bootstrap run exists");
        assert_eq!(SetupRunStatus::Completed, completed.status());
        assert_eq!(
            SetupActionStatus::Completed,
            completed.actions()[0].status()
        );
    }
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy)]
struct ResolvedSecretCanaryAdapter;

#[cfg(feature = "test-support")]
impl ComputerUseAdapter for ResolvedSecretCanaryAdapter {
    fn preflight(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<AdapterReadiness, SatelleError> {
        let binding = provider_intent
            .resolved_provider_binding()
            .expect("Host must inject the authoritative provider binding");
        let secret = runtime::resolve_provider_child_secret_for_test(binding)?
            .expect("the canary provider binding must resolve a secret");
        assert!(
            secret
                .expose_to_provider(|value| { value == "PRIVATE_RESOLVED_PROVIDER_SECRET_CANARY" })
        );
        FakeComputerUseAdapter.preflight(host, provider_intent)
    }

    fn execute(&self, request: ExecuteRequest<'_>) -> Result<ExecuteResult, SatelleError> {
        FakeComputerUseAdapter.execute(request)
    }

    fn observe_stop(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<satelle_core::session::StopObservation, SatelleError> {
        FakeComputerUseAdapter.observe_stop(subject)
    }

    fn observe_recovery(
        &self,
        subject: AdapterSubject<'_>,
    ) -> Result<RecoveryObservation, SatelleError> {
        FakeComputerUseAdapter.observe_recovery(subject)
    }
}

#[derive(Clone, Debug)]
pub struct HostService {
    runtime: RuntimeHandle,
    operation_capacity: Arc<OperationCapacity>,
    turn_execution_timeout: satelle_core::session::TimeoutPolicy,
    mode: HostMode,
    bootstrap_auth: Option<Arc<EphemeralApiAuthenticator>>,
    bootstrap_maintenance: Arc<Mutex<Option<MaintenanceOperationHandle>>>,
    doctor_tasks: DoctorTaskRegistry,
}

#[derive(Clone, Debug)]
enum HostMode {
    Production {
        snapshot: Arc<RwLock<ProductionCapabilitySnapshot>>,
    },
    #[cfg(any(test, feature = "test-support"))]
    TestFake { image_attachments: bool },
}

fn configured_turn_execution_timeout(config: &HostConfig) -> satelle_core::session::TimeoutPolicy {
    let seconds = config
        .timeouts
        .as_ref()
        .and_then(|timeouts| timeouts.turn_execution.as_ref())
        .map_or(
            (satelle_core::DEFAULT_TURN_EXECUTION_TIMEOUT_MS / 1_000) as u32,
            satelle_core::TurnExecutionDuration::seconds,
        );
    satelle_core::session::TimeoutPolicy::bounded_seconds(seconds)
        .expect("validated Turn execution configuration has a nonzero timeout")
}

#[derive(Clone, Debug)]
pub(crate) struct ProductionCapabilitySnapshot {
    evidence: codex_capabilities::Phase0CapabilityEvidence,
    verdict: Phase0SupportVerdict,
    control_plane_admission: codex_capabilities::ControlPlaneAdmission,
    budget_failure: Option<codex_capabilities::Phase0BudgetFailure>,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
}

impl ProductionCapabilitySnapshot {
    fn collect(probe_timeout: Option<std::time::Duration>) -> Self {
        let started_at = utc_now();
        let started = Instant::now();
        let discovery = discover_phase0(probe_timeout);
        let verdict = evaluate_phase0_support(discovery.evidence);
        debug_assert!(
            discovery.budget_failure.is_none() || !verdict.is_supported(),
            "a Phase 0 budget failure cannot produce supported evidence"
        );
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        Self {
            evidence: discovery.evidence,
            verdict,
            control_plane_admission: discovery.control_plane_admission,
            budget_failure: discovery.budget_failure,
            started_at,
            finished_at: utc_now(),
            duration_ms,
        }
    }

    pub(crate) const fn goal_set_supported(&self) -> bool {
        self.control_plane_admission.goal_set()
    }

    pub(crate) const fn image_input_mode(&self) -> codex_capabilities::CodexImageInputMode {
        self.control_plane_admission.image_input()
    }

    pub(crate) const fn image_attachments_supported(&self) -> bool {
        !matches!(
            self.image_input_mode(),
            codex_capabilities::CodexImageInputMode::Unsupported
        )
    }
}

fn read_production_snapshot(
    snapshot: &RwLock<ProductionCapabilitySnapshot>,
) -> Result<RwLockReadGuard<'_, ProductionCapabilitySnapshot>, SatelleError> {
    snapshot.read().map_err(|_| {
        crate::runtime::integrity_error("the production capability snapshot lock was poisoned")
    })
}

fn replace_production_snapshot(
    snapshot: &RwLock<ProductionCapabilitySnapshot>,
    refreshed: ProductionCapabilitySnapshot,
) -> Result<(), SatelleError> {
    *snapshot.write().map_err(|_| {
        crate::runtime::integrity_error("the production capability snapshot lock was poisoned")
    })? = refreshed;
    Ok(())
}

fn provider_validation_outcome_for_error(
    error: &SatelleError,
) -> Option<satelle_core::ProviderAuthValidationOutcome> {
    match error.code {
        satelle_core::ErrorCode::ProviderSecretResolutionFailed => {
            Some(satelle_core::ProviderAuthValidationOutcome::UnresolvedHostSecret)
        }
        satelle_core::ErrorCode::ProviderSmokeTestTimeout
        | satelle_core::ErrorCode::ExperimentalProviderNotValidated => {
            Some(satelle_core::ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed)
        }
        _ if error
            .details
            .get("provider_smoke_status")
            .and_then(serde_json::Value::as_str)
            == Some("failed") =>
        {
            Some(satelle_core::ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed)
        }
        _ => None,
    }
}

struct ProviderSecretComparison {
    key: Zeroizing<String>,
    digest: [u8; 32],
    digest_hex: String,
}

#[derive(Clone, Copy)]
enum ProviderSecretPostT0Phase {
    Planned,
    Staged,
    Validated,
    PublishIntent,
    Committed,
}

enum ProviderSecretPostT0Failure {
    Ordinary(SatelleError),
    RecoveryRequired(SatelleError),
    UnknownProviderOutcome(SatelleError),
}

impl From<SatelleError> for ProviderSecretPostT0Failure {
    fn from(error: SatelleError) -> Self {
        Self::Ordinary(error)
    }
}

/// Owns every exit after the provisioning journal has durably claimed T0.
///
/// Ordinary failures must either terminalize now or leave enough verified
/// evidence for startup recovery. Journal, cleanup, rollback, and unknown
/// provider outcomes cannot safely choose a terminal state, so those paths
/// deliberately retain the lease.
struct ProviderSecretPostT0Guard<'a> {
    runtime: &'a RuntimeHandle,
    operation_id: String,
    paths: satelle_core::OwnerOnlySecretFilePaths,
    candidate: ProviderSecretComparison,
    prior: Option<ProviderSecretComparison>,
    destination_existed: Option<bool>,
    phase: ProviderSecretPostT0Phase,
    publish_may_have_mutated: bool,
    preserve_raced_destination: bool,
    published_overwrite: Option<bool>,
    pending: Option<runtime::PendingProviderReadiness>,
}

impl<'a> ProviderSecretPostT0Guard<'a> {
    fn new(
        runtime: &'a RuntimeHandle,
        operation_id: String,
        paths: satelle_core::OwnerOnlySecretFilePaths,
        candidate: ProviderSecretComparison,
    ) -> Self {
        Self {
            runtime,
            operation_id,
            paths,
            candidate,
            prior: None,
            destination_existed: None,
            phase: ProviderSecretPostT0Phase::Planned,
            publish_may_have_mutated: false,
            preserve_raced_destination: false,
            published_overwrite: None,
            pending: None,
        }
    }

    fn record_destination(
        &mut self,
        destination_existed: bool,
        prior: Option<ProviderSecretComparison>,
    ) {
        self.destination_existed = Some(destination_existed);
        self.prior = prior;
    }

    fn candidate_evidence(&self) -> (&[u8], &[u8; 32]) {
        (self.candidate.key.as_bytes(), &self.candidate.digest)
    }

    fn prior_evidence(&self) -> Option<(&[u8], &[u8; 32])> {
        self.prior
            .as_ref()
            .map(|prior| (prior.key.as_bytes(), &prior.digest))
    }

    fn mark_staged(&mut self) {
        self.phase = ProviderSecretPostT0Phase::Staged;
    }

    fn mark_validated(&mut self) {
        self.phase = ProviderSecretPostT0Phase::Validated;
    }

    fn mark_publish_intent(&mut self) {
        self.phase = ProviderSecretPostT0Phase::PublishIntent;
        self.publish_may_have_mutated = true;
    }

    fn preserve_raced_destination(&mut self) {
        self.preserve_raced_destination = true;
    }

    fn record_published(&mut self, overwritten: bool) {
        self.published_overwrite = Some(overwritten);
    }

    fn mark_committed(&mut self) {
        self.phase = ProviderSecretPostT0Phase::Committed;
    }

    fn set_pending(&mut self, pending: runtime::PendingProviderReadiness) {
        self.pending = Some(pending);
    }

    fn readiness(&self) -> Result<&AdapterReadiness, SatelleError> {
        self.pending
            .as_ref()
            .ok_or_else(SatelleError::state_conflict)?
            .readiness()
    }

    fn cleanup_staging(&self) -> Result<(), SatelleError> {
        satelle_core::cleanup_owner_only_secret_file(
            &self.paths,
            Some(self.candidate_evidence()),
            self.prior_evidence(),
        )
        .map_err(|_| SatelleError::state_conflict())
    }

    fn rollback_publish(&self) -> Result<(), SatelleError> {
        let overwritten = self
            .published_overwrite
            .or(self.destination_existed)
            .unwrap_or(false);
        satelle_core::rollback_owner_only_secret_file(
            &self.paths,
            overwritten,
            self.candidate.key.as_bytes(),
            &self.candidate.digest,
            self.prior.as_ref().map(|prior| prior.key.as_bytes()),
            self.prior.as_ref().map(|prior| &prior.digest),
        )
        .map_err(|_| SatelleError::state_conflict())
    }

    fn retain_for_recovery(mut self) {
        if let Some(pending) = self.pending.take() {
            pending.retain_for_recovery();
        }
    }

    fn finish_success(mut self) {
        if let Some(pending) = self.pending.take() {
            pending.finish();
        }
    }

    fn terminalize_failure(mut self, error: SatelleError) -> SatelleError {
        let expected_phase = match self.phase {
            ProviderSecretPostT0Phase::Planned => None,
            ProviderSecretPostT0Phase::Staged => {
                Some(storage::ProviderSecretProvisioningPhase::Staged)
            }
            ProviderSecretPostT0Phase::Validated => {
                Some(storage::ProviderSecretProvisioningPhase::Validated)
            }
            ProviderSecretPostT0Phase::PublishIntent => {
                Some(storage::ProviderSecretProvisioningPhase::PublishIntent)
            }
            ProviderSecretPostT0Phase::Committed => {
                self.retain_for_recovery();
                return SatelleError::state_conflict();
            }
        };
        if let Some(expected_phase) = expected_phase
            && self
                .runtime
                .mark_provider_secret_provisioning_rollback_pending(
                    &self.operation_id,
                    expected_phase,
                )
                .is_err()
        {
            self.retain_for_recovery();
            return SatelleError::state_conflict();
        }

        // Before publication, rollback means deleting only verified sibling
        // artifacts. Once publication may have started, restore the prior
        // destination or remove the verified new candidate. An overwrite race
        // is the exception: the newly occupied destination is not ours.
        let rollback = match self.phase {
            ProviderSecretPostT0Phase::Planned
            | ProviderSecretPostT0Phase::Staged
            | ProviderSecretPostT0Phase::Validated => self.cleanup_staging(),
            ProviderSecretPostT0Phase::PublishIntent
                if self.preserve_raced_destination || !self.publish_may_have_mutated =>
            {
                self.cleanup_staging()
            }
            ProviderSecretPostT0Phase::PublishIntent => self.rollback_publish(),
            ProviderSecretPostT0Phase::Committed => unreachable!("handled above"),
        };
        if rollback.is_err() {
            self.retain_for_recovery();
            return SatelleError::state_conflict();
        }

        if let Some(pending) = self.pending.take() {
            pending.finish();
        }
        self.runtime
            .finish_provider_secret_provisioning_failure(&self.operation_id, error)
            .unwrap_or_else(|_| SatelleError::state_conflict())
    }
}

fn provider_secret_comparison(
    runtime: &RuntimeHandle,
    domain: &'static str,
    secret: &provider_auth::ResolvedProviderSecret,
) -> Result<ProviderSecretComparison, SatelleError> {
    let key = Zeroizing::new(runtime.provider_secret_provisioning_hmac(domain, secret)?);
    let digest = secret
        .expose_to_provider(|value| {
            satelle_core::keyed_secret_comparison_digest(key.as_bytes(), value.as_bytes())
        })
        .map_err(|_| {
            SatelleError::config_error(
                "the Host could not verify provider secret staging material",
                None,
            )
        })?;
    let digest_hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(ProviderSecretComparison {
        key,
        digest,
        digest_hex,
    })
}

fn provider_secret_file_comparison(
    runtime: &RuntimeHandle,
    domain: &'static str,
    secret: &provider_auth::ResolvedProviderSecret,
    path: &std::path::Path,
) -> Result<ProviderSecretComparison, SatelleError> {
    let key = Zeroizing::new(runtime.provider_secret_provisioning_hmac(domain, secret)?);
    let digest = satelle_core::keyed_owner_only_secret_file_comparison_digest(path, key.as_bytes())
        .map_err(|_| provider_secret_file_error())?;
    let digest_hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(ProviderSecretComparison {
        key,
        digest,
        digest_hex,
    })
}

fn provider_secret_file_error() -> SatelleError {
    SatelleError {
        code: satelle_core::ErrorCode::ProviderSecretProvisioningRequired,
        message: "the Host could not safely provision the provider secret File destination"
            .to_string(),
        recovery_command: Some(
            "retry provider secret provisioning after inspecting the Host destination".to_string(),
        ),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn provider_secret_source_error() -> SatelleError {
    SatelleError {
        code: satelle_core::ErrorCode::ProviderSecretSourceRequired,
        message: "provider secret provisioning requires a File Secret Source".to_string(),
        recovery_command: Some("configure an absolute target-host File Secret Source".to_string()),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn provider_secret_overwrite_error() -> SatelleError {
    SatelleError {
        code: satelle_core::ErrorCode::ProviderSecretOverwriteRequired,
        message:
            "explicit overwrite confirmation is required for the provider secret File destination"
                .to_string(),
        recovery_command: Some(
            "repeat provisioning with explicit overwrite confirmation".to_string(),
        ),
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

pub(crate) fn validate_provider_binding_authorization(
    authorization: &ProviderBindingAuthorization,
) -> Result<(), SatelleError> {
    if authorization.requested_model_alias().trim().is_empty()
        || authorization.requested_provider_alias().trim().is_empty()
        || authorization.model().trim().is_empty()
        || authorization.model_provider().trim().is_empty()
    {
        return Err(SatelleError::config_error(
            "provider binding authorization values must not be empty",
            None,
        ));
    }
    if authorization.requested_model_alias() == DEFAULT_MODEL_BINDING
        && authorization.requested_provider_alias() == DEFAULT_PROVIDER_BINDING
    {
        return Err(SatelleError::config_error(
            "the provider binding alias pair `codex-default/codex-default` is reserved for implicit Codex defaults",
            None,
        ));
    }
    satelle_core::session::EffectiveModelRef::new(authorization.requested_model_alias())
        .map_err(|_| SatelleError::config_error("the model alias is invalid", None))?;
    satelle_core::session::ProviderBindingRef::new(authorization.requested_provider_alias())
        .map_err(|_| SatelleError::config_error("the provider alias is invalid", None))?;
    if let Some(endpoint) = authorization.endpoint() {
        runtime::validate_provider_endpoint(endpoint)?;
    }
    if let Some(source) = authorization.auth_source() {
        provider_auth::validate_provider_secret_source_descriptor(
            source,
            provider_auth::ProviderHostPlatform::current(),
        )
        .map_err(|error| match error {
            provider_auth::ProviderAuthResolutionError::InvalidFilePath => SatelleError {
                code: satelle_core::ErrorCode::SecretFilePathNotAbsolute,
                message: "the provider Secret Source file path is not absolute for the target Host"
                    .to_string(),
                recovery_command: Some(
                    "use an absolute target-host file path for file Secret Sources".to_string(),
                ),
                source_detail: None,
                details: std::collections::BTreeMap::new(),
            },
            _ => SatelleError::config_error(
                "the provider Secret Source descriptor is invalid for the target Host",
                None,
            ),
        })?;
        if authorization.endpoint().is_none()
            && !authorization
                .model_provider()
                .eq_ignore_ascii_case("openai")
        {
            return Err(SatelleError::config_error(
                "provider Secret Sources without a custom endpoint are supported only for the built-in OpenAI provider",
                None,
            ));
        }
    }
    if (!authorization
        .model_provider()
        .eq_ignore_ascii_case("openai")
        || authorization.endpoint().is_some())
        && !authorization.experimental_provider_computer_use()
    {
        return Err(SatelleError {
            code: satelle_core::ErrorCode::ExperimentalProviderOptInRequired,
            message: "custom provider Computer Use requires explicit Host authorization"
                .to_string(),
            recovery_command: Some(
                "enable experimental provider Computer Use during SSH bootstrap setup".to_string(),
            ),
            source_detail: None,
            details: std::collections::BTreeMap::new(),
        });
    }
    Ok(())
}

impl HostService {
    #[cfg(test)]
    pub(crate) fn local_demo_with_readiness_driver_for_tests_at<
        D: runtime::ReadinessProbeDriver,
    >(
        state_root: impl Into<std::path::PathBuf>,
        driver: D,
    ) -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new_with_readiness_probe_driver(
                Ok(state_root.into()),
                FakeComputerUseAdapter,
                driver,
            ),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        })
    }

    /// Persists an ordered setup or repair plan before any action can mutate
    /// the Host. CLI presentation and transport code do not get a separate
    /// ledger path.
    pub fn begin_setup_run(
        &self,
        plan: &SetupRunPlan,
    ) -> Result<MaintenanceOperationHandle, SatelleError> {
        self.runtime.begin_setup_run(plan)
    }

    pub fn acquire_bootstrap_maintenance(
        &self,
        operation_id: &str,
        operation_kind: SetupOperationKind,
    ) -> Result<(), SatelleError> {
        self.acquire_bootstrap_maintenance_plan(
            operation_id,
            operation_kind,
            BootstrapMaintenancePlanKind::OnDemandHandoff,
        )
    }

    pub fn acquire_bootstrap_maintenance_plan(
        &self,
        operation_id: &str,
        operation_kind: SetupOperationKind,
        plan_kind: BootstrapMaintenancePlanKind,
    ) -> Result<(), SatelleError> {
        if !plan_kind.accepts_operation_kind(operation_kind) {
            return Err(SatelleError::invalid_usage(
                "maintenance plan and operation kind do not match",
            ));
        }
        let mut slot = self
            .bootstrap_maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(operation) = slot.as_ref() {
            if operation.operation_id() != operation_id {
                return Err(SatelleError::state_conflict());
            }
            let run = self
                .runtime
                .load_setup_run(operation_id)?
                .ok_or_else(SatelleError::state_conflict)?;
            return if run.operation_kind() == operation_kind && plan_kind.matches_run(&run)? {
                Ok(())
            } else {
                Err(SatelleError::state_conflict())
            };
        }
        let existing_run = self.runtime.load_setup_run(operation_id)?;
        if let Some(run) = existing_run.as_ref() {
            if run.operation_kind() != operation_kind || !plan_kind.matches_run(run)? {
                return Err(SatelleError::state_conflict());
            }
            if run.status() == SetupRunStatus::Completed {
                return Ok(());
            }
        }
        let operation = if existing_run.is_some() {
            self.runtime.adopt_recovery_maintenance(operation_id)?
        } else {
            let plan = SetupRunPlan::new(
                operation_id,
                operation_kind,
                None,
                time::OffsetDateTime::now_utc(),
                plan_kind.actions()?,
            )?;
            self.runtime.begin_bootstrap_maintenance(&plan)?
        };
        *slot = Some(operation);
        Ok(())
    }

    pub fn start_bootstrap_service_action(
        &self,
        operation_id: &str,
        action_id: &str,
    ) -> Result<(), SatelleError> {
        if !persistent_service_action(action_id) {
            return Err(SatelleError::invalid_usage(
                "invalid persistent Host service action",
            ));
        }
        let slot = self
            .bootstrap_maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let operation = slot.as_ref().ok_or_else(SatelleError::state_conflict)?;
        if operation.operation_id() != operation_id {
            return Err(SatelleError::state_conflict());
        }
        self.runtime
            .start_setup_action(operation, action_id, time::OffsetDateTime::now_utc())
    }

    pub fn complete_bootstrap_service_action(
        &self,
        operation_id: &str,
        action_id: &str,
    ) -> Result<(), SatelleError> {
        if !persistent_service_action(action_id) {
            return Err(SatelleError::invalid_usage(
                "invalid persistent Host service action",
            ));
        }
        let slot = self
            .bootstrap_maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let operation = slot.as_ref().ok_or_else(SatelleError::state_conflict)?;
        if operation.operation_id() != operation_id {
            return Err(SatelleError::state_conflict());
        }
        self.runtime
            .complete_setup_action_after_verified_postcondition(
                operation,
                action_id,
                time::OffsetDateTime::now_utc(),
            )
    }

    pub fn fail_bootstrap_service_action(
        &self,
        operation_id: &str,
        action_id: &str,
        failure_kind: &str,
    ) -> Result<(), SatelleError> {
        if !persistent_service_action(action_id) {
            return Err(SatelleError::invalid_usage(
                "invalid persistent Host service action",
            ));
        }
        let (error_code, recovery_hint) = match failure_kind {
            "remote_command_failed" => (
                "remote_command_failed",
                "rerun persistent setup after correcting the reported remote command failure",
            ),
            "postcondition_failed" => (
                "postcondition_failed",
                "inspect the user service definition, then rerun persistent setup",
            ),
            "readiness_failed" => (
                "readiness_failed",
                "inspect the user service and loopback listener, then rerun persistent setup",
            ),
            "listener_still_reachable" => (
                "listener_still_reachable",
                "inspect the user service and loopback listener, then retry the Host stop",
            ),
            _ => {
                return Err(SatelleError::invalid_usage(
                    "invalid persistent Host service failure kind",
                ));
            }
        };
        let slot = self
            .bootstrap_maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let operation = slot.as_ref().ok_or_else(SatelleError::state_conflict)?;
        if operation.operation_id() != operation_id {
            return Err(SatelleError::state_conflict());
        }
        let failed_at = time::OffsetDateTime::now_utc();
        self.runtime.fail_setup_action(
            operation,
            action_id,
            error_code,
            None,
            Some(recovery_hint),
            failed_at,
        )?;
        let run = self
            .runtime
            .load_setup_run(operation_id)?
            .ok_or_else(SatelleError::state_conflict)?;
        let failed_index = run
            .actions()
            .iter()
            .position(|action| action.action_id() == action_id)
            .ok_or_else(SatelleError::state_conflict)?;
        for (offset, action) in run.actions()[failed_index + 1..].iter().enumerate() {
            if action.status() == SetupActionStatus::Planned {
                self.runtime.skip_setup_action(
                    operation,
                    action.action_id(),
                    SetupActionSkipReason::DependencyFailed,
                    failed_at + time::Duration::nanoseconds((offset + 1) as i64),
                )?;
            }
        }
        Ok(())
    }

    pub fn finish_bootstrap_service_maintenance(
        &self,
        operation_id: &str,
    ) -> Result<(), SatelleError> {
        let mut slot = self
            .bootstrap_maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let operation = slot.as_mut().ok_or_else(SatelleError::state_conflict)?;
        if operation.operation_id() != operation_id {
            return Err(SatelleError::state_conflict());
        }
        self.runtime
            .finish_setup_run(operation, time::OffsetDateTime::now_utc())?;
        *slot = None;
        Ok(())
    }

    pub fn complete_bootstrap_maintenance(&self, operation_id: &str) -> Result<(), SatelleError> {
        let mut slot = self
            .bootstrap_maintenance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(operation) = slot.as_mut() else {
            let completed = self
                .runtime
                .load_setup_run(operation_id)?
                .is_some_and(|run| {
                    run.status() == SetupRunStatus::Completed
                        && run.actions().iter().any(|action| {
                            action.action_id() == "bootstrap-handoff"
                                && action.status() == SetupActionStatus::Completed
                        })
                });
            return if completed {
                Ok(())
            } else {
                Err(SatelleError::state_conflict())
            };
        };
        if operation.operation_id() != operation_id {
            return Err(SatelleError::state_conflict());
        }
        self.runtime
            .complete_bootstrap_maintenance(operation, time::OffsetDateTime::now_utc())?;
        *slot = None;
        Ok(())
    }

    /// Durably marks one planned action as started before external mutation.
    pub fn start_setup_action(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        started_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.runtime
            .start_setup_action(operation, action_id, started_at)
    }

    /// Commits completion only through the postcondition-verified boundary.
    pub fn complete_setup_action_after_verified_postcondition(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        completed_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.runtime
            .complete_setup_action_after_verified_postcondition(operation, action_id, completed_at)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fail_setup_action(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        error_code: &str,
        exit_status: Option<i64>,
        recovery_hint: Option<&str>,
        failed_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.runtime.fail_setup_action(
            operation,
            action_id,
            error_code,
            exit_status,
            recovery_hint,
            failed_at,
        )
    }

    pub fn skip_setup_action(
        &self,
        operation: &MaintenanceOperationHandle,
        action_id: &str,
        reason: SetupActionSkipReason,
        skipped_at: time::OffsetDateTime,
    ) -> Result<(), SatelleError> {
        self.runtime
            .skip_setup_action(operation, action_id, reason, skipped_at)
    }

    /// Runs the canonical native readiness observer while this operation owns
    /// both Maintenance and its same-operation postcheck Control sublease.
    pub fn run_maintenance_postcheck(
        &self,
        operation: &mut MaintenanceOperationHandle,
        key: &ReadinessCacheKey,
        postcheck_action_id: &str,
    ) -> Result<SetupRunStatus, SatelleError> {
        self.runtime
            .run_maintenance_postcheck(operation, key, postcheck_action_id)
    }

    /// Derives the terminal run status from committed action states rather
    /// than accepting a caller-supplied outcome.
    pub fn finish_setup_run(
        &self,
        operation: &mut MaintenanceOperationHandle,
        finished_at: time::OffsetDateTime,
    ) -> Result<SetupRunStatus, SatelleError> {
        self.runtime.finish_setup_run(operation, finished_at)
    }

    pub fn load_setup_run(&self, run_id: &str) -> Result<Option<SetupRunRecord>, SatelleError> {
        self.runtime.load_setup_run(run_id)
    }

    /// Plans repair from current live postconditions. Retained ledger records
    /// contribute safety metadata when present but are not required.
    pub fn plan_setup_repair(
        &self,
        desktop_binding: Option<&satelle_core::session::DesktopBindingRef>,
        probes: &[SetupRepairProbe],
    ) -> Result<SetupRepairPlan, SatelleError> {
        self.runtime.plan_setup_repair(desktop_binding, probes)
    }

    /// Reconciles an interrupted maintenance run from current, operation-
    /// specific postconditions. Unknown evidence retains recovery ownership.
    pub fn reconcile_setup_maintenance(
        &self,
        observer: &mut dyn SetupPostconditionObserver,
    ) -> Result<Option<SetupRunStatus>, SatelleError> {
        self.runtime.reconcile_setup_maintenance(observer)
    }

    /// Builds the only runtime available in normal and release builds. The
    /// constructor retains only typed, diagnostic-safe capability evidence.
    pub fn production() -> Self {
        let config = satelle_core::SatelleConfig::defaults()
            .hosts
            .remove(LOCAL_DEMO_HOST)
            .expect("the built-in local Host config exists");
        Self::production_for_host(&config)
    }

    /// Builds a production Host whose probe timeouts and cache TTLs come from
    /// the fully resolved host/profile configuration.
    pub fn production_for_host(config: &HostConfig) -> Self {
        let snapshot = Arc::new(RwLock::new(ProductionCapabilitySnapshot::collect(None)));
        let paths = satelle_core::resolve_path_set(
            &std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        );
        let state_root = paths
            .as_ref()
            .map(|paths| paths.state_root.clone())
            .map_err(Clone::clone);
        let operator_log_root = paths
            .as_ref()
            .map(|paths| paths.operator_log_root.clone())
            .map_err(Clone::clone);
        let working_directory = state_root
            .as_ref()
            .map(|path| path.join("codex-app-server-work"))
            .map_err(Clone::clone);
        let (timeout, provider_smoke_timeout) = readiness_probe_timeouts(config);
        let ttl = config
            .native_readiness_cache_ttl
            .as_ref()
            .map_or(DEFAULT_NATIVE_READINESS_TTL, duration_to_time);
        let provider_smoke_success_ttl = config
            .provider_smoke_success_cache_ttl
            .as_ref()
            .map_or(DEFAULT_PROVIDER_SMOKE_SUCCESS_TTL, duration_to_time);
        let provider_smoke_failure_ttl = config
            .provider_smoke_failure_cache_ttl
            .as_ref()
            .map_or(DEFAULT_PROVIDER_SMOKE_FAILURE_TTL, duration_to_time);
        let policy = runtime::ProductionAdapterPolicy {
            native_readiness_timeout: timeout,
            native_readiness_ttl: ttl,
            provider_smoke_timeout,
            provider_smoke_success_ttl,
            provider_smoke_failure_ttl,
            desktop_selection: satelle_core::DesktopSelectionPolicy::from_host_config(config),
        };
        let adapter = ProductionComputerUseAdapter::with_readiness_policy(
            Arc::clone(&snapshot),
            working_directory,
            policy,
        );
        Self {
            runtime: RuntimeHandle::new_production(
                state_root,
                operator_log_root,
                adapter,
                runtime::RuntimeProviderPolicy::from_host_config(config),
            ),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(config),
            mode: HostMode::Production { snapshot },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        }
    }

    /// Builds an on-demand Host whose only bootstrap credential is held in
    /// process memory and expires independently of durable Host state.
    pub fn production_for_ssh_bootstrap(
        token: &ApiBearerToken,
        scopes: ApiScopes,
        expires_at: time::OffsetDateTime,
        config: &HostConfig,
    ) -> Self {
        let mut service = Self::production_for_host(config);
        service.bootstrap_auth = Some(Arc::new(EphemeralApiAuthenticator::new(
            token, scopes, expires_at,
        )));
        service
    }

    /// Commits the exact Controller-accepted identity for a fresh SSH Host
    /// before any listener can expose the new daemon.
    pub fn commit_fresh_ssh_host_identity(
        state_root: &Path,
        record: &satelle_core::SshIdentityCommitRecord,
    ) -> Result<satelle_core::session::HostIdentityRef, SatelleError> {
        let executing_artifact = std::env::current_exe().map_err(|error| {
            SatelleError::invalid_usage(format!(
                "could not identify the fresh SSH Host artifact: {error}"
            ))
        })?;
        Storage::commit_fresh_ssh_host_identity(state_root, record, &executing_artifact)
            .map_err(runtime::storage_error)
    }

    /// Reports an interrupted fresh-identity commit so ordinary startup can
    /// fail closed instead of opening the partially initialized store.
    pub fn fresh_ssh_identity_commit_pending(state_root: &Path) -> Result<bool, SatelleError> {
        Storage::fresh_ssh_identity_commit_pending(state_root).map_err(runtime::storage_error)
    }

    /// Reports whether this service owns a process-local SSH bootstrap
    /// credential. Transport servers use this to keep that credential behind
    /// the loopback boundary even when TLS is configured.
    pub fn uses_ssh_bootstrap_authentication(&self) -> bool {
        self.bootstrap_auth.is_some()
    }

    /// The deterministic adapter requires both the compile-time feature and a
    /// separate Satelle-owned CLI opt-in. It is not present in default builds.
    #[cfg(feature = "test-support")]
    pub fn local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new_with_readiness_probe_driver(
                satelle_core::state_dir(),
                FakeComputerUseAdapter,
                FakeComputerUseAdapter,
            ),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn pending_local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), PendingComputerUseAdapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn readiness_failing_local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(
                satelle_core::state_dir(),
                ReadinessFailingComputerUseAdapter,
            ),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn resolved_secret_canary_local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), ResolvedSecretCanaryAdapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        })
    }

    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn failing_local_demo_for_tests() -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: RuntimeHandle::new(satelle_core::state_dir(), FailingComputerUseAdapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
            doctor_tasks: DoctorTaskRegistry::new(),
        })
    }

    pub fn doctor(
        &self,
        host: &str,
        scope_selection: &DoctorScopeSelection,
        options: DoctorOptions,
    ) -> Result<DoctorReport, SatelleError> {
        self.doctor_with_provider_intent(
            host,
            scope_selection,
            Arc::new(ReadyControllerTransportProbe),
            options,
            &ProviderComputerUseIntent::host_default(),
        )
    }

    pub fn doctor_with_provider_intent(
        &self,
        host: &str,
        scope_selection: &DoctorScopeSelection,
        transport_probe: Arc<dyn ControllerTransportProbe>,
        options: DoctorOptions,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        match &self.mode {
            HostMode::Production { snapshot } => production_doctor_with_provider_intent(
                self,
                host,
                scope_selection,
                transport_probe,
                options,
                provider_intent,
                snapshot,
            ),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { .. } => self.test_fake_doctor_with_provider_intent(
                host,
                scope_selection,
                transport_probe,
                options,
                provider_intent,
            ),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn test_fake_doctor_with_provider_intent(
        &self,
        host: &str,
        scope_selection: &DoctorScopeSelection,
        transport_probe: Arc<dyn ControllerTransportProbe>,
        options: DoctorOptions,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        let includes_provider_scope = scope_selection.contains(DoctorScope::Provider);
        let includes_native_scope = scope_selection.contains(DoctorScope::ComputerUse);
        let has_provider_selection =
            provider_intent.model().is_some() || provider_intent.provider().is_some();
        let should_resolve_provider = includes_provider_scope && has_provider_selection;
        let mut provider_auth_evidence = if should_resolve_provider {
            let evidence = match self.resolve_provider_binding(host, provider_intent)? {
                ProviderBindingResolution::Ready(binding) => match binding.auth_source() {
                    Some(source) => (
                        provider_auth::diagnose_provider_secret(Some(source), None, false),
                        satelle_core::ProviderAuthObservationSource::Deferred,
                    ),
                    None => (
                        satelle_core::ProviderAuthValidationOutcome::Resolved,
                        satelle_core::ProviderAuthObservationSource::Cached,
                    ),
                },
                ProviderBindingResolution::MissingDescriptor { .. } => (
                    satelle_core::ProviderAuthValidationOutcome::MissingDescriptor,
                    satelle_core::ProviderAuthObservationSource::Deferred,
                ),
            };
            Some(evidence)
        } else {
            None
        };
        let transport_observation =
            execute_test_controller_transport_probe(&*transport_probe, options)?;
        let mut report = self.fake_doctor(
            host,
            scope_selection,
            &transport_observation,
            options,
            &FakeComputerUseAdapter,
        )?;
        if options.refresh() && (includes_native_scope || should_resolve_provider) {
            if scope_selection.scopes() == [DoctorScope::Provider] {
                report.changed = false;
                report.cache_updates.clear();
            }
            let provider_refresh_allowed = provider_auth_evidence.is_some_and(|outcome| {
                !matches!(
                    outcome.0,
                    satelle_core::ProviderAuthValidationOutcome::MissingDescriptor
                        | satelle_core::ProviderAuthValidationOutcome::UnsupportedDescriptorKind
                )
            });
            let provider_probe_required =
                should_resolve_provider && provider_intent.provider_probe_required();
            let should_run_native_phase =
                includes_native_scope || (provider_refresh_allowed && provider_probe_required);
            let native_only_intent = ProviderComputerUseIntent::host_default();
            let native_intent = if scope_selection.scopes() == [DoctorScope::ComputerUse] {
                &native_only_intent
            } else {
                provider_intent
            };
            let mut native_evidence = None;
            if should_run_native_phase {
                let started_at = utc_now();
                let started = Instant::now();
                let native_refresh = self
                    .runtime
                    .refresh_setup_native_readiness(host, native_intent);
                apply_native_refresh(
                    &mut report,
                    &native_refresh,
                    started_at,
                    started.elapsed(),
                    includes_native_scope,
                );
                native_evidence = native_refresh.ok();
            }
            if should_resolve_provider && provider_refresh_allowed {
                let deferred_outcome =
                    provider_auth_evidence.expect("provider scopes always diagnose provider auth");
                if provider_probe_required {
                    if let Some(native_evidence) = native_evidence {
                        let started_at = utc_now();
                        let started = Instant::now();
                        let cancellation = AdmissionCancellation::new();
                        let provider_refresh = self
                            .runtime
                            .refresh_setup_provider_readiness_with_cancellation(
                                host,
                                provider_intent,
                                native_evidence,
                                &cancellation,
                            );
                        let observed = match &provider_refresh {
                            Ok(readiness) if readiness.provider_smoke_evidence().is_some() => (
                                satelle_core::ProviderAuthValidationOutcome::Resolved,
                                satelle_core::ProviderAuthObservationSource::Live,
                            ),
                            Ok(_) => deferred_outcome,
                            Err(error) => provider_validation_outcome_for_error(error)
                                .map(|outcome| {
                                    (outcome, satelle_core::ProviderAuthObservationSource::Live)
                                })
                                .unwrap_or(deferred_outcome),
                        };
                        apply_provider_refresh(
                            &mut report,
                            &provider_refresh,
                            started_at,
                            started.elapsed(),
                        );
                        provider_auth_evidence = Some(observed);
                    }
                } else {
                    apply_provider_not_required(&mut report);
                }
            } else if matches!(
                provider_auth_evidence,
                Some((
                    satelle_core::ProviderAuthValidationOutcome::MissingDescriptor
                        | satelle_core::ProviderAuthValidationOutcome::UnsupportedDescriptorKind,
                    _
                ))
            ) {
                recompute_doctor_summary(&mut report);
            }
        }
        if let Some((outcome, source)) = provider_auth_evidence {
            for finding in &mut report.findings {
                if finding.scope == "provider" {
                    finding
                        .evidence
                        .push(format!("provider_auth_outcome={}", outcome.as_str()));
                    finding.evidence.push(format!(
                        "provider_auth_observation_source={}",
                        source.as_str()
                    ));
                }
            }
        }
        Ok(report)
    }

    /// Runs the canonical live setup readiness path through Doctor so setup,
    /// admission, and diagnostics share lease, cache, timeout, and recovery
    /// semantics.
    pub fn verify_setup(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        let raw_scopes =
            if provider_intent.model().is_some() || provider_intent.provider().is_some() {
                Vec::new()
            } else {
                vec!["computer-use".to_string()]
            };
        let scope_selection = DoctorScopeSelection::parse(&raw_scopes)
            .expect("setup verification uses supported Doctor scopes");
        let mut report = self.doctor_with_provider_intent(
            host,
            &scope_selection,
            Arc::new(ReadyControllerTransportProbe),
            DoctorOptions::new(true, None).expect("default timeout is valid"),
            provider_intent,
        )?;
        if report.changed
            && !report
                .cache_updates
                .iter()
                .any(|entry| matches!(entry.as_str(), "local-demo-readiness" | "native_readiness"))
        {
            report.cache_updates.push("native_readiness".to_string());
        }
        Ok(report)
    }

    /// Invalidates the current Host identity's native readiness evidence while
    /// leaving provider smoke evidence untouched.
    pub fn invalidate_native_readiness(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<u64, SatelleError> {
        self.runtime
            .invalidate_native_readiness(host, provider_intent)
    }

    /// Reports cached provider-auth evidence without resolving a secret, or
    /// delegates an explicit live refresh to the normal provider-smoke path.
    pub fn resolve_provider_binding(
        &self,
        host: &str,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<ProviderBindingResolution, SatelleError> {
        self.runtime.resolve_provider_binding(host, provider_intent)
    }

    pub fn authorize_provider_binding(
        &self,
        host: &str,
        model_alias: &str,
        provider_alias: &str,
        authorization: ProviderBindingAuthorization,
    ) -> Result<ResolvedProviderBinding, SatelleError> {
        let binding = self.prepare_provider_binding_authorization(
            host,
            model_alias,
            provider_alias,
            authorization,
        )?;
        let previous_digest = self
            .runtime
            .provider_binding_digest(model_alias, provider_alias)?;
        let missing_file_destination = matches!(
            binding.auth_source(),
            Some(satelle_core::ProviderSecretSource::File { path })
                if matches!(
                    satelle_core::owner_only_secret_destination_exists(path),
                    Ok(false)
                )
        );
        if !missing_file_destination {
            self.validate_provider_binding_candidate(host, &binding)?;
        }
        self.runtime
            .authorize_provider_binding_if_unchanged(&binding, previous_digest.as_deref())?;
        Ok(binding)
    }

    pub fn preview_provider_secret_provisioning(
        &self,
        host: &str,
        authorization: ProviderBindingAuthorization,
        // Preview remains on the mutation-authorized route so provisioning
        // cannot bypass the authority checked at the transport boundary.
        _authority: &MutationAuthority,
    ) -> Result<ProviderSecretProvisioningPreview, SatelleError> {
        let model_alias = authorization.requested_model_alias().to_string();
        let provider_alias = authorization.requested_provider_alias().to_string();
        let binding = self.prepare_provider_binding_authorization(
            host,
            &model_alias,
            &provider_alias,
            authorization,
        )?;
        if !matches!(
            binding.auth_source(),
            Some(satelle_core::ProviderSecretSource::File { .. })
        ) {
            return Err(provider_secret_source_error());
        }
        Ok(ProviderSecretProvisioningPreview::file())
    }

    fn provision_provider_secret(
        &self,
        host: &str,
        authorization: ProviderBindingAuthorization,
        secret: Zeroizing<String>,
        overwrite_authorized: bool,
        identity: &RequestIdentity,
    ) -> Result<ProviderSecretProvisioningResult, SatelleError> {
        // Exact-idempotency replay and retained recovery ownership must be
        // classified before native readiness can attempt a competing lease.
        if let Some(result) = self.runtime.provider_secret_provisioning_replay(identity)? {
            return Ok(result);
        }
        let model_alias = authorization.requested_model_alias().to_string();
        let provider_alias = authorization.requested_provider_alias().to_string();
        let binding = self.prepare_provider_binding_authorization(
            host,
            &model_alias,
            &provider_alias,
            authorization,
        )?;
        let destination = match binding.auth_source() {
            Some(satelle_core::ProviderSecretSource::File { path }) => path.clone(),
            _ => return Err(provider_secret_source_error()),
        };
        let intent = Self::provider_candidate_intent(&binding)?;
        // Native readiness owns its own durable probe lease. Complete that
        // phase before T0 so staged provider validation can reuse the exact
        // evidence without competing with the provider-secret lease.
        let native_readiness = self.runtime.refresh_setup_native_readiness(host, &intent)?;
        let provider_probe_ref = format!("provider-probe-{}", SessionId::new());
        let (host_identity, key, owner) =
            self.runtime
                .provider_secret_provisioning_ownership(host, &intent, identity.key())?;
        let paths = storage::provider_secret_file_paths(&destination, identity.key())
            .map_err(|_| provider_secret_file_error())?;
        let candidate_secret = provider_auth::ResolvedProviderSecret::from_provisioning(secret);
        let candidate_comparison = provider_secret_comparison(
            &self.runtime,
            storage::PROVIDER_SECRET_CANDIDATE_HMAC_DOMAIN,
            &candidate_secret,
        )?;
        let plan = storage::ProviderSecretProvisioningPlan::new(
            host_identity,
            key.desktop_binding().clone(),
            &provider_probe_ref,
            binding.clone(),
            destination.clone(),
            paths.staging().to_path_buf(),
            candidate_comparison.digest_hex.clone(),
        )
        .map_err(|_| SatelleError::state_conflict())?;
        let journal = match self
            .runtime
            .begin_provider_secret_provisioning(identity, &key, &owner, plan)?
        {
            storage::BeginProviderSecretProvisioning::Claimed(journal) => *journal,
            storage::BeginProviderSecretProvisioning::Resume => {
                return Err(SatelleError::state_conflict());
            }
            storage::BeginProviderSecretProvisioning::Replay(
                storage::ProviderSecretProvisioningReplay::Completed(result),
            ) => return Ok(result),
            storage::BeginProviderSecretProvisioning::Replay(
                storage::ProviderSecretProvisioningReplay::Failed(error),
            ) => return Err(error),
        };
        let operation_id = journal.operation_id().to_string();
        let mut lifecycle = ProviderSecretPostT0Guard::new(
            &self.runtime,
            operation_id,
            paths,
            candidate_comparison,
        );
        let workflow =
            (|| -> Result<ProviderSecretProvisioningResult, ProviderSecretPostT0Failure> {
                let owned_probe = self
                    .runtime
                    .start_owned_provider_probe(&provider_probe_ref, &owner)?;

                // The preview was advisory. T0 ownership precedes this
                // authoritative no-follow inspection so a
                // preview-to-confirmation race cannot decide overwrite behavior.
                let destination_existed =
                    satelle_core::owner_only_secret_destination_exists(&destination)
                        .map_err(|_| provider_secret_file_error())?;
                if destination_existed && !overwrite_authorized {
                    return Err(ProviderSecretPostT0Failure::Ordinary(
                        provider_secret_overwrite_error(),
                    ));
                }
                let prior_comparison = if destination_existed {
                    let prior = satelle_core::read_owner_only_secret_file(&destination)
                        .map(provider_auth::ResolvedProviderSecret::from_provisioning)
                        .map_err(|_| provider_secret_file_error())?;
                    Some(provider_secret_file_comparison(
                        &self.runtime,
                        storage::PROVIDER_SECRET_PRIOR_HMAC_DOMAIN,
                        &prior,
                        &destination,
                    )?)
                } else {
                    None
                };
                lifecycle.record_destination(destination_existed, prior_comparison);
                candidate_secret
                    .expose_to_provider(|value| {
                        satelle_core::stage_owner_only_secret_file(
                            &lifecycle.paths,
                            value,
                            lifecycle.candidate.key.as_bytes(),
                            &lifecycle.candidate.digest,
                        )
                    })
                    .map_err(|_| provider_secret_file_error())?;
                self.runtime
                    .record_staged_provider_secret(
                        &lifecycle.operation_id,
                        destination_existed,
                        destination_existed.then_some(lifecycle.paths.backup()),
                        lifecycle
                            .prior
                            .as_ref()
                            .map(|comparison| comparison.digest_hex.as_str()),
                    )
                    .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                lifecycle.mark_staged();

                let pending = match self.runtime.validate_staged_provider_secret(
                    host,
                    &intent,
                    native_readiness,
                    candidate_secret,
                    owned_probe,
                ) {
                    Ok(pending) => pending,
                    Err(runtime::ProviderSecretValidationFailure::RecoveryRequired(error)) => {
                        self.runtime
                            .mark_provider_secret_provisioning_rollback_pending(
                                &lifecycle.operation_id,
                                storage::ProviderSecretProvisioningPhase::Staged,
                            )
                            .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                        return Err(ProviderSecretPostT0Failure::UnknownProviderOutcome(error));
                    }
                    Err(runtime::ProviderSecretValidationFailure::Terminal(error)) => {
                        return Err(ProviderSecretPostT0Failure::Ordinary(error));
                    }
                };
                lifecycle.set_pending(pending);
                self.runtime
                    .transition_provider_secret_provisioning(
                        &lifecycle.operation_id,
                        storage::ProviderSecretProvisioningPhase::Staged,
                        storage::ProviderSecretProvisioningPhase::Validated,
                    )
                    .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                lifecycle.mark_validated();
                self.runtime
                    .transition_provider_secret_provisioning(
                        &lifecycle.operation_id,
                        storage::ProviderSecretProvisioningPhase::Validated,
                        storage::ProviderSecretProvisioningPhase::PublishIntent,
                    )
                    .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                lifecycle.mark_publish_intent();
                let overwritten = match satelle_core::publish_owner_only_secret_file(
                    &lifecycle.paths,
                    destination_existed,
                    overwrite_authorized,
                    lifecycle.candidate.key.as_bytes(),
                    &lifecycle.candidate.digest,
                    lifecycle
                        .prior
                        .as_ref()
                        .map(|comparison| comparison.key.as_bytes()),
                    lifecycle
                        .prior
                        .as_ref()
                        .map(|comparison| &comparison.digest),
                ) {
                    Ok(overwritten) => overwritten,
                    Err(satelle_core::SecureFileError::OverwriteRequired) => {
                        lifecycle.preserve_raced_destination();
                        return Err(ProviderSecretPostT0Failure::Ordinary(
                            provider_secret_overwrite_error(),
                        ));
                    }
                    Err(_) => {
                        return Err(ProviderSecretPostT0Failure::Ordinary(
                            provider_secret_file_error(),
                        ));
                    }
                };
                lifecycle.record_published(overwritten);

                // Re-open both durable artifacts through the owner-only reader
                // immediately before T3. The journal stores only keyed
                // comparisons, so neither this check nor recovery needs a raw
                // reusable hash.
                let published_digest =
                    satelle_core::keyed_owner_only_secret_file_comparison_digest(
                        &destination,
                        lifecycle.candidate.key.as_bytes(),
                    )
                    .map_err(|_| provider_secret_file_error())?;
                if published_digest != lifecycle.candidate.digest {
                    return Err(ProviderSecretPostT0Failure::Ordinary(
                        SatelleError::state_conflict(),
                    ));
                }
                if overwritten {
                    let backup =
                        satelle_core::read_owner_only_secret_file(lifecycle.paths.backup())
                            .map(provider_auth::ResolvedProviderSecret::from_provisioning)
                            .map_err(|_| provider_secret_file_error())?;
                    let backup_comparison = provider_secret_file_comparison(
                        &self.runtime,
                        storage::PROVIDER_SECRET_PRIOR_HMAC_DOMAIN,
                        &backup,
                        lifecycle.paths.backup(),
                    )?;
                    if lifecycle
                        .prior
                        .as_ref()
                        .map(|prior| prior.digest_hex.as_str())
                        != Some(backup_comparison.digest_hex.as_str())
                    {
                        return Err(ProviderSecretPostT0Failure::Ordinary(
                            SatelleError::state_conflict(),
                        ));
                    }
                }

                let readiness = lifecycle.readiness()?;
                self.runtime
                    .commit_provider_secret_provisioning(
                        &lifecycle.operation_id,
                        &binding,
                        &key,
                        readiness.evidence(),
                        readiness.provider_smoke_evidence(),
                    )
                    .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                lifecycle.mark_committed();
                lifecycle
                    .cleanup_staging()
                    .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                let result = self
                    .runtime
                    .finish_provider_secret_provisioning_success(&lifecycle.operation_id)
                    .map_err(ProviderSecretPostT0Failure::RecoveryRequired)?;
                Ok(result)
            })();

        match workflow {
            Ok(result) => {
                lifecycle.finish_success();
                Ok(result)
            }
            Err(ProviderSecretPostT0Failure::Ordinary(error)) => {
                Err(lifecycle.terminalize_failure(error))
            }
            Err(
                ProviderSecretPostT0Failure::RecoveryRequired(error)
                | ProviderSecretPostT0Failure::UnknownProviderOutcome(error),
            ) => {
                lifecycle.retain_for_recovery();
                Err(error)
            }
        }
    }

    pub(crate) fn prepare_provider_binding_authorization(
        &self,
        host: &str,
        model_alias: &str,
        provider_alias: &str,
        authorization: ProviderBindingAuthorization,
    ) -> Result<ResolvedProviderBinding, SatelleError> {
        if authorization.requested_model_alias() != model_alias
            || authorization.requested_provider_alias() != provider_alias
        {
            return Err(SatelleError::config_error(
                "provider binding aliases do not match the authorization resource path",
                None,
            ));
        }
        validate_provider_binding_authorization(&authorization)?;
        let binding = ResolvedProviderBinding::from_authorization(
            authorization,
            ProviderBindingSource::UserConfig,
        );
        let _ = host;
        Ok(binding)
    }

    fn provider_candidate_intent(
        binding: &ResolvedProviderBinding,
    ) -> Result<ProviderComputerUseIntent, SatelleError> {
        Ok(ProviderComputerUseIntent::new(
            Some(
                satelle_core::session::EffectiveModelRef::new(binding.requested_model_alias())
                    .map_err(|_| SatelleError::config_error("the model alias is invalid", None))?,
            ),
            Some(
                satelle_core::session::ProviderBindingRef::new(binding.requested_provider_alias())
                    .map_err(|_| {
                        SatelleError::config_error("the provider alias is invalid", None)
                    })?,
            ),
            true,
        )
        .with_resolved_provider_binding(binding.clone())
        .with_experimental_provider_computer_use(binding.experimental_provider_computer_use()))
    }

    pub fn delete_provider_binding(
        &self,
        model_alias: &str,
        provider_alias: &str,
    ) -> Result<bool, SatelleError> {
        satelle_core::session::EffectiveModelRef::new(model_alias)
            .map_err(|_| SatelleError::config_error("the model alias is invalid", None))?;
        satelle_core::session::ProviderBindingRef::new(provider_alias)
            .map_err(|_| SatelleError::config_error("the provider alias is invalid", None))?;
        self.runtime
            .delete_provider_binding(model_alias, provider_alias)
    }

    pub fn validate_provider_descriptor(
        &self,
        host: &str,
        model_alias: &str,
        provider_alias: &str,
        options: ProviderDescriptorValidationOptions,
    ) -> Result<ProviderDescriptorValidation, SatelleError> {
        use satelle_core::{
            ProviderAuthObservationSource, ProviderAuthValidationMode,
            ProviderAuthValidationOutcome, ProviderAuthValidationResult,
        };
        let mode = options.mode();

        let intent =
            if model_alias == DEFAULT_MODEL_BINDING && provider_alias == DEFAULT_PROVIDER_BINDING {
                ProviderComputerUseIntent::new(
                    None,
                    None,
                    matches!(mode, ProviderAuthValidationMode::RefreshProviderSmoke),
                )
            } else {
                ProviderComputerUseIntent::new(
                    Some(
                        satelle_core::session::EffectiveModelRef::new(model_alias).map_err(
                            |_| SatelleError::config_error("the model alias is invalid", None),
                        )?,
                    ),
                    Some(
                        satelle_core::session::ProviderBindingRef::new(provider_alias).map_err(
                            |_| SatelleError::config_error("the provider alias is invalid", None),
                        )?,
                    ),
                    matches!(mode, ProviderAuthValidationMode::RefreshProviderSmoke),
                )
            }
            .with_project_selection_provenance(
                options.model_from_project(),
                options.provider_from_project(),
            )
            .with_experimental_provider_computer_use(options.experimental_provider_computer_use());
        let (resolved_binding, deferred_outcome, deferred_source) =
            match self.resolve_provider_binding(host, &intent)? {
                ProviderBindingResolution::Ready(binding) => {
                    let (outcome, source) = match binding.auth_source() {
                        Some(satelle_core::ProviderSecretSource::File { path })
                            if matches!(mode, ProviderAuthValidationMode::Cached)
                                && !matches!(
                                    satelle_core::owner_only_secret_destination_exists(path),
                                    Ok(true)
                                ) =>
                        {
                            // Cached validation may inspect destination metadata, but it
                            // must not read secret bytes or contact the provider.
                            (
                                ProviderAuthValidationOutcome::UnresolvedHostSecret,
                                ProviderAuthObservationSource::Live,
                            )
                        }
                        Some(source) => (
                            provider_auth::diagnose_provider_secret(Some(source), None, false),
                            ProviderAuthObservationSource::Deferred,
                        ),
                        None => (
                            ProviderAuthValidationOutcome::Resolved,
                            ProviderAuthObservationSource::Cached,
                        ),
                    };
                    (binding, outcome, source)
                }
                ProviderBindingResolution::MissingDescriptor { binding, .. } => (
                    binding,
                    ProviderAuthValidationOutcome::MissingDescriptor,
                    ProviderAuthObservationSource::Deferred,
                ),
            };
        let requires_live_refresh =
            matches!(mode, ProviderAuthValidationMode::RefreshProviderSmoke)
                && deferred_outcome == ProviderAuthValidationOutcome::Resolved
                && resolved_binding.auth_source().is_none();
        if deferred_outcome != ProviderAuthValidationOutcome::ConfiguredDeferred
            && !requires_live_refresh
        {
            return Ok(ProviderDescriptorValidation::new(
                resolved_binding,
                ProviderAuthValidationResult::new(deferred_outcome, deferred_source),
            ));
        }

        let validation = match mode {
            // A read-only check cannot associate historical provider-smoke
            // evidence with the current env/file credential without resolving
            // that secret. Keep the descriptor deferred until a live provider
            // boundary can compare the keyed credential identity.
            ProviderAuthValidationMode::Cached => ProviderAuthValidationResult::new(
                ProviderAuthValidationOutcome::ConfiguredDeferred,
                ProviderAuthObservationSource::Deferred,
            ),
            ProviderAuthValidationMode::RefreshProviderSmoke => {
                let result = self.runtime.refresh_provider_smoke(host, &intent);
                match result {
                    Ok(readiness) => {
                        if readiness.resolved_provider_binding() != Some(&resolved_binding) {
                            return Err(crate::runtime::integrity_error(
                                "provider readiness binding diverged from Host resolution",
                            ));
                        }
                        ProviderAuthValidationResult::new(
                            ProviderAuthValidationOutcome::Resolved,
                            ProviderAuthObservationSource::Live,
                        )
                    }
                    Err(error) => {
                        let Some(outcome) = provider_validation_outcome_for_error(&error) else {
                            return Err(error);
                        };
                        ProviderAuthValidationResult::new(
                            outcome,
                            ProviderAuthObservationSource::Live,
                        )
                    }
                }
            }
        };
        Ok(ProviderDescriptorValidation::new(
            resolved_binding,
            validation,
        ))
    }

    fn validate_provider_binding_candidate(
        &self,
        host: &str,
        binding: &ResolvedProviderBinding,
    ) -> Result<(), SatelleError> {
        let intent = Self::provider_candidate_intent(binding)?;
        let readiness = self.runtime.refresh_provider_smoke(host, &intent)?;
        if readiness.resolved_provider_binding() != Some(binding) {
            return Err(crate::runtime::integrity_error(
                "provider readiness binding diverged from the authorization candidate",
            ));
        }
        Ok(())
    }

    pub fn setup(
        &self,
        host: &str,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        match &self.mode {
            HostMode::Production { .. } => {
                if !dry_run {
                    return Err(SatelleError::not_implemented(format!(
                        "{setup_mode} setup mutations are not supported by the local Host transport"
                    )));
                }
                Ok(production_setup_report(
                    host,
                    dry_run,
                    setup_mode,
                    setup_components,
                    daemon_path_overrides,
                ))
            }
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { .. } => self.setup_fake(
                host,
                dry_run,
                setup_mode,
                setup_components,
                daemon_path_overrides,
            ),
        }
    }

    pub fn host_status(&self) -> Result<HostStatus, SatelleError> {
        match &self.mode {
            HostMode::Production { .. } => Ok(HostStatus {
                running: false,
                mode: "production-capability-blocked".to_string(),
                sessions: 0,
            }),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { .. } => {
                let snapshot = self.runtime.reconcile_and_snapshot()?;
                Ok(HostStatus {
                    running: true,
                    mode: "local-demo-in-process".to_string(),
                    sessions: snapshot.session_count(),
                })
            }
        }
    }

    fn ensure_image_attachments_supported(&self, intent: &TurnIntent) -> Result<(), SatelleError> {
        if intent.attachments().is_empty() {
            return Ok(());
        }
        let supported = match &self.mode {
            HostMode::Production { snapshot } => {
                read_production_snapshot(snapshot)?.image_attachments_supported()
            }
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { image_attachments } => *image_attachments,
        };
        if supported {
            Ok(())
        } else {
            Err(SatelleError::invalid_usage(
                "the selected Codex protocol does not support image input",
            ))
        }
    }

    fn run_command<'a>(&self, command: RunCommand<'a>, intent: &TurnIntent) -> RunCommand<'a> {
        command
            .with_execution_mode(intent.execution_mode())
            .with_provider_intent(intent.provider_intent().clone())
            .with_turn_execution_timeout(Some(self.effective_turn_execution_timeout(intent)))
            .with_attachments(intent.attachments().to_vec())
    }

    fn steer_command<'a>(
        &self,
        command: SteerCommand<'a>,
        intent: &TurnIntent,
    ) -> SteerCommand<'a> {
        command
            .with_execution_mode(intent.execution_mode())
            .with_provider_intent(intent.provider_intent().clone())
            .with_turn_execution_timeout(Some(self.effective_turn_execution_timeout(intent)))
            .with_attachments(intent.attachments().to_vec())
    }

    pub fn run(
        &self,
        host: &str,
        intent: &TurnIntent,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        self.ensure_image_attachments_supported(intent)
            .map_err(TurnAdmissionFailure::not_admitted)?;
        self.runtime
            .run(self.run_command(RunCommand::attached(host, intent.prompt()), intent))
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn run_with_cancellation(
        &self,
        host: &str,
        intent: &TurnIntent,
        cancellation: AdmissionCancellation,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        self.ensure_image_attachments_supported(intent)
            .map_err(TurnAdmissionFailure::not_admitted)?;
        self.runtime
            .run(
                self.run_command(RunCommand::attached(host, intent.prompt()), intent)
                    .with_cancellation(cancellation),
            )
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn run_detached(
        &self,
        host: &str,
        intent: &TurnIntent,
    ) -> Result<PublicSession, SatelleError> {
        self.ensure_image_attachments_supported(intent)?;
        crate::runtime::admitted_session(
            self.runtime
                .run(self.run_command(RunCommand::detached(host, intent.prompt()), intent)),
        )
    }

    pub fn run_detached_with_cancellation(
        &self,
        host: &str,
        intent: &TurnIntent,
        cancellation: AdmissionCancellation,
    ) -> Result<PublicSession, SatelleError> {
        self.ensure_image_attachments_supported(intent)?;
        crate::runtime::admitted_session(
            self.runtime.run(
                self.run_command(RunCommand::detached(host, intent.prompt()), intent)
                    .with_cancellation(cancellation),
            ),
        )
    }

    pub fn steer(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        self.ensure_image_attachments_supported(intent)
            .map_err(TurnAdmissionFailure::not_admitted)?;
        self.runtime
            .steer(self.steer_command(
                SteerCommand::attached(session_id.clone(), intent.prompt()),
                intent,
            ))
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn steer_with_cancellation(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        cancellation: AdmissionCancellation,
    ) -> Result<TurnOutcome, TurnAdmissionFailure> {
        self.ensure_image_attachments_supported(intent)
            .map_err(TurnAdmissionFailure::not_admitted)?;
        self.runtime
            .steer(
                self.steer_command(
                    SteerCommand::attached(session_id.clone(), intent.prompt()),
                    intent,
                )
                .with_cancellation(cancellation),
            )
            .map(crate::runtime::RuntimeTurnOutcome::into_command_outcome)
    }

    pub fn steer_detached(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
    ) -> Result<PublicSession, SatelleError> {
        self.ensure_image_attachments_supported(intent)?;
        crate::runtime::admitted_session(self.runtime.steer(self.steer_command(
            SteerCommand::detached(session_id.clone(), intent.prompt()),
            intent,
        )))
    }

    pub fn steer_detached_with_cancellation(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        cancellation: AdmissionCancellation,
    ) -> Result<PublicSession, SatelleError> {
        self.ensure_image_attachments_supported(intent)?;
        crate::runtime::admitted_session(
            self.runtime.steer(
                self.steer_command(
                    SteerCommand::detached(session_id.clone(), intent.prompt()),
                    intent,
                )
                .with_cancellation(cancellation),
            ),
        )
    }

    pub fn status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.runtime.status(session_id.clone())
    }

    pub fn stop(&self, session_id: &SessionId) -> Result<StopResult, SatelleError> {
        self.runtime.stop(StopCommand::new(session_id.clone()))
    }

    pub fn stop_expected_turn(
        &self,
        session_id: &SessionId,
        expected_turn_id: &TurnId,
    ) -> Result<StopResult, SatelleError> {
        self.runtime.stop(StopCommand::for_turn(
            session_id.clone(),
            expected_turn_id.clone(),
        ))
    }

    pub fn host_sessions(
        &self,
        host: &str,
        no_bootstrap: bool,
    ) -> Result<HostSessionsReport, SatelleError> {
        let sessions = self.daemon_desktop_sessions()?;
        let platform = match &self.mode {
            HostMode::Production { .. } => {
                crate::codex_capabilities::HostPlatform::current().as_str()
            }
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { .. } => "local-demo",
        };
        let bootstrap_actions = if no_bootstrap {
            Vec::new()
        } else {
            vec![format!("direct {host} Host daemon already reachable")]
        };
        Ok(HostSessionsReport {
            schema_version: HostSessionsSchemaVersion::V1,
            host: host.to_string(),
            detected_platform: platform.to_string(),
            connection_mode: "direct".to_string(),
            bootstrapped: false,
            bootstrap_actions,
            host_daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            sessions,
        })
    }
}

#[derive(Clone)]
pub enum ControllerTransportProbeOutcome {
    Observed(DoctorTransportObservation),
    TimedOut(DoctorTransportObservation),
}

impl ControllerTransportProbeOutcome {
    fn observation(&self) -> &DoctorTransportObservation {
        match self {
            Self::Observed(observation) | Self::TimedOut(observation) => observation,
        }
    }

    fn completion(&self) -> DoctorProbeCompletion {
        match self {
            Self::Observed(observation) => probe_completion(!observation.is_ready()),
            Self::TimedOut(_) => DoctorProbeCompletion::new(
                DoctorProbeStatus::TimedOut,
                DoctorDependentEvidence::NotUseful,
            ),
        }
    }
}

pub trait ControllerTransportProbe: Send + Sync {
    fn execute(
        &self,
        context: &satelle_core::doctor::DoctorProbeExecutionContext,
    ) -> ControllerTransportProbeOutcome;
}

struct ReadyControllerTransportProbe;

impl ControllerTransportProbe for ReadyControllerTransportProbe {
    fn execute(
        &self,
        _context: &satelle_core::doctor::DoctorProbeExecutionContext,
    ) -> ControllerTransportProbeOutcome {
        ControllerTransportProbeOutcome::Observed(DoctorTransportObservation::ready(None))
    }
}

fn doctor_cleanup_reserve(timeout: Duration) -> Duration {
    (timeout / 4).min(Duration::from_secs(1))
}

#[cfg(any(test, feature = "test-support"))]
fn execute_test_controller_transport_probe(
    probe: &dyn ControllerTransportProbe,
    options: DoctorOptions,
) -> Result<DoctorTransportObservation, SatelleError> {
    // Test-fake Hosts do not own production task resources. They still use the
    // canonical deadline context so controller probe fakes exercise the same
    // cancellation input as production probes.
    let lifecycle = DoctorProbeLifecycle::start(
        DoctorScope::Transport.as_str(),
        Instant::now(),
        options.effective_probe_timeout(),
        Duration::ZERO,
    )
    .map_err(|error| runtime::integrity_error(error.to_string()))?;
    Ok(probe.execute(&lifecycle.context()).observation().clone())
}

enum ProductionDoctorTaskEffect {
    None,
    Snapshot(Result<ProductionCapabilitySnapshot, SatelleError>),
    NativeRefresh {
        refresh: Result<ReadinessEvidence, SatelleError>,
        started_at: String,
        duration: Duration,
    },
    ProviderAuth {
        evidence: Option<(
            satelle_core::ProviderAuthValidationOutcome,
            satelle_core::ProviderAuthObservationSource,
        )>,
        error: Option<SatelleError>,
    },
    ProviderRefresh {
        refresh: Box<Result<AdapterReadiness, SatelleError>>,
        started_at: String,
        duration: Duration,
        observed_auth: Option<(
            satelle_core::ProviderAuthValidationOutcome,
            satelle_core::ProviderAuthObservationSource,
        )>,
    },
    ProviderNotRequired,
    Transport {
        outcome: ControllerTransportProbeOutcome,
        started_at: String,
        finished_at: String,
        duration: Duration,
    },
}

struct ProductionDoctorTaskResult {
    completion: DoctorProbeCompletion,
    effect: ProductionDoctorTaskEffect,
}

enum DoctorWorkerTerminal {
    Completed {
        completed_at: Instant,
        result: Box<ProductionDoctorTaskResult>,
    },
    Panicked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DoctorRegistryTaskPhase {
    Running,
    CleanupOnly,
}

struct DoctorRegistryTask {
    request_id: u64,
    probe_id: String,
    resource_locks: BTreeSet<DoctorProbeResource>,
    lifecycle: DoctorProbeLifecycle,
    phase: DoctorRegistryTaskPhase,
    terminal: Option<DoctorWorkerTerminal>,
    worker: Option<std::thread::JoinHandle<()>>,
}

enum DoctorRegistryEvent {
    Completed {
        probe_id: String,
        completion: DoctorProbeCompletion,
        effect: Box<ProductionDoctorTaskEffect>,
    },
    TimedOut {
        probe_id: String,
    },
    Panicked {
        probe_id: String,
    },
}

struct DoctorTaskRegistryState {
    next_request_id: u64,
    next_task_id: u64,
    tasks: BTreeMap<u64, DoctorRegistryTask>,
    events: BTreeMap<u64, VecDeque<DoctorRegistryEvent>>,
}

struct DoctorTaskRegistryInner {
    scheduling: Mutex<()>,
    state: Mutex<DoctorTaskRegistryState>,
    changed: Condvar,
}

#[derive(Clone)]
struct DoctorTaskRegistry {
    inner: Arc<DoctorTaskRegistryInner>,
}

impl std::fmt::Debug for DoctorTaskRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DoctorTaskRegistry")
    }
}

impl DoctorTaskRegistry {
    fn new() -> Self {
        Self {
            inner: Arc::new(DoctorTaskRegistryInner {
                scheduling: Mutex::new(()),
                state: Mutex::new(DoctorTaskRegistryState {
                    next_request_id: 1,
                    next_task_id: 1,
                    tasks: BTreeMap::new(),
                    events: BTreeMap::new(),
                }),
                changed: Condvar::new(),
            }),
        }
    }

    fn lock_scheduling(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner
            .scheduling
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin_request(&self) -> u64 {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let request_id = state.next_request_id;
        state.next_request_id = state.next_request_id.saturating_add(1);
        request_id
    }

    fn spawn(
        &self,
        request_id: u64,
        probe: &DoctorProbe,
        operation: impl FnOnce(
            satelle_core::doctor::DoctorProbeExecutionContext,
        ) -> ProductionDoctorTaskResult
        + Send
        + 'static,
    ) -> Result<(), SatelleError> {
        let lifecycle = DoctorProbeLifecycle::start(
            probe.probe_id.clone(),
            Instant::now(),
            probe.timeout,
            doctor_cleanup_reserve(probe.timeout),
        )
        .map_err(|error| runtime::integrity_error(error.to_string()))?;
        let context = lifecycle.context();
        // Keep registry ownership across thread creation so a fast worker cannot
        // publish completion and be reaped before its join handle is installed.
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let task_id = state.next_task_id;
        state.next_task_id = state.next_task_id.saturating_add(1);
        state.tasks.insert(
            task_id,
            DoctorRegistryTask {
                request_id,
                probe_id: probe.probe_id.clone(),
                resource_locks: probe.resource_locks.clone(),
                lifecycle,
                phase: DoctorRegistryTaskPhase::Running,
                terminal: None,
                worker: None,
            },
        );

        let weak = Arc::downgrade(&self.inner);
        let worker = match std::thread::Builder::new()
            .name(format!("doctor-{}", probe.probe_id))
            .spawn(move || {
                let terminal = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    operation(context)
                })) {
                    Ok(result) => DoctorWorkerTerminal::Completed {
                        completed_at: Instant::now(),
                        result: Box::new(result),
                    },
                    Err(_) => DoctorWorkerTerminal::Panicked,
                };
                let Some(inner) = Weak::upgrade(&weak) else {
                    return;
                };
                let mut state = inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(task) = state.tasks.get_mut(&task_id) {
                    task.terminal = Some(terminal);
                }
                inner.changed.notify_all();
            }) {
            Ok(worker) => worker,
            Err(error) => {
                state.tasks.remove(&task_id);
                return Err(runtime::integrity_error(error.to_string()));
            }
        };

        state
            .tasks
            .get_mut(&task_id)
            .expect("new Doctor registry task remains owned")
            .worker = Some(worker);
        Ok(())
    }

    fn advance(&self, now: Instant) {
        let mut joins = Vec::new();
        let mut queued = Vec::new();
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let task_ids = state.tasks.keys().copied().collect::<Vec<_>>();
            for task_id in task_ids {
                let mut remove = false;
                let mut event = None;
                {
                    let task = state
                        .tasks
                        .get_mut(&task_id)
                        .expect("listed Doctor registry task exists");
                    if let Some(terminal) = task.terminal.take() {
                        let request_id = task.request_id;
                        let probe_id = task.probe_id.clone();
                        if let Some(worker) = task.worker.take() {
                            joins.push(worker);
                        }
                        if task.phase == DoctorRegistryTaskPhase::CleanupOnly {
                            remove = true;
                        } else {
                            match terminal {
                                DoctorWorkerTerminal::Completed {
                                    completed_at,
                                    result,
                                } => {
                                    let ProductionDoctorTaskResult {
                                        completion: result_completion,
                                        effect,
                                    } = *result;
                                    let lifecycle_event = task
                                        .lifecycle
                                        .poll(completed_at, Some((completed_at, result_completion)))
                                        .expect("terminal acknowledgment cannot miss cleanup");
                                    let DoctorProbeLifecycleEvent::TerminalAck(completion) =
                                        lifecycle_event
                                    else {
                                        unreachable!("worker completion is a terminal ack")
                                    };
                                    event = Some((
                                        request_id,
                                        if completion.status == DoctorProbeStatus::TimedOut {
                                            DoctorRegistryEvent::TimedOut { probe_id }
                                        } else {
                                            DoctorRegistryEvent::Completed {
                                                probe_id,
                                                completion,
                                                effect: Box::new(effect),
                                            }
                                        },
                                    ));
                                }
                                DoctorWorkerTerminal::Panicked => {
                                    event = Some((
                                        request_id,
                                        DoctorRegistryEvent::Panicked { probe_id },
                                    ));
                                }
                            }
                            remove = true;
                        }
                    } else if task.phase == DoctorRegistryTaskPhase::Running {
                        match task.lifecycle.poll(now, None) {
                            Ok(DoctorProbeLifecycleEvent::BeginCancellation)
                            | Ok(DoctorProbeLifecycleEvent::Running) => {}
                            Ok(DoctorProbeLifecycleEvent::TerminalAck(_)) => {
                                unreachable!("no terminal ack was supplied")
                            }
                            Err(
                                satelle_core::doctor::DoctorProbeExecutionError::CleanupDeadlineMissed {
                                    ..
                                },
                            ) => {
                                task.phase = DoctorRegistryTaskPhase::CleanupOnly;
                                event = Some((
                                    task.request_id,
                                    DoctorRegistryEvent::TimedOut {
                                        probe_id: task.probe_id.clone(),
                                    },
                                ));
                            }
                            Err(
                                satelle_core::doctor::DoctorProbeExecutionError::DeadlineOverflow {
                                    ..
                                },
                            ) => unreachable!("deadline overflow is rejected at task start"),
                            Err(
                                satelle_core::doctor::DoctorProbeExecutionError::AlreadyTerminal {
                                    ..
                                },
                            ) => unreachable!("terminal tasks are removed in the acknowledgment pass"),
                        }
                    }
                }
                if remove {
                    state.tasks.remove(&task_id);
                }
                if let Some(event) = event {
                    queued.push(event);
                }
            }
            for (request_id, event) in queued.drain(..) {
                state.events.entry(request_id).or_default().push_back(event);
            }
        }
        for worker in joins {
            worker
                .join()
                .expect("a terminal Doctor worker joins after publishing its slot");
        }
    }

    fn external_occupancy(&self, request_id: u64) -> (usize, BTreeSet<DoctorProbeResource>) {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tasks = state.tasks.values().filter(|task| {
            task.request_id != request_id || task.phase == DoctorRegistryTaskPhase::CleanupOnly
        });
        let mut capacity = 0;
        let mut resources = BTreeSet::new();
        for task in tasks {
            capacity += 1;
            resources.extend(task.resource_locks.iter().copied());
        }
        (capacity, resources)
    }

    fn drain_events(&self, request_id: u64) -> Vec<DoctorRegistryEvent> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .remove(&request_id)
            .map(VecDeque::into_iter)
            .into_iter()
            .flatten()
            .collect()
    }

    fn wait_until(&self, deadline: Instant) {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let wait = deadline.saturating_duration_since(Instant::now());
        if !wait.is_zero() {
            drop(
                self.inner
                    .changed
                    .wait_timeout(state, wait)
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }
    }

    fn next_transition(&self) -> Option<Instant> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tasks
            .values()
            .filter(|task| task.phase == DoctorRegistryTaskPhase::Running)
            .map(|task| {
                if task.lifecycle.context().is_cancelled() {
                    task.lifecycle.deadline()
                } else {
                    task.lifecycle.cancel_at()
                }
            })
            .min()
    }
}

impl Drop for DoctorTaskRegistryInner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in state.tasks.values_mut() {
            task.lifecycle.request_cancellation();
        }
        // Dropping a JoinHandle detaches the worker. Shutdown must not turn a
        // bounded Doctor timeout back into an unbounded wait when an external
        // operation ignores cancellation.
    }
}

struct ProductionDoctorExecution {
    snapshot: Option<ProductionCapabilitySnapshot>,
    fatal_error: Option<SatelleError>,
    native_refresh: Option<(
        Result<ReadinessEvidence, SatelleError>,
        String,
        std::time::Duration,
    )>,
    provider_refresh: Option<(
        Result<AdapterReadiness, SatelleError>,
        String,
        std::time::Duration,
    )>,
    provider_auth_evidence: Option<(
        satelle_core::ProviderAuthValidationOutcome,
        satelle_core::ProviderAuthObservationSource,
    )>,
    provider_not_required: bool,
    transport: Option<(
        ControllerTransportProbeOutcome,
        String,
        String,
        std::time::Duration,
    )>,
}

impl ProductionDoctorExecution {
    fn new() -> Self {
        Self {
            snapshot: None,
            fatal_error: None,
            native_refresh: None,
            provider_refresh: None,
            provider_auth_evidence: None,
            provider_not_required: false,
            transport: None,
        }
    }
}

fn apply_production_doctor_effect(
    execution: &mut ProductionDoctorExecution,
    effect: ProductionDoctorTaskEffect,
) {
    match effect {
        ProductionDoctorTaskEffect::None => {}
        ProductionDoctorTaskEffect::Snapshot(Ok(snapshot)) => {
            execution.snapshot = Some(snapshot);
        }
        ProductionDoctorTaskEffect::Snapshot(Err(error)) => {
            execution.fatal_error = Some(error);
        }
        ProductionDoctorTaskEffect::NativeRefresh {
            refresh,
            started_at,
            duration,
        } => {
            execution.native_refresh = Some((refresh, started_at, duration));
        }
        ProductionDoctorTaskEffect::ProviderAuth { evidence, error } => {
            if let Some(evidence) = evidence {
                execution.provider_auth_evidence = Some(evidence);
            }
            if let Some(error) = error {
                execution.fatal_error = Some(error);
            }
        }
        ProductionDoctorTaskEffect::ProviderRefresh {
            refresh,
            started_at,
            duration,
            observed_auth,
        } => {
            if let Some(observed_auth) = observed_auth {
                execution.provider_auth_evidence = Some(observed_auth);
            }
            execution.provider_refresh = Some((*refresh, started_at, duration));
        }
        ProductionDoctorTaskEffect::ProviderNotRequired => {
            execution.provider_not_required = true;
        }
        ProductionDoctorTaskEffect::Transport {
            outcome,
            started_at,
            finished_at,
            duration,
        } => {
            execution.transport = Some((outcome, started_at, finished_at, duration));
        }
    }
}

fn production_doctor_with_provider_intent(
    service: &HostService,
    host: &str,
    scope_selection: &DoctorScopeSelection,
    transport_probe: Arc<dyn ControllerTransportProbe>,
    options: DoctorOptions,
    provider_intent: &ProviderComputerUseIntent,
    snapshot_slot: &Arc<RwLock<ProductionCapabilitySnapshot>>,
) -> Result<DoctorReport, SatelleError> {
    let includes_native_scope = scope_selection.contains(DoctorScope::ComputerUse);
    let includes_provider_scope = scope_selection.contains(DoctorScope::Provider);
    let has_provider_selection =
        provider_intent.model().is_some() || provider_intent.provider().is_some();
    let should_resolve_provider = includes_provider_scope && has_provider_selection;
    let provider_probe_required =
        should_resolve_provider && provider_intent.provider_probe_required();

    // Phase 0 is an atomic capability observation. Keep it as one real probe,
    // and add hidden prerequisite scopes only when a selected probe consumes
    // their evidence.
    let execution_scopes = DoctorScope::ALL
        .into_iter()
        .filter(|scope| {
            scope_selection.contains(*scope)
                || *scope == DoctorScope::Codex
                || (provider_probe_required && *scope == DoctorScope::ComputerUse)
        })
        .collect::<Vec<_>>();
    let mut probes = production_doctor_probes(&execution_scopes, options.probe_timeout());
    if should_resolve_provider {
        probes.push(DoctorProbe {
            probe_id: "provider-auth".to_string(),
            scope: DoctorScope::Provider.as_str().to_string(),
            dependencies: Vec::new(),
            resource_locks: Default::default(),
            timeout: options.effective_probe_timeout(),
            cache_policy: DoctorProbeCachePolicy::Reuse,
        });
        let provider = probes
            .iter_mut()
            .find(|probe| probe.probe_id == DoctorScope::Provider.as_str())
            .expect("a selected provider scope has a provider probe");
        provider.dependencies.push("provider-auth".to_string());
    }

    let mut execution = ProductionDoctorExecution::new();
    let mut scheduler = production_doctor_scheduler(probes, options)?;
    let registry = &service.doctor_tasks;
    let request_id = registry.begin_request();
    let mut records = Vec::new();
    let mut admission_deadlines = BTreeMap::new();

    while !scheduler.is_complete() {
        let now = Instant::now();
        registry.advance(now);
        let mut progressed = false;

        for event in registry.drain_events(request_id) {
            progressed = true;
            match event {
                DoctorRegistryEvent::Completed {
                    probe_id,
                    completion,
                    effect,
                } => {
                    let status = completion.status;
                    apply_production_doctor_effect(&mut execution, *effect);
                    scheduler
                        .finish(&probe_id, completion)
                        .expect("registry completion belongs to a running probe");
                    records.push(DoctorProbeExecutionRecord { probe_id, status });
                }
                DoctorRegistryEvent::TimedOut { probe_id } => {
                    let completion = DoctorProbeCompletion::new(
                        DoctorProbeStatus::TimedOut,
                        DoctorDependentEvidence::NotUseful,
                    );
                    scheduler
                        .finish(&probe_id, completion)
                        .expect("registry timeout belongs to a running probe");
                    records.push(DoctorProbeExecutionRecord {
                        probe_id,
                        status: DoctorProbeStatus::TimedOut,
                    });
                }
                DoctorRegistryEvent::Panicked { probe_id } => {
                    return Err(runtime::integrity_error(format!(
                        "Doctor probe {probe_id} panicked inside the owned task registry"
                    )));
                }
            }
        }

        if scheduler.is_complete() {
            break;
        }

        // Occupancy inspection and registration form one admission decision
        // across concurrent Doctor calls for this Host service.
        let scheduling = registry.lock_scheduling();
        let (external_capacity, external_resources) = registry.external_occupancy(request_id);
        let ready_without_external = scheduler.clone().start_ready();
        let ready =
            scheduler.start_ready_with_external_occupancy(external_capacity, &external_resources);
        let admitted = ready
            .iter()
            .map(|probe| probe.probe_id.clone())
            .collect::<BTreeSet<_>>();
        let externally_blocked = ready_without_external
            .iter()
            .filter(|probe| !admitted.contains(&probe.probe_id))
            .map(|probe| probe.probe_id.clone())
            .collect::<BTreeSet<_>>();
        admission_deadlines.retain(|probe_id, _| externally_blocked.contains(probe_id));
        for probe in ready_without_external
            .iter()
            .filter(|probe| externally_blocked.contains(&probe.probe_id))
        {
            let deadline = now.checked_add(probe.timeout).ok_or_else(|| {
                runtime::integrity_error(format!(
                    "Doctor probe {} admission timeout cannot form an absolute deadline",
                    probe.probe_id
                ))
            })?;
            admission_deadlines
                .entry(probe.probe_id.clone())
                .or_insert(deadline);
        }
        for probe in ready {
            progressed = true;
            match probe.probe_id.as_str() {
                "codex" => {
                    let snapshot_slot = Arc::clone(snapshot_slot);
                    registry.spawn(request_id, &probe, move |context| {
                        let snapshot = if options.refresh() {
                            let remaining = context.remaining();
                            if remaining.is_zero() {
                                Err(runtime::integrity_error(
                                    "Phase 0 started without useful-work budget",
                                ))
                            } else {
                                Ok(ProductionCapabilitySnapshot::collect(Some(remaining)))
                            }
                        } else {
                            read_production_snapshot(&snapshot_slot)
                                .map(|snapshot| snapshot.clone())
                        };
                        let completion = match &snapshot {
                            Ok(snapshot) => phase0_snapshot_completion(snapshot),
                            Err(error) => error_probe_completion(error),
                        };
                        ProductionDoctorTaskResult {
                            completion,
                            effect: ProductionDoctorTaskEffect::Snapshot(snapshot),
                        }
                    })?;
                }
                "computer-use" if options.refresh() => {
                    let runtime = service.runtime.clone();
                    let host = host.to_string();
                    let native_only_intent = ProviderComputerUseIntent::host_default();
                    let native_intent = native_probe_intent(
                        provider_probe_required,
                        provider_intent,
                        &native_only_intent,
                    )
                    .clone();
                    registry.spawn(request_id, &probe, move |context| {
                        let started_at = utc_now();
                        let started = Instant::now();
                        let refresh = with_doctor_probe_cancellation(&context, |cancellation| {
                            runtime.refresh_setup_native_readiness_with_cancellation(
                                &host,
                                &native_intent,
                                cancellation,
                            )
                        });
                        ProductionDoctorTaskResult {
                            completion: result_probe_completion(&refresh),
                            effect: ProductionDoctorTaskEffect::NativeRefresh {
                                refresh,
                                started_at,
                                duration: started.elapsed(),
                            },
                        }
                    })?;
                }
                "computer-use" => {
                    let blocked = execution.snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot
                            .verdict
                            .blockers()
                            .iter()
                            .any(|blocker| blocker_scope(blocker) == "computer-use")
                    });
                    registry.spawn(request_id, &probe, move |_context| {
                        ProductionDoctorTaskResult {
                            completion: probe_completion(blocked),
                            effect: ProductionDoctorTaskEffect::None,
                        }
                    })?;
                }
                "provider-auth" => {
                    let runtime = service.runtime.clone();
                    let host = host.to_string();
                    let provider_intent = provider_intent.clone();
                    registry.spawn(request_id, &probe, move |_context| {
                        let resolution =
                            runtime.resolve_provider_binding(&host, &provider_intent);
                        let (completion, evidence, error) = match resolution {
                            Ok(ProviderBindingResolution::Ready(binding)) => {
                                let evidence = match binding.auth_source() {
                                    Some(source) => (
                                        provider_auth::diagnose_provider_secret(
                                            Some(source),
                                            None,
                                            false,
                                        ),
                                        satelle_core::ProviderAuthObservationSource::Deferred,
                                    ),
                                    None => (
                                        satelle_core::ProviderAuthValidationOutcome::Resolved,
                                        satelle_core::ProviderAuthObservationSource::Cached,
                                    ),
                                };
                                let blocked = matches!(
                                    evidence.0,
                                    satelle_core::ProviderAuthValidationOutcome::MissingDescriptor
                                        | satelle_core::ProviderAuthValidationOutcome::UnsupportedDescriptorKind
                                );
                                (probe_completion(blocked), Some(evidence), None)
                            }
                            Ok(ProviderBindingResolution::MissingDescriptor { .. }) => (
                                probe_completion(true),
                                Some((
                                    satelle_core::ProviderAuthValidationOutcome::MissingDescriptor,
                                    satelle_core::ProviderAuthObservationSource::Deferred,
                                )),
                                None,
                            ),
                            Err(error) => (
                                error_probe_completion(&error),
                                None,
                                Some(error),
                            ),
                        };
                        ProductionDoctorTaskResult {
                            completion,
                            effect: ProductionDoctorTaskEffect::ProviderAuth {
                                evidence,
                                error,
                            },
                        }
                    })?;
                }
                "provider" => {
                    let provider_refresh_allowed =
                        execution.provider_auth_evidence.is_some_and(|outcome| {
                            !matches!(
                                outcome.0,
                                satelle_core::ProviderAuthValidationOutcome::MissingDescriptor
                                    | satelle_core::ProviderAuthValidationOutcome::UnsupportedDescriptorKind
                            )
                        });
                    if !should_resolve_provider || !options.refresh() {
                        registry.spawn(request_id, &probe, move |_context| {
                            ProductionDoctorTaskResult {
                                completion: probe_completion(true),
                                effect: ProductionDoctorTaskEffect::None,
                            }
                        })?;
                    } else if !provider_refresh_allowed {
                        registry.spawn(request_id, &probe, move |_context| {
                            ProductionDoctorTaskResult {
                                completion: probe_completion(true),
                                effect: ProductionDoctorTaskEffect::None,
                            }
                        })?;
                    } else if !provider_probe_required {
                        registry.spawn(request_id, &probe, move |_context| {
                            ProductionDoctorTaskResult {
                                completion: probe_completion(false),
                                effect: ProductionDoctorTaskEffect::ProviderNotRequired,
                            }
                        })?;
                    } else {
                        let native_evidence = execution
                            .native_refresh
                            .as_ref()
                            .and_then(|(refresh, _, _)| refresh.as_ref().ok())
                            .cloned();
                        let Some(native_evidence) = native_evidence else {
                            registry.spawn(request_id, &probe, move |_context| {
                                ProductionDoctorTaskResult {
                                    completion: DoctorProbeCompletion::new(
                                        DoctorProbeStatus::Failed,
                                        DoctorDependentEvidence::NotUseful,
                                    ),
                                    effect: ProductionDoctorTaskEffect::None,
                                }
                            })?;
                            continue;
                        };
                        let runtime = service.runtime.clone();
                        let host = host.to_string();
                        let provider_intent = provider_intent.clone();
                        registry.spawn(request_id, &probe, move |context| {
                            let started_at = utc_now();
                            let started = Instant::now();
                            let refresh =
                                with_doctor_probe_cancellation(&context, |cancellation| {
                                    runtime.refresh_setup_provider_readiness_with_cancellation(
                                        &host,
                                        &provider_intent,
                                        native_evidence,
                                        cancellation,
                                    )
                                });
                            let observed_auth = match &refresh {
                                Ok(readiness) if readiness.provider_smoke_evidence().is_some() => {
                                    Some((
                                        satelle_core::ProviderAuthValidationOutcome::Resolved,
                                        satelle_core::ProviderAuthObservationSource::Live,
                                    ))
                                }
                                Err(error) => {
                                    provider_validation_outcome_for_error(error).map(|outcome| {
                                        (outcome, satelle_core::ProviderAuthObservationSource::Live)
                                    })
                                }
                                Ok(_) => None,
                            };
                            ProductionDoctorTaskResult {
                                completion: result_probe_completion(&refresh),
                                effect: ProductionDoctorTaskEffect::ProviderRefresh {
                                    refresh: Box::new(refresh),
                                    started_at,
                                    duration: started.elapsed(),
                                    observed_auth,
                                },
                            }
                        })?;
                    }
                }
                "transport" => {
                    let transport_probe = Arc::clone(&transport_probe);
                    registry.spawn(request_id, &probe, move |context| {
                        let started_at = utc_now();
                        let started = Instant::now();
                        let outcome = transport_probe.execute(&context);
                        let finished_at = utc_now();
                        let duration = started.elapsed();
                        ProductionDoctorTaskResult {
                            completion: outcome.completion(),
                            effect: ProductionDoctorTaskEffect::Transport {
                                outcome,
                                started_at,
                                finished_at,
                                duration,
                            },
                        }
                    })?;
                }
                "config" => {
                    registry.spawn(request_id, &probe, move |_context| {
                        ProductionDoctorTaskResult {
                            completion: probe_completion(false),
                            effect: ProductionDoctorTaskEffect::None,
                        }
                    })?;
                }
                unknown => panic!("unknown production Doctor probe {unknown}"),
            }
        }
        drop(scheduling);

        if let Some(probe_id) = admission_deadlines
            .iter()
            .find_map(|(probe_id, deadline)| (Instant::now() >= *deadline).then_some(probe_id))
        {
            let mut error = SatelleError::state_conflict();
            error.message = format!(
                "Doctor probe {probe_id} could not start before its admission wait deadline because another Doctor task still owns its capacity or resource lock"
            );
            error.recovery_command = Some(
                "retry satelle doctor after the prior Doctor task releases its resources".into(),
            );
            error.details.insert(
                "probe_id".to_string(),
                serde_json::Value::String(probe_id.clone()),
            );
            return Err(error);
        }

        if !progressed {
            let next = registry
                .next_transition()
                .into_iter()
                .chain(admission_deadlines.values().copied())
                .min()
                .unwrap_or_else(|| Instant::now() + Duration::from_millis(10));
            registry.wait_until(next);
        }
    }

    if let Some(error) = execution.fatal_error {
        // Every independent probe has reached a reportable terminal state.
        // A timed-out operation may still be retained for cleanup.
        return Err(error);
    }
    let (snapshot, snapshot_was_refreshed) =
        production_snapshot_after_execution(&mut execution, &records, snapshot_slot)?;
    let default_transport_observation = DoctorTransportObservation::ready(None);
    let transport_observation = execution
        .transport
        .as_ref()
        .map(|(outcome, _, _, _)| outcome.observation())
        .unwrap_or(&default_transport_observation);
    let mut report = production_doctor_report_with_selection(
        host,
        scope_selection,
        transport_observation,
        options,
        &snapshot,
    );

    if let Some((refresh, started_at, duration)) = execution.native_refresh {
        apply_native_refresh(
            &mut report,
            &refresh,
            started_at,
            duration,
            includes_native_scope,
        );
    }
    if let Some((refresh, started_at, duration)) = execution.provider_refresh {
        apply_provider_refresh(&mut report, &refresh, started_at, duration);
    } else if execution.provider_not_required {
        apply_provider_not_required(&mut report);
    } else if matches!(
        execution.provider_auth_evidence,
        Some((
            satelle_core::ProviderAuthValidationOutcome::MissingDescriptor
                | satelle_core::ProviderAuthValidationOutcome::UnsupportedDescriptorKind,
            _
        ))
    ) {
        recompute_doctor_summary(&mut report);
    }
    if let Some((outcome, started_at, finished_at, duration)) = &execution.transport
        && let Some(result) = report
            .probe_results
            .iter_mut()
            .find(|result| result.scope == DoctorScope::Transport.as_str())
    {
        result.started_at = started_at.clone();
        result.finished_at = finished_at.clone();
        result.duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);
        result.status = match outcome {
            ControllerTransportProbeOutcome::Observed(observation) if observation.is_ready() => {
                "passed"
            }
            ControllerTransportProbeOutcome::Observed(_) => "blocked",
            ControllerTransportProbeOutcome::TimedOut(_) => "timed_out",
        }
        .to_string();
    }
    if let Some((outcome, source)) = execution.provider_auth_evidence {
        for finding in &mut report.findings {
            if finding.scope == "provider" {
                finding
                    .evidence
                    .push(format!("provider_auth_outcome={}", outcome.as_str()));
                finding.evidence.push(format!(
                    "provider_auth_observation_source={}",
                    source.as_str()
                ));
            }
        }
    }
    // Refresh applicators and the Phase 0 report own scope-aware Finding and
    // Passed projections. The scheduler's aggregate Phase 0 completion cannot
    // safely relabel those rows, but terminal failures, timeouts, and skipped
    // dependencies still override them.
    apply_production_execution_status(&mut report, &scheduler, &records, &snapshot.finished_at);
    report.probe_schedule_events =
        public_probe_schedule_events(&report, scheduler.schedule_events());
    if options.refresh() && snapshot_was_refreshed {
        replace_production_snapshot(snapshot_slot, snapshot)?;
    }
    Ok(report)
}

fn public_probe_schedule_events(
    report: &DoctorReport,
    scheduler_events: &[DoctorProbeScheduleEvent],
) -> Box<[DoctorProbeScheduleEvent]> {
    scheduler_events
        .iter()
        .filter_map(|event| {
            let public_probe_id = report
                .probe_results
                .iter()
                .find(|probe| {
                    probe.scope == event.probe_id() || probe.probe_id == event.probe_id()
                })?
                .probe_id
                .clone();
            Some(match event {
                DoctorProbeScheduleEvent::Started { .. } => DoctorProbeScheduleEvent::Started {
                    probe_id: public_probe_id,
                },
                DoctorProbeScheduleEvent::Finished { .. } => DoctorProbeScheduleEvent::Finished {
                    probe_id: public_probe_id,
                },
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn production_snapshot_after_execution(
    execution: &mut ProductionDoctorExecution,
    records: &[DoctorProbeExecutionRecord],
    snapshot_slot: &RwLock<ProductionCapabilitySnapshot>,
) -> Result<(ProductionCapabilitySnapshot, bool), SatelleError> {
    if let Some(snapshot) = execution.snapshot.take() {
        return Ok((snapshot, true));
    }
    if records.iter().any(|record| {
        record.probe_id == DoctorScope::Codex.as_str()
            && record.status == DoctorProbeStatus::TimedOut
    }) {
        return read_production_snapshot(snapshot_slot).map(|snapshot| (snapshot.clone(), false));
    }
    Err(crate::runtime::integrity_error(
        "the production capability probe completed without a snapshot or typed timeout",
    ))
}

fn probe_completion(blocked: bool) -> DoctorProbeCompletion {
    if blocked {
        DoctorProbeCompletion::new(
            DoctorProbeStatus::Finding,
            DoctorDependentEvidence::NotUseful,
        )
    } else {
        DoctorProbeCompletion::new(DoctorProbeStatus::Passed, DoctorDependentEvidence::Useful)
    }
}

fn phase0_probe_completion(blockers: &[Phase0CapabilityBlocker]) -> DoctorProbeCompletion {
    let status = if blockers.is_empty() {
        DoctorProbeStatus::Passed
    } else {
        DoctorProbeStatus::Finding
    };
    let dependent_evidence = if blockers
        .iter()
        .any(|blocker| blocker_scope(blocker) == DoctorScope::Codex.as_str())
    {
        DoctorDependentEvidence::NotUseful
    } else {
        DoctorDependentEvidence::Useful
    };
    DoctorProbeCompletion::new(status, dependent_evidence)
}

fn phase0_snapshot_completion(snapshot: &ProductionCapabilitySnapshot) -> DoctorProbeCompletion {
    if snapshot.budget_failure.is_some() {
        DoctorProbeCompletion::new(
            DoctorProbeStatus::TimedOut,
            DoctorDependentEvidence::NotUseful,
        )
    } else {
        phase0_probe_completion(snapshot.verdict.blockers())
    }
}

fn with_doctor_probe_cancellation<T>(
    context: &DoctorProbeExecutionContext,
    operation: impl FnOnce(&AdmissionCancellation) -> T,
) -> T {
    let cancellation = AdmissionCancellation::with_deadline(context.deadline());
    let operation_finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let cancellation_ref = &cancellation;
        let operation_finished_ref = &operation_finished;
        scope.spawn(move || {
            while !operation_finished_ref.load(Ordering::Acquire) {
                if context.is_cancelled() {
                    cancellation_ref.request();
                    return;
                }
                let sleep = context.remaining().min(Duration::from_millis(1));
                if sleep.is_zero() {
                    std::thread::yield_now();
                } else {
                    std::thread::sleep(sleep);
                }
            }
        });
        let result = operation(&cancellation);
        operation_finished.store(true, Ordering::Release);
        result
    })
}

fn production_doctor_scheduler(
    probes: Vec<DoctorProbe>,
    options: DoctorOptions,
) -> Result<DoctorProbeScheduler, SatelleError> {
    let scheduler = if options.serial_probes() {
        DoctorProbeScheduler::serial(probes)
    } else {
        DoctorProbeScheduler::new(probes)
    };
    scheduler.map_err(|error| SatelleError::invalid_usage(error.to_string()))
}

fn native_probe_intent<'a>(
    provider_probe_required: bool,
    provider_intent: &'a ProviderComputerUseIntent,
    native_only_intent: &'a ProviderComputerUseIntent,
) -> &'a ProviderComputerUseIntent {
    if provider_probe_required {
        provider_intent
    } else {
        native_only_intent
    }
}

fn error_probe_completion(error: &SatelleError) -> DoctorProbeCompletion {
    let status = if error.code.as_str().contains("timeout") {
        DoctorProbeStatus::TimedOut
    } else {
        DoctorProbeStatus::Failed
    };
    DoctorProbeCompletion::new(status, DoctorDependentEvidence::NotUseful)
}

fn result_probe_completion<T>(result: &Result<T, SatelleError>) -> DoctorProbeCompletion {
    result.as_ref().map_or_else(error_probe_completion, |_| {
        DoctorProbeCompletion::new(DoctorProbeStatus::Passed, DoctorDependentEvidence::Useful)
    })
}

fn apply_production_execution_status(
    report: &mut DoctorReport,
    scheduler: &DoctorProbeScheduler,
    records: &[DoctorProbeExecutionRecord],
    fallback_finished_at: &str,
) {
    for result in &mut report.probe_results {
        if matches!(
            scheduler.state(&result.scope),
            Some(DoctorProbeState::SkippedDependency { .. })
        ) {
            result.status = "blocked".to_string();
            result.dependency_status = "blocked".to_string();
            result.started_at = fallback_finished_at.to_string();
            result.finished_at = fallback_finished_at.to_string();
            result.duration_ms = 0;
            continue;
        }
        let Some(record) = records
            .iter()
            .find(|record| record.probe_id == result.scope)
        else {
            continue;
        };
        match record.status {
            DoctorProbeStatus::Passed | DoctorProbeStatus::Finding => {}
            DoctorProbeStatus::Failed => result.status = "blocked".to_string(),
            DoctorProbeStatus::TimedOut => result.status = "timed_out".to_string(),
        }
    }
    recompute_doctor_summary(report);
}

fn duration_to_time(duration: &satelle_core::ExplicitDuration) -> time::Duration {
    time::Duration::milliseconds(i64::try_from(duration.milliseconds()).unwrap_or(i64::MAX))
}

/// Returns the native and provider probe deadlines resolved from Host config.
pub fn readiness_probe_timeouts(config: &HostConfig) -> (std::time::Duration, std::time::Duration) {
    let native = config
        .timeouts
        .as_ref()
        .and_then(|timeouts| timeouts.native_readiness.as_ref())
        .map_or(DEFAULT_NATIVE_READINESS_TIMEOUT, |duration| {
            std::time::Duration::from_millis(duration.milliseconds())
        });
    let provider = config
        .timeouts
        .as_ref()
        .and_then(|timeouts| timeouts.provider_smoke_test.as_ref())
        .map_or(DEFAULT_PROVIDER_SMOKE_TEST_TIMEOUT, |duration| {
            std::time::Duration::from_millis(duration.milliseconds())
        });
    (native, provider)
}

/// Returns the deadline a remote admission request needs in order to receive
/// typed outcomes from both serial readiness probes, timeout cancellation,
/// and response overhead.
pub fn admission_request_timeout(config: &HostConfig) -> std::time::Duration {
    let (native, provider) = readiness_probe_timeouts(config);
    native
        .saturating_add(provider)
        .saturating_add(READINESS_CANCELLATION_GRACE)
        .saturating_add(ADMISSION_RESPONSE_GRACE)
}

fn apply_provider_refresh(
    report: &mut DoctorReport,
    refresh: &Result<AdapterReadiness, SatelleError>,
    started_at: String,
    duration: std::time::Duration,
) {
    report
        .findings
        .retain(|finding| finding.scope != "provider");
    report
        .probe_results
        .retain(|probe| probe.scope != "provider");
    let (finding, status, cache_status, changed) = match refresh {
        Ok(readiness) => match readiness.provider_smoke_evidence() {
            Some(evidence) => (
                DoctorFinding {
                    finding_id: "provider.smoke.refresh.passed".to_string(),
                    scope: "provider".to_string(),
                    severity: "info".to_string(),
                    fixability: DoctorFixability::Informational,
                    readiness_impact: "ready".to_string(),
                    summary: "provider Computer Use smoke refresh passed".to_string(),
                    evidence: vec![
                        format!("source={}", evidence.source().as_str()),
                        format!(
                            "observed_at={}",
                            evidence
                                .observed_at()
                                .format(&Rfc3339)
                                .expect("provider evidence timestamp is RFC 3339 representable")
                        ),
                        format!(
                            "expires_at={}",
                            evidence
                                .expires_at()
                                .format(&Rfc3339)
                                .expect("provider evidence expiry is RFC 3339 representable")
                        ),
                    ],
                    recovery_command: None,
                },
                "passed",
                "refreshed",
                true,
            ),
            None => (
                DoctorFinding {
                    finding_id: "provider.smoke.refresh.not_required".to_string(),
                    scope: "provider".to_string(),
                    severity: "info".to_string(),
                    fixability: DoctorFixability::Informational,
                    readiness_impact: "ready".to_string(),
                    summary: "the selected provider does not require an experimental smoke test"
                        .to_string(),
                    evidence: vec!["source=not_required".to_string()],
                    recovery_command: None,
                },
                "passed",
                "not_required",
                false,
            ),
        },
        Err(error) => {
            let mut evidence = vec![format!("code={}", error.code.as_str())];
            for key in [
                "provider_smoke_source",
                "provider_smoke_status",
                "provider_smoke_observed_at",
                "provider_smoke_expires_at",
                "provider_smoke_age_ms",
            ] {
                if let Some(value) = error.details.get(key) {
                    evidence.push(format!("{key}={}", json_scalar(value)));
                }
            }
            let changed = error.details.contains_key("provider_smoke_expires_at");
            (
                DoctorFinding {
                    finding_id: "provider.smoke.refresh.failed".to_string(),
                    scope: "provider".to_string(),
                    severity: "error".to_string(),
                    fixability: DoctorFixability::Blocked,
                    readiness_impact: "blocked".to_string(),
                    summary: error.message.clone(),
                    evidence,
                    recovery_command: error.recovery_command.clone(),
                },
                "blocked",
                if changed {
                    "refreshed_failed"
                } else {
                    "not_updated"
                },
                changed,
            )
        }
    };
    let finding_id = finding.finding_id.clone();
    let finished_at = utc_now();
    report.findings.push(finding);
    report.probe_results.push(DoctorProbeResult {
        probe_id: "provider.smoke.refresh".to_string(),
        scope: "provider".to_string(),
        status: status.to_string(),
        started_at,
        finished_at,
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        cache_status: cache_status.to_string(),
        dependency_status: "satisfied".to_string(),
        finding_ids: vec![finding_id],
    });
    report.findings.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.finding_id.cmp(&right.finding_id))
    });
    report.probe_results.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.probe_id.cmp(&right.probe_id))
    });
    report.changed |= changed;
    if changed
        && !report
            .cache_updates
            .iter()
            .any(|entry| entry == "provider_smoke")
    {
        report.cache_updates.push("provider_smoke".to_string());
    }
    recompute_doctor_summary(report);
}

fn apply_native_refresh(
    report: &mut DoctorReport,
    refresh: &Result<ReadinessEvidence, SatelleError>,
    started_at: String,
    duration: std::time::Duration,
    project_public_result: bool,
) {
    let changed = native_refresh_changed(refresh);
    report.changed |= changed;
    if changed
        && !report
            .cache_updates
            .iter()
            .any(|entry| matches!(entry.as_str(), "local-demo-readiness" | "native_readiness"))
    {
        report.cache_updates.push("native_readiness".to_string());
    }
    if !project_public_result {
        return;
    }

    report
        .findings
        .retain(|finding| finding.scope != "computer-use");
    report
        .probe_results
        .retain(|probe| probe.scope != "computer-use");
    let (finding, status, cache_status) = match refresh {
        Ok(readiness) => (
            DoctorFinding {
                finding_id: "computer-use.native.refresh.passed".to_string(),
                scope: "computer-use".to_string(),
                severity: "info".to_string(),
                fixability: DoctorFixability::Informational,
                readiness_impact: "ready".to_string(),
                summary: "native Computer Use readiness passed".to_string(),
                evidence: vec![
                    format!("source={}", readiness.source().as_str()),
                    format!(
                        "observed_at={}",
                        readiness
                            .observed_at()
                            .format(&Rfc3339)
                            .expect("native evidence timestamp is RFC 3339 representable")
                    ),
                    format!(
                        "expires_at={}",
                        readiness
                            .expires_at()
                            .format(&Rfc3339)
                            .expect("native evidence expiry is RFC 3339 representable")
                    ),
                ],
                recovery_command: None,
            },
            "passed",
            "refreshed",
        ),
        Err(error) => {
            let manual_action_required = error
                .details
                .get("native_readiness")
                .and_then(Value::as_object)
                .and_then(|details| details.get("status"))
                .and_then(Value::as_str)
                == Some("manual_action_required")
                || error.details.get("status").and_then(Value::as_str)
                    == Some("manual_action_required");
            let mut evidence = vec![format!("code={}", error.code.as_str())];
            if let Some(details) = error
                .details
                .get("native_readiness")
                .and_then(Value::as_object)
            {
                for key in ["status", "reason", "observed_at", "expires_at"] {
                    if let Some(value) = details.get(key) {
                        evidence.push(format!("{key}={}", json_scalar(value)));
                    }
                }
            }
            (
                DoctorFinding {
                    finding_id: "computer-use.native.refresh.failed".to_string(),
                    scope: "computer-use".to_string(),
                    severity: "error".to_string(),
                    fixability: if manual_action_required {
                        DoctorFixability::ManualActionRequired
                    } else {
                        DoctorFixability::Blocked
                    },
                    readiness_impact: "blocked".to_string(),
                    summary: error.message.clone(),
                    evidence,
                    recovery_command: error.recovery_command.clone(),
                },
                "blocked",
                if changed {
                    "refreshed_failed"
                } else {
                    "not_updated"
                },
            )
        }
    };
    let finding_id = finding.finding_id.clone();
    report.findings.push(finding);
    report.probe_results.push(DoctorProbeResult {
        probe_id: "computer-use.native.refresh".to_string(),
        scope: "computer-use".to_string(),
        status: status.to_string(),
        started_at,
        finished_at: utc_now(),
        duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
        cache_status: cache_status.to_string(),
        dependency_status: "satisfied".to_string(),
        finding_ids: vec![finding_id],
    });
    report.findings.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.finding_id.cmp(&right.finding_id))
    });
    report.probe_results.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.probe_id.cmp(&right.probe_id))
    });
    recompute_doctor_summary(report);
}

fn native_refresh_changed(refresh: &Result<ReadinessEvidence, SatelleError>) -> bool {
    match refresh {
        Ok(_) => true,
        Err(error) => {
            error.details.contains_key("native_readiness")
                || matches!(
                    error.code.as_str(),
                    "computer-use-not-ready" | "native-readiness-timeout"
                )
        }
    }
}

fn apply_provider_not_required(report: &mut DoctorReport) {
    report
        .findings
        .retain(|finding| finding.scope != "provider");
    report
        .probe_results
        .retain(|probe| probe.scope != "provider");
    let finding_id = "provider.smoke.refresh.not_required".to_string();
    report.findings.push(DoctorFinding {
        finding_id: finding_id.clone(),
        scope: "provider".to_string(),
        severity: "info".to_string(),
        fixability: DoctorFixability::Informational,
        readiness_impact: "ready".to_string(),
        summary: "the selected provider does not require an experimental smoke test".to_string(),
        evidence: vec!["source=not_required".to_string()],
        recovery_command: None,
    });
    let observed_at = utc_now();
    report.probe_results.push(DoctorProbeResult {
        probe_id: "provider.smoke.refresh".to_string(),
        scope: "provider".to_string(),
        status: "passed".to_string(),
        started_at: observed_at.clone(),
        finished_at: observed_at,
        duration_ms: 0,
        cache_status: "not_required".to_string(),
        dependency_status: "satisfied".to_string(),
        finding_ids: vec![finding_id],
    });
    report.findings.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.finding_id.cmp(&right.finding_id))
    });
    report.probe_results.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.probe_id.cmp(&right.probe_id))
    });
    recompute_doctor_summary(report);
}

fn json_scalar(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string)
}

fn recompute_doctor_summary(report: &mut DoctorReport) {
    let blocking_findings = report
        .findings
        .iter()
        .filter(|finding| finding.readiness_impact == "blocked")
        .count();
    let repairable_findings = report
        .findings
        .iter()
        .filter(|finding| finding.fixability == DoctorFixability::Repairable)
        .count();
    let informational_findings = report
        .findings
        .iter()
        .filter(|finding| finding.fixability == DoctorFixability::Informational)
        .count();
    let ready = blocking_findings == 0
        && report
            .probe_results
            .iter()
            .all(|probe| probe.status == "passed");
    report.ready = ready;
    report.status = if ready { "ready" } else { "blocked" }.to_string();
    report.summary = DoctorSummary {
        ready,
        blocking_findings,
        repairable_findings,
        informational_findings,
    };
    report.recovery_commands = report
        .findings
        .iter()
        .filter_map(|finding| finding.recovery_command.clone())
        .collect();
    report.recovery_commands.sort();
    report.recovery_commands.dedup();
}

fn execution_blocker(verdict: &Phase0SupportVerdict) -> SatelleError {
    if verdict.is_supported() {
        return SatelleError::not_implemented(
            "native Computer Use execution is not implemented after capability admission",
        );
    }

    SatelleError::computer_use_not_ready()
}

#[cfg(test)]
fn production_doctor_report(
    host: &str,
    scope: Option<&str>,
    snapshot: &ProductionCapabilitySnapshot,
) -> DoctorReport {
    let raw_scopes = scope.into_iter().map(str::to_string).collect::<Vec<_>>();
    let scope_selection = DoctorScopeSelection::parse(&raw_scopes)
        .expect("existing Doctor tests use supported scopes");
    let transport_observation = DoctorTransportObservation::ready(None);
    production_doctor_report_with_selection(
        host,
        &scope_selection,
        &transport_observation,
        DoctorOptions::default(),
        snapshot,
    )
}

fn production_doctor_report_with_selection(
    host: &str,
    scope_selection: &DoctorScopeSelection,
    transport_observation: &DoctorTransportObservation,
    options: DoctorOptions,
    snapshot: &ProductionCapabilitySnapshot,
) -> DoctorReport {
    let selected_scopes = scope_selection
        .scopes()
        .iter()
        .map(|scope| scope.as_str())
        .collect::<Vec<_>>();
    let capability_recovery = "satelle doctor --scope computer-use --refresh --json";
    let mut findings = snapshot
        .verdict
        .blockers()
        .iter()
        .filter_map(|blocker| {
            let scope = blocker_scope(blocker);
            selected_scopes
                .contains(&scope)
                .then(|| blocker_finding(scope, blocker, capability_recovery))
        })
        .collect::<Vec<_>>();
    if selected_scopes.contains(&"transport")
        && let Some(finding) = transport_observation.finding()
    {
        findings.push(finding.clone());
    }
    if selected_scopes.contains(&"provider") {
        findings.push(unavailable_scope_finding(
            "provider",
            "provider_readiness_not_observed",
            "provider readiness has not been observed through a production Host",
            "satelle setup --host local-demo --component provider-auth --dry-run --json",
        ));
    }
    findings.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then(left.finding_id.cmp(&right.finding_id))
    });

    // Capability discovery is one bounded live operation. The scheduler owns
    // how its per-scope projections become visible: dependency and resource
    // rules apply without repeating the live probe or tying final order to
    // completion order.
    let probe_results = scheduled_production_probe_results(
        scope_selection,
        options.probe_timeout(),
        &findings,
        snapshot,
    );
    let ready = probe_results.iter().all(|probe| probe.status == "passed");
    let blocking_findings = findings
        .iter()
        .filter(|finding| finding.readiness_impact == "blocked")
        .count()
        + probe_results
            .iter()
            .filter(|probe| probe.status == "blocked" && probe.finding_ids.is_empty())
            .count();
    let mut recovery_commands = findings
        .iter()
        .filter_map(|finding| finding.recovery_command.clone())
        .collect::<Vec<_>>();
    recovery_commands.sort();
    recovery_commands.dedup();

    let probe_schedule_events = probe_results
        .iter()
        .flat_map(|probe| {
            [
                DoctorProbeScheduleEvent::Started {
                    probe_id: probe.probe_id.clone(),
                },
                DoctorProbeScheduleEvent::Finished {
                    probe_id: probe.probe_id.clone(),
                },
            ]
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    DoctorReport {
        schema_version: DoctorSchemaVersion::V1,
        status: if ready { "ready" } else { "blocked" }.to_string(),
        target: host.to_string(),
        host: host.to_string(),
        scopes: selected_scopes
            .iter()
            .map(|scope| scope.to_string())
            .collect(),
        started_at: snapshot.started_at.clone(),
        finished_at: snapshot.finished_at.clone(),
        duration_ms: snapshot.duration_ms,
        summary: DoctorSummary {
            ready,
            blocking_findings,
            repairable_findings: 0,
            informational_findings: findings
                .iter()
                .filter(|finding| finding.fixability == DoctorFixability::Informational)
                .count(),
        },
        probe_results,
        probe_schedule_events,
        ready,
        findings,
        recovery_commands,
        changed: false,
        cache_updates: Vec::new(),
    }
}

fn production_doctor_probes(
    scopes: &[DoctorScope],
    probe_timeout: Option<std::time::Duration>,
) -> Vec<DoctorProbe> {
    let timeout = probe_timeout.unwrap_or(DoctorOptions::DEFAULT_PROBE_TIMEOUT);
    scopes
        .iter()
        .map(|scope| {
            let dependencies = match scope {
                DoctorScope::ComputerUse if scopes.contains(&DoctorScope::Codex) => {
                    vec![DoctorScope::Codex.as_str().to_string()]
                }
                DoctorScope::Provider if scopes.contains(&DoctorScope::ComputerUse) => {
                    vec![DoctorScope::ComputerUse.as_str().to_string()]
                }
                _ => Vec::new(),
            };
            let resource_locks = match scope {
                DoctorScope::ComputerUse => [
                    DoctorProbeResource::NativeComputerUse,
                    DoctorProbeResource::VisibleDesktop,
                    DoctorProbeResource::ReadinessCacheWrite,
                ]
                .into_iter()
                .collect(),
                DoctorScope::Provider => [
                    DoctorProbeResource::ProviderProbeSurface,
                    DoctorProbeResource::ReadinessCacheWrite,
                ]
                .into_iter()
                .collect(),
                DoctorScope::Transport => [DoctorProbeResource::RemoteServiceManager]
                    .into_iter()
                    .collect(),
                DoctorScope::Codex | DoctorScope::Config => Default::default(),
            };
            DoctorProbe {
                probe_id: scope.as_str().to_string(),
                scope: scope.as_str().to_string(),
                dependencies,
                resource_locks,
                timeout,
                cache_policy: DoctorProbeCachePolicy::Reuse,
            }
        })
        .collect()
}

fn scheduled_production_probe_results(
    scope_selection: &DoctorScopeSelection,
    _probe_timeout: Option<std::time::Duration>,
    findings: &[DoctorFinding],
    snapshot: &ProductionCapabilitySnapshot,
) -> Vec<DoctorProbeResult> {
    scope_selection
        .scopes()
        .iter()
        .map(|scope| production_probe_result(scope.as_str(), findings, snapshot))
        .collect()
}

fn blocker_scope(blocker: &Phase0CapabilityBlocker) -> &'static str {
    match blocker.reason {
        BlockerReason::MissingCodexRuntime
        | BlockerReason::MalformedCodexVersion
        | BlockerReason::CodexVersionUnavailable
        | BlockerReason::UnsupportedCodexVersion => "codex",
        BlockerReason::UnsupportedHostPlatform | BlockerReason::NativeExecutionPathUnavailable => {
            "computer-use"
        }
        BlockerReason::NonStableSurface | BlockerReason::IncompleteLiveProof => {
            capability_scope(blocker.capability)
        }
    }
}

fn capability_scope(capability: RequiredCapability) -> &'static str {
    match capability {
        RequiredCapability::Handshake
        | RequiredCapability::SessionThreadCreation
        | RequiredCapability::TurnStart
        | RequiredCapability::LifecycleEvents => "codex",
        RequiredCapability::ApprovalObservation
        | RequiredCapability::NativeReadiness
        | RequiredCapability::NativeHarmlessAction
        | RequiredCapability::Recovery
        | RequiredCapability::FollowUpTurn
        | RequiredCapability::DetachedTurnOwnership
        | RequiredCapability::InterruptRequest
        | RequiredCapability::ConfirmedStop => "computer-use",
    }
}

fn unavailable_scope_finding(
    scope: &str,
    reason: &str,
    summary: &str,
    recovery_command: &str,
) -> DoctorFinding {
    DoctorFinding {
        finding_id: format!("production.{scope}.{reason}"),
        scope: scope.to_string(),
        severity: "error".to_string(),
        fixability: DoctorFixability::Blocked,
        readiness_impact: "blocked".to_string(),
        summary: summary.to_string(),
        evidence: vec![format!("reason={reason}")],
        recovery_command: Some(recovery_command.to_string()),
    }
}

fn production_probe_result(
    scope: &str,
    findings: &[DoctorFinding],
    snapshot: &ProductionCapabilitySnapshot,
) -> DoctorProbeResult {
    let finding_ids = findings
        .iter()
        .filter(|finding| finding.scope == scope)
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    let blockers = snapshot.verdict.blockers();
    let computer_use_blocked_by_codex = scope == "computer-use"
        && blockers
            .iter()
            .any(|blocker| blocker_scope(blocker) == "codex");
    // Codex probing is deliberately skipped when native Computer Use cannot
    // run on the host. The unobserved control-plane gate is blocked rather
    // than mislabeled as passed, without inventing a Codex-specific finding.
    let codex_blocked_by_platform = scope == "codex"
        && blockers
            .iter()
            .any(|blocker| blocker.reason == BlockerReason::UnsupportedHostPlatform);
    let dependency_blocked = computer_use_blocked_by_codex || codex_blocked_by_platform;
    let blocked = findings
        .iter()
        .any(|finding| finding.scope == scope && finding.readiness_impact == "blocked")
        || dependency_blocked;
    let capability_probe = matches!(scope, "codex" | "computer-use");
    let (started_at, finished_at, duration_ms) = if capability_probe {
        (
            snapshot.started_at.clone(),
            snapshot.finished_at.clone(),
            snapshot.duration_ms,
        )
    } else {
        (
            snapshot.finished_at.clone(),
            snapshot.finished_at.clone(),
            0,
        )
    };

    DoctorProbeResult {
        probe_id: match scope {
            "codex" => "codex.phase0_capability_gate",
            "computer-use" => "computer-use.phase0_capability_gate",
            "config" => "config.selected_host_resolution",
            "provider" => "provider.production_readiness",
            "transport" => "transport.production_availability",
            _ => "unknown.invalid_scope",
        }
        .to_string(),
        scope: scope.to_string(),
        status: if blocked { "blocked" } else { "passed" }.to_string(),
        started_at,
        finished_at,
        duration_ms,
        cache_status: "not_persisted".to_string(),
        dependency_status: if dependency_blocked {
            "blocked"
        } else {
            "satisfied"
        }
        .to_string(),
        finding_ids,
    }
}

fn blocker_finding(
    scope: &str,
    blocker: &Phase0CapabilityBlocker,
    recovery_command: &str,
) -> DoctorFinding {
    let readiness_blocker = blocker.doctor_readiness_blocker();
    let mut evidence = vec![
        format!("reason={}", blocker.reason.as_str()),
        format!("capability={}", blocker.capability.as_str()),
        version_evidence(blocker.codex_version),
        format!("host_platform={}", blocker.host_platform.as_str()),
        format!("observed_surface={}", blocker.observed_surface.as_str()),
        format!("live_proof={}", blocker.live_proof.as_str()),
    ];
    if let Some(readiness_blocker) = readiness_blocker {
        evidence.push(format!(
            "doctor_readiness_blocker={}",
            readiness_blocker.as_str()
        ));
    }
    DoctorFinding {
        finding_id: format!(
            "phase0.{}.{}",
            blocker.capability.as_str(),
            blocker.reason.as_str()
        ),
        scope: scope.to_string(),
        severity: "error".to_string(),
        fixability: DoctorFixability::Blocked,
        readiness_impact: "blocked".to_string(),
        summary: blocker_summary(blocker).to_string(),
        evidence,
        recovery_command: Some(recovery_command.to_string()),
    }
}

fn blocker_summary(blocker: &Phase0CapabilityBlocker) -> &'static str {
    use codex_capabilities::BlockerReason;

    match blocker.reason {
        BlockerReason::MissingCodexRuntime => "the Codex runtime was not found",
        BlockerReason::MalformedCodexVersion => "the Codex version response was malformed",
        BlockerReason::CodexVersionUnavailable => "the Codex version probe was unavailable",
        BlockerReason::UnsupportedCodexVersion => "the installed Codex version is unsupported",
        BlockerReason::UnsupportedHostPlatform => {
            "native Computer Use is unsupported on this host platform"
        }
        BlockerReason::NativeExecutionPathUnavailable => {
            "the private Codex app-server exposes no stable native Computer Use path"
        }
        BlockerReason::NonStableSurface => {
            "a required capability lacks evidence from the stable surface"
        }
        BlockerReason::IncompleteLiveProof => "a required capability lacks passing live-host proof",
    }
}

fn version_evidence(evidence: CodexVersionEvidence) -> String {
    match evidence {
        CodexVersionEvidence::Detected { version } => format!("codex_version={version}"),
        evidence => format!("codex_version_status={}", evidence.status_name()),
    }
}

fn production_setup_report(
    host: &str,
    dry_run: bool,
    setup_mode: String,
    setup_components: Vec<String>,
    daemon_path_overrides: DaemonPathOverrides,
) -> SetupReport {
    let service_persistent = setup_mode == "persistent";
    let mutation_planned = setup_components.iter().any(|component| {
        matches!(
            component.as_str(),
            "all" | "host" | "codex" | "computer-use"
        )
    });
    let service_scope = if service_persistent {
        "user"
    } else {
        "on_demand"
    };
    let daemon_path_overrides = daemon_path_overrides.entries();
    let mut planned_actions = vec![
        "resolve the configured local host".to_string(),
        "report the current standalone Codex admission state".to_string(),
        "keep native Computer Use blocked until stable schema and live-host proof pass".to_string(),
    ];
    planned_actions.extend(daemon_path_overrides.iter().map(|override_entry| {
        format!(
            "map {}={} in Satelle-owned service configuration",
            override_entry.environment_variable, override_entry.value
        )
    }));

    SetupReport {
        schema_version: SetupSchemaVersion::V2,
        host: host.to_string(),
        dry_run,
        status: "planned".to_string(),
        cancellation_reason: None,
        verification: None,
        setup_mode,
        service_persistent,
        service_scope: service_scope.to_string(),
        fallback_reason: None,
        target_platform: None,
        host_artifact: None,
        service_plan: None,
        current_daemon_paths: None,
        planned_daemon_paths: None,
        setup_components,
        planned_actions,
        applied_actions: Vec::new(),
        required_input: Vec::new(),
        recovery_commands: vec!["satelle doctor --scope computer-use --refresh --json".to_string()],
        readiness_summary: SetupReadinessSummary {
            transport: "not_available".to_string(),
            host_daemon: "not_installed".to_string(),
            codex_runtime: "not_ready".to_string(),
            native_computer_use: "blocked_pending_acceptance".to_string(),
            provider_auth: "not_checked".to_string(),
        },
        descriptor_configured: false,
        secret_provisioned: false,
        validation_status: "not_checked".to_string(),
        provider_smoke_test_status: "not_checked".to_string(),
        daemon_path_overrides,
        changed: false,
        mutated: false,
        mutation_planned,
        native_computer_use_readiness: "blocked_pending_acceptance".to_string(),
        next_command: "satelle doctor --scope computer-use --refresh --json".to_string(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostStatus {
    pub running: bool,
    pub mode: String,
    pub sessions: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TurnOutcome {
    pub session: PublicSession,
    pub events: Vec<SatelleEvent>,
}

pub fn health_route() -> Value {
    object_value([
        ("status", json!("ok")),
        ("service", json!("satelle-host")),
        ("mode", json!("production-capability-gated")),
    ])
}

pub fn readiness_route() -> Value {
    object_value([
        ("ready", json!(false)),
        ("adapter", json!("codex")),
        ("host", json!(LOCAL_DEMO_HOST)),
        ("blocker", json!("computer-use-not-ready")),
    ])
}

#[cfg(test)]
mod packet17_doctor_tests {
    use super::*;

    #[test]
    fn host_default_doctor_graph_uses_dependencies_resources_and_bounded_concurrency() {
        let selection = DoctorScopeSelection::parse(&[]).expect("default scope is valid");
        let probes =
            production_doctor_probes(selection.scopes(), Some(std::time::Duration::from_secs(7)));
        let mut scheduler = DoctorProbeScheduler::new(probes.clone()).expect("valid Host graph");

        assert_eq!(probes.len(), 5);
        assert!(
            probes
                .iter()
                .all(|probe| probe.timeout == std::time::Duration::from_secs(7))
        );
        let first = scheduler.start_ready();
        assert!(first.len() <= satelle_core::doctor::DEFAULT_DOCTOR_PROBE_CONCURRENCY);
        assert!(first.iter().any(|probe| probe.scope == "codex"));
        assert!(!first.iter().any(|probe| probe.scope == "computer-use"));
        assert!(!first.iter().any(|probe| probe.scope == "provider"));
        let native = probes
            .iter()
            .find(|probe| probe.scope == "computer-use")
            .expect("native probe");
        let provider = probes
            .iter()
            .find(|probe| probe.scope == "provider")
            .expect("provider probe");
        assert_eq!(native.dependencies, ["codex"]);
        assert_eq!(provider.dependencies, ["computer-use"]);
        assert!(
            native
                .resource_locks
                .contains(&DoctorProbeResource::NativeComputerUse)
        );
        assert!(
            provider
                .resource_locks
                .contains(&DoctorProbeResource::ProviderProbeSurface)
        );
    }

    #[test]
    fn authoritative_capability_blocker_reaches_doctor_finding_evidence() {
        let blocker = Phase0CapabilityBlocker {
            reason: BlockerReason::MissingCodexRuntime,
            capability: RequiredCapability::NativeReadiness,
            codex_version: CodexVersionEvidence::Missing,
            host_platform: codex_capabilities::HostPlatform::Windows,
            observed_surface: codex_capabilities::EvidenceSurface::Absent,
            live_proof: codex_capabilities::LiveProofStatus::NotObserved,
        };

        let finding = blocker_finding("codex", &blocker, "satelle doctor --refresh");

        assert!(
            finding
                .evidence
                .contains(&"doctor_readiness_blocker=codex-runtime-missing".to_string())
        );
    }

    #[test]
    fn missing_private_execution_path_does_not_claim_plugin_absence() {
        let blocker = Phase0CapabilityBlocker {
            reason: BlockerReason::NativeExecutionPathUnavailable,
            capability: RequiredCapability::NativeReadiness,
            codex_version: CodexVersionEvidence::Missing,
            host_platform: codex_capabilities::HostPlatform::Windows,
            observed_surface: codex_capabilities::EvidenceSurface::Absent,
            live_proof: codex_capabilities::LiveProofStatus::NotObserved,
        };

        let finding = blocker_finding("computer-use", &blocker, "satelle doctor --refresh");

        assert!(
            finding
                .evidence
                .iter()
                .all(|entry| !entry.contains("computer-use-plugin-missing"))
        );
    }

    #[test]
    fn non_codex_phase0_blockers_do_not_suppress_native_probe_evidence() {
        let blocker = Phase0CapabilityBlocker {
            reason: BlockerReason::NativeExecutionPathUnavailable,
            capability: RequiredCapability::NativeReadiness,
            codex_version: CodexVersionEvidence::Missing,
            host_platform: codex_capabilities::HostPlatform::Windows,
            observed_surface: codex_capabilities::EvidenceSurface::Absent,
            live_proof: codex_capabilities::LiveProofStatus::NotObserved,
        };

        assert_eq!(
            phase0_probe_completion(&[blocker]),
            DoctorProbeCompletion::new(DoctorProbeStatus::Finding, DoctorDependentEvidence::Useful,)
        );
    }

    #[test]
    fn phase0_budget_failure_is_a_typed_probe_timeout() {
        let snapshot = ProductionCapabilitySnapshot::collect(Some(Duration::ZERO));

        assert_eq!(
            phase0_snapshot_completion(&snapshot),
            DoctorProbeCompletion::new(
                DoctorProbeStatus::TimedOut,
                DoctorDependentEvidence::NotUseful,
            )
        );
    }

    #[test]
    fn refresh_result_ids_follow_scheduler_lifecycle_scope_order() {
        let snapshot = ProductionCapabilitySnapshot::collect(None);
        let mut report = production_doctor_report(LOCAL_DEMO_HOST, None, &snapshot);
        report
            .probe_results
            .iter_mut()
            .find(|probe| probe.scope == "computer-use")
            .expect("native probe result")
            .probe_id = "computer-use.native.refresh".to_string();
        report
            .probe_results
            .iter_mut()
            .find(|probe| probe.scope == "provider")
            .expect("provider probe result")
            .probe_id = "provider.smoke.refresh".to_string();

        assert_eq!(
            public_probe_schedule_events(
                &report,
                &[
                    DoctorProbeScheduleEvent::Started {
                        probe_id: "provider".to_string()
                    },
                    DoctorProbeScheduleEvent::Finished {
                        probe_id: "provider".to_string()
                    },
                    DoctorProbeScheduleEvent::Started {
                        probe_id: "computer-use".to_string()
                    },
                    DoctorProbeScheduleEvent::Finished {
                        probe_id: "computer-use".to_string()
                    },
                ]
            )
            .into_vec(),
            vec![
                DoctorProbeScheduleEvent::Started {
                    probe_id: "provider.smoke.refresh".to_string()
                },
                DoctorProbeScheduleEvent::Finished {
                    probe_id: "provider.smoke.refresh".to_string()
                },
                DoctorProbeScheduleEvent::Started {
                    probe_id: "computer-use.native.refresh".to_string()
                },
                DoctorProbeScheduleEvent::Finished {
                    probe_id: "computer-use.native.refresh".to_string()
                },
            ]
        );
    }

    #[test]
    fn serial_option_and_zero_timeout_cross_the_typed_scheduler_boundary() {
        let selection = DoctorScopeSelection::parse(&[]).expect("default scope is valid");
        let probes = production_doctor_probes(selection.scopes(), None);
        let mut scheduler =
            production_doctor_scheduler(probes, DoctorOptions::default().with_serial_probes(true))
                .expect("serial scheduler");
        assert_eq!(scheduler.start_ready().len(), 1);

        let zero_timeout_probes =
            production_doctor_probes(selection.scopes(), Some(Duration::ZERO));
        let error = production_doctor_scheduler(zero_timeout_probes, DoctorOptions::default())
            .expect_err("zero timeout must be rejected");
        assert!(error.message.contains("timeout must be greater than zero"));
    }

    #[test]
    fn capability_refresh_dispatched_after_deadline_uses_typed_timeout_without_a_new_snapshot() {
        let fallback = ProductionCapabilitySnapshot::collect(None);
        let snapshot_slot = RwLock::new(fallback.clone());
        let mut execution = ProductionDoctorExecution::new();
        let records = vec![DoctorProbeExecutionRecord {
            probe_id: DoctorScope::Codex.as_str().to_string(),
            status: DoctorProbeStatus::TimedOut,
        }];

        let (snapshot, snapshot_was_refreshed) =
            production_snapshot_after_execution(&mut execution, &records, &snapshot_slot)
                .expect("a typed timeout keeps the last authoritative snapshot as report context");

        assert_eq!(records[0].status, DoctorProbeStatus::TimedOut);
        assert!(!snapshot_was_refreshed);
        assert_eq!(snapshot.finished_at, fallback.finished_at);
    }

    #[test]
    fn provider_refresh_native_evidence_keeps_provider_intent() {
        let provider_intent = ProviderComputerUseIntent::host_default();
        let native_only_intent = ProviderComputerUseIntent::host_default();

        assert!(std::ptr::eq(
            native_probe_intent(true, &provider_intent, &native_only_intent),
            &provider_intent,
        ));
        assert!(std::ptr::eq(
            native_probe_intent(false, &provider_intent, &native_only_intent),
            &native_only_intent,
        ));
    }
}

#[cfg(test)]
#[test]
fn doctor_registry_retains_timed_out_capacity_and_lock_until_cleanup_ack() {
    use std::sync::mpsc;

    let registry = DoctorTaskRegistry::new();
    let request_id = registry.begin_request();
    let definition = DoctorProbe {
        probe_id: "provider".to_string(),
        scope: DoctorScope::Provider.as_str().to_string(),
        dependencies: Vec::new(),
        resource_locks: [DoctorProbeResource::ProviderProbeSurface]
            .into_iter()
            .collect(),
        timeout: Duration::from_millis(100),
        cache_policy: DoctorProbeCachePolicy::Never,
    };
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    registry
        .spawn(request_id, &definition, move |context| {
            started_tx.send(()).expect("signal worker start");
            release_rx.recv().expect("release cleanup-only worker");
            assert!(context.is_cancelled());
            ProductionDoctorTaskResult {
                completion: DoctorProbeCompletion::new(
                    DoctorProbeStatus::Passed,
                    DoctorDependentEvidence::Useful,
                ),
                effect: ProductionDoctorTaskEffect::ProviderNotRequired,
            }
        })
        .expect("spawn registry worker");
    started_rx.recv().expect("worker started");

    registry.advance(Instant::now() + definition.timeout);
    assert!(matches!(
        registry.drain_events(request_id).as_slice(),
        [DoctorRegistryEvent::TimedOut { probe_id }] if probe_id == "provider"
    ));

    let later_request_id = registry.begin_request();
    let (capacity, locks) = registry.external_occupancy(later_request_id);
    assert_eq!(capacity, 1);
    assert!(locks.contains(&DoctorProbeResource::ProviderProbeSurface));

    let mut same_lock =
        DoctorProbeScheduler::new(vec![definition.clone()]).expect("same-lock graph is valid");
    assert!(
        same_lock
            .start_ready_with_external_occupancy(capacity, &locks)
            .is_empty()
    );

    let mut disjoint = DoctorProbeScheduler::new(vec![DoctorProbe {
        probe_id: "config".to_string(),
        scope: DoctorScope::Config.as_str().to_string(),
        dependencies: Vec::new(),
        resource_locks: Default::default(),
        timeout: Duration::from_millis(100),
        cache_policy: DoctorProbeCachePolicy::Never,
    }])
    .expect("disjoint graph is valid");
    assert_eq!(
        disjoint
            .start_ready_with_external_occupancy(capacity, &locks)
            .len(),
        1
    );

    release_tx.send(()).expect("release worker");
    loop {
        registry.advance(Instant::now());
        if registry.external_occupancy(later_request_id).0 == 0 {
            break;
        }
        registry.wait_until(Instant::now() + Duration::from_millis(10));
    }
    assert!(
        registry.drain_events(request_id).is_empty(),
        "late success and effect must be discarded"
    );
}

#[cfg(test)]
#[test]
fn doctor_registry_shutdown_cancels_without_waiting_for_owned_worker() {
    use std::sync::mpsc;

    let registry = DoctorTaskRegistry::new();
    let request_id = registry.begin_request();
    let definition = DoctorProbe {
        probe_id: "native".to_string(),
        scope: DoctorScope::ComputerUse.as_str().to_string(),
        dependencies: Vec::new(),
        resource_locks: Default::default(),
        timeout: Duration::from_secs(1),
        cache_policy: DoctorProbeCachePolicy::Never,
    };
    let (started_tx, started_rx) = mpsc::channel();
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    registry
        .spawn(request_id, &definition, move |context| {
            started_tx.send(()).expect("signal worker start");
            while !context.is_cancelled() {
                std::thread::yield_now();
            }
            cancelled_tx.send(()).expect("signal cancellation");
            release_rx.recv().expect("release cancelled worker");
            ProductionDoctorTaskResult {
                completion: DoctorProbeCompletion::new(
                    DoctorProbeStatus::TimedOut,
                    DoctorDependentEvidence::NotUseful,
                ),
                effect: ProductionDoctorTaskEffect::None,
            }
        })
        .expect("spawn registry worker");
    started_rx.recv().expect("worker started");

    let (dropped_tx, dropped_rx) = mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(registry);
        dropped_tx.send(()).expect("signal registry drop");
    });
    dropped_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("registry shutdown must not join an uncooperative worker");

    cancelled_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("registry shutdown requested worker cancellation");
    release_tx.send(()).expect("release detached worker");
    dropper.join().expect("join registry drop proof");
}

#[cfg(test)]
#[path = "lib-tests.rs"]
mod tests;
