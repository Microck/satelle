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
    ProviderComputerUseIntent, ProviderSmokeEvidence, ProviderSmokeFailureEvidence,
    ProviderSmokeResult, ProviderSmokeSource, ReadinessCacheKey, ReadinessEvidence,
    ReadinessObservationState, RecoveryObservation,
};
use runtime::{ProductionComputerUseAdapter, RunCommand, RuntimeHandle, SteerCommand, StopCommand};
use satelle_core::session::{PublicSession, TurnAdmissionFailure};
use satelle_core::{
    DaemonPathOverrides, DoctorFinding, DoctorFixability, DoctorOptions, DoctorProbeResult,
    DoctorReport, DoctorSchemaVersion, DoctorSummary, HostConfig, HostSessionsReport,
    HostSessionsSchemaVersion, LOCAL_DEMO_HOST, SatelleError, SatelleEvent, SessionId,
    SetupReadinessSummary, SetupReport, SetupSchemaVersion, StopResult, TurnId, object_value,
    utc_now,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};
use std::time::Instant;
pub use storage::{
    SetupActionPlan, SetupActionRecord, SetupActionSkipReason, SetupActionStatus,
    SetupOperationKind, SetupRepairAction, SetupRepairDecision, SetupRepairPlan,
    SetupRepairPostcondition, SetupRepairProbe, SetupRunPlan, SetupRunRecord, SetupRunStatus,
};

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
use test_runtime::{FailingComputerUseAdapter, PendingComputerUseAdapter};
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

#[derive(Clone, Debug)]
pub struct HostService {
    runtime: RuntimeHandle,
    operation_capacity: Arc<OperationCapacity>,
    turn_execution_timeout: satelle_core::session::TimeoutPolicy,
    mode: HostMode,
    bootstrap_auth: Option<Arc<EphemeralApiAuthenticator>>,
    bootstrap_maintenance: Arc<Mutex<Option<MaintenanceOperationHandle>>>,
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
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        Self {
            evidence: discovery.evidence,
            verdict,
            control_plane_admission: discovery.control_plane_admission,
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
            runtime: RuntimeHandle::new_production(state_root, operator_log_root, adapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(config),
            mode: HostMode::Production { snapshot },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
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
            runtime: RuntimeHandle::new(satelle_core::state_dir(), FakeComputerUseAdapter),
            operation_capacity: Arc::new(OperationCapacity::default()),
            turn_execution_timeout: configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: Arc::new(Mutex::new(None)),
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
        })
    }

    pub fn doctor(
        &self,
        host: &str,
        scope: Option<&str>,
        options: DoctorOptions,
    ) -> Result<DoctorReport, SatelleError> {
        self.doctor_with_provider_intent(
            host,
            scope,
            options,
            &ProviderComputerUseIntent::host_default(),
        )
    }

    pub fn doctor_with_provider_intent(
        &self,
        host: &str,
        scope: Option<&str>,
        options: DoctorOptions,
        provider_intent: &ProviderComputerUseIntent,
    ) -> Result<DoctorReport, SatelleError> {
        if let Some(scope) = scope
            && ![
                "transport",
                "codex",
                "computer-use",
                "provider",
                "config",
                "all",
            ]
            .contains(&scope)
        {
            return Err(SatelleError::invalid_usage("unsupported doctor scope"));
        }
        let mut report = match &self.mode {
            HostMode::Production { snapshot } if options.refresh() => {
                let refreshed = ProductionCapabilitySnapshot::collect(options.probe_timeout());
                let report = production_doctor_report(host, scope, &refreshed);
                replace_production_snapshot(snapshot, refreshed)?;
                report
            }
            HostMode::Production { snapshot } => {
                production_doctor_report(host, scope, &*read_production_snapshot(snapshot)?)
            }
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { .. } => {
                self.fake_doctor(host, scope, options, &FakeComputerUseAdapter)?
            }
        };
        if options.refresh() && matches!(scope, Some("provider" | "all")) {
            if scope == Some("provider") {
                report.changed = false;
                report.cache_updates.clear();
            }
            let started_at = utc_now();
            let started = Instant::now();
            let refresh = self.runtime.refresh_provider_smoke(host, provider_intent);
            apply_provider_refresh(&mut report, refresh, started_at, started.elapsed());
        }
        Ok(report)
    }

    pub fn setup(
        &self,
        host: &str,
        dry_run: bool,
        setup_mode: String,
        setup_components: Vec<String>,
        daemon_path_overrides: DaemonPathOverrides,
    ) -> Result<SetupReport, SatelleError> {
        if !dry_run {
            return Err(SatelleError::not_implemented(format!(
                "{setup_mode} setup mutations are not supported by the local Host transport"
            )));
        }
        match &self.mode {
            HostMode::Production { .. } => Ok(production_setup_report(
                host,
                dry_run,
                setup_mode,
                setup_components,
                daemon_path_overrides,
            )),
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
    refresh: Result<AdapterReadiness, SatelleError>,
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
                    summary: error.message,
                    evidence,
                    recovery_command: error.recovery_command,
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

fn production_doctor_report(
    host: &str,
    scope: Option<&str>,
    snapshot: &ProductionCapabilitySnapshot,
) -> DoctorReport {
    let selected_scopes = selected_doctor_scopes(scope);
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
    if selected_scopes.contains(&"transport") {
        findings.push(unavailable_scope_finding(
            "transport",
            "transport_unavailable",
            "no production Host transport is available",
            "satelle setup --host local-demo --dry-run --json",
        ));
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

    // Production capability discovery is currently one combined live probe,
    // so it already satisfies the at-most-one execution promised by
    // --serial-probes. The per-scope results below are static projections of
    // that single snapshot, not additional live work to schedule.
    let probe_results = selected_scopes
        .iter()
        .map(|scope| production_probe_result(scope, &findings, snapshot))
        .collect::<Vec<_>>();
    let ready = probe_results.iter().all(|probe| probe.status == "passed");
    let blocking_findings = findings.len()
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
            informational_findings: 0,
        },
        probe_results,
        ready,
        findings,
        recovery_commands,
        changed: false,
        cache_updates: Vec::new(),
    }
}

fn selected_doctor_scopes(scope: Option<&str>) -> Vec<&'static str> {
    match scope {
        None | Some("all") => vec!["codex", "computer-use", "config", "provider", "transport"],
        Some("codex") => vec!["codex"],
        Some("computer-use") => vec!["computer-use"],
        Some("config") => vec!["config"],
        Some("provider") => vec!["provider"],
        Some("transport") => vec!["transport"],
        Some(_) => Vec::new(),
    }
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
    let blocked = !finding_ids.is_empty() || dependency_blocked;
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
        evidence: vec![
            format!("reason={}", blocker.reason.as_str()),
            format!("capability={}", blocker.capability.as_str()),
            version_evidence(blocker.codex_version),
            format!("host_platform={}", blocker.host_platform.as_str()),
            format!("observed_surface={}", blocker.observed_surface.as_str()),
            format!("live_proof={}", blocker.live_proof.as_str()),
        ],
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
        schema_version: SetupSchemaVersion::V1,
        host: host.to_string(),
        dry_run,
        status: "planned".to_string(),
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
        daemon_path_overrides,
        mutated: false,
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
#[path = "lib-tests.rs"]
mod tests;
