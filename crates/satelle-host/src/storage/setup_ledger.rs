use super::codec::{format_time, parse_time, validated_private_reference};
use super::{LeaseOwner, Storage, StorageError, StorageErrorKind, sqlite_error};
use crate::runtime::VerifiedSetupPostconditions;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use satelle_core::session::DesktopBindingRef;
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;

const OUTCOME_UNKNOWN_RECOVERY_HINT: &str =
    "inspect live postconditions before retrying this action";
const MAX_ACTION_LABEL_BYTES: usize = 256;
const MAX_RECOVERY_HINT_BYTES: usize = 512;

/// In-process authority for one live Host maintenance operation.
///
/// `LeaseOwner` remains durable identity. This non-Clone capability can only
/// be constructed here after the setup ledger and lease commit together.
pub(crate) struct MaintenanceLeaseCapability {
    owner: LeaseOwner,
}

impl MaintenanceLeaseCapability {
    fn new(owner: LeaseOwner) -> Self {
        Self { owner }
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.owner.operation_id()
    }

    pub(crate) fn lease_owner(&self) -> &LeaseOwner {
        &self.owner
    }
}

impl std::fmt::Debug for MaintenanceLeaseCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MaintenanceLeaseCapability")
            .finish_non_exhaustive()
    }
}

enum StartedActionOutcome<'a> {
    Completed,
    Failed {
        error_code: &'a str,
        exit_status: Option<i64>,
        recovery_hint: Option<&'a str>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupOperationKind {
    Setup,
    Repair,
    HostUpdate,
    StorageMigration,
    ServiceRestart,
}

impl SetupOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Repair => "repair",
            Self::HostUpdate => "host_update",
            Self::StorageMigration => "storage_migration",
            Self::ServiceRestart => "service_restart",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "setup" => Ok(Self::Setup),
            "repair" => Ok(Self::Repair),
            "host_update" => Ok(Self::HostUpdate),
            "storage_migration" => Ok(Self::StorageMigration),
            "service_restart" => Ok(Self::ServiceRestart),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupRunStatus {
    Running,
    Completed,
    Failed,
    PartialFailure,
    OutcomeUnknown,
}

impl SetupRunStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::PartialFailure => "partial_failure",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "partial_failure" => Ok(Self::PartialFailure),
            "outcome_unknown" => Ok(Self::OutcomeUnknown),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupActionStatus {
    Planned,
    Started,
    Completed,
    Failed,
    Skipped,
    OutcomeUnknown,
}

impl SetupActionStatus {
    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "planned" => Ok(Self::Planned),
            "started" => Ok(Self::Started),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "skipped" => Ok(Self::Skipped),
            "outcome_unknown" => Ok(Self::OutcomeUnknown),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupActionSkipReason {
    AlreadySatisfied,
    DependencyFailed,
    NotRequired,
}

impl SetupActionSkipReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AlreadySatisfied => "already_satisfied",
            Self::DependencyFailed => "dependency_failed",
            Self::NotRequired => "not_required",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "already_satisfied" => Ok(Self::AlreadySatisfied),
            "dependency_failed" => Ok(Self::DependencyFailed),
            "not_required" => Ok(Self::NotRequired),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupActionPlan {
    action_id: String,
    label: String,
    retry_safe: bool,
}

impl SetupActionPlan {
    pub fn new(
        action_id: impl Into<String>,
        label: impl Into<String>,
        retry_safe: bool,
    ) -> Result<Self, satelle_core::SatelleError> {
        Self::try_new(action_id, label, retry_safe).map_err(crate::runtime::storage_error)
    }

    fn try_new(
        action_id: impl Into<String>,
        label: impl Into<String>,
        retry_safe: bool,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            action_id: validated_private_reference(action_id.into())?,
            label: normalized_text(label.into(), MAX_ACTION_LABEL_BYTES)?,
            retry_safe,
        })
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn retry_safe(&self) -> bool {
        self.retry_safe
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRunPlan {
    run_id: String,
    operation_kind: SetupOperationKind,
    desktop_binding: Option<DesktopBindingRef>,
    started_at: OffsetDateTime,
    actions: Vec<SetupActionPlan>,
}

impl SetupRunPlan {
    pub fn new(
        run_id: impl Into<String>,
        operation_kind: SetupOperationKind,
        desktop_binding: Option<DesktopBindingRef>,
        started_at: OffsetDateTime,
        actions: Vec<SetupActionPlan>,
    ) -> Result<Self, satelle_core::SatelleError> {
        Self::try_new(run_id, operation_kind, desktop_binding, started_at, actions)
            .map_err(crate::runtime::storage_error)
    }

    fn try_new(
        run_id: impl Into<String>,
        operation_kind: SetupOperationKind,
        desktop_binding: Option<DesktopBindingRef>,
        started_at: OffsetDateTime,
        actions: Vec<SetupActionPlan>,
    ) -> Result<Self, StorageError> {
        let run_id = validated_private_reference(run_id.into())?;
        if actions.is_empty() {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let mut action_ids = HashSet::with_capacity(actions.len());
        if actions
            .iter()
            .any(|action| !action_ids.insert(action.action_id.as_str()))
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            run_id,
            operation_kind,
            desktop_binding,
            started_at,
            actions,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn operation_kind(&self) -> SetupOperationKind {
        self.operation_kind
    }

    pub fn desktop_binding(&self) -> Option<&DesktopBindingRef> {
        self.desktop_binding.as_ref()
    }

    pub const fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    pub fn actions(&self) -> &[SetupActionPlan] {
        &self.actions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupActionRecord {
    action_id: String,
    order: usize,
    label: String,
    status: SetupActionStatus,
    started_at: Option<OffsetDateTime>,
    finished_at: Option<OffsetDateTime>,
    retry_safe: bool,
    error_code: Option<String>,
    exit_status: Option<i64>,
    recovery_hint: Option<String>,
    skip_reason: Option<SetupActionSkipReason>,
}

impl SetupActionRecord {
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub const fn order(&self) -> usize {
        self.order
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn status(&self) -> SetupActionStatus {
        self.status
    }

    pub const fn started_at(&self) -> Option<OffsetDateTime> {
        self.started_at
    }

    pub const fn finished_at(&self) -> Option<OffsetDateTime> {
        self.finished_at
    }

    pub const fn retry_safe(&self) -> bool {
        self.retry_safe
    }

    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }

    pub const fn exit_status(&self) -> Option<i64> {
        self.exit_status
    }

    pub fn recovery_hint(&self) -> Option<&str> {
        self.recovery_hint.as_deref()
    }

    pub const fn skip_reason(&self) -> Option<SetupActionSkipReason> {
        self.skip_reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRunRecord {
    run_id: String,
    operation_kind: SetupOperationKind,
    desktop_binding: Option<DesktopBindingRef>,
    satelle_version: String,
    status: SetupRunStatus,
    started_at: OffsetDateTime,
    finished_at: Option<OffsetDateTime>,
    actions: Vec<SetupActionRecord>,
}

impl SetupRunRecord {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn operation_kind(&self) -> SetupOperationKind {
        self.operation_kind
    }

    pub fn desktop_binding(&self) -> Option<&DesktopBindingRef> {
        self.desktop_binding.as_ref()
    }

    pub fn satelle_version(&self) -> &str {
        &self.satelle_version
    }

    pub const fn status(&self) -> SetupRunStatus {
        self.status
    }

    pub const fn started_at(&self) -> OffsetDateTime {
        self.started_at
    }

    pub const fn finished_at(&self) -> Option<OffsetDateTime> {
        self.finished_at
    }

    pub fn actions(&self) -> &[SetupActionRecord] {
        &self.actions
    }
}

/// Result of the live postcondition probe for one repairable setup action.
/// Repair never infers this state from a prior ledger outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupRepairPostcondition {
    Satisfied,
    Unsatisfied,
    Unknown,
}

/// A current repair candidate paired with its live postcondition result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRepairProbe {
    action: SetupActionPlan,
    postcondition: SetupRepairPostcondition,
}

impl SetupRepairProbe {
    pub fn new(
        action_id: impl Into<String>,
        label: impl Into<String>,
        retry_safe: bool,
        postcondition: SetupRepairPostcondition,
    ) -> Result<Self, satelle_core::SatelleError> {
        Self::try_new(action_id, label, retry_safe, postcondition)
            .map_err(crate::runtime::storage_error)
    }

    pub(crate) fn try_new(
        action_id: impl Into<String>,
        label: impl Into<String>,
        retry_safe: bool,
        postcondition: SetupRepairPostcondition,
    ) -> Result<Self, StorageError> {
        Ok(Self {
            action: SetupActionPlan::try_new(action_id, label, retry_safe)?,
            postcondition,
        })
    }

    pub fn action(&self) -> &SetupActionPlan {
        &self.action
    }

    pub const fn postcondition(&self) -> SetupRepairPostcondition {
        self.postcondition
    }
}

/// Repair disposition derived from current probes and retained ledger safety
/// metadata. Only `RetryAutomatically` authorizes an unattended retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupRepairDecision {
    NoActionRequired,
    RetryAutomatically,
    OperatorActionRequired,
    ProbeRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRepairAction {
    action_id: String,
    label: String,
    decision: SetupRepairDecision,
    retry_safe: bool,
    previous_run_id: Option<String>,
    previous_status: Option<SetupActionStatus>,
}

impl SetupRepairAction {
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn decision(&self) -> SetupRepairDecision {
        self.decision
    }

    /// This is the effective retry-safety value. When history exists, both
    /// the retained action and the current repair candidate must permit retry.
    pub const fn retry_safe(&self) -> bool {
        self.retry_safe
    }

    pub fn previous_run_id(&self) -> Option<&str> {
        self.previous_run_id.as_deref()
    }

    pub const fn previous_status(&self) -> Option<SetupActionStatus> {
        self.previous_status
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupRepairPlan {
    actions: Vec<SetupRepairAction>,
}

pub(crate) struct MaintenanceRecoverySubject {
    owner: LeaseOwner,
    run: SetupRunRecord,
    has_postcheck: bool,
}

impl MaintenanceRecoverySubject {
    pub(super) fn new(owner: LeaseOwner, run: SetupRunRecord, has_postcheck: bool) -> Self {
        Self {
            owner,
            run,
            has_postcheck,
        }
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.owner.operation_id()
    }

    pub(crate) const fn operation_kind(&self) -> SetupOperationKind {
        self.run.operation_kind()
    }

    pub(crate) fn run(&self) -> &SetupRunRecord {
        &self.run
    }

    pub(crate) const fn has_postcheck(&self) -> bool {
        self.has_postcheck
    }
}

pub(crate) enum MaintenanceLeaseState {
    Active {
        operation_id: String,
        freshness: super::LeaseFreshness,
    },
    RecoveryPending(Box<MaintenanceRecoverySubject>),
}

impl SetupRepairPlan {
    pub fn actions(&self) -> &[SetupRepairAction] {
        &self.actions
    }

    pub fn automatic_actions(&self) -> impl Iterator<Item = &SetupRepairAction> {
        self.actions
            .iter()
            .filter(|action| action.decision == SetupRepairDecision::RetryAutomatically)
    }
}

struct PreviousSetupAction {
    run_id: String,
    status: SetupActionStatus,
    retry_safe: bool,
    row_id: i64,
}

impl Storage {
    pub(crate) fn begin_setup_run(
        &mut self,
        plan: &SetupRunPlan,
        owner: LeaseOwner,
    ) -> Result<MaintenanceLeaseCapability, StorageError> {
        if plan.run_id != owner.operation_id {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let host_identity = self.host_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let maintenance_exists: i64 = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM maintenance_leases WHERE host_identity_ref = ?1)",
                [host_identity.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if maintenance_exists != 0 {
            return Err(StorageError::new(StorageErrorKind::LeaseConflict));
        }
        // Planning and execution are separate API calls. Reserving mutation
        // scope inside the write transaction closes the race between callers
        // that both planned before either persisted its run.
        if active_setup_run_in_scope(&transaction, plan.desktop_binding.as_ref())? {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let control_exists: i64 = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM control_leases WHERE host_identity_ref = ?1)",
                [host_identity.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        if control_exists != 0 {
            return Err(StorageError::new(StorageErrorKind::LeaseConflict));
        }
        transaction
            .execute(
                "INSERT INTO setup_runs (
                    run_id, host_identity_ref, desktop_binding_ref, satelle_version,
                    operation_kind, status, started_at, finished_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6, NULL)",
                params![
                    plan.run_id,
                    host_identity.as_str(),
                    plan.desktop_binding.as_ref().map(DesktopBindingRef::as_str),
                    env!("CARGO_PKG_VERSION"),
                    plan.operation_kind.as_str(),
                    format_time(plan.started_at)?,
                ],
            )
            .map_err(setup_write_error)?;
        for (order, action) in plan.actions.iter().enumerate() {
            let order = i64::try_from(order)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
            transaction
                .execute(
                    "INSERT INTO setup_actions (
                        run_id, action_id, action_order, action_label, status,
                        started_at, finished_at, retry_safe, error_code, exit_status,
                        recovery_hint, skip_reason
                     ) VALUES (?1, ?2, ?3, ?4, 'planned', NULL, NULL, ?5, NULL, NULL, NULL, NULL)",
                    params![
                        plan.run_id,
                        action.action_id,
                        order,
                        action.label,
                        i64::from(action.retry_safe),
                    ],
                )
                .map_err(setup_write_error)?;
        }
        transaction
            .execute(
                "INSERT INTO maintenance_leases (
                    host_identity_ref, operation_id, owner_process_id,
                    owner_process_start_ref, owner_boot_identity_ref,
                    acquired_at, heartbeat_at, lease_state
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 'active')",
                params![
                    host_identity.as_str(),
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    format_time(owner.acquired_at)?,
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::LeaseConflict, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(MaintenanceLeaseCapability::new(owner))
    }

    pub(crate) fn start_setup_action(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        action_id: &str,
        started_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let run_id = capability.operation_id();
        let action_id = validated_private_reference(action_id.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_active_maintenance_owner(&transaction, capability)?;
        require_run_and_predecessor_times(&transaction, run_id, &action_id, started_at)?;
        let changed = transaction
            .execute(
                "UPDATE setup_actions
                 SET status = 'started', started_at = ?3
                 WHERE run_id = ?1 AND action_id = ?2 AND status = 'planned'
                   AND EXISTS (
                       SELECT 1 FROM setup_runs
                       WHERE setup_runs.run_id = setup_actions.run_id
                         AND setup_runs.status = 'running'
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM setup_actions AS predecessor
                       WHERE predecessor.run_id = setup_actions.run_id
                         AND predecessor.action_order < setup_actions.action_order
                         AND predecessor.status NOT IN ('completed', 'skipped')
                   )",
                params![run_id, action_id, format_time(started_at)?],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_one_transition(changed)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn complete_setup_action_after_verified_postcondition(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        action_id: &str,
        completed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        self.transition_started_action(
            capability,
            action_id,
            StartedActionOutcome::Completed,
            completed_at,
        )
    }

    pub(crate) fn fail_setup_action(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        action_id: &str,
        error_code: &str,
        exit_status: Option<i64>,
        recovery_hint: Option<&str>,
        failed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let error_code = validated_private_reference(error_code.to_string())?;
        let recovery_hint = recovery_hint
            .map(|hint| normalized_text(hint.to_string(), MAX_RECOVERY_HINT_BYTES))
            .transpose()?;
        self.transition_started_action(
            capability,
            action_id,
            StartedActionOutcome::Failed {
                error_code: &error_code,
                exit_status,
                recovery_hint: recovery_hint.as_deref(),
            },
            failed_at,
        )
    }

    pub(crate) fn skip_setup_action(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        action_id: &str,
        reason: SetupActionSkipReason,
        skipped_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let run_id = capability.operation_id();
        let action_id = validated_private_reference(action_id.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_active_maintenance_owner(&transaction, capability)?;
        require_run_and_predecessor_times(&transaction, run_id, &action_id, skipped_at)?;
        let changed = transaction
            .execute(
                "UPDATE setup_actions
                 SET status = 'skipped', finished_at = ?3, skip_reason = ?4
                 WHERE run_id = ?1 AND action_id = ?2 AND status = 'planned'
                   AND EXISTS (
                       SELECT 1 FROM setup_runs
                       WHERE setup_runs.run_id = setup_actions.run_id
                         AND setup_runs.status = 'running'
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM setup_actions AS predecessor
                       WHERE predecessor.run_id = setup_actions.run_id
                         AND predecessor.action_order < setup_actions.action_order
                         AND predecessor.status IN ('planned', 'started')
                   )",
                params![run_id, action_id, format_time(skipped_at)?, reason.as_str()],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_one_transition(changed)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    /// Commits the terminal setup ledger state and releases Host maintenance
    /// ownership in the same SQLite transaction. Operations with a live
    /// postcheck must use the operational postcheck finalizer instead.
    pub(crate) fn finish_setup_run_and_release_maintenance(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        finished_at: OffsetDateTime,
    ) -> Result<SetupRunStatus, StorageError> {
        let owner = capability.lease_owner();
        let run_id = capability.operation_id();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_active_maintenance_owner(&transaction, capability)?;
        let status = finish_setup_run_in_transaction(&transaction, run_id, finished_at)?;
        let released = transaction
            .execute(
                "DELETE FROM maintenance_leases
                 WHERE operation_id = ?1
                   AND owner_process_id = ?2
                   AND owner_process_start_ref = ?3
                   AND owner_boot_identity_ref = ?4
                   AND acquired_at = ?5
                   AND lease_state = 'active'
                   AND NOT EXISTS (
                       SELECT 1 FROM control_leases
                       WHERE control_leases.operation_id = maintenance_leases.operation_id
                   )",
                params![
                    run_id,
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    format_time(owner.acquired_at)?,
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_one_transition(released)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(status)
    }

    /// Commits live postcondition reconciliation and releases the exact
    /// restart-preserved owner in one transaction. Any unknown or missing
    /// postcondition leaves the ledger and ownership untouched.
    pub(crate) fn reconcile_maintenance_after_restart(
        &mut self,
        subject: &MaintenanceRecoverySubject,
        verified: &VerifiedSetupPostconditions,
    ) -> Result<Option<SetupRunStatus>, StorageError> {
        if subject.has_postcheck() {
            // A postcheck needs its readiness-specific recovery observation;
            // action probes alone cannot truthfully finalize that Control Lease.
            return Ok(None);
        }
        let mut outcomes = Vec::new();
        for action in subject.run().actions() {
            if action.status() != SetupActionStatus::OutcomeUnknown {
                continue;
            }
            let satisfied = verified
                .outcome(action.action_id())
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
            outcomes.push((action.action_id(), satisfied));
        }
        let unsatisfied_code = match subject.operation_kind() {
            SetupOperationKind::Setup => "setup_postcondition_unsatisfied",
            SetupOperationKind::Repair => "repair_postcondition_unsatisfied",
            SetupOperationKind::HostUpdate => "host_update_postcondition_unsatisfied",
            SetupOperationKind::StorageMigration => "storage_migration_postcondition_unsatisfied",
            SetupOperationKind::ServiceRestart => "service_restart_postcondition_unsatisfied",
        };
        let owner = &subject.owner;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let reconciled_at = subject
            .run()
            .actions()
            .iter()
            .filter_map(SetupActionRecord::finished_at)
            .fold(
                OffsetDateTime::now_utc().max(subject.run().started_at()),
                OffsetDateTime::max,
            );
        require_recovery_maintenance_owner(&transaction, subject)?;
        for (action_id, satisfied) in outcomes {
            let (status, error_code, recovery_hint) = if satisfied {
                ("completed", None, None)
            } else {
                (
                    "failed",
                    Some(unsatisfied_code),
                    Some("inspect the failed postcondition before retrying maintenance"),
                )
            };
            require_one_transition(
                transaction
                    .execute(
                        "UPDATE setup_actions
                         SET status = ?3, finished_at = ?4, error_code = ?5,
                             recovery_hint = ?6
                         WHERE run_id = ?1 AND action_id = ?2
                           AND status = 'outcome_unknown'",
                        params![
                            subject.operation_id(),
                            action_id,
                            status,
                            format_time(reconciled_at)?,
                            error_code,
                            recovery_hint,
                        ],
                    )
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?,
            )?;
        }
        transaction
            .execute(
                "UPDATE setup_actions
                 SET status = 'skipped', finished_at = ?2,
                     skip_reason = 'dependency_failed'
                 WHERE run_id = ?1 AND status = 'planned'",
                params![subject.operation_id(), format_time(reconciled_at)?],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let status = terminal_setup_status(&transaction, subject.operation_id())?;
        require_one_transition(
            transaction
                .execute(
                    "UPDATE setup_runs SET status = ?2, finished_at = ?3
                     WHERE run_id = ?1 AND status = 'outcome_unknown'",
                    params![
                        subject.operation_id(),
                        status.as_str(),
                        format_time(reconciled_at)?,
                    ],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?,
        )?;
        require_one_transition(
            transaction
                .execute(
                    "DELETE FROM maintenance_leases
                     WHERE operation_id = ?1
                       AND owner_process_id = ?2
                       AND owner_process_start_ref = ?3
                       AND owner_boot_identity_ref = ?4
                       AND acquired_at = ?5
                       AND lease_state = 'recovery_pending'
                       AND NOT EXISTS (
                           SELECT 1 FROM control_leases
                           WHERE control_leases.operation_id = maintenance_leases.operation_id
                       )",
                    params![
                        owner.operation_id.as_str(),
                        i64::from(owner.process_id),
                        owner.process_start_ref.as_str(),
                        owner.boot_identity_ref.as_str(),
                        format_time(owner.acquired_at)?,
                    ],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(Some(status))
    }

    pub(crate) fn load_setup_run(
        &self,
        run_id: &str,
    ) -> Result<Option<SetupRunRecord>, StorageError> {
        let run_id = validated_private_reference(run_id.to_string())?;
        let run = self
            .connection
            .query_row(
                "SELECT run_id, operation_kind, desktop_binding_ref, satelle_version,
                        status, started_at, finished_at
                 FROM setup_runs WHERE run_id = ?1",
                [&run_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        let Some((
            run_id,
            operation_kind,
            desktop_binding,
            version,
            status,
            started_at,
            finished_at,
        )) = run
        else {
            return Ok(None);
        };
        let desktop_binding = desktop_binding
            .map(DesktopBindingRef::new)
            .transpose()
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT action_id, action_order, action_label, status, started_at,
                        finished_at, retry_safe, error_code, exit_status, recovery_hint,
                        skip_reason
                 FROM setup_actions WHERE run_id = ?1 ORDER BY action_order",
            )
            .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        let rows = statement
            .query_map([&run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        let mut actions = Vec::new();
        for row in rows {
            let (
                action_id,
                order,
                label,
                status,
                started_at,
                finished_at,
                retry_safe,
                error_code,
                exit_status,
                recovery_hint,
                skip_reason,
            ) = row.map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            actions.push(SetupActionRecord {
                action_id: validated_stored_private_reference(action_id)?,
                order: usize::try_from(order)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                label: normalized_stored_text(label, MAX_ACTION_LABEL_BYTES)?,
                status: SetupActionStatus::parse(&status)?,
                started_at: started_at.as_deref().map(parse_time).transpose()?,
                finished_at: finished_at.as_deref().map(parse_time).transpose()?,
                retry_safe: parse_boolean(retry_safe)?,
                error_code: error_code
                    .map(validated_stored_private_reference)
                    .transpose()?,
                exit_status,
                recovery_hint: recovery_hint
                    .map(|hint| normalized_stored_text(hint, MAX_RECOVERY_HINT_BYTES))
                    .transpose()?,
                skip_reason: skip_reason
                    .as_deref()
                    .map(SetupActionSkipReason::parse)
                    .transpose()?,
            });
        }
        Ok(Some(SetupRunRecord {
            run_id: validated_stored_private_reference(run_id)?,
            operation_kind: SetupOperationKind::parse(&operation_kind)?,
            desktop_binding,
            satelle_version: validated_stored_private_reference(version)?,
            status: SetupRunStatus::parse(&status)?,
            started_at: parse_time(&started_at)?,
            finished_at: finished_at.as_deref().map(parse_time).transpose()?,
            actions,
        }))
    }

    /// Combines current live probes with the latest retained record for each
    /// action. Missing history is intentionally not an error: current probes
    /// can produce a complete repair plan without the ledger.
    pub(crate) fn plan_setup_repair(
        &self,
        desktop_binding: Option<&DesktopBindingRef>,
        probes: &[SetupRepairProbe],
    ) -> Result<SetupRepairPlan, StorageError> {
        let mut action_ids = HashSet::with_capacity(probes.len());
        if probes
            .iter()
            .any(|probe| !action_ids.insert(probe.action.action_id.as_str()))
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        if active_setup_run_in_scope(&self.connection, desktop_binding)? {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }

        let history = self.latest_setup_actions(desktop_binding)?;
        let actions = probes
            .iter()
            .map(|probe| {
                let previous = history.get(probe.action.action_id.as_str());
                // A newer definition cannot silently upgrade a historically
                // unsafe action into an unattended retry.
                let retry_safe =
                    probe.action.retry_safe && previous.is_none_or(|action| action.retry_safe);
                let decision = match probe.postcondition {
                    SetupRepairPostcondition::Satisfied => SetupRepairDecision::NoActionRequired,
                    SetupRepairPostcondition::Unknown => SetupRepairDecision::ProbeRequired,
                    SetupRepairPostcondition::Unsatisfied if retry_safe => {
                        SetupRepairDecision::RetryAutomatically
                    }
                    SetupRepairPostcondition::Unsatisfied => {
                        SetupRepairDecision::OperatorActionRequired
                    }
                };
                SetupRepairAction {
                    action_id: probe.action.action_id.clone(),
                    label: probe.action.label.clone(),
                    decision,
                    retry_safe,
                    previous_run_id: previous.map(|action| action.run_id.clone()),
                    previous_status: previous.map(|action| action.status),
                }
            })
            .collect();
        Ok(SetupRepairPlan { actions })
    }

    fn latest_setup_actions(
        &self,
        desktop_binding: Option<&DesktopBindingRef>,
    ) -> Result<HashMap<String, PreviousSetupAction>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT runs.rowid, runs.run_id, actions.action_id, actions.status,
                        actions.retry_safe
                 FROM setup_actions AS actions
                 JOIN setup_runs AS runs ON runs.run_id = actions.run_id
                 WHERE runs.satelle_version = ?1
                   AND (
                       (?2 IS NULL AND runs.desktop_binding_ref IS NULL)
                       OR runs.desktop_binding_ref = ?2
                   )",
            )
            .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        let rows = statement
            .query_map(
                params![
                    env!("CARGO_PKG_VERSION"),
                    desktop_binding.map(DesktopBindingRef::as_str)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        let mut latest: HashMap<String, PreviousSetupAction> = HashMap::new();
        for row in rows {
            let (row_id, run_id, action_id, status, retry_safe) =
                row.map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            let run_id = validated_stored_private_reference(run_id)?;
            let action_id = validated_stored_private_reference(action_id)?;
            let status = SetupActionStatus::parse(&status)?;
            let retry_safe = parse_boolean(retry_safe)?;
            if let Some(action) = latest.get_mut(&action_id) {
                // Every compatible record contributes its safety marker. The
                // context shown to callers comes from the most recently
                // inserted run, which remains monotonic across clock changes.
                action.retry_safe &= retry_safe;
                if row_id > action.row_id {
                    action.run_id = run_id;
                    action.status = status;
                    action.row_id = row_id;
                }
                continue;
            }
            latest.insert(
                action_id,
                PreviousSetupAction {
                    run_id,
                    status,
                    retry_safe,
                    row_id,
                },
            );
        }
        Ok(latest)
    }

    fn transition_started_action(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        action_id: &str,
        outcome: StartedActionOutcome<'_>,
        finished_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let run_id = capability.operation_id();
        let action_id = validated_private_reference(action_id.to_string())?;
        let (status, error_code, exit_status, recovery_hint) = match outcome {
            StartedActionOutcome::Completed => ("completed", None, None, None),
            StartedActionOutcome::Failed {
                error_code,
                exit_status,
                recovery_hint,
            } => ("failed", Some(error_code), exit_status, recovery_hint),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_active_maintenance_owner(&transaction, capability)?;
        require_started_action_time(&transaction, run_id, &action_id, finished_at)?;
        let changed = transaction
            .execute(
                "UPDATE setup_actions
                 SET status = ?3, finished_at = ?4, error_code = ?5,
                     exit_status = ?6, recovery_hint = ?7
                 WHERE run_id = ?1 AND action_id = ?2 AND status = 'started'
                   AND EXISTS (
                       SELECT 1 FROM setup_runs
                       WHERE setup_runs.run_id = setup_actions.run_id
                         AND setup_runs.status = 'running'
                   )",
                params![
                    run_id,
                    action_id,
                    status,
                    format_time(finished_at)?,
                    error_code,
                    exit_status,
                    recovery_hint,
                ],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_one_transition(changed)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(super) fn mark_interrupted_setup_actions_outcome_unknown(
        &mut self,
        detected_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        // Seed every interrupted run, including crashes before the first
        // action or between actions. Terminal timestamps contribute to the
        // clamp so a backward wall-clock change cannot violate ledger order.
        let mut run_recovery_times = HashMap::new();
        {
            let mut statement = transaction
                .prepare(
                    "SELECT setup_runs.run_id, setup_runs.started_at,
                            setup_actions.started_at, setup_actions.finished_at
                     FROM setup_runs
                     LEFT JOIN setup_actions USING (run_id)
                     WHERE setup_runs.status = 'running'",
                )
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            for row in rows {
                let (run_id, run_started_at, action_started_at, action_finished_at) = row
                    .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
                let run_id = validated_stored_private_reference(run_id)?;
                let mut recovered_at = detected_at.max(parse_time(&run_started_at)?);
                if let Some(started_at) = action_started_at {
                    recovered_at = recovered_at.max(parse_time(&started_at)?);
                }
                if let Some(finished_at) = action_finished_at {
                    recovered_at = recovered_at.max(parse_time(&finished_at)?);
                }
                run_recovery_times
                    .entry(run_id)
                    .and_modify(|existing: &mut OffsetDateTime| {
                        *existing = (*existing).max(recovered_at);
                    })
                    .or_insert(recovered_at);
            }
        }
        let interrupted_actions = {
            let mut statement = transaction
                .prepare(
                    "SELECT setup_actions.run_id, setup_actions.action_id
                     FROM setup_actions
                     JOIN setup_runs USING (run_id)
                     WHERE setup_actions.status = 'started'
                       AND setup_runs.status = 'running'",
                )
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?
        };
        for (run_id, action_id) in interrupted_actions {
            let run_id = validated_stored_private_reference(run_id)?;
            let action_id = validated_stored_private_reference(action_id)?;
            let recovered_at = *run_recovery_times
                .get(&run_id)
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let changed = transaction
                .execute(
                    "UPDATE setup_actions
                     SET status = 'outcome_unknown', finished_at = ?3, recovery_hint = ?4
                     WHERE run_id = ?1 AND action_id = ?2 AND status = 'started'",
                    params![
                        run_id,
                        action_id,
                        format_time(recovered_at)?,
                        OUTCOME_UNKNOWN_RECOVERY_HINT,
                    ],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            require_one_transition(changed)?;
        }
        for (run_id, recovered_at) in run_recovery_times {
            let changed = transaction
                .execute(
                    "UPDATE setup_runs
                     SET status = 'outcome_unknown', finished_at = ?2
                     WHERE run_id = ?1 AND status = 'running'",
                    params![run_id, format_time(recovered_at)?],
                )
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            require_one_transition(changed)?;
        }
        // A restart never infers that the previous process's external side
        // effect stopped. Durable ownership remains present but changes to the
        // canonical recovery state until action postconditions are reconciled.
        transaction
            .execute(
                "UPDATE maintenance_leases
                 SET lease_state = 'recovery_pending'
                 WHERE lease_state = 'active'",
                [],
            )
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }
}

pub(super) fn finish_setup_run_in_transaction(
    transaction: &Transaction<'_>,
    run_id: &str,
    finished_at: OffsetDateTime,
) -> Result<SetupRunStatus, StorageError> {
    require_running_run(transaction, run_id)?;
    require_run_finish_time(transaction, run_id, finished_at)?;
    let (pending, completed, failed, unknown): (i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT
                sum(CASE WHEN status IN ('planned', 'started') THEN 1 ELSE 0 END),
                sum(CASE WHEN status = 'completed' THEN 1 ELSE 0 END),
                sum(CASE
                    WHEN status = 'failed'
                      OR (status = 'skipped' AND skip_reason = 'dependency_failed')
                    THEN 1 ELSE 0
                END),
                sum(CASE WHEN status = 'outcome_unknown' THEN 1 ELSE 0 END)
             FROM setup_actions WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    if pending != 0 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    let status = if unknown != 0 {
        SetupRunStatus::OutcomeUnknown
    } else if failed == 0 {
        SetupRunStatus::Completed
    } else if completed == 0 {
        SetupRunStatus::Failed
    } else {
        SetupRunStatus::PartialFailure
    };
    let changed = transaction
        .execute(
            "UPDATE setup_runs SET status = ?2, finished_at = ?3
             WHERE run_id = ?1 AND status = 'running'",
            params![run_id, status.as_str(), format_time(finished_at)?],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    require_one_transition(changed)?;
    Ok(status)
}

pub(super) fn mark_setup_run_outcome_unknown_in_transaction(
    transaction: &Transaction<'_>,
    run_id: &str,
    detected_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let changed = transaction
        .execute(
            "UPDATE setup_actions
             SET status = 'outcome_unknown', finished_at = ?2,
                 recovery_hint = ?3
             WHERE run_id = ?1 AND status = 'started'",
            params![
                run_id,
                format_time(detected_at)?,
                OUTCOME_UNKNOWN_RECOVERY_HINT,
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    let _started_actions = changed;
    let changed = transaction
        .execute(
            "UPDATE setup_runs SET status = 'outcome_unknown', finished_at = ?2
             WHERE run_id = ?1 AND status = 'running'",
            params![run_id, format_time(detected_at)?],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    require_one_transition(changed)
}

fn active_setup_run_in_scope(
    connection: &Connection,
    desktop_binding: Option<&DesktopBindingRef>,
) -> Result<bool, StorageError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM setup_runs
                WHERE status = 'running'
                  AND satelle_version = ?1
                  AND (
                      (?2 IS NULL AND desktop_binding_ref IS NULL)
                      OR desktop_binding_ref = ?2
                  )
             )",
            params![
                env!("CARGO_PKG_VERSION"),
                desktop_binding.map(DesktopBindingRef::as_str)
            ],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
}

fn require_running_run(transaction: &Transaction<'_>, run_id: &str) -> Result<(), StorageError> {
    let running = transaction
        .query_row(
            "SELECT status = 'running' FROM setup_runs WHERE run_id = ?1",
            [run_id],
            |row| row.get::<_, bool>(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    if running == Some(true) {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    }
}

fn require_active_maintenance_owner(
    transaction: &Transaction<'_>,
    capability: &MaintenanceLeaseCapability,
) -> Result<(), StorageError> {
    let owner = capability.lease_owner();
    let owned: i64 = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM maintenance_leases
                WHERE operation_id = ?1
                  AND owner_process_id = ?2
                  AND owner_process_start_ref = ?3
                  AND owner_boot_identity_ref = ?4
                  AND acquired_at = ?5
                  AND lease_state = 'active'
             )",
            params![
                owner.operation_id.as_str(),
                i64::from(owner.process_id),
                owner.process_start_ref.as_str(),
                owner.boot_identity_ref.as_str(),
                format_time(owner.acquired_at)?,
            ],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if owned == 1 {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    }
}

fn require_recovery_maintenance_owner(
    transaction: &Transaction<'_>,
    subject: &MaintenanceRecoverySubject,
) -> Result<(), StorageError> {
    let owner = &subject.owner;
    let owned: i64 = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM maintenance_leases
                JOIN setup_runs ON setup_runs.run_id = maintenance_leases.operation_id
                WHERE maintenance_leases.operation_id = ?1
                  AND maintenance_leases.owner_process_id = ?2
                  AND maintenance_leases.owner_process_start_ref = ?3
                  AND maintenance_leases.owner_boot_identity_ref = ?4
                  AND maintenance_leases.acquired_at = ?5
                  AND maintenance_leases.lease_state = 'recovery_pending'
                  AND setup_runs.status = 'outcome_unknown'
             )",
            params![
                owner.operation_id.as_str(),
                i64::from(owner.process_id),
                owner.process_start_ref.as_str(),
                owner.boot_identity_ref.as_str(),
                format_time(owner.acquired_at)?,
            ],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
    if owned == 1 {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    }
}

fn terminal_setup_status(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<SetupRunStatus, StorageError> {
    let (pending, completed, failed, unknown): (i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT
                sum(CASE WHEN status IN ('planned', 'started') THEN 1 ELSE 0 END),
                sum(CASE WHEN status = 'completed' THEN 1 ELSE 0 END),
                sum(CASE WHEN status = 'failed' OR
                    (status = 'skipped' AND skip_reason = 'dependency_failed')
                    THEN 1 ELSE 0 END),
                sum(CASE WHEN status = 'outcome_unknown' THEN 1 ELSE 0 END)
             FROM setup_actions WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    if pending != 0 || unknown != 0 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    Ok(if failed == 0 {
        SetupRunStatus::Completed
    } else if completed == 0 {
        SetupRunStatus::Failed
    } else {
        SetupRunStatus::PartialFailure
    })
}

fn require_run_and_predecessor_times(
    transaction: &Transaction<'_>,
    run_id: &str,
    action_id: &str,
    transition_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let run_started_at = load_run_started_at(transaction, run_id)?;
    require_not_before(transition_at, &run_started_at)?;

    let mut statement = transaction
        .prepare(
            "SELECT predecessor.status, predecessor.finished_at
             FROM setup_actions AS predecessor
             JOIN setup_actions AS current
               ON current.run_id = predecessor.run_id
             WHERE current.run_id = ?1 AND current.action_id = ?2
               AND predecessor.action_order < current.action_order",
        )
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    let rows = statement
        .query_map(params![run_id, action_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    for row in rows {
        let (status, finished_at) =
            row.map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        if matches!(
            SetupActionStatus::parse(&status)?,
            SetupActionStatus::Completed
                | SetupActionStatus::Failed
                | SetupActionStatus::Skipped
                | SetupActionStatus::OutcomeUnknown
        ) {
            let finished_at = finished_at
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            require_not_before(transition_at, &finished_at)?;
        }
    }
    Ok(())
}

fn require_started_action_time(
    transaction: &Transaction<'_>,
    run_id: &str,
    action_id: &str,
    finished_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let action = transaction
        .query_row(
            "SELECT status, started_at FROM setup_actions
             WHERE run_id = ?1 AND action_id = ?2",
            params![run_id, action_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    let Some((status, started_at)) = action else {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    };
    if SetupActionStatus::parse(&status)? != SetupActionStatus::Started {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    let started_at =
        started_at.ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    require_not_before(finished_at, &started_at)
}

fn require_run_finish_time(
    transaction: &Transaction<'_>,
    run_id: &str,
    finished_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let run_started_at = load_run_started_at(transaction, run_id)?;
    require_not_before(finished_at, &run_started_at)?;

    let mut statement = transaction
        .prepare("SELECT status, finished_at FROM setup_actions WHERE run_id = ?1")
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
    for row in rows {
        let (status, action_finished_at) =
            row.map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
        if matches!(
            SetupActionStatus::parse(&status)?,
            SetupActionStatus::Completed
                | SetupActionStatus::Failed
                | SetupActionStatus::Skipped
                | SetupActionStatus::OutcomeUnknown
        ) {
            let action_finished_at = action_finished_at
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            require_not_before(finished_at, &action_finished_at)?;
        }
    }
    Ok(())
}

fn load_run_started_at(
    transaction: &Transaction<'_>,
    run_id: &str,
) -> Result<String, StorageError> {
    transaction
        .query_row(
            "SELECT started_at FROM setup_runs WHERE run_id = ?1",
            [run_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?
        .ok_or_else(|| StorageError::new(StorageErrorKind::StateConflict))
}

fn require_not_before(
    transition_at: OffsetDateTime,
    stored_boundary: &str,
) -> Result<(), StorageError> {
    if transition_at < parse_time(stored_boundary)? {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    } else {
        Ok(())
    }
}

fn require_one_transition(changed: usize) -> Result<(), StorageError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    }
}

fn setup_write_error(source: rusqlite::Error) -> StorageError {
    match source {
        rusqlite::Error::SqliteFailure(error, _)
            if error.code == rusqlite::ffi::ErrorCode::ConstraintViolation =>
        {
            StorageError::with_source(StorageErrorKind::StateConflict, source)
        }
        source => sqlite_error(StorageErrorKind::OperationFailed, source),
    }
}

fn normalized_text(value: String, maximum_bytes: usize) -> Result<String, StorageError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(value)
}

fn normalized_stored_text(value: String, maximum_bytes: usize) -> Result<String, StorageError> {
    normalized_text(value, maximum_bytes)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

fn validated_stored_private_reference(value: String) -> Result<String, StorageError> {
    validated_private_reference(value)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

fn parse_boolean(value: i64) -> Result<bool, StorageError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
    }
}
