use super::codec::{format_time, parse_time, validated_private_reference};
use super::{Storage, StorageError, StorageErrorKind, sqlite_error};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use satelle_core::session::DesktopBindingRef;
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;

const OUTCOME_UNKNOWN_RECOVERY_HINT: &str =
    "inspect live postconditions before retrying this action";
const MAX_ACTION_LABEL_BYTES: usize = 256;
const MAX_RECOVERY_HINT_BYTES: usize = 512;

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
}

impl SetupOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Repair => "repair",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "setup" => Ok(Self::Setup),
            "repair" => Ok(Self::Repair),
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

impl Storage {
    pub(crate) fn begin_setup_run(&mut self, plan: &SetupRunPlan) -> Result<(), StorageError> {
        let host_identity = self.host_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
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
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }

    pub(crate) fn start_setup_action(
        &mut self,
        run_id: &str,
        action_id: &str,
        started_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let run_id = validated_private_reference(run_id.to_string())?;
        let action_id = validated_private_reference(action_id.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_run_and_predecessor_times(&transaction, &run_id, &action_id, started_at)?;
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
        run_id: &str,
        action_id: &str,
        completed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        self.transition_started_action(
            run_id,
            action_id,
            StartedActionOutcome::Completed,
            completed_at,
        )
    }

    pub(crate) fn fail_setup_action(
        &mut self,
        run_id: &str,
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
            run_id,
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
        run_id: &str,
        action_id: &str,
        reason: SetupActionSkipReason,
        skipped_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let run_id = validated_private_reference(run_id.to_string())?;
        let action_id = validated_private_reference(action_id.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_run_and_predecessor_times(&transaction, &run_id, &action_id, skipped_at)?;
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

    pub(crate) fn finish_setup_run(
        &mut self,
        run_id: &str,
        finished_at: OffsetDateTime,
    ) -> Result<SetupRunStatus, StorageError> {
        let run_id = validated_private_reference(run_id.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        require_running_run(&transaction, &run_id)?;
        require_run_finish_time(&transaction, &run_id, finished_at)?;
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
                [&run_id],
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
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(status)
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

    fn transition_started_action(
        &mut self,
        run_id: &str,
        action_id: &str,
        outcome: StartedActionOutcome<'_>,
        finished_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let run_id = validated_private_reference(run_id.to_string())?;
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
        require_started_action_time(&transaction, &run_id, &action_id, finished_at)?;
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
        let interrupted_actions = {
            let mut statement = transaction
                .prepare(
                    "SELECT setup_actions.run_id, setup_actions.action_id,
                            setup_actions.started_at, setup_runs.started_at
                     FROM setup_actions
                     JOIN setup_runs USING (run_id)
                     WHERE setup_actions.status = 'started'
                       AND setup_runs.status = 'running'",
                )
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|source| sqlite_error(StorageErrorKind::InvalidStoredState, source))?
        };
        let mut run_recovery_times = HashMap::new();
        for (run_id, action_id, action_started_at, run_started_at) in interrupted_actions {
            let recovered_at = detected_at
                .max(parse_time(&action_started_at)?)
                .max(parse_time(&run_started_at)?);
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
            run_recovery_times
                .entry(run_id)
                .and_modify(|existing: &mut OffsetDateTime| {
                    *existing = (*existing).max(recovered_at);
                })
                .or_insert(recovered_at);
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
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))
    }
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
