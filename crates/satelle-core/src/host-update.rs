use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HostUpdateSchemaVersion {
    #[serde(rename = "satelle.host.update.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateComponent {
    Host,
    Codex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateTarget {
    HostDaemon,
    HostDaemonService,
    CodexRuntime,
    CodexNativeComputerUse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateDisposition {
    Current,
    Install,
    Update,
    SkippedUnsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateRestartImpact {
    None,
    HostDaemon,
    CodexRuntime,
    NativeComputerUse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateVersionSource {
    InvokingCliRelease,
    HostCompatibilityRequirement,
    CodexCompatibilityRequirement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateStatus {
    Planned,
    DryRun,
    UpToDate,
    Applied,
    PartialFailure,
    PostcheckFailed,
    ManualActionRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdatePostcheckStatus {
    Planned,
    Passed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdatePostcheck {
    pub check_id: String,
    pub status: HostUpdatePostcheckStatus,
    pub summary: String,
}

impl HostUpdatePostcheck {
    pub fn planned(check_id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            check_id: check_id.into(),
            status: HostUpdatePostcheckStatus::Planned,
            summary: summary.into(),
        }
    }

    pub fn passed(check_id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            check_id: check_id.into(),
            status: HostUpdatePostcheckStatus::Passed,
            summary: summary.into(),
        }
    }

    pub fn failed(check_id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            check_id: check_id.into(),
            status: HostUpdatePostcheckStatus::Failed,
            summary: summary.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexComponentOwnership {
    CodexOwned,
    Ambiguous,
}

/// Typed Host evidence used to plan Codex-owned updates. Raw probe output does
/// not cross this boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CodexUpdateEvidence {
    pub runtime_ownership: CodexComponentOwnership,
    pub native_component_ownership: CodexComponentOwnership,
    pub runtime_current_version: Option<String>,
    pub native_component_current_version: Option<String>,
    pub required_version: String,
    pub runtime_update_required: bool,
    pub native_update_required: bool,
    pub runtime_compatibility_reason: Option<RepairCompatibilityReason>,
    pub native_component_compatibility_reason: Option<RepairCompatibilityReason>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdateMutation {
    pub operation: String,
    pub remote_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdateTargetPlan {
    pub target: HostUpdateTarget,
    pub current_version: Option<String>,
    pub target_version: String,
    pub version_source: HostUpdateVersionSource,
    pub disposition: HostUpdateDisposition,
    pub restart_impact: HostUpdateRestartImpact,
    pub remote_mutations: Vec<HostUpdateMutation>,
}

impl HostUpdateTargetPlan {
    pub fn requires_mutation(&self) -> bool {
        matches!(
            self.disposition,
            HostUpdateDisposition::Install | HostUpdateDisposition::Update
        ) && !self.remote_mutations.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdateReport {
    pub schema_version: HostUpdateSchemaVersion,
    pub host: String,
    pub status: HostUpdateStatus,
    pub reusable_plan: bool,
    pub changed: bool,
    pub checked_components: Vec<HostUpdateComponent>,
    pub targets: Vec<HostUpdateTargetPlan>,
    pub planned_actions: Vec<String>,
    pub applied_actions: Vec<String>,
    pub skipped_actions: Vec<String>,
    pub postcheck_results: Vec<HostUpdatePostcheck>,
    pub invalidated_caches: Vec<String>,
    pub preserved_state: Option<String>,
    pub recovery_command: Option<String>,
    pub confirmation_required: bool,
}

impl HostUpdateReport {
    pub fn new(
        host: impl Into<String>,
        checked_components: Vec<HostUpdateComponent>,
        targets: Vec<HostUpdateTargetPlan>,
    ) -> Self {
        let confirmation_required = targets.iter().any(HostUpdateTargetPlan::requires_mutation);
        let mut planned_actions: Vec<String> = targets
            .iter()
            .filter(|target| target.requires_mutation())
            .flat_map(|target| target.remote_mutations.iter())
            .map(|mutation| mutation.operation.clone())
            .collect();
        if targets.iter().any(|target| {
            target.requires_mutation()
                && target.restart_impact == HostUpdateRestartImpact::HostDaemon
        }) {
            push_unique_action(&mut planned_actions, "restart-host-daemon");
        }
        if confirmation_required {
            push_unique_action(&mut planned_actions, "invalidate-readiness-caches");
            push_unique_action(&mut planned_actions, "host-update-postcheck");
        }
        let skipped_actions: Vec<String> = targets
            .iter()
            .filter(|target| target.disposition == HostUpdateDisposition::SkippedUnsupported)
            .flat_map(|target| target.remote_mutations.iter())
            .map(|mutation| mutation.operation.clone())
            .collect();
        let postcheck_results = planned_postchecks(&targets);
        Self {
            schema_version: HostUpdateSchemaVersion::V1,
            host: host.into(),
            status: if confirmation_required {
                HostUpdateStatus::Planned
            } else if !skipped_actions.is_empty() {
                HostUpdateStatus::ManualActionRequired
            } else {
                HostUpdateStatus::UpToDate
            },
            reusable_plan: false,
            changed: false,
            checked_components,
            targets,
            planned_actions,
            applied_actions: Vec::new(),
            skipped_actions,
            postcheck_results,
            invalidated_caches: Vec::new(),
            preserved_state: None,
            recovery_command: None,
            confirmation_required,
        }
    }

    pub fn into_dry_run(mut self) -> Self {
        self.status = if self.confirmation_required {
            HostUpdateStatus::DryRun
        } else if !self.skipped_actions.is_empty() {
            HostUpdateStatus::ManualActionRequired
        } else {
            HostUpdateStatus::UpToDate
        };
        self.reusable_plan = false;
        self
    }

    pub fn with_applied_action(mut self, action_id: impl Into<String>) -> Self {
        self.applied_actions.push(action_id.into());
        self.changed = true;
        self
    }

    pub fn with_invalidated_cache(mut self, cache: impl Into<String>) -> Self {
        self.invalidated_caches.push(cache.into());
        self
    }

    pub fn with_postcheck(mut self, postcheck: HostUpdatePostcheck) -> Self {
        if let Some(existing) = self
            .postcheck_results
            .iter_mut()
            .find(|existing| existing.check_id == postcheck.check_id)
        {
            *existing = postcheck;
        } else {
            self.postcheck_results.push(postcheck);
        }
        self
    }

    pub fn finish_postchecks(mut self) -> Self {
        self.status = if self
            .postcheck_results
            .iter()
            .any(|postcheck| postcheck.status == HostUpdatePostcheckStatus::Failed)
        {
            HostUpdateStatus::PostcheckFailed
        } else if self.changed {
            HostUpdateStatus::Applied
        } else {
            HostUpdateStatus::UpToDate
        };
        self
    }
}

fn push_unique_action(actions: &mut Vec<String>, action_id: &str) {
    if !actions.iter().any(|existing| existing == action_id) {
        actions.push(action_id.to_string());
    }
}

fn planned_postchecks(targets: &[HostUpdateTargetPlan]) -> Vec<HostUpdatePostcheck> {
    let mut checks = Vec::new();
    let mut add = |check_id: &str, summary: &str| {
        if !checks
            .iter()
            .any(|check: &HostUpdatePostcheck| check.check_id == check_id)
        {
            checks.push(HostUpdatePostcheck::planned(check_id, summary));
        }
    };

    for target in targets.iter().filter(|target| target.requires_mutation()) {
        match target.target {
            HostUpdateTarget::HostDaemon | HostUpdateTarget::HostDaemonService => {
                add(
                    "host-api-reachable",
                    "Verify authenticated Host API reachability",
                );
                add(
                    "host-version-aligned",
                    "Verify the Host version matches the invoking CLI",
                );
                add(
                    "storage-migrations-current",
                    "Verify required Host storage migrations are current",
                );
                add(
                    "native-computer-use-ready",
                    "Run the native Computer Use readiness smoke test",
                );
            }
            HostUpdateTarget::CodexRuntime => {
                add(
                    "codex-app-server-starts",
                    "Verify the Codex app-server starts",
                );
                add(
                    "codex-control-plane-compatible",
                    "Verify required Codex control-plane protocol compatibility",
                );
                add(
                    "native-computer-use-ready",
                    "Run the native Computer Use readiness smoke test",
                );
            }
            HostUpdateTarget::CodexNativeComputerUse => {
                add(
                    "native-computer-use-ready",
                    "Run the native Computer Use readiness smoke test",
                );
            }
        }
    }
    checks
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairCompatibilityReason {
    Missing,
    Corrupted,
    Unsupported,
    BelowMinimumVersion,
    ControlPlaneIncompatible,
    NativeReadinessBlocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairUpgradeDisposition {
    NotNeeded,
    Required,
    ManualActionRequired,
    RecommendHostUpdate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairStatus {
    Planned,
    DryRun,
    UpToDate,
    Cancelled,
    Applied,
    PartialFailure,
    ManualActionRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RepairUpgradeSchemaVersion {
    #[serde(rename = "satelle.repair.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairLedgerStatus {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairPlanSource {
    SetupLedger,
    LiveProbes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepairUpgradeAction {
    pub action_id: String,
    pub target: HostUpdateTarget,
    pub current_version: Option<String>,
    pub target_version: String,
    pub compatibility_reason: Option<RepairCompatibilityReason>,
    pub version_source: HostUpdateVersionSource,
    pub disposition: RepairUpgradeDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepairUpgradeReport {
    pub schema_version: RepairUpgradeSchemaVersion,
    pub host: String,
    pub status: RepairStatus,
    pub changed: bool,
    pub ledger_status: RepairLedgerStatus,
    pub plan_source: RepairPlanSource,
    pub actions: Vec<RepairUpgradeAction>,
    pub planned_actions: Vec<String>,
    pub applied_actions: Vec<String>,
    pub completed_actions: Vec<String>,
    pub failed_action: Option<String>,
    pub skipped_actions: Vec<String>,
    pub preserved_state: Option<String>,
    pub recovery_command: Option<String>,
    pub cancellation_reason: Option<String>,
}

impl RepairUpgradeReport {
    pub fn new(host: impl Into<String>, actions: Vec<RepairUpgradeAction>) -> Self {
        let planned_actions = if actions.iter().any(|action| {
            action.disposition == RepairUpgradeDisposition::Required
                && matches!(
                    action.target,
                    HostUpdateTarget::HostDaemon | HostUpdateTarget::HostDaemonService
                )
        }) {
            [
                "install-host-artifact",
                "publish-host-service",
                "restart-host-daemon",
                "invalidate-readiness-caches",
                "host-update-postcheck",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        } else {
            actions
                .iter()
                .filter(|action| action.disposition == RepairUpgradeDisposition::Required)
                .map(|action| action.action_id.clone())
                .collect::<Vec<_>>()
        };
        let skipped_actions = actions
            .iter()
            .filter(|action| action.disposition == RepairUpgradeDisposition::ManualActionRequired)
            .map(|action| action.action_id.clone())
            .collect::<Vec<_>>();
        let status = if !planned_actions.is_empty() {
            RepairStatus::Planned
        } else if !skipped_actions.is_empty() {
            RepairStatus::ManualActionRequired
        } else {
            RepairStatus::UpToDate
        };
        Self {
            schema_version: RepairUpgradeSchemaVersion::V1,
            host: host.into(),
            status,
            changed: false,
            ledger_status: RepairLedgerStatus::Unavailable,
            plan_source: RepairPlanSource::LiveProbes,
            actions,
            planned_actions,
            applied_actions: Vec::new(),
            completed_actions: Vec::new(),
            failed_action: None,
            skipped_actions,
            preserved_state: None,
            recovery_command: None,
            cancellation_reason: None,
        }
    }

    pub fn requires_mutation(&self) -> bool {
        !self.planned_actions.is_empty()
    }

    pub fn into_dry_run(mut self) -> Self {
        if self.requires_mutation() {
            self.status = RepairStatus::DryRun;
        }
        self
    }

    pub fn cancelled(mut self) -> Self {
        self.status = RepairStatus::Cancelled;
        self.changed = false;
        self.applied_actions.clear();
        self.completed_actions.clear();
        self.cancellation_reason = Some("user_declined_confirmation".to_string());
        self
    }

    pub fn applied(mut self, completed_actions: Vec<String>) -> Self {
        self.status = RepairStatus::Applied;
        self.changed = !completed_actions.is_empty();
        self.applied_actions.clone_from(&completed_actions);
        self.completed_actions = completed_actions;
        self
    }

    pub fn partial_failure(
        mut self,
        completed_actions: Vec<String>,
        failed_action: impl Into<String>,
    ) -> Self {
        self.status = RepairStatus::PartialFailure;
        self.changed = !completed_actions.is_empty();
        self.applied_actions.clone_from(&completed_actions);
        self.completed_actions = completed_actions;
        self.failed_action = Some(failed_action.into());
        self.preserved_state = Some("completed repair actions were preserved".to_string());
        self.recovery_command = Some(format!(
            "satelle repair --host {} --no-input --yes",
            self.host
        ));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update_target(target: HostUpdateTarget, operation: &str) -> HostUpdateTargetPlan {
        HostUpdateTargetPlan {
            target,
            current_version: Some("1.0.0".to_string()),
            target_version: "1.1.0".to_string(),
            version_source: HostUpdateVersionSource::InvokingCliRelease,
            disposition: HostUpdateDisposition::Update,
            restart_impact: HostUpdateRestartImpact::HostDaemon,
            remote_mutations: vec![HostUpdateMutation {
                operation: operation.to_string(),
                remote_path: None,
            }],
        }
    }

    #[test]
    fn update_report_exposes_stable_planned_action_ids() {
        let report = HostUpdateReport::new(
            "office",
            vec![HostUpdateComponent::Host],
            vec![
                update_target(HostUpdateTarget::HostDaemon, "install-host-artifact"),
                update_target(HostUpdateTarget::HostDaemonService, "publish-host-service"),
            ],
        );

        assert_eq!(report.status, HostUpdateStatus::Planned);
        assert_eq!(
            report.planned_actions,
            [
                "install-host-artifact",
                "publish-host-service",
                "restart-host-daemon",
                "invalidate-readiness-caches",
                "host-update-postcheck",
            ]
        );
        assert!(!report.reusable_plan);
        assert!(!report.changed);
    }

    #[test]
    fn repair_report_has_stable_action_and_terminal_result_contracts() {
        let action = RepairUpgradeAction {
            action_id: "repair-host-daemon".to_string(),
            target: HostUpdateTarget::HostDaemon,
            current_version: Some("1.0.0".to_string()),
            target_version: "1.1.0".to_string(),
            compatibility_reason: Some(RepairCompatibilityReason::BelowMinimumVersion),
            version_source: HostUpdateVersionSource::HostCompatibilityRequirement,
            disposition: RepairUpgradeDisposition::Required,
        };
        let planned = RepairUpgradeReport::new("remote", vec![action]);
        assert_eq!(planned.schema_version, RepairUpgradeSchemaVersion::V1);
        assert_eq!(planned.status, RepairStatus::Planned);
        assert_eq!(
            planned.planned_actions,
            [
                "install-host-artifact",
                "publish-host-service",
                "restart-host-daemon",
                "invalidate-readiness-caches",
                "host-update-postcheck",
            ]
        );

        let cancelled = planned.clone().cancelled();
        assert_eq!(cancelled.status, RepairStatus::Cancelled);
        assert!(!cancelled.changed);
        assert!(cancelled.applied_actions.is_empty());
        assert_eq!(
            cancelled.cancellation_reason.as_deref(),
            Some("user_declined_confirmation")
        );

        let partial = planned.partial_failure(
            vec!["repair-host-daemon".to_string()],
            "repair-native-computer-use",
        );
        assert_eq!(partial.status, RepairStatus::PartialFailure);
        assert!(partial.changed);
        assert_eq!(partial.completed_actions, ["repair-host-daemon"]);
        assert_eq!(
            partial.failed_action.as_deref(),
            Some("repair-native-computer-use")
        );
        assert_eq!(
            partial.recovery_command.as_deref(),
            Some("satelle repair --host remote --no-input --yes")
        );
    }

    #[test]
    fn dry_run_and_up_to_date_results_are_non_mutating() {
        let dry_run = HostUpdateReport::new(
            "office",
            vec![HostUpdateComponent::Host],
            vec![update_target(
                HostUpdateTarget::HostDaemon,
                "install-host-artifact",
            )],
        )
        .into_dry_run();
        assert_eq!(dry_run.status, HostUpdateStatus::DryRun);
        assert!(!dry_run.reusable_plan);
        assert!(!dry_run.changed);
        assert!(dry_run.applied_actions.is_empty());

        let current = HostUpdateTargetPlan {
            target: HostUpdateTarget::HostDaemon,
            current_version: Some("1.1.0".to_string()),
            target_version: "1.1.0".to_string(),
            version_source: HostUpdateVersionSource::InvokingCliRelease,
            disposition: HostUpdateDisposition::Current,
            restart_impact: HostUpdateRestartImpact::None,
            remote_mutations: Vec::new(),
        };
        let up_to_date =
            HostUpdateReport::new("office", vec![HostUpdateComponent::Host], vec![current]);
        assert_eq!(up_to_date.status, HostUpdateStatus::UpToDate);
        assert!(!up_to_date.confirmation_required);
        assert!(up_to_date.planned_actions.is_empty());
    }

    #[test]
    fn applied_and_postcheck_failed_results_preserve_mutation_evidence() {
        let report = HostUpdateReport::new(
            "office",
            vec![HostUpdateComponent::Host],
            vec![update_target(
                HostUpdateTarget::HostDaemon,
                "install-host-artifact",
            )],
        )
        .with_applied_action("install-host-artifact")
        .with_invalidated_cache("native_computer_use")
        .with_postcheck(HostUpdatePostcheck::passed(
            "host-api-reachable",
            "Host API is reachable",
        ))
        .with_postcheck(HostUpdatePostcheck::failed(
            "host-version-aligned",
            "Host version did not match the invoking CLI",
        ))
        .finish_postchecks();

        assert_eq!(report.status, HostUpdateStatus::PostcheckFailed);
        assert!(report.changed);
        assert_eq!(report.applied_actions, ["install-host-artifact"]);
        assert_eq!(report.invalidated_caches, ["native_computer_use"]);
        assert_eq!(report.postcheck_results.len(), 4);
        assert_eq!(
            report
                .postcheck_results
                .iter()
                .map(|postcheck| (&*postcheck.check_id, postcheck.status))
                .collect::<Vec<_>>(),
            [
                ("host-api-reachable", HostUpdatePostcheckStatus::Passed),
                ("host-version-aligned", HostUpdatePostcheckStatus::Failed),
                (
                    "storage-migrations-current",
                    HostUpdatePostcheckStatus::Planned
                ),
                (
                    "native-computer-use-ready",
                    HostUpdatePostcheckStatus::Planned
                ),
            ]
        );
    }
}
