use satelle_core::host_update::{HostUpdateReport, HostUpdateStatus};
use satelle_core::{ErrorCode, SatelleError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::thread;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteHostOutcomeStatus {
    Succeeded,
    Unchanged,
    Skipped,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteHostUpdateOutcome {
    pub(crate) host: String,
    pub(crate) status: RemoteHostOutcomeStatus,
    pub(crate) changed: bool,
    pub(crate) report: Option<HostUpdateReport>,
    pub(crate) error_code: Option<ErrorCode>,
    pub(crate) error_message: Option<String>,
    pub(crate) preserved_state: Option<String>,
    pub(crate) recovery_command: Option<String>,
}

impl RemoteHostUpdateOutcome {
    pub(crate) fn completed(
        report: HostUpdateReport,
        profile: Option<&str>,
        components: &[String],
    ) -> Self {
        let manual_action_required = report.status == HostUpdateStatus::ManualActionRequired
            || (report.status != HostUpdateStatus::DryRun && !report.skipped_actions.is_empty());
        let status = if manual_action_required {
            RemoteHostOutcomeStatus::Failed
        } else if report.changed {
            RemoteHostOutcomeStatus::Succeeded
        } else if report.status == HostUpdateStatus::DryRun {
            RemoteHostOutcomeStatus::Skipped
        } else {
            RemoteHostOutcomeStatus::Unchanged
        };
        let recovery_command = manual_action_required.then(|| {
            remote_host_recovery_command(
                &report.host,
                report.recovery_command.clone(),
                profile,
                components,
            )
        });
        Self {
            host: report.host.clone(),
            status,
            changed: report.changed,
            preserved_state: report.preserved_state.clone().or_else(|| {
                manual_action_required.then(|| {
                    if report.changed {
                        "Some remote changes were applied; manual action is required to finish the update."
                            .to_string()
                    } else {
                        "No remote changes were applied; manual action is required.".to_string()
                    }
                })
            }),
            recovery_command: recovery_command.or_else(|| report.recovery_command.clone()),
            report: Some(report),
            error_code: manual_action_required.then_some(ErrorCode::RemoteExecution),
            error_message: manual_action_required
                .then(|| "the Host update requires manual action".to_string()),
        }
    }

    pub(crate) fn failed(
        host: impl Into<String>,
        error: SatelleError,
        profile: Option<&str>,
        components: &[String],
    ) -> Self {
        let host = host.into();
        let changed = error
            .details
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let preserved_state = error
            .details
            .get("preserved_state")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if changed {
                    "The remote update changed state before failure.".to_string()
                } else {
                    "Remote state could not be confirmed after the failure.".to_string()
                }
            });
        let recovery_command =
            remote_host_recovery_command(&host, error.recovery_command, profile, components);
        Self {
            host,
            status: RemoteHostOutcomeStatus::Failed,
            changed,
            report: None,
            error_code: Some(error.code),
            error_message: Some(error.message),
            preserved_state: Some(preserved_state),
            recovery_command: Some(recovery_command),
        }
    }

    pub(crate) fn planning_failed(
        host: impl Into<String>,
        error: SatelleError,
        profile: Option<&str>,
        components: &[String],
    ) -> Self {
        let mut outcome = Self::failed(host, error, profile, components);
        outcome.preserved_state = Some("No remote changes were applied.".to_string());
        outcome
    }

    pub(crate) fn skipped(report: HostUpdateReport) -> Self {
        Self {
            host: report.host.clone(),
            status: RemoteHostOutcomeStatus::Skipped,
            changed: false,
            preserved_state: report.preserved_state.clone(),
            recovery_command: report.recovery_command.clone(),
            report: Some(report),
            error_code: None,
            error_message: None,
        }
    }
}

fn remote_host_recovery_command(
    host: &str,
    recovery_command: Option<String>,
    profile: Option<&str>,
    components: &[String],
) -> String {
    let recovery_command = recovery_command.unwrap_or_else(|| {
        let mut command = format!("satelle host update --host {}", crate::shell_argument(host));
        for component in components {
            command.push_str(&format!(
                " --component {}",
                crate::shell_argument(component)
            ));
        }
        command.push_str(" --no-input --yes");
        command
    });
    match (profile, recovery_command.strip_prefix("satelle ")) {
        (Some(profile), Some(command)) => format!(
            "satelle --profile {} {command}",
            crate::shell_argument(profile)
        ),
        _ => recovery_command,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteHostBatchStatus {
    Succeeded,
    PartialFailure,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct RemoteHostAggregateCounts {
    pub(crate) succeeded: usize,
    pub(crate) unchanged: usize,
    pub(crate) skipped: usize,
    pub(crate) failed: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RemoteHostUpdateBatchReport {
    pub(crate) schema_version: String,
    pub(crate) status: RemoteHostBatchStatus,
    pub(crate) changed: bool,
    pub(crate) remote_hosts: Vec<RemoteHostUpdateOutcome>,
    pub(crate) aggregate_counts: RemoteHostAggregateCounts,
    pub(crate) failed_hosts: Vec<String>,
    pub(crate) recovery_commands: Vec<String>,
}

impl RemoteHostUpdateBatchReport {
    pub(crate) fn new(remote_hosts: Vec<RemoteHostUpdateOutcome>) -> Self {
        let mut aggregate_counts = RemoteHostAggregateCounts::default();
        for outcome in &remote_hosts {
            match outcome.status {
                RemoteHostOutcomeStatus::Succeeded => aggregate_counts.succeeded += 1,
                RemoteHostOutcomeStatus::Unchanged => aggregate_counts.unchanged += 1,
                RemoteHostOutcomeStatus::Skipped => aggregate_counts.skipped += 1,
                RemoteHostOutcomeStatus::Failed => aggregate_counts.failed += 1,
            }
        }
        let failed_hosts = remote_hosts
            .iter()
            .filter(|outcome| outcome.status == RemoteHostOutcomeStatus::Failed)
            .map(|outcome| outcome.host.clone())
            .collect();
        let recovery_commands = remote_hosts
            .iter()
            .filter(|outcome| outcome.status == RemoteHostOutcomeStatus::Failed)
            .filter_map(|outcome| outcome.recovery_command.clone())
            .collect();
        Self {
            schema_version: "satelle.host.update.batch.v1".to_string(),
            status: if aggregate_counts.failed == 0 {
                RemoteHostBatchStatus::Succeeded
            } else {
                RemoteHostBatchStatus::PartialFailure
            },
            changed: remote_hosts.iter().any(|outcome| outcome.changed),
            remote_hosts,
            aggregate_counts,
            failed_hosts,
            recovery_commands,
        }
    }

    pub(crate) const fn has_failures(&self) -> bool {
        matches!(self.status, RemoteHostBatchStatus::PartialFailure)
    }
}

/// Runs one bounded cohort at a time and joins in input order. This keeps
/// output deterministic while allowing the remote I/O inside a cohort to run
/// concurrently.
pub(crate) fn bounded_map<T, R>(
    items: &[T],
    concurrency: usize,
    operation: impl Fn(T) -> R + Sync,
) -> Vec<(T, thread::Result<R>)>
where
    T: Clone + Send,
    R: Send,
{
    debug_assert!(concurrency > 0);
    let mut results = Vec::with_capacity(items.len());
    for cohort in items.chunks(concurrency) {
        thread::scope(|scope| {
            let operation = &operation;
            let tasks = cohort
                .iter()
                .cloned()
                .map(|item| {
                    let task_item = item.clone();
                    (item, scope.spawn(move || operation(task_item)))
                })
                .collect::<Vec<_>>();
            for (item, task) in tasks {
                // Retain the input so callers can turn a failed worker into
                // the required terminal outcome for that exact Host.
                results.push((item, task.join()));
            }
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    #[test]
    fn bounded_map_preserves_input_order_and_enforces_the_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(0usize), Condvar::new()));
        let values = (0..8).collect::<Vec<_>>();

        let outputs = bounded_map(&values, 4, |value| {
            let observed = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(observed, Ordering::SeqCst);
            let (count, ready) = &*gate;
            let mut count = count.lock().expect("lock test cohort");
            *count += 1;
            if *count % 4 == 0 {
                ready.notify_all();
            } else {
                count = ready
                    .wait_while(count, |count| *count % 4 != 0)
                    .expect("wait for bounded cohort");
            }
            drop(count);
            active.fetch_sub(1, Ordering::SeqCst);
            value * 2
        });

        assert_eq!(
            outputs
                .into_iter()
                .map(|(_, output)| output.expect("worker completes"))
                .collect::<Vec<_>>(),
            [0, 2, 4, 6, 8, 10, 12, 14]
        );
        assert_eq!(maximum.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn bounded_map_with_limit_one_is_serial_and_does_not_fail_fast() {
        let active = AtomicUsize::new(0);
        let maximum = AtomicUsize::new(0);
        let attempted = AtomicUsize::new(0);

        let outputs = bounded_map(&[0, 1, 2, 3], 1, |value| {
            let observed = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum.fetch_max(observed, Ordering::SeqCst);
            attempted.fetch_add(1, Ordering::SeqCst);
            active.fetch_sub(1, Ordering::SeqCst);
            if value == 1 { Err(value) } else { Ok(value) }
        });

        assert_eq!(
            outputs
                .into_iter()
                .map(|(_, output)| output.expect("worker completes"))
                .collect::<Vec<_>>(),
            [Ok(0), Err(1), Ok(2), Ok(3)]
        );
        assert_eq!(attempted.load(Ordering::SeqCst), 4);
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn bounded_map_preserves_the_input_for_a_panicked_worker() {
        let outputs = bounded_map(&["office", "lab"], 2, |host| {
            assert_ne!(host, "office", "fixture worker panic");
            host
        });

        assert_eq!(outputs[0].0, "office");
        assert!(outputs[0].1.is_err());
        assert_eq!(outputs[1].0, "lab");
        assert_eq!(outputs[1].1.as_ref().expect("lab completes"), &"lab");
    }

    #[test]
    fn batch_report_records_each_terminal_outcome_class() {
        let succeeded = RemoteHostUpdateOutcome::completed(
            HostUpdateReport::new("changed", Vec::new(), Vec::new())
                .with_applied_action("install-host-artifact")
                .finish_postchecks(),
            None,
            &[],
        );
        let unchanged = RemoteHostUpdateOutcome::completed(
            HostUpdateReport::new("current", Vec::new(), Vec::new()),
            None,
            &[],
        );
        let skipped = RemoteHostUpdateOutcome::skipped(HostUpdateReport::new(
            "declined",
            Vec::new(),
            Vec::new(),
        ));
        let failed = RemoteHostUpdateOutcome::failed(
            "offline",
            SatelleError {
                code: ErrorCode::HostUnreachable,
                message: "Host is unreachable".to_string(),
                recovery_command: Some("satelle doctor --host offline".to_string()),
                source_detail: None,
                details: BTreeMap::new(),
            },
            None,
            &[],
        );

        let report = RemoteHostUpdateBatchReport::new(vec![succeeded, unchanged, skipped, failed]);

        assert_eq!(report.status, RemoteHostBatchStatus::PartialFailure);
        assert!(report.changed);
        assert_eq!(
            report.aggregate_counts,
            RemoteHostAggregateCounts {
                succeeded: 1,
                unchanged: 1,
                skipped: 1,
                failed: 1,
            }
        );
        assert_eq!(
            report
                .remote_hosts
                .iter()
                .map(|outcome| outcome.status)
                .collect::<Vec<_>>(),
            [
                RemoteHostOutcomeStatus::Succeeded,
                RemoteHostOutcomeStatus::Unchanged,
                RemoteHostOutcomeStatus::Skipped,
                RemoteHostOutcomeStatus::Failed,
            ]
        );
    }

    #[test]
    fn automatic_manual_action_is_a_failed_terminal_outcome() {
        let mut report = HostUpdateReport::new("unsafe", Vec::new(), Vec::new());
        report.status = HostUpdateStatus::ManualActionRequired;
        report.skipped_actions = vec!["install-host-artifact".to_string()];
        report.changed = true;

        let outcome =
            RemoteHostUpdateOutcome::completed(report, Some("team profile"), &["host".to_string()]);

        assert_eq!(outcome.status, RemoteHostOutcomeStatus::Failed);
        assert!(outcome.changed);
        assert_eq!(outcome.error_code, Some(ErrorCode::RemoteExecution));
        assert_eq!(
            outcome.preserved_state.as_deref(),
            Some(
                "Some remote changes were applied; manual action is required to finish the update."
            )
        );
        assert_eq!(
            outcome.recovery_command.as_deref(),
            Some(
                "satelle --profile 'team profile' host update --host unsafe --component host --no-input --yes"
            )
        );
    }

    #[test]
    fn aggregate_recovery_commands_belong_only_to_failed_hosts() {
        let mut skipped = RemoteHostUpdateOutcome::skipped(HostUpdateReport::new(
            "manual",
            Vec::new(),
            Vec::new(),
        ));
        skipped.recovery_command = Some("satelle host update --host manual".to_string());
        let failed = RemoteHostUpdateOutcome::failed(
            "broken",
            SatelleError {
                code: ErrorCode::RemoteExecution,
                message: "remote update failed".to_string(),
                recovery_command: Some("satelle repair --host broken".to_string()),
                source_detail: None,
                details: BTreeMap::new(),
            },
            None,
            &["codex".to_string()],
        );

        let report = RemoteHostUpdateBatchReport::new(vec![skipped, failed]);

        assert_eq!(report.failed_hosts, ["broken"]);
        assert_eq!(report.recovery_commands, ["satelle repair --host broken"]);
    }

    #[test]
    fn planning_failures_record_that_remote_state_was_not_changed() {
        let outcome = RemoteHostUpdateOutcome::planning_failed(
            "offline",
            SatelleError {
                code: ErrorCode::HostUnreachable,
                message: "Host is unreachable".to_string(),
                recovery_command: Some("satelle doctor --host offline".to_string()),
                source_detail: None,
                details: BTreeMap::new(),
            },
            None,
            &[],
        );

        assert!(!outcome.changed);
        assert_eq!(
            outcome.preserved_state.as_deref(),
            Some("No remote changes were applied.")
        );
    }

    #[test]
    fn failed_hosts_always_include_state_and_shell_safe_recovery() {
        let outcome = RemoteHostUpdateOutcome::failed(
            "remote host'; touch /tmp/pwn",
            SatelleError {
                code: ErrorCode::HostUnreachable,
                message: "Host is unreachable".to_string(),
                recovery_command: None,
                source_detail: None,
                details: BTreeMap::new(),
            },
            None,
            &["codex".to_string()],
        );

        assert_eq!(
            outcome.preserved_state.as_deref(),
            Some("Remote state could not be confirmed after the failure.")
        );
        assert_eq!(
            outcome.recovery_command.as_deref(),
            Some(
                "satelle host update --host 'remote host'\"'\"'; touch /tmp/pwn' --component codex --no-input --yes"
            )
        );
    }

    #[test]
    fn failed_host_recovery_preserves_the_selected_profile() {
        let outcome = RemoteHostUpdateOutcome::failed(
            "office",
            SatelleError {
                code: ErrorCode::RemoteExecution,
                message: "remote update failed".to_string(),
                recovery_command: Some("satelle repair --host office".to_string()),
                source_detail: None,
                details: BTreeMap::new(),
            },
            Some("team profile"),
            &["codex".to_string()],
        );

        assert_eq!(
            outcome.recovery_command.as_deref(),
            Some("satelle --profile 'team profile' repair --host office")
        );
    }
}
