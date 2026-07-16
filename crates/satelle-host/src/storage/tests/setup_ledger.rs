use super::*;
use crate::storage::{
    SetupActionPlan, SetupActionSkipReason, SetupActionStatus, SetupOperationKind,
    SetupRepairDecision, SetupRepairPostcondition, SetupRepairProbe, SetupRunPlan, SetupRunStatus,
};

fn plan() -> SetupRunPlan {
    plan_with_run_id("setup-run-1")
}

fn plan_with_run_id(run_id: &str) -> SetupRunPlan {
    plan_with_run_id_and_binding(run_id, "desktop-binding-1")
}

fn plan_with_run_id_and_binding(run_id: &str, desktop_binding: &str) -> SetupRunPlan {
    SetupRunPlan::new(
        run_id,
        SetupOperationKind::Setup,
        Some(DesktopBindingRef::new(desktop_binding).unwrap()),
        at(1),
        vec![
            SetupActionPlan::new("install-codex", "Install Codex runtime", true).unwrap(),
            SetupActionPlan::new(
                "configure-computer-use",
                "Configure native Computer Use",
                false,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn setup_action_ledger_migrates_and_persists_ordered_state_transitions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");

    storage
        .begin_setup_run(&plan())
        .expect("persist setup plan");
    let planned = storage
        .load_setup_run("setup-run-1")
        .expect("load setup run")
        .expect("setup run exists");
    assert_eq!(SetupRunStatus::Running, planned.status());
    assert_eq!(2, planned.actions().len());
    assert_eq!(SetupActionStatus::Planned, planned.actions()[0].status());
    assert_eq!(0, planned.actions()[0].order());
    assert_eq!(1, planned.actions()[1].order());

    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .expect("record start before mutation");
    assert_eq!(
        SetupActionStatus::Started,
        storage
            .load_setup_run("setup-run-1")
            .unwrap()
            .unwrap()
            .actions()[0]
            .status()
    );
    storage
        .complete_setup_action_after_verified_postcondition("setup-run-1", "install-codex", at(3))
        .expect("commit verified completion");
    storage
        .skip_setup_action(
            "setup-run-1",
            "configure-computer-use",
            SetupActionSkipReason::AlreadySatisfied,
            at(4),
        )
        .expect("skip an action that needs no mutation");

    let finished = storage
        .finish_setup_run("setup-run-1", at(5))
        .expect("derive terminal run outcome");
    assert_eq!(SetupRunStatus::Completed, finished);
    let stored = storage.load_setup_run("setup-run-1").unwrap().unwrap();
    assert_eq!(SetupRunStatus::Completed, stored.status());
    assert_eq!(SetupActionStatus::Completed, stored.actions()[0].status());
    assert_eq!(SetupActionStatus::Skipped, stored.actions()[1].status());
    assert_eq!(
        Some(SetupActionSkipReason::AlreadySatisfied),
        stored.actions()[1].skip_reason()
    );
}

#[test]
fn setup_action_ledger_rejects_out_of_order_or_conflicting_transitions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage.begin_setup_run(&plan()).unwrap();

    let out_of_order = storage
        .start_setup_action("setup-run-1", "configure-computer-use", at(2))
        .expect_err("later actions wait for preceding terminal outcomes");
    assert_eq!(StorageErrorKind::StateConflict, out_of_order.kind());
    let out_of_order_skip = storage
        .skip_setup_action(
            "setup-run-1",
            "configure-computer-use",
            SetupActionSkipReason::NotRequired,
            at(2),
        )
        .expect_err("later skips also wait for preceding terminal outcomes");
    assert_eq!(StorageErrorKind::StateConflict, out_of_order_skip.kind());

    let complete_before_start = storage
        .complete_setup_action_after_verified_postcondition("setup-run-1", "install-codex", at(2))
        .expect_err("completion requires a durable started state");
    assert_eq!(
        StorageErrorKind::StateConflict,
        complete_before_start.kind()
    );

    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .unwrap();
    let skip_after_start = storage
        .skip_setup_action(
            "setup-run-1",
            "install-codex",
            SetupActionSkipReason::NotRequired,
            at(3),
        )
        .expect_err("a started mutation cannot become skipped");
    assert_eq!(StorageErrorKind::StateConflict, skip_after_start.kind());

    let unfinished = storage
        .finish_setup_run("setup-run-1", at(4))
        .expect_err("a run with active actions cannot become terminal");
    assert_eq!(StorageErrorKind::StateConflict, unfinished.kind());
}

#[test]
fn setup_action_ledger_rejects_backward_transition_times() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage.begin_setup_run(&plan()).unwrap();

    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .start_setup_action("setup-run-1", "install-codex", at(0))
            .unwrap_err()
            .kind()
    );
    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .complete_setup_action_after_verified_postcondition(
                "setup-run-1",
                "install-codex",
                at(1),
            )
            .unwrap_err()
            .kind()
    );
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .fail_setup_action(
                "setup-run-1",
                "install-codex",
                "installer-failed",
                None,
                None,
                at(1),
            )
            .unwrap_err()
            .kind()
    );
    storage
        .complete_setup_action_after_verified_postcondition("setup-run-1", "install-codex", at(3))
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .skip_setup_action(
                "setup-run-1",
                "configure-computer-use",
                SetupActionSkipReason::AlreadySatisfied,
                at(2),
            )
            .unwrap_err()
            .kind()
    );
    storage
        .skip_setup_action(
            "setup-run-1",
            "configure-computer-use",
            SetupActionSkipReason::AlreadySatisfied,
            at(4),
        )
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .finish_setup_run("setup-run-1", at(3))
            .unwrap_err()
            .kind()
    );
    assert_eq!(
        SetupRunStatus::Completed,
        storage.finish_setup_run("setup-run-1", at(5)).unwrap()
    );
}

#[test]
fn setup_run_plans_require_a_nonempty_unique_action_sequence() {
    let empty = SetupRunPlan::new(
        "setup-run-empty",
        SetupOperationKind::Setup,
        None,
        at(1),
        Vec::new(),
    )
    .expect_err("a durable run needs at least one action");
    assert_eq!(satelle_core::ErrorCode::InvalidUsage, empty.code);

    let duplicate = SetupActionPlan::new("same-action", "First action", true).unwrap();
    let duplicate_plan = SetupRunPlan::new(
        "setup-run-duplicate",
        SetupOperationKind::Repair,
        None,
        at(1),
        vec![
            duplicate,
            SetupActionPlan::new("same-action", "Second action", false).unwrap(),
        ],
    )
    .expect_err("stable action identifiers must be unique within a run");
    assert_eq!(satelle_core::ErrorCode::InvalidUsage, duplicate_plan.code);
}

#[test]
fn restart_classifies_started_setup_actions_as_outcome_unknown() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage.begin_setup_run(&plan()).unwrap();
    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .unwrap();
    drop(storage);

    let untouched = Storage::open_without_restart_recovery(state.path())
        .expect("read-only replay open must not classify restart state");
    assert_eq!(
        SetupActionStatus::Started,
        untouched
            .load_setup_run("setup-run-1")
            .unwrap()
            .unwrap()
            .actions()[0]
            .status()
    );
    drop(untouched);

    let (recovered, _) = Storage::open(state.path()).expect("restart recovery opens storage");
    let run = recovered.load_setup_run("setup-run-1").unwrap().unwrap();
    assert_eq!(SetupRunStatus::OutcomeUnknown, run.status());
    assert_eq!(SetupActionStatus::OutcomeUnknown, run.actions()[0].status());
    assert_eq!(SetupActionStatus::Planned, run.actions()[1].status());
    assert_eq!(
        Some("inspect live postconditions before retrying this action"),
        run.actions()[0].recovery_hint()
    );
}

#[test]
fn restart_recovery_clamps_backward_clock_changes_to_durable_start_times() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let future_plan = SetupRunPlan::new(
        "future-run",
        SetupOperationKind::Repair,
        None,
        at(10),
        vec![SetupActionPlan::new("future-action", "Future action", false).unwrap()],
    )
    .unwrap();
    storage.begin_setup_run(&future_plan).unwrap();
    storage
        .start_setup_action("future-run", "future-action", at(20))
        .unwrap();

    storage
        .mark_interrupted_setup_actions_outcome_unknown(at(5))
        .unwrap();

    let recovered = storage.load_setup_run("future-run").unwrap().unwrap();
    assert_eq!(SetupRunStatus::OutcomeUnknown, recovered.status());
    assert_eq!(Some(at(20)), recovered.finished_at());
    assert_eq!(Some(at(20)), recovered.actions()[0].finished_at());
}

#[test]
fn restart_closes_runs_interrupted_before_or_between_actions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .begin_setup_run(&plan_with_run_id("before-first-action"))
        .unwrap();
    storage
        .begin_setup_run(&plan_with_run_id_and_binding(
            "between-actions",
            "desktop-binding-2",
        ))
        .unwrap();
    storage
        .start_setup_action("between-actions", "install-codex", at(2))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition(
            "between-actions",
            "install-codex",
            at(3),
        )
        .unwrap();
    drop(storage);

    let (recovered, _) = Storage::open(state.path()).expect("restart recovery opens storage");
    let before_first = recovered
        .load_setup_run("before-first-action")
        .unwrap()
        .unwrap();
    assert_eq!(SetupRunStatus::OutcomeUnknown, before_first.status());
    assert!(
        before_first
            .actions()
            .iter()
            .all(|action| action.status() == SetupActionStatus::Planned)
    );
    let between = recovered
        .load_setup_run("between-actions")
        .unwrap()
        .unwrap();
    assert_eq!(SetupRunStatus::OutcomeUnknown, between.status());
    assert_eq!(SetupActionStatus::Completed, between.actions()[0].status());
    assert_eq!(SetupActionStatus::Planned, between.actions()[1].status());

    let binding = DesktopBindingRef::new("desktop-binding-1").unwrap();
    let repair = recovered
        .plan_setup_repair(
            Some(&binding),
            &[SetupRepairProbe::try_new(
                "install-codex",
                "Install Codex runtime",
                true,
                SetupRepairPostcondition::Unsatisfied,
            )
            .unwrap()],
        )
        .expect("stale running rows no longer block repair planning");
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        repair.actions()[0].decision()
    );
}

#[test]
fn failed_actions_store_normalized_metadata_without_raw_stream_columns() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage.begin_setup_run(&plan()).unwrap();
    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            "setup-run-1",
            "install-codex",
            "installer-exit-failed",
            Some(17),
            Some("rerun satelle repair after fixing package access"),
            at(3),
        )
        .unwrap();
    storage
        .skip_setup_action(
            "setup-run-1",
            "configure-computer-use",
            SetupActionSkipReason::DependencyFailed,
            at(4),
        )
        .unwrap();
    assert_eq!(
        SetupRunStatus::Failed,
        storage.finish_setup_run("setup-run-1", at(5)).unwrap()
    );

    let run = storage.load_setup_run("setup-run-1").unwrap().unwrap();
    let failed = &run.actions()[0];
    assert_eq!(SetupActionStatus::Failed, failed.status());
    assert_eq!(Some("installer-exit-failed"), failed.error_code());
    assert_eq!(Some(17), failed.exit_status());
    assert_eq!(
        Some("rerun satelle repair after fixing package access"),
        failed.recovery_hint()
    );

    let columns = storage
        .connection_for_test()
        .prepare("SELECT name FROM pragma_table_info('setup_actions') ORDER BY cid")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!columns.iter().any(|column| column.contains("stdout")));
    assert!(!columns.iter().any(|column| column.contains("stderr")));
    assert!(!columns.iter().any(|column| column.contains("output")));
}

#[test]
fn dependency_failed_skips_contribute_to_failed_and_partial_run_outcomes() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");

    storage.begin_setup_run(&plan()).unwrap();
    storage
        .skip_setup_action(
            "setup-run-1",
            "install-codex",
            SetupActionSkipReason::DependencyFailed,
            at(2),
        )
        .unwrap();
    storage
        .skip_setup_action(
            "setup-run-1",
            "configure-computer-use",
            SetupActionSkipReason::DependencyFailed,
            at(3),
        )
        .unwrap();
    assert_eq!(
        SetupRunStatus::Failed,
        storage.finish_setup_run("setup-run-1", at(4)).unwrap()
    );

    storage
        .begin_setup_run(&plan_with_run_id("setup-run-2"))
        .unwrap();
    storage
        .start_setup_action("setup-run-2", "install-codex", at(2))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition("setup-run-2", "install-codex", at(3))
        .unwrap();
    storage
        .skip_setup_action(
            "setup-run-2",
            "configure-computer-use",
            SetupActionSkipReason::DependencyFailed,
            at(4),
        )
        .unwrap();
    assert_eq!(
        SetupRunStatus::PartialFailure,
        storage.finish_setup_run("setup-run-2", at(5)).unwrap()
    );
}

#[test]
fn malformed_persisted_action_references_are_stored_state_errors() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage.begin_setup_run(&plan()).unwrap();
    storage
        .connection_for_test()
        .execute(
            "UPDATE setup_actions SET action_id = '' WHERE action_id = 'install-codex'",
            [],
        )
        .unwrap();

    let error = storage
        .load_setup_run("setup-run-1")
        .expect_err("malformed durable identifiers are storage corruption");
    assert_eq!(StorageErrorKind::InvalidStoredState, error.kind());
}

#[test]
fn repair_waits_for_a_live_postcondition_before_retrying_outcome_unknown() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let setup_plan = plan();
    storage.begin_setup_run(&setup_plan).unwrap();
    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .unwrap();
    storage
        .mark_interrupted_setup_actions_outcome_unknown(at(3))
        .unwrap();

    let unknown = storage
        .plan_setup_repair(
            setup_plan.desktop_binding(),
            &[SetupRepairProbe::try_new(
                "install-codex",
                "Install Codex runtime",
                true,
                SetupRepairPostcondition::Unknown,
            )
            .unwrap()],
        )
        .unwrap();
    assert_eq!(
        SetupRepairDecision::ProbeRequired,
        unknown.actions()[0].decision()
    );

    let satisfied = storage
        .plan_setup_repair(
            setup_plan.desktop_binding(),
            &[SetupRepairProbe::try_new(
                "install-codex",
                "Install Codex runtime",
                true,
                SetupRepairPostcondition::Satisfied,
            )
            .unwrap()],
        )
        .unwrap();
    assert_eq!(
        SetupRepairDecision::NoActionRequired,
        satisfied.actions()[0].decision()
    );

    let unsatisfied = storage
        .plan_setup_repair(
            setup_plan.desktop_binding(),
            &[SetupRepairProbe::try_new(
                "install-codex",
                "Install Codex runtime",
                true,
                SetupRepairPostcondition::Unsatisfied,
            )
            .unwrap()],
        )
        .unwrap();
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        unsatisfied.actions()[0].decision()
    );
    assert_eq!(
        Some(SetupActionStatus::OutcomeUnknown),
        unsatisfied.actions()[0].previous_status()
    );
}

#[test]
fn repair_uses_the_durable_retry_safe_marker_for_incomplete_actions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let safe_run = SetupRunPlan::new(
        "setup-run-safe",
        SetupOperationKind::Setup,
        None,
        at(1),
        vec![SetupActionPlan::new("install-codex", "Install Codex runtime", true).unwrap()],
    )
    .unwrap();
    storage.begin_setup_run(&safe_run).unwrap();
    storage
        .start_setup_action("setup-run-safe", "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            "setup-run-safe",
            "install-codex",
            "installer-failed",
            None,
            None,
            at(3),
        )
        .unwrap();
    storage.finish_setup_run("setup-run-safe", at(4)).unwrap();

    let unsafe_run = SetupRunPlan::new(
        "setup-run-unsafe",
        SetupOperationKind::Setup,
        None,
        at(5),
        vec![
            SetupActionPlan::new(
                "configure-computer-use",
                "Configure native Computer Use",
                false,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    storage.begin_setup_run(&unsafe_run).unwrap();
    storage
        .start_setup_action("setup-run-unsafe", "configure-computer-use", at(6))
        .unwrap();
    storage
        .fail_setup_action(
            "setup-run-unsafe",
            "configure-computer-use",
            "configuration-failed",
            None,
            None,
            at(7),
        )
        .unwrap();
    storage.finish_setup_run("setup-run-unsafe", at(8)).unwrap();

    let repair = storage
        .plan_setup_repair(
            None,
            &[
                SetupRepairProbe::try_new(
                    "install-codex",
                    "Install Codex runtime",
                    true,
                    SetupRepairPostcondition::Unsatisfied,
                )
                .unwrap(),
                // A caller cannot make a historically unsafe action automatic by
                // changing its current probe declaration to retry-safe.
                SetupRepairProbe::try_new(
                    "configure-computer-use",
                    "Configure native Computer Use",
                    true,
                    SetupRepairPostcondition::Unsatisfied,
                )
                .unwrap(),
            ],
        )
        .unwrap();

    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        repair.actions()[0].decision()
    );
    assert_eq!(
        SetupRepairDecision::OperatorActionRequired,
        repair.actions()[1].decision()
    );
    assert!(repair.actions()[0].retry_safe());
    assert!(!repair.actions()[1].retry_safe());
}

#[test]
fn repair_replans_from_live_probes_when_ledger_history_is_missing() {
    let state = TempDir::new().expect("temporary state directory");
    let (storage, _) = Storage::open(state.path()).expect("open storage");

    let repair = storage
        .plan_setup_repair(
            None,
            &[
                SetupRepairProbe::try_new(
                    "already-ready",
                    "Already ready component",
                    true,
                    SetupRepairPostcondition::Satisfied,
                )
                .unwrap(),
                SetupRepairProbe::try_new(
                    "safe-missing-action",
                    "Missing retry-safe component",
                    true,
                    SetupRepairPostcondition::Unsatisfied,
                )
                .unwrap(),
                SetupRepairProbe::try_new(
                    "unsafe-missing-action",
                    "Missing unsafe component",
                    false,
                    SetupRepairPostcondition::Unsatisfied,
                )
                .unwrap(),
            ],
        )
        .unwrap();

    assert_eq!(3, repair.actions().len());
    assert!(
        repair
            .actions()
            .iter()
            .all(|action| action.previous_status().is_none())
    );
    assert_eq!(
        SetupRepairDecision::NoActionRequired,
        repair.actions()[0].decision()
    );
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        repair.actions()[1].decision()
    );
    assert_eq!(
        SetupRepairDecision::OperatorActionRequired,
        repair.actions()[2].decision()
    );
}

#[test]
fn repair_blocks_automatic_retry_while_a_compatible_run_is_active() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let active_binding = DesktopBindingRef::new("active-desktop-binding").unwrap();
    let other_binding = DesktopBindingRef::new("other-desktop-binding").unwrap();
    let active = SetupRunPlan::new(
        "active-run",
        SetupOperationKind::Setup,
        Some(active_binding.clone()),
        at(1),
        vec![SetupActionPlan::new("install-codex", "Install Codex runtime", false).unwrap()],
    )
    .unwrap();
    storage.begin_setup_run(&active).unwrap();
    storage
        .start_setup_action("active-run", "install-codex", at(2))
        .unwrap();
    let probe = SetupRepairProbe::try_new(
        "install-codex",
        "Install Codex runtime",
        true,
        SetupRepairPostcondition::Unsatisfied,
    )
    .unwrap();

    let error = storage
        .plan_setup_repair(Some(&active_binding), std::slice::from_ref(&probe))
        .expect_err("an active host mutation blocks repair planning");
    assert_eq!(StorageErrorKind::StateConflict, error.kind());

    let other_binding_plan = storage
        .plan_setup_repair(Some(&other_binding), std::slice::from_ref(&probe))
        .expect("an active run for another binding does not block repair");
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        other_binding_plan.actions()[0].decision()
    );

    storage
        .connection_for_test()
        .execute(
            "UPDATE setup_runs
             SET satelle_version = 'incompatible-version'
             WHERE run_id = 'active-run'",
            [],
        )
        .unwrap();
    let other_version_plan = storage
        .plan_setup_repair(Some(&active_binding), &[probe])
        .expect("an active run from another version does not block repair");
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        other_version_plan.actions()[0].decision()
    );
}

#[test]
fn beginning_repair_atomically_reserves_compatible_scope() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let binding = DesktopBindingRef::new("repair-desktop-binding").unwrap();
    let other_binding = DesktopBindingRef::new("other-desktop-binding").unwrap();
    let action = SetupActionPlan::new("install-codex", "Install Codex runtime", true).unwrap();
    let first = SetupRunPlan::new(
        "repair-run-1",
        SetupOperationKind::Repair,
        Some(binding.clone()),
        at(1),
        vec![action.clone()],
    )
    .unwrap();
    let competing = SetupRunPlan::new(
        "repair-run-2",
        SetupOperationKind::Repair,
        Some(binding.clone()),
        at(2),
        vec![action.clone()],
    )
    .unwrap();
    let competing_setup = SetupRunPlan::new(
        "setup-run-2",
        SetupOperationKind::Setup,
        Some(binding.clone()),
        at(3),
        vec![action.clone()],
    )
    .unwrap();
    let other_scope = SetupRunPlan::new(
        "repair-run-3",
        SetupOperationKind::Repair,
        Some(other_binding),
        at(4),
        vec![action],
    )
    .unwrap();
    let probe = SetupRepairProbe::try_new(
        "install-codex",
        "Install Codex runtime",
        true,
        SetupRepairPostcondition::Unsatisfied,
    )
    .unwrap();

    // Both callers can plan before either reserves the repair scope.
    storage
        .plan_setup_repair(Some(&binding), std::slice::from_ref(&probe))
        .unwrap();
    storage.plan_setup_repair(Some(&binding), &[probe]).unwrap();

    storage.begin_setup_run(&first).unwrap();
    let error = storage
        .begin_setup_run(&competing)
        .expect_err("the first repair run reserves its compatible scope");
    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    let error = storage
        .begin_setup_run(&competing_setup)
        .expect_err("a setup run cannot bypass the repair reservation");
    assert_eq!(StorageErrorKind::StateConflict, error.kind());
    storage
        .begin_setup_run(&other_scope)
        .expect("another desktop binding has an independent repair scope");
}

#[test]
fn repair_ignores_history_from_other_bindings_or_satelle_versions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let old_binding = DesktopBindingRef::new("old-desktop-binding").unwrap();
    let current_binding = DesktopBindingRef::new("current-desktop-binding").unwrap();
    let old_run = SetupRunPlan::new(
        "old-scope-run",
        SetupOperationKind::Setup,
        Some(old_binding),
        at(1),
        vec![SetupActionPlan::new("install-codex", "Install Codex runtime", false).unwrap()],
    )
    .unwrap();
    storage.begin_setup_run(&old_run).unwrap();
    storage
        .start_setup_action("old-scope-run", "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            "old-scope-run",
            "install-codex",
            "installer-failed",
            None,
            None,
            at(3),
        )
        .unwrap();
    storage.finish_setup_run("old-scope-run", at(4)).unwrap();
    let probe = SetupRepairProbe::try_new(
        "install-codex",
        "Install Codex runtime",
        true,
        SetupRepairPostcondition::Unsatisfied,
    )
    .unwrap();

    let other_binding = storage
        .plan_setup_repair(Some(&current_binding), std::slice::from_ref(&probe))
        .unwrap();
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        other_binding.actions()[0].decision()
    );
    assert_eq!(None, other_binding.actions()[0].previous_run_id());

    storage
        .connection_for_test()
        .execute(
            "UPDATE setup_runs
             SET desktop_binding_ref = ?1, satelle_version = 'incompatible-version'
             WHERE run_id = 'old-scope-run'",
            [current_binding.as_str()],
        )
        .unwrap();
    let other_version = storage
        .plan_setup_repair(Some(&current_binding), &[probe])
        .unwrap();
    assert_eq!(
        SetupRepairDecision::RetryAutomatically,
        other_version.actions()[0].decision()
    );
    assert_eq!(None, other_version.actions()[0].previous_run_id());
}

#[test]
fn repair_uses_each_actions_most_recent_retained_ledger_entry() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let older = SetupRunPlan::new(
        "setup-run-1",
        SetupOperationKind::Setup,
        None,
        at(1),
        vec![SetupActionPlan::new("install-codex", "Install Codex runtime", false).unwrap()],
    )
    .unwrap();
    storage.begin_setup_run(&older).unwrap();
    storage
        .start_setup_action("setup-run-1", "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            "setup-run-1",
            "install-codex",
            "installer-failed",
            None,
            None,
            at(3),
        )
        .unwrap();
    storage.finish_setup_run("setup-run-1", at(4)).unwrap();

    // The second run remains the newest ledger entry even if the wall clock
    // moves backward between runs.
    let newer = SetupRunPlan::new(
        "setup-run-2",
        SetupOperationKind::Repair,
        None,
        at(0),
        vec![SetupActionPlan::new("install-codex", "Install Codex runtime", true).unwrap()],
    )
    .unwrap();
    storage.begin_setup_run(&newer).unwrap();
    storage
        .start_setup_action("setup-run-2", "install-codex", at(6))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition("setup-run-2", "install-codex", at(7))
        .unwrap();
    storage.finish_setup_run("setup-run-2", at(8)).unwrap();

    let repair = storage
        .plan_setup_repair(
            None,
            &[SetupRepairProbe::try_new(
                "install-codex",
                "Install Codex runtime",
                true,
                SetupRepairPostcondition::Unsatisfied,
            )
            .unwrap()],
        )
        .unwrap();
    assert_eq!(
        SetupRepairDecision::OperatorActionRequired,
        repair.actions()[0].decision()
    );
    assert_eq!(Some("setup-run-2"), repair.actions()[0].previous_run_id());
    assert_eq!(
        Some(SetupActionStatus::Completed),
        repair.actions()[0].previous_status()
    );
}
