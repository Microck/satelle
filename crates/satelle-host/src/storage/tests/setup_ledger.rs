use super::*;
use crate::storage::{
    SetupActionPlan, SetupActionSkipReason, SetupActionStatus, SetupOperationKind, SetupRunPlan,
    SetupRunStatus,
};

fn plan() -> SetupRunPlan {
    plan_with_run_id("setup-run-1")
}

fn plan_with_run_id(run_id: &str) -> SetupRunPlan {
    SetupRunPlan::new(
        run_id,
        SetupOperationKind::Setup,
        Some(DesktopBindingRef::new("desktop-binding-1").unwrap()),
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
