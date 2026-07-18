use super::*;
use crate::storage::{
    LeaseOwner, MaintenanceLeaseCapability, SetupActionPlan, SetupActionSkipReason,
    SetupActionStatus, SetupOperationKind, SetupRepairDecision, SetupRepairPostcondition,
    SetupRepairProbe, SetupRunPlan, SetupRunStatus,
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

fn begin_setup_run(storage: &mut Storage, plan: &SetupRunPlan) -> MaintenanceLeaseCapability {
    storage
        .begin_setup_run(plan, maintenance_owner(plan.run_id(), plan.started_at()))
        .expect("setup admission acquires its Maintenance Lease atomically")
}

#[test]
fn setup_action_ledger_migrates_and_persists_ordered_state_transitions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");

    let capability = begin_setup_run(&mut storage, &plan());
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
        .start_setup_action(&capability, "install-codex", at(2))
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
        .complete_setup_action_after_verified_postcondition(&capability, "install-codex", at(3))
        .expect("commit verified completion");
    storage
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::AlreadySatisfied,
            at(4),
        )
        .expect("skip an action that needs no mutation");

    let finished = storage
        .finish_setup_run_and_release_maintenance(&capability, at(5))
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
    let capability = begin_setup_run(&mut storage, &plan());

    let out_of_order = storage
        .start_setup_action(&capability, "configure-computer-use", at(2))
        .expect_err("later actions wait for preceding terminal outcomes");
    assert_eq!(StorageErrorKind::StateConflict, out_of_order.kind());
    let out_of_order_skip = storage
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::NotRequired,
            at(2),
        )
        .expect_err("later skips also wait for preceding terminal outcomes");
    assert_eq!(StorageErrorKind::StateConflict, out_of_order_skip.kind());

    let complete_before_start = storage
        .complete_setup_action_after_verified_postcondition(&capability, "install-codex", at(2))
        .expect_err("completion requires a durable started state");
    assert_eq!(
        StorageErrorKind::StateConflict,
        complete_before_start.kind()
    );

    storage
        .start_setup_action(&capability, "install-codex", at(2))
        .unwrap();
    let skip_after_start = storage
        .skip_setup_action(
            &capability,
            "install-codex",
            SetupActionSkipReason::NotRequired,
            at(3),
        )
        .expect_err("a started mutation cannot become skipped");
    assert_eq!(StorageErrorKind::StateConflict, skip_after_start.kind());

    let unfinished = storage
        .finish_setup_run_and_release_maintenance(&capability, at(4))
        .expect_err("a run with active actions cannot become terminal");
    assert_eq!(StorageErrorKind::StateConflict, unfinished.kind());
}

#[test]
fn wrong_and_stale_maintenance_capabilities_cannot_mutate_or_release() {
    let state = TempDir::new().expect("temporary state directory");
    let other_state = TempDir::new().expect("second temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let (mut other_storage, _) = Storage::open(other_state.path()).expect("open second storage");
    let plan = SetupRunPlan::new(
        "authority-run",
        SetupOperationKind::Repair,
        None,
        at(1),
        vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
    )
    .unwrap();
    let capability = storage
        .begin_setup_run(
            &plan,
            LeaseOwner::new(
                plan.run_id(),
                std::process::id(),
                "authority-process-start",
                "authority-boot",
                at(1),
            )
            .unwrap(),
        )
        .unwrap();
    let wrong_capability = other_storage
        .begin_setup_run(
            &plan,
            LeaseOwner::new(
                plan.run_id(),
                std::process::id(),
                "wrong-process-start",
                "wrong-boot",
                at(1),
            )
            .unwrap(),
        )
        .unwrap();

    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .start_setup_action(&wrong_capability, "repair-runtime", at(2))
            .expect_err("authority from another exact stored owner is rejected")
            .kind()
    );
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition(&capability, "repair-runtime", at(3))
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&capability, at(4))
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .finish_setup_run_and_release_maintenance(&capability, at(5))
            .expect_err("a released capability cannot finalize again")
            .kind()
    );
}

#[test]
fn every_exact_owner_field_and_state_guards_action_normal_and_recovery_release() {
    for (column, wrong_value) in [
        ("operation_id", "different-operation"),
        ("owner_process_id", "424242"),
        ("owner_process_start_ref", "different-process-start"),
        ("owner_boot_identity_ref", "different-boot"),
        ("acquired_at", "1970-01-01T00:00:09Z"),
        ("lease_state", "recovery_pending"),
    ] {
        let state = TempDir::new().expect("temporary state directory");
        let (mut storage, _) = Storage::open(state.path()).expect("open storage");
        let plan = plan_with_run_id(&format!("owner-field-{column}"));
        let capability = begin_setup_run(&mut storage, &plan);
        let original = replace_maintenance_field(&storage, column, wrong_value);
        assert_eq!(
            StorageErrorKind::StateConflict,
            storage
                .start_setup_action(&capability, "install-codex", at(2))
                .expect_err("one changed owner field must reject action mutation")
                .kind(),
            "action predicate omitted {column}"
        );
        replace_maintenance_field(&storage, column, &original);
        storage
            .start_setup_action(&capability, "install-codex", at(2))
            .unwrap();
        storage
            .complete_setup_action_after_verified_postcondition(&capability, "install-codex", at(3))
            .unwrap();
        storage
            .skip_setup_action(
                &capability,
                "configure-computer-use",
                SetupActionSkipReason::AlreadySatisfied,
                at(4),
            )
            .unwrap();
        replace_maintenance_field(&storage, column, wrong_value);
        assert_eq!(
            StorageErrorKind::StateConflict,
            storage
                .finish_setup_run_and_release_maintenance(&capability, at(5))
                .expect_err("one changed owner field must reject normal release")
                .kind(),
            "normal release predicate omitted {column}"
        );

        let recovery_state = TempDir::new().expect("recovery state directory");
        let (mut recovery_storage, _) =
            Storage::open(recovery_state.path()).expect("open recovery storage");
        let recovery_plan = plan_with_run_id(&format!("recovery-field-{column}"));
        let recovery_capability = begin_setup_run(&mut recovery_storage, &recovery_plan);
        recovery_storage
            .start_setup_action(&recovery_capability, "install-codex", at(2))
            .unwrap();
        recovery_storage
            .retain_lease_recovery(recovery_capability.lease_owner())
            .unwrap();
        let subject = match recovery_storage.maintenance_lease_state().unwrap().unwrap() {
            crate::storage::MaintenanceLeaseState::RecoveryPending(subject) => subject,
            crate::storage::MaintenanceLeaseState::Active { .. } => unreachable!(),
        };
        let verified =
            crate::runtime::verify_setup_postconditions(&subject, &mut FixedSetupObserver(true))
                .unwrap();
        let recovery_wrong_value = if column == "lease_state" {
            "active"
        } else {
            wrong_value
        };
        replace_maintenance_field(&recovery_storage, column, recovery_wrong_value);
        assert_eq!(
            StorageErrorKind::StateConflict,
            recovery_storage
                .reconcile_maintenance_after_restart(&subject, &verified)
                .expect_err("one changed recovery-owner field must reject release")
                .kind(),
            "recovery release predicate omitted {column}"
        );
    }
}

#[test]
fn maintenance_insert_failure_rolls_back_setup_run_and_actions() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_maintenance_insert
             BEFORE INSERT ON maintenance_leases
             BEGIN SELECT RAISE(ABORT, 'forced maintenance insert failure'); END;",
        )
        .unwrap();
    let plan = plan_with_run_id("acquisition-rollback");
    storage
        .begin_setup_run(&plan, maintenance_owner(plan.run_id(), plan.started_at()))
        .expect_err("lease insertion failure must roll back the ledger acquisition");
    for table in ["setup_runs", "setup_actions", "maintenance_leases"] {
        let count: i64 = storage
            .connection_for_test()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(0, count, "acquisition left partial rows in {table}");
    }
}

fn replace_maintenance_field(storage: &Storage, column: &str, value: &str) -> String {
    let original = storage
        .connection_for_test()
        .query_row(
            &format!("SELECT CAST({column} AS TEXT) FROM maintenance_leases"),
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    storage
        .connection_for_test()
        .execute(
            &format!("UPDATE maintenance_leases SET {column} = ?1"),
            [value],
        )
        .unwrap();
    original
}

fn maintenance_recovery_snapshot(storage: &Storage, operation_id: &str) -> String {
    storage
        .connection_for_test()
        .query_row(
            "SELECT printf(
                '%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q|%Q',
                setup_runs.status, setup_runs.finished_at,
                actions.snapshot,
                maintenance_leases.operation_id, maintenance_leases.owner_process_id,
                maintenance_leases.owner_process_start_ref,
                maintenance_leases.owner_boot_identity_ref,
                maintenance_leases.acquired_at, maintenance_leases.heartbeat_at
             )
             FROM setup_runs
             JOIN (
                SELECT run_id, group_concat(action_snapshot, ';') AS snapshot
                FROM (
                    SELECT run_id, printf(
                        '%Q,%Q,%Q,%Q,%Q,%Q',
                        action_id, status, finished_at, error_code,
                        recovery_hint, skip_reason
                    ) AS action_snapshot
                    FROM setup_actions
                    ORDER BY run_id, action_order
                )
                GROUP BY run_id
             ) AS actions USING (run_id)
             JOIN maintenance_leases ON maintenance_leases.operation_id = setup_runs.run_id
             WHERE setup_runs.run_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn setup_action_ledger_rejects_backward_transition_times() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let capability = begin_setup_run(&mut storage, &plan());

    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .start_setup_action(&capability, "install-codex", at(0))
            .unwrap_err()
            .kind()
    );
    storage
        .start_setup_action(&capability, "install-codex", at(2))
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .complete_setup_action_after_verified_postcondition(
                &capability,
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
                &capability,
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
        .complete_setup_action_after_verified_postcondition(&capability, "install-codex", at(3))
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .skip_setup_action(
                &capability,
                "configure-computer-use",
                SetupActionSkipReason::AlreadySatisfied,
                at(2),
            )
            .unwrap_err()
            .kind()
    );
    storage
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::AlreadySatisfied,
            at(4),
        )
        .unwrap();
    assert_eq!(
        StorageErrorKind::StateConflict,
        storage
            .finish_setup_run_and_release_maintenance(&capability, at(3))
            .unwrap_err()
            .kind()
    );
    assert_eq!(
        SetupRunStatus::Completed,
        storage
            .finish_setup_run_and_release_maintenance(&capability, at(5))
            .unwrap()
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
    let capability = begin_setup_run(&mut storage, &plan());
    storage
        .start_setup_action(&capability, "install-codex", at(2))
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
fn terminal_setup_ledger_commit_releases_maintenance_in_the_same_transaction() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let capability = begin_setup_run(&mut storage, &plan());
    storage
        .start_setup_action(&capability, "install-codex", at(2))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition(&capability, "install-codex", at(3))
        .unwrap();
    storage
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::AlreadySatisfied,
            at(4),
        )
        .unwrap();
    storage
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_terminal_setup_ledger
             BEFORE UPDATE OF status ON setup_runs
             WHEN OLD.run_id = 'setup-run-1' AND NEW.status != 'running'
             BEGIN SELECT RAISE(ABORT, 'forced final ledger failure'); END;",
        )
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&capability, at(5))
        .expect_err("failed ledger commit must retain maintenance ownership");
    assert_eq!(
        SetupRunStatus::Running,
        storage
            .load_setup_run("setup-run-1")
            .unwrap()
            .unwrap()
            .status()
    );
    assert_eq!(
        1_i64,
        storage
            .connection_for_test()
            .query_row("SELECT count(*) FROM maintenance_leases", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    );

    storage
        .connection_for_test()
        .execute_batch("DROP TRIGGER fail_terminal_setup_ledger;")
        .unwrap();
    assert_eq!(
        SetupRunStatus::Completed,
        storage
            .finish_setup_run_and_release_maintenance(&capability, at(5))
            .unwrap()
    );
    assert_eq!(
        0_i64,
        storage
            .connection_for_test()
            .query_row("SELECT count(*) FROM maintenance_leases", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    );
}

#[test]
fn maintenance_delete_failure_rolls_back_normal_and_recovery_terminal_ledgers() {
    let normal_state = TempDir::new().expect("normal state directory");
    let (mut normal, _) = Storage::open(normal_state.path()).expect("open normal storage");
    let normal_plan = plan_with_run_id("normal-delete-rollback");
    let capability = begin_setup_run(&mut normal, &normal_plan);
    normal
        .start_setup_action(&capability, "install-codex", at(2))
        .unwrap();
    normal
        .complete_setup_action_after_verified_postcondition(&capability, "install-codex", at(3))
        .unwrap();
    normal
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::AlreadySatisfied,
            at(4),
        )
        .unwrap();
    normal
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_normal_maintenance_delete
             BEFORE DELETE ON maintenance_leases
             BEGIN SELECT RAISE(ABORT, 'forced normal delete failure'); END;",
        )
        .unwrap();
    normal
        .finish_setup_run_and_release_maintenance(&capability, at(5))
        .expect_err("normal delete failure must roll back the terminal ledger");
    assert_eq!(
        SetupRunStatus::Running,
        normal
            .load_setup_run(normal_plan.run_id())
            .unwrap()
            .unwrap()
            .status()
    );
    assert!(normal.maintenance_lease_state().unwrap().is_some());

    let recovery_state = TempDir::new().expect("recovery state directory");
    let (mut recovery, _) = Storage::open(recovery_state.path()).expect("open recovery storage");
    let recovery_plan = SetupRunPlan::new(
        "recovery-delete-rollback",
        SetupOperationKind::Repair,
        None,
        at(1),
        vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
    )
    .unwrap();
    let recovery_capability = begin_setup_run(&mut recovery, &recovery_plan);
    recovery
        .start_setup_action(&recovery_capability, "repair-runtime", at(2))
        .unwrap();
    recovery
        .retain_lease_recovery(recovery_capability.lease_owner())
        .unwrap();
    let subject = match recovery.maintenance_lease_state().unwrap().unwrap() {
        crate::storage::MaintenanceLeaseState::RecoveryPending(subject) => subject,
        crate::storage::MaintenanceLeaseState::Active { .. } => unreachable!(),
    };
    let verified =
        crate::runtime::verify_setup_postconditions(&subject, &mut FixedSetupObserver(true))
            .unwrap();
    recovery
        .connection_for_test()
        .execute_batch(
            "CREATE TRIGGER fail_recovery_maintenance_delete
             BEFORE DELETE ON maintenance_leases
             BEGIN SELECT RAISE(ABORT, 'forced recovery delete failure'); END;",
        )
        .unwrap();
    recovery
        .reconcile_maintenance_after_restart(&subject, &verified)
        .expect_err("recovery delete failure must roll back verified ledger state");
    let retained = recovery
        .load_setup_run(recovery_plan.run_id())
        .unwrap()
        .unwrap();
    assert_eq!(SetupRunStatus::OutcomeUnknown, retained.status());
    assert_eq!(
        SetupActionStatus::OutcomeUnknown,
        retained.actions()[0].status()
    );
    assert!(recovery.maintenance_lease_state().unwrap().is_some());
}

#[test]
fn startup_preserves_orphaned_maintenance_as_recovery_pending_outcome_unknown() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let capability = begin_setup_run(&mut storage, &plan());
    storage
        .start_setup_action(&capability, "install-codex", at(2))
        .unwrap();
    storage
        .connection_for_test()
        .execute(
            "UPDATE maintenance_leases SET heartbeat_at = ?1 WHERE operation_id = 'setup-run-1'",
            [at(0).format(&Rfc3339).unwrap()],
        )
        .unwrap();
    drop(storage);

    let (mut recovered, _) = Storage::open(state.path()).expect("run startup recovery");
    assert_eq!(
        SetupRunStatus::OutcomeUnknown,
        recovered
            .load_setup_run("setup-run-1")
            .unwrap()
            .unwrap()
            .status()
    );
    let lease_state: String = recovered
        .connection_for_test()
        .query_row(
            "SELECT lease_state FROM maintenance_leases WHERE operation_id = 'setup-run-1'",
            [],
            |row| row.get(0),
        )
        .expect("stale ownership must remain durable");
    assert_eq!("recovery_pending", lease_state);
    let unknown_subject = match recovered.maintenance_lease_state().unwrap().unwrap() {
        crate::storage::MaintenanceLeaseState::RecoveryPending(subject) => subject,
        crate::storage::MaintenanceLeaseState::Active { .. } => {
            panic!("startup must classify the orphan as recovery_pending")
        }
    };
    let before_unknown = maintenance_recovery_snapshot(&recovered, unknown_subject.operation_id());
    crate::runtime::verify_setup_postconditions(&unknown_subject, &mut UnknownSetupObserver)
        .expect_err("unknown observation cannot mint verified release authority");
    assert_eq!(
        before_unknown,
        maintenance_recovery_snapshot(&recovered, unknown_subject.operation_id()),
        "missing verified observer evidence must not change any durable recovery field"
    );
    let verified_subject = match recovered.maintenance_lease_state().unwrap().unwrap() {
        crate::storage::MaintenanceLeaseState::RecoveryPending(subject) => subject,
        crate::storage::MaintenanceLeaseState::Active { .. } => unreachable!(),
    };
    let verified = crate::runtime::verify_setup_postconditions(
        &verified_subject,
        &mut FixedSetupObserver(true),
    )
    .unwrap();
    assert_eq!(
        Some(SetupRunStatus::PartialFailure),
        recovered
            .reconcile_maintenance_after_restart(&verified_subject, &verified)
            .expect("verified postconditions commit the outcome and release together")
    );
    assert_eq!(
        StorageErrorKind::StateConflict,
        recovered
            .reconcile_maintenance_after_restart(&verified_subject, &verified)
            .expect_err("a stale recovery subject cannot finalize a released owner")
            .kind()
    );
    let replacement = plan_with_run_id("replacement-maintenance");
    begin_setup_run(&mut recovered, &replacement);
}

#[test]
fn restart_reconciliation_commits_verified_unsatisfied_as_failed_before_release() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let plan = SetupRunPlan::new(
        "failed-recovery",
        SetupOperationKind::Repair,
        None,
        at(1),
        vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
    )
    .unwrap();
    let capability = begin_setup_run(&mut storage, &plan);
    storage
        .start_setup_action(&capability, "repair-runtime", at(2))
        .unwrap();
    storage
        .retain_lease_recovery(capability.lease_owner())
        .expect("ambiguous worker loss retains exact ownership");
    let subject = match storage.maintenance_lease_state().unwrap().unwrap() {
        crate::storage::MaintenanceLeaseState::RecoveryPending(subject) => subject,
        crate::storage::MaintenanceLeaseState::Active { .. } => unreachable!(),
    };

    let verified =
        crate::runtime::verify_setup_postconditions(&subject, &mut FixedSetupObserver(false))
            .unwrap();
    assert_eq!(
        Some(SetupRunStatus::Failed),
        storage
            .reconcile_maintenance_after_restart(&subject, &verified)
            .expect("verified failure commits before exact recovery release")
    );
    let run = storage.load_setup_run(plan.run_id()).unwrap().unwrap();
    assert_eq!(SetupActionStatus::Failed, run.actions()[0].status());
    assert_eq!(
        Some("repair_postcondition_unsatisfied"),
        run.actions()[0].error_code()
    );
    assert!(storage.maintenance_lease_state().unwrap().is_none());
}

struct FixedSetupObserver(bool);

impl crate::SetupPostconditionObserver for FixedSetupObserver {
    fn observe(&mut self, _action: &SetupActionRecord) -> Result<bool, satelle_core::SatelleError> {
        Ok(self.0)
    }
}

struct UnknownSetupObserver;

impl crate::SetupPostconditionObserver for UnknownSetupObserver {
    fn observe(&mut self, _action: &SetupActionRecord) -> Result<bool, satelle_core::SatelleError> {
        Err(satelle_core::SatelleError::computer_use_not_ready())
    }
}

fn maintenance_owner(operation_id: &str, acquired_at: OffsetDateTime) -> LeaseOwner {
    LeaseOwner::new(
        operation_id,
        std::process::id(),
        "setup-process-start",
        "setup-boot-identity",
        acquired_at,
    )
    .unwrap()
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
    let capability = begin_setup_run(&mut storage, &future_plan);
    storage
        .start_setup_action(&capability, "future-action", at(20))
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
    let before_state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(before_state.path()).expect("open storage");
    let before_plan = plan_with_run_id("before-first-action");
    let _before_capability = begin_setup_run(&mut storage, &before_plan);
    drop(storage);
    let (recovered, _) =
        Storage::open(before_state.path()).expect("restart recovery opens storage");
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
    drop(recovered);

    let between_state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(between_state.path()).expect("open storage");
    let between_plan = plan_with_run_id_and_binding("between-actions", "desktop-binding-2");
    let between_capability = begin_setup_run(&mut storage, &between_plan);
    storage
        .start_setup_action(&between_capability, "install-codex", at(2))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition(
            &between_capability,
            "install-codex",
            at(3),
        )
        .unwrap();
    drop(storage);

    let (recovered, _) =
        Storage::open(between_state.path()).expect("restart recovery opens storage");
    let between = recovered
        .load_setup_run("between-actions")
        .unwrap()
        .unwrap();
    assert_eq!(SetupRunStatus::OutcomeUnknown, between.status());
    assert_eq!(SetupActionStatus::Completed, between.actions()[0].status());
    assert_eq!(SetupActionStatus::Planned, between.actions()[1].status());
}

#[test]
fn failed_actions_store_normalized_metadata_without_raw_stream_columns() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let capability = begin_setup_run(&mut storage, &plan());
    storage
        .start_setup_action(&capability, "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            &capability,
            "install-codex",
            "installer-exit-failed",
            Some(17),
            Some("rerun satelle repair after fixing package access"),
            at(3),
        )
        .unwrap();
    storage
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::DependencyFailed,
            at(4),
        )
        .unwrap();
    assert_eq!(
        SetupRunStatus::Failed,
        storage
            .finish_setup_run_and_release_maintenance(&capability, at(5))
            .unwrap()
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

    let capability = begin_setup_run(&mut storage, &plan());
    storage
        .skip_setup_action(
            &capability,
            "install-codex",
            SetupActionSkipReason::DependencyFailed,
            at(2),
        )
        .unwrap();
    storage
        .skip_setup_action(
            &capability,
            "configure-computer-use",
            SetupActionSkipReason::DependencyFailed,
            at(3),
        )
        .unwrap();
    assert_eq!(
        SetupRunStatus::Failed,
        storage
            .finish_setup_run_and_release_maintenance(&capability, at(4))
            .unwrap()
    );

    let second_plan = plan_with_run_id("setup-run-2");
    let second_capability = begin_setup_run(&mut storage, &second_plan);
    storage
        .start_setup_action(&second_capability, "install-codex", at(2))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition(
            &second_capability,
            "install-codex",
            at(3),
        )
        .unwrap();
    storage
        .skip_setup_action(
            &second_capability,
            "configure-computer-use",
            SetupActionSkipReason::DependencyFailed,
            at(4),
        )
        .unwrap();
    assert_eq!(
        SetupRunStatus::PartialFailure,
        storage
            .finish_setup_run_and_release_maintenance(&second_capability, at(5))
            .unwrap()
    );
}

#[test]
fn malformed_persisted_action_references_are_stored_state_errors() {
    let state = TempDir::new().expect("temporary state directory");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let _capability = begin_setup_run(&mut storage, &plan());
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
    let capability = begin_setup_run(&mut storage, &setup_plan);
    storage
        .start_setup_action(&capability, "install-codex", at(2))
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
    let safe_capability = begin_setup_run(&mut storage, &safe_run);
    storage
        .start_setup_action(&safe_capability, "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            &safe_capability,
            "install-codex",
            "installer-failed",
            None,
            None,
            at(3),
        )
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&safe_capability, at(4))
        .unwrap();

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
    let unsafe_capability = begin_setup_run(&mut storage, &unsafe_run);
    storage
        .start_setup_action(&unsafe_capability, "configure-computer-use", at(6))
        .unwrap();
    storage
        .fail_setup_action(
            &unsafe_capability,
            "configure-computer-use",
            "configuration-failed",
            None,
            None,
            at(7),
        )
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&unsafe_capability, at(8))
        .unwrap();

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
    let active_capability = begin_setup_run(&mut storage, &active);
    storage
        .start_setup_action(&active_capability, "install-codex", at(2))
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

    let _first_capability = begin_setup_run(&mut storage, &first);
    let error = storage
        .begin_setup_run(
            &competing,
            maintenance_owner(competing.run_id(), competing.started_at()),
        )
        .expect_err("the first repair run reserves its compatible scope");
    assert_eq!(StorageErrorKind::LeaseConflict, error.kind());
    let error = storage
        .begin_setup_run(
            &competing_setup,
            maintenance_owner(competing_setup.run_id(), competing_setup.started_at()),
        )
        .expect_err("a setup run cannot bypass the repair reservation");
    assert_eq!(StorageErrorKind::LeaseConflict, error.kind());
    let error = storage
        .begin_setup_run(
            &other_scope,
            maintenance_owner(other_scope.run_id(), other_scope.started_at()),
        )
        .expect_err("Host maintenance excludes every other desktop binding");
    assert_eq!(StorageErrorKind::LeaseConflict, error.kind());
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
    let old_capability = begin_setup_run(&mut storage, &old_run);
    storage
        .start_setup_action(&old_capability, "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            &old_capability,
            "install-codex",
            "installer-failed",
            None,
            None,
            at(3),
        )
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&old_capability, at(4))
        .unwrap();
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
    let older_capability = begin_setup_run(&mut storage, &older);
    storage
        .start_setup_action(&older_capability, "install-codex", at(2))
        .unwrap();
    storage
        .fail_setup_action(
            &older_capability,
            "install-codex",
            "installer-failed",
            None,
            None,
            at(3),
        )
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&older_capability, at(4))
        .unwrap();

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
    let newer_capability = begin_setup_run(&mut storage, &newer);
    storage
        .start_setup_action(&newer_capability, "install-codex", at(6))
        .unwrap();
    storage
        .complete_setup_action_after_verified_postcondition(
            &newer_capability,
            "install-codex",
            at(7),
        )
        .unwrap();
    storage
        .finish_setup_run_and_release_maintenance(&newer_capability, at(8))
        .unwrap();

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
