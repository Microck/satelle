use assert_cmd::Command;
use satelle_host::test_support::TestStateDir;
use serde_json::Value;

fn satelle() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("satelle"))
}

#[test]
fn host_update_dry_run_emits_the_v1_plan_before_any_apply_boundary() {
    let output = satelle()
        .args([
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "host",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run host update dry-run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse update report");
    assert_eq!(report["schema_version"], "satelle.host.update.v1");
    assert_eq!(report["host"], "local-demo");
    assert_eq!(report["status"], "up_to_date");
    assert_eq!(report["reusable_plan"], false);
    assert_eq!(report["changed"], false);
    assert_eq!(report["applied_actions"], serde_json::json!([]));
    assert_eq!(report["checked_components"], serde_json::json!(["host"]));
    assert!(report["targets"].as_array().is_some_and(|targets| {
        !targets.is_empty()
            && targets.iter().all(|target| {
                target["current_version"].is_string()
                    && target["target_version"].is_string()
                    && target["restart_impact"].is_string()
                    && target["remote_mutations"].is_array()
            })
    }));
}

#[test]
fn local_maintenance_dry_runs_do_not_create_host_storage() {
    let temporary_root =
        TestStateDir::new().expect("create secure parent for absent Host state roots");
    let commands = [
        vec![
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "host",
            "--dry-run",
            "--json",
        ],
        vec!["repair", "--host", "local-demo", "--dry-run", "--json"],
    ];

    for (index, arguments) in commands.iter().enumerate() {
        let state_root = temporary_root.path().join(format!("absent-{index}"));
        let output = satelle()
            .env("SATELLE_STATE_DIR", &state_root)
            .args(arguments)
            .output()
            .expect("run local maintenance dry-run");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !state_root.exists(),
            "local maintenance dry-run created Host storage at {}",
            state_root.display()
        );
    }
}

#[test]
fn current_host_update_exits_without_confirmation_or_mutation() {
    let state = tempfile::tempdir().expect("temporary update state");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "host",
            "--json",
        ])
        .output()
        .expect("run current Host update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse update report");
    assert_eq!(report["status"], "up_to_date");
    assert_eq!(report["changed"], false);
    assert_eq!(report["confirmation_required"], false);
}

#[test]
fn quiet_current_host_update_has_no_output() {
    let state = tempfile::tempdir().expect("temporary update state");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "host",
            "update",
            "--host",
            "local-demo",
            "--component",
            "host",
            "--quiet",
        ])
        .output()
        .expect("run quiet current Host update");

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn host_update_has_no_arbitrary_version_or_channel_flags() {
    for unsupported in ["--version", "--channel", "--latest"] {
        satelle()
            .args([
                "host",
                "update",
                "--host",
                "local-demo",
                unsupported,
                "candidate",
            ])
            .assert()
            .failure();
    }
}

#[test]
fn repair_dry_run_uses_live_typed_upgrade_evidence() {
    let state = TestStateDir::new().expect("create secure temporary state directory");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["repair", "--host", "local-demo", "--dry-run", "--json"])
        .output()
        .expect("run repair dry-run");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse repair report");
    assert_eq!(report["schema_version"], "satelle.repair.v1");
    assert_eq!(report["host"], "local-demo");
    assert_eq!(report["ledger_status"], "unavailable");
    assert_eq!(report["plan_source"], "live_probes");
    let actions = report["actions"]
        .as_array()
        .expect("repair report has typed actions");
    assert!(actions.iter().all(|action| {
        action["target"].is_string()
            && (action["current_version"].is_string() || action["current_version"].is_null())
            && action["target_version"].is_string()
            && action["version_source"].is_string()
            && action["disposition"].is_string()
    }));
    if cfg!(any(target_os = "windows", target_os = "macos")) {
        assert_eq!(actions.len(), 3);
        let runtime = actions
            .iter()
            .find(|action| action["target"] == "codex_runtime")
            .expect("repair report includes the supported Codex runtime");
        assert_eq!(runtime["version_source"], "codex_compatibility_requirement");
        assert!(
            matches!(
                runtime["disposition"].as_str(),
                Some(
                    "not_needed" | "required" | "manual_action_required" | "recommend_host_update"
                )
            ),
            "repair disposition must stay inside the typed contract: {runtime}"
        );
    } else {
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["target"], "host_daemon");
    }
}
