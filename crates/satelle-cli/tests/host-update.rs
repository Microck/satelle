use assert_cmd::Command;
use serde_json::Value;
use std::fs;

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
    let state = tempfile::tempdir().expect("temporary repair state");
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
    assert_eq!(actions.len(), 3);
    assert!(actions.iter().all(|action| {
        action["target"].is_string()
            && (action["current_version"].is_string() || action["current_version"].is_null())
            && action["target_version"].is_string()
            && action["version_source"].is_string()
            && action["disposition"].is_string()
    }));
    let runtime = actions
        .iter()
        .find(|action| action["target"] == "codex_runtime")
        .expect("repair report includes the Codex runtime");
    assert_eq!(runtime["version_source"], "codex_compatibility_requirement");
    assert_eq!(
        runtime["disposition"],
        if runtime["compatibility_reason"].is_null() {
            "not_needed"
        } else {
            "manual_action_required"
        }
    );
}

#[test]
fn repair_selected_missing_run_returns_the_typed_ledger_diagnostic() {
    let state = tempfile::tempdir().expect("temporary repair state");
    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "repair",
            "--host",
            "local-demo",
            "--run",
            "expired-setup-run",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("inspect a missing repair run");

    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("parse repair error");
    assert_eq!(error["code"], "setup-ledger-unavailable");
    assert_eq!(error["details"]["run_id"], "expired-setup-run");
}

#[test]
fn store_reset_dry_run_is_a_noop_and_apply_preserves_recordings_by_default() {
    let state = tempfile::tempdir().expect("temporary store reset state");
    let recordings = state.path().join("recordings");
    fs::create_dir(&recordings).expect("create recordings directory");
    let recording = recordings.join("recording.webm");
    fs::write(&recording, b"recording").expect("write recording fixture");

    let dry_run = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "host",
            "store",
            "reset",
            "--host",
            "local-demo",
            "--dry-run",
            "--yes",
            "--json",
        ])
        .output()
        .expect("preview store reset");
    assert!(dry_run.status.success());
    assert!(recording.exists());
    assert!(!state.path().join("satelle.sqlite3").exists());

    let applied = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "host",
            "store",
            "reset",
            "--host",
            "local-demo",
            "--no-input",
            "--yes",
            "--json",
        ])
        .output()
        .expect("apply store reset");
    assert!(
        applied.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let report: Value = serde_json::from_slice(&applied.stdout).expect("parse reset report");
    assert_eq!(report["status"], "applied");
    assert_eq!(report["result"]["recordings_deleted"], false);
    assert!(recording.exists());
    assert!(state.path().join("satelle.sqlite3").exists());
}

#[test]
fn store_reset_deletes_recordings_only_with_the_explicit_option() {
    let state = tempfile::tempdir().expect("temporary store reset state");
    let recordings = state.path().join("recordings");
    fs::create_dir(&recordings).expect("create recordings directory");
    fs::write(recordings.join("recording.webm"), b"recording").expect("write recording fixture");

    let applied = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "host",
            "store",
            "reset",
            "--host",
            "local-demo",
            "--delete-recordings",
            "--no-input",
            "--yes",
            "--json",
        ])
        .output()
        .expect("apply explicit recording deletion");
    assert!(
        applied.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let report: Value = serde_json::from_slice(&applied.stdout).expect("parse reset report");
    assert_eq!(report["result"]["recordings_deleted"], true);
    assert!(!recordings.exists());
}
