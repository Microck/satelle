use assert_cmd::Command;
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
