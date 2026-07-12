use assert_cmd::Command;
use satelle_host::test_support::TestStateDir;
use serde_json::Value;
use std::fs;

const TEST_SUPPORT_ADAPTER_ENV: &str = "SATELLE_TEST_SUPPORT_ADAPTER";

fn satelle() -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle binary should build");
    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        TEST_SUPPORT_ADAPTER_ENV,
    ] {
        command.env_remove(name);
    }
    command.env(TEST_SUPPORT_ADAPTER_ENV, "fake");
    command
}

fn state_dir() -> TestStateDir {
    TestStateDir::new().expect("secure temp state directory should be created")
}

fn session_id(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find_map(|line| line.strip_prefix("Session: "))
        .expect("command should print a Session line")
        .to_string()
}

fn parse_json_output(output: &[u8]) -> Value {
    serde_json::from_slice(output).expect("output should be one JSON value")
}

#[test]
fn session_commands_route_through_the_explicit_host() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    fs::write(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.remote]
transport = "direct"
adapter = "fake"
address = "https://example.invalid"
"#,
    )
    .expect("user config should be written");
    let run_output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "run",
            "--host",
            "local-demo",
            "Create a host-routed Session",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let session = session_id(&run_output.stdout);

    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["status", &session, "--host", "local-demo", "--json"])
        .assert()
        .success();
    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "steer",
            &session,
            "--host",
            "local-demo",
            "Continue through the selected Host",
        ])
        .assert()
        .success();
    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args([
            "logs",
            "--session",
            &session,
            "--host",
            "local-demo",
            "--json",
        ])
        .assert()
        .success();
    satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["stop", &session, "--host", "local-demo", "--json"])
        .assert()
        .success();

    for args in [
        vec!["status", &session, "--host", "remote", "--json"],
        vec![
            "steer",
            &session,
            "--host",
            "remote",
            "Do not route this Turn",
            "--json",
        ],
        vec!["stop", &session, "--host", "remote", "--json"],
        vec!["logs", "--session", &session, "--host", "remote", "--json"],
    ] {
        let output = satelle()
            .env("SATELLE_CONFIG_FILE", &user_config)
            .env("SATELLE_STATE_DIR", state.path())
            .args(args)
            .assert()
            .failure()
            .get_output()
            .clone();
        assert_eq!(
            parse_json_output(&output.stderr)["error"]["code"],
            "host-unreachable"
        );
    }
}

#[test]
fn host_status_resolves_the_selected_host_before_contacting_transport() {
    let state = state_dir();
    satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--host", "local-demo", "--json"])
        .assert()
        .success();

    let output = satelle()
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--host", "missing", "--json"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_eq!(
        parse_json_output(&output.stderr)["error"]["code"],
        "host-not-found"
    );
}
