use assert_cmd::Command;
#[cfg(unix)]
use satelle_host::ApiBearerToken;
use satelle_host::test_support::TestStateDir;
use serde_json::Value;
use std::fs;

#[path = "support/test-file.rs"]
mod test_file;

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::time::Duration;

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

fn write_user_config(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    test_file::write_user_controlled(path, contents)
        .expect("user config should be written securely");
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
    write_user_config(
        &user_config,
        r#"
default_host = "local-demo"

[hosts.local-demo]
transport = "local"
adapter = "fake"

[hosts.remote]
transport = "ssh"
adapter = "fake"
"#,
    );
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

#[test]
fn direct_host_status_requires_a_complete_pinned_binding() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    write_user_config(
        &user_config,
        r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://127.0.0.1:9"
"#,
    );

    let output = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["error"]["code"], "configuration-error");
    assert!(
        error["error"]["message"]
            .as_str()
            .expect("error message")
            .contains("expected_host_id")
    );
}

#[test]
fn project_selected_direct_host_is_rejected_before_its_token_is_read() {
    let state = state_dir();
    let project = state.path().join("project");
    let project_config = project.join(".satelle").join("config.toml");
    let user_config = state.path().join("user-config.toml");
    let missing_token = state.path().join("must-not-be-read.token");
    let missing_token_literal =
        toml::Value::String(missing_token.to_string_lossy().into_owned()).to_string();
    fs::create_dir_all(
        project_config
            .parent()
            .expect("project config should have a parent"),
    )
    .expect("project config directory should be created");
    fs::write(&project_config, "default_host = \"remote\"\n")
        .expect("project config should be written");
    write_user_config(
        &user_config,
        format!(
            r#"
[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://127.0.0.1:9"
expected_host_id = "host-windows-11"
api_token = {{ kind = "file", path = {missing_token_literal} }}
"#,
        ),
    );

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["error"]["code"], "project-host-selection-not-allowed");
    assert_eq!(error["error"]["host"], "remote");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("must-not-be-read.token"));
}

#[test]
fn project_host_redirection_is_rejected_before_secret_or_transport_access() {
    let state = state_dir();
    let project = state.path().join("project");
    let project_config = project.join(".satelle").join("config.toml");
    let user_config = state.path().join("user-config.toml");
    let missing_token = state.path().join("trusted-token-must-not-be-read.token");
    let missing_token_literal =
        toml::Value::String(missing_token.to_string_lossy().into_owned()).to_string();
    fs::create_dir_all(
        project_config
            .parent()
            .expect("project config should have a parent"),
    )
    .expect("project config directory should be created");
    fs::write(
        &project_config,
        r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://attacker.example.test"
"#,
    )
    .expect("project config should be written");
    write_user_config(
        &user_config,
        format!(
            r#"
[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://127.0.0.1:9"
expected_host_id = "host-windows-11"
api_token = {{ kind = "file", path = {missing_token_literal} }}
allow_project_selection = true
"#,
        ),
    );

    let output = satelle()
        .current_dir(&project)
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    let error = parse_json_output(&output.stderr);
    assert_eq!(error["error"]["code"], "project-host-binding-not-allowed");
    assert_eq!(error["error"]["path"], "hosts.remote.address");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("trusted-token-must-not-be-read"));
}

#[cfg(unix)]
#[test]
fn direct_host_status_reads_a_secure_token_and_rejects_plaintext_transport() {
    let state = state_dir();
    let user_config = state.path().join("user-config.toml");
    let token_file = state.path().join("satelle.token");
    let token = ApiBearerToken::generate().expect("generate API token");
    let exposed = token.expose();
    fs::write(&token_file, exposed.as_bytes()).expect("write token file");
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))
        .expect("restrict token file");

    let write_config = |address: &str| {
        write_user_config(
            &user_config,
            format!(
                r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "{address}"
expected_host_id = "host-windows-11"
api_token = {{ kind = "file", path = "{}" }}
"#,
                token_file.display()
            ),
        );
    };

    write_config("http://127.0.0.1:9");
    let insecure = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(66)
        .get_output()
        .clone();
    assert_eq!(
        parse_json_output(&insecure.stderr)["error"]["code"],
        "configuration-error"
    );
    assert!(!String::from_utf8_lossy(&insecure.stderr).contains(exposed.as_str()));

    let closed = TcpListener::bind("127.0.0.1:0").expect("bind temporary port");
    let closed_address = closed.local_addr().expect("read temporary address");
    drop(closed);
    write_config(&format!("https://{closed_address}"));
    let unreachable = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(69)
        .get_output()
        .clone();
    assert_eq!(
        parse_json_output(&unreachable.stderr)["error"]["code"],
        "host-unreachable"
    );
    assert!(!String::from_utf8_lossy(&unreachable.stderr).contains(exposed.as_str()));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind plaintext server");
    let plaintext_address = listener.local_addr().expect("read plaintext address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TLS client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set server timeout");
        let mut client_hello = [0_u8; 1024];
        let _ = stream.read(&mut client_hello);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .expect("write plaintext response");
    });
    write_config(&format!("https://{plaintext_address}"));
    let tls_failure = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(76)
        .get_output()
        .clone();
    assert_eq!(
        parse_json_output(&tls_failure.stderr)["error"]["code"],
        "tls-handshake-failed"
    );
    assert!(!String::from_utf8_lossy(&tls_failure.stderr).contains(exposed.as_str()));
    server.join().expect("join plaintext server");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS alert server");
    let alert_address = listener.local_addr().expect("read TLS alert address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept TLS client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set server timeout");
        let mut client_hello = [0_u8; 1024];
        let _ = stream.read(&mut client_hello);
        stream
            .write_all(&[21, 3, 3, 0, 2, 2, 70])
            .expect("write protocol-version alert");
    });
    write_config(&format!("https://{alert_address}"));
    let tls_version = satelle()
        .env("SATELLE_CONFIG_FILE", &user_config)
        .env("SATELLE_STATE_DIR", state.path())
        .args(["host", "status", "--json"])
        .assert()
        .code(76)
        .get_output()
        .clone();
    assert_eq!(
        parse_json_output(&tls_version.stderr)["error"]["code"],
        "tls-version-unsupported"
    );
    assert!(!String::from_utf8_lossy(&tls_version.stderr).contains(exposed.as_str()));
    server.join().expect("join TLS alert server");
}
