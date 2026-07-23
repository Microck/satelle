use super::control_plane::{
    ControlPlaneAdmission, configure_app_server_command, probe_control_plane_with,
};
use satelle_core::{ControlPlaneCapability, ControlPlaneOperation, ErrorCode};
use serde_json::json;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const FIXTURE_MODE: &str = "SATELLE_CODEX_CONTROL_PLANE_FIXTURE";
const FIXTURE_SCHEMA_DIR: &str = "SATELLE_CODEX_SCHEMA_FIXTURE_DIR";
const RAW_NOTIFICATION_CANARY: &str = "PRIVATE_RAW_NOTIFICATION_CANARY";
const RAW_SCHEMA_CANARY: &str = "PRIVATE_RAW_SCHEMA_CANARY";

const STDIO_FIXTURE_SOURCE: &str = r#"
use std::io::{BufRead, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("success") => success(),
        Some("hang-with-descendant") => hang_with_descendant(),
        Some("hang-with-descendant-exit") => spawn_descendant(),
        Some("hang-with-escaped-descendant-exit") => spawn_escaped_descendant(),
        Some("version-with-descendant") => version_with_descendant(),
        Some("version-with-escaped-descendant") => version_with_escaped_descendant(),
        Some("descendant") => std::thread::sleep(Duration::from_secs(30)),
        Some("short-descendant") => std::thread::sleep(Duration::from_secs(2)),
        _ => std::process::exit(2),
    }
}

fn success() {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    input.read_line(&mut line).expect("read initialize request");
    assert!(line.contains("\"method\":\"initialize\""));

    let mut output = std::io::stdout().lock();
    writeln!(output, "{{\"method\":\"future/notification\",\"params\":{{\"raw\":\"PRIVATE_RAW_NOTIFICATION_CANARY\"}}}}")
        .expect("write notification");
    output
        .write_all(b"{\"id\":1,\"result\":{\"userAgent\":")
        .expect("write initialize response prefix");
    output.flush().expect("flush initialize response prefix");
    std::thread::sleep(Duration::from_millis(10));
    output
        .write_all(b"\"PRIVATE_RAW_NOTIFICATION_CANARY\",\"codexHome\":\"PRIVATE_RAW_NOTIFICATION_CANARY\",\"platformFamily\":\"fixture\",\"platformOs\":\"fixture\"}}\n")
        .expect("write initialize response suffix");
    output.flush().expect("flush initialize response");

    line.clear();
    input.read_line(&mut line).expect("read initialized notification");
    assert!(line.contains("\"method\":\"initialized\""));

    line.clear();
    assert_eq!(
        input.read_line(&mut line).expect("wait for app-server shutdown"),
        0,
        "the app-server fixture must remain alive until its stdin closes"
    );
}

fn hang_with_descendant() {
    spawn_descendant();
    std::thread::sleep(Duration::from_secs(30));
}

fn version_with_descendant() {
    spawn_descendant();
    println!("codex-cli 0.144.0");
}

fn version_with_escaped_descendant() {
    spawn_escaped_descendant();
    println!("codex-cli 0.144.0");
}

fn spawn_descendant() {
    Command::new(std::env::current_exe().expect("resolve fixture executable"))
        .arg("descendant")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn stdout-inheriting descendant");
}

fn spawn_escaped_descendant() {
    let mut command = Command::new(std::env::current_exe().expect("resolve fixture executable"));
    command
        .arg("short-descendant")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null());
    #[cfg(unix)]
    command.process_group(0);
    command.spawn().expect("spawn group-escaping descendant");
}
"#;

#[test]
fn required_method_set_is_exact_and_missing_capabilities_are_typed() {
    assert_eq!(
        ControlPlaneCapability::ALL,
        [
            ControlPlaneCapability::SessionCreation,
            ControlPlaneCapability::TurnStart,
            ControlPlaneCapability::EventObservation,
            ControlPlaneCapability::Steering,
            ControlPlaneCapability::Status,
            ControlPlaneCapability::Cancellation,
        ]
    );

    let probe = run_fixture("missing-cancellation");
    let error = ControlPlaneAdmission::from_probe(probe)
        .admit(ControlPlaneOperation::Stop)
        .expect_err("a missing required method must block cancellation");

    assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(
        error.details["reason"],
        serde_json::json!("required_capability_missing")
    );
    assert_eq!(
        error.details["missing_capabilities"],
        serde_json::json!(["cancellation"])
    );
    assert!(
        ControlPlaneAdmission::from_probe(probe)
            .admit(ControlPlaneOperation::Run)
            .is_ok(),
        "one missing method must not erase unrelated capability evidence"
    );
    let matrix = super::CapabilityMatrix::from_control_plane(probe);
    assert_eq!(
        matrix.session_thread_creation.surface,
        super::EvidenceSurface::Stable
    );
    assert_eq!(
        matrix.interrupt_request.surface,
        super::EvidenceSurface::Absent
    );
    assert!(!format!("{error:?}").contains(RAW_SCHEMA_CANARY));
}

#[test]
fn unavailable_goal_methods_do_not_block_core_session_and_turn_control() {
    let probe = run_fixture("required");

    for operation in [
        ControlPlaneOperation::Run,
        ControlPlaneOperation::Steer,
        ControlPlaneOperation::Stop,
        ControlPlaneOperation::Status,
    ] {
        ControlPlaneAdmission::from_probe(probe)
            .admit(operation)
            .expect("optional goal methods must not gate core control");
    }
}

#[test]
fn recovery_requires_status_and_steering_capabilities() {
    let probe = run_fixture("missing-steering");
    let error = ControlPlaneAdmission::from_probe(probe)
        .admit(ControlPlaneOperation::Status)
        .expect_err("recovery must fail before I/O when steering is unavailable");

    assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
    assert_eq!(
        error.details["required_capabilities"],
        serde_json::json!(["status", "steering"])
    );
    assert_eq!(
        error.details["missing_capabilities"],
        serde_json::json!(["steering"])
    );
}

#[test]
fn nested_schema_decoy_does_not_satisfy_a_required_capability() {
    let probe = run_fixture("decoy-cancellation");
    let error = ControlPlaneAdmission::from_probe(probe)
        .admit(ControlPlaneOperation::Stop)
        .expect_err("a nested decoy must not declare a top-level request method");

    assert_eq!(
        error.details["reason"],
        serde_json::json!("required_capability_missing")
    );
}

#[test]
fn schema_and_handshake_share_one_hard_deadline() {
    let fixture = compile_stdio_fixture();
    let started = std::time::Instant::now();

    let probe = run_schema_and_stdio_fixture_with(
        &fixture,
        "timeout",
        "hang-with-descendant",
        Duration::from_secs(5),
    );

    assert!(
        started.elapsed() < Duration::from_millis(6_500),
        "schema discovery and the handshake used separate timeout budgets"
    );
    assert_eq!(
        ControlPlaneAdmission::from_probe(probe)
            .admit(ControlPlaneOperation::Run)
            .expect_err("the incomplete handshake must remain blocked")
            .details["reason"],
        serde_json::json!("handshake_unavailable")
    );
}

#[test]
fn handshake_ignores_unknown_notifications() {
    let probe = run_fixture("required");

    for capability in ControlPlaneCapability::ALL {
        assert!(probe.supports(capability));
    }
    assert!(probe.handshake_completed());

    let diagnostic = format!("{probe:?}");
    assert!(!diagnostic.contains(RAW_NOTIFICATION_CANARY));
    assert!(!diagnostic.contains(RAW_SCHEMA_CANARY));
}

#[test]
fn installed_app_server_is_private_stdio_only() {
    let command = configure_app_server_command(Command::new("receipt-recorded-codex"));
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(arguments, ["app-server", "--listen", "stdio://"]);
    assert!(
        !arguments
            .iter()
            .any(|argument| { argument.starts_with("ws://") || argument.starts_with("unix://") })
    );
}

#[test]
fn production_stdio_handshake_uses_the_same_parser_and_redaction_boundary() {
    let probe = run_production_stdio_fixture("success", Duration::from_secs(2));

    for capability in ControlPlaneCapability::ALL {
        assert!(probe.supports(capability));
    }
    let diagnostic = format!("{probe:?}");
    assert!(!diagnostic.contains(RAW_NOTIFICATION_CANARY));
    assert!(!diagnostic.contains(RAW_SCHEMA_CANARY));
}

#[test]
fn production_stdio_timeout_terminates_stdout_inheriting_descendants() {
    let fixture = compile_stdio_fixture();
    let started = std::time::Instant::now();

    let probe = run_production_stdio_fixture_with(
        &fixture,
        "hang-with-descendant-exit",
        Duration::from_secs(2),
    );

    assert!(
        started.elapsed() < Duration::from_millis(2_500),
        "production stdio process-tree shutdown exceeded the hard deadline"
    );
    assert_eq!(
        ControlPlaneAdmission::from_probe(probe)
            .admit(ControlPlaneOperation::Run)
            .expect_err("the timed-out production stdio handshake must remain blocked")
            .details["reason"],
        serde_json::json!("handshake_unavailable")
    );
}

#[cfg(unix)]
#[test]
fn production_stdio_deadline_survives_a_group_escaping_pipe_holder() {
    let fixture = compile_stdio_fixture();
    let started = std::time::Instant::now();

    let probe = run_production_stdio_fixture_with(
        &fixture,
        "hang-with-escaped-descendant-exit",
        Duration::from_millis(100),
    );

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "an escaped stdout holder exceeded the hard protocol deadline"
    );
    assert_eq!(
        ControlPlaneAdmission::from_probe(probe)
            .admit(ControlPlaneOperation::Run)
            .expect_err("an incomplete escaped-child handshake must remain blocked")
            .details["reason"],
        serde_json::json!("handshake_unavailable")
    );
}

fn run_fixture(mode: &'static str) -> super::control_plane::ControlPlaneProbe {
    run_fixture_with_timeout(mode, Duration::from_secs(2))
}

fn run_fixture_with_timeout(
    mode: &'static str,
    timeout: Duration,
) -> super::control_plane::ControlPlaneProbe {
    let fixture = compile_stdio_fixture();
    let app_server_mode = if mode == "timeout" {
        "hang-with-descendant"
    } else {
        "success"
    };
    run_schema_and_stdio_fixture_with(&fixture, mode, app_server_mode, timeout)
}

fn run_schema_and_stdio_fixture_with(
    fixture: &CompiledStdioFixture,
    schema_mode: &'static str,
    app_server_mode: &'static str,
    timeout: Duration,
) -> super::control_plane::ControlPlaneProbe {
    let schema_command = move |schema_dir: &Path| {
        let mut command = fixture_command("schema_fixture_child");
        command
            .env(FIXTURE_MODE, schema_mode)
            .env(FIXTURE_SCHEMA_DIR, schema_dir);
        command
    };
    let mut app_server = Command::new(fixture.executable());
    app_server.arg(app_server_mode);

    probe_control_plane_with(schema_command, app_server, timeout)
}

fn run_production_stdio_fixture(
    mode: &'static str,
    timeout: Duration,
) -> super::control_plane::ControlPlaneProbe {
    let fixture = compile_stdio_fixture();
    run_production_stdio_fixture_with(&fixture, mode, timeout)
}

fn run_production_stdio_fixture_with(
    fixture: &CompiledStdioFixture,
    mode: &'static str,
    timeout: Duration,
) -> super::control_plane::ControlPlaneProbe {
    run_schema_and_stdio_fixture_with(fixture, "required", mode, timeout)
}

pub(super) struct CompiledStdioFixture {
    _directory: tempfile::TempDir,
    executable: PathBuf,
}

impl CompiledStdioFixture {
    pub(super) fn executable(&self) -> &Path {
        &self.executable
    }
}

pub(super) fn compile_stdio_fixture() -> CompiledStdioFixture {
    let directory = tempfile::tempdir().expect("create stdio fixture directory");
    let source = directory.path().join("stdio-fixture.rs");
    std::fs::write(&source, STDIO_FIXTURE_SOURCE).expect("write stdio fixture source");
    let executable = directory.path().join(if cfg!(windows) {
        "stdio-fixture.exe"
    } else {
        "stdio-fixture"
    });
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc)
        .arg(&source)
        .arg("--edition=2024")
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile production stdio fixture");
    assert!(
        output.status.success(),
        "stdio fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    CompiledStdioFixture {
        _directory: directory,
        executable,
    }
}

fn fixture_command(test_name: &str) -> Command {
    let mut command = Command::new(
        std::env::current_exe().expect("the current test executable should be available"),
    );
    command.args([
        "--exact",
        &format!("codex_capabilities::control_plane_tests::{test_name}"),
        "--ignored",
        "--nocapture",
        "--quiet",
    ]);
    command
}

#[test]
#[ignore = "spawned by the process-backed protocol probe tests"]
fn schema_fixture_child() {
    let Some(mode) = std::env::var_os(FIXTURE_MODE) else {
        return;
    };
    let schema_dir = std::env::var_os(FIXTURE_SCHEMA_DIR)
        .map(std::path::PathBuf::from)
        .expect("the schema fixture directory must be provided");
    if mode == "timeout" {
        // Spending part of the budget here proves schema discovery and the
        // live handshake share one deadline instead of receiving fresh timers.
        std::thread::sleep(Duration::from_secs(3));
    }
    let include_cancellation = !matches!(
        mode.to_str(),
        Some("missing-cancellation" | "decoy-cancellation")
    );

    let mut client_methods = vec!["initialize", "thread/start", "turn/start", "thread/read"];
    if mode != "missing-steering" {
        client_methods.push("thread/resume");
    }
    if include_cancellation {
        client_methods.push("turn/interrupt");
    }
    client_methods.push(RAW_SCHEMA_CANARY);

    write_method_schema(
        &schema_dir.join("ClientRequest.json"),
        &client_methods,
        (mode == "decoy-cancellation").then_some("turn/interrupt"),
    );
    write_method_schema(
        &schema_dir.join("ClientNotification.json"),
        &["initialized"],
        None,
    );
    write_method_schema(
        &schema_dir.join("ServerNotification.json"),
        &[
            "thread/started",
            "turn/started",
            "item/started",
            "item/completed",
            "turn/completed",
            RAW_SCHEMA_CANARY,
        ],
        None,
    );
}

fn write_method_schema(path: &Path, methods: &[&str], nested_decoy: Option<&str>) {
    let variants = methods
        .iter()
        .map(|method| {
            json!({
                "type": "object",
                "properties": {"method": {"type": "string", "enum": [method]}}
            })
        })
        .collect::<Vec<_>>();
    let nested_decoy = nested_decoy.into_iter().collect::<Vec<_>>();
    serde_json::to_writer(
        File::create(path).expect("create fixture schema"),
        &json!({
            "oneOf": variants,
            "definitions": {
                "UnusedPayload": {
                    "properties": {"method": {"enum": nested_decoy}}
                }
            }
        }),
    )
    .expect("write fixture schema");
}
