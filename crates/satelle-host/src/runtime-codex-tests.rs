#[cfg(target_os = "macos")]
use super::control_plane::MacosNativeSessionResources;
#[cfg(unix)]
use super::control_plane::perform_handshake;
#[cfg(unix)]
#[cfg(unix)]
use super::control_plane::validate_macos_computer_use_service_layout;
use super::control_plane::{
    CodexImageInputMode, ControlPlaneAdmission, NativeMcpBinding,
    PlannedNativeComputerUseActionPath, bounded_inventory_command_output,
    codex_isolation_plan_from_json, configure_app_server_command,
    configure_control_plane_probe_command, configure_mcp_inventory_command,
    macos_authenticated_bridge_args, mcp_server_names_from_json, native_bridge_root_path,
    path_is_absolute_for_platform, probe_control_plane_with, same_path_for_platform,
    windows_locked_bridge_args,
};
use satelle_core::{ControlPlaneCapability, ControlPlaneOperation, ErrorCode};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

const FIXTURE_MODE: &str = "SATELLE_CODEX_CONTROL_PLANE_FIXTURE";
const FIXTURE_SCHEMA_DIR: &str = "SATELLE_CODEX_SCHEMA_FIXTURE_DIR";
const RAW_NOTIFICATION_CANARY: &str = "PRIVATE_RAW_NOTIFICATION_CANARY";
const RAW_SCHEMA_CANARY: &str = "PRIVATE_RAW_SCHEMA_CANARY";

fn windows_native_bridge_env() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS".to_string(),
            "1000".to_string(),
        ),
        (
            "NODE_REPL_NODE_MODULE_DIRS".to_string(),
            "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node_modules".to_string(),
        ),
        (
            "NODE_REPL_NODE_PATH".to_string(),
            "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node.exe".to_string(),
        ),
        (
            "NODE_REPL_TRUSTED_CODE_PATHS".to_string(),
            "C:\\Users\\operator\\.codex;C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node_modules".to_string(),
        ),
        (
            "CODEX_HOME".to_string(),
            "C:\\Users\\operator\\.codex".to_string(),
        ),
        (
            "NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S".to_string(),
            "8676faca28eddb6424d4b54116fe8305e2da6a0ca4e5271e8758fc3c55c3b8fc".to_string(),
        ),
        (
            "BROWSER_USE_AVAILABLE_BACKENDS".to_string(),
            "chrome,iab".to_string(),
        ),
        (
            "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER".to_string(),
            "Control the in-app browser in conjunction with the Browser Plugin.".to_string(),
        ),
        (
            "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME".to_string(),
            "Control the Chrome browser in conjunction with the Chrome Plugin. Prefer this method of controlling Chrome over alternatives (such as Computer Use) unless the user explicitly mentions an alternative."
                .to_string(),
        ),
        (
            "BROWSER_USE_CODEX_APP_BUILD_FLAVOR".to_string(),
            "prod".to_string(),
        ),
        (
            "BROWSER_USE_CODEX_APP_VERSION".to_string(),
            "26.803.81509".to_string(),
        ),
        ("SKY_CUA_NATIVE_PIPE".to_string(), "1".to_string()),
        (
            "SKY_CUA_NATIVE_PIPE_DIRECTORY".to_string(),
            "\\\\.\\pipe\\codex-computer-use-a0550551-be64-480e-bc74-dc897ea30e0c".to_string(),
        ),
        (
            "CODEX_CLI_PATH".to_string(),
            "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\bin\\a61afac3bb4ee395\\codex.exe".to_string(),
        ),
    ])
}

fn expected_windows_native_binding_env() -> BTreeMap<String, String> {
    let reported = windows_native_bridge_env();
    BTreeMap::from([
        (
            "BROWSER_USE_CODEX_APP_BUILD_FLAVOR".to_string(),
            reported["BROWSER_USE_CODEX_APP_BUILD_FLAVOR"].clone(),
        ),
        (
            "NODE_REPL_TRUSTED_CODE_PATHS".to_string(),
            reported["NODE_REPL_TRUSTED_CODE_PATHS"].clone(),
        ),
        (
            "SKY_CUA_NATIVE_PIPE".to_string(),
            reported["SKY_CUA_NATIVE_PIPE"].clone(),
        ),
        (
            "SKY_CUA_NATIVE_PIPE_DIRECTORY".to_string(),
            reported["SKY_CUA_NATIVE_PIPE_DIRECTORY"].clone(),
        ),
    ])
}

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
        Some("inventory-success") => println!("{{\"installed\":[]}}"),
        Some("inventory-with-escaped-descendant") => {
            spawn_escaped_descendant();
            println!("{{\"installed\":[]}}")
        }
        Some("inventory-large") => print!("{}", "x".repeat(128 * 1024)),
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
fn goal_and_local_image_are_detected_from_canonical_schema_paths() {
    let admission = ControlPlaneAdmission::from_probe(run_fixture("goal-local-image"));

    assert!(admission.goal_set());
    assert_eq!(admission.image_input(), CodexImageInputMode::Local);
}

#[test]
fn inline_image_is_detected_when_local_image_is_absent() {
    let admission = ControlPlaneAdmission::from_probe(run_fixture("inline-image"));

    assert!(admission.goal_set());
    assert_eq!(admission.image_input(), CodexImageInputMode::Inline);
}

#[test]
fn optional_capability_decoys_outside_canonical_paths_are_ignored() {
    let admission = ControlPlaneAdmission::from_probe(run_fixture("optional-decoy"));

    assert!(!admission.goal_set());
    assert_eq!(admission.image_input(), CodexImageInputMode::Unsupported);
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
    let admission = ControlPlaneAdmission::from_probe(probe);
    assert!(!admission.goal_set());
    assert_eq!(admission.image_input(), CodexImageInputMode::Unsupported);
    assert_eq!(
        admission
            .admit(ControlPlaneOperation::Run)
            .expect_err("the incomplete handshake must remain blocked")
            .details["reason"],
        serde_json::json!("handshake_unavailable")
    );
}

#[test]
fn inventory_probe_is_bounded_and_terminates_descendants() {
    let fixture = compile_stdio_fixture();
    let mut success = Command::new(fixture.executable());
    success.arg("inventory-success");
    assert_eq!(
        bounded_inventory_command_output(
            success,
            Instant::now() + Duration::from_secs(2),
            "inventory_unavailable",
            "inventory_failed",
        )
        .expect("a bounded inventory command should return its output"),
        br#"{"installed":[]}
"#
    );

    let mut large = Command::new(fixture.executable());
    large.arg("inventory-large");
    assert_eq!(
        bounded_inventory_command_output(
            large,
            Instant::now() + Duration::from_secs(2),
            "inventory_unavailable",
            "inventory_failed",
        )
        .expect("inventory output larger than a pipe buffer must be drained concurrently")
        .len(),
        128 * 1024
    );

    let mut hanging = Command::new(fixture.executable());
    hanging.arg("hang-with-descendant");
    let started = Instant::now();
    let error = bounded_inventory_command_output(
        hanging,
        Instant::now() + Duration::from_millis(250),
        "inventory_unavailable",
        "inventory_failed",
    )
    .expect_err("a hanging inventory process must fail closed");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(error.details["reason"], json!("inventory_unavailable"));
}

#[cfg(unix)]
#[test]
fn complete_inventory_does_not_wait_for_an_escaped_stdout_holder() {
    let fixture = compile_stdio_fixture();
    let mut command = Command::new(fixture.executable());
    command.arg("inventory-with-escaped-descendant");

    assert_eq!(
        bounded_inventory_command_output(
            command,
            Instant::now() + Duration::from_secs(1),
            "inventory_unavailable",
            "inventory_failed",
        )
        .expect("one complete JSON inventory value must not require pipe EOF"),
        br#"{"installed":[]}
"#
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
    let native_binding = NativeMcpBinding {
        command: "C:\\OpenAI\\node_repl.exe".to_string(),
        args: Vec::new(),
        env: BTreeMap::from([
            (
                "BROWSER_USE_CODEX_APP_BUILD_FLAVOR".to_string(),
                "prod".to_string(),
            ),
            ("SKY_CUA_NATIVE_PIPE".to_string(), "1".to_string()),
        ]),
    };
    let command = configure_app_server_command(
        Command::new("receipt-recorded-codex"),
        &["mcp-vnc".to_string(), "paper".to_string()],
        "node_repl",
        &native_binding,
    );
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    let native_command_config = arguments
        .iter()
        .find(|argument| argument.starts_with("mcp_servers.node_repl.command="))
        .expect("the native command must be pinned");
    let native_args_config = arguments
        .iter()
        .find(|argument| argument.starts_with("mcp_servers.node_repl.args="))
        .expect("the native arguments must be pinned");
    let native_env_config = arguments
        .iter()
        .find(|argument| argument.starts_with("mcp_servers.node_repl.env="))
        .expect("the native environment must be pinned");
    assert!(!native_args_config.contains('\n') && !native_args_config.contains('\r'));
    assert!(!native_env_config.contains('\n') && !native_env_config.contains('\r'));
    let parse_value = |config: &str, prefix: &str| {
        toml::from_str::<toml::Value>(&format!("value = {}", config.strip_prefix(prefix).unwrap()))
            .expect("the native launch binding must be valid TOML")["value"]
            .clone()
    };
    assert_eq!(
        parse_value(native_command_config, "mcp_servers.node_repl.command=").as_str(),
        Some("C:\\OpenAI\\node_repl.exe")
    );
    assert!(
        parse_value(native_args_config, "mcp_servers.node_repl.args=")
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        parse_value(native_env_config, "mcp_servers.node_repl.env=")
            .as_table()
            .unwrap(),
        &toml::Table::from_iter([
            (
                "BROWSER_USE_CODEX_APP_BUILD_FLAVOR".to_string(),
                toml::Value::String("prod".to_string()),
            ),
            (
                "SKY_CUA_NATIVE_PIPE".to_string(),
                toml::Value::String("1".to_string()),
            ),
        ])
    );
    assert_eq!(
        arguments,
        [
            "app-server",
            "--config",
            "mcp_servers.mcp-vnc.enabled=false",
            "--config",
            "mcp_servers.paper.enabled=false",
            "--config",
            "mcp_servers.node_repl.enabled=true",
            "--config",
            native_command_config.as_str(),
            "--config",
            native_args_config.as_str(),
            "--config",
            native_env_config.as_str(),
            "--config",
            "features.auth_elicitation=true",
            "--config",
            "features.tool_call_mcp_elicitation=true",
            "--config",
            "features.apps=false",
            "--config",
            "features.plugins=false",
            "--listen",
            "stdio://"
        ]
    );
    assert_eq!(
        command
            .get_envs()
            .find(|(key, _)| *key == "SKY_CUA_NATIVE_PIPE")
            .and_then(|(_, value)| value)
            .and_then(|value| value.to_str()),
        Some("1")
    );
    assert!(
        !arguments
            .iter()
            .any(|argument| { argument.starts_with("ws://") || argument.starts_with("unix://") })
    );
}

#[cfg(windows)]
#[test]
fn windows_protected_bridge_selection_preserves_the_admitted_identity() {
    use super::control_plane::{matching_native_bridge_path, native_bridge_digest};

    let directory = tempfile::tempdir().expect("create native bridge fixture");
    let inventory_bridge = directory.path().join("inventory-node_repl.exe");
    let protected_bridge = directory.path().join("protected-node_repl.exe");
    let mismatched_bridge = directory.path().join("mismatched-node_repl.exe");
    std::fs::write(&inventory_bridge, b"official bridge bytes").expect("write inventory fixture");
    std::fs::write(&protected_bridge, b"official bridge bytes").expect("write protected fixture");
    std::fs::write(&mismatched_bridge, b"replacement bytes").expect("write mismatch fixture");
    let admitted_digest = native_bridge_digest(&inventory_bridge).expect("hash inventory bridge");

    std::fs::write(&inventory_bridge, b"replacement bytes").expect("replace mutable inventory");
    let selected = matching_native_bridge_path(
        &admitted_digest,
        [mismatched_bridge, protected_bridge.clone()],
    )
    .expect("select the exact protected package bridge");

    assert_eq!(selected, protected_bridge);
}

#[test]
fn windows_protected_bridge_accepts_any_well_formed_desktop_version() {
    use super::control_plane::windows_package_full_name_has_valid_version;

    assert!(windows_package_full_name_has_valid_version(
        "OpenAI.Codex_26.803.5235.0_x64__2p2nqsd0c76g0",
    ));
    assert!(windows_package_full_name_has_valid_version(
        "OpenAI.Codex_27.1.0.0_x64__2p2nqsd0c76g0",
    ));
    assert!(!windows_package_full_name_has_valid_version(
        "OpenAI.Codex_27..0.0_x64__2p2nqsd0c76g0",
    ));
}

#[test]
fn windows_bridge_launcher_locks_the_authenticated_path_before_spawn() {
    let args =
        windows_locked_bridge_args(Path::new(r"C:\Users\O'Brien\node_repl.exe"), &[0xab; 32]);

    assert_eq!(
        &args[..4],
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
    );
    let command = &args[4];
    let lock = command
        .find("[System.IO.FileShare]::Read")
        .expect("the checked bridge must deny write and delete sharing");
    let hash = command
        .find("ComputeHash($stream)")
        .expect("the held file must be authenticated");
    let spawn = command
        .find("[System.Diagnostics.Process]::Start($start)")
        .expect("the authenticated bridge must be started while held");
    assert!(lock < hash && hash < spawn);
    assert!(command.contains(r"'C:\Users\O''Brien\node_repl.exe'"));
    assert!(command.contains(&format!("'{}'", "ab".repeat(32))));
}

#[cfg(windows)]
#[test]
fn windows_bridge_launcher_executes_the_authenticated_held_file() {
    use super::control_plane::{
        native_bridge_digest, windows_locked_bridge_args, windows_powershell_path,
    };
    use std::process::Stdio;

    let directory = tempfile::tempdir().expect("create locked launcher fixture");
    let bridge = directory.path().join("whoami.exe");
    let system_root = std::env::var_os("SystemRoot").expect("Windows must define SystemRoot");
    std::fs::copy(
        PathBuf::from(system_root)
            .join("System32")
            .join("whoami.exe"),
        &bridge,
    )
    .expect("copy a harmless signed executable");
    let digest = native_bridge_digest(&bridge).expect("hash the held executable");

    let status = Command::new(windows_powershell_path().expect("resolve protected PowerShell"))
        .args(windows_locked_bridge_args(&bridge, &digest))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run the locked launcher");

    assert!(status.success());

    let rejected = Command::new(windows_powershell_path().expect("resolve protected PowerShell"))
        .args(windows_locked_bridge_args(&bridge, &[0; 32]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("reject a digest mismatch");
    assert_eq!(rejected.code(), Some(74));
}

#[test]
fn control_plane_probe_disables_every_discovered_mcp_server() {
    let inventory = serde_json::to_vec(&json!([
        {
            "name": "paper",
            "transport": { "type": "stdio", "command": "paper", "args": [], "env": {} }
        },
        {
            "name": "node_repl",
            "transport": { "type": "stdio", "command": "node_repl", "args": [], "env": {} }
        }
    ]))
    .unwrap();
    let names = mcp_server_names_from_json(&inventory).expect("valid MCP names must be isolated");
    let command = configure_control_plane_probe_command(Command::new("codex"), &names);
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        arguments,
        [
            "app-server",
            "--config",
            "mcp_servers.node_repl.enabled=false",
            "--config",
            "mcp_servers.paper.enabled=false",
            "--config",
            "features.apps=false",
            "--config",
            "features.plugins=false",
            "--listen",
            "stdio://",
        ]
    );
}

#[test]
fn mcp_inventory_excludes_plugin_derived_servers() {
    let command = configure_mcp_inventory_command(Command::new("codex"));
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        arguments,
        [
            "mcp",
            "list",
            "--config",
            "features.plugins=false",
            "--json",
        ]
    );
}

#[test]
fn read_only_app_server_keeps_native_computer_use_disabled() {
    let command = configure_control_plane_probe_command(
        Command::new("codex"),
        &["node_repl".to_string(), "paper".to_string()],
    );
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(arguments.contains(&"mcp_servers.node_repl.enabled=false".to_string()));
    assert!(arguments.contains(&"features.apps=false".to_string()));
    assert!(arguments.contains(&"features.plugins=false".to_string()));
    assert!(!arguments.iter().any(|argument| {
        argument == "features.plugins=true" || argument == "features.remote_plugin=true"
    }));
}

#[test]
fn macos_bridge_launcher_requires_the_exact_spawned_code_identity() {
    let args = macos_authenticated_bridge_args(
        Path::new("/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl"),
        "fccc86027f96363299379fa64814147a555b3f49",
        "1111111111111111111111111111111111111111",
    );

    assert_eq!(
        args,
        [
            "__satelle-launch-macos-native-bridge",
            "1111111111111111111111111111111111111111",
            "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl",
            "fccc86027f96363299379fa64814147a555b3f49",
        ]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_native_resources_remove_an_unconsumed_launcher() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let directory = PathBuf::from(format!(
        "/tmp/satelle-native-launcher-test-{}",
        uuid::Uuid::now_v7()
    ));
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700).create(&directory).unwrap();
    let launcher = directory.join("satelle");
    std::fs::write(&launcher, b"unconsumed launcher").unwrap();
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o700)).unwrap();

    let resources = MacosNativeSessionResources::start(directory.clone());

    drop(resources);
    assert!(!directory.exists());
}

#[test]
fn isolation_preserves_only_the_validated_official_computer_use_path() {
    let plugins = serde_json::to_vec(&json!({
        "installed": [
            {
                "pluginId": "browser@openai-bundled",
                "marketplaceName": "openai-bundled",
                "installed": true,
                "enabled": true,
                "source": {
                    "source": "local",
                    "path": "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\browser"
                }
            },
            {
                "pluginId": "computer-use@openai-bundled",
                "marketplaceName": "openai-bundled",
                "installed": true,
                "enabled": true,
                "version": "27.1.0",
                "source": {
                    "source": "local",
                    "path": "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use"
                }
            },
            {
                "pluginId": "disabled@openai-curated",
                "marketplaceName": "openai-curated",
                "installed": true,
                "enabled": false,
                "source": {
                    "source": "local",
                    "path": "C:\\Users\\operator\\.codex\\plugins\\disabled"
                }
            }
        ]
    }))
    .expect("serialize plugin fixture");
    let mut mcp_inventory = json!([
        {
            "name": "paper",
            "transport": { "type": "stdio", "command": "node", "args": [], "env": {} }
        },
        {
            "name": "node_repl",
            "transport": {
                "type": "stdio",
                "command": "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node_repl.exe",
                "args": [],
                "env": windows_native_bridge_env()
            }
        }
    ]);
    let mcp_servers = serde_json::to_vec(&mcp_inventory).expect("serialize MCP fixture");

    let plan = codex_isolation_plan_from_json(
        &plugins,
        &mcp_servers,
        "windows",
        Path::new("C:\\Users\\operator\\.codex"),
        Path::new("C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node"),
    )
    .expect("the official Windows bridge must be admitted");

    assert_eq!(plan.native_mcp_server_name, "node_repl");
    assert_eq!(
        plan.planned_native_action_path,
        PlannedNativeComputerUseActionPath::WindowsNodeRepl
    );
    assert_eq!(
        plan.native_mcp_binding.env,
        expected_windows_native_binding_env()
    );
    assert_eq!(plan.disabled_mcp_server_names, ["paper"]);

    mcp_inventory[1]["transport"]["cwd"] = json!("C:\\Users\\operator");
    let error = codex_isolation_plan_from_json(
        &plugins,
        &serde_json::to_vec(&mcp_inventory).expect("serialize redirected MCP fixture"),
        "windows",
        Path::new("C:\\Users\\operator\\.codex"),
        Path::new("C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node"),
    )
    .expect_err("the Windows bridge must not inherit an inventory working directory");
    assert_eq!(error.details["reason"], json!("native_bridge_untrusted"));
}

#[test]
fn isolation_rejects_incomplete_or_tampered_windows_bridge_environment() {
    let plugins = serde_json::to_vec(&json!({
        "installed": [{
            "pluginId": "computer-use@openai-bundled",
            "marketplaceName": "openai-bundled",
            "installed": true,
            "enabled": true,
            "version": "26.803.41515",
            "source": {
                "source": "local",
                "path": "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use"
            }
        }]
    }))
    .expect("serialize plugin fixture");
    for mutate in [
        |env: &mut BTreeMap<String, String>| {
            env.remove("NODE_REPL_TRUSTED_CODE_PATHS");
        },
        |env: &mut BTreeMap<String, String>| {
            env.insert(
                "NODE_REPL_TRUSTED_CODE_PATHS".to_string(),
                "C:\\Users\\operator\\Downloads".to_string(),
            );
        },
    ] {
        let mut env = windows_native_bridge_env();
        mutate(&mut env);
        let mcp_servers = serde_json::to_vec(&json!([{
            "name": "node_repl",
            "transport": {
                "type": "stdio",
                "command": "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node_repl.exe",
                "args": [],
                "env": env
            }
        }]))
        .expect("serialize MCP fixture");

        let error = codex_isolation_plan_from_json(
            &plugins,
            &mcp_servers,
            "windows",
            Path::new("C:\\Users\\operator\\.codex"),
            Path::new("C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node"),
        )
        .expect_err("the trusted bridge environment must fail closed");

        assert_eq!(error.details["reason"], json!("native_bridge_untrusted"));
    }
}

#[test]
fn windows_plugin_path_accepts_the_canonical_verbatim_drive_form_only() {
    let reported = Path::new(
        "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use",
    );
    let canonical = Path::new(
        "\\\\?\\C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use",
    );

    assert!(same_path_for_platform(reported, canonical, "windows"));
    assert!(path_is_absolute_for_platform(canonical, "windows"));
    assert!(!same_path_for_platform(
        reported,
        Path::new("\\\\?\\UNC\\server\\share\\computer-use"),
        "windows",
    ));
    assert!(!path_is_absolute_for_platform(
        Path::new("\\\\.\\C:\\computer-use"),
        "windows",
    ));
}

#[test]
fn isolation_rejects_a_same_named_bridge_outside_the_official_runtime() {
    let plugins = serde_json::to_vec(&json!({
        "installed": [{
            "pluginId": "computer-use@openai-bundled",
            "marketplaceName": "openai-bundled",
            "installed": true,
            "enabled": true,
            "version": "26.803.41515",
            "source": {
                "source": "local",
                "path": "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use"
            }
        }]
    }))
    .expect("serialize plugin fixture");
    let mcp_servers = serde_json::to_vec(&json!([{
        "name": "node_repl",
        "transport": {
            "type": "stdio",
            "command": "C:\\Users\\operator\\bin\\node_repl.exe",
            "args": [],
            "env": {
                "SKY_CUA_NATIVE_PIPE": "1",
                "SKY_CUA_NATIVE_PIPE_DIRECTORY": "C:\\Users\\operator\\AppData\\Local\\Temp\\codex-computer-use",
                "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod"
            }
        }
    }]))
    .expect("serialize MCP fixture");

    let error = codex_isolation_plan_from_json(
        &plugins,
        &mcp_servers,
        "windows",
        Path::new("C:\\Users\\operator\\.codex"),
        Path::new("C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node"),
    )
    .expect_err("an arbitrary same-named executable must not become the native bridge");

    assert_eq!(error.code, ErrorCode::ComputerUseNotReady);
    assert_eq!(error.details["reason"], json!("native_bridge_untrusted"));
}

#[test]
fn isolation_rejects_malformed_or_redirected_computer_use_plugins() {
    let mcp_servers = serde_json::to_vec(&json!([{
        "name": "node_repl",
        "transport": {
            "type": "stdio",
            "command": "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node_repl.exe",
            "args": [],
            "env": {
                "SKY_CUA_NATIVE_PIPE": "1",
                "SKY_CUA_NATIVE_PIPE_DIRECTORY": "C:\\Users\\operator\\AppData\\Local\\Temp\\codex-computer-use",
                "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod"
            }
        }
    }]))
    .expect("serialize MCP fixture");

    for (version, path, expected_reason) in [
        (
            "26..99999",
            "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use",
            "computer_use_plugin_not_ready",
        ),
        (
            "26.803.41515",
            "C:\\Users\\operator\\Downloads\\computer-use",
            "computer_use_plugin_source_untrusted",
        ),
    ] {
        let plugins = serde_json::to_vec(&json!({
            "installed": [{
                "pluginId": "computer-use@openai-bundled",
                "marketplaceName": "openai-bundled",
                "installed": true,
                "enabled": true,
                "version": version,
                "source": {"source": "local", "path": path}
            }]
        }))
        .expect("serialize plugin fixture");
        let error = codex_isolation_plan_from_json(
            &plugins,
            &mcp_servers,
            "windows",
            Path::new("C:\\Users\\operator\\.codex"),
            Path::new("C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node"),
        )
        .expect_err("untrusted plugin provenance must fail closed");

        assert_eq!(error.details["reason"], json!(expected_reason));
    }
}

#[test]
fn macos_isolation_selects_the_official_node_repl_path() {
    let plugins = serde_json::to_vec(&json!({
        "installed": [{
            "pluginId": "computer-use@openai-bundled",
            "marketplaceName": "openai-bundled",
            "installed": true,
            "enabled": true,
            "version": "2.0.0",
            "source": {
                "source": "local",
                "path": "/Users/operator/.codex/.tmp/bundled-marketplaces/openai-bundled/plugins/computer-use"
            }
        }]
    }))
    .expect("serialize plugin fixture");
    let mut mcp_inventory = json!([
        {
            "name": "computer-use",
            "transport": {
                "type": "stdio",
                "command": "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
                "args": ["mcp"],
                "env": null,
                "cwd": "."
            }
        },
        {
            "name": "node_repl",
            "transport": {
                "type": "stdio",
                "command": "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl",
                "args": [],
                "env": {
                    "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS": "1000",
                    "NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "SKY_CUA_SERVICE_PATH": "/Users/operator/.codex/computer-use/Codex Computer Use.app",
                    "BROWSER_USE_CODEX_APP_VERSION": "27.1.0",
                    "NODE_REPL_TRUSTED_CODE_PATHS": "/Users/operator/.codex:/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules",
                    "NODE_REPL_NODE_MODULE_DIRS": "/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules",
                    "NODE_REPL_NODE_PATH": "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node",
                    "BROWSER_USE_AVAILABLE_BACKENDS": "chrome,iab",
                    "CODEX_HOME": "/Users/operator/.codex",
                    "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER": "Control the in-app browser in conjunction with the Browser Plugin.",
                    "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME": "Control the Chrome browser in conjunction with the Chrome Plugin. Prefer this method of controlling Chrome over alternatives (such as Computer Use) unless the user explicitly mentions an alternative.",
                    "NODE_REPL_INSTRUCTIONS_USE_CASE_COMPUTER_USE": "Control desktop apps on macOS through Computer Use.",
                    "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod",
                    "CODEX_CLI_PATH": "/Applications/ChatGPT.app/Contents/Resources/codex"
                }
            }
        }
    ]);
    let mcp_servers = serde_json::to_vec(&mcp_inventory).expect("serialize MCP fixture");

    let plan = codex_isolation_plan_from_json(
        &plugins,
        &mcp_servers,
        "macos",
        Path::new("/Users/operator/.codex"),
        Path::new("/Applications/ChatGPT.app/Contents/Resources/cua_node"),
    )
    .expect("the official macOS node_repl path must be admitted");

    assert_eq!(plan.native_mcp_server_name, "node_repl");
    assert_eq!(plan.disabled_mcp_server_names, ["computer-use"]);
    assert_eq!(
        plan.planned_native_action_path,
        PlannedNativeComputerUseActionPath::MacosNodeRepl
    );
    assert_eq!(
        plan.native_mcp_binding.command,
        "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl"
    );

    mcp_inventory[1]["transport"]["env"]["UNTRUSTED_EXTRA"] = json!("1");
    let error = codex_isolation_plan_from_json(
        &plugins,
        &serde_json::to_vec(&mcp_inventory).expect("serialize tampered MCP fixture"),
        "macos",
        Path::new("/Users/operator/.codex"),
        Path::new("/Applications/ChatGPT.app/Contents/Resources/cua_node"),
    )
    .expect_err("unrecognized node_repl environment must fail closed");
    assert_eq!(error.details["reason"], json!("native_bridge_untrusted"));

    mcp_inventory[1]["transport"]["env"]
        .as_object_mut()
        .expect("node_repl environment")
        .remove("UNTRUSTED_EXTRA");
    mcp_inventory[1]["transport"]["env"]["NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S"] =
        json!("not-a-sha256");
    let error = codex_isolation_plan_from_json(
        &plugins,
        &serde_json::to_vec(&mcp_inventory).expect("serialize malformed digest fixture"),
        "macos",
        Path::new("/Users/operator/.codex"),
        Path::new("/Applications/ChatGPT.app/Contents/Resources/cua_node"),
    )
    .expect_err("a malformed bridge client digest must fail closed");
    assert_eq!(error.details["reason"], json!("native_bridge_untrusted"));
}

#[test]
fn macos_isolation_rejects_a_malformed_plugin_version_or_relative_bridge_base() {
    for (version, command, cwd) in [
        (
            "1..0",
            "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
            ".",
        ),
        (
            "1.0.1000621",
            "../computer-use/Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
            ".",
        ),
        (
            "1.0.1000621",
            "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
            "/tmp",
        ),
    ] {
        let plugins = serde_json::to_vec(&json!({
            "installed": [{
                "pluginId": "computer-use@openai-bundled",
                "marketplaceName": "openai-bundled",
                "installed": true,
                "enabled": true,
                "version": version,
                "source": {
                    "source": "local",
                    "path": "/Users/operator/.codex/.tmp/bundled-marketplaces/openai-bundled/plugins/computer-use"
                }
            }]
        }))
        .expect("serialize plugin fixture");
        let mcp_servers = serde_json::to_vec(&json!([{
            "name": "computer-use",
            "transport": {
                "type": "stdio",
                "command": command,
                "args": ["mcp"],
                "env": null,
                "cwd": cwd
            }
        }]))
        .expect("serialize MCP fixture");

        codex_isolation_plan_from_json(
            &plugins,
            &mcp_servers,
            "macos",
            Path::new("/Users/operator/.codex"),
            Path::new("/Users/operator/.codex/computer-use/Codex Computer Use.app"),
        )
        .expect_err("macOS Computer Use authority must stay on the exact signed bundle contract");
    }
}

#[test]
fn macos_native_bridge_root_is_the_chatgpt_node_runtime() {
    assert_eq!(
        native_bridge_root_path("macos", Path::new("/Users/operator/.codex")),
        Some(PathBuf::from(
            "/Applications/ChatGPT.app/Contents/Resources/cua_node"
        ))
    );
}

#[cfg(unix)]
#[test]
fn macos_computer_use_service_layout_rejects_redirected_executable_identity() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("create macOS service fixture");
    let codex_home = directory.path().join("codex-home");
    let bundle = codex_home
        .join("computer-use")
        .join("Codex Computer Use.app");
    let macos = bundle.join("Contents").join("MacOS");
    std::fs::create_dir_all(&macos).expect("create exact service bundle layout");
    std::fs::write(bundle.join("Contents").join("Info.plist"), "fixture")
        .expect("write service metadata fixture");
    let executable = macos.join("SkyComputerUseService");
    std::fs::write(&executable, "fixture").expect("write service executable fixture");
    assert_eq!(
        validate_macos_computer_use_service_layout(&codex_home)
            .expect("the exact regular bundle layout must be accepted"),
        std::fs::canonicalize(&bundle).expect("canonicalize exact service bundle fixture")
    );

    std::fs::remove_file(&executable).expect("remove regular executable fixture");
    let redirected = directory.path().join("replacement-service");
    std::fs::write(&redirected, "replacement").expect("write redirected service fixture");
    symlink(&redirected, &executable).expect("redirect the service executable");
    let error = validate_macos_computer_use_service_layout(&codex_home)
        .expect_err("a redirected service executable must fail closed");
    assert_eq!(
        error.details["reason"],
        json!("computer_use_service_untrusted")
    );
}

#[test]
fn isolation_rejects_application_shaped_bridges_outside_the_official_roots() {
    for (platform, command, codex_home, trusted_root) in [
        (
            "macos",
            "/tmp/ChatGPT.app/Contents/Resources/cua_node/bin/node_repl",
            "/Users/operator/.codex",
            "/Applications/ChatGPT.app/Contents/Resources/cua_node",
        ),
        (
            "windows",
            "C:\\Users\\operator\\lookalike\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node\\f1359d6e9a17bb1d\\bin\\node_repl.exe",
            "C:\\Users\\operator\\.codex",
            "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node",
        ),
        (
            "windows",
            "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_nodef1359d6e9a17bb1d\\bin\\node_repl.exe",
            "C:\\Users\\operator\\.codex",
            "C:\\Users\\operator\\AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node",
        ),
    ] {
        let plugin_path = if platform == "macos" {
            "/Users/operator/.codex/.tmp/bundled-marketplaces/openai-bundled/plugins/computer-use"
        } else {
            "C:\\Users\\operator\\.codex\\.tmp\\bundled-marketplaces\\openai-bundled\\plugins\\computer-use"
        };
        let plugins = serde_json::to_vec(&json!({
            "installed": [{
                "pluginId": "computer-use@openai-bundled",
                "marketplaceName": "openai-bundled",
                "installed": true,
                "enabled": true,
                "version": if platform == "macos" { "1.0.1000621" } else { "26.803.41515" },
                "source": {"source": "local", "path": plugin_path}
            }]
        }))
        .expect("serialize plugin fixture");
        let (server_name, args, env) = if platform == "macos" {
            (
                "node_repl",
                json!([]),
                json!({
                    "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS": "1000",
                    "NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S": "091a81603ff202a16ed56557709bf42d97caf8f0dd2e07ae9e26d7c014d71035",
                    "SKY_CUA_SERVICE_PATH": "/Users/operator/.codex/computer-use/Codex Computer Use.app",
                    "BROWSER_USE_CODEX_APP_VERSION": "26.730.61639",
                    "NODE_REPL_TRUSTED_CODE_PATHS": "/Users/operator/.codex:/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules",
                    "NODE_REPL_NODE_MODULE_DIRS": "/Applications/ChatGPT.app/Contents/Resources/cua_node/lib/node_modules",
                    "NODE_REPL_NODE_PATH": "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node",
                    "BROWSER_USE_AVAILABLE_BACKENDS": "chrome,iab",
                    "CODEX_HOME": "/Users/operator/.codex",
                    "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER": "Control the in-app browser in conjunction with the Browser Plugin.",
                    "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME": "Control the Chrome browser in conjunction with the Chrome Plugin. Prefer this method of controlling Chrome over alternatives (such as Computer Use) unless the user explicitly mentions an alternative.",
                    "NODE_REPL_INSTRUCTIONS_USE_CASE_COMPUTER_USE": "Control desktop apps on macOS through Computer Use.",
                    "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod",
                    "CODEX_CLI_PATH": "/Applications/ChatGPT.app/Contents/Resources/codex"
                }),
            )
        } else {
            (
                "node_repl",
                json!([]),
                json!({
                    "SKY_CUA_NATIVE_PIPE": "1",
                    "SKY_CUA_NATIVE_PIPE_DIRECTORY": "C:\\Users\\operator\\AppData\\Local\\Temp\\codex-computer-use",
                    "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod"
                }),
            )
        };
        let mcp_servers = serde_json::to_vec(&json!([{
            "name": server_name,
            "transport": {
                "type": "stdio",
                "command": command,
                "args": args,
                "env": env
            }
        }]))
        .expect("serialize MCP fixture");

        let error = codex_isolation_plan_from_json(
            &plugins,
            &mcp_servers,
            platform,
            Path::new(codex_home),
            Path::new(trusted_root),
        )
        .expect_err("a lookalike native bridge must not receive Computer Use authority");

        assert_eq!(error.details["reason"], json!("native_bridge_untrusted"));
    }
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
    let mut app_server = Command::new(fixture.executable());
    app_server.arg("hang-with-escaped-descendant-exit");
    let started = Instant::now();

    let handshake_completed = perform_handshake(
        app_server,
        fixture
            .executable()
            .parent()
            .expect("the fixture executable must have a parent directory"),
        Instant::now() + Duration::from_millis(100),
    );

    assert!(
        started.elapsed() < Duration::from_secs(1),
        "an escaped stdout holder exceeded the hard protocol deadline"
    );
    assert!(
        !handshake_completed,
        "an incomplete escaped-child handshake must remain blocked"
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
    if matches!(mode.to_str(), Some("goal-local-image" | "inline-image")) {
        client_methods.push("thread/goal/set");
    }
    client_methods.push(RAW_SCHEMA_CANARY);

    let image_types: &[&str] = match mode.to_str() {
        Some("goal-local-image") => &["image", "localImage"],
        Some("inline-image") => &["image"],
        _ => &[],
    };

    write_client_request_schema(
        &schema_dir.join("ClientRequest.json"),
        &client_methods,
        (mode == "decoy-cancellation").then_some("turn/interrupt"),
        image_types,
        mode == "optional-decoy",
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

fn write_client_request_schema(
    path: &Path,
    methods: &[&str],
    nested_decoy: Option<&str>,
    image_types: &[&str],
    optional_decoys: bool,
) {
    let variants = methods
        .iter()
        .map(|method| {
            let mut variant = json!({
                "type": "object",
                "properties": {"method": {"type": "string", "enum": [method]}}
            });
            if *method == "turn/start" && !image_types.is_empty() {
                variant["properties"]["params"] = json!({"$ref": "#/definitions/TurnStartParams"});
            }
            variant
        })
        .collect::<Vec<_>>();
    let input_variants = image_types
        .iter()
        .map(|input_type| match *input_type {
            "image" => json!({"$ref": "#/definitions/ImageInput"}),
            "localImage" => json!({"$ref": "#/definitions/LocalImageInput"}),
            _ => unreachable!("the fixture only defines supported image variants"),
        })
        .collect::<Vec<_>>();
    let mut unused_methods = nested_decoy.into_iter().collect::<Vec<_>>();
    if optional_decoys {
        unused_methods.push("thread/goal/set");
    }
    let unused_payload = if optional_decoys {
        json!({
            "properties": {
                "method": {"enum": unused_methods},
                "attachments": {"items": {"oneOf": [
                    {"properties": {"type": {"const": "image"}}},
                    {"properties": {"type": {"const": "localImage"}}}
                ]}}
            }
        })
    } else {
        json!({"properties": {"method": {"enum": unused_methods}}})
    };
    serde_json::to_writer(
        File::create(path).expect("create fixture schema"),
        &json!({
            "oneOf": variants,
            "definitions": {
                "TurnStartParams": {
                    "properties": {"input": {"items": {"oneOf": input_variants}}}
                },
                "ImageInput": {"properties": {"type": {"const": "image"}}},
                "LocalImageInput": {"properties": {"type": {"const": "localImage"}}},
                "UnusedPayload": unused_payload
            }
        }),
    )
    .expect("write fixture schema");
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
