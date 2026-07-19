use assert_cmd::cargo::CommandCargoExt;
use satelle_host::{ApiBearerToken, test_support::TestStateDir};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[path = "support/test-file.rs"]
mod test_file;

const SESSION_ID: &str = "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11";
const DIRECT_READ_CONNECTIONS: usize = 4;

struct ImmediateCloseEndpoint {
    address: SocketAddr,
    shutdown: Option<mpsc::Sender<()>>,
    server: Option<thread::JoinHandle<usize>>,
}

impl ImmediateCloseEndpoint {
    fn start(max_connections: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind immediate-close endpoint");
        listener
            .set_nonblocking(true)
            .expect("make immediate-close endpoint nonblocking");
        let address = listener
            .local_addr()
            .expect("read immediate-close endpoint address");
        let (shutdown, shutdown_requested) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut accepted = 0;
            loop {
                if shutdown_requested.try_recv().is_ok() {
                    return accepted;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        accepted += 1;
                        drop(stream);
                        assert!(
                            accepted <= max_connections,
                            "immediate-close endpoint exceeded {max_connections} connections"
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("immediate-close endpoint failed: {error}"),
                }
            }
        });
        Self {
            address,
            shutdown: Some(shutdown),
            server: Some(server),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn shutdown(mut self) -> usize {
        let _ = self
            .shutdown
            .take()
            .expect("shutdown sender is present")
            .send(());
        self.server
            .take()
            .expect("server thread is present")
            .join()
            .expect("join immediate-close endpoint")
    }
}

impl Drop for ImmediateCloseEndpoint {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let joined = server.join();
            if !thread::panicking() {
                joined.expect("join immediate-close endpoint during cleanup");
            }
        }
    }
}

fn mcp_command() -> (Command, TestStateDir) {
    let home = TestStateDir::new().expect("production-safe temporary Satelle home");
    let command = mcp_command_for(home.path(), true);
    (command, home)
}

fn satelle_command(home: &Path, test_adapter: bool) -> Command {
    let mut command = Command::cargo_bin("satelle").expect("satelle test binary");
    let home = std::fs::canonicalize(home).expect("canonical temporary Satelle home");
    for name in [
        "SATELLE_HOME",
        "SATELLE_CONFIG_FILE",
        "SATELLE_STATE_DIR",
        "SATELLE_CACHE_DIR",
        "SATELLE_LOG_DIR",
        "SATELLE_HOST",
        "SATELLE_PROFILE",
        "SATELLE_ERROR_FORMAT",
        "SATELLE_TEST_SUPPORT_ADAPTER",
    ] {
        command.env_remove(name);
    }
    command
        .env("SATELLE_HOME", &home)
        // TestStateDir satisfies the production state-path security contract
        // on every supported platform, including Windows ACL requirements.
        .env("SATELLE_STATE_DIR", &home);
    if test_adapter {
        command.env("SATELLE_TEST_SUPPORT_ADAPTER", "fake");
    }
    command
}

fn mcp_command_for(home: &Path, test_adapter: bool) -> Command {
    let mut command = satelle_command(home, test_adapter);
    command
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn run_mcp(messages: &[Value]) -> Output {
    let (mut command, _home) = mcp_command();
    run_mcp_command(&mut command, messages)
}

fn run_mcp_command(command: &mut Command, messages: &[Value]) -> Output {
    let mut child = command.spawn().expect("spawn MCP server");
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        for message in messages {
            serde_json::to_writer(&mut stdin, message).expect("serialize MCP message");
            stdin.write_all(b"\n").expect("write MCP delimiter");
        }
    }
    child.wait_with_output().expect("wait for MCP server")
}

fn wait_with_open_stdin(mut child: Child, stdin: ChildStdin, timeout_message: &str) -> Output {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().expect("poll MCP server").is_some() {
            drop(stdin);
            return child.wait_with_output().expect("collect MCP server output");
        }
        if Instant::now() >= deadline {
            child.kill().expect("terminate hung MCP server");
            child.wait().expect("reap hung MCP server");
            panic!("{timeout_message}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn synchronize_pre_initialization_server(child: &mut Child, stdin: &mut ChildStdin) {
    // RMCP permits ping before initialization. Waiting for its response proves
    // that the child runtime, bounded framer, and protocol reader are all
    // running before an EOF-independent exit deadline starts. This keeps slow
    // Windows process startup out of the shutdown contract being measured.
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"ping\"}\n")
        .expect("write pre-initialization ping");
    stdin.flush().expect("flush pre-initialization ping");

    let stdout = child.stdout.as_mut().expect("piped stdout");
    let mut response = String::new();
    BufReader::new(stdout)
        .read_line(&mut response)
        .expect("read pre-initialization ping response");
    let response: Value = serde_json::from_str(&response).expect("parse ping response");
    assert_eq!(response["id"], 0);
    assert_eq!(response["result"], json!({}));
}

fn seed_session(home: &Path) -> String {
    let output = satelle_command(home, true)
        .args(["run", "--host", "local-demo", "Seed retained MCP state"])
        .output()
        .expect("run Satelle test-support session");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("run stdout is UTF-8")
        .lines()
        .find_map(|line| line.strip_prefix("Session: "))
        .expect("run output contains a Session ID")
        .to_string()
}

fn initialize(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "satelle-test", "version": "1"}
        }
    })
}

fn initialized() -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    })
}

fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

fn responses(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .expect("MCP stdout is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("MCP stdout line is JSON"))
        .collect()
}

fn response(responses: &[Value], id: u64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("missing MCP response {id}: {responses:#?}"))
}

fn advertised_output_schemas(response: &Value) -> BTreeMap<String, Value> {
    response["result"]["tools"]
        .as_array()
        .expect("tools/list tools array")
        .iter()
        .filter_map(|tool| {
            tool.get("outputSchema").map(|schema| {
                (
                    tool["name"].as_str().expect("tool name").to_string(),
                    schema.clone(),
                )
            })
        })
        .collect()
}

fn assert_schema_accepts(tool: &str, schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|error| panic!("{tool} advertised an invalid output schema: {error}"));
    let errors = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "{tool} output did not conform to its advertised schema: {errors:#?}\n{instance:#}"
    );
}

#[test]
fn initialize_and_tool_contracts_are_sdk_compatible() {
    let output = run_mcp(&[
        initialize(1),
        initialized(),
        json!({"jsonrpc": "2.0", "method": "notifications/example", "params": {}}),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 999, "reason": "nothing is running"}
        }),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        tool_call(3, "paths", json!({})),
        tool_call(4, "status", json!({"session_id": SESSION_ID})),
        json!({"jsonrpc": "2.0", "id": 5, "method": "satelle/unknown", "params": {}}),
        tool_call(6, "unknown", json!({})),
        tool_call(7, "paths", json!({"unexpected": true})),
        tool_call(8, "config_check", json!({})),
        tool_call(9, "config_explain", json!({})),
        tool_call(10, "logs", json!({"tail": 1})),
        tool_call(11, "doctor", json!({"scope": "config"})),
        tool_call(12, "host_status", json!({})),
        tool_call(13, "host_sessions", json!({})),
    ]);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = responses(&output);
    assert_eq!(
        responses.len(),
        13,
        "notifications must not receive responses"
    );

    let init = &response(&responses, 1)["result"];
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["serverInfo"]["name"], "satelle");
    assert_eq!(init["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(init["capabilities"]["tools"].is_object());
    for absent in ["prompts", "resources", "logging"] {
        assert!(init["capabilities"].get(absent).is_none());
    }

    let tools = response(&responses, 2)["result"]["tools"]
        .as_array()
        .expect("tools/list tools array");
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect::<Vec<_>>(),
        [
            "config_check",
            "config_explain",
            "paths",
            "status",
            "logs",
            "doctor",
            "host_status",
            "host_sessions"
        ]
    );
    for tool in tools {
        assert_eq!(
            tool["inputSchema"]["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["destructiveHint"], false);
        assert_eq!(tool["annotations"]["idempotentHint"], true);
        assert_eq!(tool["annotations"]["openWorldHint"], false);
    }
    assert!(
        tools[4].get("outputSchema").is_none(),
        "logs is an NDJSON stream result"
    );
    assert!(
        tools[6].get("outputSchema").is_none(),
        "host_status has no versioned payload"
    );
    for tool in [
        &tools[0], &tools[1], &tools[2], &tools[3], &tools[5], &tools[7],
    ] {
        let branches = tool["outputSchema"]["oneOf"]
            .as_array()
            .expect("versioned tool output oneOf");
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0]["additionalProperties"], false);
        assert_eq!(
            branches[1]["properties"]["schema_version"]["const"],
            "satelle.error.v1"
        );
    }

    let paths = &response(&responses, 3)["result"];
    assert_eq!(paths["isError"], false);
    assert_eq!(
        paths["structuredContent"]["schema_version"],
        "satelle.paths.v1"
    );
    assert_eq!(
        paths["content"][0]["text"],
        paths["structuredContent"].to_string()
    );

    let missing = &response(&responses, 4)["result"];
    assert_eq!(missing["isError"], true);
    assert_eq!(
        missing["structuredContent"]["schema_version"],
        "satelle.error.v1"
    );
    assert_eq!(missing["structuredContent"]["code"], "session-not-found");
    assert_eq!(missing["structuredContent"]["category"], "not_found");
    assert_eq!(missing["structuredContent"]["retryable"], false);
    assert_eq!(
        missing["content"][0]["text"],
        missing["structuredContent"].to_string()
    );

    assert_eq!(response(&responses, 5)["error"]["code"], -32601);
    assert_eq!(response(&responses, 6)["error"]["code"], -32602);
    assert_eq!(response(&responses, 7)["error"]["code"], -32602);

    assert_eq!(
        response(&responses, 8)["result"]["structuredContent"]["schema_version"],
        "satelle.config.check.v1"
    );
    assert_eq!(
        response(&responses, 9)["result"]["structuredContent"]["schema_version"],
        "satelle.config.explain.v1"
    );
    let logs = &response(&responses, 10)["result"];
    assert_eq!(logs["isError"], false, "logs result: {logs}");
    assert!(logs.get("structuredContent").is_none());
    assert!(logs["content"][0]["text"].is_string());

    let doctor = &response(&responses, 11)["result"];
    assert_eq!(
        doctor["structuredContent"]["schema_version"],
        "satelle.doctor.v1"
    );
    assert_eq!(
        doctor["isError"],
        !doctor["structuredContent"]["summary"]["ready"]
            .as_bool()
            .expect("doctor readiness boolean")
    );

    let host_status = &response(&responses, 12)["result"];
    assert_eq!(host_status["isError"], false);
    assert!(host_status.get("structuredContent").is_none());
    let host_status_text: Value = serde_json::from_str(
        host_status["content"][0]["text"]
            .as_str()
            .expect("status text"),
    )
    .expect("compact host status JSON");
    let mut host_status_keys = host_status_text
        .as_object()
        .expect("host status object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    host_status_keys.sort_unstable();
    assert_eq!(host_status_keys, ["mode", "running", "sessions"]);

    assert_eq!(
        response(&responses, 13)["result"]["structuredContent"]["schema_version"],
        "satelle.host.sessions.v1"
    );
    assert_eq!(
        response(&responses, 13)["result"]["structuredContent"]["bootstrapped"],
        false
    );
    assert_eq!(
        response(&responses, 13)["result"]["structuredContent"]["bootstrap_actions"],
        json!([])
    );
}

#[test]
fn versioned_tool_results_conform_to_their_advertised_json_schemas() {
    let home = TestStateDir::new().expect("production-safe temporary Satelle home");
    let session_id = seed_session(home.path());
    let mut success_command = mcp_command_for(home.path(), true);
    let success_output = run_mcp_command(
        &mut success_command,
        &[
            initialize(1),
            initialized(),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            tool_call(10, "config_check", json!({})),
            tool_call(11, "config_explain", json!({})),
            tool_call(12, "paths", json!({})),
            tool_call(13, "status", json!({"session_id": session_id.as_str()})),
            tool_call(14, "doctor", json!({"scope": "config"})),
            tool_call(15, "host_sessions", json!({})),
            tool_call(16, "logs", json!({"tail": 100})),
        ],
    );
    assert!(
        success_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&success_output.stderr)
    );
    let success_responses = responses(&success_output);
    let schemas = advertised_output_schemas(response(&success_responses, 2));
    assert_eq!(
        schemas.keys().map(String::as_str).collect::<Vec<_>>(),
        [
            "config_check",
            "config_explain",
            "doctor",
            "host_sessions",
            "paths",
            "status",
        ]
    );

    for (tool, id) in [
        ("config_check", 10),
        ("config_explain", 11),
        ("paths", 12),
        ("status", 13),
        ("doctor", 14),
        ("host_sessions", 15),
    ] {
        let result = &response(&success_responses, id)["result"];
        assert_eq!(result["isError"], false, "{tool} success result: {result}");
        assert_schema_accepts(
            tool,
            schemas.get(tool).expect("versioned tool output schema"),
            &result["structuredContent"],
        );
    }

    // The seeded session commits its canonical log records before this MCP
    // process opens the same state. The finite logs result must retain those
    // records as nonempty, complete NDJSON lines.
    let log_text = response(&success_responses, 16)["result"]["content"][0]["text"]
        .as_str()
        .expect("logs text result");
    assert!(!log_text.is_empty(), "seeded logs must be retained");
    assert!(
        log_text.ends_with('\n'),
        "retained logs must end with newline"
    );
    let log_records = log_text
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .expect("every retained log record must be one complete JSON line")
        })
        .collect::<Vec<_>>();
    for record in &log_records {
        assert_eq!(
            record["schema_version"], "satelle.logs.entry.v1",
            "every retained log record must use the advertised schema version"
        );
    }
    assert!(
        log_records.iter().any(|record| {
            record["subject"]["session_id"].as_str() == Some(session_id.as_str())
        }),
        "at least one retained log record must belong to the seeded Session"
    );

    let mut error_command = mcp_command_for(home.path(), true);
    let error_output = run_mcp_command(
        &mut error_command,
        &[
            initialize(20),
            initialized(),
            tool_call(21, "config_check", json!({"host": "missing-host"})),
            tool_call(22, "config_explain", json!({"host": "missing-host"})),
            tool_call(23, "status", json!({"session_id": SESSION_ID})),
            tool_call(24, "doctor", json!({"host": "missing-host"})),
            tool_call(25, "host_sessions", json!({"host": "missing-host"})),
        ],
    );
    assert!(error_output.status.success());
    let error_responses = responses(&error_output);
    for (tool, id) in [
        ("config_check", 21),
        ("config_explain", 22),
        ("status", 23),
        ("doctor", 24),
        ("host_sessions", 25),
    ] {
        let result = &response(&error_responses, id)["result"];
        assert_eq!(result["isError"], true, "{tool} operational error");
        assert_schema_accepts(
            tool,
            schemas.get(tool).expect("versioned tool output schema"),
            &result["structuredContent"],
        );
    }

    // Paths does not resolve a configured Host, so exercise its own real
    // operational failure with an invalid absolute-path override.
    let path_home = TestStateDir::new().expect("production-safe temporary invalid-path home");
    let mut path_error_command = mcp_command_for(path_home.path(), true);
    path_error_command.env("SATELLE_LOG_DIR", "relative-log-directory");
    let path_error_output = run_mcp_command(
        &mut path_error_command,
        &[
            initialize(30),
            initialized(),
            tool_call(31, "paths", json!({})),
        ],
    );
    assert!(path_error_output.status.success());
    let path_error_responses = responses(&path_error_output);
    let result = &response(&path_error_responses, 31)["result"];
    assert_eq!(result["isError"], true);
    assert_schema_accepts(
        "paths",
        schemas.get("paths").expect("paths output schema"),
        &result["structuredContent"],
    );
}

#[test]
fn blocked_doctor_is_a_structured_error_with_the_complete_report_as_text() {
    let home = TestStateDir::new().expect("production-safe temporary Satelle home");
    let mut command = mcp_command_for(home.path(), false);
    let output = run_mcp_command(
        &mut command,
        &[
            initialize(1),
            initialized(),
            tool_call(2, "doctor", json!({"scope": "transport"})),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = responses(&output);
    let result = &response(&responses, 2)["result"];
    let report = &result["structuredContent"];
    assert_eq!(result["isError"], true);
    assert_eq!(report["schema_version"], "satelle.doctor.v1");
    assert_eq!(report["status"], "blocked");
    assert_eq!(report["summary"]["ready"], false);
    assert_eq!(report["ready"], false);
    assert_eq!(
        result["content"][0]["text"],
        report.to_string(),
        "blocked doctor text must retain the complete structured report"
    );
}

#[test]
fn logs_since_grammar_accepts_zero_and_rejects_noncanonical_tokens() {
    let mut messages = vec![initialize(1), initialized()];
    for (index, since) in ["0ms", "0s", "0m"].into_iter().enumerate() {
        messages.push(tool_call(
            10 + index as u64,
            "logs",
            json!({"since": since}),
        ));
    }
    for (index, since) in [
        "+1s",
        "1.0s",
        " 1s",
        "1 s",
        "1s ",
        "1",
        "1h",
        "18446744073709551616ms",
    ]
    .into_iter()
    .enumerate()
    {
        messages.push(tool_call(
            20 + index as u64,
            "logs",
            json!({"since": since}),
        ));
    }
    messages.push(tool_call(
        30,
        "logs",
        json!({"after": "slc1_0000000000000000", "tail": 1}),
    ));

    let output = run_mcp(&messages);
    assert!(output.status.success());
    let responses = responses(&output);
    for id in 10..=12 {
        let result = &response(&responses, id)["result"];
        assert_eq!(result["isError"], false, "logs result {id}: {result}");
        assert!(result.get("structuredContent").is_none());
        assert!(result["content"][0]["text"].is_string());
    }
    for id in 20..=27 {
        assert_eq!(response(&responses, id)["error"]["code"], -32602);
    }
    assert_eq!(response(&responses, 30)["error"]["code"], -32602);
}

#[test]
fn direct_host_read_tools_return_typed_errors_without_runtime_drop_panics() {
    let home = TestStateDir::new().expect("production-safe temporary Satelle home");
    let config_file = home.path().join("user-config.toml");
    let token_file = home.path().join("satelle.token");
    let token = ApiBearerToken::generate().expect("generate direct Host API token");
    test_file::write_user_controlled(&token_file, token.expose().as_str())
        .expect("write owner-only direct Host API token");

    let endpoint = ImmediateCloseEndpoint::start(DIRECT_READ_CONNECTIONS);

    let token_path = toml::Value::String(token_file.to_string_lossy().into_owned()).to_string();
    test_file::write_user_controlled(
        &config_file,
        format!(
            r#"
default_host = "remote"

[hosts.remote]
transport = "direct"
adapter = "codex"
address = "https://{}"
expected_host_id = "host-direct-mcp-test"
api_token = {{ kind = "file", path = {token_path} }}
"#,
            endpoint.address(),
        ),
    )
    .expect("write direct Host config");

    let mut command = mcp_command_for(home.path(), false);
    command.env("SATELLE_CONFIG_FILE", &config_file);
    let output = run_mcp_command(
        &mut command,
        &[
            initialize(1),
            initialized(),
            tool_call(2, "status", json!({"session_id": SESSION_ID})),
            tool_call(3, "logs", json!({"tail": 1})),
            tool_call(4, "doctor", json!({"scope": "transport"})),
            tool_call(5, "host_status", json!({})),
            tool_call(6, "host_sessions", json!({})),
        ],
    );
    let accepted_connections = endpoint.shutdown();

    assert!(
        output.status.success(),
        "direct Host MCP reads must not panic while dropping their transport: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        accepted_connections, DIRECT_READ_CONNECTIONS,
        "each network-backed direct Host read must reach the owned endpoint exactly once"
    );
    let responses = responses(&output);
    for (id, expected_code) in [
        (2, "host-unreachable"),
        (3, "host-unreachable"),
        (4, "not-implemented"),
        (5, "host-unreachable"),
        (6, "host-unreachable"),
    ] {
        let result = &response(&responses, id)["result"];
        assert_eq!(result["isError"], true, "tool result {id}: {result}");
        assert_eq!(
            result["structuredContent"]["schema_version"],
            "satelle.error.v1"
        );
        assert_eq!(result["structuredContent"]["code"], expected_code);
    }
}

#[test]
fn eof_before_initialize_is_a_clean_protocol_failure() {
    let output = run_mcp(&[]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("initialization did not complete"));
}

#[test]
fn initialization_failure_exits_while_client_stdin_remains_open() {
    let (mut command, _home) = mcp_command();
    let mut child = command.spawn().expect("spawn MCP server");
    let mut stdin = child.stdin.take().expect("piped stdin");
    synchronize_pre_initialization_server(&mut child, &mut stdin);
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n")
        .expect("write a request before initialization");
    stdin.flush().expect("flush invalid initialization request");

    let output = wait_with_open_stdin(
        child,
        stdin,
        "MCP initialization failure waited indefinitely for client EOF",
    );

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("initialization did not complete"));
}

#[test]
fn oversized_input_is_rejected_before_rmcp() {
    let (mut command, _home) = mcp_command();
    let mut child = command.spawn().expect("spawn MCP server");
    let mut stdin = child.stdin.take().expect("piped stdin");
    synchronize_pre_initialization_server(&mut child, &mut stdin);
    let _ = stdin.write_all(&vec![b' '; 1_048_577]);
    let output = wait_with_open_stdin(
        child,
        stdin,
        "oversized MCP input waited indefinitely for client EOF",
    );

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("1048576-byte limit"));
}

#[test]
fn fragmented_maximum_size_message_is_processed_once() {
    let (mut command, _home) = mcp_command();
    let mut child = command.spawn().expect("spawn MCP server");
    let mut message = serde_json::to_vec(&initialize(1)).expect("serialize initialize");
    message.resize(1_048_576, b' ');
    message.push(b'\n');
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        for fragment in message.chunks(7777) {
            stdin.write_all(fragment).expect("write fragment");
        }
    }
    let output = child.wait_with_output().expect("wait for MCP server");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = responses(&output);
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 1);
}
