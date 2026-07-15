use super::*;
use serde_json::{Value, json};
use std::fs::{OpenOptions, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[path = "codex-session-tests/approvals.rs"]
mod approvals;

const FIXTURE_SOURCE: &str = r##"
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    if std::env::args().nth(1).as_deref() == Some("descendant") {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(std::env::args().nth(2).unwrap(), "escaped").unwrap();
        return;
    }
    let scenario = std::env::var("SATELLE_FIXTURE_SCENARIO").unwrap();
    let log = PathBuf::from(std::env::var_os("SATELLE_FIXTURE_LOG").unwrap());
    std::fs::write(
        std::env::var_os("SATELLE_FIXTURE_CWD_LOG").unwrap(),
        std::env::current_dir().unwrap().to_string_lossy().as_bytes(),
    ).unwrap();
    let thread_marker = PathBuf::from(std::env::var_os("SATELLE_THREAD_MARKER").unwrap());
    let turn_marker = PathBuf::from(std::env::var_os("SATELLE_TURN_MARKER").unwrap());
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();

    receive(&mut input, &log);
    match scenario.as_str() {
        "wrong-id" => send(&mut output, r#"{"id":9,"result":{}}"#),
        "out-of-order" => send(&mut output, r#"{"id":2,"result":{"thread":{"id":"thread-early"}}}"#),
        "malformed" => send(&mut output, "not-json"),
        "non-object" => send(&mut output, "[]"),
        "unterminated" => {
            output.write_all(br#"{"id":1,"result":{}}"#).unwrap();
            output.flush().unwrap();
            // A valid JSON fragment without the JSON Lines delimiter is not a
            // protocol message and cannot advance the exchange.
            hang();
        }
        "oversized" => {
            output.write_all(&vec![b'x'; 2 * 1024 * 1024 + 1]).unwrap();
            output.write_all(b"\n").unwrap();
            output.flush().unwrap();
        }
        "eof" => return,
        "timeout" => hang(),
        _ => {}
    }
    if matches!(scenario.as_str(), "wrong-id" | "out-of-order" | "malformed" | "non-object" | "oversized" | "unterminated") {
        hang();
    }

    send(&mut output, r#"{"id":1,"result":{"userAgent":"fixture","codexHome":"/fixture","platformFamily":"fixture","platformOs":"fixture"}}"#);
    if scenario == "descendant-timeout" {
        Command::new(std::env::current_exe().unwrap())
            .arg("descendant")
            .arg(std::env::var_os("SATELLE_DESCENDANT_MARKER").unwrap())
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::null())
            .spawn().unwrap();
        hang();
    }
    if scenario == "flood-timeout" {
        let payload = "x".repeat(64 * 1024);
        for _ in 0..10_000 {
            send(&mut output, &format!(r#"{{"method":"private/flood","params":{{"raw":"{payload}"}}}}"#));
        }
        hang();
    }
    receive(&mut input, &log);
    if scenario.starts_with("read-") {
        let request = receive(&mut input, &log);
        assert!(request.contains(r#""method":"thread/read""#));
        assert!(request.contains(r#""threadId":"thread-1""#));
        assert!(request.contains(r#""includeTurns":true"#));
        let status = scenario.strip_prefix("read-").unwrap();
        send(&mut output, &format!(r#"{{"id":2,"result":{{"thread":{{"id":"thread-1","turns":[{{"id":"turn-1","status":"{status}"}}]}}}}}}"#));
        hang();
    }
    let thread_request = receive(&mut input, &log);
    let thread_id = if thread_request.contains(r#""threadId":"thread-existing""#) {
        "thread-existing"
    } else {
        "thread-1"
    };
    let thread_response = format!(r#"{{"id":2,"result":{{"thread":{{"id":"{thread_id}"}}}}}}"#);

    if scenario == "notification-first" {
        send(&mut output, &format!(r#"{{"method":"thread/started","params":{{"thread":{{"id":"{thread_id}"}}}}}}"#));
        wait_for(&thread_marker);
        receive(&mut input, &log);
        send(&mut output, &format!(r#"{{"method":"turn/started","params":{{"threadId":"{thread_id}","turn":{{"id":"turn-1","status":"inProgress"}}}}}}"#));
        wait_for(&turn_marker);
        send(&mut output, &thread_response);
    } else if scenario == "conflict" {
        send(&mut output, &thread_response);
        wait_for(&thread_marker);
        receive(&mut input, &log);
        send(&mut output, r#"{"method":"thread/started","params":{"thread":{"id":"thread-conflict"}}}"#);
        hang();
    } else {
        send(&mut output, &thread_response);
        if thread_id == "thread-1" { wait_for(&thread_marker); }
        if scenario == "blocked-write" { hang(); }
        receive(&mut input, &log);
    }

    match scenario.as_str() {
        "duplicate" => { send(&mut output, &thread_response); hang(); }
        "response-error" => {
            send(&mut output, r#"{"id":3,"error":{"code":-1,"message":"PRIVATE_RAW_CANARY"}}"#);
            hang();
        }
        _ => {}
    }

    send(&mut output, r#"{"id":3,"result":{"turn":{"id":"turn-1","status":"inProgress"}}}"#);
    wait_for(&turn_marker);
    if scenario == "controlled-interrupt" {
        let interrupt = receive(&mut input, &log);
        assert!(interrupt.contains(r#""id":4"#));
        assert!(interrupt.contains(r#""method":"turn/interrupt""#));
        assert!(interrupt.contains(r#""threadId":"thread-1""#));
        assert!(interrupt.contains(r#""turnId":"turn-1""#));
        send(&mut output, r#"{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"interrupted"}}}"#);
        send(&mut output, r#"{"id":4,"result":{}}"#);
        return;
    }
    if scenario == "server-requests" {
        send(&mut output, &format!(r#"{{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{{"threadId":"{thread_id}","turnId":"turn-1","itemId":"item-1","startedAtMs":1,"additionalPermissions":{{"fileSystem":{{"entries":[]}}}},"availableDecisions":["accept","decline"]}}}}"#));
        receive(&mut input, &log);
        send(&mut output, &format!(r#"{{"id":"file-1","method":"item/fileChange/requestApproval","params":{{"threadId":"{thread_id}","turnId":"turn-1","itemId":"item-2","startedAtMs":2}}}}"#));
        receive(&mut input, &log);
        send(&mut output, &format!(r#"{{"id":"permissions-1","method":"item/permissions/requestApproval","params":{{"threadId":"{thread_id}","turnId":"turn-1","itemId":"item-3","startedAtMs":3,"cwd":"/fixture","permissions":{{"fileSystem":{{"entries":[]}},"network":{{"enabled":true}}}}}}}}"#));
        receive(&mut input, &log);
        send(&mut output, &format!(r#"{{"id":"legacy-patch","method":"applyPatchApproval","params":{{"callId":"patch-1","conversationId":"{thread_id}","fileChanges":{{}}}}}}"#));
        receive(&mut input, &log);
        send(&mut output, &format!(r#"{{"id":"legacy-command","method":"execCommandApproval","params":{{"callId":"command-1","command":[],"conversationId":"{thread_id}","cwd":"/fixture","parsedCmd":[]}}}}"#));
        receive(&mut input, &log);
        send(&mut output, &format!(r#"{{"id":"input-1","method":"item/tool/requestUserInput","params":{{"threadId":"{thread_id}","turnId":"turn-1","itemId":"item-4","questions":[]}}}}"#));
        receive(&mut input, &log);
        send(&mut output, r#"{"id":"native-ui","method":"private/osPrivacy/requestApproval"}"#);
        receive(&mut input, &log);
        send(&mut output, r#"{"id":99,"method":"account/chatgptAuthTokens/refresh"}"#);
        receive(&mut input, &log);
    }
    if scenario == "unsupported-permission" {
        send(&mut output, &format!(r#"{{"id":"permissions-unsupported","method":"item/permissions/requestApproval","params":{{"threadId":"{thread_id}","turnId":"turn-1","itemId":"item-1","startedAtMs":1,"cwd":"/fixture","permissions":{{"osPrivacy":{{"screenRecording":true}}}}}}}}"#));
        receive(&mut input, &log);
    }
    if scenario == "malformed-permission" {
        send(&mut output, &format!(r#"{{"id":"permissions-malformed","method":"item/permissions/requestApproval","params":{{"threadId":"{thread_id}","turnId":"turn-1","itemId":"item-1","startedAtMs":1,"cwd":"/fixture","permissions":{{"network":"enabled"}}}}}}"#));
        hang();
    }
    if scenario == "server-request-conflict" {
        send(&mut output, r#"{"id":"approval-conflict","method":"item/fileChange/requestApproval","params":{"threadId":"thread-conflict","turnId":"turn-1","itemId":"item-1","startedAtMs":1}}"#);
        hang();
    }
    if scenario == "legacy-server-request-conflict" {
        send(&mut output, r#"{"id":"legacy-conflict","method":"execCommandApproval","params":{"callId":"command-1","command":[],"conversationId":"thread-conflict","cwd":"/fixture","parsedCmd":[]}}"#);
        hang();
    }
    if scenario == "unknown-canary" {
        send(&mut output, r#"{"method":"private/future","params":{"raw":"PRIVATE_RAW_CANARY"}}"#);
        send(&mut output, &format!(r#"{{"method":"item/started","params":{{"threadId":"{thread_id}","turnId":"turn-1","item":{{"raw":"PRIVATE_RAW_CANARY"}}}}}}"#));
        send(&mut output, &format!(r#"{{"method":"item/completed","params":{{"threadId":"{thread_id}","turnId":"turn-1","item":{{"raw":"PRIVATE_RAW_CANARY"}}}}}}"#));
    }
    if scenario == "descendant" {
        Command::new(std::env::current_exe().unwrap())
            .arg("descendant")
            .arg(std::env::var_os("SATELLE_DESCENDANT_MARKER").unwrap())
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::null())
            .spawn().unwrap();
    }
    let status = match scenario.as_str() {
        "interrupted" => "interrupted",
        "failed" => "failed",
        _ => "completed",
    };
    let terminal_turn = if scenario == "turn-conflict" { "turn-conflict" } else { "turn-1" };
    send(&mut output, &format!(r#"{{"method":"turn/completed","params":{{"threadId":"{thread_id}","turn":{{"id":"{terminal_turn}","status":"{status}"}}}}}}"#));
    hang();
}

fn receive(input: &mut impl BufRead, log_path: &Path) -> String {
    let mut line = String::new();
    assert_ne!(input.read_line(&mut line).unwrap(), 0);
    OpenOptions::new().create(true).append(true).open(log_path)
        .unwrap().write_all(line.as_bytes()).unwrap();
    line
}

fn send(output: &mut impl Write, line: &str) {
    writeln!(output, "{line}").unwrap();
    output.flush().unwrap();
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !path.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn hang() -> ! {
    std::thread::sleep(Duration::from_secs(5));
    std::process::exit(0)
}
"##;

struct CompiledFixture {
    _directory: tempfile::TempDir,
    executable: PathBuf,
}

fn compile_fixture() -> CompiledFixture {
    let directory = tempfile::tempdir().expect("fixture directory");
    let source = directory.path().join("codex-session-fixture.rs");
    std::fs::write(&source, FIXTURE_SOURCE).expect("write fixture source");
    let executable = directory.path().join(if cfg!(windows) {
        "codex-session-fixture.exe"
    } else {
        "codex-session-fixture"
    });
    let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .arg(&source)
        .arg("--edition=2024")
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile fixture");
    assert!(
        output.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    CompiledFixture {
        _directory: directory,
        executable,
    }
}

struct ScenarioResult {
    result: Result<CodexSessionTerminal, CodexSessionError>,
    session_elapsed: Duration,
    turn_dispatch_attempted: bool,
    requests: Vec<Value>,
    persisted_threads: Vec<String>,
    persisted_turns: Vec<String>,
    child_working_directory: PathBuf,
    _fixture: CompiledFixture,
    directory: tempfile::TempDir,
}

#[derive(Clone, Copy)]
enum PersistFailure {
    None,
    Thread,
    Turn,
}

#[derive(Clone, Copy)]
struct ScenarioExecution {
    mode: TurnExecutionMode,
    approval_policy: CodexApprovalPolicy,
    sandbox_policy: CodexSandboxPolicy,
}

impl ScenarioExecution {
    const STANDARD: Self = Self {
        mode: TurnExecutionMode::Standard,
        approval_policy: CodexApprovalPolicy::OnRequest,
        sandbox_policy: CodexSandboxPolicy::WorkspaceWrite,
    };

    const YOLO: Self = Self {
        mode: TurnExecutionMode::Yolo,
        approval_policy: CodexApprovalPolicy::Never,
        sandbox_policy: CodexSandboxPolicy::DangerFullAccess,
    };

    const fn new(
        mode: TurnExecutionMode,
        approval_policy: CodexApprovalPolicy,
        sandbox_policy: CodexSandboxPolicy,
    ) -> Self {
        Self {
            mode,
            approval_policy,
            sandbox_policy,
        }
    }
}

fn run_scenario(
    scenario: &str,
    existing_thread_ref: Option<&str>,
    timeout: Duration,
) -> ScenarioResult {
    run_scenario_with_options(
        scenario,
        existing_thread_ref,
        timeout,
        "perform the harmless action PRIVATE_PROMPT_CANARY",
        PersistFailure::None,
        ScenarioExecution::STANDARD,
    )
}

fn run_scenario_with_prompt(
    scenario: &str,
    existing_thread_ref: Option<&str>,
    timeout: Duration,
    prompt: &str,
) -> ScenarioResult {
    run_scenario_with_options(
        scenario,
        existing_thread_ref,
        timeout,
        prompt,
        PersistFailure::None,
        ScenarioExecution::STANDARD,
    )
}

fn run_yolo_scenario(scenario: &str, timeout: Duration) -> ScenarioResult {
    run_scenario_with_options(
        scenario,
        None,
        timeout,
        "perform the harmless action PRIVATE_PROMPT_CANARY",
        PersistFailure::None,
        ScenarioExecution::YOLO,
    )
}

fn run_scenario_with_options(
    scenario: &str,
    existing_thread_ref: Option<&str>,
    timeout: Duration,
    prompt: &str,
    persist_failure: PersistFailure,
    execution: ScenarioExecution,
) -> ScenarioResult {
    let fixture = compile_fixture();
    let directory = tempfile::tempdir().expect("scenario directory");
    let log_path = directory.path().join("requests.jsonl");
    let cwd_log_path = directory.path().join("child-cwd");
    let thread_marker = directory.path().join("thread-persisted");
    let turn_marker = directory.path().join("turn-persisted");
    let descendant_marker = directory.path().join("descendant-escaped");
    let mut command = Command::new(&fixture.executable);
    command
        .env("SATELLE_FIXTURE_SCENARIO", scenario)
        .env("SATELLE_FIXTURE_LOG", &log_path)
        .env("SATELLE_FIXTURE_CWD_LOG", &cwd_log_path)
        .env("SATELLE_THREAD_MARKER", &thread_marker)
        .env("SATELLE_TURN_MARKER", &turn_marker)
        .env("SATELLE_DESCENDANT_MARKER", &descendant_marker);

    let mut persisted_threads = Vec::new();
    let mut persisted_turns = Vec::new();
    let mut persist_thread = |value: &str| {
        if matches!(persist_failure, PersistFailure::Thread) {
            return Err(());
        }
        persisted_threads.push(value.to_owned());
        touch(&thread_marker);
        Ok(())
    };
    let mut persist_turn = |value: &str| {
        if matches!(persist_failure, PersistFailure::Turn) {
            return Err(());
        }
        persisted_turns.push(value.to_owned());
        touch(&turn_marker);
        Ok(())
    };
    let session_started = Instant::now();
    let session_result = run_codex_session(
        command,
        CodexSessionRequest {
            working_directory: directory.path(),
            prompt,
            existing_thread_ref,
            model: Some("gpt-fixture"),
            model_provider: Some("fixture-provider"),
            execution_mode: execution.mode,
            approval_policy: execution.approval_policy,
            sandbox_policy: execution.sandbox_policy,
            deadline: Instant::now() + timeout,
            persist_thread_ref: &mut persist_thread,
            persist_turn_ref: &mut persist_turn,
            control: None,
        },
    );
    let session_elapsed = session_started.elapsed();
    let turn_dispatch_attempted = session_result
        .as_ref()
        .err()
        .is_some_and(|failure| failure.turn_dispatch_attempted());
    let result = session_result.map_err(CodexSessionFailure::error);
    let requests = read_to_string(&log_path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("request JSON"))
        .collect();
    ScenarioResult {
        result,
        session_elapsed,
        turn_dispatch_attempted,
        requests,
        persisted_threads,
        persisted_turns,
        child_working_directory: PathBuf::from(
            std::fs::read_to_string(cwd_log_path).expect("child working-directory record"),
        ),
        _fixture: fixture,
        directory,
    }
}
fn touch(path: &Path) {
    writeln!(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("persistence marker"),
        "persisted"
    )
    .expect("write persistence marker");
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for fixture marker"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn first_thread_uses_exact_policy_order_and_persists_refs() {
    let run = run_scenario("completed", None, Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.persisted_threads, ["thread-1"]);
    assert_eq!(run.persisted_turns, ["turn-1"]);
    assert_eq!(
        std::fs::canonicalize(&run.child_working_directory).unwrap(),
        std::fs::canonicalize(run.directory.path()).unwrap()
    );
    assert_ne!(
        run.child_working_directory,
        std::env::current_dir().unwrap()
    );
    assert_eq!(run.requests.len(), 4);
    assert_eq!(run.requests[0]["id"], 1);
    assert_eq!(run.requests[0]["method"], "initialize");
    assert_eq!(run.requests[1], json!({"method": "initialized"}));
    assert_eq!(
        run.requests[2],
        json!({"id":2,"method":"thread/start","params":{
        "model":"gpt-fixture","modelProvider":"fixture-provider",
        "approvalPolicy":"on-request","sandbox":"workspace-write"}})
    );
    assert_eq!(
        run.requests[3],
        json!({"id":3,"method":"turn/start","params":{
        "input":[{"type":"text","text":"perform the harmless action PRIVATE_PROMPT_CANARY"}],
        "threadId":"thread-1","model":"gpt-fixture","approvalPolicy":"on-request",
        "sandboxPolicy":{"type":"workspaceWrite","writableRoots":[run.directory.path()],"networkAccess":false,
            "excludeTmpdirEnvVar":true,"excludeSlashTmp":true}}})
    );
}

#[test]
fn resume_uses_persisted_thread_without_persisting_it_again() {
    let run = run_scenario("completed", Some("thread-existing"), Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert!(run.persisted_threads.is_empty());
    assert_eq!(run.persisted_turns, ["turn-1"]);
    assert_eq!(run.requests[2]["method"], "thread/resume");
    assert_eq!(run.requests[2]["params"]["threadId"], "thread-existing");
    assert_eq!(run.requests[3]["params"]["threadId"], "thread-existing");
}

#[test]
fn notifications_may_precede_correlated_responses() {
    let run = run_scenario("notification-first", None, Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.persisted_threads, ["thread-1"]);
    assert_eq!(run.persisted_turns, ["turn-1"]);
}

#[test]
fn terminal_status_is_closed() {
    for (scenario, expected) in [
        ("completed", CodexSessionTerminal::Completed),
        ("interrupted", CodexSessionTerminal::Interrupted),
        ("failed", CodexSessionTerminal::Failed),
    ] {
        assert_eq!(
            run_scenario(scenario, None, Duration::from_secs(3)).result,
            Ok(expected)
        );
    }
}

#[test]
fn live_interrupt_waits_for_the_durable_stop_acknowledgement() {
    let fixture = compile_fixture();
    let directory = tempfile::tempdir().expect("control scenario directory");
    let log_path = directory.path().join("requests.jsonl");
    let cwd_log_path = directory.path().join("child-cwd");
    let thread_marker = directory.path().join("thread-persisted");
    let turn_marker = directory.path().join("turn-persisted");
    let descendant_marker = directory.path().join("descendant-escaped");
    let mut command = Command::new(&fixture.executable);
    command
        .env("SATELLE_FIXTURE_SCENARIO", "controlled-interrupt")
        .env("SATELLE_FIXTURE_LOG", &log_path)
        .env("SATELLE_FIXTURE_CWD_LOG", &cwd_log_path)
        .env("SATELLE_THREAD_MARKER", &thread_marker)
        .env("SATELLE_TURN_MARKER", &turn_marker)
        .env("SATELLE_DESCENDANT_MARKER", &descendant_marker);
    let deadline = Instant::now() + Duration::from_secs(3);
    let control = CodexSessionControl::new(deadline);
    let session_control = control.clone();
    let session_directory = directory.path().to_path_buf();
    let session_thread_marker = thread_marker.clone();
    let session_turn_marker = turn_marker.clone();
    let session = std::thread::spawn(move || {
        let mut persist_thread = |_: &str| {
            touch(&session_thread_marker);
            Ok(())
        };
        let mut persist_turn = |_: &str| {
            touch(&session_turn_marker);
            Ok(())
        };
        run_codex_session(
            command,
            CodexSessionRequest {
                working_directory: &session_directory,
                prompt: "PRIVATE_CONTROLLED_STOP_PROMPT",
                existing_thread_ref: None,
                model: Some("gpt-fixture"),
                model_provider: Some("fixture-provider"),
                execution_mode: TurnExecutionMode::Standard,
                approval_policy: CodexApprovalPolicy::OnRequest,
                sandbox_policy: CodexSandboxPolicy::WorkspaceWrite,
                deadline,
                persist_thread_ref: &mut persist_thread,
                persist_turn_ref: &mut persist_turn,
                control: Some(session_control),
            },
        )
    });
    wait_for(&turn_marker);

    assert_eq!(
        control.interrupt(),
        StopObservation::UpstreamInactiveConfirmed
    );
    assert!(
        !session.is_finished(),
        "execution must wait until the stopped state is durable"
    );
    control.stop_committed();

    assert_eq!(
        session.join().expect("join controlled execution"),
        Ok(CodexSessionTerminal::StoppedByControl)
    );
}

#[test]
fn restart_observation_reads_only_the_matching_persisted_turn() {
    for (status, expected) in [
        ("inProgress", CodexTurnStatus::InProgress),
        ("completed", CodexTurnStatus::Completed),
        ("interrupted", CodexTurnStatus::Interrupted),
        ("failed", CodexTurnStatus::Failed),
    ] {
        let fixture = compile_fixture();
        let directory = tempfile::tempdir().expect("read scenario directory");
        let log_path = directory.path().join("requests.jsonl");
        let cwd_log_path = directory.path().join("child-cwd");
        let mut command = Command::new(&fixture.executable);
        command
            .env("SATELLE_FIXTURE_SCENARIO", format!("read-{status}"))
            .env("SATELLE_FIXTURE_LOG", &log_path)
            .env("SATELLE_FIXTURE_CWD_LOG", &cwd_log_path)
            .env(
                "SATELLE_THREAD_MARKER",
                directory.path().join("unused-thread"),
            )
            .env("SATELLE_TURN_MARKER", directory.path().join("unused-turn"))
            .env(
                "SATELLE_DESCENDANT_MARKER",
                directory.path().join("unused-descendant"),
            );

        let observed = read_codex_turn(
            command,
            CodexTurnReadRequest {
                working_directory: directory.path(),
                thread_ref: "thread-1",
                turn_ref: "turn-1",
                deadline: Instant::now() + Duration::from_secs(3),
            },
        );
        assert!(
            observed.is_ok(),
            "read matching durable Turn failed with {observed:?}; requests: {}",
            read_to_string(&log_path).unwrap_or_default()
        );
        let observed = observed.unwrap();

        assert_eq!(observed, expected);
    }
}

#[test]
fn malformed_and_adversarial_messages_fail_closed() {
    for (scenario, expected) in [
        ("conflict", CodexSessionError::ConflictingIdentity),
        ("wrong-id", CodexSessionError::UnexpectedResponse),
        ("out-of-order", CodexSessionError::UnexpectedResponse),
        ("duplicate", CodexSessionError::DuplicateResponse),
        ("oversized", CodexSessionError::OversizedMessage),
        ("malformed", CodexSessionError::MalformedMessage),
        ("non-object", CodexSessionError::MalformedMessage),
        ("turn-conflict", CodexSessionError::ConflictingIdentity),
        (
            "server-request-conflict",
            CodexSessionError::ConflictingIdentity,
        ),
        ("unterminated", CodexSessionError::Timeout),
        ("eof", CodexSessionError::PrematureExit),
        ("response-error", CodexSessionError::ResponseError),
        ("timeout", CodexSessionError::Timeout),
    ] {
        // This table checks protocol classification, not process-start or pipe
        // throughput. Keep short deadlines only for scenarios that must prove
        // timeout behavior; loaded Windows and macOS runners need more time to
        // reach the later protocol states and transfer the oversized fixture.
        let timeout = if matches!(scenario, "timeout" | "unterminated") {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(3)
        };
        let run = run_scenario(scenario, None, timeout);
        let error = run.result.expect_err("adversarial fixture must fail");
        assert_eq!(error, expected, "scenario {scenario}");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("PRIVATE_RAW_CANARY"));
        assert!(!rendered.contains("PRIVATE_PROMPT_CANARY"));
        assert!(!rendered.contains("thread-"));
        assert!(!rendered.contains("turn-"));
    }
}

#[test]
fn persistence_failure_stops_before_dependent_protocol_work() {
    let thread_failure = run_scenario_with_options(
        "completed",
        None,
        Duration::from_secs(3),
        "PRIVATE_THREAD_PERSISTENCE_FAILURE_PROMPT",
        PersistFailure::Thread,
        ScenarioExecution::STANDARD,
    );
    assert_eq!(thread_failure.result, Err(CodexSessionError::Persistence));
    assert!(!thread_failure.turn_dispatch_attempted);
    assert_eq!(thread_failure.requests.len(), 3);
    assert!(thread_failure.persisted_threads.is_empty());
    assert!(thread_failure.persisted_turns.is_empty());

    let turn_failure = run_scenario_with_options(
        "completed",
        None,
        Duration::from_secs(3),
        "PRIVATE_TURN_PERSISTENCE_FAILURE_PROMPT",
        PersistFailure::Turn,
        ScenarioExecution::STANDARD,
    );
    assert_eq!(turn_failure.result, Err(CodexSessionError::Persistence));
    assert!(turn_failure.turn_dispatch_attempted);
    assert_eq!(turn_failure.requests.len(), 4);
    assert_eq!(turn_failure.persisted_threads, ["thread-1"]);
    assert!(turn_failure.persisted_turns.is_empty());
}

#[test]
fn a_non_reading_child_cannot_block_a_large_prompt_past_the_deadline() {
    // Large enough to exceed a normal pipe buffer, but small enough that JSON
    // serialization itself does not consume the test deadline on slow CI.
    let prompt = "x".repeat(128 * 1024);
    let run = run_scenario_with_prompt("blocked-write", None, Duration::from_secs(2), &prompt);

    assert_eq!(run.result, Err(CodexSessionError::Timeout));
    assert!(run.turn_dispatch_attempted);
    assert!(
        run.session_elapsed < Duration::from_secs(5),
        "a blocked app-server stdin exceeded the whole-session deadline"
    );
}

#[test]
fn notification_flood_is_backpressured_and_cleanup_remains_bounded() {
    let run = run_scenario("flood-timeout", None, Duration::from_secs(1));

    assert_eq!(run.result, Err(CodexSessionError::Timeout));
    assert!(
        run.session_elapsed < Duration::from_secs(5),
        "a backpressured notification flood deadlocked session cleanup"
    );
}

#[test]
fn unknown_and_item_payloads_are_discarded_without_leaking_canaries() {
    let run = run_scenario("unknown-canary", None, Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.requests.len(), 4);
    assert_eq!(run.persisted_threads, ["thread-1"]);
    assert_eq!(run.persisted_turns, ["turn-1"]);

    let retained = format!(
        "{:?} {}",
        run.result,
        serde_json::to_string(&(&run.requests, &run.persisted_threads, &run.persisted_turns,))
            .expect("retained protocol state serializes")
    );
    assert!(!retained.contains("PRIVATE_RAW_CANARY"));
}

#[test]
fn terminating_a_successful_session_contains_descendants() {
    let run = run_scenario("descendant", None, Duration::from_secs(3));
    let escaped_marker = run.directory.path().join("descendant-escaped");
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline && !escaped_marker.exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!escaped_marker.exists(), "a descendant escaped containment");
}

#[test]
fn timeout_cleanup_contains_descendants() {
    let run = run_scenario("descendant-timeout", None, Duration::from_millis(250));
    let escaped_marker = run.directory.path().join("descendant-escaped");

    assert_eq!(run.result, Err(CodexSessionError::Timeout));
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !escaped_marker.exists(),
        "an error-path descendant escaped process containment"
    );
}

#[test]
fn every_closed_policy_has_an_exact_protocol_mapping() {
    assert_eq!(
        CodexApprovalPolicy::Untrusted.as_protocol_value(),
        "untrusted"
    );
    assert_eq!(
        CodexApprovalPolicy::OnRequest.as_protocol_value(),
        "on-request"
    );
    assert_eq!(CodexApprovalPolicy::Never.as_protocol_value(), "never");
    assert_eq!(CodexSandboxPolicy::ReadOnly.as_thread_value(), "read-only");
    assert_eq!(
        CodexSandboxPolicy::WorkspaceWrite.as_thread_value(),
        "workspace-write"
    );
    assert_eq!(
        CodexSandboxPolicy::DangerFullAccess.as_thread_value(),
        "danger-full-access"
    );
    assert_eq!(
        CodexSandboxPolicy::ReadOnly
            .as_turn_value(Path::new("/fixture"))
            .unwrap(),
        json!({"type": "readOnly", "networkAccess": false})
    );
    assert_eq!(
        CodexSandboxPolicy::DangerFullAccess
            .as_turn_value(Path::new("/fixture"))
            .unwrap(),
        json!({"type": "dangerFullAccess"})
    );
}

#[test]
fn an_expired_writer_does_not_mark_turn_dispatch() {
    let writer = ProtocolWriter::expired_for_test();
    let mut dispatched = false;

    assert_eq!(
        writer.write_after_queue(&json!({"method": "turn/start"}), || dispatched = true),
        Err(CodexSessionError::Timeout)
    );
    assert!(!dispatched);
}
