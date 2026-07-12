use command_group::CommandGroup;
use serde_json::{Map, Value, json};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "codex-session-tests.rs"]
mod tests;

const INBOUND_LINE_LIMIT: usize = 2 * 1024 * 1024;
const INBOUND_QUEUE_CAPACITY: usize = 8;
const READER_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexApprovalPolicy {
    Untrusted,
    OnRequest,
    Never,
}

impl CodexApprovalPolicy {
    const fn as_protocol_value(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::OnRequest => "on-request",
            Self::Never => "never",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexSandboxPolicy {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl CodexSandboxPolicy {
    const fn as_thread_value(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }

    fn as_turn_value(self, working_directory: &Path) -> Result<Value, CodexSessionError> {
        match self {
            Self::ReadOnly => Ok(json!({"type": "readOnly", "networkAccess": false})),
            Self::WorkspaceWrite => {
                let writable_root = working_directory.to_str().ok_or(CodexSessionError::Write)?;
                Ok(json!({
                    "type": "workspaceWrite",
                    "writableRoots": [writable_root],
                    "networkAccess": false,
                    "excludeTmpdirEnvVar": true,
                    "excludeSlashTmp": true
                }))
            }
            Self::DangerFullAccess => Ok(json!({"type": "dangerFullAccess"})),
        }
    }
}

pub(crate) struct CodexSessionRequest<'a> {
    pub(crate) working_directory: &'a Path,
    pub(crate) prompt: &'a str,
    pub(crate) existing_thread_ref: Option<&'a str>,
    pub(crate) model: &'a str,
    pub(crate) model_provider: &'a str,
    pub(crate) approval_policy: CodexApprovalPolicy,
    pub(crate) sandbox_policy: CodexSandboxPolicy,
    pub(crate) deadline: Instant,
    pub(crate) persist_thread_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
    pub(crate) persist_turn_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexSessionTerminal {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CodexSessionError {
    #[error("the private Codex app-server process could not be started")]
    Spawn,
    #[error("the private Codex app-server protocol could not be written")]
    Write,
    #[error("the private Codex app-server sent a malformed message")]
    MalformedMessage,
    #[error("the private Codex app-server sent an oversized message")]
    OversizedMessage,
    #[error("the private Codex app-server sent an unexpected response")]
    UnexpectedResponse,
    #[error("the private Codex app-server sent a duplicate response")]
    DuplicateResponse,
    #[error("the private Codex app-server reported a protocol error")]
    ResponseError,
    #[error("the private Codex app-server reported conflicting session identity")]
    ConflictingIdentity,
    #[error("the private Codex app-server ended before the turn completed")]
    PrematureExit,
    #[error("the private Codex app-server exchange timed out")]
    Timeout,
    #[error("the private Codex app-server identity could not be persisted")]
    Persistence,
    #[error("the private Codex app-server process group could not be contained")]
    Containment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CodexSessionFailure {
    error: CodexSessionError,
    turn_dispatch_attempted: bool,
}

impl CodexSessionFailure {
    const fn before_turn_dispatch(error: CodexSessionError) -> Self {
        Self {
            error,
            turn_dispatch_attempted: false,
        }
    }

    pub(crate) const fn after_exchange(
        error: CodexSessionError,
        turn_dispatch_attempted: bool,
    ) -> Self {
        Self {
            error,
            turn_dispatch_attempted,
        }
    }

    pub(crate) const fn error(self) -> CodexSessionError {
        self.error
    }

    pub(crate) const fn turn_dispatch_attempted(self) -> bool {
        self.turn_dispatch_attempted
    }
}

pub(crate) fn run_codex_session(
    mut command: Command,
    request: CodexSessionRequest<'_>,
) -> Result<CodexSessionTerminal, CodexSessionFailure> {
    if Instant::now() >= request.deadline {
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Timeout,
        ));
    }

    let mut child = command
        .current_dir(request.working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
        .map_err(|_| CodexSessionFailure::before_turn_dispatch(CodexSessionError::Spawn))?;
    let stdin = child.inner().stdin.take();
    let stdout = child.inner().stdout.take();
    let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
        let _ = crate::codex_capabilities::terminate_group(&mut child);
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Spawn,
        ));
    };

    #[cfg(unix)]
    if crate::codex_capabilities::set_nonblocking(&stdout).is_err() {
        let _ = crate::codex_capabilities::terminate_group(&mut child);
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Spawn,
        ));
    }

    let deadline = request.deadline;
    let (sender, receiver) = mpsc::sync_channel(INBOUND_QUEUE_CAPACITY);
    let reader = match thread::Builder::new()
        .name("satelle-codex-reader".to_string())
        .spawn(move || read_messages(stdout, deadline, sender))
    {
        Ok(reader) => reader,
        Err(_) => {
            let _ = crate::codex_capabilities::terminate_group(&mut child);
            return Err(CodexSessionFailure::before_turn_dispatch(
                CodexSessionError::Spawn,
            ));
        }
    };
    let (write_sender, write_receiver) = mpsc::channel();
    let writer = ProtocolWriter {
        sender: write_sender,
        deadline,
    };
    let writer_thread = match thread::Builder::new()
        .name("satelle-codex-writer".to_string())
        .spawn(move || write_messages(stdin, write_receiver))
    {
        Ok(writer_thread) => writer_thread,
        Err(_) => {
            drop(writer);
            drop(receiver);
            let _ = crate::codex_capabilities::terminate_group(&mut child);
            let _ = reader.join();
            return Err(CodexSessionFailure::before_turn_dispatch(
                CodexSessionError::Spawn,
            ));
        }
    };
    let mut exchange = SessionExchange::new(request);
    let exchange_result = exchange.run(&writer, &receiver);
    let turn_dispatch_attempted = exchange.turn_dispatch_attempted;

    // The reader may be backpressured on the bounded queue. Drop the receiver
    // before joining so every cleanup path can release that blocked send.
    drop(receiver);
    drop(writer);
    let group_stopped = crate::codex_capabilities::terminate_group(&mut child);
    let reader_stopped = reader.join().is_ok();
    let writer_stopped = writer_thread.join().is_ok();
    if !group_stopped || !reader_stopped || !writer_stopped {
        return Err(CodexSessionFailure::after_exchange(
            CodexSessionError::Containment,
            turn_dispatch_attempted,
        ));
    }
    match exchange_result {
        Ok(terminal) => Ok(terminal),
        Err(error) => Err(CodexSessionFailure::after_exchange(
            error,
            turn_dispatch_attempted,
        )),
    }
}

struct SessionExchange<'a> {
    request: CodexSessionRequest<'a>,
    responses: [bool; 4],
    thread_ref: Option<String>,
    thread_observed: bool,
    turn_ref: Option<String>,
    turn_dispatch_attempted: bool,
    terminal: Option<CodexSessionTerminal>,
}

impl<'a> SessionExchange<'a> {
    fn new(request: CodexSessionRequest<'a>) -> Self {
        Self {
            thread_ref: request.existing_thread_ref.map(str::to_owned),
            request,
            responses: [false; 4],
            thread_observed: false,
            turn_ref: None,
            turn_dispatch_attempted: false,
            terminal: None,
        }
    }

    fn run(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<CodexSessionTerminal, CodexSessionError> {
        self.write_initialize(writer)?;
        while !self.responses[1] {
            self.consume_next(writer, receiver)?;
        }
        writer.write(&json!({"method": "initialized"}))?;
        self.write_thread_request(writer)?;

        loop {
            if !self.turn_dispatch_attempted && self.thread_observed {
                self.write_turn_request(writer)?;
            }
            if self.responses[2]
                && self.responses[3]
                && let Some(terminal) = self.terminal
            {
                return Ok(terminal);
            }
            self.consume_next(writer, receiver)?;
        }
    }

    fn consume_next(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<(), CodexSessionError> {
        let remaining = self
            .request
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexSessionError::Timeout)?;
        match receiver.recv_timeout(remaining) {
            Ok(ReadEvent::Line(line)) => {
                if let Some(response) = self.consume_line(&line)? {
                    writer.write(&response)?;
                }
                Ok(())
            }
            Ok(ReadEvent::Oversized) => Err(CodexSessionError::OversizedMessage),
            Ok(ReadEvent::Eof | ReadEvent::Io) => Err(CodexSessionError::PrematureExit),
            Ok(ReadEvent::Timeout) => Err(CodexSessionError::Timeout),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CodexSessionError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(CodexSessionError::PrematureExit),
        }
    }

    fn consume_line(&mut self, line: &[u8]) -> Result<Option<Value>, CodexSessionError> {
        let message: Value =
            serde_json::from_slice(line).map_err(|_| CodexSessionError::MalformedMessage)?;
        let object = message
            .as_object()
            .ok_or(CodexSessionError::MalformedMessage)?;
        if object.contains_key("id") && object.contains_key("method") {
            self.consume_server_request(object).map(Some)
        } else if object.contains_key("id") {
            self.consume_response(object).map(|()| None)
        } else {
            self.consume_notification(object).map(|()| None)
        }
    }

    fn consume_server_request(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<Value, CodexSessionError> {
        let id = object
            .get("id")
            .filter(|id| {
                id.as_str().is_some_and(|value| !value.is_empty()) || id.as_i64().is_some()
            })
            .ok_or(CodexSessionError::MalformedMessage)?
            .clone();
        let method = required_string(object, "method")?;
        if matches!(
            method,
            "item/commandExecution/requestApproval"
                | "item/fileChange/requestApproval"
                | "item/tool/requestUserInput"
                | "item/permissions/requestApproval"
                | "item/tool/call"
        ) {
            self.validate_server_request_correlation(required_object(object, "params")?)?;
        }
        let result = match method {
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                json!({"decision": "decline"})
            }
            "item/permissions/requestApproval" => json!({"permissions": {}}),
            "mcpServer/elicitation/request" => json!({"action": "decline"}),
            "item/tool/call" => json!({"contentItems": [], "success": false}),
            "applyPatchApproval" | "execCommandApproval" => json!({"decision": "denied"}),
            _ => {
                return Ok(json!({
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": "server request is not supported by the Satelle adapter"
                    }
                }));
            }
        };
        Ok(json!({"id": id, "result": result}))
    }

    fn validate_server_request_correlation(
        &self,
        params: &Map<String, Value>,
    ) -> Result<(), CodexSessionError> {
        self.correlate_thread(required_string(params, "threadId")?)?;
        let observed_turn = required_string(params, "turnId")?;
        self.turn_ref
            .as_deref()
            .is_some_and(|expected| expected == observed_turn)
            .then_some(())
            .ok_or(CodexSessionError::ConflictingIdentity)
    }

    fn consume_response(&mut self, object: &Map<String, Value>) -> Result<(), CodexSessionError> {
        let id = object
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| usize::try_from(id).ok())
            .filter(|id| (1..=3).contains(id))
            .ok_or(CodexSessionError::UnexpectedResponse)?;
        if self.responses[id] {
            return Err(CodexSessionError::DuplicateResponse);
        }
        if object.contains_key("error") {
            return Err(CodexSessionError::ResponseError);
        }
        let result = object
            .get("result")
            .and_then(Value::as_object)
            .ok_or(CodexSessionError::MalformedMessage)?;
        match id {
            1 => validate_initialize(result)?,
            2 if self.responses[1] => {
                let thread_ref = nested_id(result, "thread")?;
                self.observe_thread(thread_ref)?;
            }
            3 if self.turn_dispatch_attempted => {
                let turn = result
                    .get("turn")
                    .and_then(Value::as_object)
                    .ok_or(CodexSessionError::MalformedMessage)?;
                if turn.get("status").and_then(Value::as_str) != Some("inProgress") {
                    return Err(CodexSessionError::MalformedMessage);
                }
                let turn_ref = required_string(turn, "id")?;
                self.observe_turn(turn_ref)?;
            }
            _ => return Err(CodexSessionError::UnexpectedResponse),
        }
        self.responses[id] = true;
        Ok(())
    }

    fn consume_notification(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<(), CodexSessionError> {
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or(CodexSessionError::MalformedMessage)?;
        match method {
            "thread/started" if self.responses[1] => {
                let params = required_object(object, "params")?;
                self.observe_thread(nested_id(params, "thread")?)
            }
            "turn/started" if self.turn_dispatch_attempted => {
                let params = required_object(object, "params")?;
                self.correlate_thread(required_string(params, "threadId")?)?;
                let turn = required_object(params, "turn")?;
                if turn.get("status").and_then(Value::as_str) != Some("inProgress") {
                    return Err(CodexSessionError::MalformedMessage);
                }
                self.observe_turn(required_string(turn, "id")?)
            }
            "turn/completed" if self.turn_dispatch_attempted => {
                let params = required_object(object, "params")?;
                self.correlate_thread(required_string(params, "threadId")?)?;
                let turn = required_object(params, "turn")?;
                let turn_ref = required_string(turn, "id")?;
                self.observe_turn(turn_ref)?;
                let terminal = match required_string(turn, "status")? {
                    "completed" => CodexSessionTerminal::Completed,
                    "interrupted" => CodexSessionTerminal::Interrupted,
                    "failed" => CodexSessionTerminal::Failed,
                    _ => return Err(CodexSessionError::MalformedMessage),
                };
                if self.terminal.is_some_and(|observed| observed != terminal) {
                    return Err(CodexSessionError::ConflictingIdentity);
                }
                self.terminal = Some(terminal);
                Ok(())
            }
            "item/started" | "item/completed" if self.turn_dispatch_attempted => {
                self.validate_item_correlation(object)
            }
            "thread/started" | "turn/started" | "turn/completed" | "item/started"
            | "item/completed" => Err(CodexSessionError::MalformedMessage),
            _ => Ok(()),
        }
    }

    fn observe_thread(&mut self, observed: &str) -> Result<(), CodexSessionError> {
        if let Some(expected) = self.thread_ref.as_deref() {
            (expected == observed)
                .then_some(())
                .ok_or(CodexSessionError::ConflictingIdentity)?;
            self.thread_observed = true;
            return Ok(());
        }
        (self.request.persist_thread_ref)(observed).map_err(|_| CodexSessionError::Persistence)?;
        self.thread_ref = Some(observed.to_owned());
        self.thread_observed = true;
        Ok(())
    }

    fn observe_turn(&mut self, observed: &str) -> Result<(), CodexSessionError> {
        if let Some(expected) = self.turn_ref.as_deref() {
            return (expected == observed)
                .then_some(())
                .ok_or(CodexSessionError::ConflictingIdentity);
        }
        (self.request.persist_turn_ref)(observed).map_err(|_| CodexSessionError::Persistence)?;
        self.turn_ref = Some(observed.to_owned());
        Ok(())
    }

    fn correlate_thread(&self, observed: &str) -> Result<(), CodexSessionError> {
        self.thread_ref
            .as_deref()
            .is_some_and(|expected| expected == observed)
            .then_some(())
            .ok_or(CodexSessionError::ConflictingIdentity)
    }

    fn validate_item_correlation(
        &self,
        object: &Map<String, Value>,
    ) -> Result<(), CodexSessionError> {
        let params = required_object(object, "params")?;
        self.correlate_thread(required_string(params, "threadId")?)?;
        let observed_turn = required_string(params, "turnId")?;
        self.turn_ref
            .as_deref()
            .is_some_and(|expected| expected == observed_turn)
            .then_some(())
            .ok_or(CodexSessionError::ConflictingIdentity)
    }

    fn write_initialize(&self, writer: &ProtocolWriter) -> Result<(), CodexSessionError> {
        writer.write(&json!({
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "satelle-host",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {"experimentalApi": false}
            }
        }))
    }

    fn write_thread_request(&self, writer: &ProtocolWriter) -> Result<(), CodexSessionError> {
        let mut params = json!({
            "model": self.request.model,
            "modelProvider": self.request.model_provider,
            "approvalPolicy": self.request.approval_policy.as_protocol_value(),
            "sandbox": self.request.sandbox_policy.as_thread_value()
        });
        let method = if let Some(thread_ref) = self.request.existing_thread_ref {
            params["threadId"] = Value::String(thread_ref.to_owned());
            "thread/resume"
        } else {
            "thread/start"
        };
        writer.write(&json!({"id": 2, "method": method, "params": params}))
    }

    fn write_turn_request(&mut self, writer: &ProtocolWriter) -> Result<(), CodexSessionError> {
        let thread_ref = self.thread_ref.as_deref().ok_or(CodexSessionError::Write)?;
        let request = json!({
            "id": 3,
            "method": "turn/start",
            "params": {
                "input": [{"type": "text", "text": self.request.prompt}],
                "threadId": thread_ref,
                "model": self.request.model,
                "approvalPolicy": self.request.approval_policy.as_protocol_value(),
                "sandboxPolicy": self.request.sandbox_policy.as_turn_value(
                    self.request.working_directory
                )?
            }
        });
        writer.write_after_queue(&request, || {
            // Once queued, a timeout or pipe error cannot prove that the
            // writer sent none of the turn request bytes.
            self.turn_dispatch_attempted = true;
        })
    }
}

fn validate_initialize(result: &Map<String, Value>) -> Result<(), CodexSessionError> {
    ["userAgent", "codexHome", "platformFamily", "platformOs"]
        .into_iter()
        .all(|field| result.get(field).and_then(Value::as_str).is_some())
        .then_some(())
        .ok_or(CodexSessionError::MalformedMessage)
}

fn nested_id<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, CodexSessionError> {
    required_string(required_object(object, field)?, "id")
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, CodexSessionError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(CodexSessionError::MalformedMessage)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, CodexSessionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(CodexSessionError::MalformedMessage)
}

struct ProtocolWriter {
    sender: mpsc::Sender<WriteCommand>,
    deadline: Instant,
}

struct WriteCommand {
    bytes: Vec<u8>,
    completed: mpsc::Sender<Result<(), ()>>,
}

impl ProtocolWriter {
    fn write(&self, value: &Value) -> Result<(), CodexSessionError> {
        self.write_after_queue(value, || {})
    }

    fn write_after_queue(
        &self,
        value: &Value,
        after_queue: impl FnOnce(),
    ) -> Result<(), CodexSessionError> {
        if Instant::now() >= self.deadline {
            return Err(CodexSessionError::Timeout);
        }
        let mut bytes = serde_json::to_vec(value).map_err(|_| CodexSessionError::Write)?;
        bytes.push(b'\n');
        if Instant::now() >= self.deadline {
            return Err(CodexSessionError::Timeout);
        }
        let (completed, completion) = mpsc::channel();
        self.sender
            .send(WriteCommand { bytes, completed })
            .map_err(|_| CodexSessionError::Write)?;
        after_queue();
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexSessionError::Timeout)?;
        match completion.recv_timeout(remaining) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(CodexSessionError::Write)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CodexSessionError::Timeout),
        }
    }
}

fn write_messages(mut stdin: std::process::ChildStdin, receiver: mpsc::Receiver<WriteCommand>) {
    while let Ok(command) = receiver.recv() {
        let result = stdin
            .write_all(&command.bytes)
            .and_then(|()| stdin.flush())
            .map_err(|_| ());
        let failed = result.is_err();
        let _ = command.completed.send(result);
        if failed {
            return;
        }
    }
}

enum ReadEvent {
    Line(Vec<u8>),
    Oversized,
    Eof,
    Io,
    Timeout,
}

fn read_messages(
    stdout: std::process::ChildStdout,
    deadline: Instant,
    sender: mpsc::SyncSender<ReadEvent>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = Vec::new();
        let mut bounded = (&mut reader).take((INBOUND_LINE_LIMIT + 1) as u64);
        loop {
            match bounded.read_until(b'\n', &mut line) {
                Ok(0) if line.is_empty() => {
                    let _ = sender.send(ReadEvent::Eof);
                    return;
                }
                // App-server messages are JSON Lines. A final fragment is not
                // a message even when its bytes happen to form valid JSON.
                Ok(0) => {
                    let _ = sender.send(ReadEvent::Io);
                    return;
                }
                Ok(_) if line.last() == Some(&b'\n') => break,
                Ok(_) if line.len() > INBOUND_LINE_LIMIT => {
                    let _ = sender.send(ReadEvent::Oversized);
                    return;
                }
                Ok(_) => {}
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(READER_POLL_INTERVAL);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let _ = sender.send(ReadEvent::Timeout);
                    return;
                }
                Err(_) => {
                    let _ = sender.send(ReadEvent::Io);
                    return;
                }
            }
        }
        if line.len() > INBOUND_LINE_LIMIT {
            let _ = sender.send(ReadEvent::Oversized);
            return;
        }
        if sender.send(ReadEvent::Line(line)).is_err() {
            return;
        }
    }
}
