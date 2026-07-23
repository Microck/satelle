use crate::provider_auth::ResolvedProviderSecret;
use base64::Engine as _;
use satelle_core::session::StopObservation;
use satelle_core::session::TurnExecutionMode;
use serde_json::{Map, Value, json};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

#[path = "codex-approval.rs"]
mod codex_approval;
#[path = "codex-process.rs"]
mod codex_process;
#[path = "codex-turn-read.rs"]
mod codex_turn_read;

use codex_process::{CodexExchange, ProtocolWriter, ReadEvent, run_exchange};

#[cfg(test)]
#[path = "codex-session-tests.rs"]
pub(crate) mod tests;

const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER_CHILD_ID: &str = "satelle_runtime";
const PROVIDER_CHILD_SECRET_ENV: &str = "SATELLE_CODEX_API_KEY";

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
    pub(crate) model: Option<&'a str>,
    pub(crate) model_provider: Option<&'a str>,
    pub(crate) provider_endpoint: Option<&'a str>,
    pub(crate) provider_secret: Option<ResolvedProviderSecret>,
    pub(crate) execution_mode: TurnExecutionMode,
    pub(crate) approval_policy: CodexApprovalPolicy,
    pub(crate) sandbox_policy: CodexSandboxPolicy,
    pub(crate) deadline: Instant,
    pub(crate) persist_thread_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
    pub(crate) persist_turn_ref: &'a mut dyn FnMut(&str) -> Result<(), ()>,
    pub(crate) control: Option<CodexSessionControl>,
    pub(crate) goal_set_supported: bool,
    pub(crate) image_input_mode: crate::codex_capabilities::CodexImageInputMode,
    pub(crate) attachments: &'a [crate::attachment::StagedImage],
}

impl CodexSessionRequest<'_> {
    const fn auto_approves_callbacks(&self) -> bool {
        matches!(self.execution_mode, TurnExecutionMode::Yolo)
            && matches!(self.approval_policy, CodexApprovalPolicy::Never)
            && matches!(self.sandbox_policy, CodexSandboxPolicy::DangerFullAccess)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexSessionTerminal {
    Completed,
    Interrupted,
    Failed(CodexFailedTurnKind),
    StoppedByControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexFailedTurnKind {
    Other,
}

pub(crate) struct TimedCodexSessionRun {
    pub(crate) result: Result<CodexSessionTerminal, CodexSessionFailure>,
    pub(crate) cancellation: Option<StopObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexTurnStatus {
    InProgress,
    Completed,
    Interrupted,
    Failed,
}

pub(crate) struct CodexTurnReadRequest<'a> {
    pub(crate) working_directory: &'a Path,
    pub(crate) thread_ref: &'a str,
    pub(crate) turn_ref: &'a str,
    pub(crate) deadline: Instant,
}

#[derive(Clone)]
pub(crate) struct CodexSessionControl {
    inner: Arc<CodexSessionControlInner>,
}

struct CodexSessionControlInner {
    sender: mpsc::Sender<ControlCommand>,
    receiver: Mutex<Option<mpsc::Receiver<ControlCommand>>>,
    deadline: Instant,
}

enum ControlCommand {
    Interrupt {
        reply: mpsc::Sender<StopObservation>,
    },
    StopCommitted,
}

impl CodexSessionControl {
    pub(crate) fn new(deadline: Instant) -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            inner: Arc::new(CodexSessionControlInner {
                sender,
                receiver: Mutex::new(Some(receiver)),
                deadline,
            }),
        }
    }

    pub(crate) fn interrupt(&self) -> StopObservation {
        let (reply, response) = mpsc::channel();
        if self
            .inner
            .sender
            .send(ControlCommand::Interrupt { reply })
            .is_err()
        {
            return StopObservation::OutcomeUnknown;
        }
        let Some(remaining) = self.inner.deadline.checked_duration_since(Instant::now()) else {
            return StopObservation::OutcomeUnknown;
        };
        response
            .recv_timeout(remaining.min(CONTROL_RESPONSE_TIMEOUT))
            .unwrap_or(StopObservation::OutcomeUnknown)
    }

    pub(crate) fn stop_committed(&self) {
        let _ = self.inner.sender.send(ControlCommand::StopCommitted);
    }

    fn claim_receiver(&self) -> Result<mpsc::Receiver<ControlCommand>, CodexSessionError> {
        self.inner
            .receiver
            .lock()
            .map_err(|_| CodexSessionError::Control)?
            .take()
            .ok_or(CodexSessionError::Control)
    }
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
    #[error("the private Codex app-server control channel failed")]
    Control,
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

    #[cfg(test)]
    pub(crate) const fn before_turn_dispatch_for_test(error: CodexSessionError) -> Self {
        Self::before_turn_dispatch(error)
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
    if let Some(endpoint) = request.provider_endpoint {
        let Some(model) = request.model else {
            return Err(CodexSessionFailure::before_turn_dispatch(
                CodexSessionError::Write,
            ));
        };
        let toml_model = serde_json::to_string(model)
            .map_err(|_| CodexSessionFailure::before_turn_dispatch(CodexSessionError::Write))?;
        let toml_endpoint = serde_json::to_string(endpoint)
            .map_err(|_| CodexSessionFailure::before_turn_dispatch(CodexSessionError::Write))?;
        for override_value in [
            format!("model={toml_model}"),
            format!("model_provider=\"{PROVIDER_CHILD_ID}\""),
            format!("model_providers.{PROVIDER_CHILD_ID}.name=\"Satelle\""),
            format!("model_providers.{PROVIDER_CHILD_ID}.base_url={toml_endpoint}"),
            format!("model_providers.{PROVIDER_CHILD_ID}.env_key=\"{PROVIDER_CHILD_SECRET_ENV}\""),
            format!("model_providers.{PROVIDER_CHILD_ID}.wire_api=\"responses\""),
            format!("model_providers.{PROVIDER_CHILD_ID}.requires_openai_auth=false"),
            format!("shell_environment_policy.exclude=[\"{PROVIDER_CHILD_SECRET_ENV}\"]"),
        ] {
            command.arg("-c").arg(override_value);
        }
        if let Some(secret) = request.provider_secret.as_ref() {
            secret.expose_to_provider(|value| {
                command.env(PROVIDER_CHILD_SECRET_ENV, value);
            });
        }
    } else if request.provider_secret.is_some() {
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Write,
        ));
    }
    let working_directory = request.working_directory;
    let deadline = request.deadline;
    let control = match request.control.as_ref() {
        Some(control) => match control.claim_receiver() {
            Ok(receiver) => Some(receiver),
            Err(error) => return Err(CodexSessionFailure::before_turn_dispatch(error)),
        },
        None => None,
    };
    let mut exchange = SessionExchange::new(request, control);
    run_exchange(command, working_directory, deadline, &mut exchange)
}

/// Runs an exchange until its user-visible timeout, then uses its registered
/// correlated control channel to request upstream cancellation. The exchange
/// deadline includes a short grace period so the app server can confirm that
/// the Turn is no longer active.
pub(crate) fn run_codex_session_with_timeout_cancellation(
    command: Command,
    mut request: CodexSessionRequest<'_>,
    cancellation_grace: Duration,
    admission_cancellation: Option<crate::AdmissionCancellation>,
) -> TimedCodexSessionRun {
    let timeout_deadline = request.deadline;
    let cancellation_deadline = timeout_deadline
        .checked_add(cancellation_grace)
        .unwrap_or(timeout_deadline);
    let control = request
        .control
        .clone()
        .unwrap_or_else(|| CodexSessionControl::new(cancellation_deadline));
    request.deadline = cancellation_deadline;
    request.control = Some(control.clone());

    let (finished_sender, finished_receiver) = mpsc::channel();
    let cancellation_control = control.clone();
    let watchdog = std::thread::spawn(move || {
        loop {
            if admission_cancellation
                .as_ref()
                .is_some_and(crate::AdmissionCancellation::is_requested)
            {
                let observation = cancellation_control.interrupt();
                if matches!(
                    observation,
                    StopObservation::CancellationConfirmed
                        | StopObservation::UpstreamInactiveConfirmed
                ) {
                    cancellation_control.stop_committed();
                }
                return Some(observation);
            }
            let now = Instant::now();
            if now >= timeout_deadline {
                let observation = cancellation_control.interrupt();
                if matches!(
                    observation,
                    StopObservation::CancellationConfirmed
                        | StopObservation::UpstreamInactiveConfirmed
                ) {
                    cancellation_control.stop_committed();
                }
                return Some(observation);
            }
            let wait = timeout_deadline
                .saturating_duration_since(now)
                .min(CONTROL_POLL_INTERVAL);
            match finished_receiver.recv_timeout(wait) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    });

    let result = run_codex_session(command, request);
    let _ = finished_sender.send(());
    let cancellation = watchdog
        .join()
        .unwrap_or(Some(StopObservation::OutcomeUnknown));
    TimedCodexSessionRun {
        result,
        cancellation,
    }
}

pub(crate) fn read_codex_turn(
    command: Command,
    request: CodexTurnReadRequest<'_>,
) -> Result<CodexTurnStatus, CodexSessionFailure> {
    if Instant::now() >= request.deadline {
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Timeout,
        ));
    }
    let mut exchange = codex_turn_read::TurnReadExchange::new(
        request.thread_ref,
        request.turn_ref,
        request.deadline,
    );
    run_exchange(
        command,
        request.working_directory,
        request.deadline,
        &mut exchange,
    )
}

struct SessionExchange<'a> {
    request: CodexSessionRequest<'a>,
    responses: [bool; 6],
    thread_ref: Option<String>,
    thread_observed: bool,
    turn_ref: Option<String>,
    turn_dispatch_attempted: bool,
    goal_dispatch_attempted: bool,
    terminal: Option<CodexSessionTerminal>,
    control: Option<mpsc::Receiver<ControlCommand>>,
    pending_interrupt: Option<mpsc::Sender<StopObservation>>,
    interrupt_sent: bool,
    controlled_stop: bool,
    stop_committed: bool,
}

impl<'a> SessionExchange<'a> {
    fn new(
        request: CodexSessionRequest<'a>,
        control: Option<mpsc::Receiver<ControlCommand>>,
    ) -> Self {
        Self {
            thread_ref: request.existing_thread_ref.map(str::to_owned),
            request,
            responses: [false; 6],
            thread_observed: false,
            turn_ref: None,
            turn_dispatch_attempted: false,
            goal_dispatch_attempted: false,
            terminal: None,
            control,
            pending_interrupt: None,
            interrupt_sent: false,
            controlled_stop: false,
            stop_committed: false,
        }
    }

    fn run_inner(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<CodexSessionTerminal, CodexSessionError> {
        self.write_initialize(writer)?;
        while !self.responses[1] {
            self.consume_next(writer, receiver)?;
            if self.controlled_stop {
                return self.wait_for_stop_commit(writer);
            }
        }
        self.poll_control(writer)?;
        if self.controlled_stop {
            return self.wait_for_stop_commit(writer);
        }
        writer.write(&json!({"method": "initialized"}))?;
        self.write_thread_request(writer)?;

        loop {
            self.poll_control(writer)?;
            if self.controlled_stop {
                return self.wait_for_stop_commit(writer);
            }
            if !self.controlled_stop
                && self.thread_observed
                && self.goal_required()
                && !self.goal_dispatch_attempted
            {
                self.write_goal_request(writer)?;
            }
            if !self.controlled_stop
                && !self.turn_dispatch_attempted
                && self.thread_observed
                && (!self.goal_required() || self.responses[3])
            {
                self.write_turn_request(writer)?;
            }
            if !self.controlled_stop
                && self.responses[2]
                && self.responses[self.turn_request_id()]
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
        self.poll_control(writer)?;
        if self.controlled_stop {
            return Ok(());
        }
        let remaining = self
            .request
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexSessionError::Timeout)?;
        let wait = if self.control.is_some() {
            remaining.min(CONTROL_POLL_INTERVAL)
        } else {
            remaining
        };
        match receiver.recv_timeout(wait) {
            Ok(ReadEvent::Line(line)) => {
                if let Some(response) = self.consume_line(&line)? {
                    writer.write(&response)?;
                }
                self.poll_control(writer)?;
                Ok(())
            }
            Ok(ReadEvent::Oversized) => Err(CodexSessionError::OversizedMessage),
            Ok(ReadEvent::Eof | ReadEvent::Io) => Err(CodexSessionError::PrematureExit),
            Ok(ReadEvent::Timeout) => Err(CodexSessionError::Timeout),
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() < self.request.deadline => {
                self.poll_control(writer)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CodexSessionError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(CodexSessionError::PrematureExit),
        }
    }

    fn poll_control(&mut self, writer: &ProtocolWriter) -> Result<(), CodexSessionError> {
        loop {
            let command = match self.control.as_ref().map(mpsc::Receiver::try_recv) {
                Some(Ok(command)) => command,
                Some(Err(mpsc::TryRecvError::Empty)) | None => break,
                Some(Err(mpsc::TryRecvError::Disconnected)) => {
                    self.control = None;
                    break;
                }
            };
            match command {
                ControlCommand::Interrupt { reply } => {
                    if self.pending_interrupt.is_some() || self.controlled_stop {
                        let _ = reply.send(StopObservation::OutcomeUnknown);
                    } else if self.terminal.is_some() || !self.turn_dispatch_attempted {
                        self.controlled_stop = reply
                            .send(StopObservation::UpstreamInactiveConfirmed)
                            .is_ok();
                    } else {
                        self.pending_interrupt = Some(reply);
                    }
                }
                ControlCommand::StopCommitted => self.stop_committed = true,
            }
        }
        self.maybe_write_interrupt(writer)
    }

    fn maybe_write_interrupt(&mut self, writer: &ProtocolWriter) -> Result<(), CodexSessionError> {
        if self.pending_interrupt.is_none() || self.interrupt_sent {
            return Ok(());
        }
        let (Some(thread_ref), Some(turn_ref)) =
            (self.thread_ref.as_deref(), self.turn_ref.as_deref())
        else {
            return Ok(());
        };
        writer.write_after_queue(
            &json!({
                "id": self.interrupt_request_id(),
                "method": "turn/interrupt",
                "params": {"threadId": thread_ref, "turnId": turn_ref}
            }),
            || self.interrupt_sent = true,
        )
    }

    fn wait_for_stop_commit(
        &mut self,
        writer: &ProtocolWriter,
    ) -> Result<CodexSessionTerminal, CodexSessionError> {
        while !self.stop_committed {
            self.poll_control(writer)?;
            if !self.stop_committed {
                let remaining = self
                    .request
                    .deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(CodexSessionError::Timeout)?;
                std::thread::sleep(remaining.min(CONTROL_POLL_INTERVAL));
            }
        }
        Ok(CodexSessionTerminal::StoppedByControl)
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
        let auto_approve = self.request.auto_approves_callbacks();
        if let Some(result) = codex_approval::approval_result(
            method,
            object,
            auto_approve,
            self.thread_ref.as_deref(),
            self.turn_ref.as_deref(),
        )? {
            return Ok(json!({"id": id, "result": result}));
        }
        if matches!(method, "item/tool/requestUserInput" | "item/tool/call") {
            let params = required_object(object, "params")?;
            self.validate_server_request_correlation(params)?;
        }
        let result = match method {
            "mcpServer/elicitation/request" => json!({"action": "decline"}),
            "item/tool/call" => json!({"contentItems": [], "success": false}),
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
            .filter(|id| (1..=5).contains(id))
            .ok_or(CodexSessionError::UnexpectedResponse)?;
        if self.responses[id] {
            return Err(CodexSessionError::DuplicateResponse);
        }
        if object.contains_key("error") && id == self.interrupt_request_id() && self.interrupt_sent
        {
            if let Some(reply) = self.pending_interrupt.take() {
                let _ = reply.send(StopObservation::OutcomeUnknown);
            }
            self.responses[id] = true;
            return Ok(());
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
            3 if self.goal_dispatch_attempted => {
                let goal = result
                    .get("goal")
                    .and_then(Value::as_object)
                    .ok_or(CodexSessionError::MalformedMessage)?;
                self.correlate_thread(required_string(goal, "threadId")?)?;
                if required_string(goal, "objective")? != self.request.prompt {
                    return Err(CodexSessionError::ConflictingIdentity);
                }
            }
            3 if self.turn_dispatch_attempted && !self.goal_required() => {
                self.consume_turn_start_response(result)?;
            }
            4 if self.turn_dispatch_attempted && self.goal_required() => {
                self.consume_turn_start_response(result)?;
            }
            4 if self.interrupt_sent && !self.goal_required() => {}
            5 if self.interrupt_sent && self.goal_required() => {}
            _ => return Err(CodexSessionError::UnexpectedResponse),
        }
        self.responses[id] = true;
        Ok(())
    }

    fn consume_turn_start_response(
        &mut self,
        result: &Map<String, Value>,
    ) -> Result<(), CodexSessionError> {
        let turn = result
            .get("turn")
            .and_then(Value::as_object)
            .ok_or(CodexSessionError::MalformedMessage)?;
        if turn.get("status").and_then(Value::as_str) != Some("inProgress") {
            return Err(CodexSessionError::MalformedMessage);
        }
        let turn_ref = required_string(turn, "id")?;
        self.observe_turn(turn_ref)?;
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
                    "failed" => CodexSessionTerminal::Failed(failed_turn_kind(turn)),
                    _ => return Err(CodexSessionError::MalformedMessage),
                };
                if self.terminal.is_some_and(|observed| observed != terminal) {
                    return Err(CodexSessionError::ConflictingIdentity);
                }
                self.terminal = Some(terminal);
                if let Some(reply) = self.pending_interrupt.take() {
                    self.controlled_stop = reply
                        .send(StopObservation::UpstreamInactiveConfirmed)
                        .is_ok();
                }
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
            "approvalPolicy": self.request.approval_policy.as_protocol_value(),
            "sandbox": self.request.sandbox_policy.as_thread_value()
        });
        if let Some(model) = self.request.model {
            params["model"] = Value::String(model.to_owned());
        }
        if let Some(provider) = self.request.model_provider {
            params["modelProvider"] = Value::String(provider.to_owned());
        }
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
        let mut input = vec![json!({"type": "text", "text": self.request.prompt})];
        for attachment in self.request.attachments {
            let image = match self.request.image_input_mode {
                crate::codex_capabilities::CodexImageInputMode::Local => {
                    let path = attachment.path().to_str().ok_or(CodexSessionError::Write)?;
                    json!({"type": "localImage", "path": path})
                }
                crate::codex_capabilities::CodexImageInputMode::Inline => {
                    let encoded =
                        base64::engine::general_purpose::STANDARD.encode(attachment.bytes());
                    json!({
                        "type": "image",
                        "url": format!("data:{};base64,{encoded}", attachment.media_type())
                    })
                }
                crate::codex_capabilities::CodexImageInputMode::Unsupported => {
                    return Err(CodexSessionError::Write);
                }
            };
            input.push(image);
        }
        let request = json!({
            "id": self.turn_request_id(),
            "method": "turn/start",
            "params": {
                "input": input,
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

    fn goal_required(&self) -> bool {
        self.request.goal_set_supported && self.request.existing_thread_ref.is_none()
    }

    fn turn_request_id(&self) -> usize {
        if self.goal_required() { 4 } else { 3 }
    }

    fn interrupt_request_id(&self) -> usize {
        if self.goal_required() { 5 } else { 4 }
    }

    fn write_goal_request(&mut self, writer: &ProtocolWriter) -> Result<(), CodexSessionError> {
        let thread_ref = self.thread_ref.as_deref().ok_or(CodexSessionError::Write)?;
        writer.write_after_queue(
            &json!({
                "id": 3,
                "method": "thread/goal/set",
                "params": {"threadId": thread_ref, "objective": self.request.prompt}
            }),
            || self.goal_dispatch_attempted = true,
        )
    }
}

fn failed_turn_kind(_turn: &Map<String, Value>) -> CodexFailedTurnKind {
    // Generic Codex HTTP and response-stream failures describe upstream
    // provider transport. They do not prove that the browser failed to reach
    // Satelle's local Provider Probe Surface.
    CodexFailedTurnKind::Other
}

impl CodexExchange for SessionExchange<'_> {
    type Output = CodexSessionTerminal;

    fn run(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<Self::Output, CodexSessionError> {
        self.run_inner(writer, receiver)
    }

    fn turn_dispatch_attempted(&self) -> bool {
        self.turn_dispatch_attempted
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
