use super::{
    CodexExchange, CodexSessionError, CodexTurnStatus, ProtocolWriter, ReadEvent, required_object,
    required_string, validate_initialize,
};
use serde_json::{Map, Value, json};
use std::sync::mpsc;
use std::time::Instant;

/// A read-only app-server exchange used to reconcile durable Turn ownership
/// after a daemon restart. It accepts only the exact persisted thread and Turn
/// identities so unrelated history can never release the desktop lease.
pub(super) struct TurnReadExchange<'a> {
    thread_ref: &'a str,
    turn_ref: &'a str,
    deadline: Instant,
    responses: [bool; 3],
    status: Option<CodexTurnStatus>,
}

impl<'a> TurnReadExchange<'a> {
    pub(super) const fn new(thread_ref: &'a str, turn_ref: &'a str, deadline: Instant) -> Self {
        Self {
            thread_ref,
            turn_ref,
            deadline,
            responses: [false; 3],
            status: None,
        }
    }

    fn consume_next(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<(), CodexSessionError> {
        let remaining = self
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
            Ok(ReadEvent::Timeout) | Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(CodexSessionError::Timeout)
            }
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
            return unsupported_server_request(object).map(Some);
        }
        if object.contains_key("id") {
            self.consume_response(object)?;
            return Ok(None);
        }
        required_string(object, "method")?;
        Ok(None)
    }

    fn consume_response(&mut self, object: &Map<String, Value>) -> Result<(), CodexSessionError> {
        let id = object
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| usize::try_from(id).ok())
            .filter(|id| (1..=2).contains(id))
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
            2 if self.responses[1] => self.observe_thread(result)?,
            _ => return Err(CodexSessionError::UnexpectedResponse),
        }
        self.responses[id] = true;
        Ok(())
    }

    fn observe_thread(&mut self, result: &Map<String, Value>) -> Result<(), CodexSessionError> {
        let thread = required_object(result, "thread")?;
        if required_string(thread, "id")? != self.thread_ref {
            return Err(CodexSessionError::ConflictingIdentity);
        }
        let turns = thread
            .get("turns")
            .and_then(Value::as_array)
            .ok_or(CodexSessionError::MalformedMessage)?;
        let mut matching_status = None;
        for turn in turns {
            let turn = turn
                .as_object()
                .ok_or(CodexSessionError::MalformedMessage)?;
            if required_string(turn, "id")? != self.turn_ref {
                continue;
            }
            if matching_status.is_some() {
                return Err(CodexSessionError::ConflictingIdentity);
            }
            matching_status = Some(parse_status(required_string(turn, "status")?)?);
        }
        self.status = Some(matching_status.ok_or(CodexSessionError::ConflictingIdentity)?);
        Ok(())
    }
}

impl CodexExchange for TurnReadExchange<'_> {
    type Output = CodexTurnStatus;

    fn run(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<Self::Output, CodexSessionError> {
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
        }))?;
        while !self.responses[1] {
            self.consume_next(writer, receiver)?;
        }
        writer.write(&json!({"method": "initialized"}))?;
        writer.write(&json!({
            "id": 2,
            "method": "thread/read",
            "params": {"threadId": self.thread_ref, "includeTurns": true}
        }))?;
        while !self.responses[2] {
            self.consume_next(writer, receiver)?;
        }
        self.status.ok_or(CodexSessionError::MalformedMessage)
    }
}

fn parse_status(status: &str) -> Result<CodexTurnStatus, CodexSessionError> {
    match status {
        "inProgress" => Ok(CodexTurnStatus::InProgress),
        "completed" => Ok(CodexTurnStatus::Completed),
        "interrupted" => Ok(CodexTurnStatus::Interrupted),
        "failed" => Ok(CodexTurnStatus::Failed),
        _ => Err(CodexSessionError::MalformedMessage),
    }
}

fn unsupported_server_request(object: &Map<String, Value>) -> Result<Value, CodexSessionError> {
    let id = object
        .get("id")
        .filter(|id| id.as_str().is_some_and(|value| !value.is_empty()) || id.as_i64().is_some())
        .ok_or(CodexSessionError::MalformedMessage)?
        .clone();
    required_string(object, "method")?;
    Ok(json!({
        "id": id,
        "error": {
            "code": -32601,
            "message": "server request is not supported by the Satelle adapter"
        }
    }))
}
