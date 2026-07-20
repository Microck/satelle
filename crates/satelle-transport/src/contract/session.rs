use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_core::session::{
    PublicSession, SessionStateRevision, TurnExecutionMode, TurnState, TurnStateRevision,
};
use satelle_core::{SessionId, StopResult, StopResultOutcome, TurnId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;

define_schema_token!(TurnRequestSchema, "satelle.api.v2");
define_schema_token!(StopRequestSchema, "satelle.api.v1");
define_schema_token!(SessionSchema, "satelle.session.v1");
define_schema_token!(SessionStopSchema, "satelle.session.stop.v1");

pub(crate) trait ApiRequestContract {
    const SCHEMA_VERSION: &'static str;

    fn exceeds_attachment_limit(_value: &Value) -> bool {
        false
    }
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRequest {
    schema_version: TurnRequestSchema,
    prompt: String,
    execution_mode: TurnExecutionMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    experimental_provider_computer_use: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    refresh_provider_smoke_test: bool,
}

pub(crate) struct TurnRequestParts {
    pub(crate) prompt: String,
    pub(crate) execution_mode: TurnExecutionMode,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) experimental_provider_computer_use: bool,
    pub(crate) refresh_provider_smoke_test: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl TurnRequest {
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            schema_version: TurnRequestSchema,
            prompt: prompt.into(),
            execution_mode: TurnExecutionMode::Standard,
            model: None,
            provider: None,
            experimental_provider_computer_use: false,
            refresh_provider_smoke_test: false,
        }
    }

    pub fn with_execution_mode(mut self, execution_mode: TurnExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    pub fn with_provider_intent(
        mut self,
        model: Option<String>,
        provider: Option<String>,
        experimental_provider_computer_use: bool,
        refresh_provider_smoke_test: bool,
    ) -> Self {
        self.model = model;
        self.provider = provider;
        self.experimental_provider_computer_use = experimental_provider_computer_use;
        self.refresh_provider_smoke_test = refresh_provider_smoke_test;
        self
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub const fn execution_mode(&self) -> TurnExecutionMode {
        self.execution_mode
    }

    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    pub fn provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }

    pub const fn experimental_provider_computer_use(&self) -> bool {
        self.experimental_provider_computer_use
    }

    pub const fn refresh_provider_smoke_test(&self) -> bool {
        self.refresh_provider_smoke_test
    }

    pub(crate) fn into_parts(self) -> TurnRequestParts {
        TurnRequestParts {
            prompt: self.prompt,
            execution_mode: self.execution_mode,
            model: self.model,
            provider: self.provider,
            experimental_provider_computer_use: self.experimental_provider_computer_use,
            refresh_provider_smoke_test: self.refresh_provider_smoke_test,
        }
    }
}

impl ApiRequestContract for TurnRequest {
    const SCHEMA_VERSION: &'static str = TurnRequestSchema::TOKEN;

    fn exceeds_attachment_limit(value: &Value) -> bool {
        // Attachments remain outside the TurnRequest grammar. Inspect only a
        // non-empty list so the advertised zero limit can fail as capacity.
        value
            .as_object()
            .and_then(|object| object.get("attachments"))
            .is_some_and(
                |attachments| matches!(attachments, Value::Array(values) if !values.is_empty()),
            )
    }
}

impl fmt::Debug for TurnRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnRequest")
            .field("prompt_bytes", &self.prompt.len())
            .field("execution_mode", &self.execution_mode)
            .field("has_model_override", &self.model.is_some())
            .field("has_provider_override", &self.provider.is_some())
            .field(
                "experimental_provider_computer_use",
                &self.experimental_provider_computer_use,
            )
            .field(
                "refresh_provider_smoke_test",
                &self.refresh_provider_smoke_test,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    schema_version: StopRequestSchema,
}

impl StopRequest {
    pub const fn new() -> Self {
        Self {
            schema_version: StopRequestSchema,
        }
    }
}

impl Default for StopRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiRequestContract for StopRequest {
    const SCHEMA_VERSION: &'static str = StopRequestSchema::TOKEN;
}

/// Flat authenticated Session envelope. The lifecycle projection remains the
/// one core-owned, validated `PublicSession` wire representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    schema_version: SessionSchema,
    request_id: RequestId,
    host_identity: String,
    #[serde(flatten)]
    session: PublicSession,
}

impl SessionResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        session: PublicSession,
    ) -> Self {
        Self {
            schema_version: SessionSchema,
            request_id,
            host_identity,
            session,
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn session(&self) -> &PublicSession {
        &self.session
    }
}

impl AuthenticatedResponseContract for SessionResponse {
    fn request_id(&self) -> &RequestId {
        self.request_id()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StopOutcome {
    Stopped,
    AlreadyTerminal,
}

impl From<StopResultOutcome> for StopOutcome {
    fn from(value: StopResultOutcome) -> Self {
        match value {
            StopResultOutcome::Stopped => Self::Stopped,
            StopResultOutcome::AlreadyTerminal => Self::AlreadyTerminal,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopResponse {
    request_id: RequestId,
    host_identity: String,
    result: StopResult,
    session_state_revision: SessionStateRevision,
    turn_state_revision: TurnStateRevision,
}

impl StopResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        result: StopResult,
        session_state_revision: SessionStateRevision,
        turn_state_revision: TurnStateRevision,
    ) -> Self {
        Self {
            request_id,
            host_identity,
            result,
            session_state_revision,
            turn_state_revision,
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn result(&self) -> &StopResult {
        &self.result
    }
}

impl AuthenticatedResponseContract for StopResponse {
    fn request_id(&self) -> &RequestId {
        self.request_id()
    }

    fn host_identity(&self) -> &str {
        self.host_identity()
    }
}

#[derive(Serialize)]
struct StopResponseRef<'a> {
    schema_version: SessionStopSchema,
    request_id: &'a RequestId,
    host_identity: &'a str,
    outcome: StopOutcome,
    session_id: &'a SessionId,
    turn_id: &'a TurnId,
    session_state_revision: SessionStateRevision,
    turn_state_revision: TurnStateRevision,
    previous_state: TurnState,
    current_state: TurnState,
    changed: bool,
    stopped_at: Option<&'a str>,
}

impl Serialize for StopResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        StopResponseRef {
            schema_version: SessionStopSchema,
            request_id: &self.request_id,
            host_identity: &self.host_identity,
            outcome: self.result.outcome().into(),
            session_id: self.result.session_id(),
            turn_id: self.result.turn_id(),
            session_state_revision: self.session_state_revision,
            turn_state_revision: self.turn_state_revision,
            previous_state: self.result.previous_state(),
            current_state: self.result.current_state(),
            changed: self.result.changed(),
            stopped_at: self.result.stopped_at(),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopResponseOwned {
    #[serde(rename = "schema_version")]
    _schema_version: SessionStopSchema,
    request_id: RequestId,
    host_identity: String,
    outcome: StopOutcome,
    session_id: SessionId,
    turn_id: TurnId,
    session_state_revision: SessionStateRevision,
    turn_state_revision: TurnStateRevision,
    previous_state: TurnState,
    current_state: TurnState,
    changed: bool,
    #[serde(deserialize_with = "Option::deserialize")]
    stopped_at: Option<String>,
}

impl<'de> Deserialize<'de> for StopResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StopResponseOwned::deserialize(deserializer)?;
        let result = match wire.outcome {
            StopOutcome::Stopped => StopResult::stopped(
                wire.session_id,
                wire.turn_id,
                wire.previous_state,
                wire.stopped_at
                    .clone()
                    .ok_or_else(|| serde::de::Error::missing_field("stopped_at"))?,
            ),
            StopOutcome::AlreadyTerminal => {
                if wire.stopped_at.is_some() {
                    return Err(serde::de::Error::custom(
                        "already_terminal stop responses cannot contain stopped_at",
                    ));
                }
                StopResult::already_terminal(wire.session_id, wire.turn_id, wire.previous_state)
            }
        }
        .map_err(serde::de::Error::custom)?;
        if result.current_state() != wire.current_state || result.changed() != wire.changed {
            return Err(serde::de::Error::custom(
                "the stop response fields violate the outcome invariant",
            ));
        }
        if wire.turn_state_revision.get() == 1
            || wire.session_state_revision.get() < wire.turn_state_revision.get()
        {
            return Err(serde::de::Error::custom(
                "the stop response revisions violate lifecycle invariants",
            ));
        }
        Ok(Self {
            request_id: wire.request_id,
            host_identity: wire.host_identity,
            result,
            session_state_revision: wire.session_state_revision,
            turn_state_revision: wire.turn_state_revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn starting_session_response() -> serde_json::Value {
        serde_json::json!({
            "schema_version": "satelle.session.v1",
            "request_id": "01890a5d-ac96-7b7c-8f89-37c3d0a66e01",
            "host_identity": "host-test",
            "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "display_name": null,
            "session_state_revision": 1,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
            "activity": {
                "state": "starting",
                "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
                "turn_state_revision": 1
            },
            "turns": [{
                "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
                "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
                "turn_state_revision": 1,
                "state": "starting",
                "started_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "terminal_at": null,
                "safe_summary": null
            }]
        })
    }

    fn terminal_stop_response() -> serde_json::Value {
        serde_json::json!({
            "schema_version": "satelle.session.stop.v1",
            "request_id": "01890a5d-ac96-7b7c-8f89-37c3d0a66e01",
            "host_identity": "host-test",
            "outcome": "already_terminal",
            "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21",
            "session_state_revision": 3,
            "turn_state_revision": 3,
            "previous_state": "completed",
            "current_state": "completed",
            "changed": false,
            "stopped_at": null
        })
    }

    #[test]
    fn request_contract_requires_an_explicit_closed_execution_mode() {
        let request = TurnRequest::new("private prompt");
        assert_eq!(
            serde_json::to_value(request).expect("serialize request"),
            serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt",
                "execution_mode": "standard"
            })
        );
        assert_eq!(
            serde_json::to_value(
                TurnRequest::new("private prompt").with_execution_mode(TurnExecutionMode::Yolo)
            )
            .expect("serialize YOLO request"),
            serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt",
                "execution_mode": "yolo"
            })
        );
        assert_eq!(
            serde_json::to_value(TurnRequest::new("private prompt").with_provider_intent(
                Some("model-explicit".to_string()),
                Some("provider-explicit".to_string()),
                true,
                true,
            ))
            .expect("serialize provider intent"),
            serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt",
                "execution_mode": "standard",
                "model": "model-explicit",
                "provider": "provider-explicit",
                "experimental_provider_computer_use": true,
                "refresh_provider_smoke_test": true
            })
        );
        assert!(
            serde_json::from_value::<TurnRequest>(serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TurnRequest>(serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt",
                "execution_mode": "standard",
                "attachments": []
            }))
            .is_err()
        );
        assert_eq!(
            serde_json::to_value(StopRequest::new()).expect("serialize stop request"),
            serde_json::json!({"schema_version": "satelle.api.v1"})
        );
    }

    #[test]
    fn controller_presentation_fields_are_absent_from_the_turn_request_contract() {
        for field in ["attach", "detach"] {
            let mut request = serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt",
                "execution_mode": "standard"
            });
            request
                .as_object_mut()
                .expect("Turn request fixture is an object")
                .insert(field.to_string(), serde_json::json!(true));

            assert!(
                serde_json::from_value::<TurnRequest>(request).is_err(),
                "Controller-only {field} must not enter the Host Turn request grammar"
            );
        }
    }

    #[test]
    fn session_response_rejects_unknown_and_duplicate_envelope_fields() {
        serde_json::from_value::<SessionResponse>(starting_session_response())
            .expect("decode coherent Session response");

        let mut unknown = starting_session_response();
        unknown["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SessionResponse>(unknown).is_err());

        let duplicate = r#"{
            "schema_version":"satelle.session.v1",
            "request_id":"01890a5d-ac96-7b7c-8f89-37c3d0a66e01",
            "host_identity":"host-test",
            "host_identity":"host-other",
            "session_id":"rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "display_name":null,
            "session_state_revision":1,
            "created_at":"2024-01-01T00:00:00Z",
            "updated_at":"2024-01-01T00:00:00Z",
            "activity":{"state":"starting","turn_id":"rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21","turn_state_revision":1},
            "turns":[{"session_id":"rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11","turn_id":"rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21","turn_state_revision":1,"state":"starting","started_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","terminal_at":null,"safe_summary":null}]
        }"#;
        assert!(serde_json::from_str::<SessionResponse>(duplicate).is_err());
    }

    #[test]
    fn stop_response_deserialization_enforces_result_and_revision_invariants() {
        serde_json::from_value::<StopResponse>(terminal_stop_response())
            .expect("decode coherent stop response");

        let mut cases = Vec::new();
        let mut wrong_state = terminal_stop_response();
        wrong_state["current_state"] = serde_json::json!("running");
        cases.push(wrong_state);

        let mut wrong_changed = terminal_stop_response();
        wrong_changed["changed"] = serde_json::json!(true);
        cases.push(wrong_changed);

        let mut unexpected_time = terminal_stop_response();
        unexpected_time["stopped_at"] = serde_json::json!("2024-01-01T00:00:00Z");
        cases.push(unexpected_time);

        let mut initial_terminal_revision = terminal_stop_response();
        initial_terminal_revision["turn_state_revision"] = serde_json::json!(1);
        cases.push(initial_terminal_revision);

        let mut session_revision_too_small = terminal_stop_response();
        session_revision_too_small["session_state_revision"] = serde_json::json!(2);
        cases.push(session_revision_too_small);

        for case in cases {
            assert!(serde_json::from_value::<StopResponse>(case).is_err());
        }
    }

    #[test]
    fn stop_response_requires_nullable_stopped_at() {
        let response = serde_json::from_value::<StopResponse>(terminal_stop_response())
            .expect("decode coherent stop response");
        let mut wire = serde_json::to_value(response).expect("serialize stop response");

        assert_eq!(
            wire.get("stopped_at"),
            Some(&serde_json::Value::Null),
            "serialization must emit stopped_at as explicit null"
        );
        serde_json::from_value::<StopResponse>(wire.clone())
            .expect("decode complete serialized stop response");
        let removed = wire
            .as_object_mut()
            .expect("stop response is an object")
            .remove("stopped_at");
        assert_eq!(removed, Some(serde_json::Value::Null));

        assert!(serde_json::from_value::<StopResponse>(wire).is_err());
    }
}
