use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use satelle_core::session::{
    PublicSession, SessionStateRevision, TurnExecutionMode, TurnState, TurnStateRevision,
};
use satelle_core::{SessionId, StopResult, StopResultOutcome, TurnId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;

define_schema_token!(TurnRequestSchema, "satelle.api.v3");
define_schema_token!(StopRequestSchema, "satelle.api.v1");
define_schema_token!(SessionSchema, "satelle.session.v1");
define_schema_token!(SessionStopSchema, "satelle.session.stop.v1");
define_schema_token!(AdmissionCancellationSchema, "satelle.admission.cancel.v1");

pub const MAX_IMAGE_ATTACHMENT_COUNT: usize = 2;
pub const MAX_IMAGE_ATTACHMENT_BYTES: usize = 5 * 1_024 * 1_024;
pub const MAX_IMAGE_ATTACHMENT_BYTES_TOTAL: usize = 10 * 1_024 * 1_024;
pub(crate) const MAX_IMAGE_ATTACHMENT_BASE64_BYTES: usize =
    4 * MAX_IMAGE_ATTACHMENT_BYTES.div_ceil(3);
pub(crate) const MAX_IMAGE_ATTACHMENT_BASE64_BYTES_TOTAL: usize =
    4 * ((MAX_IMAGE_ATTACHMENT_BYTES_TOTAL + 2 * MAX_IMAGE_ATTACHMENT_COUNT) / 3);
pub const SUPPORTED_IMAGE_MEDIA_TYPES: &[&str] = &["image/jpeg", "image/png"];

pub(crate) trait ApiRequestContract {
    const SCHEMA_VERSION: &'static str;
    const MAX_BASE64_BODY_ALLOWANCE: usize = 0;

    fn exceeds_attachment_limit(_value: &Value, _image_attachments_supported: bool) -> bool {
        false
    }

    fn attachment_data_base64_bytes(_value: &Value) -> usize {
        0
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<ImageAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    turn_execution_timeout_ms: Option<u64>,
}

pub(crate) struct TurnRequestParts {
    pub(crate) prompt: String,
    pub(crate) execution_mode: TurnExecutionMode,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) experimental_provider_computer_use: bool,
    pub(crate) refresh_provider_smoke_test: bool,
    pub(crate) attachments: Vec<ImageAttachment>,
    pub(crate) turn_execution_timeout_ms: Option<u64>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageAttachment {
    media_type: String,
    size_bytes: u64,
    sha256: String,
    data_base64: String,
}

impl ImageAttachment {
    pub fn new(
        media_type: impl Into<String>,
        size_bytes: u64,
        sha256: impl Into<String>,
        data_base64: impl Into<String>,
    ) -> Self {
        Self {
            media_type: media_type.into(),
            size_bytes,
            sha256: sha256.into(),
            data_base64: data_base64.into(),
        }
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn data_base64(&self) -> &str {
        &self.data_base64
    }
}

impl fmt::Debug for ImageAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageAttachment")
            .field("media_type", &self.media_type)
            .field("size_bytes", &self.size_bytes)
            .field("data", &"[redacted]")
            .finish()
    }
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
            attachments: Vec::new(),
            turn_execution_timeout_ms: None,
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

    pub fn with_attachments(mut self, attachments: Vec<ImageAttachment>) -> Self {
        self.attachments = attachments;
        self
    }

    pub fn with_turn_execution_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.turn_execution_timeout_ms = Some(timeout_ms);
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

    pub fn attachments(&self) -> &[ImageAttachment] {
        &self.attachments
    }

    pub const fn turn_execution_timeout_ms(&self) -> Option<u64> {
        self.turn_execution_timeout_ms
    }

    pub(crate) fn into_parts(self) -> TurnRequestParts {
        TurnRequestParts {
            prompt: self.prompt,
            execution_mode: self.execution_mode,
            model: self.model,
            provider: self.provider,
            experimental_provider_computer_use: self.experimental_provider_computer_use,
            refresh_provider_smoke_test: self.refresh_provider_smoke_test,
            attachments: self.attachments,
            turn_execution_timeout_ms: self.turn_execution_timeout_ms,
        }
    }
}

impl ApiRequestContract for TurnRequest {
    const SCHEMA_VERSION: &'static str = TurnRequestSchema::TOKEN;
    const MAX_BASE64_BODY_ALLOWANCE: usize = MAX_IMAGE_ATTACHMENT_BASE64_BYTES_TOTAL;

    fn exceeds_attachment_limit(value: &Value, image_attachments_supported: bool) -> bool {
        value
            .as_object()
            .and_then(|object| object.get("attachments"))
            .is_some_and(|attachments| match attachments {
                Value::Array(values) => {
                    (!image_attachments_supported && !values.is_empty())
                        || values.len() > MAX_IMAGE_ATTACHMENT_COUNT
                        || values.iter().any(|value| {
                            let size = value.get("size_bytes").and_then(Value::as_u64);
                            let media_type = value.get("media_type").and_then(Value::as_str);
                            let data_base64 = value.get("data_base64").and_then(Value::as_str);
                            size.is_none_or(|size| size > MAX_IMAGE_ATTACHMENT_BYTES as u64)
                                || media_type.is_none_or(|media_type| {
                                    !SUPPORTED_IMAGE_MEDIA_TYPES.contains(&media_type)
                                })
                                || data_base64.is_none_or(|value| {
                                    value.len() > MAX_IMAGE_ATTACHMENT_BASE64_BYTES
                                })
                        })
                        || values
                            .iter()
                            .try_fold(0_u64, |total, value| {
                                total.checked_add(value.get("size_bytes")?.as_u64()?)
                            })
                            .is_none_or(|total| total > MAX_IMAGE_ATTACHMENT_BYTES_TOTAL as u64)
                        || values
                            .iter()
                            .try_fold(0_usize, |total, value| {
                                total.checked_add(value.get("data_base64")?.as_str()?.len())
                            })
                            .is_none_or(|total| total > MAX_IMAGE_ATTACHMENT_BASE64_BYTES_TOTAL)
                }
                _ => false,
            })
    }

    fn attachment_data_base64_bytes(value: &Value) -> usize {
        value
            .as_object()
            .and_then(|object| object.get("attachments"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|attachment| attachment.get("data_base64")?.as_str())
            .map(str::len)
            .sum()
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
            .field("attachment_count", &self.attachments.len())
            .field("turn_execution_timeout_ms", &self.turn_execution_timeout_ms)
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
pub enum AdmissionCancellationOutcome {
    Cancelled,
    Admitted,
    RecoveryPending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionCancellationResponse {
    schema_version: AdmissionCancellationSchema,
    request_id: RequestId,
    host_identity: String,
    outcome: AdmissionCancellationOutcome,
    #[serde(deserialize_with = "Option::deserialize")]
    session_id: Option<SessionId>,
    #[serde(deserialize_with = "Option::deserialize")]
    turn_id: Option<TurnId>,
}

impl AdmissionCancellationResponse {
    pub(crate) fn cancelled(request_id: RequestId, host_identity: String) -> Self {
        Self {
            schema_version: AdmissionCancellationSchema,
            request_id,
            host_identity,
            outcome: AdmissionCancellationOutcome::Cancelled,
            session_id: None,
            turn_id: None,
        }
    }

    pub(crate) fn admitted(
        request_id: RequestId,
        host_identity: String,
        session_id: SessionId,
        turn_id: TurnId,
    ) -> Self {
        Self {
            schema_version: AdmissionCancellationSchema,
            request_id,
            host_identity,
            outcome: AdmissionCancellationOutcome::Admitted,
            session_id: Some(session_id),
            turn_id: Some(turn_id),
        }
    }

    pub(crate) fn recovery_pending(request_id: RequestId, host_identity: String) -> Self {
        Self {
            schema_version: AdmissionCancellationSchema,
            request_id,
            host_identity,
            outcome: AdmissionCancellationOutcome::RecoveryPending,
            session_id: None,
            turn_id: None,
        }
    }

    pub const fn outcome(&self) -> AdmissionCancellationOutcome {
        self.outcome
    }

    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub const fn turn_id(&self) -> Option<&TurnId> {
        self.turn_id.as_ref()
    }

    pub(crate) fn validate(&self) -> bool {
        matches!(
            (self.outcome, &self.session_id, &self.turn_id),
            (AdmissionCancellationOutcome::Admitted, Some(_), Some(_))
                | (
                    AdmissionCancellationOutcome::Cancelled
                        | AdmissionCancellationOutcome::RecoveryPending,
                    None,
                    None
                )
        )
    }
}

impl AuthenticatedResponseContract for AdmissionCancellationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
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
                "schema_version": "satelle.api.v3",
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
                "schema_version": "satelle.api.v3",
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
                "schema_version": "satelle.api.v3",
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
                "schema_version": "satelle.api.v3",
                "prompt": "private prompt"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TurnRequest>(serde_json::json!({
                "schema_version": "satelle.api.v3",
                "prompt": "private prompt",
                "execution_mode": "standard",
                "controller_only": true
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
                "schema_version": "satelle.api.v3",
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
    fn mvp_turn_requests_cannot_route_across_desktop_bindings() {
        for field in ["desktop_user", "desktop_binding", "desktop_session"] {
            let mut request = serde_json::json!({
                "schema_version": "satelle.api.v2",
                "prompt": "private prompt",
                "execution_mode": "standard"
            });
            request
                .as_object_mut()
                .expect("Turn request fixture is an object")
                .insert(field.to_string(), serde_json::json!("someone-else"));

            assert!(
                serde_json::from_value::<TurnRequest>(request).is_err(),
                "MVP Turn requests must not select {field}"
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
    fn admission_cancellation_response_requires_handles_only_for_admitted() {
        let base = serde_json::json!({
            "schema_version": "satelle.admission.cancel.v1",
            "request_id": "01890a5d-ac96-7b7c-8f89-37c3d0a66e01",
            "host_identity": "host-test",
            "outcome": "admitted",
            "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
            "turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21"
        });
        let admitted = serde_json::from_value::<AdmissionCancellationResponse>(base.clone())
            .expect("decode admitted cancellation response");
        assert!(admitted.validate());

        let mut missing_turn = base.clone();
        missing_turn["turn_id"] = serde_json::Value::Null;
        assert!(
            !serde_json::from_value::<AdmissionCancellationResponse>(missing_turn)
                .expect("wire types remain decodable for client validation")
                .validate()
        );

        for outcome in ["cancelled", "recovery_pending"] {
            let terminal = serde_json::json!({
                "schema_version": "satelle.admission.cancel.v1",
                "request_id": "01890a5d-ac96-7b7c-8f89-37c3d0a66e01",
                "host_identity": "host-test",
                "outcome": outcome,
                "session_id": null,
                "turn_id": null
            });
            let decoded = serde_json::from_value::<AdmissionCancellationResponse>(terminal.clone())
                .expect("decode complete terminal cancellation response");
            assert!(decoded.validate());
            assert_eq!(serde_json::to_value(decoded).unwrap(), terminal);

            for field in ["session_id", "turn_id"] {
                let mut missing = terminal.clone();
                missing
                    .as_object_mut()
                    .expect("cancellation response is an object")
                    .remove(field);
                assert!(
                    serde_json::from_value::<AdmissionCancellationResponse>(missing).is_err(),
                    "missing nullable {field} must be rejected for {outcome}"
                );
            }
        }

        let mut cancelled_with_handles = base;
        cancelled_with_handles["outcome"] = serde_json::json!("cancelled");
        assert!(
            !serde_json::from_value::<AdmissionCancellationResponse>(cancelled_with_handles)
                .expect("wire types remain decodable for client validation")
                .validate()
        );
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
