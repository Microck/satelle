use super::{ApiErrorCategory, ApiErrorCode, RequestId, define_schema_token};
use satelle_core::{SatelleEventBody, SessionId, TurnId};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_EVENT_SUBSCRIPTIONS: usize = 16;

define_schema_token!(WsControlSchema, "satelle.ws.control.v1");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SubscribeType;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SubscribedType;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ErrorType;

macro_rules! control_type {
    ($name:ident, $token:literal) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str($token)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                if value == $token {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(concat!(
                        "expected WebSocket control type ",
                        $token
                    )))
                }
            }
        }
    };
}

control_type!(SubscribeType, "subscribe");
control_type!(SubscribedType, "subscribed");
control_type!(ErrorType, "error");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WsCloseReason {
    InvalidRequest,
    UnsupportedSchema,
    AuthorizationInsufficientScope,
    CapacityExceeded,
    RateLimited,
    AuthenticationFailed,
    SlowConsumer,
    PayloadTooLarge,
    InternalError,
    IdleTimeout,
    ServerShutdown,
}

impl WsCloseReason {
    pub const ALL: [Self; 11] = [
        Self::InvalidRequest,
        Self::UnsupportedSchema,
        Self::AuthorizationInsufficientScope,
        Self::CapacityExceeded,
        Self::RateLimited,
        Self::AuthenticationFailed,
        Self::SlowConsumer,
        Self::PayloadTooLarge,
        Self::InternalError,
        Self::IdleTimeout,
        Self::ServerShutdown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedSchema => "unsupported-schema",
            Self::AuthorizationInsufficientScope => "authorization-insufficient-scope",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::RateLimited => "rate-limited",
            Self::AuthenticationFailed => "authentication-failed",
            Self::SlowConsumer => "slow-consumer",
            Self::PayloadTooLarge => "payload-too-large",
            Self::InternalError => "internal-error",
            Self::IdleTimeout => "idle-timeout",
            Self::ServerShutdown => "server-shutdown",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "invalid-request" => Some(Self::InvalidRequest),
            "unsupported-schema" => Some(Self::UnsupportedSchema),
            "authorization-insufficient-scope" => Some(Self::AuthorizationInsufficientScope),
            "capacity-exceeded" => Some(Self::CapacityExceeded),
            "rate-limited" => Some(Self::RateLimited),
            "authentication-failed" => Some(Self::AuthenticationFailed),
            "slow-consumer" => Some(Self::SlowConsumer),
            "payload-too-large" => Some(Self::PayloadTooLarge),
            "internal-error" => Some(Self::InternalError),
            "idle-timeout" => Some(Self::IdleTimeout),
            "server-shutdown" => Some(Self::ServerShutdown),
            _ => None,
        }
    }

    pub const fn close_code(self) -> u16 {
        match self {
            Self::PayloadTooLarge => 1009,
            Self::InternalError => 1011,
            Self::ServerShutdown => 1001,
            Self::InvalidRequest
            | Self::UnsupportedSchema
            | Self::AuthorizationInsufficientScope
            | Self::CapacityExceeded
            | Self::RateLimited
            | Self::AuthenticationFailed
            | Self::SlowConsumer
            | Self::IdleTimeout => 1008,
        }
    }

    pub(crate) const fn api_code(self) -> ApiErrorCode {
        match self {
            Self::InvalidRequest => ApiErrorCode::InvalidRequest,
            Self::UnsupportedSchema => ApiErrorCode::UnsupportedSchema,
            Self::AuthorizationInsufficientScope => ApiErrorCode::AuthorizationInsufficientScope,
            Self::CapacityExceeded | Self::SlowConsumer => ApiErrorCode::CapacityExceeded,
            Self::RateLimited | Self::IdleTimeout => ApiErrorCode::RateLimited,
            Self::AuthenticationFailed => ApiErrorCode::AuthenticationFailed,
            Self::PayloadTooLarge => ApiErrorCode::PayloadTooLarge,
            Self::InternalError => ApiErrorCode::InternalError,
            Self::ServerShutdown => ApiErrorCode::HostUnreachable,
        }
    }

    pub(crate) const fn category(self) -> ApiErrorCategory {
        match self {
            Self::InvalidRequest | Self::UnsupportedSchema | Self::PayloadTooLarge => {
                ApiErrorCategory::InvalidRequest
            }
            Self::AuthorizationInsufficientScope => ApiErrorCategory::Authorization,
            Self::CapacityExceeded | Self::SlowConsumer => ApiErrorCategory::Capacity,
            Self::RateLimited | Self::IdleTimeout => ApiErrorCategory::RateLimit,
            Self::AuthenticationFailed => ApiErrorCategory::Authentication,
            Self::InternalError => ApiErrorCategory::Internal,
            Self::ServerShutdown => ApiErrorCategory::Readiness,
        }
    }

    pub(crate) const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::IdleTimeout | Self::ServerShutdown
        )
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "the WebSocket control message is invalid",
            Self::UnsupportedSchema => "the WebSocket control schema is unsupported",
            Self::AuthorizationInsufficientScope => {
                "the API Principal does not authorize this WebSocket operation"
            }
            Self::CapacityExceeded => "the WebSocket subscription limit was exceeded",
            Self::RateLimited => "the API Principal exceeded the WebSocket inbound message limit",
            Self::AuthenticationFailed => "authentication failed",
            Self::SlowConsumer => "the WebSocket subscriber could not keep up with live events",
            Self::PayloadTooLarge => "the WebSocket message exceeds the configured byte limit",
            Self::InternalError => "the Host Daemon event stream failed",
            Self::IdleTimeout => "the WebSocket connection exceeded its idle timeout",
            Self::ServerShutdown => "the Host Daemon is shutting down",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventSubscription {
    Host,
    Session {
        session_id: SessionId,
    },
    Turn {
        session_id: SessionId,
        turn_id: TurnId,
    },
}

impl EventSubscription {
    pub fn matches(&self, event: &SatelleEventBody) -> bool {
        match self {
            Self::Host => true,
            Self::Session { session_id } => event.session_id() == Some(session_id),
            Self::Turn {
                session_id,
                turn_id,
            } => event.session_id() == Some(session_id) && event.turn_id() == Some(turn_id),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubscribeRequest {
    schema_version: WsControlSchema,
    #[serde(rename = "type")]
    message_type: SubscribeType,
    request_id: RequestId,
    subscriptions: Vec<EventSubscription>,
}

impl SubscribeRequest {
    pub fn new(
        request_id: RequestId,
        subscriptions: Vec<EventSubscription>,
    ) -> Result<Self, SubscribeRequestError> {
        validate_subscriptions(&subscriptions)?;
        Ok(Self {
            schema_version: WsControlSchema,
            message_type: SubscribeType,
            request_id,
            subscriptions,
        })
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn subscriptions(&self) -> &[EventSubscription] {
        &self.subscriptions
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeRequestOwned {
    #[serde(rename = "schema_version")]
    _schema_version: WsControlSchema,
    #[serde(rename = "type")]
    _message_type: SubscribeType,
    request_id: RequestId,
    subscriptions: Vec<EventSubscription>,
}

impl<'de> Deserialize<'de> for SubscribeRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SubscribeRequestOwned::deserialize(deserializer)?;
        Self::new(value.request_id, value.subscriptions).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribedResponse {
    schema_version: WsControlSchema,
    #[serde(rename = "type")]
    message_type: SubscribedType,
    request_id: RequestId,
    host_identity: String,
    subscriptions: Vec<EventSubscription>,
}

impl SubscribedResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        subscriptions: Vec<EventSubscription>,
    ) -> Self {
        Self {
            schema_version: WsControlSchema,
            message_type: SubscribedType,
            request_id,
            host_identity,
            subscriptions,
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub fn subscriptions(&self) -> &[EventSubscription] {
        &self.subscriptions
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WsControlError {
    schema_version: WsControlSchema,
    #[serde(rename = "type")]
    message_type: ErrorType,
    request_id: RequestId,
    host_identity: String,
    reason: WsCloseReason,
    code: ApiErrorCode,
    category: ApiErrorCategory,
    retryable: bool,
    message: String,
    details: Option<Value>,
    docs_url: Option<String>,
    suggested_commands: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WsControlErrorOwned {
    #[serde(rename = "schema_version")]
    _schema_version: WsControlSchema,
    #[serde(rename = "type")]
    _message_type: ErrorType,
    request_id: RequestId,
    host_identity: String,
    reason: WsCloseReason,
    code: ApiErrorCode,
    category: ApiErrorCategory,
    retryable: bool,
    message: String,
    details: Option<Value>,
    docs_url: Option<String>,
    suggested_commands: Vec<String>,
}

impl<'de> Deserialize<'de> for WsControlError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = WsControlErrorOwned::deserialize(deserializer)?;
        if value.code != value.reason.api_code()
            || value.category != value.reason.category()
            || value.retryable != value.reason.retryable()
        {
            return Err(serde::de::Error::custom(
                "WebSocket error fields do not match the close reason",
            ));
        }
        Ok(Self {
            schema_version: WsControlSchema,
            message_type: ErrorType,
            request_id: value.request_id,
            host_identity: value.host_identity,
            reason: value.reason,
            code: value.code,
            category: value.category,
            retryable: value.retryable,
            message: value.message,
            details: value.details,
            docs_url: value.docs_url,
            suggested_commands: value.suggested_commands,
        })
    }
}

impl WsControlError {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        reason: WsCloseReason,
        details: Option<Value>,
    ) -> Self {
        Self {
            schema_version: WsControlSchema,
            message_type: ErrorType,
            request_id,
            host_identity,
            reason,
            code: reason.api_code(),
            category: reason.category(),
            retryable: reason.retryable(),
            message: reason.message().to_string(),
            details,
            docs_url: None,
            suggested_commands: Vec::new(),
        }
    }

    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn reason(&self) -> WsCloseReason {
        self.reason
    }

    pub const fn code(&self) -> ApiErrorCode {
        self.code
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum WsServerControl {
    Subscribed(SubscribedResponse),
    Error(WsControlError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscribeRequestError;

impl fmt::Display for SubscribeRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("subscriptions must contain from 1 through 16 unique scopes")
    }
}

impl std::error::Error for SubscribeRequestError {}

fn validate_subscriptions(
    subscriptions: &[EventSubscription],
) -> Result<(), SubscribeRequestError> {
    if subscriptions.is_empty() || subscriptions.len() > MAX_EVENT_SUBSCRIPTIONS {
        return Err(SubscribeRequestError);
    }
    let unique = subscriptions.iter().collect::<BTreeSet<_>>();
    if unique.len() != subscriptions.len() {
        return Err(SubscribeRequestError);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscribe_contract_is_closed_bounded_and_duplicate_free() {
        let request = SubscribeRequest::new(
            RequestId::new(),
            vec![
                EventSubscription::Host,
                EventSubscription::Session {
                    session_id: SessionId::parse("rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11")
                        .unwrap(),
                },
            ],
        )
        .unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["schema_version"], "satelle.ws.control.v1");
        assert_eq!(value["type"], "subscribe");
        assert_eq!(
            serde_json::from_value::<SubscribeRequest>(value.clone()).unwrap(),
            request
        );

        for invalid in [
            serde_json::json!({
                "schema_version": "satelle.ws.control.v1",
                "type": "subscribe",
                "request_id": RequestId::new(),
                "subscriptions": []
            }),
            serde_json::json!({
                "schema_version": "satelle.ws.control.v1",
                "type": "subscribe",
                "request_id": RequestId::new(),
                "subscriptions": [{"kind":"host"}, {"kind":"host"}]
            }),
            {
                let mut value = value.clone();
                value["authorization"] = serde_json::json!("Bearer forbidden");
                value
            },
        ] {
            assert!(serde_json::from_value::<SubscribeRequest>(invalid).is_err());
        }
    }

    #[test]
    fn close_reasons_own_one_exact_token_code_and_control_mapping() {
        let expected = [
            (WsCloseReason::InvalidRequest, "invalid-request", 1008),
            (WsCloseReason::UnsupportedSchema, "unsupported-schema", 1008),
            (
                WsCloseReason::AuthorizationInsufficientScope,
                "authorization-insufficient-scope",
                1008,
            ),
            (WsCloseReason::CapacityExceeded, "capacity-exceeded", 1008),
            (WsCloseReason::RateLimited, "rate-limited", 1008),
            (
                WsCloseReason::AuthenticationFailed,
                "authentication-failed",
                1008,
            ),
            (WsCloseReason::SlowConsumer, "slow-consumer", 1008),
            (WsCloseReason::PayloadTooLarge, "payload-too-large", 1009),
            (WsCloseReason::InternalError, "internal-error", 1011),
            (WsCloseReason::IdleTimeout, "idle-timeout", 1008),
            (WsCloseReason::ServerShutdown, "server-shutdown", 1001),
        ];
        assert_eq!(
            WsCloseReason::ALL,
            expected.map(|(reason, _, _)| reason),
            "the closed reason set and its literal contract table must stay synchronized"
        );

        for (reason, token, close_code) in expected {
            let encoded = serde_json::to_value(reason).unwrap();
            assert_eq!(reason.as_str(), token);
            assert_eq!(reason.close_code(), close_code);
            assert_eq!(encoded, token);
            assert_eq!(WsCloseReason::parse(token), Some(reason));
            assert_eq!(
                serde_json::from_value::<WsCloseReason>(encoded).unwrap(),
                reason
            );

            let error =
                WsControlError::new(RequestId::new(), "host-test".to_string(), reason, None);
            assert_eq!(error.reason(), reason);
            assert_eq!(error.code(), reason.api_code());

            let mut mismatched = serde_json::to_value(&error).unwrap();
            mismatched["code"] = serde_json::json!(if reason == WsCloseReason::InvalidRequest {
                "internal-error"
            } else {
                "invalid-request"
            });
            assert!(serde_json::from_value::<WsControlError>(mismatched).is_err());
        }
        assert_eq!(WsCloseReason::parse("not-a-close-reason"), None);
    }
}
