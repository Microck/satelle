use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response};
use crate::contract::{ApiErrorCategory, ApiErrorCode, ApiRequestContract};
use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Request};
use axum::http::HeaderMap;
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use http_body_util::{BodyExt as _, LengthLimitError, Limited};
use serde::Deserialize;
use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;
use std::sync::Arc;

pub(super) struct ApiJson<T>(pub(super) T);

impl<T> FromRequest<Arc<DaemonState>> for ApiJson<T>
where
    T: DeserializeOwned + ApiRequestContract,
{
    type Rejection = Response;

    async fn from_request(
        request: Request,
        state: &Arc<DaemonState>,
    ) -> Result<Self, Self::Rejection> {
        let authorized = request
            .extensions()
            .get::<AuthorizedRequest>()
            .cloned()
            .ok_or_else(internal_context_error)?;
        if !has_json_content_type(request.headers()) {
            return Err(api_error_response(
                authorized.request_id().clone(),
                Some(state.host_identity.clone()),
                ApiFailure {
                    status: axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    code: ApiErrorCode::UnsupportedContentType,
                    category: ApiErrorCategory::InvalidRequest,
                    retryable: false,
                    message: "Content-Type must be application/json with optional UTF-8 charset",
                    details: None,
                },
            ));
        }
        let limit = state
            .limits
            .json_body_bytes()
            .checked_add(T::MAX_BASE64_BODY_ALLOWANCE)
            .ok_or_else(internal_context_error)?;
        // Always let the bounded reader consume through the limit. Rejecting
        // from Content-Length alone can reset an in-flight Windows upload
        // before the client receives Satelle's typed 413 response.
        let body = match read_bounded_body(request.into_body(), limit).await {
            Ok(body) => body,
            Err(BoundedBodyError::TooLarge) => {
                return Err(payload_too_large(
                    state,
                    &authorized,
                    "the request body exceeds the advertised JSON body limit",
                ));
            }
            Err(BoundedBodyError::Read) => {
                return Err(invalid_request(
                    state,
                    &authorized,
                    "the request body could not be read",
                ));
            }
        };
        if body
            .trailers
            .as_ref()
            .is_some_and(super::auth::trailers_have_disallowed_bearer_carrier)
        {
            return Err(super::auth::disallowed_bearer_token_carrier(
                Some(state.host_identity.clone()),
                authorized.request_id().clone(),
            ));
        }
        let value = parse_json_value(&body.bytes).map_err(|_| {
            invalid_request(state, &authorized, "the request body must be valid JSON")
        })?;
        if super::auth::json_contains_bearer_token(&value) {
            return Err(invalid_request(
                state,
                &authorized,
                "bearer tokens are not accepted in JSON request bodies",
            ));
        }
        let probe: SchemaProbe = serde_json::from_value(value.clone()).map_err(|_| {
            invalid_request(state, &authorized, "the request body must be valid JSON")
        })?;
        if probe.schema_version != T::SCHEMA_VERSION {
            return Err(api_error_response(
                authorized.request_id().clone(),
                Some(state.host_identity.clone()),
                ApiFailure {
                    status: axum::http::StatusCode::BAD_REQUEST,
                    code: ApiErrorCode::UnsupportedSchema,
                    category: ApiErrorCategory::InvalidRequest,
                    retryable: false,
                    message: "the request schema_version is unsupported",
                    details: None,
                },
            ));
        }
        if T::exceeds_attachment_limit(&value, state.capabilities.image_attachments()) {
            return Err(payload_too_large(
                state,
                &authorized,
                "the request exceeds the advertised attachment limit",
            ));
        }
        let non_attachment_bytes = body
            .bytes
            .len()
            .saturating_sub(T::attachment_data_base64_bytes(&value));
        if non_attachment_bytes > state.limits.json_body_bytes() {
            return Err(payload_too_large(
                state,
                &authorized,
                "the request body exceeds the advertised JSON body limit",
            ));
        }
        let decoded = serde_json::from_value(value).map_err(|_| {
            invalid_request(
                state,
                &authorized,
                "the request body does not match the operation contract",
            )
        })?;
        Ok(Self(decoded))
    }
}

pub(super) struct BoundedBody {
    pub(super) bytes: Bytes,
    pub(super) trailers: Option<HeaderMap>,
}

pub(super) enum BoundedBodyError {
    TooLarge,
    Read,
}

/// Collects data and trailers together so security checks cannot lose fields
/// that arrive after the final body chunk.
pub(super) async fn read_bounded_body(
    body: Body,
    limit: usize,
) -> Result<BoundedBody, BoundedBodyError> {
    let collected = Limited::new(body, limit).collect().await.map_err(|error| {
        if error.downcast_ref::<LengthLimitError>().is_some() {
            BoundedBodyError::TooLarge
        } else {
            BoundedBodyError::Read
        }
    })?;
    let trailers = collected.trailers().cloned();
    Ok(BoundedBody {
        bytes: collected.to_bytes(),
        trailers,
    })
}

/// Parses JSON without losing an earlier value behind a duplicate object key.
/// Carrier scanning must inspect exactly the data the caller supplied.
pub(super) fn parse_json_value(input: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = UniqueJsonValue.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct UniqueJsonValue;

impl<'de> DeserializeSeed<'de> for UniqueJsonValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueJsonValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(UniqueJsonValue)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            values.insert(key, object.next_value_seed(UniqueJsonValue)?);
        }
        Ok(Value::Object(values))
    }
}

#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: String,
}

pub(super) fn has_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    parts.all(|parameter| {
        parameter.split_once('=').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("charset")
                && value.trim().eq_ignore_ascii_case("utf-8")
        })
    })
}

fn payload_too_large(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    message: &'static str,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            code: ApiErrorCode::PayloadTooLarge,
            category: ApiErrorCategory::Capacity,
            retryable: false,
            message,
            details: None,
        },
    )
}

fn invalid_request(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    message: &'static str,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message,
            details: None,
        },
    )
}

fn internal_context_error() -> Response {
    api_error_response(
        crate::RequestId::new(),
        None,
        ApiFailure {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: ApiErrorCode::InternalError,
            category: ApiErrorCategory::Internal,
            retryable: false,
            message: "the Host Daemon request context is unavailable",
            details: None,
        },
    )
}
