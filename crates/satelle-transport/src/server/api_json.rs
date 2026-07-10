use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response};
use crate::contract::{ApiErrorCategory, ApiErrorCode, ApiRequestContract};
use axum::body::to_bytes;
use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::response::Response;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::error::Error;
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
        let limit = state.limits.json_body_bytes();
        // Always let the bounded reader consume through the limit. Rejecting
        // from Content-Length alone can reset an in-flight Windows upload
        // before the client receives Satelle's typed 413 response.
        let body = match to_bytes(request.into_body(), limit).await {
            Ok(body) => body,
            Err(error)
                if error
                    .source()
                    .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
            {
                return Err(payload_too_large(state, &authorized));
            }
            Err(_) => {
                return Err(invalid_request(
                    state,
                    &authorized,
                    "the request body could not be read",
                ));
            }
        };
        let probe: SchemaProbe = serde_json::from_slice(&body).map_err(|_| {
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
        let decoded = serde_json::from_slice(&body).map_err(|_| {
            invalid_request(
                state,
                &authorized,
                "the request body does not match the operation contract",
            )
        })?;
        Ok(Self(decoded))
    }
}

#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: String,
}

fn has_json_content_type(headers: &axum::http::HeaderMap) -> bool {
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

fn payload_too_large(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            code: ApiErrorCode::PayloadTooLarge,
            category: ApiErrorCategory::Capacity,
            retryable: false,
            message: "the request body exceeds the advertised JSON body limit",
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
