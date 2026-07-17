use super::{
    ApiFailure, DaemonState, api_error_response, header_request_id, listener::ConnectionContext,
    security_headers,
};
use crate::contract::{
    ApiErrorCategory, ApiErrorCode, PROTOCOL_VERSION, PROTOCOL_VERSION_HEADER, RequestId,
};
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, TRANSFER_ENCODING};
use axum::middleware::Next;
use axum::response::Response;
use percent_encoding::percent_decode_str;
use satelle_host::{
    ApiBearerToken, ApiPrincipal, ApiScopes, MutationAuthority, contains_api_bearer_token,
};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub(super) const EXPECTED_HOST_IDENTITY_HEADER: &str = "satelle-expected-host-identity";
pub(super) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
pub(super) const REQUEST_ID_HEADER: &str = "satelle-request-id";
const MAX_PERCENT_DECODE_LAYERS: usize = 8;
const REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) fn expected_host_identity_matches(
    headers: &axum::http::HeaderMap,
    host_identity: &str,
) -> bool {
    single_header(headers, EXPECTED_HOST_IDENTITY_HEADER) == Some(host_identity)
}

#[derive(Clone)]
pub(super) struct AuthorizedRequest {
    request_id: RequestId,
    request_id_was_supplied: bool,
    principal: ApiPrincipal,
}

impl AuthorizedRequest {
    pub(super) fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub(super) const fn request_id_was_supplied(&self) -> bool {
        self.request_id_was_supplied
    }

    pub(super) const fn principal(&self) -> &ApiPrincipal {
        &self.principal
    }
}

pub(super) async fn authorize(
    State(state): State<Arc<DaemonState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let supplied_request_id = header_request_id(request.headers());
    let request_id = supplied_request_id.clone().unwrap_or_default();
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<ConnectionContext>>()
        .map_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), |peer| {
            peer.0.peer_ip()
        });
    if let Some(retry_after) = state.failed_auth_limit.retry_after(peer_ip) {
        return rate_limited_response(
            request_id,
            None,
            "too many failed authentication attempts",
            retry_after,
        );
    }

    let token = match bearer_token(request.headers()) {
        Ok(token) => token,
        Err(()) => {
            state.failed_auth_limit.record_failure(peer_ip);
            return authentication_failed(request_id);
        }
    };
    let pending_setup_self_activation = request.method() == axum::http::Method::POST
        && request.uri().path() == format!("/v1/setup/api-token/{}/activate", token.token_id());
    let service = Arc::clone(&state.service);
    let principal =
        match tokio::task::spawn_blocking(move || match service.authenticate_api_token(&token)? {
            Some(principal) => Ok(Some(principal)),
            None if pending_setup_self_activation => {
                service.authenticate_pending_setup_api_token(&token)
            }
            None => Ok(None),
        })
        .await
        {
            Ok(Ok(Some(principal))) => principal,
            Ok(Ok(None)) => {
                state.failed_auth_limit.record_failure(peer_ip);
                return authentication_failed(request_id);
            }
            Ok(Err(_)) | Err(_) => {
                return api_error_response(
                    request_id,
                    None,
                    ApiFailure {
                        status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        code: ApiErrorCode::InternalError,
                        category: ApiErrorCategory::Internal,
                        retryable: false,
                        message: "the Host Daemon could not authenticate this request",
                        details: None,
                    },
                );
            }
        };

    if let Some(retry_after) = state
        .authenticated_limit
        .admit(principal.principal_ref().to_string())
    {
        return rate_limited_response(
            request_id,
            Some(state.host_identity.clone()),
            "the API Principal exceeded the authenticated request limit",
            retry_after,
        );
    }

    let request_id_was_supplied = supplied_request_id.is_some();
    let valid_request_id = match supplied_request_id {
        Some(request_id) => request_id,
        None if !request.headers().contains_key(REQUEST_ID_HEADER) => request_id,
        None => {
            return api_error_response(
                request_id,
                Some(state.host_identity.clone()),
                ApiFailure {
                    status: axum::http::StatusCode::BAD_REQUEST,
                    code: ApiErrorCode::InvalidRequest,
                    category: ApiErrorCategory::InvalidRequest,
                    retryable: false,
                    message: "Satelle-Request-Id must contain one canonical UUIDv7",
                    details: None,
                },
            );
        }
    };
    let has_disallowed_bearer_carrier = request_has_disallowed_bearer_token(&request);
    let expected_identity = single_header(request.headers(), EXPECTED_HOST_IDENTITY_HEADER);
    let Some(expected_identity) = expected_identity else {
        return api_error_response(
            valid_request_id,
            Some(state.host_identity.clone()),
            ApiFailure {
                status: axum::http::StatusCode::BAD_REQUEST,
                code: ApiErrorCode::InvalidRequest,
                category: ApiErrorCategory::InvalidRequest,
                retryable: false,
                message: "Satelle-Expected-Host-Identity is required",
                details: None,
            },
        );
    };
    if expected_identity != state.host_identity {
        let details = if encoded_text_has_disallowed_bearer_carrier(expected_identity) {
            serde_json::json!({
                "observed_host_identity": state.host_identity,
            })
        } else {
            serde_json::json!({
                "expected_host_identity": expected_identity,
                "observed_host_identity": state.host_identity,
            })
        };
        return api_error_response(
            valid_request_id,
            Some(state.host_identity.clone()),
            ApiFailure {
                status: axum::http::StatusCode::CONFLICT,
                code: ApiErrorCode::HostIdentityMismatch,
                category: ApiErrorCategory::Conflict,
                retryable: false,
                message: "the observed Host Identity does not match the expected Host Identity",
                details: Some(details),
            },
        );
    }
    if has_disallowed_bearer_carrier {
        return disallowed_bearer_token_carrier(
            Some(state.host_identity.clone()),
            valid_request_id,
        );
    }
    request.extensions_mut().insert(AuthorizedRequest {
        request_id: valid_request_id,
        request_id_was_supplied,
        principal,
    });
    security_headers(next.run(request).await)
}

fn request_has_disallowed_bearer_token(request: &Request) -> bool {
    encoded_text_has_disallowed_bearer_carrier(&request.uri().to_string())
        || headers_have_disallowed_bearer_carrier(request.headers(), true)
}

pub(super) fn trailers_have_disallowed_bearer_carrier(trailers: &axum::http::HeaderMap) -> bool {
    headers_have_disallowed_bearer_carrier(trailers, false)
}

fn headers_have_disallowed_bearer_carrier(
    headers: &axum::http::HeaderMap,
    allow_authorization: bool,
) -> bool {
    headers.iter().any(|(name, value)| {
        contains_api_bearer_token(name.as_str())
            || (!allow_authorization || name != AUTHORIZATION)
                && encoded_text_has_disallowed_bearer_carrier(&String::from_utf8_lossy(
                    value.as_bytes(),
                ))
    })
}

fn encoded_text_has_disallowed_bearer_carrier(value: &str) -> bool {
    if contains_api_bearer_token(value) {
        return true;
    }
    let first = percent_decode_str(value).decode_utf8_lossy();
    if first.as_ref() == value {
        return false;
    }
    let mut decoded = first.into_owned();
    for _ in 1..MAX_PERCENT_DECODE_LAYERS {
        if contains_api_bearer_token(&decoded) {
            return true;
        }
        // Continue to a fixed point because a downstream decoder can expose
        // another percent-encoded layer.
        let next = percent_decode_str(&decoded)
            .decode_utf8_lossy()
            .into_owned();
        if next == decoded {
            return false;
        }
        decoded = next;
    }
    if contains_api_bearer_token(&decoded) {
        return true;
    }
    // Deeply nested encoding is itself disallowed. Failing closed keeps the
    // unauthenticated liveness boundary at constant work per input byte.
    percent_decode_str(&decoded).decode_utf8_lossy().as_ref() != decoded
}

pub(super) fn json_contains_bearer_token(value: &Value) -> bool {
    match value {
        Value::String(value) => contains_api_bearer_token(value),
        Value::Array(values) => values.iter().any(json_contains_bearer_token),
        Value::Object(values) => values.iter().any(|(key, value)| {
            contains_api_bearer_token(key) || json_contains_bearer_token(value)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

pub(super) fn disallowed_bearer_token_carrier(
    host_identity: Option<String>,
    request_id: RequestId,
) -> Response {
    api_error_response(
        request_id,
        host_identity,
        ApiFailure {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "bearer tokens are accepted only through the Authorization header",
            details: None,
        },
    )
}

pub(super) async fn reject_public_bearer_carriers(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    if request_has_disallowed_bearer_token(&request) {
        let request_id = header_request_id(request.headers()).unwrap_or_default();
        return disallowed_bearer_token_carrier(None, request_id);
    }
    let request_id = header_request_id(request.headers()).unwrap_or_default();
    let has_json_content_type = super::api_json::has_json_content_type(request.headers());
    let is_supported_method = request.method() == axum::http::Method::GET;
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        REQUEST_BODY_READ_TIMEOUT,
        super::api_json::read_bounded_body(body, state.limits.json_body_bytes()),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(super::api_json::BoundedBodyError::TooLarge)) => {
            return public_body_failure(
                request_id,
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                ApiErrorCode::PayloadTooLarge,
                ApiErrorCategory::Capacity,
                "the request body exceeds the advertised JSON body limit",
            );
        }
        Ok(Err(super::api_json::BoundedBodyError::Read)) => {
            return public_body_failure(
                request_id,
                axum::http::StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the liveness request body could not be read",
            );
        }
        Err(_) => {
            return public_body_failure(
                request_id,
                axum::http::StatusCode::REQUEST_TIMEOUT,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the liveness request body exceeded its read deadline",
            );
        }
    };
    if body
        .trailers
        .as_ref()
        .is_some_and(trailers_have_disallowed_bearer_carrier)
        || contains_api_bearer_token(&String::from_utf8_lossy(&body.bytes))
    {
        return disallowed_bearer_token_carrier(None, request_id);
    }
    // An empty body with an explicit JSON content type is still a normal
    // liveness probe. Parse only actual JSON payload bytes.
    if has_json_content_type && !body.bytes.is_empty() {
        match super::api_json::parse_json_value(&body.bytes) {
            Ok(value) if json_contains_bearer_token(&value) => {
                return disallowed_bearer_token_carrier(None, request_id);
            }
            Ok(_) => {}
            Err(_) if is_supported_method => {
                return public_body_failure(
                    request_id,
                    axum::http::StatusCode::BAD_REQUEST,
                    ApiErrorCode::InvalidRequest,
                    ApiErrorCategory::InvalidRequest,
                    "the liveness request body must be valid JSON",
                );
            }
            Err(_) => {}
        }
    }
    let request = Request::from_parts(parts, Body::from(body.bytes));
    security_headers(next.run(request).await)
}

fn public_body_failure(
    request_id: RequestId,
    status: axum::http::StatusCode,
    code: ApiErrorCode,
    category: ApiErrorCategory,
    message: &'static str,
) -> Response {
    api_error_response(
        request_id,
        None,
        ApiFailure {
            status,
            code,
            category,
            retryable: false,
            message,
            details: None,
        },
    )
}

pub(super) async fn require_read(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(authorized) = request.extensions().get::<AuthorizedRequest>() else {
        return missing_authorization_context();
    };
    if !authorized.principal().scopes().allows(ApiScopes::READ) {
        return insufficient_scope(&state, authorized, "read");
    }
    next.run(request).await
}

pub(super) async fn require_empty_read(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    let request = match validate_read_shape(
        &state,
        request,
        true,
        "this read request does not accept query parameters, cookies, or a body",
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    next.run(request).await
}

pub(super) async fn require_query_read(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    let request = match validate_read_shape(
        &state,
        request,
        false,
        "this query read does not accept cookies or a body",
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    next.run(request).await
}

pub(super) async fn require_empty_setup_mutation(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(authorized) = request.extensions().get::<AuthorizedRequest>().cloned() else {
        return missing_authorization_context();
    };

    let request = match read_empty_body(&state, request).await {
        Ok(request) => request,
        Err(EmptyBodyFailure::TooLarge) => {
            return empty_setup_body_failure(
                &state,
                &authorized,
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                ApiErrorCode::PayloadTooLarge,
                ApiErrorCategory::Capacity,
                "the request body exceeds the advertised JSON body limit",
            );
        }
        Err(EmptyBodyFailure::Read) => {
            return empty_setup_body_failure(
                &state,
                &authorized,
                axum::http::StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the setup token request body could not be read",
            );
        }
        Err(EmptyBodyFailure::Timeout) => {
            return empty_setup_body_failure(
                &state,
                &authorized,
                axum::http::StatusCode::REQUEST_TIMEOUT,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the setup token request body exceeded its read deadline",
            );
        }
        Err(EmptyBodyFailure::DisallowedBearer) => {
            return disallowed_bearer_token_carrier(
                Some(state.host_identity.clone()),
                authorized.request_id().clone(),
            );
        }
        Err(EmptyBodyFailure::NonEmpty) => {
            return empty_setup_body_failure(
                &state,
                &authorized,
                axum::http::StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "setup token mutations do not accept a request body",
            );
        }
    };

    next.run(request).await
}

fn empty_setup_body_failure(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    status: axum::http::StatusCode,
    code: ApiErrorCode,
    category: ApiErrorCategory,
    message: &'static str,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status,
            code,
            category,
            retryable: false,
            message,
            details: None,
        },
    )
}

async fn validate_read_shape(
    state: &DaemonState,
    request: Request,
    reject_query: bool,
    message: &'static str,
) -> Result<Request, Response> {
    let Some(authorized) = request.extensions().get::<AuthorizedRequest>().cloned() else {
        return Err(missing_authorization_context());
    };
    if (reject_query && request.uri().query().is_some())
        || request.headers().contains_key(COOKIE)
        || request_declares_body(&request)
    {
        return Err(invalid_read_shape(state, &authorized, message));
    }

    read_empty_body(state, request)
        .await
        .map_err(|_| invalid_read_shape(state, &authorized, message))
}

enum EmptyBodyFailure {
    TooLarge,
    Read,
    Timeout,
    DisallowedBearer,
    NonEmpty,
}

/// Reads a bodyless route through one bounded path. HTTP/2 can carry data or
/// trailers without HTTP/1 framing headers, so header inspection is not enough.
async fn read_empty_body(
    state: &DaemonState,
    request: Request,
) -> Result<Request, EmptyBodyFailure> {
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        REQUEST_BODY_READ_TIMEOUT,
        super::api_json::read_bounded_body(body, state.limits.json_body_bytes()),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(super::api_json::BoundedBodyError::TooLarge)) => {
            return Err(EmptyBodyFailure::TooLarge);
        }
        Ok(Err(super::api_json::BoundedBodyError::Read)) => {
            return Err(EmptyBodyFailure::Read);
        }
        Err(_) => return Err(EmptyBodyFailure::Timeout),
    };
    if body
        .trailers
        .as_ref()
        .is_some_and(trailers_have_disallowed_bearer_carrier)
        || contains_api_bearer_token(&String::from_utf8_lossy(&body.bytes))
    {
        return Err(EmptyBodyFailure::DisallowedBearer);
    }
    if !body.bytes.is_empty() || body.trailers.is_some() {
        return Err(EmptyBodyFailure::NonEmpty);
    }
    Ok(Request::from_parts(parts, Body::from(body.bytes)))
}

fn request_declares_body(request: &Request) -> bool {
    request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value != "0")
        || request.headers().contains_key(TRANSFER_ENCODING)
}

fn invalid_read_shape(
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

pub(super) async fn require_control(
    State(state): State<Arc<DaemonState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(authorized) = request.extensions().get::<AuthorizedRequest>().cloned() else {
        return missing_authorization_context();
    };
    if !authorized.principal().scopes().allows(ApiScopes::CONTROL) {
        return insufficient_scope(&state, &authorized, "control");
    }
    if let Err(failure) = validate_protocol_version(request.headers()) {
        return incompatible_protocol(&state, &authorized, failure);
    }
    if request.uri().query().is_some() || request.headers().contains_key(COOKIE) {
        return api_error_response(
            authorized.request_id().clone(),
            Some(state.host_identity.clone()),
            ApiFailure {
                status: axum::http::StatusCode::BAD_REQUEST,
                code: ApiErrorCode::InvalidRequest,
                category: ApiErrorCategory::InvalidRequest,
                retryable: false,
                message: "this mutation does not accept query parameters or cookies",
                details: None,
            },
        );
    }
    if let Some(retry_after) = state
        .control_limit
        .admit(authorized.principal().principal_ref().to_string())
    {
        return rate_limited_response(
            authorized.request_id().clone(),
            Some(state.host_identity.clone()),
            "the API Principal exceeded the control request limit",
            retry_after,
        );
    }
    let Some(idempotency_key) = single_header(request.headers(), IDEMPOTENCY_KEY_HEADER) else {
        return invalid_idempotency_key(&state, &authorized);
    };
    let authority =
        match MutationAuthority::new(authorized.principal().clone(), idempotency_key.to_string()) {
            Ok(authority) => authority,
            Err(_) => return invalid_idempotency_key(&state, &authorized),
        };
    request.extensions_mut().insert(authority);
    next.run(request).await
}

enum ProtocolVersionFailure {
    Missing,
    Malformed,
    Duplicate,
    Unsupported(String),
}

impl ProtocolVersionFailure {
    const fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Duplicate => "duplicate",
            Self::Unsupported(_) => "unsupported",
        }
    }

    fn received_version(&self) -> Option<&str> {
        match self {
            Self::Missing | Self::Malformed | Self::Duplicate => None,
            Self::Unsupported(value) => Some(value),
        }
    }
}

fn validate_protocol_version(
    headers: &axum::http::HeaderMap,
) -> Result<(), ProtocolVersionFailure> {
    let mut values = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(ProtocolVersionFailure::Missing);
    };
    if values.next().is_some() {
        return Err(ProtocolVersionFailure::Duplicate);
    }
    let value = value
        .to_str()
        .map_err(|_| ProtocolVersionFailure::Malformed)?;
    if value.contains(',') {
        return Err(ProtocolVersionFailure::Duplicate);
    }
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProtocolVersionFailure::Malformed);
    }
    if value != PROTOCOL_VERSION {
        return Err(ProtocolVersionFailure::Unsupported(value.to_string()));
    }
    Ok(())
}

fn incompatible_protocol(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    failure: ProtocolVersionFailure,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::UPGRADE_REQUIRED,
            code: ApiErrorCode::IncompatibleProtocol,
            category: ApiErrorCategory::Compatibility,
            retryable: false,
            message: "the CLI and Host Daemon protocol versions are incompatible",
            details: Some(serde_json::json!({
                "reason": failure.reason(),
                "supported_versions": [PROTOCOL_VERSION],
                "received_version": failure.received_version(),
            })),
        },
    )
}

fn invalid_idempotency_key(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "Idempotency-Key must contain one supported non-empty key",
            details: None,
        },
    )
}

fn insufficient_scope(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    scope: &'static str,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::FORBIDDEN,
            code: ApiErrorCode::AuthorizationInsufficientScope,
            category: ApiErrorCategory::Authorization,
            retryable: false,
            message: match scope {
                "control" => "the API Principal does not have control scope",
                _ => "the API Principal does not have read scope",
            },
            details: None,
        },
    )
}

fn rate_limited_response(
    request_id: RequestId,
    host_identity: Option<String>,
    message: &'static str,
    retry_after: std::time::Duration,
) -> Response {
    api_error_response(
        request_id,
        host_identity,
        ApiFailure {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            code: ApiErrorCode::RateLimited,
            category: ApiErrorCategory::RateLimit,
            retryable: true,
            message,
            details: Some(serde_json::json!({
                "retry_after_ms": super::retry_after_ms(retry_after)
            })),
        },
    )
}

fn missing_authorization_context() -> Response {
    api_error_response(
        RequestId::new(),
        None,
        ApiFailure {
            status: axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            code: ApiErrorCode::InternalError,
            category: ApiErrorCategory::Internal,
            retryable: false,
            message: "the Host Daemon authorization context is unavailable",
            details: None,
        },
    )
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<ApiBearerToken, ()> {
    let values = headers.get_all(AUTHORIZATION);
    let mut values = values.iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next().ok_or(())?;
    let token = parts.next().ok_or(())?;
    if !scheme.eq_ignore_ascii_case("bearer") || parts.next().is_some() {
        return Err(());
    }
    ApiBearerToken::parse(token).map_err(|_| ())
}

fn single_header<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

fn authentication_failed(request_id: RequestId) -> Response {
    api_error_response(
        request_id,
        None,
        ApiFailure {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: ApiErrorCode::AuthenticationFailed,
            category: ApiErrorCategory::Authentication,
            retryable: false,
            message: "authentication failed",
            details: None,
        },
    )
}
