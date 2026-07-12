use super::{
    ApiFailure, DaemonState, PeerAddress, api_error_response, header_request_id, security_headers,
};
use crate::contract::{ApiErrorCategory, ApiErrorCode, RequestId};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_LENGTH, COOKIE, TRANSFER_ENCODING};
use axum::middleware::Next;
use axum::response::Response;
use satelle_host::{ApiBearerToken, ApiPrincipal, ApiScopes, MutationAuthority};
use std::net::IpAddr;
use std::sync::Arc;

pub(super) const EXPECTED_HOST_IDENTITY_HEADER: &str = "satelle-expected-host-identity";
pub(super) const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
pub(super) const REQUEST_ID_HEADER: &str = "satelle-request-id";

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
        .get::<ConnectInfo<PeerAddress>>()
        .map_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), |peer| {
            peer.0.0.ip()
        });
    if state.failed_auth_limit.is_blocked(peer_ip) {
        return api_error_response(
            request_id,
            None,
            ApiFailure {
                status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                code: ApiErrorCode::RateLimited,
                category: ApiErrorCategory::RateLimit,
                retryable: true,
                message: "too many failed authentication attempts",
                details: None,
            },
        );
    }

    let token = match bearer_token(request.headers()) {
        Ok(token) => token,
        Err(()) => {
            state.failed_auth_limit.record_failure(peer_ip);
            return authentication_failed(request_id);
        }
    };
    let service = Arc::clone(&state.service);
    let principal =
        match tokio::task::spawn_blocking(move || service.authenticate_api_token(&token)).await {
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

    if !state
        .authenticated_limit
        .allow(principal.principal_ref().to_string())
    {
        return rate_limited(&state, &request_id, "authenticated");
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
        return api_error_response(
            valid_request_id,
            Some(state.host_identity.clone()),
            ApiFailure {
                status: axum::http::StatusCode::CONFLICT,
                code: ApiErrorCode::HostIdentityMismatch,
                category: ApiErrorCategory::Conflict,
                retryable: false,
                message: "the observed Host Identity does not match the expected Host Identity",
                details: Some(serde_json::json!({
                    "expected_host_identity": expected_identity,
                    "observed_host_identity": state.host_identity,
                })),
            },
        );
    }
    request.extensions_mut().insert(AuthorizedRequest {
        request_id: valid_request_id,
        request_id_was_supplied,
        principal,
    });
    security_headers(next.run(request).await)
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
    let Some(authorized) = request.extensions().get::<AuthorizedRequest>() else {
        return missing_authorization_context();
    };
    if request.uri().query().is_some() || read_has_body_or_cookie(&request) {
        return invalid_read_shape(
            &state,
            authorized,
            "this read request does not accept query parameters, cookies, or a body",
        );
    }
    next.run(request).await
}

pub(super) async fn require_query_read(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(authorized) = request.extensions().get::<AuthorizedRequest>() else {
        return missing_authorization_context();
    };
    if read_has_body_or_cookie(&request) {
        return invalid_read_shape(
            &state,
            authorized,
            "this query read does not accept cookies or a body",
        );
    }
    next.run(request).await
}

fn read_has_body_or_cookie(request: &Request) -> bool {
    request.headers().contains_key(COOKIE)
        || request
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
    if !state
        .control_limit
        .allow(authorized.principal().principal_ref().to_string())
    {
        return rate_limited(&state, authorized.request_id(), "control");
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

fn rate_limited(state: &DaemonState, request_id: &RequestId, scope: &'static str) -> Response {
    api_error_response(
        request_id.clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: axum::http::StatusCode::TOO_MANY_REQUESTS,
            code: ApiErrorCode::RateLimited,
            category: ApiErrorCategory::RateLimit,
            retryable: true,
            message: match scope {
                "control" => "the API Principal exceeded the control request limit",
                _ => "the API Principal exceeded the read request limit",
            },
            details: Some(serde_json::json!({"retry_after_ms": 60_000})),
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
