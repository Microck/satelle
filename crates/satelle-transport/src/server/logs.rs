use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response, authenticated_json_response, host_error};
use crate::contract::{ApiErrorCategory, ApiErrorCode, LogsPageResponse};
use axum::extract::{Extension, FromRequestParts, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use satelle_host::LogPageQuery;
use std::sync::Arc;

pub(super) async fn get_logs(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    LogsQuery(query): LogsQuery,
) -> Response {
    let service = Arc::clone(&state.service);
    let page = match tokio::task::spawn_blocking(move || service.daemon_log_page(&query)).await {
        Ok(Ok(page)) => page,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = LogsPageResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        page,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) struct LogsQuery(LogPageQuery);

impl FromRequestParts<Arc<DaemonState>> for LogsQuery {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<DaemonState>,
    ) -> Result<Self, Self::Rejection> {
        let authorized = parts
            .extensions
            .get::<AuthorizedRequest>()
            .cloned()
            .ok_or_else(missing_authorization_context)?;
        Query::<LogPageQuery>::from_request_parts(parts, state)
            .await
            .map(|Query(query)| Self(query))
            .map_err(|_| invalid_query(state, &authorized))
    }
}

fn invalid_query(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message: "the logs query does not match the v1 contract",
            details: None,
        },
    )
}

fn missing_authorization_context() -> Response {
    api_error_response(
        crate::RequestId::new(),
        None,
        ApiFailure {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ApiErrorCode::InternalError,
            category: ApiErrorCategory::Internal,
            retryable: false,
            message: "the Host Daemon request context is unavailable",
            details: None,
        },
    )
}
