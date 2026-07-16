use super::api_json::ApiJson;
use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response, authenticated_json_response, host_error};
use crate::contract::{
    ApiErrorCategory, ApiErrorCode, RequestId, SessionResponse, StopRequest, StopResponse,
    TurnRequest, TurnRequestParts,
};
use axum::extract::{Extension, FromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::Response;
use satelle_core::{SatelleError, SessionId};
use satelle_host::{MutationAuthority, TurnIntent, TurnIntentError};
use std::sync::Arc;

pub(super) async fn create_session(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    ApiJson(request): ApiJson<TurnRequest>,
) -> Response {
    let intent = match turn_intent(request) {
        Ok(intent) => intent,
        Err(error) => return invalid_turn_request(&state, &authorized, error),
    };
    let service = Arc::clone(&state.service);
    let session = match host_call(&state, &authorized, move || {
        service.admit_run(&intent, &authority)
    })
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    authenticated_json_response(
        StatusCode::ACCEPTED,
        &SessionResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            session,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn create_turn(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    SessionPath(session_id): SessionPath,
    ApiJson(request): ApiJson<TurnRequest>,
) -> Response {
    let intent = match turn_intent(request) {
        Ok(intent) => intent,
        Err(error) => return invalid_turn_request(&state, &authorized, error),
    };
    let service = Arc::clone(&state.service);
    let session = match host_call(&state, &authorized, move || {
        service.admit_steer(&session_id, &intent, &authority)
    })
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    authenticated_json_response(
        StatusCode::ACCEPTED,
        &SessionResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            session,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn get_session(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    SessionPath(session_id): SessionPath,
) -> Response {
    let service = Arc::clone(&state.service);
    let session = match host_call(&state, &authorized, move || {
        service.session_status(&session_id)
    })
    .await
    {
        Ok(session) => session,
        Err(response) => return response,
    };
    authenticated_json_response(
        StatusCode::OK,
        &SessionResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            session,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn stop_session(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    SessionPath(session_id): SessionPath,
    ApiJson(_request): ApiJson<StopRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let admission = match host_call(&state, &authorized, move || {
        service.admit_stop(&session_id, &authority)
    })
    .await
    {
        Ok(admission) => admission,
        Err(response) => return response,
    };
    let (result, session_revision, turn_revision) = admission.into_parts();
    let response = StopResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        result,
        session_revision,
        turn_revision,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) struct SessionPath(SessionId);

impl FromRequestParts<Arc<DaemonState>> for SessionPath {
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
        let Path(raw_session_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| invalid_session_id(state, &authorized))?;
        SessionId::parse(&raw_session_id)
            .map(Self)
            .map_err(|_| invalid_session_id(state, &authorized))
    }
}

async fn host_call<T, F>(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    operation: F,
) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, SatelleError> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(host_error::response(state, authorized, &error)),
        Err(_) => Err(host_error::task_failure(state, authorized)),
    }
}

fn turn_intent(request: TurnRequest) -> Result<TurnIntent, TurnIntentError> {
    let TurnRequestParts {
        prompt,
        execution_mode,
        model,
        provider,
        experimental_provider_computer_use,
        refresh_provider_smoke_test,
    } = request.into_parts();

    TurnIntent::new(prompt, execution_mode).and_then(|intent| {
        intent.with_provider_intent(
            model,
            provider,
            experimental_provider_computer_use,
            refresh_provider_smoke_test,
        )
    })
}

fn invalid_turn_request(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    error: TurnIntentError,
) -> Response {
    let message = match error {
        TurnIntentError::EmptyPrompt => "prompt must not be empty",
        TurnIntentError::InvalidModel => "model override is invalid",
        TurnIntentError::InvalidProvider => "provider override is invalid",
    };
    request_error(state, authorized, message)
}

fn invalid_session_id(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    request_error(
        state,
        authorized,
        "the path must contain one canonical Satelle Session ID",
    )
}

fn request_error(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    message: &'static str,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::BAD_REQUEST,
            code: ApiErrorCode::InvalidRequest,
            category: ApiErrorCategory::InvalidRequest,
            retryable: false,
            message,
            details: None,
        },
    )
}

fn missing_authorization_context() -> Response {
    api_error_response(
        RequestId::new(),
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
