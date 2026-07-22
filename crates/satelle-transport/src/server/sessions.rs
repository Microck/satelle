use super::api_json::ApiJson;
use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response, authenticated_json_response, host_error};
use crate::contract::{
    AdmissionCancellationResponse, ApiErrorCategory, ApiErrorCode, RequestId, SessionResponse,
    StopRequest, StopResponse, TurnRequest, TurnRequestParts,
};
use axum::extract::{Extension, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use satelle_core::{SatelleError, SessionId, TurnId};
use satelle_host::{AdmissionCancellationResult, MutationAuthority, TurnIntent, TurnIntentError};
use std::sync::Arc;

pub(super) async fn create_session(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<TurnRequest>,
) -> Response {
    let intent = match turn_intent(request, state.capabilities.image_attachments()) {
        Ok(intent) => intent,
        Err(error) => return invalid_turn_request(&state, &authorized, error),
    };
    let action = match admission_action(&headers) {
        Ok(action) => action,
        Err(()) => return request_error(&state, &authorized, "invalid admission action"),
    };
    let service = Arc::clone(&state.service);
    if action == AdmissionAction::Cancel {
        let cancellation = match host_call(&state, &authorized, move || {
            service.cancel_run_admission(&intent, &authority)
        })
        .await
        {
            Ok(cancellation) => cancellation,
            Err(response) => return response,
        };
        return cancellation_response(&state, &authorized, cancellation);
    }
    let session = match host_call(&state, &authorized, move || {
        service
            .admit_run(&intent, &authority)
            .map_err(admission_wire_error)
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
    headers: HeaderMap,
    SessionPath(session_id): SessionPath,
    ApiJson(request): ApiJson<TurnRequest>,
) -> Response {
    let intent = match turn_intent(request, state.capabilities.image_attachments()) {
        Ok(intent) => intent,
        Err(error) => return invalid_turn_request(&state, &authorized, error),
    };
    let action = match admission_action(&headers) {
        Ok(action) => action,
        Err(()) => return request_error(&state, &authorized, "invalid admission action"),
    };
    let service = Arc::clone(&state.service);
    if action == AdmissionAction::Cancel {
        let cancellation = match host_call(&state, &authorized, move || {
            service.cancel_steer_admission(&session_id, &intent, &authority)
        })
        .await
        {
            Ok(cancellation) => cancellation,
            Err(response) => return response,
        };
        return cancellation_response(&state, &authorized, cancellation);
    }
    let session = match host_call(&state, &authorized, move || {
        service
            .admit_steer(&session_id, &intent, &authority)
            .map_err(admission_wire_error)
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

const ADMISSION_ACTION_HEADER: &str = "satelle-admission-action";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionAction {
    Admit,
    Cancel,
}

fn admission_action(headers: &HeaderMap) -> Result<AdmissionAction, ()> {
    let values = headers.get_all(ADMISSION_ACTION_HEADER);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Ok(AdmissionAction::Admit);
    };
    if values.next().is_some() || value.as_bytes() != b"cancel" {
        return Err(());
    }
    Ok(AdmissionAction::Cancel)
}

fn cancellation_response(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    result: AdmissionCancellationResult,
) -> Response {
    let response = match result {
        AdmissionCancellationResult::Cancelled => AdmissionCancellationResponse::cancelled(
            authorized.request_id().clone(),
            state.host_identity.clone(),
        ),
        AdmissionCancellationResult::RecoveryPending => {
            AdmissionCancellationResponse::recovery_pending(
                authorized.request_id().clone(),
                state.host_identity.clone(),
            )
        }
        AdmissionCancellationResult::Admitted { session, turn_id } => {
            AdmissionCancellationResponse::admitted(
                authorized.request_id().clone(),
                state.host_identity.clone(),
                session.session_id().clone(),
                turn_id,
            )
        }
    };
    authenticated_json_response(
        StatusCode::OK,
        &response,
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
    headers: HeaderMap,
    SessionPath(session_id): SessionPath,
    ApiJson(_request): ApiJson<StopRequest>,
) -> Response {
    let expected_turn_id = match expected_turn_id(&headers) {
        Ok(expected_turn_id) => expected_turn_id,
        Err(()) => return request_error(&state, &authorized, "invalid expected Turn ID"),
    };
    let service = Arc::clone(&state.service);
    let admission = match host_call(&state, &authorized, move || {
        match expected_turn_id.as_ref() {
            Some(turn_id) => service.admit_stop_expected_turn(&session_id, turn_id, &authority),
            None => service.admit_stop(&session_id, &authority),
        }
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

const EXPECTED_TURN_ID_HEADER: &str = "satelle-expected-turn-id";

fn expected_turn_id(headers: &HeaderMap) -> Result<Option<TurnId>, ()> {
    let values = headers.get_all(EXPECTED_TURN_ID_HEADER);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.as_bytes().contains(&b',') {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    TurnId::parse(value).map(Some).map_err(|_| ())
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

fn admission_wire_error(error: SatelleError) -> SatelleError {
    if error.code == satelle_core::ErrorCode::Interrupted {
        SatelleError::state_conflict()
    } else {
        error
    }
}

fn turn_intent(
    request: TurnRequest,
    image_attachments_supported: bool,
) -> Result<TurnIntent, TurnIntentError> {
    if !image_attachments_supported && !request.attachments().is_empty() {
        return Err(TurnIntentError::InvalidAttachments);
    }
    let TurnRequestParts {
        prompt,
        execution_mode,
        model,
        provider,
        experimental_provider_computer_use,
        refresh_provider_smoke_test,
        attachments,
        turn_execution_timeout_ms,
    } = request.into_parts();
    let attachments = attachments
        .into_iter()
        .map(|attachment| {
            satelle_host::AttachmentUpload::new(
                attachment.media_type(),
                attachment.size_bytes(),
                attachment.sha256(),
                attachment.data_base64(),
            )
        })
        .collect();

    TurnIntent::new(prompt, execution_mode)
        .and_then(|intent| {
            intent.with_provider_intent(
                model,
                provider,
                experimental_provider_computer_use,
                refresh_provider_smoke_test,
            )
        })
        .and_then(|intent| intent.with_turn_execution_timeout_ms(turn_execution_timeout_ms))
        .and_then(|intent| intent.with_attachments(attachments))
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
        TurnIntentError::InvalidTurnExecutionTimeout => {
            "Turn execution timeout must be a whole number of seconds from 1s through 24h"
        }
        TurnIntentError::InvalidAttachments => "image attachments failed integrity validation",
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

#[cfg(test)]
mod expected_turn_header_tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn expected_turn_header_is_an_optional_canonical_singleton() {
        assert_eq!(expected_turn_id(&HeaderMap::new()), Ok(None));

        let turn_id = TurnId::new();
        let mut valid = HeaderMap::new();
        valid.insert(
            EXPECTED_TURN_ID_HEADER,
            HeaderValue::from_str(turn_id.as_str()).expect("canonical Turn header"),
        );
        assert_eq!(expected_turn_id(&valid), Ok(Some(turn_id.clone())));

        let mut malformed = HeaderMap::new();
        malformed.insert(
            EXPECTED_TURN_ID_HEADER,
            HeaderValue::from_static("not-a-turn"),
        );
        assert_eq!(expected_turn_id(&malformed), Err(()));

        valid.append(
            EXPECTED_TURN_ID_HEADER,
            HeaderValue::from_str(turn_id.as_str()).expect("duplicate Turn header"),
        );
        assert_eq!(expected_turn_id(&valid), Err(()));
    }
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

#[cfg(test)]
mod admission_action_tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn absent_header_preserves_admission_compatibility() {
        assert_eq!(
            admission_action(&HeaderMap::new()),
            Ok(AdmissionAction::Admit)
        );
    }

    #[test]
    fn only_one_exact_cancel_header_is_accepted() {
        let mut headers = HeaderMap::new();
        headers.insert(ADMISSION_ACTION_HEADER, HeaderValue::from_static("cancel"));
        assert_eq!(admission_action(&headers), Ok(AdmissionAction::Cancel));

        headers.append(ADMISSION_ACTION_HEADER, HeaderValue::from_static("cancel"));
        assert_eq!(admission_action(&headers), Err(()));

        headers.insert(ADMISSION_ACTION_HEADER, HeaderValue::from_static("Cancel"));
        assert_eq!(admission_action(&headers), Err(()));
    }

    #[test]
    fn interrupted_admission_maps_to_wire_safe_conflict() {
        let mapped = admission_wire_error(SatelleError::interrupted_attached_command());
        assert_eq!(mapped.code, satelle_core::ErrorCode::StateConflict);

        let unchanged = admission_wire_error(SatelleError::invalid_usage("invalid admission"));
        assert_eq!(unchanged.code, satelle_core::ErrorCode::InvalidUsage);
    }
}
