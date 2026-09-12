use super::api_json::ApiJson;
use super::auth::AuthorizedRequest;
use super::{
    ApiFailure, DaemonState, api_error_response, authenticated_json_bytes_response,
    authenticated_json_response, host_error,
};
use crate::contract::{
    AdmissionCancellationResponse, ApiErrorCategory, ApiErrorCode,
    DesktopSnapshotAcknowledgeRequest, DesktopSnapshotAcknowledgeResponse,
    DesktopSnapshotCaptureRequest, DesktopSnapshotCaptureResponse, RawProtocolAcknowledgeRequest,
    RawProtocolAcknowledgeResponse, RawProtocolDownloadResponse, RawSubprocessBeginRequest,
    RawSubprocessBeginResponse, RawSubprocessPrepareRequest, RawSubprocessPrepareResponse,
    RequestId, SessionResponse, StopRequest, StopResponse, TaskArtifactsResponse, TurnRequest,
    TurnRequestParts,
};
use axum::extract::{Extension, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use satelle_core::{SatelleError, SessionId, TurnId};
use satelle_host::{
    AdmissionCancellationResult, ApiScopes, MutationAuthority, TurnIntent, TurnIntentError,
};
use std::sync::Arc;

pub(super) async fn create_session(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<TurnRequest>,
) -> Response {
    if let Some(response) = raw_protocol_scope_failure(&state, &authorized, &request) {
        return response;
    }
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
    if let Some(response) = raw_protocol_scope_failure(&state, &authorized, &request) {
        return response;
    }
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

fn raw_protocol_scope_failure(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    request: &TurnRequest,
) -> Option<Response> {
    if request.raw_protocol_capture().is_some()
        && !authorized
            .principal()
            .scopes()
            .allows(ApiScopes::DIAGNOSTICS_SENSITIVE)
    {
        Some(super::auth::insufficient_scope(
            state,
            authorized,
            "diagnostics:sensitive",
        ))
    } else {
        None
    }
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

pub(super) async fn get_task_artifacts(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    SessionPath(session_id): SessionPath,
) -> Response {
    let service = Arc::clone(&state.service);
    let artifacts = match host_call(&state, &authorized, move || {
        service.task_artifacts(&session_id)
    })
    .await
    {
        Ok(artifacts) => artifacts,
        Err(response) => return response,
    };
    authenticated_json_response(
        StatusCode::OK,
        &TaskArtifactsResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            artifacts.session_id().clone(),
            artifacts.plan().to_string(),
            artifacts.worklog().to_string(),
            artifacts.goal().to_string(),
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn get_raw_protocol_export(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    TurnPath(turn_id): TurnPath,
) -> Response {
    let principal_ref = authorized.principal().principal_ref().to_string();
    let request_id = authorized.request_id().clone();
    let host_identity = state.host_identity.clone();
    let service = Arc::clone(&state.service);
    let body = match host_call(&state, &authorized, move || {
        let artifact = service.raw_protocol_export(&principal_ref, &turn_id)?;
        serde_json::to_vec(&RawProtocolDownloadResponse::new(
            request_id,
            host_identity,
            artifact,
        ))
        .map_err(|_| {
            SatelleError::raw_diagnostics_failure(
                satelle_core::sensitive_diagnostics::RawDiagnosticFailure::ExportFailed,
                "the Host Daemon could not encode the raw protocol export",
            )
        })
    })
    .await
    {
        Ok(body) => body,
        Err(response) => return response,
    };
    authenticated_json_bytes_response(
        StatusCode::OK,
        body,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn begin_raw_subprocess_export(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    ApiJson(request): ApiJson<RawSubprocessBeginRequest>,
) -> Response {
    if uuid::Uuid::parse_str(request.invocation_id()).is_err() || request.source_host().is_empty() {
        return request_error(
            &state,
            &authorized,
            "raw subprocess export identity is invalid",
        );
    }
    let manifest = satelle_core::sensitive_diagnostics::RawSubprocessManifest::new(
        request.source_host(),
        state.host_identity.clone(),
        request.command(),
        request.invocation_id(),
    );
    let principal_ref = authorized.principal().principal_ref().to_string();
    let service = Arc::clone(&state.service);
    let stored_manifest = manifest.clone();
    if let Err(response) = host_call(&state, &authorized, move || {
        service.begin_raw_subprocess_export(&principal_ref, &stored_manifest)
    })
    .await
    {
        return response;
    }
    authenticated_json_response(
        StatusCode::OK,
        &RawSubprocessBeginResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            manifest,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn capture_desktop_snapshot(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    ApiJson(request): ApiJson<DesktopSnapshotCaptureRequest>,
) -> Response {
    if request.source_host().is_empty()
        || request.desktop_binding().is_empty()
        || request.desktop_session_identity().is_empty()
    {
        return request_error(&state, &authorized, "desktop snapshot target is invalid");
    }
    let principal_ref = authorized.principal().principal_ref().to_string();
    let source_host = request.source_host().to_string();
    let desktop_binding = request.desktop_binding().to_string();
    let desktop_session_identity = request.desktop_session_identity().to_string();
    let service = Arc::clone(&state.service);
    let artifact = match host_call(&state, &authorized, move || {
        service.capture_desktop_snapshot(
            &principal_ref,
            &source_host,
            &desktop_binding,
            &desktop_session_identity,
        )
    })
    .await
    {
        Ok(artifact) => artifact,
        Err(response) => return response,
    };
    authenticated_json_response(
        StatusCode::OK,
        &DesktopSnapshotCaptureResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            artifact,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn acknowledge_desktop_snapshot(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(snapshot_id): Path<String>,
    ApiJson(request): ApiJson<DesktopSnapshotAcknowledgeRequest>,
) -> Response {
    if uuid::Uuid::parse_str(&snapshot_id).is_err() {
        return request_error(&state, &authorized, "desktop snapshot identity is invalid");
    }
    let principal_ref = authorized.principal().principal_ref().to_string();
    let outcome = request.outcome();
    let service = Arc::clone(&state.service);
    if let Err(response) = host_call(&state, &authorized, move || {
        service.acknowledge_desktop_snapshot(&principal_ref, &snapshot_id, outcome)
    })
    .await
    {
        return response;
    }
    authenticated_json_response(
        StatusCode::OK,
        &DesktopSnapshotAcknowledgeResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            outcome,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn prepare_raw_subprocess_export(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(invocation_id): Path<String>,
    ApiJson(request): ApiJson<RawSubprocessPrepareRequest>,
) -> Response {
    if uuid::Uuid::parse_str(&invocation_id).is_err() {
        return request_error(
            &state,
            &authorized,
            "raw subprocess export identity is invalid",
        );
    }
    let artifact_byte_size = request.artifact_byte_size();
    if artifact_byte_size > satelle_core::sensitive_diagnostics::MAX_RAW_PROTOCOL_BYTES {
        return request_error(
            &state,
            &authorized,
            "raw subprocess export exceeds the maximum artifact size",
        );
    }
    let service = Arc::clone(&state.service);
    if let Err(response) = host_call(&state, &authorized, move || {
        service.prepare_raw_subprocess_export(&invocation_id, artifact_byte_size)
    })
    .await
    {
        return response;
    }
    authenticated_json_response(
        StatusCode::OK,
        &RawSubprocessPrepareResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            artifact_byte_size,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn acknowledge_raw_subprocess_export(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(invocation_id): Path<String>,
    ApiJson(request): ApiJson<RawProtocolAcknowledgeRequest>,
) -> Response {
    if uuid::Uuid::parse_str(&invocation_id).is_err() {
        return request_error(
            &state,
            &authorized,
            "raw subprocess export identity is invalid",
        );
    }
    let principal_ref = authorized.principal().principal_ref().to_string();
    let outcome = request.outcome();
    let service = Arc::clone(&state.service);
    if let Err(response) = host_call(&state, &authorized, move || {
        service.acknowledge_raw_subprocess_export(&principal_ref, &invocation_id, outcome)
    })
    .await
    {
        return response;
    }
    authenticated_json_response(
        StatusCode::OK,
        &RawProtocolAcknowledgeResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            outcome,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn acknowledge_raw_protocol_export(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    TurnPath(turn_id): TurnPath,
    ApiJson(request): ApiJson<RawProtocolAcknowledgeRequest>,
) -> Response {
    let principal_ref = authorized.principal().principal_ref().to_string();
    let outcome = request.outcome();
    let service = Arc::clone(&state.service);
    if let Err(response) = host_call(&state, &authorized, move || {
        service.acknowledge_raw_protocol_export(&principal_ref, &turn_id, outcome)
    })
    .await
    {
        return response;
    }
    authenticated_json_response(
        StatusCode::OK,
        &RawProtocolAcknowledgeResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            outcome,
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
pub(super) struct TurnPath(TurnId);

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

impl FromRequestParts<Arc<DaemonState>> for TurnPath {
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
        let Path(raw_turn_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| invalid_turn_id(state, &authorized))?;
        TurnId::parse(&raw_turn_id)
            .map(Self)
            .map_err(|_| invalid_turn_id(state, &authorized))
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
        model_from_project,
        provider_from_project,
        refresh_provider_smoke_test,
        experimental_provider_computer_use,
        attachments,
        turn_execution_timeout_ms,
        raw_protocol,
    } = request.into_parts();
    let attachments = attachments
        .into_iter()
        .map(|attachment| match attachment {
            crate::ImageAttachment::Upload {
                media_type,
                size_bytes,
                sha256,
                data_base64,
            } => satelle_host::AttachmentInput::upload(media_type, size_bytes, sha256, data_base64),
            crate::ImageAttachment::HostFile { path } => {
                satelle_host::AttachmentInput::host_file(path)
            }
        })
        .collect();

    TurnIntent::new(prompt, execution_mode)
        .and_then(|intent| {
            intent.with_provider_intent(model, provider, refresh_provider_smoke_test)
        })
        .map(|intent| {
            intent.with_project_selection_provenance(model_from_project, provider_from_project)
        })
        .map(|intent| {
            intent.with_experimental_provider_computer_use(experimental_provider_computer_use)
        })
        .and_then(|intent| intent.with_turn_execution_timeout_ms(turn_execution_timeout_ms))
        .and_then(|intent| intent.with_attachments(attachments))
        .and_then(|intent| {
            intent.with_raw_protocol_capture(raw_protocol.map(|capture| capture.into_source_host()))
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
        TurnIntentError::InvalidTurnExecutionTimeout => {
            "Turn execution timeout must be a whole number of seconds from 1s through 24h"
        }
        TurnIntentError::InvalidAttachments => "image attachments failed integrity validation",
        TurnIntentError::InvalidRawProtocolSourceHost => {
            "raw protocol source Host alias is invalid"
        }
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

fn invalid_turn_id(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    request_error(
        state,
        authorized,
        "the path must contain one canonical Satelle Turn ID",
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
