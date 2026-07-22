use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response, authenticated_json_response, host_error};
use crate::contract::{
    ApiErrorCategory, ApiErrorCode, BootstrapMaintenanceResponse, DURABLE_SETUP_PENDING_TTL,
    DurableTokenActivationResponse, DurableTokenConfirmationResponse, DurableTokenIssuanceResponse,
};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use satelle_core::SatelleError;
use satelle_host::{ApiScopes, MutationAuthority, SetupOperationKind};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(super) struct SetupTokenIssuance {
    token_id: String,
    pending_expires_at: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum SetupTokenMutationOperation {
    Activate,
    Abort,
}

#[derive(Clone)]
pub(super) struct SetupTokenMutation {
    token_id: String,
}

enum SetupTokenMutationOutcome {
    Committed(SetupTokenMutation),
    Conflict,
    HostError(SatelleError),
    TaskFailure,
}

pub(super) async fn complete_bootstrap_maintenance(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(operation_id): Path<String>,
) -> Response {
    if !bootstrap_maintenance_principal_is_authorized(&authorized) {
        return bootstrap_maintenance_principal_required(&state, &authorized);
    }
    let service = Arc::clone(&state.service);
    let operation = operation_id.clone();
    match tokio::task::spawn_blocking(move || service.complete_bootstrap_maintenance(&operation))
        .await
    {
        Ok(Ok(())) => authenticated_json_response(
            StatusCode::OK,
            &BootstrapMaintenanceResponse::new(
                authorized.request_id().clone(),
                state.host_identity.clone(),
                operation_id,
            ),
            authorized.request_id(),
            &state.host_identity,
        ),
        Ok(Err(error)) => host_error::response(&state, &authorized, &error),
        Err(_) => host_error::task_failure(&state, &authorized),
    }
}

pub(super) async fn begin_bootstrap_maintenance(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path((operation_id, operation_kind)): Path<(String, String)>,
) -> Response {
    if !bootstrap_maintenance_principal_is_authorized(&authorized) {
        return bootstrap_maintenance_principal_required(&state, &authorized);
    }
    let operation_kind = match operation_kind.as_str() {
        "initial_setup" => SetupOperationKind::Setup,
        "missing_daemon_repair" => SetupOperationKind::Repair,
        "host_binary_replacement" => SetupOperationKind::HostUpdate,
        _ => {
            return host_error::response(
                &state,
                &authorized,
                &SatelleError::invalid_usage("invalid Bootstrap Lock operation kind"),
            );
        }
    };
    let service = Arc::clone(&state.service);
    let operation = operation_id.clone();
    match tokio::task::spawn_blocking(move || {
        service.acquire_bootstrap_maintenance(&operation, operation_kind)
    })
    .await
    {
        Ok(Ok(())) => authenticated_json_response(
            StatusCode::OK,
            &BootstrapMaintenanceResponse::new(
                authorized.request_id().clone(),
                state.host_identity.clone(),
                operation_id,
            ),
            authorized.request_id(),
            &state.host_identity,
        ),
        Ok(Err(error)) => host_error::response(&state, &authorized, &error),
        Err(_) => host_error::task_failure(&state, &authorized),
    }
}

pub(super) async fn issue_api_token(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
) -> Response {
    if !setup_principal_is_authorized(&authorized) {
        return bootstrap_required(&state, &authorized);
    }
    let replay_key = (
        authority.principal().token_id().to_string(),
        authority.idempotency_key().to_string(),
    );
    let operation_state = Arc::clone(&state);
    let issued = tokio::task::spawn_blocking(move || {
        let Ok(mut issuances) = operation_state.setup_issuances.lock() else {
            return Err(None);
        };
        if let Some(issuance) = issuances.get(&replay_key) {
            return Ok((issuance.clone(), None));
        }
        let pending_until = OffsetDateTime::now_utc() + DURABLE_SETUP_PENDING_TTL;
        let (token, principal) = operation_state
            .service
            .issue_pending_api_token(ApiScopes::CONTROL, pending_until)
            .map_err(Some)?;
        let Some(pending_expires_at) = principal
            .expires_at()
            .and_then(|expires_at| expires_at.format(&Rfc3339).ok())
        else {
            return Err(None);
        };
        let issuance = SetupTokenIssuance {
            token_id: principal.token_id().to_string(),
            pending_expires_at,
        };
        issuances.insert(replay_key, issuance.clone());
        Ok((issuance, Some(token.expose())))
    })
    .await;
    let (issuance, bearer_token): (SetupTokenIssuance, Option<Zeroizing<String>>) = match issued {
        Ok(Ok(issuance)) => issuance,
        Ok(Err(Some(error))) => return host_error::response(&state, &authorized, &error),
        Ok(Err(None)) | Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = DurableTokenIssuanceResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        issuance.token_id,
        bearer_token.map(|token| token.as_str().to_string()),
        issuance.pending_expires_at,
    );
    authenticated_json_response(
        StatusCode::CREATED,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn confirm_api_token(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let principal = authorized.principal();
    if !principal.is_durable_setup_active() || principal.scopes() != ApiScopes::CONTROL {
        return durable_setup_credential_required(&state, &authorized);
    }
    let response = DurableTokenConfirmationResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        principal.token_id().to_string(),
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn activate_api_token(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path(token_id): Path<String>,
) -> Response {
    if !setup_principal_can_activate(&authorized, &token_id) {
        return bootstrap_required(&state, &authorized);
    }
    match execute_setup_token_mutation(
        Arc::clone(&state),
        authority,
        token_id,
        SetupTokenMutationOperation::Activate,
    )
    .await
    {
        SetupTokenMutationOutcome::Committed(mutation) => {
            let response = DurableTokenActivationResponse::new(
                authorized.request_id().clone(),
                state.host_identity.clone(),
                mutation.token_id,
                true,
            );
            authenticated_json_response(
                StatusCode::OK,
                &response,
                authorized.request_id(),
                &state.host_identity,
            )
        }
        SetupTokenMutationOutcome::Conflict => idempotency_conflict(&state, &authorized),
        SetupTokenMutationOutcome::HostError(error) => {
            host_error::response(&state, &authorized, &error)
        }
        SetupTokenMutationOutcome::TaskFailure => host_error::task_failure(&state, &authorized),
    }
}

pub(super) async fn abort_api_token(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path(token_id): Path<String>,
) -> Response {
    if !setup_principal_is_authorized(&authorized) {
        return bootstrap_required(&state, &authorized);
    }
    match execute_setup_token_mutation(
        Arc::clone(&state),
        authority,
        token_id,
        SetupTokenMutationOperation::Abort,
    )
    .await
    {
        SetupTokenMutationOutcome::Committed(mutation) => {
            let response = DurableTokenActivationResponse::new(
                authorized.request_id().clone(),
                state.host_identity.clone(),
                mutation.token_id,
                false,
            );
            authenticated_json_response(
                StatusCode::OK,
                &response,
                authorized.request_id(),
                &state.host_identity,
            )
        }
        SetupTokenMutationOutcome::Conflict => idempotency_conflict(&state, &authorized),
        SetupTokenMutationOutcome::HostError(error) => {
            host_error::response(&state, &authorized, &error)
        }
        SetupTokenMutationOutcome::TaskFailure => host_error::task_failure(&state, &authorized),
    }
}

async fn execute_setup_token_mutation(
    state: Arc<DaemonState>,
    authority: MutationAuthority,
    token_id: String,
    operation: SetupTokenMutationOperation,
) -> SetupTokenMutationOutcome {
    let replay_key = (
        authority.principal().token_id().to_string(),
        operation,
        authority.idempotency_key().to_string(),
    );
    match tokio::task::spawn_blocking(move || {
        // Keep lookup, transition, and replay publication under one lock. Two
        // concurrent requests with the same key must never both execute.
        let Ok(mut mutations) = state.setup_mutations.lock() else {
            return SetupTokenMutationOutcome::TaskFailure;
        };
        if let Some(mutation) = mutations.get(&replay_key) {
            return if mutation.token_id == token_id {
                SetupTokenMutationOutcome::Committed(mutation.clone())
            } else {
                SetupTokenMutationOutcome::Conflict
            };
        }

        match operation {
            SetupTokenMutationOperation::Activate => {
                if let Err(error) = state.service.activate_api_token(&token_id) {
                    return SetupTokenMutationOutcome::HostError(error);
                }
            }
            SetupTokenMutationOperation::Abort => {
                if let Err(error) = state.service.abort_setup_api_token(&token_id) {
                    return SetupTokenMutationOutcome::HostError(error);
                }
            }
        }
        let mutation = SetupTokenMutation { token_id };
        mutations.insert(replay_key, mutation.clone());
        SetupTokenMutationOutcome::Committed(mutation)
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => SetupTokenMutationOutcome::TaskFailure,
    }
}

fn idempotency_conflict(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::IdempotencyKeyConflict,
            category: ApiErrorCategory::Conflict,
            retryable: false,
            message: "the idempotency key was already used for a different request",
            details: None,
        },
    )
}

fn bootstrap_required(state: &DaemonState, authorized: &AuthorizedRequest) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::FORBIDDEN,
            code: ApiErrorCode::AuthorizationInsufficientScope,
            category: ApiErrorCategory::Authorization,
            retryable: false,
            message: "durable setup credentials require an admin-scoped SSH bootstrap principal",
            details: None,
        },
    )
}

fn bootstrap_maintenance_principal_required(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::FORBIDDEN,
            code: ApiErrorCode::AuthorizationInsufficientScope,
            category: ApiErrorCategory::Authorization,
            retryable: false,
            message: "bootstrap maintenance requires an SSH bootstrap principal",
            details: None,
        },
    )
}

fn durable_setup_credential_required(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::FORBIDDEN,
            code: ApiErrorCode::AuthorizationInsufficientScope,
            category: ApiErrorCategory::Authorization,
            retryable: false,
            message: "the current credential is not an activated control-scoped setup credential",
            details: None,
        },
    )
}

fn setup_principal_is_authorized(authorized: &AuthorizedRequest) -> bool {
    authorized.principal().is_ssh_bootstrap()
        && authorized.principal().scopes().allows(ApiScopes::ADMIN)
}

// Bootstrap maintenance is an internal handoff capability, not part of the
// public Read/Control/Admin hierarchy. A process-local SSH bootstrap principal
// needs it even when the daemon exposes only read operations to that client.
fn bootstrap_maintenance_principal_is_authorized(authorized: &AuthorizedRequest) -> bool {
    authorized.principal().is_ssh_bootstrap()
}

fn setup_principal_can_activate(authorized: &AuthorizedRequest, token_id: &str) -> bool {
    let principal = authorized.principal();
    setup_principal_is_authorized(authorized)
        || (principal.token_id() == token_id
            && principal.scopes() == ApiScopes::CONTROL
            && (principal.is_durable_setup_pending() || principal.is_durable_setup_active()))
}
