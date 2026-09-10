use super::{
    ApiFailure, ApiJson, AuthorizedRequest, DaemonState, api_error_response,
    authenticated_json_response, host_error,
};
use crate::contract::{
    ApiErrorCategory, ApiErrorCode, ApiTokenIssueRequest, ApiTokenResponse, ApiTokenRevokeRequest,
    ApiTokenRotateRequest,
};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use satelle_host::{
    ApiTokenMutation, ApiTokenMutationOutcome, ApiTokenRejection, MutationAuthority,
};
use std::sync::Arc;

pub(super) async fn issue(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    ApiJson(request): ApiJson<ApiTokenIssueRequest>,
) -> Response {
    let Some(mutation) = request.into_mutation() else {
        return invalid_request(
            &state,
            &authorized,
            "token issuance requires nonempty known scopes and an optional UTC expiry",
        );
    };
    execute(state, authorized, authority, mutation).await
}

pub(super) async fn rotate(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path(token_id): Path<String>,
    ApiJson(request): ApiJson<ApiTokenRotateRequest>,
) -> Response {
    execute(
        state,
        authorized,
        authority,
        ApiTokenMutation::Rotate {
            token_id,
            expected_credential_revision: request.expected_credential_revision,
        },
    )
    .await
}

pub(super) async fn revoke(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path(token_id): Path<String>,
    ApiJson(request): ApiJson<ApiTokenRevokeRequest>,
) -> Response {
    execute(
        state,
        authorized,
        authority,
        ApiTokenMutation::Revoke {
            token_id,
            expected_credential_revision: request.expected_credential_revision,
        },
    )
    .await
}

async fn execute(
    state: Arc<DaemonState>,
    authorized: AuthorizedRequest,
    authority: MutationAuthority,
    mutation: ApiTokenMutation,
) -> Response {
    if let ApiTokenMutation::Rotate {
        expected_credential_revision,
        ..
    }
    | ApiTokenMutation::Revoke {
        expected_credential_revision,
        ..
    } = &mutation
        && (*expected_credential_revision == 0
            || i64::try_from(*expected_credential_revision).is_err())
    {
        return invalid_request(
            &state,
            &authorized,
            "expected_credential_revision must be a positive signed 64-bit integer",
        );
    }
    let issuing = matches!(mutation, ApiTokenMutation::Issue { .. });
    let returns_secret = !matches!(mutation, ApiTokenMutation::Revoke { .. });
    let service = Arc::clone(&state.service);
    let mutation_result =
        match tokio::task::spawn_blocking(move || service.mutate_api_token(&mutation, &authority))
            .await
        {
            Ok(Ok(mutation_result)) => mutation_result,
            Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
            Err(_) => return host_error::task_failure(&state, &authorized),
        };
    let metadata = match mutation_result.outcome {
        ApiTokenMutationOutcome::Completed(metadata) => metadata,
        ApiTokenMutationOutcome::Rejected(rejection) => {
            return rejected(&state, &authorized, rejection);
        }
    };
    if returns_secret && mutation_result.bearer_token.is_none() {
        return secret_not_replayable(&state, &authorized, &metadata);
    }
    let secret = mutation_result
        .bearer_token
        .as_ref()
        .map(|token| token.expose());
    authenticated_json_response(
        if issuing {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        &ApiTokenResponse::new(
            authorized.request_id(),
            &state.host_identity,
            &metadata,
            secret.as_ref().map(|secret| secret.as_str()),
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) fn secret_not_replayable(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    metadata: &impl serde::Serialize,
) -> Response {
    api_error_response(
        authorized.request_id().clone(),
        Some(state.host_identity.clone()),
        ApiFailure {
            status: StatusCode::CONFLICT,
            code: ApiErrorCode::TokenSecretNotReplayable,
            category: ApiErrorCategory::Conflict,
            retryable: false,
            message: "this operation completed, but its token secret is returned only once; if the secret was lost, revoke the token (or abort a pending setup token) and issue a new one with a new idempotency key",
            details: Some(serde_json::json!({ "token": metadata })),
        },
    )
}

fn rejected(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    rejection: ApiTokenRejection,
) -> Response {
    let (status, code, category, message) = match rejection {
        ApiTokenRejection::AuthenticationFailed => {
            return super::auth::authentication_failed(authorized.request_id().clone());
        }
        ApiTokenRejection::InsufficientScope => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::AuthorizationInsufficientScope,
            ApiErrorCategory::Authorization,
            "token management requires a durable admin credential",
        ),
        ApiTokenRejection::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::ApiTokenNotFound,
            ApiErrorCategory::NotFound,
            "the API token does not exist",
        ),
        ApiTokenRejection::StateConflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::ApiTokenStateConflict,
            ApiErrorCategory::Conflict,
            "the token revision changed or the token cannot perform this operation in its current state",
        ),
        ApiTokenRejection::InvalidExpiry => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            ApiErrorCategory::InvalidRequest,
            "the token expiry must be in the future",
        ),
    };
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

fn invalid_request(
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
