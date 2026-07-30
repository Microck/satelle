use super::api_json::{ApiJson, BoundedBodyError, read_bounded_body};
use super::auth::{self, AuthorizedRequest};
use super::{ApiFailure, DaemonState, api_error_response, authenticated_json_response, host_error};
use crate::contract::{
    ApiErrorCategory, ApiErrorCode, BootstrapMaintenanceResponse, DURABLE_SETUP_PENDING_TTL,
    DurableTokenActivationResponse, DurableTokenConfirmationResponse, DurableTokenIssuanceResponse,
    NativeReadinessInvalidationRequest, NativeReadinessInvalidationResponse,
    PROVIDER_SECRET_UPLOAD_CONTENT_TYPE, PROVIDER_SECRET_UPLOAD_INFO,
    ProviderBindingAuthorizationRequest, ProviderBindingAuthorizationResponse,
    ProviderBindingDeletionResponse, ProviderDescriptorValidationRequest,
    ProviderDescriptorValidationResponse, ProviderSecretProvisioningMetadata,
    ProviderSecretProvisioningPreviewResponse, ProviderSecretProvisioningResponse,
    ProviderSecretUploadEnvelope, SetupRepairDecision, SetupRepairOperationKind,
    SetupRepairPlanAction, SetupRepairPlanRequest, SetupRepairPlanResponse,
    SetupRepairPostcondition, SetupRepairPreviousStatus, SetupRepairRunStatus,
    SetupVerificationRequest, SetupVerificationResponse, provider_secret_upload_aad,
};
use axum::extract::{Extension, Path, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use satelle_core::SatelleError;
use satelle_host::{ApiScopes, HostService, MutationAuthority, SetupOperationKind};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::{Zeroize, Zeroizing};

const MAX_PROVIDER_SECRET_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_SECRET_ENVELOPE_BYTES: usize = 96 * 1024;
const MAX_PENDING_PROVIDER_SECRET_UPLOADS: usize = 128;
const PROVIDER_SECRET_UPLOAD_TTL: time::Duration = time::Duration::minutes(5);

pub(super) struct PendingProviderSecretUpload {
    preview: ProviderSecretProvisioningPreviewResponse,
    metadata: ProviderSecretProvisioningMetadata,
    token_id: String,
    principal_ref: String,
    credential_revision: u64,
    idempotency_key: String,
    request_digest: [u8; 32],
    expires_at: OffsetDateTime,
    private_key: Zeroizing<Vec<u8>>,
}

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

pub(super) async fn plan_setup_repair(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(_authority): Extension<MutationAuthority>,
    ApiJson(request): ApiJson<SetupRepairPlanRequest>,
) -> Response {
    // The route's control-scope middleware is the authorization boundary.
    // Planning reads Host-owned ledger and live-probe state but does not grant
    // the persistent-service mutation capability used by apply handlers.
    let run_id = request.run_id().map(str::to_string);
    let probes = match request
        .probes()
        .iter()
        .map(|probe| {
            satelle_host::SetupRepairProbe::new(
                &probe.action_id,
                &probe.label,
                probe.retry_safe,
                match probe.postcondition {
                    SetupRepairPostcondition::Satisfied => {
                        satelle_host::SetupRepairPostcondition::Satisfied
                    }
                    SetupRepairPostcondition::Unsatisfied => {
                        satelle_host::SetupRepairPostcondition::Unsatisfied
                    }
                    SetupRepairPostcondition::Unknown => {
                        satelle_host::SetupRepairPostcondition::Unknown
                    }
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(probes) => probes,
        Err(error) => return host_error::response(&state, &authorized, &error),
    };
    let service = Arc::clone(&state.service);
    let plan = match tokio::task::spawn_blocking(move || {
        service.plan_setup_repair(None, run_id.as_deref(), &probes)
    })
    .await
    {
        Ok(Ok(plan)) => plan,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let selected_operation_kind = plan.selected_operation_kind().map(|kind| match kind {
        SetupOperationKind::Setup => SetupRepairOperationKind::Setup,
        SetupOperationKind::Repair => SetupRepairOperationKind::Repair,
        SetupOperationKind::HostUpdate => SetupRepairOperationKind::HostUpdate,
        SetupOperationKind::StorageMigration => SetupRepairOperationKind::StorageMigration,
        SetupOperationKind::ServiceStop => SetupRepairOperationKind::ServiceStop,
        SetupOperationKind::ServiceRestart => SetupRepairOperationKind::ServiceRestart,
    });
    let selected_run_status = plan.selected_run_status().map(|status| match status {
        satelle_host::SetupRunStatus::Running => SetupRepairRunStatus::Running,
        satelle_host::SetupRunStatus::Completed => SetupRepairRunStatus::Completed,
        satelle_host::SetupRunStatus::Failed => SetupRepairRunStatus::Failed,
        satelle_host::SetupRunStatus::PartialFailure => SetupRepairRunStatus::PartialFailure,
        satelle_host::SetupRunStatus::OutcomeUnknown => SetupRepairRunStatus::OutcomeUnknown,
    });
    let actions = plan
        .actions()
        .iter()
        .map(|action| SetupRepairPlanAction {
            action_id: action.action_id().to_string(),
            label: action.label().to_string(),
            decision: match action.decision() {
                satelle_host::SetupRepairDecision::NoActionRequired => {
                    SetupRepairDecision::NoActionRequired
                }
                satelle_host::SetupRepairDecision::RetryAutomatically => {
                    SetupRepairDecision::RetryAutomatically
                }
                satelle_host::SetupRepairDecision::OperatorActionRequired => {
                    SetupRepairDecision::OperatorActionRequired
                }
                satelle_host::SetupRepairDecision::ProbeRequired => {
                    SetupRepairDecision::ProbeRequired
                }
            },
            retry_safe: action.retry_safe(),
            previous_run_id: action.previous_run_id().map(str::to_string),
            previous_status: action.previous_status().map(|status| match status {
                satelle_host::SetupActionStatus::Planned => SetupRepairPreviousStatus::Planned,
                satelle_host::SetupActionStatus::Started => SetupRepairPreviousStatus::Started,
                satelle_host::SetupActionStatus::Completed => SetupRepairPreviousStatus::Completed,
                satelle_host::SetupActionStatus::Failed => SetupRepairPreviousStatus::Failed,
                satelle_host::SetupActionStatus::Skipped => SetupRepairPreviousStatus::Skipped,
                satelle_host::SetupActionStatus::OutcomeUnknown => {
                    SetupRepairPreviousStatus::OutcomeUnknown
                }
            }),
        })
        .collect();
    authenticated_json_response(
        StatusCode::OK,
        &SetupRepairPlanResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            selected_operation_kind,
            selected_run_status,
            actions,
        ),
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn verify_setup(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    ApiJson(request): ApiJson<SetupVerificationRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let model_alias = request.model_alias().map(str::to_string);
    let provider_alias = request.provider_alias().map(str::to_string);
    let model_from_project = request.model_from_project();
    let provider_from_project = request.provider_from_project();
    let experimental_provider_computer_use = request.experimental_provider_computer_use();
    let verification = match tokio::task::spawn_blocking(move || {
        service.verify_setup_idempotent(
            &authority,
            model_alias.as_deref(),
            provider_alias.as_deref(),
            model_from_project,
            provider_from_project,
            experimental_provider_computer_use,
        )
    })
    .await
    {
        Ok(Ok(verification)) => verification,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = SetupVerificationResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        verification,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn invalidate_native_readiness(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    ApiJson(request): ApiJson<NativeReadinessInvalidationRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let model_alias = request.model_alias().map(str::to_string);
    let provider_alias = request.provider_alias().map(str::to_string);
    let host_wide = request.scope() == NativeReadinessInvalidationScope::Host;
    let model_from_project = request.model_from_project();
    let provider_from_project = request.provider_from_project();
    let experimental_provider_computer_use = request.experimental_provider_computer_use();
    let deleted = match tokio::task::spawn_blocking(move || {
        service.invalidate_native_readiness_idempotent(
            &authority,
            host_wide,
            model_alias.as_deref(),
            provider_alias.as_deref(),
            (model_from_project, provider_from_project),
            experimental_provider_computer_use,
        )
    })
    .await
    {
        Ok(Ok(deleted)) => deleted,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = NativeReadinessInvalidationResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        deleted,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn validate_provider_descriptor(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path((provider_alias, model_alias)): Path<(String, String)>,
    ApiJson(request): ApiJson<ProviderDescriptorValidationRequest>,
) -> Response {
    let options = satelle_host::ProviderDescriptorValidationOptions::new(
        request.mode(),
        request.model_from_project(),
        request.provider_from_project(),
        request.experimental_provider_computer_use(),
    );
    let service = Arc::clone(&state.service);
    let validation = match tokio::task::spawn_blocking(move || {
        service.validate_provider_descriptor_idempotent(
            satelle_core::LOCAL_DEMO_HOST,
            &model_alias,
            &provider_alias,
            options,
            &authority,
        )
    })
    .await
    {
        Ok(Ok(validation)) => validation,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = ProviderDescriptorValidationResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        &validation,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn preview_provider_secret_provisioning(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    ApiJson(request): ApiJson<ProviderSecretProvisioningMetadata>,
) -> Response {
    let request_digest = match serde_json::to_vec(&request) {
        Ok(bytes) => Sha256::digest(bytes).into(),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let now = OffsetDateTime::now_utc();
    let replay = {
        let mut uploads = match state.provider_secret_uploads.lock() {
            Ok(uploads) => uploads,
            Err(_) => return host_error::task_failure(&state, &authorized),
        };
        uploads.retain(|_, pending| pending.expires_at > now);
        matching_pending_provider_secret_upload(
            &uploads,
            authorized.principal().token_id(),
            authorized.principal().principal_ref(),
            authorized.principal().credential_revision(),
            authority.idempotency_key(),
        )
        .map(|pending| (pending.request_digest, pending.preview.clone()))
    };
    if let Some((original_digest, original_response)) = replay {
        if original_digest != request_digest {
            return idempotency_conflict(&state, &authorized);
        }
        return replay_provider_secret_preview(&state, &authorized, &original_response);
    }

    let service = Arc::clone(&state.service);
    let authorization = request.authorization().clone();
    let preview_authority = authority.clone();
    let preview = match tokio::task::spawn_blocking(move || {
        service.preview_provider_secret_provisioning(
            satelle_core::LOCAL_DEMO_HOST,
            authorization,
            &preview_authority,
        )
    })
    .await
    {
        Ok(Ok(preview)) => preview,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let now = OffsetDateTime::now_utc();
    let expires_at = now + PROVIDER_SECRET_UPLOAD_TTL;
    let expires_at_text = match expires_at.format(&Rfc3339) {
        Ok(value) => value,
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let upload_id = crate::contract::RequestId::new().to_string();
    let keypair = crate::provider_secret_crypto::generate_server_keypair();
    let response = ProviderSecretProvisioningPreviewResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        preview.destination_kind().to_string(),
        preview.persistence_location_class().to_string(),
        preview.overwrite_behavior().to_string(),
        upload_id.clone(),
        crate::provider_secret_crypto::encode_canonical_base64(&keypair.public_key),
        expires_at_text,
    );
    let mut uploads = match state.provider_secret_uploads.lock() {
        Ok(uploads) => uploads,
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    uploads.retain(|_, pending| pending.expires_at > now);
    if let Some(pending) = matching_pending_provider_secret_upload(
        &uploads,
        authorized.principal().token_id(),
        authorized.principal().principal_ref(),
        authorized.principal().credential_revision(),
        authority.idempotency_key(),
    ) {
        if pending.request_digest != request_digest {
            return idempotency_conflict(&state, &authorized);
        }
        let original_response = pending.preview.clone();
        drop(uploads);
        return replay_provider_secret_preview(&state, &authorized, &original_response);
    }
    if uploads.len() >= MAX_PENDING_PROVIDER_SECRET_UPLOADS {
        return provider_secret_request_failure(
            &state,
            &authorized,
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            ApiErrorCategory::Conflict,
            "the Host has no provider-secret upload capacity",
        );
    }
    uploads.insert(
        upload_id,
        PendingProviderSecretUpload {
            preview: response.clone(),
            metadata: request,
            token_id: authorized.principal().token_id().to_string(),
            principal_ref: authorized.principal().principal_ref().to_string(),
            credential_revision: authorized.principal().credential_revision(),
            idempotency_key: authority.idempotency_key().to_string(),
            request_digest,
            expires_at,
            private_key: keypair.private_key,
        },
    );
    drop(uploads);
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

fn matching_pending_provider_secret_upload<'a>(
    uploads: &'a HashMap<String, PendingProviderSecretUpload>,
    token_id: &str,
    principal_ref: &str,
    credential_revision: u64,
    idempotency_key: &str,
) -> Option<&'a PendingProviderSecretUpload> {
    uploads.values().find(|pending| {
        pending.token_id == token_id
            && pending.principal_ref == principal_ref
            && pending.credential_revision == credential_revision
            && pending.idempotency_key == idempotency_key
    })
}

fn replay_provider_secret_preview(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    original: &ProviderSecretProvisioningPreviewResponse,
) -> Response {
    let response = ProviderSecretProvisioningPreviewResponse::new(
        authorized.request_id().clone(),
        original.host_identity().to_string(),
        original.destination_kind(),
        original.persistence_location_class(),
        original.overwrite_behavior(),
        original.upload_id(),
        original.recipient_public_key(),
        original.expires_at(),
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn provision_provider_secret(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    request: Request,
) -> Response {
    if let Err(failure) = require_provider_secret_content_type(request.headers()) {
        return api_error_response(
            authorized.request_id().clone(),
            Some(state.host_identity.clone()),
            failure,
        );
    }

    let body = match tokio::time::timeout(
        auth::REQUEST_BODY_READ_TIMEOUT,
        read_bounded_body(request.into_body(), MAX_PROVIDER_SECRET_ENVELOPE_BYTES),
    )
    .await
    {
        Ok(Ok(body)) if !body.bytes.is_empty() => body,
        Ok(Ok(_)) => {
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the provider secret body must not be empty",
            );
        }
        Ok(Err(BoundedBodyError::TooLarge)) => {
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::PAYLOAD_TOO_LARGE,
                ApiErrorCode::PayloadTooLarge,
                ApiErrorCategory::Capacity,
                "the provider secret body exceeds the accepted limit",
            );
        }
        Ok(Err(BoundedBodyError::Read)) => {
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the provider secret body could not be read",
            );
        }
        Err(_) => {
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::REQUEST_TIMEOUT,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the provider secret body was not received before the deadline",
            );
        }
    };
    if body
        .trailers
        .as_ref()
        .is_some_and(auth::trailers_have_disallowed_bearer_carrier)
    {
        return auth::disallowed_bearer_token_carrier(
            Some(state.host_identity.clone()),
            authorized.request_id().clone(),
        );
    }
    let envelope_digest = Sha256::digest(&body.bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let envelope: ProviderSecretUploadEnvelope = match serde_json::from_slice(&body.bytes) {
        Ok(envelope) => envelope,
        Err(_) => {
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the provider secret upload envelope is invalid",
            );
        }
    };
    let service = Arc::clone(&state.service);
    let replay_authorization = envelope.metadata().authorization().clone();
    let replay_overwrite_authorized = envelope.metadata().overwrite_authorized();
    let replay_envelope_digest = envelope_digest.clone();
    let replay_authority = authority.clone();
    let replay = match tokio::task::spawn_blocking(move || {
        service.replay_provider_secret_provisioning_idempotent(
            satelle_core::LOCAL_DEMO_HOST,
            replay_authorization,
            replay_overwrite_authorized,
            &replay_envelope_digest,
            &replay_authority,
        )
    })
    .await
    {
        Ok(Ok(replay)) => replay,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    if let Some(report) = replay {
        let response = ProviderSecretProvisioningResponse::new(
            authorized.request_id().clone(),
            state.host_identity.clone(),
            report.destination_kind().to_string(),
            report.overwritten(),
            report.validation_status(),
        );
        return authenticated_json_response(
            StatusCode::OK,
            &response,
            authorized.request_id(),
            &state.host_identity,
        );
    }

    // Removing the grant is the single-use claim. From this point every
    // outcome consumes it, including an invalid ciphertext.
    let pending = match state.provider_secret_uploads.lock() {
        Ok(mut uploads) => uploads.remove(envelope.upload_id()),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let Some(pending) = pending else {
        return provider_secret_request_failure(
            &state,
            &authorized,
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            ApiErrorCategory::Conflict,
            "the provider secret upload grant is unavailable",
        );
    };
    let now = OffsetDateTime::now_utc();
    if pending.expires_at <= now
        || pending.preview.host_identity() != state.host_identity
        || envelope.host_identity() != pending.preview.host_identity()
        || envelope.expires_at() != pending.preview.expires_at()
        || envelope.metadata() != &pending.metadata
        || pending.token_id != authorized.principal().token_id()
        || pending.principal_ref != authorized.principal().principal_ref()
        || pending.credential_revision != authorized.principal().credential_revision()
        || pending.idempotency_key != authority.idempotency_key()
    {
        return provider_secret_request_failure(
            &state,
            &authorized,
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            ApiErrorCategory::Conflict,
            "the provider secret upload grant does not match this request",
        );
    }
    let aad = match provider_secret_upload_aad(
        &pending.preview,
        &pending.metadata,
        &pending.token_id,
        &pending.idempotency_key,
    ) {
        Ok(aad) => aad,
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let encapsulated_key =
        match crate::provider_secret_crypto::decode_canonical_base64(envelope.encapsulated_key()) {
            Ok(value) => value,
            Err(_) => {
                return provider_secret_request_failure(
                    &state,
                    &authorized,
                    StatusCode::BAD_REQUEST,
                    ApiErrorCode::InvalidRequest,
                    ApiErrorCategory::InvalidRequest,
                    "the provider secret upload envelope is invalid",
                );
            }
        };
    let ciphertext =
        match crate::provider_secret_crypto::decode_canonical_base64(envelope.ciphertext()) {
            Ok(value) => value,
            Err(_) => {
                return provider_secret_request_failure(
                    &state,
                    &authorized,
                    StatusCode::BAD_REQUEST,
                    ApiErrorCode::InvalidRequest,
                    ApiErrorCategory::InvalidRequest,
                    "the provider secret upload envelope is invalid",
                );
            }
        };
    let mut secret_bytes = match crate::provider_secret_crypto::decrypt_provider_secret(
        pending.private_key.as_slice(),
        PROVIDER_SECRET_UPLOAD_INFO,
        aad.as_slice(),
        encapsulated_key.as_slice(),
        ciphertext.as_slice(),
    ) {
        Ok(secret) if !secret.is_empty() && secret.len() <= MAX_PROVIDER_SECRET_BYTES => secret,
        _ => {
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the provider secret upload envelope could not be opened",
            );
        }
    };
    let secret = match String::from_utf8(std::mem::take(&mut *secret_bytes)) {
        Ok(secret) => Zeroizing::new(secret),
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            return provider_secret_request_failure(
                &state,
                &authorized,
                StatusCode::BAD_REQUEST,
                ApiErrorCode::InvalidRequest,
                ApiErrorCategory::InvalidRequest,
                "the provider secret body must be valid UTF-8",
            );
        }
    };

    let service = Arc::clone(&state.service);
    let overwrite_authorized = pending.metadata.overwrite_authorized();
    let authorization = pending.metadata.into_authorization();
    let report = match tokio::task::spawn_blocking(move || {
        service.provision_provider_secret_idempotent(
            satelle_core::LOCAL_DEMO_HOST,
            authorization,
            secret,
            overwrite_authorized,
            &envelope_digest,
            &authority,
        )
    })
    .await
    {
        Ok(Ok(report)) => report,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = ProviderSecretProvisioningResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        report.destination_kind().to_string(),
        report.overwritten(),
        report.validation_status(),
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

fn require_provider_secret_content_type(headers: &HeaderMap) -> Result<(), ApiFailure> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let content_type = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(unsupported_provider_secret_content_type)?;
    if values.next().is_some() || content_type != PROVIDER_SECRET_UPLOAD_CONTENT_TYPE {
        return Err(unsupported_provider_secret_content_type());
    }
    Ok(())
}

fn unsupported_provider_secret_content_type() -> ApiFailure {
    ApiFailure {
        status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
        code: ApiErrorCode::UnsupportedContentType,
        category: ApiErrorCategory::InvalidRequest,
        retryable: false,
        message: "provider secrets require the encrypted provider-secret upload content type",
        details: None,
    }
}

fn provider_secret_request_failure(
    state: &DaemonState,
    authorized: &AuthorizedRequest,
    status: StatusCode,
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

pub(super) async fn authorize_provider_binding(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path((provider_alias, model_alias)): Path<(String, String)>,
    ApiJson(request): ApiJson<ProviderBindingAuthorizationRequest>,
) -> Response {
    let service = Arc::clone(&state.service);
    let authorization = request.into_authorization();
    let binding = match tokio::task::spawn_blocking(move || {
        service.authorize_provider_binding_idempotent(
            satelle_core::LOCAL_DEMO_HOST,
            &model_alias,
            &provider_alias,
            authorization,
            &authority,
        )
    })
    .await
    {
        Ok(Ok(binding)) => binding,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = ProviderBindingAuthorizationResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        binding,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
}

pub(super) async fn delete_provider_binding(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Extension(authority): Extension<MutationAuthority>,
    Path((provider_alias, model_alias)): Path<(String, String)>,
) -> Response {
    let service = Arc::clone(&state.service);
    let deleted = match tokio::task::spawn_blocking(move || {
        service.delete_provider_binding_idempotent(&model_alias, &provider_alias, &authority)
    })
    .await
    {
        Ok(Ok(deleted)) => deleted,
        Ok(Err(error)) => return host_error::response(&state, &authorized, &error),
        Err(_) => return host_error::task_failure(&state, &authorized),
    };
    let response = ProviderBindingDeletionResponse::new(
        authorized.request_id().clone(),
        state.host_identity.clone(),
        deleted,
    );
    authenticated_json_response(
        StatusCode::OK,
        &response,
        authorized.request_id(),
        &state.host_identity,
    )
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
    Path((operation_id, operation_kind, plan_kind)): Path<(String, String, String)>,
) -> Response {
    let operation_kind = match operation_kind.as_str() {
        "initial_setup" => SetupOperationKind::Setup,
        "missing_daemon_repair" => SetupOperationKind::Repair,
        "host_binary_replacement" => SetupOperationKind::HostUpdate,
        "service_stop" => SetupOperationKind::ServiceStop,
        "service_restart" => SetupOperationKind::ServiceRestart,
        _ => {
            return host_error::response(
                &state,
                &authorized,
                &SatelleError::invalid_usage("invalid Bootstrap Lock operation kind"),
            );
        }
    };
    let plan_kind = match satelle_host::BootstrapMaintenancePlanKind::parse(&plan_kind) {
        Ok(plan_kind) => plan_kind,
        Err(error) => return host_error::response(&state, &authorized, &error),
    };
    let authorized_for_plan = match plan_kind {
        satelle_host::BootstrapMaintenancePlanKind::OnDemandHandoff => {
            bootstrap_maintenance_principal_is_authorized(&authorized)
        }
        satelle_host::BootstrapMaintenancePlanKind::PersistentHostService
        | satelle_host::BootstrapMaintenancePlanKind::PersistentHostStop
        | satelle_host::BootstrapMaintenancePlanKind::PersistentHostRestart
        | satelle_host::BootstrapMaintenancePlanKind::HostUpdate
        | satelle_host::BootstrapMaintenancePlanKind::Repair => {
            persistent_service_maintenance_principal_is_authorized(&authorized)
        }
    };
    if !authorized_for_plan {
        return bootstrap_maintenance_principal_required(&state, &authorized);
    }
    let service = Arc::clone(&state.service);
    let operation = operation_id.clone();
    match tokio::task::spawn_blocking(move || {
        service.acquire_bootstrap_maintenance_plan(&operation, operation_kind, plan_kind)
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

pub(super) async fn start_maintenance_action(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path((operation_id, action_id)): Path<(String, String)>,
) -> Response {
    run_maintenance_transition(
        state,
        authorized,
        operation_id,
        move |service, operation| service.start_bootstrap_maintenance_action(operation, &action_id),
    )
    .await
}

pub(super) async fn complete_maintenance_action(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path((operation_id, action_id)): Path<(String, String)>,
) -> Response {
    run_maintenance_transition(
        state,
        authorized,
        operation_id,
        move |service, operation| {
            service.complete_bootstrap_maintenance_action(operation, &action_id)
        },
    )
    .await
}

pub(super) async fn skip_maintenance_action(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path((operation_id, action_id)): Path<(String, String)>,
) -> Response {
    run_maintenance_transition(
        state,
        authorized,
        operation_id,
        move |service, operation| service.skip_bootstrap_maintenance_action(operation, &action_id),
    )
    .await
}

pub(super) async fn fail_maintenance_action(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path((operation_id, action_id, failure_kind)): Path<(String, String, String)>,
) -> Response {
    run_maintenance_transition(
        state,
        authorized,
        operation_id,
        move |service, operation| {
            service.fail_bootstrap_maintenance_action(operation, &action_id, &failure_kind)
        },
    )
    .await
}

pub(super) async fn finish_maintenance_plan(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(operation_id): Path<String>,
) -> Response {
    run_maintenance_transition(state, authorized, operation_id, |service, operation| {
        service.finish_bootstrap_maintenance_plan(operation)
    })
    .await
}

pub(super) async fn run_maintenance_postcheck(
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path((operation_id, action_id)): Path<(String, String)>,
) -> Response {
    run_maintenance_transition(
        state,
        authorized,
        operation_id,
        move |service, operation| {
            service
                .run_bootstrap_maintenance_postcheck(operation, &action_id)
                .map(|_| ())
        },
    )
    .await
}

async fn run_maintenance_transition(
    state: Arc<DaemonState>,
    authorized: AuthorizedRequest,
    operation_id: String,
    transition: impl FnOnce(&HostService, &str) -> Result<(), SatelleError> + Send + 'static,
) -> Response {
    if !persistent_service_maintenance_principal_is_authorized(&authorized) {
        return bootstrap_maintenance_principal_required(&state, &authorized);
    }
    let service = Arc::clone(&state.service);
    let operation = operation_id.clone();
    match tokio::task::spawn_blocking(move || transition(&service, &operation)).await {
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

fn persistent_service_maintenance_principal_is_authorized(authorized: &AuthorizedRequest) -> bool {
    let principal = authorized.principal();
    (principal.is_ssh_bootstrap() && principal.scopes().allows(ApiScopes::ADMIN))
        || (principal.is_durable_setup_active() && principal.scopes() == ApiScopes::CONTROL)
}

fn setup_principal_can_activate(authorized: &AuthorizedRequest, token_id: &str) -> bool {
    let principal = authorized.principal();
    setup_principal_is_authorized(authorized)
        || (principal.token_id() == token_id
            && principal.scopes() == ApiScopes::CONTROL
            && (principal.is_durable_setup_pending() || principal.is_durable_setup_active()))
}
