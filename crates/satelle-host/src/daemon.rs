use crate::codex_capabilities::BlockerReason;
use crate::operation_capacity::AdmissionCancellationOutcome;
use crate::runtime::{AdmissionCancellation, RunCommand, SteerCommand, StopCommand};
use crate::storage::{ApiTokenRegistration, IdempotentOperation};
use crate::{
    ApiBearerToken, ApiPrincipal, ApiScopes, HostMode, HostService, ProductionCapabilitySnapshot,
};
use satelle_core::session::{
    EffectiveModelRef, ProviderBindingRef, PublicSession, SessionStateRevision, TurnExecutionMode,
    TurnStateRevision,
};
use satelle_core::{
    DesktopSessionRecord, LOCAL_DEMO_HOST, SatelleError, SessionId, StopResult, TurnId,
};
use serde::Serialize;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

#[cfg(any(test, feature = "test-support"))]
use crate::EphemeralApiAuthenticator;
#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION: u16 = 4;
const STOP_IDEMPOTENCY_DIGEST_SCHEMA_VERSION: u16 = 1;
const DURABLE_SETUP_PRINCIPAL_PREFIX: &str = "controller-setup";

/// A diagnostic-safe snapshot captured from the daemon-owned runtime after
/// storage has opened and restart recovery has been reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonRuntimeStatus {
    host_identity: String,
    session_count: usize,
    active_turn_count: usize,
    recovery_pending_turn_count: usize,
}

/// Authoritative Host state used when a Client reconnects after losing its
/// live event stream. Satelle Events remain process-local; durable recovery
/// combines the current Session snapshot with normalized logs after the last
/// cursor the Client received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonSessionReconnect {
    host_identity: String,
    session: PublicSession,
    logs: crate::DaemonLogPage,
}

impl DaemonSessionReconnect {
    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn session(&self) -> &PublicSession {
        &self.session
    }

    pub const fn logs(&self) -> &crate::DaemonLogPage {
        &self.logs
    }
}

impl DaemonRuntimeStatus {
    pub fn host_identity(&self) -> &str {
        &self.host_identity
    }

    pub const fn session_count(&self) -> usize {
        self.session_count
    }

    pub const fn active_turn_count(&self) -> usize {
        self.active_turn_count
    }

    pub const fn recovery_pending_turn_count(&self) -> usize {
        self.recovery_pending_turn_count
    }
}

/// Host-owned capability evidence. Route availability and network limits stay
/// in the transport crate because they describe the serving process, not the
/// Computer Use runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonRuntimeCapabilities {
    codex_runtime: bool,
    native_computer_use: bool,
    provider_computer_use: bool,
    image_attachments: bool,
}

/// Volatile activity used only to decide whether an on-demand daemon may exit.
/// Durable Session records are intentionally absent from this snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonActivitySnapshot {
    idle: bool,
    generation: DaemonActivityGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonActivityGeneration {
    operations: u64,
    runtime: u64,
}

impl DaemonActivitySnapshot {
    pub const fn is_idle(self) -> bool {
        self.idle
    }

    pub const fn generation(self) -> DaemonActivityGeneration {
        self.generation
    }
}

/// Authenticated authority for one Host mutation. Canonical payload bytes are
/// intentionally absent: each admission method derives them from the exact
/// typed values it executes.
#[derive(Clone)]
pub struct MutationAuthority {
    principal: ApiPrincipal,
    idempotency_key: String,
}

impl MutationAuthority {
    pub fn new(
        principal: ApiPrincipal,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, MutationAuthorityError> {
        let idempotency_key = idempotency_key.into();
        if idempotency_key.is_empty()
            || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
            || !idempotency_key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
        {
            return Err(MutationAuthorityError::InvalidIdempotencyKey);
        }
        Ok(Self {
            principal,
            idempotency_key,
        })
    }

    pub fn principal(&self) -> &ApiPrincipal {
        &self.principal
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

impl fmt::Debug for MutationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationAuthority")
            .field("token_id", &self.principal.token_id())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MutationAuthorityError {
    #[error("the idempotency key is malformed")]
    InvalidIdempotencyKey,
}

/// Prompt, provider intent, and verified image bytes accepted by the Host API.
pub struct TurnIntent {
    prompt: String,
    execution_mode: TurnExecutionMode,
    provider_intent: crate::ProviderComputerUseIntent,
    turn_execution_timeout: Option<satelle_core::session::TimeoutPolicy>,
    attachments: Vec<crate::attachment::VerifiedImageAttachment>,
}

impl TurnIntent {
    pub fn new(
        prompt: impl Into<String>,
        execution_mode: TurnExecutionMode,
    ) -> Result<Self, TurnIntentError> {
        let prompt = prompt.into();
        if prompt.is_empty() {
            return Err(TurnIntentError::EmptyPrompt);
        }
        Ok(Self {
            prompt,
            execution_mode,
            provider_intent: crate::ProviderComputerUseIntent::host_default(),
            turn_execution_timeout: None,
            attachments: Vec::new(),
        })
    }

    pub fn with_provider_intent(
        mut self,
        model: Option<String>,
        provider: Option<String>,
        experimental: bool,
        refresh: bool,
    ) -> Result<Self, TurnIntentError> {
        let model = model
            .map(EffectiveModelRef::new)
            .transpose()
            .map_err(|_| TurnIntentError::InvalidModel)?;
        let provider = provider
            .map(ProviderBindingRef::new)
            .transpose()
            .map_err(|_| TurnIntentError::InvalidProvider)?;
        self.provider_intent =
            crate::ProviderComputerUseIntent::new(model, provider, experimental, refresh);
        Ok(self)
    }

    pub fn with_turn_execution_timeout_ms(
        mut self,
        timeout_ms: Option<u64>,
    ) -> Result<Self, TurnIntentError> {
        self.turn_execution_timeout = timeout_ms
            .map(|timeout_ms| {
                if timeout_ms == 0
                    || timeout_ms > satelle_core::MAX_TURN_EXECUTION_TIMEOUT_MS
                    || timeout_ms % 1_000 != 0
                {
                    return Err(TurnIntentError::InvalidTurnExecutionTimeout);
                }
                let seconds = u32::try_from(timeout_ms / 1_000)
                    .map_err(|_| TurnIntentError::InvalidTurnExecutionTimeout)?;
                satelle_core::session::TimeoutPolicy::bounded_seconds(seconds)
                    .map_err(|_| TurnIntentError::InvalidTurnExecutionTimeout)
            })
            .transpose()?;
        Ok(self)
    }

    pub fn with_attachments(
        mut self,
        attachments: Vec<crate::AttachmentUpload>,
    ) -> Result<Self, TurnIntentError> {
        self.attachments = crate::attachment::verify_uploads(attachments)
            .map_err(|()| TurnIntentError::InvalidAttachments)?;
        Ok(self)
    }

    pub(crate) fn prompt(&self) -> &str {
        &self.prompt
    }

    pub(crate) const fn execution_mode(&self) -> TurnExecutionMode {
        self.execution_mode
    }

    pub(crate) fn provider_intent(&self) -> &crate::ProviderComputerUseIntent {
        &self.provider_intent
    }

    pub(crate) fn attachments(&self) -> &[crate::attachment::VerifiedImageAttachment] {
        &self.attachments
    }
}

impl fmt::Debug for TurnIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnIntent")
            .field("prompt_bytes", &self.prompt.len())
            .field("execution_mode", &self.execution_mode)
            .field("provider_intent", &self.provider_intent)
            .field("attachment_count", &self.attachments.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TurnIntentError {
    #[error("the prompt must not be empty")]
    EmptyPrompt,
    #[error("the model override is invalid")]
    InvalidModel,
    #[error("the provider override is invalid")]
    InvalidProvider,
    #[error("the Turn execution timeout must be a whole number of seconds from 1s through 24h")]
    InvalidTurnExecutionTimeout,
    #[error("the image attachments failed bounded media or integrity validation")]
    InvalidAttachments,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopAdmission {
    result: StopResult,
    session_state_revision: SessionStateRevision,
    turn_state_revision: TurnStateRevision,
}

pub enum AdmissionCancellationResult {
    Cancelled,
    Admitted {
        session: PublicSession,
        turn_id: TurnId,
    },
    RecoveryPending,
}

impl StopAdmission {
    pub const fn result(&self) -> &StopResult {
        &self.result
    }

    pub const fn session_state_revision(&self) -> SessionStateRevision {
        self.session_state_revision
    }

    pub const fn turn_state_revision(&self) -> TurnStateRevision {
        self.turn_state_revision
    }

    pub fn into_parts(self) -> (StopResult, SessionStateRevision, TurnStateRevision) {
        (
            self.result,
            self.session_state_revision,
            self.turn_state_revision,
        )
    }
}

#[derive(Serialize)]
struct CanonicalSessionCreate<'a> {
    operation: &'static str,
    prompt: &'a str,
    execution_mode: TurnExecutionMode,
    model: Option<&'a str>,
    provider: Option<&'a str>,
    experimental_provider_computer_use: bool,
    refresh_provider_smoke_test: bool,
    turn_execution_timeout_seconds: Option<u32>,
    attachments: &'a [CanonicalAttachment<'a>],
}

#[derive(Serialize)]
struct CanonicalTurnCreate<'a> {
    operation: &'static str,
    session_id: &'a str,
    prompt: &'a str,
    execution_mode: TurnExecutionMode,
    model: Option<&'a str>,
    provider: Option<&'a str>,
    experimental_provider_computer_use: bool,
    refresh_provider_smoke_test: bool,
    turn_execution_timeout_seconds: Option<u32>,
    attachments: &'a [CanonicalAttachment<'a>],
}

#[derive(Serialize)]
struct CanonicalAttachment<'a> {
    media_type: &'a str,
    size_bytes: usize,
    sha256: String,
}

impl<'a> From<&'a crate::attachment::VerifiedImageAttachment> for CanonicalAttachment<'a> {
    fn from(attachment: &'a crate::attachment::VerifiedImageAttachment) -> Self {
        Self {
            media_type: attachment.media_type(),
            size_bytes: attachment.size_bytes(),
            sha256: attachment.sha256_hex(),
        }
    }
}

#[derive(Serialize)]
struct CanonicalSessionStop<'a> {
    operation: &'static str,
    session_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_turn_id: Option<&'a str>,
}

#[derive(Serialize)]
struct CanonicalPayloadEnvelope<'a, T> {
    digest_schema_version: u16,
    payload: &'a T,
}

struct SensitiveCanonicalPayload {
    bytes: Zeroizing<Vec<u8>>,
    digest_schema_version: u16,
}

impl SensitiveCanonicalPayload {
    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl DaemonRuntimeCapabilities {
    pub const fn codex_runtime(self) -> bool {
        self.codex_runtime
    }

    pub const fn native_computer_use(self) -> bool {
        self.native_computer_use
    }

    pub const fn provider_computer_use(self) -> bool {
        self.provider_computer_use
    }

    pub const fn image_attachments(self) -> bool {
        self.image_attachments
    }
}

impl HostService {
    /// Opens and exclusively owns Host state before a network listener starts.
    /// Existing nonterminal work is reconciled first, so a daemon never reports
    /// itself initialized while restart recovery remains unexamined.
    pub fn initialize_daemon(&self) -> Result<DaemonRuntimeStatus, SatelleError> {
        let snapshot = self.runtime.reconcile_and_snapshot()?;
        Ok(daemon_status(snapshot))
    }

    /// Reads current authoritative status without running restart recovery or
    /// adapter preflight. Startup owns reconciliation before the listener opens.
    pub fn daemon_runtime_status(&self) -> Result<DaemonRuntimeStatus, SatelleError> {
        self.runtime.snapshot().map(daemon_status)
    }

    pub fn daemon_workers_idle(&self) -> Result<bool, SatelleError> {
        self.runtime.daemon_workers_idle()
    }

    pub fn daemon_activity_snapshot(&self) -> Result<DaemonActivitySnapshot, SatelleError> {
        let (runtime_idle, runtime_generation) = self.runtime.daemon_activity_snapshot()?;
        let (operations_idle, generation) = self.operation_capacity.activity_snapshot()?;
        Ok(DaemonActivitySnapshot {
            idle: runtime_idle && operations_idle,
            generation: DaemonActivityGeneration {
                operations: generation,
                runtime: runtime_generation,
            },
        })
    }

    pub fn daemon_log_page(
        &self,
        query: &crate::LogPageQuery,
    ) -> Result<crate::DaemonLogPage, SatelleError> {
        self.runtime.log_page(query)
    }

    /// Restores durable Client context without pretending that missed live
    /// events can be replayed. Host Identity comes from the same authoritative
    /// runtime that owns the current Session and cursor-addressed log history.
    pub fn daemon_session_reconnect(
        &self,
        session_id: &SessionId,
        after: Option<crate::LogCursor>,
        limit: usize,
    ) -> Result<DaemonSessionReconnect, SatelleError> {
        let query = crate::LogPageQuery::forward(after, limit)
            .map_err(|error| SatelleError::invalid_usage(error.to_string()))?
            .with_session(session_id.clone());
        let status = self.daemon_runtime_status()?;
        let session = self.session_status(session_id)?;
        let logs = self.daemon_log_page(&query)?;
        Ok(DaemonSessionReconnect {
            host_identity: status.host_identity,
            session,
            logs,
        })
    }

    pub fn subscribe_live_events(&self) -> Result<crate::LiveEventSubscription, SatelleError> {
        self.runtime.subscribe_live_events()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn append_daemon_log_for_tests(
        &self,
        timestamp: time::OffsetDateTime,
        source: crate::LogSource,
        severity: crate::LogSeverity,
    ) -> Result<crate::LogCursor, SatelleError> {
        self.runtime
            .append_log_for_tests(timestamp, source, severity)
    }

    pub fn daemon_runtime_capabilities(&self) -> Result<DaemonRuntimeCapabilities, SatelleError> {
        match &self.mode {
            HostMode::Production { snapshot } => {
                let native_computer_use = self.runtime.has_reusable_readiness(LOCAL_DEMO_HOST)?;
                Ok(production_capabilities(
                    &*crate::read_production_snapshot(snapshot)?,
                    native_computer_use,
                ))
            }
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { image_attachments } => Ok(DaemonRuntimeCapabilities {
                codex_runtime: false,
                native_computer_use: false,
                provider_computer_use: false,
                image_attachments: *image_attachments,
            }),
        }
    }

    /// Reads only Host-observed desktop state. Controller transport and
    /// bootstrap metadata belong to the CLI-facing `host_sessions` wrapper.
    pub fn daemon_desktop_sessions(&self) -> Result<Vec<DesktopSessionRecord>, SatelleError> {
        match &self.mode {
            HostMode::Production { .. } => crate::desktop_sessions::discover(),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake { .. } => Ok(self.desktop_sessions_fake()),
        }
    }

    /// Registers an explicitly provided managed-environment token. The raw
    /// secret is converted to its canonical verifier inside the Host boundary
    /// and can never be passed to storage directly.
    pub fn register_api_token(
        &self,
        token: &ApiBearerToken,
        principal_ref: impl Into<String>,
        scopes: ApiScopes,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<ApiPrincipal, SatelleError> {
        let now = OffsetDateTime::now_utc();
        let registration =
            ApiTokenRegistration::new(token, principal_ref, 1, scopes, expires_at, now)
                .map_err(crate::runtime::storage_error)?;
        self.runtime.register_api_token(registration)?;
        let principal = self
            .runtime
            .authenticate_api_token(token, now)?
            .ok_or_else(authentication_state_failure)?;
        // A token ID is the deliberately non-secret identity for diagnostics.
        // Never pass the bearer value or its verifier into a logging field.
        tracing::info!(
            target: "satelle::host::api_token",
            token_id = principal.token_id(),
            credential_revision = principal.credential_revision(),
            "API token registered"
        );
        Ok(principal)
    }

    pub fn authenticate_api_token(
        &self,
        token: &ApiBearerToken,
    ) -> Result<Option<ApiPrincipal>, SatelleError> {
        if let Some(authenticator) = self
            .bootstrap_auth
            .as_ref()
            .filter(|authenticator| authenticator.owns_token_id(token.token_id()))
        {
            // A bootstrap token ID belongs exclusively to this process-local
            // authenticator. Expiry or revocation must not fall through to a
            // coincidentally matching durable credential.
            return Ok(authenticator.authenticate(token, OffsetDateTime::now_utc()));
        }
        self.runtime
            .authenticate_api_token(token, OffsetDateTime::now_utc())
    }

    /// Authenticates an unexpired pending setup token for its one narrow
    /// recovery operation. The transport must additionally bind the principal
    /// to activation of the same token ID.
    pub fn authenticate_pending_setup_api_token(
        &self,
        token: &ApiBearerToken,
    ) -> Result<Option<ApiPrincipal>, SatelleError> {
        if self
            .bootstrap_auth
            .as_ref()
            .is_some_and(|authenticator| authenticator.owns_token_id(token.token_id()))
        {
            return Ok(None);
        }
        self.runtime
            .authenticate_pending_setup_api_token(token, OffsetDateTime::now_utc())
    }

    pub fn api_principal_is_active(&self, principal: &ApiPrincipal) -> Result<bool, SatelleError> {
        if let Some(authenticator) = self
            .bootstrap_auth
            .as_ref()
            .filter(|authenticator| authenticator.owns_principal(principal))
        {
            return Ok(authenticator.is_active(principal, OffsetDateTime::now_utc()));
        }
        self.runtime
            .api_principal_is_active(principal, OffsetDateTime::now_utc())
    }

    pub fn rotate_api_token(
        &self,
        replacement: &ApiBearerToken,
        expected_credential_revision: u64,
    ) -> Result<ApiPrincipal, SatelleError> {
        let principal = self.runtime.rotate_api_token(
            replacement,
            expected_credential_revision,
            OffsetDateTime::now_utc(),
        )?;
        tracing::info!(
            target: "satelle::host::api_token",
            token_id = principal.token_id(),
            credential_revision = principal.credential_revision(),
            "API token rotated"
        );
        Ok(principal)
    }

    /// Generates a durable credential in a short-lived pending state. The raw
    /// token leaves the Host exactly once in the setup response; activation is
    /// a separate transaction after the Controller has synced its token file.
    pub fn issue_pending_api_token(
        &self,
        scopes: ApiScopes,
        pending_until: OffsetDateTime,
    ) -> Result<(ApiBearerToken, ApiPrincipal), SatelleError> {
        self.operation_capacity.execute_exclusive(|| {
            let token = ApiBearerToken::generate().map_err(|_| authentication_state_failure())?;
            // The non-secret token ID gives each durable Controller credential a
            // stable identity across restarts without deriving identity from the
            // bearer secret. Limits and idempotency remain isolated per issuance.
            let principal_ref = format!("{DURABLE_SETUP_PRINCIPAL_PREFIX}-{}", token.token_id());
            let now = OffsetDateTime::now_utc();
            let registration = ApiTokenRegistration::new_setup_pending(
                &token,
                principal_ref,
                1,
                scopes,
                pending_until,
                now,
            )
            .map_err(crate::runtime::storage_error)?;
            let principal = registration.principal();
            self.runtime.register_api_token(registration)?;
            Ok((token, principal))
        })
    }

    pub fn activate_api_token(&self, token_id: &str) -> Result<ApiPrincipal, SatelleError> {
        self.operation_capacity.execute_exclusive(|| {
            let principal = self
                .runtime
                .activate_api_token(token_id, OffsetDateTime::now_utc())?;
            tracing::info!(
                target: "satelle::host::api_token",
                token_id = principal.token_id(),
                credential_revision = principal.credential_revision(),
                "pending API token activated"
            );
            Ok(principal)
        })
    }

    pub fn abort_setup_api_token(&self, token_id: &str) -> Result<(), SatelleError> {
        self.operation_capacity.execute_exclusive(|| {
            self.runtime
                .abort_setup_api_token(token_id, OffsetDateTime::now_utc())?;
            tracing::info!(
                target: "satelle::host::api_token",
                token_id,
                "setup-issued API token revoked"
            );
            Ok(())
        })
    }

    pub fn revoke_api_token(&self, token_id: &str) -> Result<(), SatelleError> {
        if let Some(authenticator) = self
            .bootstrap_auth
            .as_ref()
            .filter(|authenticator| authenticator.owns_token_id(token_id))
        {
            authenticator.revoke();
            tracing::info!(
                target: "satelle::host::api_token",
                token_id,
                "ephemeral API token revoked"
            );
            return Ok(());
        }
        self.runtime
            .revoke_api_token(token_id, OffsetDateTime::now_utc())?;
        tracing::info!(
            target: "satelle::host::api_token",
            token_id,
            "API token revoked"
        );
        Ok(())
    }

    /// Rotates the active request-digest key while retaining every older key
    /// still referenced by an Idempotency Record.
    pub fn rotate_idempotency_hmac_key(&self) -> Result<u16, SatelleError> {
        let _identity_gate = self.operation_capacity.lock_identity_write()?;
        self.operation_capacity
            .execute_exclusive(|| self.runtime.rotate_idempotency_hmac_key())
    }

    pub fn admit_run(
        &self,
        intent: &TurnIntent,
        authority: &MutationAuthority,
    ) -> Result<PublicSession, SatelleError> {
        self.admit_run_with_cancellation(intent, authority, AdmissionCancellation::new())
    }

    pub fn admit_run_with_cancellation(
        &self,
        intent: &TurnIntent,
        authority: &MutationAuthority,
        cancellation: AdmissionCancellation,
    ) -> Result<PublicSession, SatelleError> {
        self.ensure_image_attachments_supported(intent)?;
        let turn_execution_timeout = self.effective_turn_execution_timeout(intent);
        let canonical_payload = canonical_payload(
            &CanonicalSessionCreate {
                operation: "session_create",
                prompt: &intent.prompt,
                execution_mode: intent.execution_mode,
                model: intent
                    .provider_intent
                    .model()
                    .map(EffectiveModelRef::as_str),
                provider: intent
                    .provider_intent
                    .provider()
                    .map(ProviderBindingRef::as_str),
                experimental_provider_computer_use: intent.provider_intent.experimental(),
                refresh_provider_smoke_test: intent.provider_intent.refresh(),
                turn_execution_timeout_seconds: Some(turn_execution_timeout.seconds()),
                attachments: &intent
                    .attachments
                    .iter()
                    .map(CanonicalAttachment::from)
                    .collect::<Vec<_>>(),
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let _identity_gate = self.operation_capacity.lock_identity_read()?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Run,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let operation_identity = identity.clone();
        self.operation_capacity
            .execute_interruptible_durable(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Run,
                    &identity,
                ),
                cancellation.clone(),
                || {
                    self.runtime
                        .resolve_admission_operation(IdempotentOperation::Run, &identity, None)
                        .map(durable_admission_outcome)
                },
                |outcome| {
                    self.runtime
                        .record_admission_cancellation(
                            IdempotentOperation::Run,
                            &identity,
                            None,
                            durable_cancellation_outcome(&outcome),
                            cancellation_is_reconciled(&outcome),
                        )
                        .map(durable_admission_outcome)
                },
                |registered_cancellation| {
                    let session = crate::runtime::admitted_session(
                        self.runtime.run(
                            RunCommand::detached_with_identity(
                                LOCAL_DEMO_HOST,
                                &intent.prompt,
                                operation_identity,
                            )
                            .with_execution_mode(intent.execution_mode)
                            .with_provider_intent(intent.provider_intent.clone())
                            .with_turn_execution_timeout(Some(turn_execution_timeout))
                            .with_attachments(intent.attachments.clone())
                            .with_cancellation(registered_cancellation),
                        ),
                    )?;
                    let turn_id = session
                        .turns()
                        .last()
                        .expect("a newly admitted run contains its target Turn")
                        .turn_id()
                        .clone();
                    Ok(crate::operation_capacity::OperationOutcome::admission(
                        session, turn_id,
                    ))
                },
            )?
            .into_session()
    }

    pub fn admit_steer(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        authority: &MutationAuthority,
    ) -> Result<PublicSession, SatelleError> {
        self.admit_steer_with_cancellation(
            session_id,
            intent,
            authority,
            AdmissionCancellation::new(),
        )
    }

    pub fn admit_steer_with_cancellation(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        authority: &MutationAuthority,
        cancellation: AdmissionCancellation,
    ) -> Result<PublicSession, SatelleError> {
        self.ensure_image_attachments_supported(intent)?;
        let turn_execution_timeout = self.effective_turn_execution_timeout(intent);
        let canonical_payload = canonical_payload(
            &CanonicalTurnCreate {
                operation: "turn_create",
                session_id: session_id.as_str(),
                prompt: &intent.prompt,
                execution_mode: intent.execution_mode,
                model: intent
                    .provider_intent
                    .model()
                    .map(EffectiveModelRef::as_str),
                provider: intent
                    .provider_intent
                    .provider()
                    .map(ProviderBindingRef::as_str),
                experimental_provider_computer_use: intent.provider_intent.experimental(),
                refresh_provider_smoke_test: intent.provider_intent.refresh(),
                turn_execution_timeout_seconds: Some(turn_execution_timeout.seconds()),
                attachments: &intent
                    .attachments
                    .iter()
                    .map(CanonicalAttachment::from)
                    .collect::<Vec<_>>(),
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let _identity_gate = self.operation_capacity.lock_identity_read()?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Steer,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let operation_identity = identity.clone();
        self.operation_capacity
            .execute_interruptible_durable(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Steer,
                    &identity,
                ),
                cancellation.clone(),
                || {
                    self.runtime
                        .resolve_admission_operation(
                            IdempotentOperation::Steer,
                            &identity,
                            Some(session_id),
                        )
                        .map(durable_admission_outcome)
                },
                |outcome| {
                    self.runtime
                        .record_admission_cancellation(
                            IdempotentOperation::Steer,
                            &identity,
                            Some(session_id),
                            durable_cancellation_outcome(&outcome),
                            cancellation_is_reconciled(&outcome),
                        )
                        .map(durable_admission_outcome)
                },
                |registered_cancellation| {
                    let session = crate::runtime::admitted_session(
                        self.runtime.steer(
                            SteerCommand::detached_with_identity(
                                session_id.clone(),
                                &intent.prompt,
                                operation_identity,
                            )
                            .with_execution_mode(intent.execution_mode)
                            .with_provider_intent(intent.provider_intent.clone())
                            .with_turn_execution_timeout(Some(turn_execution_timeout))
                            .with_attachments(intent.attachments.clone())
                            .with_cancellation(registered_cancellation),
                        ),
                    )?;
                    let turn_id = session
                        .turns()
                        .last()
                        .expect("a newly admitted steer contains its target Turn")
                        .turn_id()
                        .clone();
                    Ok(crate::operation_capacity::OperationOutcome::admission(
                        session, turn_id,
                    ))
                },
            )?
            .into_session()
    }

    pub fn cancel_run_admission(
        &self,
        intent: &TurnIntent,
        authority: &MutationAuthority,
    ) -> Result<AdmissionCancellationResult, SatelleError> {
        let turn_execution_timeout = self.effective_turn_execution_timeout(intent);
        let canonical_payload = canonical_payload(
            &CanonicalSessionCreate {
                operation: "session_create",
                prompt: &intent.prompt,
                execution_mode: intent.execution_mode,
                model: intent
                    .provider_intent
                    .model()
                    .map(EffectiveModelRef::as_str),
                provider: intent
                    .provider_intent
                    .provider()
                    .map(ProviderBindingRef::as_str),
                experimental_provider_computer_use: intent.provider_intent.experimental(),
                refresh_provider_smoke_test: intent.provider_intent.refresh(),
                turn_execution_timeout_seconds: Some(turn_execution_timeout.seconds()),
                attachments: &intent
                    .attachments
                    .iter()
                    .map(CanonicalAttachment::from)
                    .collect::<Vec<_>>(),
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let _identity_gate = self.operation_capacity.lock_identity_read()?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Run,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        self.operation_capacity
            .cancel_durable(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Run,
                    &identity,
                ),
                || {
                    self.runtime
                        .resolve_admission_operation(IdempotentOperation::Run, &identity, None)
                        .map(durable_admission_outcome)
                },
                |outcome| {
                    self.runtime
                        .record_admission_cancellation(
                            IdempotentOperation::Run,
                            &identity,
                            None,
                            durable_cancellation_outcome(&outcome),
                            cancellation_is_reconciled(&outcome),
                        )
                        .map(durable_admission_outcome)
                },
            )
            .map(admission_cancellation_result)
    }

    pub fn cancel_steer_admission(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        authority: &MutationAuthority,
    ) -> Result<AdmissionCancellationResult, SatelleError> {
        let turn_execution_timeout = self.effective_turn_execution_timeout(intent);
        let canonical_payload = canonical_payload(
            &CanonicalTurnCreate {
                operation: "turn_create",
                session_id: session_id.as_str(),
                prompt: &intent.prompt,
                execution_mode: intent.execution_mode,
                model: intent
                    .provider_intent
                    .model()
                    .map(EffectiveModelRef::as_str),
                provider: intent
                    .provider_intent
                    .provider()
                    .map(ProviderBindingRef::as_str),
                experimental_provider_computer_use: intent.provider_intent.experimental(),
                refresh_provider_smoke_test: intent.provider_intent.refresh(),
                turn_execution_timeout_seconds: Some(turn_execution_timeout.seconds()),
                attachments: &intent
                    .attachments
                    .iter()
                    .map(CanonicalAttachment::from)
                    .collect::<Vec<_>>(),
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let _identity_gate = self.operation_capacity.lock_identity_read()?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Steer,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        self.operation_capacity
            .cancel_durable(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Steer,
                    &identity,
                ),
                || {
                    self.runtime
                        .resolve_admission_operation(
                            IdempotentOperation::Steer,
                            &identity,
                            Some(session_id),
                        )
                        .map(durable_admission_outcome)
                },
                |outcome| {
                    self.runtime
                        .record_admission_cancellation(
                            IdempotentOperation::Steer,
                            &identity,
                            Some(session_id),
                            durable_cancellation_outcome(&outcome),
                            cancellation_is_reconciled(&outcome),
                        )
                        .map(durable_admission_outcome)
                },
            )
            .map(admission_cancellation_result)
    }

    pub fn admit_stop(
        &self,
        session_id: &SessionId,
        authority: &MutationAuthority,
    ) -> Result<StopAdmission, SatelleError> {
        self.admit_stop_inner(session_id, None, authority)
    }

    pub fn admit_stop_expected_turn(
        &self,
        session_id: &SessionId,
        expected_turn_id: &TurnId,
        authority: &MutationAuthority,
    ) -> Result<StopAdmission, SatelleError> {
        self.admit_stop_inner(session_id, Some(expected_turn_id), authority)
    }

    fn admit_stop_inner(
        &self,
        session_id: &SessionId,
        expected_turn_id: Option<&TurnId>,
        authority: &MutationAuthority,
    ) -> Result<StopAdmission, SatelleError> {
        let canonical_payload = canonical_payload(
            &CanonicalSessionStop {
                operation: "session_stop",
                session_id: session_id.as_str(),
                expected_turn_id: expected_turn_id.map(TurnId::as_str),
            },
            STOP_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let _identity_gate = self.operation_capacity.lock_identity_read()?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Stop,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let operation_identity = identity.clone();
        self.operation_capacity
            .execute(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Stop,
                    &identity,
                ),
                || {
                    self.runtime
                        .replay_completed_stop_if_present(session_id, &identity)
                        .map(|outcome| {
                            outcome.map(crate::operation_capacity::OperationOutcome::Stop)
                        })
                },
                || {
                    let command = match expected_turn_id {
                        Some(turn_id) => StopCommand::for_turn_with_identity(
                            session_id.clone(),
                            turn_id.clone(),
                            operation_identity,
                        ),
                        None => StopCommand::with_identity(session_id.clone(), operation_identity),
                    };
                    self.runtime
                        .stop_with_snapshot(command)
                        .map(crate::operation_capacity::OperationOutcome::Stop)
                },
            )?
            .into_stop()
            .map(stop_admission)
    }

    pub fn session_status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.runtime.status(session_id.clone())
    }

    pub(crate) fn effective_turn_execution_timeout(
        &self,
        intent: &TurnIntent,
    ) -> satelle_core::session::TimeoutPolicy {
        let requested = intent
            .turn_execution_timeout
            .unwrap_or(self.turn_execution_timeout);
        satelle_core::session::TimeoutPolicy::bounded_seconds(
            requested
                .seconds()
                .min(self.turn_execution_timeout.seconds()),
        )
        .expect("typed Turn timeout policies are always nonzero")
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn local_demo_for_tests_at(
        state_root: impl Into<std::path::PathBuf>,
    ) -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: crate::runtime::RuntimeHandle::new(
                Ok(state_root.into()),
                crate::test_runtime::FakeComputerUseAdapter,
            ),
            operation_capacity: std::sync::Arc::new(
                crate::operation_capacity::OperationCapacity::default(),
            ),
            turn_execution_timeout: crate::configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[satelle_core::LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_ssh_bootstrap_auth_for_tests(
        mut self,
        token: &ApiBearerToken,
        scopes: ApiScopes,
        expires_at: OffsetDateTime,
    ) -> Self {
        self.bootstrap_auth = Some(Arc::new(EphemeralApiAuthenticator::new(
            token, scopes, expires_at,
        )));
        self
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_turn_execution_timeout_for_tests(mut self, seconds: u32) -> Self {
        self.turn_execution_timeout =
            satelle_core::session::TimeoutPolicy::bounded_seconds(seconds)
                .expect("test Turn execution timeout must be nonzero");
        self
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn without_image_attachments_for_tests(mut self) -> Self {
        self.mode = HostMode::TestFake {
            image_attachments: false,
        };
        self
    }

    #[doc(hidden)]
    #[cfg(feature = "test-support")]
    pub fn with_adapter_for_tests_at<A: crate::ComputerUseAdapter>(
        state_root: impl Into<std::path::PathBuf>,
        adapter: A,
    ) -> Result<Self, SatelleError> {
        Ok(Self {
            runtime: crate::runtime::RuntimeHandle::new(Ok(state_root.into()), adapter),
            operation_capacity: std::sync::Arc::new(
                crate::operation_capacity::OperationCapacity::default(),
            ),
            turn_execution_timeout: crate::configured_turn_execution_timeout(
                &satelle_core::SatelleConfig::defaults().hosts[satelle_core::LOCAL_DEMO_HOST],
            ),
            mode: HostMode::TestFake {
                image_attachments: true,
            },
            bootstrap_auth: None,
            bootstrap_maintenance: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }
}

fn production_capabilities(
    snapshot: &ProductionCapabilitySnapshot,
    native_computer_use: bool,
) -> DaemonRuntimeCapabilities {
    let codex_runtime = !snapshot.verdict.blockers().iter().any(|blocker| {
        matches!(
            blocker.reason,
            BlockerReason::MissingCodexRuntime
                | BlockerReason::MalformedCodexVersion
                | BlockerReason::CodexVersionUnavailable
                | BlockerReason::UnsupportedCodexVersion
        )
    });
    DaemonRuntimeCapabilities {
        codex_runtime,
        native_computer_use,
        provider_computer_use: false,
        image_attachments: snapshot.image_attachments_supported(),
    }
}

fn daemon_status(snapshot: crate::runtime::RuntimeSnapshot) -> DaemonRuntimeStatus {
    DaemonRuntimeStatus {
        host_identity: snapshot.host_identity().to_string(),
        session_count: snapshot.session_count(),
        active_turn_count: snapshot.active_turn_count(),
        recovery_pending_turn_count: snapshot.recovery_pending_turn_count(),
    }
}

fn stop_admission(outcome: crate::runtime::RuntimeStopOutcome) -> StopAdmission {
    StopAdmission {
        result: outcome.result,
        session_state_revision: outcome.session_state_revision,
        turn_state_revision: outcome.turn_state_revision,
    }
}

fn admission_cancellation_result(
    outcome: AdmissionCancellationOutcome,
) -> AdmissionCancellationResult {
    match outcome {
        AdmissionCancellationOutcome::Cancelled
        | AdmissionCancellationOutcome::ReconciledCancelled => {
            AdmissionCancellationResult::Cancelled
        }
        AdmissionCancellationOutcome::Admitted { session, turn_id } => {
            AdmissionCancellationResult::Admitted { session, turn_id }
        }
        AdmissionCancellationOutcome::RecoveryPending => {
            AdmissionCancellationResult::RecoveryPending
        }
    }
}

fn durable_cancellation_outcome(
    outcome: &AdmissionCancellationOutcome,
) -> crate::storage::DurableCancellationOutcome {
    match outcome {
        AdmissionCancellationOutcome::Cancelled
        | AdmissionCancellationOutcome::ReconciledCancelled => {
            crate::storage::DurableCancellationOutcome::Cancelled
        }
        AdmissionCancellationOutcome::RecoveryPending => {
            crate::storage::DurableCancellationOutcome::RecoveryPending
        }
        AdmissionCancellationOutcome::Admitted { .. } => {
            unreachable!("an admitted outcome is never persisted as a cancellation")
        }
    }
}

fn cancellation_is_reconciled(outcome: &AdmissionCancellationOutcome) -> bool {
    matches!(outcome, AdmissionCancellationOutcome::ReconciledCancelled)
}

fn durable_admission_outcome(
    state: crate::runtime::RuntimeAdmissionState,
) -> crate::operation_capacity::DurableAdmissionOutcome {
    match state {
        crate::runtime::RuntimeAdmissionState::Missing => {
            crate::operation_capacity::DurableAdmissionOutcome::Missing
        }
        crate::runtime::RuntimeAdmissionState::Cancelled => {
            crate::operation_capacity::DurableAdmissionOutcome::Cancelled
        }
        crate::runtime::RuntimeAdmissionState::RecoveryPending => {
            crate::operation_capacity::DurableAdmissionOutcome::RecoveryPending
        }
        crate::runtime::RuntimeAdmissionState::Admitted(replay) => {
            let (session, turn_id) = replay.into_parts();
            crate::operation_capacity::DurableAdmissionOutcome::Admitted(
                crate::operation_capacity::OperationOutcome::admission(session, turn_id),
            )
        }
    }
}

fn canonical_payload<T: Serialize>(
    value: &T,
    digest_schema_version: u16,
) -> Result<SensitiveCanonicalPayload, SatelleError> {
    let envelope = CanonicalPayloadEnvelope {
        digest_schema_version,
        payload: value,
    };
    serde_json::to_vec(&envelope)
        .map(|bytes| SensitiveCanonicalPayload {
            bytes: Zeroizing::new(bytes),
            digest_schema_version,
        })
        .map_err(|_| operation_snapshot_failure())
}

fn operation_snapshot_failure() -> SatelleError {
    SatelleError {
        code: satelle_core::ErrorCode::StorageIntegrityFailed,
        message: "the Host Daemon could not preserve the durable operation snapshot".to_string(),
        recovery_command: None,
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

fn authentication_state_failure() -> SatelleError {
    SatelleError {
        code: satelle_core::ErrorCode::StorageIntegrityFailed,
        message: "the registered API token could not be read back from Host state".to_string(),
        recovery_command: None,
        source_detail: None,
        details: std::collections::BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LiveEventReceiveError;
    use crate::api_auth::EphemeralApiAuthenticator;
    use std::sync::Arc;

    #[test]
    fn host_turn_timeout_resolves_omitted_and_longer_requests_before_admission() {
        let state = crate::TestStateDir::new().expect("temporary Host state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .unwrap()
            .with_turn_execution_timeout_for_tests(5 * 60);
        let omitted = TurnIntent::new("prompt", TurnExecutionMode::Standard).unwrap();
        let longer = TurnIntent::new("prompt", TurnExecutionMode::Standard)
            .unwrap()
            .with_turn_execution_timeout_ms(Some(60 * 60 * 1_000))
            .unwrap();
        assert_eq!(
            service.effective_turn_execution_timeout(&omitted).seconds(),
            5 * 60
        );
        assert_eq!(
            service.effective_turn_execution_timeout(&longer).seconds(),
            5 * 60
        );
    }

    #[test]
    fn idempotency_digest_versions_change_only_for_turn_payloads() {
        let turn = canonical_payload(
            &CanonicalSessionCreate {
                operation: "session_create",
                prompt: "PRIVATE_DIGEST_VERSION_PROMPT",
                execution_mode: TurnExecutionMode::Yolo,
                model: Some("model-test"),
                provider: Some("provider-test"),
                experimental_provider_computer_use: true,
                refresh_provider_smoke_test: true,
                turn_execution_timeout_seconds: Some(30 * 60),
                attachments: &[],
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )
        .expect("serialize Turn idempotency payload");
        assert_eq!(turn.digest_schema_version, 4);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(turn.as_slice())
                .expect("decode Turn payload"),
            serde_json::json!({
                "digest_schema_version": 4,
                "payload": {
                    "operation": "session_create",
                    "prompt": "PRIVATE_DIGEST_VERSION_PROMPT",
                    "execution_mode": "yolo",
                    "model": "model-test",
                    "provider": "provider-test",
                    "experimental_provider_computer_use": true,
                    "refresh_provider_smoke_test": true,
                    "turn_execution_timeout_seconds": 1800,
                    "attachments": []
                }
            })
        );

        let stop = canonical_payload(
            &CanonicalSessionStop {
                operation: "session_stop",
                session_id: "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
                expected_turn_id: None,
            },
            STOP_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )
        .expect("serialize stop idempotency payload");
        assert_eq!(stop.digest_schema_version, 1);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(stop.as_slice())
                .expect("decode stop payload"),
            serde_json::json!({
                "digest_schema_version": 1,
                "payload": {
                    "operation": "session_stop",
                    "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11"
                }
            })
        );
        let guarded_stop = canonical_payload(
            &CanonicalSessionStop {
                operation: "session_stop",
                session_id: "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
                expected_turn_id: Some("rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21"),
            },
            STOP_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )
        .expect("serialize guarded stop idempotency payload");
        assert_ne!(stop.as_slice(), guarded_stop.as_slice());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(guarded_stop.as_slice())
                .expect("decode guarded stop payload"),
            serde_json::json!({
                "digest_schema_version": 1,
                "payload": {
                    "operation": "session_stop",
                    "session_id": "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
                    "expected_turn_id": "rt_01890a5d-ac96-7b7c-8f89-37c3d0a66e21"
                }
            })
        );
    }

    #[test]
    fn daemon_initialization_and_authentication_share_one_runtime_owner() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service");
        let clone = service.clone();
        let initialized = service.initialize_daemon().expect("initialize daemon");
        assert!(initialized.host_identity().starts_with("host-"));
        assert_eq!(initialized.session_count(), 0);
        assert_eq!(initialized.active_turn_count(), 0);
        assert_eq!(initialized.recovery_pending_turn_count(), 0);

        let token = ApiBearerToken::generate().expect("generate API token");
        let registered = service
            .register_api_token(&token, "principal-test", ApiScopes::CONTROL, None)
            .expect("register API token");
        assert!(registered.scopes().allows(ApiScopes::READ));
        assert_eq!(
            clone
                .authenticate_api_token(&token)
                .expect("authenticate through clone")
                .expect("token authenticates"),
            registered
        );
        assert_eq!(
            clone
                .initialize_daemon()
                .expect("read through clone")
                .host_identity(),
            initialized.host_identity()
        );
    }

    #[test]
    fn bootstrap_revocation_is_immediate_and_never_reaches_a_later_daemon() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let token = ApiBearerToken::generate().expect("generate bootstrap token");
        let mut service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service");
        service
            .initialize_daemon()
            .expect("initialize first daemon");
        service.bootstrap_auth = Some(Arc::new(EphemeralApiAuthenticator::new(
            &token,
            ApiScopes::READ,
            OffsetDateTime::now_utc() + time::Duration::minutes(15),
        )));

        let principal = service
            .authenticate_api_token(&token)
            .expect("authenticate bootstrap token")
            .expect("bootstrap token is active");
        service
            .revoke_api_token(token.token_id())
            .expect("revoke bootstrap token in memory");
        assert!(
            service
                .authenticate_api_token(&token)
                .expect("check revoked token")
                .is_none()
        );
        assert!(
            !service
                .api_principal_is_active(&principal)
                .expect("check revoked principal")
        );

        drop(service);
        let later_service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct later daemon process");
        later_service
            .initialize_daemon()
            .expect("initialize later daemon");
        assert!(
            later_service
                .authenticate_api_token(&token)
                .expect("check token in later daemon")
                .is_none()
        );
    }

    #[test]
    fn pending_setup_token_survives_restart_only_after_activation() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service");
        service.initialize_daemon().expect("initialize daemon");
        let (token, pending) = service
            .issue_pending_api_token(
                ApiScopes::CONTROL,
                OffsetDateTime::now_utc() + time::Duration::minutes(5),
            )
            .expect("issue pending setup token");
        let (other_token, other_pending) = service
            .issue_pending_api_token(
                ApiScopes::CONTROL,
                OffsetDateTime::now_utc() + time::Duration::minutes(5),
            )
            .expect("issue an independent pending setup token");
        assert_eq!(
            pending.principal_ref(),
            format!("controller-setup-{}", token.token_id())
        );
        assert_ne!(pending.principal_ref(), other_pending.principal_ref());
        service
            .abort_setup_api_token(other_token.token_id())
            .expect("discard the independent pending token");
        assert!(pending.expires_at().is_some());
        assert!(
            service
                .authenticate_api_token(&token)
                .expect("check pending setup token")
                .is_none()
        );
        drop(service);

        let restarted_pending = HostService::local_demo_for_tests_at(state.path())
            .expect("construct restarted pending service");
        restarted_pending
            .initialize_daemon()
            .expect("restart pending daemon");
        assert!(
            restarted_pending
                .authenticate_api_token(&token)
                .expect("check pending setup token after restart")
                .is_none()
        );
        let active = restarted_pending
            .activate_api_token(token.token_id())
            .expect("activate setup token");
        assert_eq!(active.expires_at(), None);
        drop(restarted_pending);

        let restarted = HostService::local_demo_for_tests_at(state.path())
            .expect("construct restarted service");
        restarted.initialize_daemon().expect("restart daemon");
        assert_eq!(
            restarted
                .authenticate_api_token(&token)
                .expect("authenticate after restart")
                .expect("activated token remains valid")
                .expires_at(),
            None
        );
    }

    #[test]
    fn unsupported_image_capability_does_not_claim_idempotency_or_accept_detached_turns() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service")
            .without_image_attachments_for_tests();
        service.initialize_daemon().expect("initialize daemon");
        let token = ApiBearerToken::generate().expect("generate API token");
        let principal = service
            .register_api_token(&token, "principal-image-test", ApiScopes::CONTROL, None)
            .expect("register API token");
        let image = || {
            crate::AttachmentUpload::new(
                "image/png",
                8,
                "4c4b6a3be1314ab86138bef4314dde022e600960d8689a2c8f8631802d20dab6",
                "iVBORw0KGgo=",
            )
        };

        let run_prompt = "PRIVATE_UNSUPPORTED_IMAGE_RUN";
        let image_run = TurnIntent::new(run_prompt, TurnExecutionMode::Standard)
            .expect("construct image run")
            .with_attachments(vec![image()])
            .expect("verify image run");
        let run_authority =
            MutationAuthority::new(principal.clone(), "01890a5d-ac96-7b7c-8f89-37c3d0a66e80")
                .expect("construct run authority");
        let run_error = service
            .admit_run(&image_run, &run_authority)
            .expect_err("unsupported detached image run must be rejected");
        assert_eq!(run_error.code, satelle_core::ErrorCode::InvalidUsage);
        assert_eq!(
            service
                .daemon_runtime_status()
                .expect("read daemon status")
                .session_count(),
            0
        );
        let image_free_run = TurnIntent::new(run_prompt, TurnExecutionMode::Standard)
            .expect("construct image-free run");
        let session = service
            .admit_run(&image_free_run, &run_authority)
            .expect("rejected image run must not claim its idempotency key");
        service
            .runtime
            .wait_for_background()
            .expect("finish image-free run");

        let steer_prompt = "PRIVATE_UNSUPPORTED_IMAGE_STEER";
        let image_steer = TurnIntent::new(steer_prompt, TurnExecutionMode::Standard)
            .expect("construct image steer")
            .with_attachments(vec![image()])
            .expect("verify image steer");
        let steer_authority =
            MutationAuthority::new(principal, "01890a5d-ac96-7b7c-8f89-37c3d0a66e81")
                .expect("construct steer authority");
        let steer_error = service
            .admit_steer(session.session_id(), &image_steer, &steer_authority)
            .expect_err("unsupported detached image steer must be rejected");
        assert_eq!(steer_error.code, satelle_core::ErrorCode::InvalidUsage);
        let image_free_steer = TurnIntent::new(steer_prompt, TurnExecutionMode::Standard)
            .expect("construct image-free steer");
        let steered = service
            .admit_steer(session.session_id(), &image_free_steer, &steer_authority)
            .expect("rejected image steer must not claim its idempotency key");
        assert_eq!(steered.turns().len(), 2);
    }

    #[test]
    fn authenticated_run_uses_payload_hmac_and_replays_one_durable_session() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service");
        service.initialize_daemon().expect("initialize daemon");
        let token = ApiBearerToken::generate().expect("generate API token");
        let principal = service
            .register_api_token(&token, "principal-test", ApiScopes::CONTROL, None)
            .expect("register API token");
        let prompt = "PRIVATE_AUTHENTICATED_PROMPT_CANARY";
        let intent =
            TurnIntent::new(prompt, TurnExecutionMode::Standard).expect("construct turn intent");
        let authority =
            MutationAuthority::new(principal.clone(), "01890a5d-ac96-7b7c-8f89-37c3d0a66e90")
                .expect("construct mutation authority");

        let first = service
            .admit_run(&intent, &authority)
            .expect("admit first run");
        service
            .runtime
            .wait_for_background()
            .expect("finish first turn");

        let follow_up =
            TurnIntent::new("SECOND_PRIVATE_PROMPT_CANARY", TurnExecutionMode::Standard)
                .expect("construct follow-up intent");
        let follow_up_authority =
            MutationAuthority::new(principal, "01890a5d-ac96-7b7c-8f89-37c3d0a66e91")
                .expect("construct follow-up authority");
        service
            .admit_steer(first.session_id(), &follow_up, &follow_up_authority)
            .expect("admit follow-up");
        service
            .runtime
            .wait_for_background()
            .expect("finish follow-up");

        let replay = service
            .admit_run(&intent, &authority)
            .expect("replay original run");
        assert_eq!(first.session_id(), replay.session_id());
        assert_eq!(replay.turns().len(), 1);
        assert_eq!(
            service
                .session_status(first.session_id())
                .expect("read current Session")
                .turns()
                .len(),
            2
        );
        assert_eq!(
            service
                .initialize_daemon()
                .expect("read daemon status")
                .session_count(),
            1
        );
        assert!(!format!("{intent:?} {authority:?}").contains(prompt));

        let changed_mode = TurnIntent::new(prompt, TurnExecutionMode::Yolo)
            .expect("construct changed-mode turn intent");
        let error = service
            .admit_run(&changed_mode, &authority)
            .expect_err("changed execution mode must conflict");
        assert_eq!(error.code, satelle_core::ErrorCode::IdempotencyKeyConflict);

        let changed = TurnIntent::new(format!("{prompt}-changed"), TurnExecutionMode::Standard)
            .expect("changed turn intent");
        let error = service
            .admit_run(&changed, &authority)
            .expect_err("changed payload must conflict");
        assert_eq!(error.code, satelle_core::ErrorCode::IdempotencyKeyConflict);
    }

    #[test]
    fn postcommit_dispatch_failure_returns_the_durable_failed_admission() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service");
        service.initialize_daemon().expect("initialize daemon");
        let token = ApiBearerToken::generate().expect("generate API token");
        let principal = service
            .register_api_token(
                &token,
                "principal-dispatch-failure",
                ApiScopes::CONTROL,
                None,
            )
            .expect("register API token");
        let intent = TurnIntent::new(
            "PRIVATE_POSTCOMMIT_DISPATCH_FAILURE",
            TurnExecutionMode::Standard,
        )
        .expect("construct Turn intent");
        let authority = MutationAuthority::new(principal, "01890a5d-ac96-7b7c-8f89-37c3d0a66e93")
            .expect("construct mutation authority");
        service
            .runtime
            .poison_worker_registry_for_tests()
            .expect("poison the deterministic worker registry");

        let admitted = service
            .admit_run(&intent, &authority)
            .expect("a committed Turn remains an accepted admission");
        let target = admitted
            .turns()
            .last()
            .expect("the accepted admission contains its target Turn");
        assert_eq!(target.state(), satelle_core::session::TurnState::Failed);
        assert_eq!(
            service
                .session_status(admitted.session_id())
                .expect("the failed admission remains readable"),
            admitted
        );
    }

    #[test]
    fn daemon_live_events_follow_commits_and_idempotent_replay_emits_nothing() {
        let state = crate::TestStateDir::new().expect("temporary state directory");
        let service = HostService::local_demo_for_tests_at(state.path())
            .expect("construct deterministic service");
        service.initialize_daemon().expect("initialize daemon");
        let token = ApiBearerToken::generate().expect("generate API token");
        let principal = service
            .register_api_token(&token, "principal-events", ApiScopes::CONTROL, None)
            .expect("register API token");
        let intent = TurnIntent::new("PRIVATE_EVENT_PROMPT", TurnExecutionMode::Standard)
            .expect("construct Turn intent");
        let authority = MutationAuthority::new(principal, "01890a5d-ac96-7b7c-8f89-37c3d0a66e92")
            .expect("construct mutation authority");
        let mut subscription = service
            .subscribe_live_events()
            .expect("subscribe to daemon events");

        let admitted = service.admit_run(&intent, &authority).expect("admit Turn");
        service.runtime.wait_for_background().expect("finish Turn");
        let mut events = Vec::new();
        while let Ok(event) = subscription.try_recv() {
            events.push(event);
        }
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type())
                .collect::<Vec<_>>(),
            [
                satelle_core::EventType::TurnStarted,
                satelle_core::EventType::ProviderSmoke,
                satelle_core::EventType::TurnProgress,
                satelle_core::EventType::TurnCompleted,
            ]
        );
        let provider = events
            .iter()
            .find(|event| event.event_type() == satelle_core::EventType::ProviderSmoke)
            .expect("provider preflight event should be live");
        assert_eq!(provider.data()["source"], "live");
        assert_eq!(provider.data()["status"], "passed");
        assert!(events.iter().all(|event| {
            event.session_id() == Some(admitted.session_id())
                && matches!(
                    event.state_subject(),
                    Some(satelle_core::EventStateSubject::Turn { .. })
                )
        }));

        service
            .admit_run(&intent, &authority)
            .expect("replay admitted Turn");
        assert!(matches!(
            subscription.try_recv(),
            Err(LiveEventReceiveError::Empty)
        ));
    }
}

#[cfg(test)]
#[path = "daemon-reconnect-tests.rs"]
mod reconnect_tests;
