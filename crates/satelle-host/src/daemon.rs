use crate::codex_capabilities::BlockerReason;
use crate::runtime::{RunCommand, SteerCommand, StopCommand};
use crate::storage::{ApiTokenRegistration, IdempotentOperation};
use crate::{
    ApiBearerToken, ApiPrincipal, ApiScopes, HostMode, HostService, ProductionCapabilitySnapshot,
};
use satelle_core::session::{
    EffectiveModelRef, ProviderBindingRef, PublicSession, SessionStateRevision, TurnExecutionMode,
    TurnStateRevision,
};
use satelle_core::{DesktopSessionRecord, LOCAL_DEMO_HOST, SatelleError, SessionId, StopResult};
use serde::Serialize;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION: u16 = 3;
const STOP_IDEMPOTENCY_DIGEST_SCHEMA_VERSION: u16 = 1;

/// A diagnostic-safe snapshot captured from the daemon-owned runtime after
/// storage has opened and restart recovery has been reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonRuntimeStatus {
    host_identity: String,
    session_count: usize,
    active_turn_count: usize,
    recovery_pending_turn_count: usize,
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
}

/// Volatile activity used only to decide whether an on-demand daemon may exit.
/// Durable Session records are intentionally absent from this snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonActivitySnapshot {
    idle: bool,
    generation: u64,
}

impl DaemonActivitySnapshot {
    pub const fn is_idle(self) -> bool {
        self.idle
    }

    pub const fn generation(self) -> u64 {
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

/// Prompt and non-secret provider intent accepted by the Host API. Attachments
/// remain absent until their full vertical slice exists.
pub struct TurnIntent {
    prompt: String,
    execution_mode: TurnExecutionMode,
    provider_intent: crate::ProviderComputerUseIntent,
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

    pub(crate) fn prompt(&self) -> &str {
        &self.prompt
    }

    pub(crate) const fn execution_mode(&self) -> TurnExecutionMode {
        self.execution_mode
    }

    pub(crate) fn provider_intent(&self) -> &crate::ProviderComputerUseIntent {
        &self.provider_intent
    }
}

impl fmt::Debug for TurnIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnIntent")
            .field("prompt_bytes", &self.prompt.len())
            .field("execution_mode", &self.execution_mode)
            .field("provider_intent", &self.provider_intent)
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopAdmission {
    result: StopResult,
    session_state_revision: SessionStateRevision,
    turn_state_revision: TurnStateRevision,
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
}

#[derive(Serialize)]
struct CanonicalSessionStop<'a> {
    operation: &'static str,
    session_id: &'a str,
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
        let workers_idle = self.runtime.daemon_workers_idle()?;
        let (operations_idle, generation) = self.operation_capacity.activity_snapshot()?;
        Ok(DaemonActivitySnapshot {
            idle: workers_idle && operations_idle,
            generation,
        })
    }

    pub fn daemon_log_page(
        &self,
        query: &crate::LogPageQuery,
    ) -> Result<crate::DaemonLogPage, SatelleError> {
        self.runtime.log_page(query)
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
            HostMode::TestFake => Ok(DaemonRuntimeCapabilities {
                codex_runtime: false,
                native_computer_use: false,
                provider_computer_use: false,
            }),
        }
    }

    /// Reads only Host-observed desktop state. Controller transport and
    /// bootstrap metadata belong to the CLI-facing `host_sessions` wrapper.
    pub fn daemon_desktop_sessions(&self) -> Result<Vec<DesktopSessionRecord>, SatelleError> {
        match &self.mode {
            HostMode::Production { .. } => crate::desktop_sessions::discover(),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake => Ok(self.desktop_sessions_fake()),
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
        if let Some(principal) = self
            .bootstrap_auth
            .as_ref()
            .and_then(|authenticator| authenticator.authenticate(token, OffsetDateTime::now_utc()))
        {
            return Ok(Some(principal));
        }
        self.runtime
            .authenticate_api_token(token, OffsetDateTime::now_utc())
    }

    pub fn api_principal_is_active(&self, principal: &ApiPrincipal) -> Result<bool, SatelleError> {
        if self.bootstrap_auth.as_ref().is_some_and(|authenticator| {
            authenticator.is_active(principal, OffsetDateTime::now_utc())
        }) {
            return Ok(true);
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

    pub fn revoke_api_token(&self, token_id: &str) -> Result<(), SatelleError> {
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
        self.runtime.rotate_idempotency_hmac_key()
    }

    pub fn admit_run(
        &self,
        intent: &TurnIntent,
        authority: &MutationAuthority,
    ) -> Result<PublicSession, SatelleError> {
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
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Run,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let operation_identity = identity.clone();
        self.operation_capacity
            .execute(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Run,
                    &identity,
                ),
                || {
                    self.runtime
                        .replay_admission_if_present(IdempotentOperation::Run, &identity, None)
                        .map(|replay| {
                            replay.map(|replay| {
                                crate::operation_capacity::OperationOutcome::Session(
                                    replay.into_session(),
                                )
                            })
                        })
                },
                || {
                    crate::runtime::admitted_session(
                        self.runtime.run(
                            RunCommand::detached_with_identity(
                                LOCAL_DEMO_HOST,
                                &intent.prompt,
                                operation_identity,
                            )
                            .with_execution_mode(intent.execution_mode)
                            .with_provider_intent(intent.provider_intent.clone()),
                        ),
                    )
                    .map(crate::operation_capacity::OperationOutcome::Session)
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
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Steer,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let operation_identity = identity.clone();
        self.operation_capacity
            .execute(
                crate::operation_capacity::OperationRequest::new(
                    IdempotentOperation::Steer,
                    &identity,
                ),
                || {
                    self.runtime
                        .replay_admission_if_present(
                            IdempotentOperation::Steer,
                            &identity,
                            Some(session_id),
                        )
                        .map(|replay| {
                            replay.map(|replay| {
                                crate::operation_capacity::OperationOutcome::Session(
                                    replay.into_session(),
                                )
                            })
                        })
                },
                || {
                    crate::runtime::admitted_session(
                        self.runtime.steer(
                            SteerCommand::detached_with_identity(
                                session_id.clone(),
                                &intent.prompt,
                                operation_identity,
                            )
                            .with_execution_mode(intent.execution_mode)
                            .with_provider_intent(intent.provider_intent.clone()),
                        ),
                    )
                    .map(crate::operation_capacity::OperationOutcome::Session)
                },
            )?
            .into_session()
    }

    pub fn admit_stop(
        &self,
        session_id: &SessionId,
        authority: &MutationAuthority,
    ) -> Result<StopAdmission, SatelleError> {
        let canonical_payload = canonical_payload(
            &CanonicalSessionStop {
                operation: "session_stop",
                session_id: session_id.as_str(),
            },
            STOP_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )?;
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
                    self.runtime
                        .stop_with_snapshot(StopCommand::with_identity(
                            session_id.clone(),
                            operation_identity,
                        ))
                        .map(crate::operation_capacity::OperationOutcome::Stop)
                },
            )?
            .into_stop()
            .map(stop_admission)
    }

    pub fn session_status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.runtime.status(session_id.clone())
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
            mode: HostMode::TestFake,
            bootstrap_auth: None,
        })
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
            mode: HostMode::TestFake,
            bootstrap_auth: None,
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
            },
            TURN_IDEMPOTENCY_DIGEST_SCHEMA_VERSION,
        )
        .expect("serialize Turn idempotency payload");
        assert_eq!(turn.digest_schema_version, 3);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(turn.as_slice())
                .expect("decode Turn payload"),
            serde_json::json!({
                "digest_schema_version": 3,
                "payload": {
                    "operation": "session_create",
                    "prompt": "PRIVATE_DIGEST_VERSION_PROMPT",
                    "execution_mode": "yolo",
                    "model": "model-test",
                    "provider": "provider-test",
                    "experimental_provider_computer_use": true,
                    "refresh_provider_smoke_test": true
                }
            })
        );

        let stop = canonical_payload(
            &CanonicalSessionStop {
                operation: "session_stop",
                session_id: "rs_01890a5d-ac96-7b7c-8f89-37c3d0a66e11",
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
