use crate::codex_capabilities::BlockerReason;
use crate::runtime::{RunCommand, SteerCommand, StopCommand};
use crate::storage::{ApiTokenRegistration, IdempotentOperation};
use crate::{
    ApiBearerToken, ApiPrincipal, ApiScopes, HostMode, HostService, ProductionCapabilitySnapshot,
};
use satelle_core::session::{PublicSession, SessionStateRevision, TurnStateRevision};
use satelle_core::{LOCAL_DEMO_HOST, SatelleError, SessionId, StopResult};
use serde::Serialize;
use std::fmt;
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const IDEMPOTENCY_DIGEST_SCHEMA_VERSION: u16 = 1;

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

/// Prompt intent accepted by the current Host API. Execution-policy overrides
/// and attachments are intentionally absent until their full vertical slices
/// exist.
pub struct TurnIntent {
    prompt: String,
}

impl TurnIntent {
    pub fn new(prompt: impl Into<String>) -> Result<Self, TurnIntentError> {
        let prompt = prompt.into();
        if prompt.is_empty() {
            return Err(TurnIntentError::EmptyPrompt);
        }
        Ok(Self { prompt })
    }
}

impl fmt::Debug for TurnIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnIntent")
            .field("prompt_bytes", &self.prompt.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TurnIntentError {
    #[error("the prompt must not be empty")]
    EmptyPrompt,
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
}

#[derive(Serialize)]
struct CanonicalTurnCreate<'a> {
    operation: &'static str,
    session_id: &'a str,
    prompt: &'a str,
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
        let snapshot = self.runtime.initialize_for_daemon()?;
        Ok(daemon_status(snapshot))
    }

    /// Reads current authoritative status without running restart recovery or
    /// adapter preflight. Startup owns reconciliation before the listener opens.
    pub fn daemon_runtime_status(&self) -> Result<DaemonRuntimeStatus, SatelleError> {
        self.runtime.snapshot_for_daemon().map(daemon_status)
    }

    pub fn daemon_workers_idle(&self) -> Result<bool, SatelleError> {
        self.runtime.daemon_workers_idle()
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

    pub fn daemon_runtime_capabilities(&self) -> DaemonRuntimeCapabilities {
        match &self.mode {
            HostMode::Production { snapshot } => production_capabilities(snapshot),
            #[cfg(any(test, feature = "test-support"))]
            HostMode::TestFake => DaemonRuntimeCapabilities {
                codex_runtime: false,
                native_computer_use: false,
                provider_computer_use: false,
            },
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
        self.runtime
            .authenticate_api_token(token, now)?
            .ok_or_else(authentication_state_failure)
    }

    pub fn authenticate_api_token(
        &self,
        token: &ApiBearerToken,
    ) -> Result<Option<ApiPrincipal>, SatelleError> {
        self.runtime
            .authenticate_api_token(token, OffsetDateTime::now_utc())
    }

    pub fn api_principal_is_active(&self, principal: &ApiPrincipal) -> Result<bool, SatelleError> {
        self.runtime
            .api_principal_is_active(principal, OffsetDateTime::now_utc())
    }

    pub fn rotate_api_token(
        &self,
        replacement: &ApiBearerToken,
        expected_credential_revision: u64,
    ) -> Result<ApiPrincipal, SatelleError> {
        self.runtime.rotate_api_token(
            replacement,
            expected_credential_revision,
            OffsetDateTime::now_utc(),
        )
    }

    pub fn revoke_api_token(&self, token_id: &str) -> Result<(), SatelleError> {
        self.runtime
            .revoke_api_token(token_id, OffsetDateTime::now_utc())
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
        let canonical_payload = canonical_payload(&CanonicalSessionCreate {
            operation: "session_create",
            prompt: &intent.prompt,
        })?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Run,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let outcome = self.runtime.run(RunCommand::detached_with_identity(
            LOCAL_DEMO_HOST,
            &intent.prompt,
            identity,
        ))?;
        Ok(outcome.public_session)
    }

    pub fn admit_steer(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        authority: &MutationAuthority,
    ) -> Result<PublicSession, SatelleError> {
        let canonical_payload = canonical_payload(&CanonicalTurnCreate {
            operation: "turn_create",
            session_id: session_id.as_str(),
            prompt: &intent.prompt,
        })?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Steer,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let outcome = self.runtime.steer(SteerCommand::detached_with_identity(
            session_id.clone(),
            &intent.prompt,
            identity,
        ))?;
        Ok(outcome.public_session)
    }

    pub fn admit_stop(
        &self,
        session_id: &SessionId,
        authority: &MutationAuthority,
    ) -> Result<StopAdmission, SatelleError> {
        let canonical_payload = canonical_payload(&CanonicalSessionStop {
            operation: "session_stop",
            session_id: session_id.as_str(),
        })?;
        let identity = self.runtime.authenticated_request_identity(
            &authority.principal,
            IdempotentOperation::Stop,
            &authority.idempotency_key,
            canonical_payload.as_slice(),
            canonical_payload.digest_schema_version,
        )?;
        let outcome = self
            .runtime
            .stop_with_snapshot(StopCommand::with_identity(session_id.clone(), identity))?;
        Ok(StopAdmission {
            result: outcome.result,
            session_state_revision: outcome.session_state_revision,
            turn_state_revision: outcome.turn_state_revision,
        })
    }

    pub fn session_status(&self, session_id: &SessionId) -> Result<PublicSession, SatelleError> {
        self.runtime.status_public(session_id)
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
            mode: HostMode::TestFake,
        })
    }
}

fn production_capabilities(snapshot: &ProductionCapabilitySnapshot) -> DaemonRuntimeCapabilities {
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
        native_computer_use: snapshot.verdict.is_supported(),
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

fn canonical_payload<T: Serialize>(value: &T) -> Result<SensitiveCanonicalPayload, SatelleError> {
    let digest_schema_version = IDEMPOTENCY_DIGEST_SCHEMA_VERSION;
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
        let intent = TurnIntent::new(prompt).expect("construct turn intent");
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
            TurnIntent::new("SECOND_PRIVATE_PROMPT_CANARY").expect("construct follow-up intent");
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

        let changed = TurnIntent::new(format!("{prompt}-changed")).expect("changed turn intent");
        let error = service
            .admit_run(&changed, &authority)
            .expect_err("changed payload must conflict");
        assert_eq!(error.code, satelle_core::ErrorCode::IdempotencyKeyConflict);
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
        let intent = TurnIntent::new("PRIVATE_EVENT_PROMPT").expect("construct Turn intent");
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
                satelle_core::EventType::TurnProgress,
                satelle_core::EventType::TurnCompleted,
            ]
        );
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
