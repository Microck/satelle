use super::ProviderComputerUseIntent;
use satelle_core::session::TurnExecutionMode;
use satelle_core::{SessionId, TurnId};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionCancellationState {
    Open,
    Requested,
    Cancelled,
    RecoveryPending,
    Admitted {
        session_id: SessionId,
        turn_id: TurnId,
    },
}

#[derive(Clone, Debug)]
pub struct AdmissionCancellation {
    inner: Arc<AdmissionCancellationInner>,
}

#[derive(Debug)]
struct AdmissionCancellationInner {
    commit: Mutex<()>,
    state: Mutex<AdmissionCancellationState>,
}

impl AdmissionCancellation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AdmissionCancellationInner {
                commit: Mutex::new(()),
                state: Mutex::new(AdmissionCancellationState::Open),
            }),
        }
    }

    pub fn request(&self) {
        let _ = self.request_state();
    }

    pub(crate) fn request_state(&self) -> AdmissionCancellationState {
        let _commit = self
            .inner
            .commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *state == AdmissionCancellationState::Open {
            *state = AdmissionCancellationState::Requested;
        }
        state.clone()
    }

    pub(crate) fn is_requested(&self) -> bool {
        matches!(
            *self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            AdmissionCancellationState::Requested
                | AdmissionCancellationState::Cancelled
                | AdmissionCancellationState::RecoveryPending
        )
    }

    pub fn admitted_handle(&self) -> Option<(SessionId, TurnId)> {
        match &*self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            AdmissionCancellationState::Admitted {
                session_id,
                turn_id,
            } => Some((session_id.clone(), turn_id.clone())),
            _ => None,
        }
    }

    pub(crate) fn finish(&self, state: AdmissionCancellationState) {
        debug_assert!(matches!(
            state,
            AdmissionCancellationState::Cancelled | AdmissionCancellationState::RecoveryPending
        ));
        let mut current = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !matches!(*current, AdmissionCancellationState::Admitted { .. }) {
            *current = state;
        }
    }

    pub(crate) fn state(&self) -> AdmissionCancellationState {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn with_commit_gate<T>(
        &self,
        session_id: SessionId,
        turn_id: TurnId,
        operation: impl FnOnce() -> Result<T, satelle_core::SatelleError>,
    ) -> Result<T, satelle_core::SatelleError> {
        let _commit = self
            .inner
            .commit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.is_requested() {
            self.finish(AdmissionCancellationState::Cancelled);
            return Err(satelle_core::SatelleError::interrupted_attached_command());
        }
        let result = operation()?;
        *self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            AdmissionCancellationState::Admitted {
                session_id,
                turn_id,
            };
        Ok(result)
    }
}

impl Default for AdmissionCancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub(crate) struct RequestIdentity {
    principal_ref: String,
    key: String,
    request_digest: String,
    digest_schema_version: u16,
    hmac_key_version: u16,
}

impl RequestIdentity {
    pub(crate) fn new(key: impl Into<String>, request_digest: impl Into<String>) -> Self {
        Self::authenticated("local-principal-v1", key, request_digest, 1, 1)
    }

    pub(crate) fn authenticated(
        principal_ref: impl Into<String>,
        key: impl Into<String>,
        request_digest: impl Into<String>,
        digest_schema_version: u16,
        hmac_key_version: u16,
    ) -> Self {
        Self {
            principal_ref: principal_ref.into(),
            key: key.into(),
            request_digest: request_digest.into(),
            digest_schema_version,
            hmac_key_version,
        }
    }

    pub(crate) fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub(crate) const fn digest_schema_version(&self) -> u16 {
        self.digest_schema_version
    }

    pub(crate) const fn hmac_key_version(&self) -> u16 {
        self.hmac_key_version
    }

    fn fresh() -> Self {
        let key_id = TurnId::new();
        let digest_id = TurnId::new();
        let request_digest = format!(
            "{}{}",
            identifier_hex(key_id.as_str()),
            identifier_hex(digest_id.as_str())
        );
        Self::new(format!("request:{}", key_id.as_str()), request_digest)
    }
}

pub(crate) struct RunCommand<'a> {
    pub(super) host: &'a str,
    pub(super) prompt: &'a str,
    pub(super) dispatch: DispatchPreference,
    pub(super) identity: RequestIdentity,
    pub(super) execution_mode: TurnExecutionMode,
    pub(super) provider_intent: ProviderComputerUseIntent,
    pub(super) cancellation: AdmissionCancellation,
}

#[derive(Clone, Copy)]
pub(super) enum DispatchPreference {
    Inline,
    Detached,
}

impl<'a> RunCommand<'a> {
    pub(crate) fn attached(host: &'a str, prompt: &'a str) -> Self {
        Self::attached_with_identity(host, prompt, RequestIdentity::fresh())
    }

    pub(crate) fn attached_with_identity(
        host: &'a str,
        prompt: &'a str,
        identity: RequestIdentity,
    ) -> Self {
        Self {
            host,
            prompt,
            dispatch: DispatchPreference::Inline,
            identity,
            execution_mode: TurnExecutionMode::Standard,
            provider_intent: ProviderComputerUseIntent::host_default(),
            cancellation: AdmissionCancellation::new(),
        }
    }

    pub(crate) fn detached(host: &'a str, prompt: &'a str) -> Self {
        Self::detached_with_identity(host, prompt, RequestIdentity::fresh())
    }

    pub(crate) fn detached_with_identity(
        host: &'a str,
        prompt: &'a str,
        identity: RequestIdentity,
    ) -> Self {
        Self {
            host,
            prompt,
            dispatch: DispatchPreference::Detached,
            identity,
            execution_mode: TurnExecutionMode::Standard,
            provider_intent: ProviderComputerUseIntent::host_default(),
            cancellation: AdmissionCancellation::new(),
        }
    }

    pub(crate) fn with_execution_mode(mut self, execution_mode: TurnExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    pub(crate) fn with_provider_intent(
        mut self,
        provider_intent: ProviderComputerUseIntent,
    ) -> Self {
        self.provider_intent = provider_intent;
        self
    }

    pub(crate) fn with_cancellation(mut self, cancellation: AdmissionCancellation) -> Self {
        self.cancellation = cancellation;
        self
    }
}

pub(crate) struct SteerCommand<'a> {
    pub(super) session_id: SessionId,
    pub(super) prompt: &'a str,
    pub(super) dispatch: DispatchPreference,
    pub(super) identity: RequestIdentity,
    pub(super) execution_mode: TurnExecutionMode,
    pub(super) provider_intent: ProviderComputerUseIntent,
    pub(super) cancellation: AdmissionCancellation,
}

impl<'a> SteerCommand<'a> {
    pub(crate) fn attached(session_id: SessionId, prompt: &'a str) -> Self {
        Self::attached_with_identity(session_id, prompt, RequestIdentity::fresh())
    }

    pub(crate) fn attached_with_identity(
        session_id: SessionId,
        prompt: &'a str,
        identity: RequestIdentity,
    ) -> Self {
        Self {
            session_id,
            prompt,
            dispatch: DispatchPreference::Inline,
            identity,
            execution_mode: TurnExecutionMode::Standard,
            provider_intent: ProviderComputerUseIntent::host_default(),
            cancellation: AdmissionCancellation::new(),
        }
    }

    pub(crate) fn detached(session_id: SessionId, prompt: &'a str) -> Self {
        Self::detached_with_identity(session_id, prompt, RequestIdentity::fresh())
    }

    pub(crate) fn detached_with_identity(
        session_id: SessionId,
        prompt: &'a str,
        identity: RequestIdentity,
    ) -> Self {
        Self {
            session_id,
            prompt,
            dispatch: DispatchPreference::Detached,
            identity,
            execution_mode: TurnExecutionMode::Standard,
            provider_intent: ProviderComputerUseIntent::host_default(),
            cancellation: AdmissionCancellation::new(),
        }
    }

    pub(crate) fn with_execution_mode(mut self, execution_mode: TurnExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }

    pub(crate) fn with_provider_intent(
        mut self,
        provider_intent: ProviderComputerUseIntent,
    ) -> Self {
        self.provider_intent = provider_intent;
        self
    }

    pub(crate) fn with_cancellation(mut self, cancellation: AdmissionCancellation) -> Self {
        self.cancellation = cancellation;
        self
    }
}

pub(crate) struct StopCommand {
    pub(super) session_id: SessionId,
    pub(super) expected_turn_id: Option<TurnId>,
    pub(super) identity: RequestIdentity,
}

impl StopCommand {
    pub(crate) fn new(session_id: SessionId) -> Self {
        Self::with_identity(session_id, RequestIdentity::fresh())
    }

    pub(crate) fn with_identity(session_id: SessionId, identity: RequestIdentity) -> Self {
        Self {
            session_id,
            expected_turn_id: None,
            identity,
        }
    }

    pub(crate) fn for_turn_with_identity(
        session_id: SessionId,
        expected_turn_id: TurnId,
        identity: RequestIdentity,
    ) -> Self {
        Self {
            session_id,
            expected_turn_id: Some(expected_turn_id),
            identity,
        }
    }

    pub(crate) fn for_turn(session_id: SessionId, expected_turn_id: TurnId) -> Self {
        Self::for_turn_with_identity(session_id, expected_turn_id, RequestIdentity::fresh())
    }
}

fn identifier_hex(value: &str) -> String {
    value
        .split_once('_')
        .map_or(value, |(_, identifier)| identifier)
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect()
}

#[cfg(test)]
mod admission_cancellation_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn cancellation_before_commit_prevents_the_storage_operation() {
        let cancellation = AdmissionCancellation::new();
        cancellation.request();
        let mut called = false;
        let result = cancellation.with_commit_gate(SessionId::new(), TurnId::new(), || {
            called = true;
            Ok(())
        });

        assert!(!called);
        assert_eq!(
            result
                .expect_err("requested cancellation must reject commit")
                .code,
            satelle_core::ErrorCode::Interrupted
        );
        assert_eq!(cancellation.state(), AdmissionCancellationState::Cancelled);
    }

    #[test]
    fn committed_admission_wins_a_concurrent_cancellation_request() {
        let cancellation = AdmissionCancellation::new();
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let operation_cancellation = cancellation.clone();
        let operation_session_id = session_id.clone();
        let operation_turn_id = turn_id.clone();
        let (entered_sender, entered_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let operation = std::thread::spawn(move || {
            operation_cancellation.with_commit_gate(operation_session_id, operation_turn_id, || {
                entered_sender.send(()).expect("signal commit entry");
                release_receiver.recv().expect("release commit operation");
                Ok(())
            })
        });
        entered_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("storage operation must hold the commit gate");

        let request_cancellation = cancellation.clone();
        let request = std::thread::spawn(move || request_cancellation.request());
        release_sender.send(()).expect("release commit operation");
        operation
            .join()
            .expect("commit thread must not panic")
            .expect("commit wins the race");
        request.join().expect("request thread must not panic");

        assert_eq!(cancellation.admitted_handle(), Some((session_id, turn_id)));
        assert!(!cancellation.is_requested());
    }
}
