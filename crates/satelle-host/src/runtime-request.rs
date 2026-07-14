use satelle_core::session::TurnExecutionMode;
use satelle_core::{SessionId, TurnId};

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
        }
    }

    pub(crate) fn with_execution_mode(mut self, execution_mode: TurnExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }
}

pub(crate) struct SteerCommand<'a> {
    pub(super) session_id: SessionId,
    pub(super) prompt: &'a str,
    pub(super) dispatch: DispatchPreference,
    pub(super) identity: RequestIdentity,
    pub(super) execution_mode: TurnExecutionMode,
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
        }
    }

    pub(crate) fn with_execution_mode(mut self, execution_mode: TurnExecutionMode) -> Self {
        self.execution_mode = execution_mode;
        self
    }
}

pub(crate) struct StopCommand {
    pub(super) session_id: SessionId,
    pub(super) identity: RequestIdentity,
}

impl StopCommand {
    pub(crate) fn new(session_id: SessionId) -> Self {
        Self::with_identity(session_id, RequestIdentity::fresh())
    }

    pub(crate) fn with_identity(session_id: SessionId, identity: RequestIdentity) -> Self {
        Self {
            session_id,
            identity,
        }
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
