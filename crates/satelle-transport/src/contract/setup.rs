use super::{AuthenticatedResponseContract, RequestId, define_schema_token};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const DURABLE_SETUP_PENDING_TTL: time::Duration = time::Duration::minutes(5);

define_schema_token!(DurableTokenIssuanceSchema, "satelle.setup-api-token.v1");
define_schema_token!(
    DurableTokenConfirmationSchema,
    "satelle.setup-api-token-confirmation.v1"
);
define_schema_token!(
    DurableTokenActivationSchema,
    "satelle.setup-api-token-activation.v1"
);

#[derive(Serialize, Deserialize)]
pub struct DurableTokenIssuanceResponse {
    schema_version: DurableTokenIssuanceSchema,
    request_id: RequestId,
    host_identity: String,
    token_id: String,
    bearer_token: Option<String>,
    pending_expires_at: String,
}

impl DurableTokenIssuanceResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        token_id: String,
        bearer_token: Option<String>,
        pending_expires_at: String,
    ) -> Self {
        Self {
            schema_version: DurableTokenIssuanceSchema,
            request_id,
            host_identity,
            token_id,
            bearer_token,
            pending_expires_at,
        }
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub fn pending_expires_at(&self) -> &str {
        &self.pending_expires_at
    }

    /// Moves the one-time bearer value directly into zeroizing storage.
    pub fn into_bearer_token(mut self) -> Option<Zeroizing<String>> {
        self.bearer_token.take().map(Zeroizing::new)
    }
}

impl fmt::Debug for DurableTokenIssuanceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableTokenIssuanceResponse")
            .field("request_id", &self.request_id)
            .field("host_identity", &self.host_identity)
            .field("token_id", &self.token_id)
            .field("pending_expires_at", &self.pending_expires_at)
            .finish_non_exhaustive()
    }
}

impl Drop for DurableTokenIssuanceResponse {
    fn drop(&mut self) {
        self.bearer_token.zeroize();
    }
}

impl AuthenticatedResponseContract for DurableTokenIssuanceResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableTokenConfirmationResponse {
    schema_version: DurableTokenConfirmationSchema,
    request_id: RequestId,
    host_identity: String,
    token_id: String,
    setup_active: bool,
    control_scoped: bool,
}

impl DurableTokenConfirmationResponse {
    pub(crate) fn new(request_id: RequestId, host_identity: String, token_id: String) -> Self {
        Self {
            schema_version: DurableTokenConfirmationSchema,
            request_id,
            host_identity,
            token_id,
            setup_active: true,
            control_scoped: true,
        }
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub const fn setup_active(&self) -> bool {
        self.setup_active
    }

    pub const fn control_scoped(&self) -> bool {
        self.control_scoped
    }
}

impl AuthenticatedResponseContract for DurableTokenConfirmationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableTokenActivationResponse {
    schema_version: DurableTokenActivationSchema,
    request_id: RequestId,
    host_identity: String,
    token_id: String,
    active: bool,
}

impl DurableTokenActivationResponse {
    pub(crate) fn new(
        request_id: RequestId,
        host_identity: String,
        token_id: String,
        active: bool,
    ) -> Self {
        Self {
            schema_version: DurableTokenActivationSchema,
            request_id,
            host_identity,
            token_id,
            active,
        }
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub const fn active(&self) -> bool {
        self.active
    }
}

impl AuthenticatedResponseContract for DurableTokenActivationResponse {
    fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn host_identity(&self) -> &str {
        &self.host_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuance_schema_is_exact_and_the_secret_moves_into_zeroizing_storage() {
        let response = DurableTokenIssuanceResponse::new(
            RequestId::new(),
            "host-test".to_string(),
            "token-test".to_string(),
            Some("satelle_v1.token-test.secret".to_string()),
            "2026-07-17T12:00:00Z".to_string(),
        );
        let encoded = serde_json::to_value(&response).expect("encode issuance response");
        assert_eq!(encoded["schema_version"], "satelle.setup-api-token.v1");
        assert_eq!(
            response
                .into_bearer_token()
                .expect("first issuance carries the secret")
                .as_str(),
            "satelle_v1.token-test.secret"
        );
    }

    #[test]
    fn confirmation_schema_explicitly_proves_setup_state_and_scope() {
        let response = DurableTokenConfirmationResponse::new(
            RequestId::new(),
            "host-test".to_string(),
            "token-test".to_string(),
        );
        let encoded = serde_json::to_value(&response).expect("encode confirmation response");
        assert_eq!(
            encoded["schema_version"],
            "satelle.setup-api-token-confirmation.v1"
        );
        assert_eq!(encoded["setup_active"], true);
        assert_eq!(encoded["control_scoped"], true);
    }
}
