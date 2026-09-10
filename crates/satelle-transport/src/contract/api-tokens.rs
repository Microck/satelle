use super::{ApiRequestContract, RequestId, define_schema_token};
use satelle_host::{ApiScope, ApiScopes, ApiTokenMetadata, ApiTokenMutation};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};

define_schema_token!(ApiTokenIssueSchema, "satelle.api-token.issue.v1");
define_schema_token!(ApiTokenRotateSchema, "satelle.api-token.rotate.v1");
define_schema_token!(ApiTokenRevokeSchema, "satelle.api-token.revoke.v1");
define_schema_token!(ApiTokenSchema, "satelle.api-token.v1");

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenIssueRequest {
    schema_version: ApiTokenIssueSchema,
    scopes: Vec<ApiScope>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
}

impl ApiTokenIssueRequest {
    pub(crate) fn into_mutation(self) -> Option<ApiTokenMutation> {
        if self
            .expires_at
            .is_some_and(|expiry| expiry.offset() != UtcOffset::UTC)
        {
            return None;
        }
        Some(ApiTokenMutation::Issue {
            scopes: ApiScopes::from_scopes(&self.scopes)?,
            expires_at: self.expires_at,
        })
    }
}

impl ApiRequestContract for ApiTokenIssueRequest {
    const SCHEMA_VERSION: &'static str = ApiTokenIssueSchema::TOKEN;
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenRotateRequest {
    schema_version: ApiTokenRotateSchema,
    pub(crate) expected_credential_revision: u64,
}

impl ApiRequestContract for ApiTokenRotateRequest {
    const SCHEMA_VERSION: &'static str = ApiTokenRotateSchema::TOKEN;
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiTokenRevokeRequest {
    schema_version: ApiTokenRevokeSchema,
    pub(crate) expected_credential_revision: u64,
}

impl ApiRequestContract for ApiTokenRevokeRequest {
    const SCHEMA_VERSION: &'static str = ApiTokenRevokeSchema::TOKEN;
}

/// Borrows the one-time secret only while encoding the HTTP body. Omitting
/// Debug and Clone keeps it out of routine diagnostics and shared outcomes.
#[derive(Serialize)]
pub struct ApiTokenResponse<'a> {
    schema_version: ApiTokenSchema,
    request_id: &'a RequestId,
    host_identity: &'a str,
    #[serde(flatten)]
    metadata: &'a ApiTokenMetadata,
    bearer_token: Option<&'a str>,
}

impl<'a> ApiTokenResponse<'a> {
    pub(crate) fn new(
        request_id: &'a RequestId,
        host_identity: &'a str,
        metadata: &'a ApiTokenMetadata,
        bearer_token: Option<&'a str>,
    ) -> Self {
        Self {
            schema_version: ApiTokenSchema,
            request_id,
            host_identity,
            metadata,
            bearer_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_issue_requires_known_nonempty_scopes_and_utc_expiry() {
        for scopes in [json!([]), json!(["root"])] {
            let decoded = serde_json::from_value::<ApiTokenIssueRequest>(json!({
                "schema_version": "satelle.api-token.issue.v1", "scopes": scopes
            }));
            assert!(
                decoded
                    .ok()
                    .and_then(ApiTokenIssueRequest::into_mutation)
                    .is_none()
            );
        }
        let request = serde_json::from_value::<ApiTokenIssueRequest>(json!({
            "schema_version": "satelle.api-token.issue.v1", "scopes": ["read", "control", "read"],
            "expires_at": "2030-01-01T01:00:00+01:00"
        }))
        .unwrap();
        assert!(request.into_mutation().is_none());
        let request = serde_json::from_value::<ApiTokenIssueRequest>(json!({
            "schema_version": "satelle.api-token.issue.v1", "scopes": ["control", "read", "read"]
        }))
        .unwrap();
        let Some(ApiTokenMutation::Issue {
            scopes,
            expires_at: None,
        }) = request.into_mutation()
        else {
            panic!("canonical scope request should decode");
        };
        assert_eq!(scopes.scopes(), [ApiScope::Read, ApiScope::Control]);
    }
}
