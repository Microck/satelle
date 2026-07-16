use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::BitOr;
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

const TOKEN_PREFIX: &str = "satelle_v1";
const TOKEN_SECRET_BYTES: usize = 32;
const TOKEN_SECRET_ENCODED_BYTES: usize = 43;
const MAX_TOKEN_ID_BYTES: usize = 128;
const VERIFIER_DOMAIN: &[u8] = b"satelle.api-token.verifier.v1\0";

/// A raw Host Daemon bearer token held only at an explicit secret boundary.
///
/// The token ID is a stable non-secret lookup key. The secret segment contains
/// 256 bits of entropy and is zeroized when this value is dropped. This type
/// intentionally implements neither `Clone` nor `Display`.
pub struct ApiBearerToken {
    token_id: String,
    secret: Zeroizing<[u8; TOKEN_SECRET_BYTES]>,
}

impl ApiBearerToken {
    pub fn generate() -> Result<Self, ApiBearerTokenError> {
        let mut secret = Zeroizing::new([0_u8; TOKEN_SECRET_BYTES]);
        getrandom::fill(secret.as_mut()).map_err(|_| ApiBearerTokenError::RandomUnavailable)?;
        Ok(Self {
            token_id: format!("token-{}", Uuid::now_v7().hyphenated()),
            secret,
        })
    }

    pub fn parse(value: &str) -> Result<Self, ApiBearerTokenError> {
        let mut parts = value.split('.');
        let prefix = parts.next();
        let token_id = parts.next();
        let encoded_secret = parts.next();
        if prefix != Some(TOKEN_PREFIX) || parts.next().is_some() {
            return Err(ApiBearerTokenError::Malformed);
        }
        let token_id = token_id.ok_or(ApiBearerTokenError::Malformed)?;
        validate_token_id(token_id)?;
        let encoded_secret = encoded_secret.ok_or(ApiBearerTokenError::Malformed)?;
        if encoded_secret.len() != TOKEN_SECRET_ENCODED_BYTES {
            return Err(ApiBearerTokenError::Malformed);
        }
        let mut secret = Zeroizing::new([0_u8; TOKEN_SECRET_BYTES]);
        let decoded = URL_SAFE_NO_PAD
            .decode_slice(encoded_secret, secret.as_mut())
            .map_err(|_| ApiBearerTokenError::Malformed)?;
        if decoded != TOKEN_SECRET_BYTES {
            return Err(ApiBearerTokenError::Malformed);
        }
        Ok(Self {
            token_id: token_id.to_string(),
            secret,
        })
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Reconstructs the raw token only for its one-time return or an
    /// Authorization header. The returned string zeroizes on drop.
    pub fn expose(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{TOKEN_PREFIX}.{}.{}",
            self.token_id,
            URL_SAFE_NO_PAD.encode(self.secret.as_slice())
        ))
    }

    pub(crate) fn verifier(&self) -> ApiTokenVerifier {
        let mut digest = Sha256::new();
        digest.update(VERIFIER_DOMAIN);
        digest.update(self.token_id.as_bytes());
        digest.update([0]);
        digest.update(self.secret.as_slice());
        ApiTokenVerifier(digest.finalize().into())
    }
}

impl fmt::Debug for ApiBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiBearerToken")
            .field("token_id", &self.token_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ApiBearerTokenError {
    #[error("the bearer token is malformed")]
    Malformed,
    #[error("the bearer token ID is malformed")]
    InvalidTokenId,
    #[error("cryptographically secure randomness is unavailable")]
    RandomUnavailable,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ApiTokenVerifier([u8; TOKEN_SECRET_BYTES]);

impl ApiTokenVerifier {
    pub(crate) const fn from_stored(bytes: [u8; TOKEN_SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn dummy() -> Self {
        Self([0_u8; TOKEN_SECRET_BYTES])
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; TOKEN_SECRET_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ApiTokenVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiTokenVerifier([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiScopes(u8);

impl ApiScopes {
    pub const READ: Self = Self(1 << 0);
    pub const CONTROL: Self = Self(1 << 1);
    pub const ADMIN: Self = Self(1 << 2);
    pub const DIAGNOSTICS_SENSITIVE: Self = Self(1 << 3);

    /// Applies the public hierarchy while keeping diagnostics-sensitive
    /// authority independent: admin grants control and read, and control
    /// grants read.
    pub const fn allows(self, required: Self) -> bool {
        let mut effective = self.0;
        if effective & Self::ADMIN.0 != 0 {
            effective |= Self::CONTROL.0 | Self::READ.0;
        }
        if effective & Self::CONTROL.0 != 0 {
            effective |= Self::READ.0;
        }
        effective & required.0 == required.0
    }

    pub(crate) const fn bits(self) -> u8 {
        self.0
    }

    pub(crate) fn from_bits(bits: u8) -> Result<Self, ApiScopeDecodeError> {
        if bits == 0 || bits & !0x0f != 0 {
            return Err(ApiScopeDecodeError);
        }
        Ok(Self(bits))
    }
}

impl BitOr for ApiScopes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ApiScopeDecodeError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiPrincipal {
    pub(crate) token_id: String,
    pub(crate) principal_ref: String,
    pub(crate) credential_revision: u64,
    pub(crate) scopes: ApiScopes,
    pub(crate) expires_at: Option<OffsetDateTime>,
}

/// Process-local authentication for the one token that starts an on-demand
/// daemon over SSH. The verifier and principal disappear with the process and
/// are never passed to durable storage.
#[derive(Clone)]
pub(crate) struct EphemeralApiAuthenticator {
    verifier: ApiTokenVerifier,
    principal: ApiPrincipal,
}

impl EphemeralApiAuthenticator {
    pub(crate) fn new(
        token: &ApiBearerToken,
        scopes: ApiScopes,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            verifier: token.verifier(),
            principal: ApiPrincipal {
                token_id: token.token_id().to_string(),
                principal_ref: "ssh-bootstrap".to_string(),
                credential_revision: 1,
                scopes,
                expires_at: Some(expires_at),
            },
        }
    }

    pub(crate) fn authenticate(
        &self,
        token: &ApiBearerToken,
        at: OffsetDateTime,
    ) -> Option<ApiPrincipal> {
        if token.token_id() != self.principal.token_id || at >= self.principal.expires_at? {
            return None;
        }
        let presented = token.verifier();
        bool::from(presented.as_bytes().ct_eq(self.verifier.as_bytes()))
            .then(|| self.principal.clone())
    }

    pub(crate) fn is_active(&self, principal: &ApiPrincipal, at: OffsetDateTime) -> bool {
        principal.token_id == self.principal.token_id
            && principal.principal_ref == self.principal.principal_ref
            && principal.credential_revision == self.principal.credential_revision
            && at < self.principal.expires_at.expect("ephemeral tokens expire")
    }
}

impl fmt::Debug for EphemeralApiAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralApiAuthenticator")
            .field("token_id", &self.principal.token_id)
            .field("expires_at", &self.principal.expires_at)
            .finish_non_exhaustive()
    }
}

impl ApiPrincipal {
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn scopes(&self) -> ApiScopes {
        self.scopes
    }

    pub const fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }
}

pub(crate) fn validate_token_id(value: &str) -> Result<(), ApiBearerTokenError> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiBearerTokenError::InvalidTokenId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN_ID: &str = "token-01890a5d-ac96-7b7c-8f89-37c3d0a66e31";

    #[test]
    fn generated_tokens_round_trip_without_debug_disclosure() {
        let token = ApiBearerToken::generate().expect("generate token");
        let exposed = token.expose();
        let reparsed = ApiBearerToken::parse(&exposed).expect("parse generated token");

        let mut segments = exposed.split('.');
        assert_eq!(segments.next(), Some(TOKEN_PREFIX));
        assert_eq!(segments.next(), Some(token.token_id()));
        let encoded_secret = segments.next().expect("token has a secret segment");
        assert!(segments.next().is_none());
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(encoded_secret)
                .expect("generated secret uses canonical base64url")
                .len(),
            TOKEN_SECRET_BYTES
        );
        let uuid = Uuid::parse_str(
            token
                .token_id()
                .strip_prefix("token-")
                .expect("generated token ID has the stable prefix"),
        )
        .expect("generated token ID contains a UUID");
        assert_eq!(uuid.get_version_num(), 7);

        assert_eq!(token.token_id(), reparsed.token_id());
        assert_eq!(token.verifier(), reparsed.verifier());
        assert!(!format!("{token:?}").contains(exposed.as_str()));
    }

    #[test]
    fn ephemeral_bootstrap_authentication_expires_without_durable_state() {
        let token = ApiBearerToken::generate().expect("generate bootstrap token");
        let expires_at = OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(15);
        let authenticator = EphemeralApiAuthenticator::new(&token, ApiScopes::CONTROL, expires_at);

        let principal = authenticator
            .authenticate(&token, OffsetDateTime::UNIX_EPOCH)
            .expect("bootstrap token authenticates before expiry");
        assert!(principal.scopes().allows(ApiScopes::READ));
        assert!(principal.scopes().allows(ApiScopes::CONTROL));
        assert!(authenticator.is_active(&principal, expires_at - time::Duration::SECOND));
        assert!(authenticator.authenticate(&token, expires_at).is_none());
        assert!(!authenticator.is_active(&principal, expires_at));
    }

    #[test]
    fn verifier_is_domain_separated_from_raw_secret_and_token_id() {
        let encoded_secret = URL_SAFE_NO_PAD.encode([0x2a_u8; TOKEN_SECRET_BYTES]);
        let first = ApiBearerToken::parse(&format!("{TOKEN_PREFIX}.{TOKEN_ID}.{encoded_secret}"))
            .expect("parse first token");
        let second = ApiBearerToken::parse(&format!(
            "{TOKEN_PREFIX}.token-01890a5d-ac96-7b7c-8f89-37c3d0a66e32.{encoded_secret}"
        ))
        .expect("parse second token");

        assert_ne!(first.verifier(), second.verifier());
        assert_ne!(first.verifier().as_bytes(), &[0x2a_u8; TOKEN_SECRET_BYTES]);
    }

    #[test]
    fn malformed_tokens_are_rejected_without_retaining_input() {
        for value in [
            "",
            "satelle_v1",
            "satelle_v1.bad.id.extra",
            "satelle_v1.bad.id",
            "satelle_v1.bad!id.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            let error = ApiBearerToken::parse(value).expect_err("reject malformed token");
            if !value.is_empty() {
                assert!(!error.to_string().contains(value));
            }
        }
    }

    #[test]
    fn scope_hierarchy_is_explicit_and_diagnostics_remains_additive() {
        for scope in [
            ApiScopes::READ,
            ApiScopes::CONTROL,
            ApiScopes::ADMIN,
            ApiScopes::DIAGNOSTICS_SENSITIVE,
        ] {
            assert_ne!(scope.bits(), 0);
            assert_eq!(ApiScopes::from_bits(scope.bits()), Ok(scope));
        }
        assert_eq!(ApiScopes::from_bits(0), Err(ApiScopeDecodeError));
        assert_eq!(ApiScopes::from_bits(0x10), Err(ApiScopeDecodeError));

        assert!(ApiScopes::CONTROL.allows(ApiScopes::READ));
        assert!(ApiScopes::ADMIN.allows(ApiScopes::CONTROL | ApiScopes::READ));
        assert!(!ApiScopes::READ.allows(ApiScopes::CONTROL));
        assert!(!ApiScopes::ADMIN.allows(ApiScopes::DIAGNOSTICS_SENSITIVE));
        assert!(
            (ApiScopes::ADMIN | ApiScopes::DIAGNOSTICS_SENSITIVE)
                .allows(ApiScopes::READ | ApiScopes::DIAGNOSTICS_SENSITIVE)
        );
    }
}
