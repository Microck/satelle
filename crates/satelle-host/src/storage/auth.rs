use super::codec::format_time;
use super::{StorageError, StorageErrorKind};
use crate::api_auth::{
    ApiBearerToken, ApiPrincipal, ApiScopes, ApiTokenVerifier, validate_token_id,
};
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use satelle_core::session::HostIdentityRef;
use sha2::Sha256;
use std::fmt;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zeroize::Zeroizing;

const SECRET_BYTES: usize = 32;
const MAX_SAFE_REFERENCE_BYTES: usize = 128;
const INITIAL_HMAC_KEY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiTokenState {
    Active,
    SetupPending,
    SetupActive,
}

impl ApiTokenState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::SetupPending => "setup_pending",
            Self::SetupActive => "setup_active",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "active" => Ok(Self::Active),
            "setup_pending" => Ok(Self::SetupPending),
            "setup_active" => Ok(Self::SetupActive),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }

    const fn authenticates(self) -> bool {
        matches!(self, Self::Active | Self::SetupActive)
    }
}

pub(crate) struct ApiTokenRegistration {
    token_id: String,
    principal_ref: String,
    credential_revision: u64,
    verifier: ApiTokenVerifier,
    scopes: ApiScopes,
    expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    token_state: ApiTokenState,
}

impl ApiTokenRegistration {
    pub(crate) fn new(
        token: &ApiBearerToken,
        principal_ref: impl Into<String>,
        credential_revision: u64,
        scopes: ApiScopes,
        expires_at: Option<OffsetDateTime>,
        created_at: OffsetDateTime,
    ) -> Result<Self, StorageError> {
        Self::new_with_state(
            token,
            principal_ref,
            credential_revision,
            scopes,
            expires_at,
            created_at,
            ApiTokenState::Active,
        )
    }

    pub(crate) fn new_setup_pending(
        token: &ApiBearerToken,
        principal_ref: impl Into<String>,
        credential_revision: u64,
        scopes: ApiScopes,
        pending_until: OffsetDateTime,
        created_at: OffsetDateTime,
    ) -> Result<Self, StorageError> {
        Self::new_with_state(
            token,
            principal_ref,
            credential_revision,
            scopes,
            Some(pending_until),
            created_at,
            ApiTokenState::SetupPending,
        )
    }

    fn new_with_state(
        token: &ApiBearerToken,
        principal_ref: impl Into<String>,
        credential_revision: u64,
        scopes: ApiScopes,
        expires_at: Option<OffsetDateTime>,
        created_at: OffsetDateTime,
        token_state: ApiTokenState,
    ) -> Result<Self, StorageError> {
        let principal_ref = principal_ref.into();
        validate_safe_reference(&principal_ref)?;
        if credential_revision == 0 || expires_at.is_some_and(|expires_at| expires_at <= created_at)
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        Ok(Self {
            token_id: token.token_id().to_string(),
            principal_ref,
            credential_revision,
            verifier: token.verifier(),
            scopes,
            expires_at,
            created_at,
            token_state,
        })
    }

    pub(crate) fn principal(&self) -> ApiPrincipal {
        ApiPrincipal {
            token_id: self.token_id.clone(),
            principal_ref: self.principal_ref.clone(),
            credential_revision: self.credential_revision,
            scopes: self.scopes,
            expires_at: self.expires_at,
            process_local_ssh_bootstrap: false,
            durable_setup_pending: self.token_state == ApiTokenState::SetupPending,
            durable_setup_active: self.token_state == ApiTokenState::SetupActive,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SensitiveRequestDigest {
    key_version: u16,
    hex: String,
}

impl SensitiveRequestDigest {
    pub(crate) const fn key_version(&self) -> u16 {
        self.key_version
    }

    pub(crate) fn hex(&self) -> &str {
        &self.hex
    }
}

impl fmt::Debug for SensitiveRequestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveRequestDigest")
            .field("key_version", &self.key_version)
            .finish_non_exhaustive()
    }
}

struct StoredTokenRow {
    token_id: String,
    principal_ref: String,
    credential_revision: i64,
    verifier: Vec<u8>,
    scopes: i64,
    created_at: String,
    credential_updated_at: String,
    expires_at: Option<String>,
    revoked_at: Option<String>,
    token_state: String,
}

impl StoredTokenRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            token_id: row.get(0)?,
            principal_ref: row.get(1)?,
            credential_revision: row.get(2)?,
            verifier: row.get(3)?,
            scopes: row.get(4)?,
            created_at: row.get(5)?,
            credential_updated_at: row.get(6)?,
            expires_at: row.get(7)?,
            revoked_at: row.get(8)?,
            token_state: row.get(9)?,
        })
    }

    fn validate(self) -> Result<StoredToken, StorageError> {
        validate_token_id(&self.token_id)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        validate_safe_reference(&self.principal_ref)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let credential_revision = u64::try_from(self.credential_revision)
            .ok()
            .filter(|revision| *revision > 0)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let verifier = self
            .verifier
            .try_into()
            .map(ApiTokenVerifier::from_stored)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let scopes = u8::try_from(self.scopes)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
            .and_then(|bits| {
                ApiScopes::from_bits(bits)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
            })?;
        let created_at = parse_stored_time(&self.created_at)?;
        let credential_updated_at = parse_stored_time(&self.credential_updated_at)?;
        let expires_at = self
            .expires_at
            .as_deref()
            .map(parse_stored_time)
            .transpose()?;
        let revoked_at = self
            .revoked_at
            .as_deref()
            .map(parse_stored_time)
            .transpose()?;
        let token_state = ApiTokenState::parse(&self.token_state)?;
        if credential_updated_at < created_at
            || expires_at.is_some_and(|expires_at| expires_at <= created_at)
            || revoked_at.is_some_and(|revoked_at| revoked_at < created_at)
            || (token_state == ApiTokenState::SetupPending && expires_at.is_none())
            || (token_state == ApiTokenState::SetupActive && expires_at.is_some())
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        Ok(StoredToken {
            token_id: self.token_id,
            principal_ref: self.principal_ref,
            credential_revision,
            verifier,
            scopes,
            created_at,
            expires_at,
            revoked_at,
            token_state,
        })
    }
}

struct StoredToken {
    token_id: String,
    principal_ref: String,
    credential_revision: u64,
    verifier: ApiTokenVerifier,
    scopes: ApiScopes,
    created_at: OffsetDateTime,
    expires_at: Option<OffsetDateTime>,
    revoked_at: Option<OffsetDateTime>,
    token_state: ApiTokenState,
}

impl StoredToken {
    fn principal(&self) -> ApiPrincipal {
        ApiPrincipal {
            token_id: self.token_id.clone(),
            principal_ref: self.principal_ref.clone(),
            credential_revision: self.credential_revision,
            scopes: self.scopes,
            expires_at: self.expires_at,
            process_local_ssh_bootstrap: false,
            durable_setup_pending: self.token_state == ApiTokenState::SetupPending,
            durable_setup_active: self.token_state == ApiTokenState::SetupActive,
        }
    }
}

/// Seeds sensitive singleton state only while the initial schema migration is
/// being committed. Reopening an existing database validates these rows and
/// fails closed instead of silently changing Host identity or key material.
pub(super) fn seed_sensitive_state(
    transaction: &Transaction<'_>,
    created_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let identity = format!("host-{}", Uuid::now_v7().hyphenated());
    let mut key = Zeroizing::new([0_u8; SECRET_BYTES]);
    getrandom::fill(key.as_mut())
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
    transaction
        .execute(
            "INSERT INTO daemon_identity (singleton, host_identity_ref, created_at) VALUES (1, ?1, ?2)",
            params![identity, format_time(created_at)?],
        )
        .map_err(operation_failed)?;
    transaction
        .execute(
            "INSERT INTO idempotency_hmac_keys (key_version, key_material, created_at) VALUES (?1, ?2, ?3)",
            params![
                i64::from(INITIAL_HMAC_KEY_VERSION),
                key.as_slice(),
                format_time(created_at)?,
            ],
        )
        .map_err(operation_failed)?;
    Ok(())
}

pub(super) fn validate_sensitive_state(connection: &Connection) -> Result<(), StorageError> {
    validate_sensitive_state_with_token_state(connection, true)
}

/// Migration 8 makes the historical implicit `active` state explicit. This
/// validator is used only before that migration is applied, so corrupt token
/// metadata still fails closed before any schema change is committed.
pub(super) fn validate_sensitive_state_before_token_state_migration(
    connection: &Connection,
) -> Result<(), StorageError> {
    validate_sensitive_state_with_token_state(connection, false)
}

fn validate_sensitive_state_with_token_state(
    connection: &Connection,
    token_state_is_stored: bool,
) -> Result<(), StorageError> {
    let identity_count: i64 = connection
        .query_row("SELECT count(*) FROM daemon_identity", [], |row| row.get(0))
        .map_err(operation_failed)?;
    if identity_count != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    host_identity(connection)?;

    let active_key_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM idempotency_hmac_keys WHERE retired_at IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(operation_failed)?;
    if active_key_count != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    let mut statement = connection
        .prepare(
            "SELECT key_version, key_material, created_at, retired_at FROM idempotency_hmac_keys ORDER BY key_version",
        )
        .map_err(operation_failed)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(operation_failed)?;
    for row in rows {
        let (version, material, created_at, retired_at) = row.map_err(operation_failed)?;
        if u16::try_from(version)
            .ok()
            .filter(|version| *version > 0)
            .is_none()
            || material.len() != SECRET_BYTES
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let created_at = parse_stored_time(&created_at)?;
        if retired_at
            .as_deref()
            .map(parse_stored_time)
            .transpose()?
            .is_some_and(|retired_at| retired_at < created_at)
        {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
    }
    let token_state = if token_state_is_stored {
        "token_state"
    } else {
        "'active' AS token_state"
    };
    let token_query = format!(
        "SELECT token_id, principal_ref, credential_revision, verifier, scopes, created_at, \
         credential_updated_at, expires_at, revoked_at, {token_state} \
         FROM api_tokens ORDER BY token_id"
    );
    let mut token_statement = connection.prepare(&token_query).map_err(operation_failed)?;
    let token_rows = token_statement
        .query_map([], StoredTokenRow::read)
        .map_err(operation_failed)?;
    for row in token_rows {
        row.map_err(operation_failed)?.validate()?;
    }
    Ok(())
}

pub(super) fn host_identity(connection: &Connection) -> Result<HostIdentityRef, StorageError> {
    let value: String = connection
        .query_row(
            "SELECT host_identity_ref FROM daemon_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|source| {
            StorageError::with_source(StorageErrorKind::InvalidStoredState, source)
        })?;
    HostIdentityRef::new(value).map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

pub(super) fn digest_idempotency_payload(
    connection: &Connection,
    canonical_payload: &[u8],
    requested_key_version: Option<u16>,
) -> Result<SensitiveRequestDigest, StorageError> {
    let (key_version, key): (i64, Vec<u8>) = match requested_key_version {
        Some(key_version) => connection.query_row(
            "SELECT key_version, key_material FROM idempotency_hmac_keys WHERE key_version = ?1",
            [i64::from(key_version)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ),
        None => connection.query_row(
            "SELECT key_version, key_material FROM idempotency_hmac_keys WHERE retired_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ),
    }
    .map_err(|source| StorageError::with_source(StorageErrorKind::InvalidStoredState, source))?;
    let key_version = u16::try_from(key_version)
        .ok()
        .filter(|version| *version > 0)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    if key.len() != SECRET_BYTES {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    let key = Zeroizing::new(key);
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_slice())
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    mac.update(canonical_payload);
    let digest = mac.finalize().into_bytes();
    Ok(SensitiveRequestDigest {
        key_version,
        hex: lowercase_hex(&digest),
    })
}

pub(super) fn rotate_idempotency_hmac_key(
    connection: &mut Connection,
    at: OffsetDateTime,
) -> Result<u16, StorageError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(operation_failed)?;
    let active_version: i64 = transaction
        .query_row(
            "SELECT key_version FROM idempotency_hmac_keys WHERE retired_at IS NULL",
            [],
            |row| row.get(0),
        )
        .map_err(|source| {
            StorageError::with_source(StorageErrorKind::InvalidStoredState, source)
        })?;
    let max_version: i64 = transaction
        .query_row(
            "SELECT max(key_version) FROM idempotency_hmac_keys",
            [],
            |row| row.get(0),
        )
        .map_err(operation_failed)?;
    let next_version = u16::try_from(max_version)
        .ok()
        .and_then(|version| version.checked_add(1))
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let mut key = Zeroizing::new([0_u8; SECRET_BYTES]);
    getrandom::fill(key.as_mut())
        .map_err(|source| StorageError::with_source(StorageErrorKind::OperationFailed, source))?;
    let formatted_at = format_time(at)?;
    let changed = transaction
        .execute(
            "UPDATE idempotency_hmac_keys SET retired_at = ?1 WHERE key_version = ?2 AND retired_at IS NULL",
            params![formatted_at, active_version],
        )
        .map_err(operation_failed)?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    transaction
        .execute(
            "INSERT INTO idempotency_hmac_keys (key_version, key_material, created_at) VALUES (?1, ?2, ?3)",
            params![i64::from(next_version), key.as_slice(), format_time(at)?],
        )
        .map_err(operation_failed)?;
    transaction.commit().map_err(operation_failed)?;
    Ok(next_version)
}

pub(super) fn register_api_token(
    connection: &mut Connection,
    registration: ApiTokenRegistration,
) -> Result<(), StorageError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(operation_failed)?;
    let stored = load_token(&transaction, &registration.token_id)?
        .map(StoredTokenRow::validate)
        .transpose()?;
    if let Some(stored) = stored {
        let same = stored.principal_ref == registration.principal_ref
            && stored.credential_revision == registration.credential_revision
            && bool::from(
                stored
                    .verifier
                    .as_bytes()
                    .ct_eq(registration.verifier.as_bytes()),
            )
            && stored.scopes == registration.scopes
            && stored.expires_at == registration.expires_at
            && stored.token_state == registration.token_state
            && stored.revoked_at.is_none();
        if !same {
            return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
        }
        transaction.commit().map_err(operation_failed)?;
        return Ok(());
    }

    let created_at = format_time(registration.created_at)?;
    transaction
        .execute(
            "INSERT INTO api_tokens (token_id, principal_ref, credential_revision, verifier, scopes, created_at, credential_updated_at, expires_at, token_state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                registration.token_id,
                registration.principal_ref,
                i64::try_from(registration.credential_revision)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?,
                registration.verifier.as_bytes().as_slice(),
                i64::from(registration.scopes.bits()),
                created_at,
                format_time(registration.created_at)?,
                registration.expires_at.map(format_time).transpose()?,
                registration.token_state.as_str(),
            ],
        )
        .map_err(operation_failed)?;
    transaction.commit().map_err(operation_failed)
}

pub(super) fn authenticate_api_token(
    connection: &Connection,
    token_id: &str,
    supplied_verifier: &ApiTokenVerifier,
    at: OffsetDateTime,
) -> Result<Option<ApiPrincipal>, StorageError> {
    authenticate_api_token_for_state(
        connection,
        token_id,
        supplied_verifier,
        at,
        ApiTokenState::authenticates,
    )
}

pub(super) fn authenticate_pending_setup_api_token(
    connection: &Connection,
    token_id: &str,
    supplied_verifier: &ApiTokenVerifier,
    at: OffsetDateTime,
) -> Result<Option<ApiPrincipal>, StorageError> {
    authenticate_api_token_for_state(connection, token_id, supplied_verifier, at, |state| {
        state == ApiTokenState::SetupPending
    })
}

fn authenticate_api_token_for_state(
    connection: &Connection,
    token_id: &str,
    supplied_verifier: &ApiTokenVerifier,
    at: OffsetDateTime,
    state_authenticates: impl FnOnce(ApiTokenState) -> bool,
) -> Result<Option<ApiPrincipal>, StorageError> {
    validate_token_id(token_id).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let stored = load_token(connection, token_id)?
        .map(StoredTokenRow::validate)
        .transpose()?;
    let comparison_verifier = stored
        .as_ref()
        .map_or_else(ApiTokenVerifier::dummy, |stored| stored.verifier.clone());
    let verifier_matches: bool = comparison_verifier
        .as_bytes()
        .ct_eq(supplied_verifier.as_bytes())
        .into();
    let Some(stored) = stored else {
        return Ok(None);
    };
    if !verifier_matches
        || stored.revoked_at.is_some()
        || !state_authenticates(stored.token_state)
        || stored.expires_at.is_some_and(|expires_at| expires_at <= at)
    {
        return Ok(None);
    }
    Ok(Some(stored.principal()))
}

pub(super) fn api_principal_is_active(
    connection: &Connection,
    principal: &ApiPrincipal,
    at: OffsetDateTime,
) -> Result<bool, StorageError> {
    let stored = load_token(connection, principal.token_id())?
        .map(StoredTokenRow::validate)
        .transpose()?;
    Ok(stored.is_some_and(|stored| {
        stored.revoked_at.is_none()
            && stored.token_state.authenticates()
            && stored.expires_at.is_none_or(|expires_at| expires_at > at)
            && stored.token_id == principal.token_id
            && stored.principal_ref == principal.principal_ref
            && stored.credential_revision == principal.credential_revision
            && stored.scopes == principal.scopes
            && stored.expires_at == principal.expires_at
    }))
}

pub(super) fn rotate_api_token(
    connection: &mut Connection,
    replacement: &ApiBearerToken,
    expected_credential_revision: u64,
    at: OffsetDateTime,
) -> Result<ApiPrincipal, StorageError> {
    if expected_credential_revision == 0 {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(operation_failed)?;
    let stored = load_token(&transaction, replacement.token_id())?
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?
        .validate()?;
    if stored.revoked_at.is_some()
        || !stored.token_state.authenticates()
        || stored.credential_revision != expected_credential_revision
    {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    let replacement_verifier = replacement.verifier();
    if bool::from(
        stored
            .verifier
            .as_bytes()
            .ct_eq(replacement_verifier.as_bytes()),
    ) {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    let next_revision = expected_credential_revision
        .checked_add(1)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    let changed = transaction
        .execute(
            "UPDATE api_tokens SET credential_revision = ?1, verifier = ?2, credential_updated_at = ?3 WHERE token_id = ?4 AND credential_revision = ?5 AND revoked_at IS NULL",
            params![
                i64::try_from(next_revision)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                replacement_verifier.as_bytes().as_slice(),
                format_time(at)?,
                replacement.token_id(),
                i64::try_from(expected_credential_revision)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?,
            ],
        )
        .map_err(operation_failed)?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    transaction.commit().map_err(operation_failed)?;
    Ok(ApiPrincipal {
        token_id: stored.token_id,
        principal_ref: stored.principal_ref,
        credential_revision: next_revision,
        scopes: stored.scopes,
        expires_at: stored.expires_at,
        process_local_ssh_bootstrap: false,
        durable_setup_pending: false,
        durable_setup_active: stored.token_state == ApiTokenState::SetupActive,
    })
}

pub(super) fn activate_api_token(
    connection: &mut Connection,
    token_id: &str,
    at: OffsetDateTime,
) -> Result<ApiPrincipal, StorageError> {
    validate_token_id(token_id).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(operation_failed)?;
    let stored = load_token(&transaction, token_id)?
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?
        .validate()?;
    if at < stored.created_at || stored.revoked_at.is_some() {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    if stored.token_state == ApiTokenState::SetupActive {
        return Ok(stored.principal());
    }
    if stored.token_state != ApiTokenState::SetupPending
        || stored.expires_at.is_none_or(|expires_at| expires_at <= at)
    {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    let changed = transaction
        .execute(
            "UPDATE api_tokens SET expires_at = NULL, token_state = 'setup_active', credential_updated_at = ?1 WHERE token_id = ?2 AND token_state = 'setup_pending' AND expires_at IS NOT NULL AND revoked_at IS NULL",
            params![format_time(at)?, token_id],
        )
        .map_err(operation_failed)?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    transaction.commit().map_err(operation_failed)?;
    Ok(ApiPrincipal {
        token_id: stored.token_id,
        principal_ref: stored.principal_ref,
        credential_revision: stored.credential_revision,
        scopes: stored.scopes,
        expires_at: None,
        process_local_ssh_bootstrap: false,
        durable_setup_pending: false,
        durable_setup_active: true,
    })
}

pub(super) fn abort_setup_api_token(
    connection: &mut Connection,
    token_id: &str,
    at: OffsetDateTime,
) -> Result<(), StorageError> {
    validate_token_id(token_id).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(operation_failed)?;
    let stored = load_token(&transaction, token_id)?
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?
        .validate()?;
    if !matches!(
        stored.token_state,
        ApiTokenState::SetupPending | ApiTokenState::SetupActive
    ) {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    if at < stored.created_at {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    if stored.revoked_at.is_some() {
        return Ok(());
    }
    let changed = transaction
        .execute(
            "UPDATE api_tokens SET revoked_at = ?1 WHERE token_id = ?2 AND token_state IN ('setup_pending', 'setup_active') AND revoked_at IS NULL",
            params![format_time(at)?, token_id],
        )
        .map_err(operation_failed)?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::StateConflict));
    }
    transaction.commit().map_err(operation_failed)?;
    Ok(())
}

pub(super) fn revoke_api_token(
    connection: &mut Connection,
    token_id: &str,
    at: OffsetDateTime,
) -> Result<(), StorageError> {
    validate_token_id(token_id).map_err(|_| StorageError::new(StorageErrorKind::InvalidInput))?;
    let changed = connection
        .execute(
            "UPDATE api_tokens SET revoked_at = ?1 WHERE token_id = ?2 AND revoked_at IS NULL",
            params![format_time(at)?, token_id],
        )
        .map_err(operation_failed)?;
    if changed != 1 {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

fn load_token(
    connection: &Connection,
    token_id: &str,
) -> Result<Option<StoredTokenRow>, StorageError> {
    connection
        .query_row(
            "SELECT token_id, principal_ref, credential_revision, verifier, scopes, created_at, credential_updated_at, expires_at, revoked_at, token_state FROM api_tokens WHERE token_id = ?1",
            [token_id],
            StoredTokenRow::read,
        )
        .optional()
        .map_err(operation_failed)
}

fn parse_stored_time(value: &str) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
}

fn validate_safe_reference(value: &str) -> Result<(), StorageError> {
    if value.is_empty()
        || value.len() > MAX_SAFE_REFERENCE_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn operation_failed(source: rusqlite::Error) -> StorageError {
    StorageError::with_source(StorageErrorKind::OperationFailed, source)
}
