use super::codec::{format_time, idempotent_operation_token};
use super::sql::{ensure_control_lease_available, insert_idempotency, matching_idempotency};
use super::{
    IdempotencyInput, IdempotentOperation, LeaseOwner, Storage, StorageError, StorageErrorKind,
    sqlite_error,
};
use crate::{
    ReadinessCacheKey,
    runtime_adapter::{ProviderSmokeEvidence, ReadinessEvidence},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use satelle_core::session::{DesktopBindingRef, HostIdentityRef};
use satelle_core::{
    ProviderBindingAuthorization, ProviderBindingSource, ProviderSecretSource,
    PublicResolvedProviderBinding, ResolvedProviderBinding, SatelleError,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const PENDING_OUTCOME: &str = "v1.provider_secret_provisioning.pending";
const COMPLETED_OUTCOME: &str = "v1.provider_secret_provisioning.completed";
const FAILED_OUTCOME: &str = "v1.provider_secret_provisioning.failed";
pub(crate) const PROVIDER_SECRET_CANDIDATE_HMAC_DOMAIN: &[u8] =
    b"satelle.provider-secret-provisioning.candidate.v1\0";
pub(crate) const PROVIDER_SECRET_PRIOR_HMAC_DOMAIN: &[u8] =
    b"satelle.provider-secret-provisioning.prior.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderSecretProvisioningPhase {
    Planned,
    Staged,
    Validated,
    PublishIntent,
    Committed,
    RollbackPending,
}

impl ProviderSecretProvisioningPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Staged => "staged",
            Self::Validated => "validated",
            Self::PublishIntent => "publish_intent",
            Self::Committed => "committed",
            Self::RollbackPending => "rollback_pending",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "planned" => Ok(Self::Planned),
            "staged" => Ok(Self::Staged),
            "validated" => Ok(Self::Validated),
            "publish_intent" => Ok(Self::PublishIntent),
            "committed" => Ok(Self::Committed),
            "rollback_pending" => Ok(Self::RollbackPending),
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }

    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Staged, Self::Validated)
                | (Self::Validated, Self::PublishIntent)
        )
    }
}

#[derive(Clone)]
pub(crate) struct ProviderSecretProvisioningPlan {
    host_identity: HostIdentityRef,
    desktop_binding: DesktopBindingRef,
    provider_probe_ref: String,
    binding: ResolvedProviderBinding,
    destination_path: PathBuf,
    staged_path: PathBuf,
    expected_previous_binding_digest: Option<String>,
    candidate_secret_hmac: String,
}

impl ProviderSecretProvisioningPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        host_identity: HostIdentityRef,
        desktop_binding: DesktopBindingRef,
        provider_probe_ref: impl Into<String>,
        binding: ResolvedProviderBinding,
        destination_path: PathBuf,
        staged_path: PathBuf,
        expected_previous_binding_digest: Option<String>,
        candidate_secret_hmac: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let provider_probe_ref = validated_reference(provider_probe_ref.into())?;
        validate_binding_file_destination(&binding, &destination_path)?;
        validate_planned_paths(&destination_path, &staged_path)?;
        if let Some(digest) = expected_previous_binding_digest.as_deref() {
            validate_digest(digest)?;
        }
        let candidate_secret_hmac = candidate_secret_hmac.into();
        validate_digest(&candidate_secret_hmac)?;
        Ok(Self {
            host_identity,
            desktop_binding,
            provider_probe_ref,
            binding,
            destination_path,
            staged_path,
            expected_previous_binding_digest,
            candidate_secret_hmac,
        })
    }
}

impl fmt::Debug for ProviderSecretProvisioningPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecretProvisioningPlan")
            .field("host_identity", &self.host_identity)
            .field("desktop_binding", &self.desktop_binding)
            .field("provider_probe_ref", &"[redacted]")
            .field("binding", &PublicResolvedProviderBinding::from(&self.binding))
            .field("destination_path", &"[redacted]")
            .field("staged_path", &"[redacted]")
            .field("candidate_secret_hmac", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct ProviderSecretProvisioningJournal {
    operation_id: String,
    host_identity: HostIdentityRef,
    desktop_binding: DesktopBindingRef,
    provider_probe_ref: String,
    binding: ResolvedProviderBinding,
    destination_path: PathBuf,
    staged_path: PathBuf,
    backup_path: Option<PathBuf>,
    destination_existed: Option<bool>,
    expected_previous_binding_digest: Option<String>,
    candidate_secret_hmac: String,
    prior_secret_hmac: Option<String>,
    phase: ProviderSecretProvisioningPhase,
}

impl ProviderSecretProvisioningJournal {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn host_identity(&self) -> &HostIdentityRef {
        &self.host_identity
    }

    pub(crate) fn desktop_binding(&self) -> &DesktopBindingRef {
        &self.desktop_binding
    }

    pub(crate) fn provider_probe_ref(&self) -> &str {
        &self.provider_probe_ref
    }

    pub(crate) fn binding(&self) -> &ResolvedProviderBinding {
        &self.binding
    }

    pub(crate) fn destination_path(&self) -> &Path {
        &self.destination_path
    }

    pub(crate) fn staged_path(&self) -> &Path {
        &self.staged_path
    }

    pub(crate) fn backup_path(&self) -> Option<&Path> {
        self.backup_path.as_deref()
    }

    pub(crate) const fn destination_existed(&self) -> Option<bool> {
        self.destination_existed
    }

    pub(crate) fn expected_previous_binding_digest(&self) -> Option<&str> {
        self.expected_previous_binding_digest.as_deref()
    }

    pub(crate) const fn phase(&self) -> ProviderSecretProvisioningPhase {
        self.phase
    }

    /// Checks already keyed, domain-separated HMAC values. Raw secret bytes
    /// never enter the storage layer.
    pub(crate) fn verify_secret_hmacs(
        &self,
        candidate_secret_hmac: &str,
        prior_secret_hmac: Option<&str>,
    ) -> Result<bool, StorageError> {
        validate_digest(candidate_secret_hmac)?;
        if let Some(hmac) = prior_secret_hmac {
            validate_digest(hmac)?;
        }
        Ok(self.candidate_secret_hmac == candidate_secret_hmac
            && self.prior_secret_hmac.as_deref() == prior_secret_hmac)
    }
}

impl fmt::Debug for ProviderSecretProvisioningJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSecretProvisioningJournal")
            .field("operation_id", &"[redacted]")
            .field("host_identity", &self.host_identity)
            .field("desktop_binding", &self.desktop_binding)
            .field("provider_probe_ref", &"[redacted]")
            .field("binding", &PublicResolvedProviderBinding::from(&self.binding))
            .field("paths", &"[redacted]")
            .field("destination_existed", &self.destination_existed)
            .field("phase", &self.phase)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "status", content = "result", rename_all = "snake_case")]
pub(crate) enum ProviderSecretProvisioningReplay {
    Completed(PublicResolvedProviderBinding),
    Failed(SatelleError),
}

pub(crate) enum BeginProviderSecretProvisioning {
    Claimed(ProviderSecretProvisioningJournal),
    Resume(ProviderSecretProvisioningJournal),
    Replay(ProviderSecretProvisioningReplay),
}

impl Storage {
    pub(crate) fn begin_provider_secret_provisioning(
        &mut self,
        idempotency: &IdempotencyInput,
        key: &ReadinessCacheKey,
        owner: &LeaseOwner,
        plan: ProviderSecretProvisioningPlan,
    ) -> Result<BeginProviderSecretProvisioning, StorageError> {
        super::sql::require_operation(
            idempotency,
            IdempotentOperation::ProviderSecretProvisioning,
        )?;
        if idempotency.operation_id != owner.operation_id
            || plan.host_identity != self.host_identity()?
            || &plan.desktop_binding != key.desktop_binding()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let outcome = match (
                record.status.as_str(),
                record.durable_outcome.as_str(),
                record.result_json,
            ) {
                ("in_progress", PENDING_OUTCOME, None) => {
                    BeginProviderSecretProvisioning::Resume(load_journal(
                        &transaction,
                        &idempotency.operation_id,
                    )?)
                }
                (
                    "terminal",
                    COMPLETED_OUTCOME | FAILED_OUTCOME,
                    Some(result_json),
                ) => BeginProviderSecretProvisioning::Replay(
                    serde_json::from_str(&result_json)
                        .map_err(|_| invalid_stored_state())?,
                ),
                _ => return Err(invalid_stored_state()),
            };
            transaction.commit().map_err(operation_failed)?;
            return Ok(outcome);
        }

        ensure_control_lease_available(
            &transaction,
            &plan.host_identity,
            &plan.desktop_binding,
        )?;
        insert_idempotency(
            &transaction,
            idempotency,
            "in_progress",
            PENDING_OUTCOME,
            None,
            None,
            None,
        )?;
        insert_provider_probe_lease(&transaction, &plan, owner)?;
        insert_journal(
            &transaction,
            idempotency.operation_id.as_str(),
            &plan,
            idempotency.created_at,
        )?;
        let journal = load_journal(&transaction, idempotency.operation_id.as_str())?;
        transaction.commit().map_err(operation_failed)?;
        Ok(BeginProviderSecretProvisioning::Claimed(journal))
    }

    pub(crate) fn transition_provider_secret_provisioning(
        &mut self,
        operation_id: &str,
        expected: ProviderSecretProvisioningPhase,
        next: ProviderSecretProvisioningPhase,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        if !expected.permits(next) {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        update_phase(
            &self.connection,
            operation_id,
            expected,
            next,
            at,
        )
    }

    pub(crate) fn record_staged_provider_secret(
        &mut self,
        operation_id: &str,
        destination_existed: bool,
        backup_path: Option<&Path>,
        prior_secret_hmac: Option<&str>,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        if let Some(hmac) = prior_secret_hmac {
            validate_digest(hmac)?;
        }
        let journal = load_journal(&self.connection, operation_id)?;
        if journal.phase != ProviderSecretProvisioningPhase::Planned
            || destination_existed != backup_path.is_some()
            || destination_existed != prior_secret_hmac.is_some()
        {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        if let Some(backup_path) = backup_path {
            validate_staged_paths(
                &journal.destination_path,
                &journal.staged_path,
                Some(backup_path),
            )?;
        }
        require_phase_update(
            self.connection
                .execute(
                    "UPDATE provider_secret_provisioning_journal
                     SET destination_existed = ?1, backup_path = ?2,
                         prior_secret_hmac = ?3, phase = 'staged', updated_at = ?4
                     WHERE operation_id = ?5
                       AND phase = 'planned'
                       AND destination_existed IS NULL
                       AND backup_path IS NULL
                       AND prior_secret_hmac IS NULL",
                    params![
                        i64::from(destination_existed),
                        backup_path.map(path_text).transpose()?,
                        prior_secret_hmac,
                        format_time(at)?,
                        operation_id,
                    ],
                )
                .map_err(operation_failed)?,
        )
    }

    pub(crate) fn mark_provider_secret_provisioning_rollback_pending(
        &mut self,
        operation_id: &str,
        expected: ProviderSecretProvisioningPhase,
        at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        if !matches!(
            expected,
            ProviderSecretProvisioningPhase::Staged
                | ProviderSecretProvisioningPhase::Validated
                | ProviderSecretProvisioningPhase::PublishIntent
        ) {
            return Err(StorageError::new(StorageErrorKind::InvalidInput));
        }
        update_phase(
            &self.connection,
            operation_id,
            expected,
            ProviderSecretProvisioningPhase::RollbackPending,
            at,
        )
    }

    /// T3 records publication and authorization as one SQLite transaction.
    /// The lease, journal, and pending replay remain until filesystem cleanup
    /// and parent-directory fsync complete at T4.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_provider_secret_provisioning(
        &mut self,
        operation_id: &str,
        binding: &ResolvedProviderBinding,
        expected_previous_digest: Option<&str>,
        key: &ReadinessCacheKey,
        readiness: &ReadinessEvidence,
        provider: Option<&ProviderSmokeEvidence>,
        committed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        let journal = load_journal(&transaction, operation_id)?;
        if journal.phase != ProviderSecretProvisioningPhase::PublishIntent
            || journal.binding.binding_digest() != binding.binding_digest()
            || journal.expected_previous_binding_digest.as_deref() != expected_previous_digest
            || journal.desktop_binding != *key.desktop_binding()
            || binding.experimental_provider_computer_use() != provider.is_some()
        {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let owns_probe: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM control_leases
                    WHERE operation_id = ?1
                      AND owner_kind = 'provider_probe'
                      AND provider_probe_ref = ?2
                      AND lease_state = 'active'
                 )",
                params![operation_id, journal.provider_probe_ref.as_str()],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        if owns_probe != 1 {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let current_digest = Self::provider_binding_digest_in_connection(
            &transaction,
            binding.requested_model_alias(),
            binding.requested_provider_alias(),
        )?;
        if current_digest.as_deref() != expected_previous_digest {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        Self::authorize_provider_binding_in_connection(&transaction, binding, committed_at)?;
        super::operational::insert_provider_provisioning_success(
            &transaction,
            journal.host_identity.as_str(),
            key,
            readiness,
            provider,
        )?;
        require_phase_update(
            transaction
                .execute(
                    "UPDATE provider_secret_provisioning_journal
                     SET phase = 'committed', updated_at = ?2
                     WHERE operation_id = ?1 AND phase = 'publish_intent'",
                    params![operation_id, format_time(committed_at)?],
                )
                .map_err(operation_failed)?,
        )?;
        transaction.commit().map_err(operation_failed)
    }

    /// T4 is called only after backup/staged artifact cleanup and a successful
    /// parent-directory fsync.
    pub(crate) fn finish_provider_secret_provisioning_success(
        &mut self,
        operation_id: &str,
        completed_at: OffsetDateTime,
    ) -> Result<ProviderSecretProvisioningReplay, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        let journal = load_journal(&transaction, operation_id)?;
        if journal.phase != ProviderSecretProvisioningPhase::Committed {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let replay = ProviderSecretProvisioningReplay::Completed(
            PublicResolvedProviderBinding::from(&journal.binding),
        );
        terminalize(
            &transaction,
            operation_id,
            COMPLETED_OUTCOME,
            &replay,
            &journal.provider_probe_ref,
            completed_at,
        )?;
        transaction.commit().map_err(operation_failed)?;
        Ok(replay)
    }

    pub(crate) fn finish_provider_secret_provisioning_failure(
        &mut self,
        operation_id: &str,
        error: SatelleError,
        completed_at: OffsetDateTime,
    ) -> Result<ProviderSecretProvisioningReplay, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        let journal = load_journal(&transaction, operation_id)?;
        if !matches!(
            journal.phase,
            ProviderSecretProvisioningPhase::Planned
                | ProviderSecretProvisioningPhase::RollbackPending
        ) {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let replay = ProviderSecretProvisioningReplay::Failed(error);
        terminalize(
            &transaction,
            operation_id,
            FAILED_OUTCOME,
            &replay,
            &journal.provider_probe_ref,
            completed_at,
        )?;
        transaction.commit().map_err(operation_failed)?;
        Ok(replay)
    }

    pub(crate) fn provider_secret_provisioning_replay(
        &self,
        idempotency: &IdempotencyInput,
    ) -> Result<Option<ProviderSecretProvisioningReplay>, StorageError> {
        super::sql::require_operation(
            idempotency,
            IdempotentOperation::ProviderSecretProvisioning,
        )?;
        let Some(record) = matching_idempotency(&self.connection, idempotency)? else {
            return Ok(None);
        };
        match (
            record.status.as_str(),
            record.durable_outcome.as_str(),
            record.result_json,
        ) {
            ("in_progress", PENDING_OUTCOME, None) => Ok(None),
            ("terminal", COMPLETED_OUTCOME | FAILED_OUTCOME, Some(result_json)) => {
                serde_json::from_str(&result_json)
                    .map(Some)
                    .map_err(|_| invalid_stored_state())
            }
            _ => Err(invalid_stored_state()),
        }
    }

    pub(crate) fn pending_provider_secret_provisionings(
        &self,
    ) -> Result<Vec<ProviderSecretProvisioningJournal>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT operation_id
                 FROM provider_secret_provisioning_journal
                 ORDER BY created_at, operation_id",
            )
            .map_err(operation_failed)?;
        let operation_ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(operation_failed)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(operation_failed)?;
        operation_ids
            .iter()
            .map(|operation_id| load_journal(&self.connection, operation_id))
            .collect()
    }

    pub(crate) fn prune_provider_secret_provisioning_journal(
        &mut self,
        observed_at: OffsetDateTime,
    ) -> Result<u64, StorageError> {
        let deleted = self
            .connection
            .execute(
                "DELETE FROM provider_secret_provisioning_journal
                 WHERE operation_id IN (
                     SELECT operation_id
                     FROM idempotency_records
                     WHERE operation = 'provider_secret_provisioning'
                       AND status = 'terminal'
                       AND expires_at <= ?1
                 )",
                [format_time(observed_at)?],
            )
            .map_err(operation_failed)?;
        u64::try_from(deleted).map_err(|_| invalid_stored_state())
    }
}

fn insert_provider_probe_lease(
    transaction: &rusqlite::Transaction<'_>,
    plan: &ProviderSecretProvisioningPlan,
    owner: &LeaseOwner,
) -> Result<(), StorageError> {
    transaction
        .execute(
            "INSERT INTO control_leases (
                host_identity_ref, desktop_binding_ref, operation_id,
                owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                acquired_at, heartbeat_at, lease_state, owner_kind, provider_probe_ref
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active',
                       'provider_probe', ?8)",
            params![
                plan.host_identity.as_str(),
                plan.desktop_binding.as_str(),
                owner.operation_id.as_str(),
                i64::from(owner.process_id),
                owner.process_start_ref.as_str(),
                owner.boot_identity_ref.as_str(),
                format_time(owner.acquired_at)?,
                plan.provider_probe_ref.as_str(),
            ],
        )
        .map_err(|source| sqlite_error(StorageErrorKind::LeaseConflict, source))?;
    Ok(())
}

fn insert_journal(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: &str,
    plan: &ProviderSecretProvisioningPlan,
    created_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let auth_source_json = serde_json::to_string(
        plan.binding
            .auth_source()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?,
    )
    .map_err(operation_failed)?;
    transaction
        .execute(
            "INSERT INTO provider_secret_provisioning_journal (
                operation_id, host_identity_ref, desktop_binding_ref, provider_probe_ref,
                requested_model_alias, requested_provider_alias, model, model_provider,
                endpoint, auth_source_json, experimental_provider_computer_use,
                allow_project_selection, destination_path, staged_path, backup_path,
                destination_existed, expected_previous_binding_digest,
                candidate_binding_digest, candidate_secret_hmac, prior_secret_hmac,
                phase, created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, 'planned', ?21, ?21
             )",
            params![
                operation_id,
                plan.host_identity.as_str(),
                plan.desktop_binding.as_str(),
                plan.provider_probe_ref.as_str(),
                plan.binding.requested_model_alias(),
                plan.binding.requested_provider_alias(),
                plan.binding.model(),
                plan.binding.model_provider(),
                plan.binding.endpoint(),
                auth_source_json,
                i64::from(plan.binding.experimental_provider_computer_use()),
                i64::from(plan.binding.allow_project_selection()),
                path_text(&plan.destination_path)?,
                path_text(&plan.staged_path)?,
                Option::<&str>::None,
                Option::<i64>::None,
                plan.expected_previous_binding_digest.as_deref(),
                plan.binding.binding_digest(),
                plan.candidate_secret_hmac.as_str(),
                Option::<&str>::None,
                format_time(created_at)?,
            ],
        )
        .map_err(operation_failed)?;
    Ok(())
}

fn load_journal(
    connection: &rusqlite::Connection,
    operation_id: &str,
) -> Result<ProviderSecretProvisioningJournal, StorageError> {
    let row = connection
        .query_row(
            "SELECT host_identity_ref, desktop_binding_ref, provider_probe_ref,
                    requested_model_alias, requested_provider_alias, model, model_provider,
                    endpoint, auth_source_json, experimental_provider_computer_use,
                    allow_project_selection, destination_path, staged_path, backup_path,
                    destination_existed, expected_previous_binding_digest,
                    candidate_binding_digest, candidate_secret_hmac, prior_secret_hmac, phase
             FROM provider_secret_provisioning_journal
             WHERE operation_id = ?1 AND operation = 'provider_secret_provisioning'",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, Option<String>>(18)?,
                    row.get::<_, String>(19)?,
                ))
            },
        )
        .optional()
        .map_err(operation_failed)?
        .ok_or_else(invalid_stored_state)?;
    let (
        host_identity,
        desktop_binding,
        provider_probe_ref,
        model_alias,
        provider_alias,
        model,
        model_provider,
        endpoint,
        auth_source_json,
        experimental,
        allow_project_selection,
        destination_path,
        staged_path,
        backup_path,
        destination_existed,
        expected_previous_binding_digest,
        candidate_binding_digest,
        candidate_secret_hmac,
        prior_secret_hmac,
        phase,
    ) = row;
    if !matches!(experimental, 0 | 1)
        || !matches!(allow_project_selection, 0 | 1)
        || !matches!(destination_existed, 0 | 1)
    {
        return Err(invalid_stored_state());
    }
    let auth_source: ProviderSecretSource =
        serde_json::from_str(&auth_source_json).map_err(|_| invalid_stored_state())?;
    let destination_path = PathBuf::from(destination_path);
    if !matches!(&auth_source, ProviderSecretSource::File { path } if path == &destination_path) {
        return Err(invalid_stored_state());
    }
    let mut authorization =
        ProviderBindingAuthorization::new(model_alias, provider_alias, model, model_provider)
            .with_auth_source(auth_source)
            .with_allow_project_selection(allow_project_selection == 1)
            .with_experimental_provider_computer_use(experimental == 1);
    if let Some(endpoint) = endpoint {
        authorization = authorization.with_endpoint(endpoint);
    }
    let binding = ResolvedProviderBinding::from_authorization(
        authorization,
        ProviderBindingSource::UserConfig,
    );
    if binding.binding_digest() != candidate_binding_digest {
        return Err(invalid_stored_state());
    }
    let journal = ProviderSecretProvisioningJournal {
        operation_id: validated_reference(operation_id.to_string())
            .map_err(|_| invalid_stored_state())?,
        host_identity: HostIdentityRef::new(host_identity).map_err(|_| invalid_stored_state())?,
        desktop_binding: DesktopBindingRef::new(desktop_binding)
            .map_err(|_| invalid_stored_state())?,
        provider_probe_ref: validated_reference(provider_probe_ref)
            .map_err(|_| invalid_stored_state())?,
        binding,
        destination_path,
        staged_path: PathBuf::from(staged_path),
        backup_path: backup_path.map(PathBuf::from),
        destination_existed: destination_existed.map(|value| value == 1),
        expected_previous_binding_digest,
        candidate_secret_hmac,
        prior_secret_hmac,
        phase: ProviderSecretProvisioningPhase::parse(&phase)?,
    };
    validate_planned_paths(&journal.destination_path, &journal.staged_path)
        .map_err(|_| invalid_stored_state())?;
    match journal.phase {
        ProviderSecretProvisioningPhase::Planned => {
            if journal.destination_existed.is_some()
                || journal.backup_path.is_some()
                || journal.prior_secret_hmac.is_some()
            {
                return Err(invalid_stored_state());
            }
        }
        _ => match journal.destination_existed {
            Some(true)
                if journal.backup_path.is_some() && journal.prior_secret_hmac.is_some() =>
            {
                validate_staged_paths(
                    &journal.destination_path,
                    &journal.staged_path,
                    journal.backup_path.as_deref(),
                )
                .map_err(|_| invalid_stored_state())?;
            }
            Some(false)
                if journal.backup_path.is_none() && journal.prior_secret_hmac.is_none() => {}
            _ => return Err(invalid_stored_state()),
        },
    }
    journal
        .verify_secret_hmacs(
            &journal.candidate_secret_hmac,
            journal.prior_secret_hmac.as_deref(),
        )
        .map_err(|_| invalid_stored_state())?;
    Ok(journal)
}

fn update_phase(
    connection: &rusqlite::Connection,
    operation_id: &str,
    expected: ProviderSecretProvisioningPhase,
    next: ProviderSecretProvisioningPhase,
    at: OffsetDateTime,
) -> Result<(), StorageError> {
    require_phase_update(
        connection
            .execute(
                "UPDATE provider_secret_provisioning_journal
                 SET phase = ?1, updated_at = ?2
                 WHERE operation_id = ?3 AND phase = ?4",
                params![next.as_str(), format_time(at)?, operation_id, expected.as_str()],
            )
            .map_err(operation_failed)?,
    )
}

fn terminalize(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: &str,
    durable_outcome: &str,
    replay: &ProviderSecretProvisioningReplay,
    provider_probe_ref: &str,
    completed_at: OffsetDateTime,
) -> Result<(), StorageError> {
    let result_json = serde_json::to_string(replay).map_err(operation_failed)?;
    require_phase_update(
        transaction
            .execute(
                "UPDATE idempotency_records
                 SET status = 'terminal', durable_outcome = ?1, result_json = ?2,
                     completed_at = ?3
                 WHERE operation_id = ?4
                   AND operation = 'provider_secret_provisioning'
                   AND status = 'in_progress'
                   AND durable_outcome = 'v1.provider_secret_provisioning.pending'",
                params![
                    durable_outcome,
                    result_json,
                    format_time(completed_at)?,
                    operation_id,
                ],
            )
            .map_err(operation_failed)?,
    )?;
    require_phase_update(
        transaction
            .execute(
                "DELETE FROM control_leases
                 WHERE operation_id = ?1
                   AND owner_kind = 'provider_probe'
                   AND provider_probe_ref = ?2",
                params![operation_id, provider_probe_ref],
            )
            .map_err(operation_failed)?,
    )?;
    require_phase_update(
        transaction
            .execute(
                "DELETE FROM provider_secret_provisioning_journal
                 WHERE operation_id = ?1",
                [operation_id],
            )
            .map_err(operation_failed)?,
    )
}

fn validate_binding_file_destination(
    binding: &ResolvedProviderBinding,
    destination: &Path,
) -> Result<(), StorageError> {
    if binding.source() != ProviderBindingSource::UserConfig
        || !binding.has_valid_binding_digest()
        || !matches!(
            binding.auth_source(),
            Some(ProviderSecretSource::File { path }) if path == destination
        )
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

fn validate_planned_paths(
    destination: &Path,
    staged: &Path,
) -> Result<(), StorageError> {
    if !destination.is_absolute()
        || !staged.is_absolute()
        || destination == staged
        || destination.parent() != staged.parent()
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    path_text(destination)?;
    path_text(staged)?;
    Ok(())
}

fn validate_staged_paths(
    destination: &Path,
    staged: &Path,
    backup: Option<&Path>,
) -> Result<(), StorageError> {
    validate_planned_paths(destination, staged)?;
    let backup = backup.ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))?;
    if !backup.is_absolute()
        || destination == backup
        || staged == backup
        || destination.parent() != backup.parent()
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    path_text(backup)?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, StorageError> {
    path.to_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidInput))
}

fn validate_digest(value: &str) -> Result<(), StorageError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(StorageError::new(StorageErrorKind::InvalidInput));
    }
    Ok(())
}

fn validated_reference(value: String) -> Result<String, StorageError> {
    super::validated_private_reference(value)
}

fn require_phase_update(changed: usize) -> Result<(), StorageError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    }
}

fn invalid_stored_state() -> StorageError {
    StorageError::new(StorageErrorKind::InvalidStoredState)
}

fn operation_failed(source: impl std::error::Error + Send + Sync + 'static) -> StorageError {
    StorageError::with_source(StorageErrorKind::OperationFailed, source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_graph_stops_before_committed_cleanup() {
        assert!(!ProviderSecretProvisioningPhase::Planned
            .permits(ProviderSecretProvisioningPhase::Staged));
        assert!(ProviderSecretProvisioningPhase::Staged
            .permits(ProviderSecretProvisioningPhase::Validated));
        assert!(ProviderSecretProvisioningPhase::Validated
            .permits(ProviderSecretProvisioningPhase::PublishIntent));
        assert!(!ProviderSecretProvisioningPhase::PublishIntent
            .permits(ProviderSecretProvisioningPhase::Committed));
        assert!(!ProviderSecretProvisioningPhase::Committed
            .permits(ProviderSecretProvisioningPhase::RollbackPending));
    }

    #[test]
    fn keyed_hmac_fields_reject_raw_or_uppercase_values() {
        assert!(validate_digest("raw-secret").is_err());
        assert!(validate_digest(&"A".repeat(64)).is_err());
        assert!(validate_digest(&"a".repeat(64)).is_ok());
    }
}
