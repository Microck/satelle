use super::codec::unix_timestamp_nanos;
use super::{Storage, StorageError, StorageErrorKind};
use crate::{
    ProviderSmokeEvidence, ProviderSmokeFailureEvidence, ProviderSmokeResult, ReadinessCacheKey,
    ReadinessEvidence,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use satelle_core::session::{DesktopBindingRef, ExecutionPolicy};

impl Storage {
    /// Persists the successful native and optional provider probes as one unit.
    /// Replaying byte-equivalent evidence is harmless; reusing an identifier
    /// for different evidence fails closed.
    pub(crate) fn store_preflight_successes(
        &mut self,
        adapter: &str,
        desktop_binding: &DesktopBindingRef,
        policy: &ExecutionPolicy,
        readiness: &ReadinessEvidence,
        provider: Option<&ProviderSmokeEvidence>,
    ) -> Result<(), StorageError> {
        let host_identity = self.host_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        insert_readiness(
            &transaction,
            host_identity.as_str(),
            adapter,
            desktop_binding,
            readiness,
            "passed",
            None,
        )?;
        if let Some(provider) = provider {
            insert_provider_smoke(
                &transaction,
                host_identity.as_str(),
                desktop_binding,
                policy,
                readiness,
                ProviderSmokeInsert::Passed(provider),
            )?;
        }
        transaction.commit().map_err(operation_failed)
    }

    pub(crate) fn store_preflight_failure(
        &mut self,
        key: &ReadinessCacheKey,
        evidence: &ReadinessEvidence,
        reason: &'static str,
    ) -> Result<(), StorageError> {
        let host_identity = self.host_identity()?;
        insert_readiness(
            &self.connection,
            host_identity.as_str(),
            key.adapter(),
            key.desktop_binding(),
            evidence,
            "failed",
            Some(reason),
        )
    }

    /// Persists successful native readiness and the terminal provider failure
    /// atomically. Provider failure evidence is a short-lived blocker, not
    /// authorization to execute.
    pub(crate) fn store_provider_smoke_failure(
        &mut self,
        key: &ReadinessCacheKey,
        readiness: &ReadinessEvidence,
        failure: &ProviderSmokeFailureEvidence,
    ) -> Result<(), StorageError> {
        let host_identity = self.host_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        insert_readiness(
            &transaction,
            host_identity.as_str(),
            key.adapter(),
            key.desktop_binding(),
            readiness,
            "passed",
            None,
        )?;
        insert_provider_smoke(
            &transaction,
            host_identity.as_str(),
            key.desktop_binding(),
            key.execution_policy(),
            readiness,
            ProviderSmokeInsert::Failed(failure),
        )?;
        transaction.commit().map_err(operation_failed)
    }

    /// Returns only a matching, unexpired success. Failed results remain in
    /// the authoritative store for diagnostics but never authorize execution.
    pub(crate) fn load_reusable_readiness(
        &self,
        key: &ReadinessCacheKey,
        now: time::OffsetDateTime,
    ) -> Result<Option<ReadinessEvidence>, StorageError> {
        let host_identity = self.host_identity()?;
        let row = self
            .connection
            .query_row(
                "SELECT result_id, observed_at, expires_at
                 FROM native_readiness_results
                 WHERE host_identity_ref = ?1
                   AND desktop_binding_ref = ?2
                   AND adapter_ref = ?3
                   AND codex_version = ?4
                   AND native_runtime_version = ?5
                   AND plugin_version IS ?6
                   AND os_permission_fingerprint = ?7
                   AND app_approval_fingerprint = ?8
                   AND status = 'passed'
                   AND observed_at <= ?9
                   AND expires_at > ?9
                 ORDER BY observed_at DESC
                 LIMIT 1",
                params![
                    host_identity.as_str(),
                    key.desktop_binding().as_str(),
                    key.adapter(),
                    key.codex_version(),
                    key.native_runtime_version(),
                    key.plugin_version(),
                    key.os_permission_fingerprint(),
                    key.app_approval_fingerprint(),
                    unix_timestamp_nanos(now)?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(operation_failed)?;
        row.map(|(result_id, observed_at, expires_at)| {
            let observed_at =
                time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(observed_at))
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let expires_at =
                time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(expires_at))
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            key.evidence(result_id, observed_at, expires_at)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })
        .transpose()
    }

    /// Returns provider evidence only for the exact unexpired provider,
    /// model, Codex, native runtime, and provider-configuration tuple.
    pub(crate) fn load_reusable_provider_smoke(
        &self,
        key: &ReadinessCacheKey,
        now: time::OffsetDateTime,
    ) -> Result<Option<ProviderSmokeResult>, StorageError> {
        let host_identity = self.host_identity()?;
        let row = self
            .connection
            .query_row(
                "SELECT result_id, provider_config_fingerprint, status,
                        failure_code, failure_reason, observed_at, expires_at
                 FROM provider_smoke_results
                 WHERE host_identity_ref = ?1
                   AND desktop_binding_ref = ?2
                   AND provider_binding_ref = ?3
                   AND effective_model_ref = ?4
                   AND codex_version = ?5
                   AND native_runtime_version = ?6
                   AND provider_config_fingerprint = ?7
                   AND observed_at <= ?8
                   AND expires_at > ?8
                 ORDER BY observed_at DESC
                 LIMIT 1",
                params![
                    host_identity.as_str(),
                    key.desktop_binding().as_str(),
                    key.execution_policy().provider_binding().as_str(),
                    key.execution_policy().effective_model().as_str(),
                    key.codex_version(),
                    key.native_runtime_version(),
                    key.provider_config_fingerprint(),
                    unix_timestamp_nanos(now)?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(operation_failed)?;
        row.map(
            |(
                result_id,
                provider_config_fingerprint,
                status,
                failure_code,
                failure_reason,
                observed_at,
                expires_at,
            )| {
                let observed_at =
                    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(observed_at))
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                let expires_at =
                    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(expires_at))
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                match (status.as_str(), failure_code, failure_reason) {
                    ("passed", None, None) => ProviderSmokeEvidence::new(
                        result_id,
                        provider_config_fingerprint,
                        observed_at,
                        expires_at,
                    )
                    .map(ProviderSmokeResult::Passed)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState)),
                    ("failed", Some(error_code), Some(failure_reason)) => {
                        let error_code = serde_json::from_value(serde_json::Value::String(
                            error_code,
                        ))
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                        ProviderSmokeFailureEvidence::new(
                            result_id,
                            provider_config_fingerprint,
                            error_code,
                            failure_reason,
                            observed_at,
                            expires_at,
                        )
                        .map(ProviderSmokeResult::Failed)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
                    }
                    _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
                }
            },
        )
        .transpose()
    }
}

fn insert_readiness(
    connection: &rusqlite::Connection,
    host_identity: &str,
    adapter: &str,
    desktop_binding: &DesktopBindingRef,
    evidence: &ReadinessEvidence,
    status: &'static str,
    failure_reason: Option<&'static str>,
) -> Result<(), StorageError> {
    connection
        .execute(
            "INSERT INTO native_readiness_results (
                result_id, host_identity_ref, desktop_binding_ref, adapter_ref,
                status, failure_reason,
                codex_version, native_runtime_version, plugin_version,
                os_permission_fingerprint, app_approval_fingerprint, observed_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(result_id) DO UPDATE SET result_id = excluded.result_id
            WHERE host_identity_ref = excluded.host_identity_ref
              AND desktop_binding_ref = excluded.desktop_binding_ref
              AND adapter_ref = excluded.adapter_ref
              AND status = excluded.status
              AND failure_reason IS excluded.failure_reason
              AND codex_version = excluded.codex_version
              AND native_runtime_version = excluded.native_runtime_version
              AND plugin_version IS excluded.plugin_version
              AND os_permission_fingerprint = excluded.os_permission_fingerprint
              AND app_approval_fingerprint = excluded.app_approval_fingerprint
              AND observed_at = excluded.observed_at
              AND expires_at = excluded.expires_at",
            params![
                evidence.result_id(),
                host_identity,
                desktop_binding.as_str(),
                adapter,
                status,
                failure_reason,
                evidence.codex_version(),
                evidence.native_runtime_version(),
                evidence.plugin_version(),
                evidence.os_permission_fingerprint(),
                evidence.app_approval_fingerprint(),
                unix_timestamp_nanos(evidence.observed_at())?,
                unix_timestamp_nanos(evidence.expires_at())?,
            ],
        )
        .map_err(operation_failed)
        .and_then(require_idempotent_write)
}

enum ProviderSmokeInsert<'a> {
    Passed(&'a ProviderSmokeEvidence),
    Failed(&'a ProviderSmokeFailureEvidence),
}

fn insert_provider_smoke(
    connection: &rusqlite::Connection,
    host_identity: &str,
    desktop_binding: &DesktopBindingRef,
    policy: &ExecutionPolicy,
    readiness: &ReadinessEvidence,
    evidence: ProviderSmokeInsert<'_>,
) -> Result<(), StorageError> {
    let (
        result_id,
        provider_config_fingerprint,
        status,
        failure_code,
        failure_reason,
        observed_at,
        expires_at,
    ) = match evidence {
        ProviderSmokeInsert::Passed(evidence) => (
            evidence.result_id(),
            evidence.provider_config_fingerprint(),
            "passed",
            None,
            None,
            evidence.observed_at(),
            evidence.expires_at(),
        ),
        ProviderSmokeInsert::Failed(evidence) => (
            evidence.result_id(),
            evidence.provider_config_fingerprint(),
            "failed",
            Some(evidence.error_code().as_str()),
            Some(evidence.failure_reason()),
            evidence.observed_at(),
            evidence.expires_at(),
        ),
    };
    connection
        .execute(
            "DELETE FROM provider_smoke_results
             WHERE host_identity_ref = ?1
               AND desktop_binding_ref = ?2
               AND provider_binding_ref = ?3
               AND effective_model_ref = ?4
               AND codex_version = ?5
               AND native_runtime_version = ?6
               AND provider_config_fingerprint = ?7
               AND result_id <> ?8",
            params![
                host_identity,
                desktop_binding.as_str(),
                policy.provider_binding().as_str(),
                policy.effective_model().as_str(),
                readiness.codex_version(),
                readiness.native_runtime_version(),
                provider_config_fingerprint,
                result_id,
            ],
        )
        .map_err(operation_failed)?;
    connection
        .execute(
            "INSERT INTO provider_smoke_results (
                result_id, host_identity_ref, desktop_binding_ref,
                provider_binding_ref, effective_model_ref, codex_version,
                native_runtime_version, provider_config_fingerprint, status,
                failure_code, failure_reason, observed_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            ON CONFLICT(result_id) DO UPDATE SET result_id = excluded.result_id
            WHERE host_identity_ref = excluded.host_identity_ref
              AND desktop_binding_ref = excluded.desktop_binding_ref
              AND provider_binding_ref = excluded.provider_binding_ref
              AND effective_model_ref = excluded.effective_model_ref
              AND codex_version = excluded.codex_version
              AND native_runtime_version = excluded.native_runtime_version
              AND provider_config_fingerprint = excluded.provider_config_fingerprint
              AND status = excluded.status
              AND failure_code IS excluded.failure_code
              AND failure_reason IS excluded.failure_reason
              AND observed_at = excluded.observed_at
              AND expires_at = excluded.expires_at",
            params![
                result_id,
                host_identity,
                desktop_binding.as_str(),
                policy.provider_binding().as_str(),
                policy.effective_model().as_str(),
                readiness.codex_version(),
                readiness.native_runtime_version(),
                provider_config_fingerprint,
                status,
                failure_code,
                failure_reason,
                unix_timestamp_nanos(observed_at)?,
                unix_timestamp_nanos(expires_at)?,
            ],
        )
        .map_err(operation_failed)
        .and_then(require_idempotent_write)
}

fn require_idempotent_write(changed: usize) -> Result<(), StorageError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StorageError::new(StorageErrorKind::StateConflict))
    }
}

fn operation_failed(source: rusqlite::Error) -> StorageError {
    super::open::sqlite_error(StorageErrorKind::OperationFailed, source)
}
