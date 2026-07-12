use super::codec::format_time;
use super::{Storage, StorageError, StorageErrorKind};
use crate::{ProviderSmokeEvidence, ReadinessEvidence};
use rusqlite::{TransactionBehavior, params};
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
        )?;
        if let Some(provider) = provider {
            insert_provider_smoke(
                &transaction,
                host_identity.as_str(),
                desktop_binding,
                policy,
                readiness,
                provider,
            )?;
        }
        transaction.commit().map_err(operation_failed)
    }
}

fn insert_readiness(
    connection: &rusqlite::Connection,
    host_identity: &str,
    adapter: &str,
    desktop_binding: &DesktopBindingRef,
    evidence: &ReadinessEvidence,
) -> Result<(), StorageError> {
    connection
        .execute(
            "INSERT INTO readiness_successes (
                result_id, host_identity_ref, desktop_binding_ref, adapter_ref,
                codex_version, native_runtime_version, plugin_version,
                os_permission_fingerprint, app_approval_fingerprint, observed_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(result_id) DO UPDATE SET result_id = excluded.result_id
            WHERE host_identity_ref = excluded.host_identity_ref
              AND desktop_binding_ref = excluded.desktop_binding_ref
              AND adapter_ref = excluded.adapter_ref
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
                evidence.codex_version(),
                evidence.native_runtime_version(),
                evidence.plugin_version(),
                evidence.os_permission_fingerprint(),
                evidence.app_approval_fingerprint(),
                format_time(evidence.observed_at())?,
                format_time(evidence.expires_at())?,
            ],
        )
        .map_err(operation_failed)
        .and_then(require_idempotent_write)
}

fn insert_provider_smoke(
    connection: &rusqlite::Connection,
    host_identity: &str,
    desktop_binding: &DesktopBindingRef,
    policy: &ExecutionPolicy,
    readiness: &ReadinessEvidence,
    evidence: &ProviderSmokeEvidence,
) -> Result<(), StorageError> {
    connection
        .execute(
            "INSERT INTO provider_smoke_successes (
                result_id, host_identity_ref, desktop_binding_ref,
                provider_binding_ref, effective_model_ref, codex_version,
                native_runtime_version, provider_config_fingerprint, observed_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(result_id) DO UPDATE SET result_id = excluded.result_id
            WHERE host_identity_ref = excluded.host_identity_ref
              AND desktop_binding_ref = excluded.desktop_binding_ref
              AND provider_binding_ref = excluded.provider_binding_ref
              AND effective_model_ref = excluded.effective_model_ref
              AND codex_version = excluded.codex_version
              AND native_runtime_version = excluded.native_runtime_version
              AND provider_config_fingerprint = excluded.provider_config_fingerprint
              AND observed_at = excluded.observed_at
              AND expires_at = excluded.expires_at",
            params![
                evidence.result_id(),
                host_identity,
                desktop_binding.as_str(),
                policy.provider_binding().as_str(),
                policy.effective_model().as_str(),
                readiness.codex_version(),
                readiness.native_runtime_version(),
                evidence.provider_config_fingerprint(),
                format_time(evidence.observed_at())?,
                format_time(evidence.expires_at())?,
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
