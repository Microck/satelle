use super::codec::unix_timestamp_nanos;
use super::{
    DEFAULT_LEASE_STALE_AFTER, LeaseFreshness, LeaseOwner, MaintenanceLeaseCapability,
    MaintenanceLeaseState, MaintenanceRecoverySubject, ObservedUpstreamRef, PrivateUpstreamRef,
    ProbeRecoverySubject, ReadinessProbeKind, ReadinessProbeTerminal, SetupRunStatus, Storage,
    StorageError, StorageErrorKind,
};
use crate::runtime::VerifiedMaintenancePostcheck;
use crate::{
    ProviderSmokeEvidence, ProviderSmokeFailureEvidence, ProviderSmokeResult, ProviderSmokeSource,
    ReadinessCacheKey, ReadinessEvidence, ReadinessSource,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use satelle_core::session::{DesktopBindingRef, ExecutionPolicy};

impl Storage {
    pub(crate) fn maintenance_lease_state(
        &self,
    ) -> Result<Option<MaintenanceLeaseState>, StorageError> {
        let lease = self
            .connection
            .query_row(
                "SELECT operation_id, owner_process_id, owner_process_start_ref,
                        owner_boot_identity_ref, acquired_at, heartbeat_at, lease_state,
                        EXISTS(
                            SELECT 1 FROM control_leases
                            WHERE control_leases.operation_id = maintenance_leases.operation_id
                              AND control_leases.lease_state = maintenance_leases.lease_state
                        )
                 FROM maintenance_leases LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, bool>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(operation_failed)?;
        let Some((
            operation_id,
            process_id,
            process_start,
            boot_identity,
            acquired_at,
            heartbeat_at,
            state,
            has_postcheck,
        )) = lease
        else {
            return Ok(None);
        };
        if state == "active" {
            return Ok(Some(MaintenanceLeaseState::Active {
                operation_id,
                freshness: classify_lease_freshness(
                    &heartbeat_at,
                    time::OffsetDateTime::now_utc(),
                )?,
            }));
        }
        if state != "recovery_pending" {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        let process_id = u32::try_from(process_id)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let owner = LeaseOwner::new(
            operation_id.clone(),
            process_id,
            process_start,
            boot_identity,
            super::codec::parse_time(&acquired_at)?,
        )?;
        let run = self
            .load_setup_run(&operation_id)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        if run.status() != SetupRunStatus::OutcomeUnknown {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        Ok(Some(MaintenanceLeaseState::RecoveryPending(Box::new(
            MaintenanceRecoverySubject::new(owner, run, has_postcheck),
        ))))
    }

    /// Retains maintenance ownership while atomically adding the same
    /// operation's native-readiness Control sublease. The current schema's
    /// native-probe discriminator is the canonical postcheck representation;
    /// the shared operation id is what distinguishes it from an ordinary
    /// standalone probe.
    pub(crate) fn begin_maintenance_postcheck(
        &mut self,
        key: &ReadinessCacheKey,
        native_probe_ref: &str,
        postcheck_action_id: &str,
        capability: &MaintenanceLeaseCapability,
    ) -> Result<(), StorageError> {
        let owner = capability.lease_owner();
        let host_identity = self.host_identity()?;
        let native_probe_ref = PrivateUpstreamRef::new(native_probe_ref.to_string())?;
        let postcheck_action_id =
            super::codec::validated_private_reference(postcheck_action_id.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        let owns_maintenance: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM maintenance_leases
                    WHERE host_identity_ref = ?1
                      AND operation_id = ?2
                      AND owner_process_id = ?3
                      AND owner_process_start_ref = ?4
                      AND owner_boot_identity_ref = ?5
                      AND acquired_at = ?6
                      AND lease_state = 'active'
                 )",
                params![
                    host_identity.as_str(),
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    super::codec::format_time(owner.acquired_at)?,
                ],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        if owns_maintenance == 0 {
            return Err(StorageError::new(StorageErrorKind::LeaseConflict));
        }
        let action_started: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM setup_actions
                    JOIN setup_runs USING (run_id)
                    WHERE setup_actions.run_id = ?1
                      AND setup_actions.action_id = ?2
                      AND setup_actions.status = 'started'
                      AND setup_runs.status = 'running'
                 )",
                params![owner.operation_id.as_str(), postcheck_action_id],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        if action_started == 0 {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let control_exists: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM control_leases WHERE host_identity_ref = ?1
                 )",
                [host_identity.as_str()],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        if control_exists != 0 {
            return Err(StorageError::new(StorageErrorKind::LeaseConflict));
        }
        transaction
            .execute(
                "INSERT INTO control_leases (
                    host_identity_ref, desktop_binding_ref, operation_id,
                    owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                    acquired_at, heartbeat_at, lease_state, owner_kind, native_probe_ref
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active',
                           'native_probe', ?8)",
                params![
                    host_identity.as_str(),
                    key.desktop_binding().as_str(),
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    super::codec::format_time(owner.acquired_at)?,
                    native_probe_ref.as_str(),
                ],
            )
            .map_err(|source| super::sqlite_error(StorageErrorKind::LeaseConflict, source))?;
        transaction.commit().map_err(operation_failed)
    }

    /// Refreshes only the exact live operation represented by `owner`.
    /// Recovery ownership is deliberately excluded: a heartbeat is evidence
    /// that this operation guard is live, not merely that its process exists.
    pub(crate) fn refresh_lease_heartbeat(
        &mut self,
        owner: &LeaseOwner,
        heartbeat_at: time::OffsetDateTime,
    ) -> Result<usize, StorageError> {
        let heartbeat_at = super::codec::format_time(heartbeat_at)?;
        let acquired_at = super::codec::format_time(owner.acquired_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        // Identify the host from either exact pair member before updating. If
        // one member was altered, the other still establishes that both rows
        // belong to one atomic heartbeat refresh.
        let expected_changed: i64 = transaction
            .query_row(
                "WITH owned_hosts AS (
                    SELECT host_identity_ref FROM control_leases
                    WHERE operation_id = ?1
                      AND owner_process_id = ?2
                      AND owner_process_start_ref = ?3
                      AND owner_boot_identity_ref = ?4
                      AND acquired_at = ?5
                    UNION
                    SELECT host_identity_ref FROM maintenance_leases
                    WHERE operation_id = ?1
                      AND owner_process_id = ?2
                      AND owner_process_start_ref = ?3
                      AND owner_boot_identity_ref = ?4
                      AND acquired_at = ?5
                 )
                 SELECT
                    (SELECT count(*) FROM control_leases
                     WHERE host_identity_ref IN (SELECT host_identity_ref FROM owned_hosts))
                  + (SELECT count(*) FROM maintenance_leases
                     WHERE host_identity_ref IN (SELECT host_identity_ref FROM owned_hosts))",
                params![
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    acquired_at,
                ],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        let expected_changed = usize::try_from(expected_changed)
            .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let mut changed = 0;
        for table in ["control_leases", "maintenance_leases"] {
            let sql = format!(
                "UPDATE {table}
                 SET heartbeat_at = ?6
                 WHERE operation_id = ?1
                   AND owner_process_id = ?2
                   AND owner_process_start_ref = ?3
                   AND owner_boot_identity_ref = ?4
                   AND acquired_at = ?5
                   AND lease_state = 'active'"
            );
            changed += transaction
                .execute(
                    &sql,
                    params![
                        owner.operation_id.as_str(),
                        i64::from(owner.process_id),
                        owner.process_start_ref.as_str(),
                        owner.boot_identity_ref.as_str(),
                        acquired_at,
                        heartbeat_at,
                    ],
                )
                .map_err(operation_failed)?;
        }
        if changed != expected_changed {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        transaction.commit().map_err(operation_failed)?;
        Ok(changed)
    }

    /// Stops treating a lost operation as live without releasing ownership.
    /// Both members of a maintenance/postcheck pair move together when present.
    pub(crate) fn retain_lease_recovery(&mut self, owner: &LeaseOwner) -> Result<(), StorageError> {
        let acquired_at = super::codec::format_time(owner.acquired_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        let expected_control: i64 = transaction
            .query_row(
                "SELECT count(*)
                 FROM control_leases
                 WHERE host_identity_ref = (
                    SELECT host_identity_ref
                    FROM maintenance_leases
                    WHERE operation_id = ?1
                 )",
                [owner.operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        let expected_control = match expected_control {
            0 => 0,
            1 => 1,
            _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        };
        let running_setup: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM setup_runs
                    WHERE run_id = ?1 AND status = 'running'
                 )",
                [owner.operation_id.as_str()],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        if running_setup == 1 {
            super::setup_ledger::mark_setup_run_outcome_unknown_in_transaction(
                &transaction,
                owner.operation_id(),
                time::OffsetDateTime::now_utc(),
            )?;
        }
        let mut changed = [0; 2];
        for (index, table) in ["control_leases", "maintenance_leases"]
            .into_iter()
            .enumerate()
        {
            let sql = format!(
                "UPDATE {table}
                 SET lease_state = 'recovery_pending'
                 WHERE operation_id = ?1
                   AND owner_process_id = ?2
                   AND owner_process_start_ref = ?3
                   AND owner_boot_identity_ref = ?4
                   AND acquired_at = ?5
                   AND lease_state = 'active'"
            );
            changed[index] = transaction
                .execute(
                    &sql,
                    params![
                        owner.operation_id.as_str(),
                        i64::from(owner.process_id),
                        owner.process_start_ref.as_str(),
                        owner.boot_identity_ref.as_str(),
                        acquired_at,
                    ],
                )
                .map_err(operation_failed)?;
        }
        let [control_changed, maintenance_changed] = changed;
        if maintenance_changed != 1 || control_changed != expected_control {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        transaction.commit().map_err(operation_failed)
    }

    /// Commits a known postcheck result with the terminal setup ledger state
    /// and both releases. Unknown evidence records recovery state but retains
    /// both leases for explicit postcondition reconciliation.
    pub(crate) fn finish_maintenance_postcheck(
        &mut self,
        capability: &MaintenanceLeaseCapability,
        native_probe_ref: &str,
        postcheck_action_id: &str,
        key: &ReadinessCacheKey,
        verified: &VerifiedMaintenancePostcheck,
    ) -> Result<Option<SetupRunStatus>, StorageError> {
        let owner = capability.lease_owner();
        let native_probe_ref = PrivateUpstreamRef::new(native_probe_ref.to_string())?;
        let postcheck_action_id =
            super::codec::validated_private_reference(postcheck_action_id.to_string())?;
        let host_identity = self.host_identity()?;
        let acquired_at = super::codec::format_time(owner.acquired_at)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        let finished_at = time::OffsetDateTime::now_utc();
        let owns_pair: i64 = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM maintenance_leases AS maintenance
                    JOIN control_leases AS control USING (host_identity_ref)
                    WHERE maintenance.host_identity_ref = ?1
                      AND maintenance.operation_id = ?2
                      AND maintenance.owner_process_id = ?4
                      AND maintenance.owner_process_start_ref = ?5
                      AND maintenance.owner_boot_identity_ref = ?6
                      AND maintenance.acquired_at = ?7
                      AND maintenance.lease_state = 'active'
                      AND control.operation_id = ?2
                      AND control.owner_process_id = ?4
                      AND control.owner_process_start_ref = ?5
                      AND control.owner_boot_identity_ref = ?6
                      AND control.acquired_at = ?7
                      AND control.owner_kind = 'native_probe'
                      AND control.native_probe_ref = ?3
                      AND control.lease_state = 'active'
                 )",
                params![
                    host_identity.as_str(),
                    owner.operation_id.as_str(),
                    native_probe_ref.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    acquired_at,
                ],
                |row| row.get(0),
            )
            .map_err(operation_failed)?;
        if owns_pair == 0 {
            return Err(StorageError::new(StorageErrorKind::LeaseConflict));
        }
        let (readiness_status, failure_reason) = match verified.terminal() {
            None => (Some("passed"), None),
            Some(ReadinessProbeTerminal::Failed) => (Some("failed"), verified.failure_reason()),
            Some(ReadinessProbeTerminal::TimedOut) => {
                (Some("timed_out"), verified.failure_reason())
            }
            Some(ReadinessProbeTerminal::OutcomeUnknown) => (None, None),
        };
        let (action_status, action_error_code, action_recovery_hint) = match verified.terminal() {
            None => ("completed", None, None),
            Some(ReadinessProbeTerminal::Failed) => (
                "failed",
                Some("maintenance_postcheck_failed"),
                Some("inspect readiness before retrying maintenance"),
            ),
            Some(ReadinessProbeTerminal::TimedOut) => (
                "failed",
                Some("maintenance_postcheck_timed_out"),
                Some("confirm the readiness probe stopped before retrying maintenance"),
            ),
            Some(ReadinessProbeTerminal::OutcomeUnknown) => (
                "outcome_unknown",
                None,
                Some("inspect live postconditions before retrying this action"),
            ),
        };
        require_idempotent_write(
            transaction
                .execute(
                    "UPDATE setup_actions
                     SET status = ?3, finished_at = ?4, error_code = ?5,
                         recovery_hint = ?6
                     WHERE run_id = ?1 AND action_id = ?2 AND status = 'started'
                       AND EXISTS (
                           SELECT 1 FROM setup_runs
                           WHERE setup_runs.run_id = setup_actions.run_id
                             AND setup_runs.status = 'running'
                       )",
                    params![
                        owner.operation_id.as_str(),
                        postcheck_action_id,
                        action_status,
                        super::codec::format_time(finished_at)?,
                        action_error_code,
                        action_recovery_hint,
                    ],
                )
                .map_err(operation_failed)?,
        )?;
        if let (Some(readiness_status), Some(evidence)) = (readiness_status, verified.evidence()) {
            insert_readiness(
                &transaction,
                host_identity.as_str(),
                key.adapter(),
                key.desktop_binding(),
                evidence,
                readiness_status,
                failure_reason,
            )?;
        } else if !verified.is_unknown() {
            return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
        }
        if verified.is_unknown() {
            super::setup_ledger::mark_setup_run_outcome_unknown_in_transaction(
                &transaction,
                owner.operation_id(),
                finished_at,
            )?;
            for table in ["control_leases", "maintenance_leases"] {
                let sql = format!(
                    "UPDATE {table} SET lease_state = 'recovery_pending'
                     WHERE operation_id = ?1
                       AND owner_process_id = ?2
                       AND owner_process_start_ref = ?3
                       AND owner_boot_identity_ref = ?4
                       AND acquired_at = ?5
                       AND lease_state = 'active'"
                );
                require_idempotent_write(
                    transaction
                        .execute(
                            &sql,
                            params![
                                owner.operation_id.as_str(),
                                i64::from(owner.process_id),
                                owner.process_start_ref.as_str(),
                                owner.boot_identity_ref.as_str(),
                                acquired_at,
                            ],
                        )
                        .map_err(operation_failed)?,
                )?;
            }
            transaction.commit().map_err(operation_failed)?;
            return Ok(None);
        }
        let status = super::setup_ledger::finish_setup_run_in_transaction(
            &transaction,
            owner.operation_id(),
            finished_at,
        )?;
        let exact_owner = params![
            host_identity.as_str(),
            owner.operation_id.as_str(),
            native_probe_ref.as_str(),
            i64::from(owner.process_id),
            owner.process_start_ref.as_str(),
            owner.boot_identity_ref.as_str(),
            acquired_at,
        ];
        let released_control = transaction
            .execute(
                "DELETE FROM control_leases
                 WHERE host_identity_ref = ?1 AND operation_id = ?2
                   AND owner_kind = 'native_probe' AND native_probe_ref = ?3
                   AND owner_process_id = ?4 AND owner_process_start_ref = ?5
                   AND owner_boot_identity_ref = ?6 AND acquired_at = ?7
                   AND lease_state = 'active'",
                exact_owner,
            )
            .map_err(operation_failed)?;
        require_idempotent_write(released_control)?;
        let released_maintenance = transaction
            .execute(
                "DELETE FROM maintenance_leases
                 WHERE host_identity_ref = ?1 AND operation_id = ?2
                   AND owner_process_id = ?3 AND owner_process_start_ref = ?4
                   AND owner_boot_identity_ref = ?5 AND acquired_at = ?6
                   AND lease_state = 'active'",
                params![
                    host_identity.as_str(),
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    acquired_at,
                ],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(released_maintenance)?;
        transaction.commit().map_err(operation_failed)?;
        Ok(Some(status))
    }

    pub(crate) fn begin_native_probe(
        &mut self,
        key: &ReadinessCacheKey,
        native_probe_ref: &str,
        owner: &LeaseOwner,
    ) -> Result<(), StorageError> {
        self.begin_readiness_probe(key, native_probe_ref, owner, ReadinessProbeKind::Native)
    }

    pub(crate) fn begin_provider_probe(
        &mut self,
        key: &ReadinessCacheKey,
        provider_probe_ref: &str,
        owner: &LeaseOwner,
    ) -> Result<(), StorageError> {
        self.begin_readiness_probe(key, provider_probe_ref, owner, ReadinessProbeKind::Provider)
    }

    fn begin_readiness_probe(
        &mut self,
        key: &ReadinessCacheKey,
        probe_ref: &str,
        owner: &LeaseOwner,
        kind: ReadinessProbeKind,
    ) -> Result<(), StorageError> {
        let host_identity = self.host_identity()?;
        let probe_ref = PrivateUpstreamRef::new(probe_ref.to_string())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(operation_failed)?;
        super::sql::ensure_control_lease_available(
            &transaction,
            &host_identity,
            key.desktop_binding(),
        )?;
        let sql = format!(
            "INSERT INTO control_leases (
                host_identity_ref, desktop_binding_ref, operation_id,
                owner_process_id, owner_process_start_ref, owner_boot_identity_ref,
                acquired_at, heartbeat_at, lease_state, owner_kind, {}
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'active', ?8, ?9)",
            kind.reference_column()
        );
        transaction
            .execute(
                &sql,
                rusqlite::params![
                    host_identity.as_str(),
                    key.desktop_binding().as_str(),
                    owner.operation_id.as_str(),
                    i64::from(owner.process_id),
                    owner.process_start_ref.as_str(),
                    owner.boot_identity_ref.as_str(),
                    super::codec::format_time(owner.acquired_at)?,
                    kind.owner_kind(),
                    probe_ref.as_str(),
                ],
            )
            .map_err(|source| super::sqlite_error(StorageErrorKind::LeaseConflict, source))?;
        transaction.commit().map_err(operation_failed)
    }

    pub(crate) fn persist_native_probe_upstream_ref(
        &mut self,
        native_probe_ref: &str,
        observed: ObservedUpstreamRef,
    ) -> Result<(), StorageError> {
        self.persist_readiness_probe_upstream_ref(
            ReadinessProbeKind::Native,
            native_probe_ref,
            observed,
        )
    }

    pub(crate) fn persist_provider_probe_upstream_ref(
        &mut self,
        provider_probe_ref: &str,
        observed: ObservedUpstreamRef,
    ) -> Result<(), StorageError> {
        self.persist_readiness_probe_upstream_ref(
            ReadinessProbeKind::Provider,
            provider_probe_ref,
            observed,
        )
    }

    fn persist_readiness_probe_upstream_ref(
        &mut self,
        kind: ReadinessProbeKind,
        probe_ref: &str,
        observed: ObservedUpstreamRef,
    ) -> Result<(), StorageError> {
        let (column, value) = match observed {
            ObservedUpstreamRef::Thread(value) => ("upstream_thread_ref", value),
            ObservedUpstreamRef::Turn(value) => ("upstream_turn_ref", value),
            ObservedUpstreamRef::Goal(_) => {
                return Err(StorageError::new(StorageErrorKind::InvalidInput));
            }
        };
        let sql = format!(
            "UPDATE control_leases SET {column} = COALESCE({column}, ?1)
             WHERE owner_kind = ?3
               AND {} = ?2
               AND ({column} IS NULL OR {column} = ?1)",
            kind.reference_column()
        );
        let changed = self
            .connection
            .execute(&sql, params![value.as_str(), probe_ref, kind.owner_kind()])
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
    }

    pub(crate) fn pending_native_probe(
        &self,
        host_identity: &satelle_core::session::HostIdentityRef,
        desktop_binding: &DesktopBindingRef,
    ) -> Result<Option<ProbeRecoverySubject>, StorageError> {
        self.pending_readiness_probe(host_identity, desktop_binding, ReadinessProbeKind::Native)
    }

    pub(crate) fn pending_provider_probe(
        &self,
        host_identity: &satelle_core::session::HostIdentityRef,
        desktop_binding: &DesktopBindingRef,
    ) -> Result<Option<ProbeRecoverySubject>, StorageError> {
        self.pending_readiness_probe(host_identity, desktop_binding, ReadinessProbeKind::Provider)
    }

    fn pending_readiness_probe(
        &self,
        host_identity: &satelle_core::session::HostIdentityRef,
        desktop_binding: &DesktopBindingRef,
        kind: ReadinessProbeKind,
    ) -> Result<Option<ProbeRecoverySubject>, StorageError> {
        let sql = format!(
            "SELECT host_identity_ref, desktop_binding_ref, {},
                    upstream_thread_ref, upstream_turn_ref, lease_state
             FROM control_leases
             WHERE owner_kind = ?3
               AND host_identity_ref = ?1
               AND desktop_binding_ref = ?2
               AND lease_state IN ('active', 'recovery_pending')",
            kind.reference_column()
        );
        self.connection
            .query_row(
                &sql,
                params![
                    host_identity.as_str(),
                    desktop_binding.as_str(),
                    kind.owner_kind()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(operation_failed)?
            .map(|(host, desktop, probe, thread, turn, lease_state)| {
                let recovery_pending = match lease_state.as_str() {
                    "active" => false,
                    "recovery_pending" => true,
                    _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
                };
                Ok(ProbeRecoverySubject {
                    host_identity: satelle_core::session::HostIdentityRef::new(host)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                    desktop_binding: DesktopBindingRef::new(desktop)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?,
                    probe_kind: kind,
                    probe_ref: PrivateUpstreamRef::new(probe)?,
                    upstream_thread_ref: thread.map(PrivateUpstreamRef::new).transpose()?,
                    upstream_turn_ref: turn.map(PrivateUpstreamRef::new).transpose()?,
                    recovery_pending,
                })
            })
            .transpose()
    }

    pub(crate) fn release_reconciled_provider_probe(
        &mut self,
        provider_probe_ref: &str,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM control_leases
                 WHERE owner_kind = 'provider_probe'
                   AND lease_state = 'recovery_pending'
                   AND provider_probe_ref = ?1",
                [provider_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
    }

    pub(crate) fn release_reconciled_native_probe(
        &mut self,
        native_probe_ref: &str,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM control_leases
                 WHERE owner_kind = 'native_probe'
                   AND lease_state = 'recovery_pending'
                   AND native_probe_ref = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM maintenance_leases
                       WHERE maintenance_leases.host_identity_ref = control_leases.host_identity_ref
                         AND maintenance_leases.operation_id = control_leases.operation_id
                   )",
                [native_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
    }

    pub(crate) fn finish_native_probe_success(
        &mut self,
        native_probe_ref: &str,
        key: &ReadinessCacheKey,
        evidence: &ReadinessEvidence,
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
            evidence,
            "passed",
            None,
        )?;
        let changed = transaction
            .execute(
                "DELETE FROM control_leases
                 WHERE owner_kind = 'native_probe'
                   AND native_probe_ref = ?1
                   AND lease_state = 'active'",
                [native_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)?;
        transaction.commit().map_err(operation_failed)
    }

    pub(crate) fn finish_native_probe_failure(
        &mut self,
        native_probe_ref: &str,
        key: &ReadinessCacheKey,
        evidence: &ReadinessEvidence,
        reason: &'static str,
        terminal: ReadinessProbeTerminal,
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
            evidence,
            terminal.as_str(),
            Some(reason),
        )?;
        let sql = match terminal {
            ReadinessProbeTerminal::Failed | ReadinessProbeTerminal::TimedOut => {
                "DELETE FROM control_leases WHERE owner_kind = 'native_probe' AND native_probe_ref = ?1 AND lease_state = 'active'"
            }
            ReadinessProbeTerminal::OutcomeUnknown => {
                "UPDATE control_leases SET lease_state = 'recovery_pending' WHERE owner_kind = 'native_probe' AND native_probe_ref = ?1 AND lease_state = 'active'"
            }
        };
        let changed = transaction
            .execute(sql, [native_probe_ref])
            .map_err(operation_failed)?;
        require_idempotent_write(changed)?;
        transaction.commit().map_err(operation_failed)
    }

    pub(crate) fn retain_native_probe_recovery(
        &mut self,
        native_probe_ref: &str,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE control_leases SET lease_state = 'recovery_pending'
                 WHERE owner_kind = 'native_probe'
                   AND native_probe_ref = ?1
                   AND lease_state = 'active'",
                [native_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
    }

    pub(crate) fn release_native_probe(
        &mut self,
        native_probe_ref: &str,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM control_leases
                 WHERE owner_kind = 'native_probe'
                   AND native_probe_ref = ?1
                   AND lease_state = 'active'",
                [native_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
    }

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

    pub(crate) fn finish_provider_probe_failure(
        &mut self,
        provider_probe_ref: &str,
        key: &ReadinessCacheKey,
        readiness: &ReadinessEvidence,
        failure: &ProviderSmokeFailureEvidence,
        terminal: ReadinessProbeTerminal,
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
            ProviderSmokeInsert::TerminalFailure {
                evidence: failure,
                status: terminal.as_str(),
            },
        )?;
        let sql = match terminal {
            ReadinessProbeTerminal::Failed | ReadinessProbeTerminal::TimedOut => {
                "DELETE FROM control_leases WHERE owner_kind = 'provider_probe' AND provider_probe_ref = ?1 AND lease_state = 'active'"
            }
            ReadinessProbeTerminal::OutcomeUnknown => {
                "UPDATE control_leases SET lease_state = 'recovery_pending' WHERE owner_kind = 'provider_probe' AND provider_probe_ref = ?1 AND lease_state = 'active'"
            }
        };
        let changed = transaction
            .execute(sql, [provider_probe_ref])
            .map_err(operation_failed)?;
        require_idempotent_write(changed)?;
        transaction.commit().map_err(operation_failed)
    }

    pub(crate) fn release_provider_probe(
        &mut self,
        provider_probe_ref: &str,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM control_leases
                 WHERE owner_kind = 'provider_probe'
                   AND provider_probe_ref = ?1
                   AND lease_state = 'active'",
                [provider_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
    }

    pub(crate) fn retain_provider_probe_recovery(
        &mut self,
        provider_probe_ref: &str,
    ) -> Result<(), StorageError> {
        let changed = self
            .connection
            .execute(
                "UPDATE control_leases SET lease_state = 'recovery_pending'
                 WHERE owner_kind = 'provider_probe'
                   AND provider_probe_ref = ?1
                   AND lease_state = 'active'",
                [provider_probe_ref],
            )
            .map_err(operation_failed)?;
        require_idempotent_write(changed)
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
                   AND desktop_session_ref = ?3
                   AND adapter_ref = ?4
                   AND codex_version = ?5
                   AND native_runtime_version = ?6
                   AND plugin_version IS ?7
                   AND os_permission_state = ?8
                   AND os_permission_fingerprint = ?9
                   AND app_approval_state = ?10
                   AND app_approval_fingerprint = ?11
                   AND status = 'passed'
                   AND observed_at <= ?12
                   AND expires_at > ?12
                 ORDER BY observed_at DESC
                 LIMIT 1",
                params![
                    host_identity.as_str(),
                    key.desktop_binding().as_str(),
                    key.desktop_session_ref(),
                    key.adapter(),
                    key.codex_version(),
                    key.native_runtime_version(),
                    key.plugin_version(),
                    key.os_permission_state().as_str(),
                    key.os_permission_fingerprint(),
                    key.app_approval_state().as_str(),
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
                .map(|evidence| evidence.with_source(ReadinessSource::Cache))
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
                "SELECT result_id, provider_config_fingerprint,
                        provider_credential_fingerprint, status,
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
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(operation_failed)?;
        row.map(
            |(
                result_id,
                provider_config_fingerprint,
                provider_credential_fingerprint,
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
                        provider_credential_fingerprint,
                        observed_at,
                        expires_at,
                    )
                    .map(|evidence| evidence.with_source(ProviderSmokeSource::Cache))
                    .map(ProviderSmokeResult::Passed)
                    .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState)),
                    (
                        "failed" | "timed_out" | "outcome_unknown",
                        Some(error_code),
                        Some(failure_reason),
                    ) => {
                        let error_code = serde_json::from_value(serde_json::Value::String(
                            error_code,
                        ))
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))?;
                        ProviderSmokeFailureEvidence::new(
                            result_id,
                            provider_config_fingerprint,
                            provider_credential_fingerprint,
                            error_code,
                            failure_reason,
                            observed_at,
                            expires_at,
                        )
                        .map(|evidence| evidence.with_source(ProviderSmokeSource::Cache))
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
    status: &str,
    failure_reason: Option<&str>,
) -> Result<(), StorageError> {
    connection
        .execute(
            "INSERT INTO native_readiness_results (
                result_id, host_identity_ref, desktop_binding_ref, desktop_session_ref, adapter_ref,
                status, failure_reason,
                codex_version, native_runtime_version, plugin_version,
                os_permission_state, os_permission_fingerprint,
                app_approval_state, app_approval_fingerprint, observed_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(result_id) DO UPDATE SET result_id = excluded.result_id
            WHERE host_identity_ref = excluded.host_identity_ref
              AND desktop_binding_ref = excluded.desktop_binding_ref
              AND desktop_session_ref = excluded.desktop_session_ref
              AND adapter_ref = excluded.adapter_ref
              AND status = excluded.status
              AND failure_reason IS excluded.failure_reason
              AND codex_version = excluded.codex_version
              AND native_runtime_version = excluded.native_runtime_version
              AND plugin_version IS excluded.plugin_version
              AND os_permission_state = excluded.os_permission_state
              AND os_permission_fingerprint = excluded.os_permission_fingerprint
              AND app_approval_state = excluded.app_approval_state
              AND app_approval_fingerprint = excluded.app_approval_fingerprint
              AND observed_at = excluded.observed_at
              AND expires_at = excluded.expires_at",
            params![
                evidence.result_id(),
                host_identity,
                desktop_binding.as_str(),
                evidence.desktop_session_ref(),
                adapter,
                status,
                failure_reason,
                evidence.codex_version(),
                evidence.native_runtime_version(),
                evidence.plugin_version(),
                evidence.os_permission_state().as_str(),
                evidence.os_permission_fingerprint(),
                evidence.app_approval_state().as_str(),
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
    TerminalFailure {
        evidence: &'a ProviderSmokeFailureEvidence,
        status: &'static str,
    },
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
        provider_credential_fingerprint,
        status,
        failure_code,
        failure_reason,
        observed_at,
        expires_at,
    ) = match evidence {
        ProviderSmokeInsert::Passed(evidence) => (
            evidence.result_id(),
            evidence.provider_config_fingerprint(),
            evidence.provider_credential_fingerprint(),
            "passed",
            None,
            None,
            evidence.observed_at(),
            evidence.expires_at(),
        ),
        ProviderSmokeInsert::Failed(evidence) => (
            evidence.result_id(),
            evidence.provider_config_fingerprint(),
            evidence.provider_credential_fingerprint(),
            "failed",
            Some(evidence.error_code().as_str()),
            Some(evidence.failure_reason()),
            evidence.observed_at(),
            evidence.expires_at(),
        ),
        ProviderSmokeInsert::TerminalFailure { evidence, status } => (
            evidence.result_id(),
            evidence.provider_config_fingerprint(),
            evidence.provider_credential_fingerprint(),
            status,
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
                native_runtime_version, provider_config_fingerprint,
                provider_credential_fingerprint, status,
                failure_code, failure_reason, observed_at, expires_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            ON CONFLICT(result_id) DO UPDATE SET result_id = excluded.result_id
            WHERE host_identity_ref = excluded.host_identity_ref
              AND desktop_binding_ref = excluded.desktop_binding_ref
              AND provider_binding_ref = excluded.provider_binding_ref
              AND effective_model_ref = excluded.effective_model_ref
              AND codex_version = excluded.codex_version
              AND native_runtime_version = excluded.native_runtime_version
              AND provider_config_fingerprint = excluded.provider_config_fingerprint
              AND provider_credential_fingerprint = excluded.provider_credential_fingerprint
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
                provider_credential_fingerprint,
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

pub(super) fn classify_lease_freshness(
    heartbeat_at: &str,
    observed_at: time::OffsetDateTime,
) -> Result<LeaseFreshness, StorageError> {
    let heartbeat_at = super::codec::parse_time(heartbeat_at)?;
    let stale_after = heartbeat_at
        .checked_add(DEFAULT_LEASE_STALE_AFTER)
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
    Ok(if observed_at > stale_after {
        LeaseFreshness::Stale
    } else {
        LeaseFreshness::Fresh
    })
}
