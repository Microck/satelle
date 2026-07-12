use super::codec::{load_required_session, parse_stop_outcome, stop_outcome_token};
use super::logs::canonical_log;
use super::sql::{
    complete_stop_idempotency, ensure_control_lease_absent, ensure_control_lease_present,
    ensure_record_handles, insert_idempotency, insert_safe_log, load_recovery_subject,
    matching_idempotency, persist_lifecycle_mutation, require_operation, synchronize_control_lease,
    update_turn_idempotency,
};
use super::{
    IdempotencyInput, IdempotentOperation, LogEvent, LogSeverity, RecoverySubject, Storage,
    StorageError, StorageErrorKind, sqlite_error,
};
use rusqlite::TransactionBehavior;
use satelle_core::session::{
    LifecycleMutation, RetainedOwnership, Session, StopObservation, StopOutcome, TerminalTurnState,
    TurnState,
};
use satelle_core::{SessionId, TurnId};
use time::OffsetDateTime;

pub(crate) struct StopClaim {
    idempotency: IdempotencyInput,
    recovery_subject: RecoverySubject,
}

pub(crate) struct StopAdmissionTarget {
    turn_id: TurnId,
    requires_control_plane: bool,
}

impl StopAdmissionTarget {
    pub(crate) fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub(crate) const fn requires_control_plane(&self) -> bool {
        self.requires_control_plane
    }
}

impl StopClaim {
    pub(crate) fn recovery_subject(&self) -> &RecoverySubject {
        &self.recovery_subject
    }
}

pub(crate) enum BeginStopOutcome {
    Observe(StopClaim),
    Complete(StopCommit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StopCommitOutcome {
    Stopped(TurnState),
    AlreadyTerminal(TerminalTurnState),
    NotConfirmed {
        ownership: RetainedOwnership,
        changed: bool,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct StopCommit {
    session: Session,
    turn_id: TurnId,
    outcome: StopCommitOutcome,
}

impl StopCommit {
    pub(crate) fn session(&self) -> &Session {
        &self.session
    }

    pub(crate) fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub(crate) fn outcome(&self) -> &StopCommitOutcome {
        &self.outcome
    }
}

impl Storage {
    /// Resolves replay and terminal-stop cases before external capability I/O.
    /// The later `begin_stop` transaction uses this Turn ID as a CAS guard.
    pub(crate) fn stop_admission_target(
        &self,
        session_id: &SessionId,
        idempotency: &IdempotencyInput,
    ) -> Result<StopAdmissionTarget, StorageError> {
        require_operation(idempotency, IdempotentOperation::Stop)?;
        if let Some(record) = matching_idempotency(&self.connection, idempotency)? {
            let turn_id = record
                .turn_id
                .as_deref()
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
                .and_then(|value| {
                    TurnId::parse(value)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
                })?;
            ensure_record_handles(&record, session_id, &turn_id)?;
            let session = load_required_session(&self.connection, session_id)?;
            let turn = session
                .turn(&turn_id)
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            let requires_control_plane =
                match (record.status.as_str(), record.durable_outcome.as_str()) {
                    ("terminal", _) => false,
                    // An interrupted observation leaves this record pending,
                    // but the Turn may have terminalized independently before
                    // the retry. `begin_stop` can then finalize the durable
                    // stop outcome without contacting the control plane.
                    ("in_progress", "v1.stop.pending") => !turn.state().is_terminal(),
                    _ => return Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
                };
            return Ok(StopAdmissionTarget {
                turn_id,
                requires_control_plane,
            });
        }

        let session = load_required_session(&self.connection, session_id)?;
        let turn = session
            .turns()
            .last()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        Ok(StopAdmissionTarget {
            turn_id: turn.id().clone(),
            requires_control_plane: !turn.state().is_terminal(),
        })
    }

    pub(crate) fn begin_stop(
        &mut self,
        session_id: &SessionId,
        expected_turn_id: &TurnId,
        idempotency: &IdempotencyInput,
    ) -> Result<BeginStopOutcome, StorageError> {
        require_operation(idempotency, IdempotentOperation::Stop)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;

        if let Some(record) = matching_idempotency(&transaction, idempotency)? {
            let turn_id = record
                .turn_id
                .as_deref()
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
                .and_then(|value| {
                    TurnId::parse(value)
                        .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
                })?;
            ensure_record_handles(&record, session_id, &turn_id)?;
            let session = load_required_session(&transaction, session_id)?;
            let turn = session
                .turn(&turn_id)
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            if record.status == "terminal" {
                let outcome = parse_stop_outcome(&record.durable_outcome)?;
                transaction
                    .commit()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                return Ok(BeginStopOutcome::Complete(StopCommit {
                    session,
                    turn_id,
                    outcome,
                }));
            }
            if record.durable_outcome != "v1.stop.pending" {
                return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
            }
            if let Ok(state) = TerminalTurnState::try_from(turn.state()) {
                let outcome = StopCommitOutcome::AlreadyTerminal(state);
                let completed_at = OffsetDateTime::now_utc().max(session.updated_at());
                ensure_control_lease_absent(&transaction, session_id, &turn_id)?;
                complete_stop_idempotency(
                    &transaction,
                    idempotency,
                    stop_outcome_token(&outcome)?,
                    completed_at,
                )?;
                insert_safe_log(
                    &transaction,
                    &canonical_log(
                        LogEvent::StopConfirmed,
                        LogSeverity::Warning,
                        &session,
                        &turn_id,
                        completed_at,
                    )?,
                )?;
                transaction
                    .commit()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                return Ok(BeginStopOutcome::Complete(StopCommit {
                    session,
                    turn_id,
                    outcome,
                }));
            }

            // The previous observer did not finish. Rebuild a fresh claim
            // from current durable revisions so the same key can resume.
            ensure_control_lease_present(&transaction, session_id, &turn_id)?;
            let recovery_subject = load_recovery_subject(&transaction, &session, &turn_id)?;
            let claim = StopClaim {
                idempotency: idempotency.clone(),
                recovery_subject,
            };
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(BeginStopOutcome::Observe(claim));
        }

        let session = load_required_session(&transaction, session_id)?;
        let turn_id = session
            .turns()
            .last()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?
            .id()
            .clone();
        if expected_turn_id != &turn_id {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
        let turn = session
            .turn(&turn_id)
            .ok_or_else(|| StorageError::new(StorageErrorKind::StateConflict))?;
        if let Ok(state) = TerminalTurnState::try_from(turn.state()) {
            let outcome = StopCommitOutcome::AlreadyTerminal(state);
            insert_idempotency(
                &transaction,
                idempotency,
                "terminal",
                stop_outcome_token(&outcome)?,
                Some(session_id),
                Some(&turn_id),
                Some(idempotency.created_at),
            )?;
            insert_safe_log(
                &transaction,
                &canonical_log(
                    LogEvent::StopConfirmed,
                    LogSeverity::Warning,
                    &session,
                    &turn_id,
                    idempotency.created_at,
                )?,
            )?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(BeginStopOutcome::Complete(StopCommit {
                session,
                turn_id,
                outcome,
            }));
        }

        ensure_control_lease_present(&transaction, session_id, &turn_id)?;
        let recovery_subject = load_recovery_subject(&transaction, &session, &turn_id)?;
        insert_idempotency(
            &transaction,
            idempotency,
            "in_progress",
            "v1.stop.pending",
            Some(session_id),
            Some(&turn_id),
            None,
        )?;
        let claim = StopClaim {
            idempotency: idempotency.clone(),
            recovery_subject,
        };
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(BeginStopOutcome::Observe(claim))
    }

    pub(crate) fn confirm_stop(
        &mut self,
        claim: StopClaim,
        observation: StopObservation,
        at: OffsetDateTime,
    ) -> Result<StopCommit, StorageError> {
        let session_id = claim.recovery_subject.session_id.clone();
        let turn_id = claim.recovery_subject.turn_id.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        let record = matching_idempotency(&transaction, &claim.idempotency)?
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        ensure_record_handles(&record, &session_id, &turn_id)?;
        if record.status == "terminal" {
            let session = load_required_session(&transaction, &session_id)?;
            let outcome = parse_stop_outcome(&record.durable_outcome)?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(StopCommit {
                session,
                turn_id,
                outcome,
            });
        }

        let mut session = load_required_session(&transaction, &session_id)?;
        let expected = claim.recovery_subject.expected_revisions;
        let previous_state = session
            .turn(&turn_id)
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?
            .state();
        let aggregate_outcome = session
            .stop_turn(&turn_id, expected, observation, at)
            .map_err(StorageError::from)?;
        let (outcome, changed) = match aggregate_outcome {
            StopOutcome::Stopped(_) => (StopCommitOutcome::Stopped(previous_state), true),
            StopOutcome::AlreadyTerminal { state, .. } => {
                (StopCommitOutcome::AlreadyTerminal(state), false)
            }
            StopOutcome::NotConfirmed {
                ownership,
                mutation,
            } => {
                let changed = matches!(mutation, LifecycleMutation::Committed(_));
                (
                    StopCommitOutcome::NotConfirmed { ownership, changed },
                    changed,
                )
            }
        };
        if changed {
            persist_lifecycle_mutation(&transaction, &session, &turn_id, expected)?;
            update_turn_idempotency(&transaction, &session, &turn_id, at)?;
        }
        if matches!(outcome, StopCommitOutcome::AlreadyTerminal(_)) {
            ensure_control_lease_absent(&transaction, &session_id, &turn_id)?;
        } else {
            synchronize_control_lease(&transaction, &session, &turn_id)?;
        }
        complete_stop_idempotency(
            &transaction,
            &claim.idempotency,
            stop_outcome_token(&outcome)?,
            at,
        )?;
        let event = if matches!(outcome, StopCommitOutcome::NotConfirmed { .. }) {
            LogEvent::StopNotConfirmed
        } else {
            LogEvent::StopConfirmed
        };
        insert_safe_log(
            &transaction,
            &canonical_log(event, LogSeverity::Warning, &session, &turn_id, at)?,
        )?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
        Ok(StopCommit {
            session,
            turn_id,
            outcome,
        })
    }
}
