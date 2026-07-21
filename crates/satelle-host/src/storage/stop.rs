use super::codec::{
    load_required_session, load_session_at_operation_outcome, parse_stop_outcome,
    stop_outcome_token,
};
use super::logs::canonical_log;
use super::sql::{
    StoredIdempotency, complete_stop_idempotency, ensure_control_lease_absent,
    ensure_control_lease_present, ensure_record_handles, insert_idempotency, insert_safe_log,
    load_recovery_subject, matching_idempotency, persist_lifecycle_mutation, require_operation,
    synchronize_control_lease, update_turn_idempotency,
};
use super::{
    IdempotencyInput, IdempotentOperation, LogEvent, LogSeverity, RecoverySubject, Storage,
    StorageError, StorageErrorKind, sqlite_error,
};
use rusqlite::{Connection, TransactionBehavior};
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

fn stop_record_turn_id(
    record: &StoredIdempotency,
    session_id: &SessionId,
) -> Result<TurnId, StorageError> {
    let turn_id = record
        .turn_id
        .as_deref()
        .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))
        .and_then(|value| {
            TurnId::parse(value)
                .map_err(|_| StorageError::new(StorageErrorKind::InvalidStoredState))
        })?;
    ensure_record_handles(record, session_id, &turn_id)?;
    Ok(turn_id)
}

fn completed_stop_commit(
    connection: &Connection,
    record: &StoredIdempotency,
    session_id: &SessionId,
) -> Result<StopCommit, StorageError> {
    if record.status != "terminal" {
        return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
    }
    let turn_id = stop_record_turn_id(record, session_id)?;
    let outcome = parse_stop_outcome(&record.durable_outcome)?;
    let session = if matches!(outcome, StopCommitOutcome::NotConfirmed { .. }) {
        // A not-confirmed response contains only durable ownership metadata.
        // The retained worker may advance the Turn after this response, so
        // combining its current row with the response's historical Session
        // revision would create an internally inconsistent snapshot.
        load_required_session(connection, session_id)?
    } else {
        let session_revision = record
            .result_session_state_revision
            .as_deref()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        let session_updated_at = record
            .result_session_updated_at
            .as_deref()
            .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
        load_session_at_operation_outcome(
            connection,
            session_id,
            &turn_id,
            session_revision,
            session_updated_at,
        )?
    };
    Ok(StopCommit {
        session,
        turn_id,
        outcome,
    })
}

impl Storage {
    /// Returns a completed stop replay without creating or advancing a stop
    /// claim. Pending records deliberately remain capacity-controlled.
    pub(crate) fn replay_completed_stop_if_present(
        &self,
        session_id: &SessionId,
        idempotency: &IdempotencyInput,
    ) -> Result<Option<StopCommit>, StorageError> {
        require_operation(idempotency, IdempotentOperation::Stop)?;
        let Some(record) = matching_idempotency(&self.connection, idempotency)? else {
            return Ok(None);
        };
        match (record.status.as_str(), record.durable_outcome.as_str()) {
            ("in_progress", "v1.stop.pending") => Ok(None),
            ("terminal", _) => {
                completed_stop_commit(&self.connection, &record, session_id).map(Some)
            }
            _ => Err(StorageError::new(StorageErrorKind::InvalidStoredState)),
        }
    }

    /// Resolves replay and terminal-stop cases before external capability I/O.
    /// The later `begin_stop` transaction uses this Turn ID as a CAS guard.
    pub(crate) fn stop_admission_target(
        &self,
        session_id: &SessionId,
        idempotency: &IdempotencyInput,
        expected_turn_id: Option<&TurnId>,
    ) -> Result<StopAdmissionTarget, StorageError> {
        require_operation(idempotency, IdempotentOperation::Stop)?;
        if let Some(record) = matching_idempotency(&self.connection, idempotency)? {
            let turn_id = stop_record_turn_id(&record, session_id)?;
            if expected_turn_id.is_some_and(|expected| expected != &turn_id) {
                return Err(StorageError::new(StorageErrorKind::IdempotencyConflict));
            }
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
        if expected_turn_id.is_some_and(|expected| expected != turn.id()) {
            return Err(StorageError::new(StorageErrorKind::StateConflict));
        }
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
            let turn_id = stop_record_turn_id(&record, session_id)?;
            if record.status == "terminal" {
                let commit = completed_stop_commit(&transaction, &record, session_id)?;
                transaction
                    .commit()
                    .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
                return Ok(BeginStopOutcome::Complete(commit));
            }
            if record.durable_outcome != "v1.stop.pending" {
                return Err(StorageError::new(StorageErrorKind::InvalidStoredState));
            }
            let session = load_required_session(&transaction, session_id)?;
            let turn = session
                .turn(&turn_id)
                .ok_or_else(|| StorageError::new(StorageErrorKind::InvalidStoredState))?;
            if let Ok(state) = TerminalTurnState::try_from(turn.state()) {
                let outcome = StopCommitOutcome::AlreadyTerminal(state);
                let completed_at = OffsetDateTime::now_utc().max(session.updated_at());
                ensure_control_lease_absent(&transaction, session_id, &turn_id)?;
                complete_stop_idempotency(
                    &transaction,
                    idempotency,
                    stop_outcome_token(&outcome)?,
                    &session,
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
                "in_progress",
                "v1.stop.pending",
                Some(session_id),
                Some(&turn_id),
                None,
            )?;
            complete_stop_idempotency(
                &transaction,
                idempotency,
                stop_outcome_token(&outcome)?,
                &session,
                idempotency.created_at,
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
            let commit = completed_stop_commit(&transaction, &record, &session_id)?;
            transaction
                .commit()
                .map_err(|source| sqlite_error(StorageErrorKind::OperationFailed, source))?;
            return Ok(commit);
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
            &session,
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
