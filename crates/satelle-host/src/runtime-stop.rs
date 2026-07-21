use super::adapter::AdapterSubject;
use super::{RequestIdentity, RuntimeEngine, RuntimeHandle, StopCommand, model};
use crate::storage::{BeginStopOutcome, StopCommit, StopCommitOutcome, StorageErrorKind};
use satelle_core::session::TurnState;
use satelle_core::{ControlPlaneOperation, SatelleError, SessionId, StopResult};

#[derive(Clone)]
pub(crate) struct RuntimeStopOutcome {
    pub(crate) result: StopResult,
    pub(crate) session_state_revision: satelle_core::session::SessionStateRevision,
    pub(crate) turn_state_revision: satelle_core::session::TurnStateRevision,
}

impl RuntimeEngine {
    fn replay_completed_stop_if_present(
        &self,
        session_id: &SessionId,
        identity: &RequestIdentity,
    ) -> Result<Option<RuntimeStopOutcome>, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        self.maintain_session_retention(requested_at)?;
        let idempotency = model::stop_idempotency(requested_at, identity)?;
        self.lock_storage()?
            .replay_completed_stop_if_present(session_id, &idempotency)
            .map_err(|error| model::storage_failure_for_session(error, session_id))?
            .map(|commit| Self::stop_outcome(&commit, session_id))
            .transpose()
    }

    fn stop(&self, command: StopCommand) -> Result<RuntimeStopOutcome, SatelleError> {
        let requested_at = time::OffsetDateTime::now_utc();
        self.maintain_session_retention(requested_at)?;
        let idempotency = model::stop_idempotency(requested_at, &command.identity)?;
        let outcome = loop {
            let target = self
                .lock_storage()?
                .stop_admission_target(
                    &command.session_id,
                    &idempotency,
                    command.expected_turn_id.as_ref(),
                )
                .map_err(|error| model::storage_failure_for_session(error, &command.session_id))?;
            if target.requires_control_plane() {
                self.adapter.admit_operation(ControlPlaneOperation::Stop)?;
            }
            let turn_id = target.turn_id().clone();
            match self
                .lock_storage()?
                .begin_stop(&command.session_id, &turn_id, &idempotency)
            {
                Ok(outcome) => break outcome,
                Err(error)
                    if error.kind() == StorageErrorKind::StateConflict
                        && command.expected_turn_id.is_none() =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(model::storage_failure_for_session(
                        error,
                        &command.session_id,
                    ));
                }
            }
        };
        let commit = match outcome {
            BeginStopOutcome::Complete(commit) => commit,
            BeginStopOutcome::Observe(claim) => {
                // Stop observation is external I/O and must not serialize
                // status, logs, or the terminal execution compare-and-swap.
                let observation = self
                    .adapter
                    .observe_stop(AdapterSubject::new(claim.recovery_subject()))?;
                let mut storage = self.lock_storage()?;
                let current = storage
                    .load_session(&command.session_id)
                    .map_err(model::storage_failure)?
                    .ok_or_else(|| SatelleError::session_not_found(&command.session_id))?;
                let confirmed_at = time::OffsetDateTime::now_utc().max(current.updated_at());
                let commit = storage
                    .confirm_stop(claim, observation, confirmed_at)
                    .map_err(model::storage_failure)?;
                let stop_committed = matches!(commit.outcome(), StopCommitOutcome::Stopped(_));
                drop(storage);
                if stop_committed {
                    self.adapter
                        .stop_committed(commit.session().id(), commit.turn_id());
                }
                if matches!(
                    commit.outcome(),
                    StopCommitOutcome::Stopped(_)
                        | StopCommitOutcome::NotConfirmed { changed: true, .. }
                ) {
                    self.publish_committed_turn(commit.session(), commit.turn_id());
                }
                commit
            }
        };
        let committed_turn = commit
            .session()
            .turn(commit.turn_id())
            .ok_or_else(|| model::integrity_failure("the stopped Turn is missing"))?;
        if committed_turn.state() == TurnState::RecoveryPending {
            let subject = self
                .lock_storage()?
                .recovery_subject(&command.session_id, commit.turn_id())
                .map_err(model::storage_failure)?;
            self.enqueue_recovery_subject(subject)?;
        } else {
            self.remove_recovery_subject(&command.session_id, commit.turn_id())?;
        }
        Self::stop_outcome(&commit, &command.session_id)
    }

    fn stop_outcome(
        commit: &StopCommit,
        session_id: &SessionId,
    ) -> Result<RuntimeStopOutcome, SatelleError> {
        let committed_turn = commit
            .session()
            .turn(commit.turn_id())
            .ok_or_else(|| model::integrity_failure("the stopped Turn is missing"))?;
        Ok(RuntimeStopOutcome {
            result: model::stop_result(commit, session_id)?,
            session_state_revision: commit.session().session_state_revision(),
            turn_state_revision: committed_turn.turn_state_revision(),
        })
    }
}

impl RuntimeHandle {
    pub(crate) fn replay_completed_stop_if_present(
        &self,
        session_id: &SessionId,
        identity: &RequestIdentity,
    ) -> Result<Option<RuntimeStopOutcome>, SatelleError> {
        let Some(engine) = self.existing_engine()? else {
            return Ok(None);
        };
        engine.replay_completed_stop_if_present(session_id, identity)
    }

    pub(crate) fn stop(&self, command: StopCommand) -> Result<StopResult, SatelleError> {
        self.stop_with_snapshot(command)
            .map(|outcome| outcome.result)
    }

    pub(crate) fn stop_with_snapshot(
        &self,
        command: StopCommand,
    ) -> Result<RuntimeStopOutcome, SatelleError> {
        self.engine()?.stop(command)
    }
}
