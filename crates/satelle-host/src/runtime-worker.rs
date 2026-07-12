use super::RuntimeTurnOutcome;
use super::adapter::{AdapterSubject, ExecuteRequest, UpstreamReference};
use super::{RuntimeEngine, model};
use crate::storage::{ObservedUpstreamRef, RecoverySubject, StorageErrorKind};
use satelle_core::session::{ExpectedRevisions, Session, TurnTransition};
use satelle_core::{SatelleError, SessionId, TurnId};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use time::OffsetDateTime;

#[derive(Clone)]
pub(super) struct TurnWork {
    pub(super) session: satelle_core::session::Session,
    pub(super) subject: RecoverySubject,
}

pub(super) struct ExecutionPlan {
    pub(super) host: String,
    pub(super) prompt: String,
    pub(super) work: TurnWork,
}

#[derive(Default)]
pub(super) struct WorkerRegistry {
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl WorkerRegistry {
    pub(super) fn reap_finished(&mut self) -> Result<(), SatelleError> {
        let mut running = Vec::with_capacity(self.handles.len());
        for handle in self.handles.drain(..) {
            if handle.is_finished() {
                handle.join().map_err(|_| {
                    model::integrity_failure("a detached runtime worker terminated unexpectedly")
                })?;
            } else {
                running.push(handle);
            }
        }
        self.handles = running;
        Ok(())
    }

    pub(super) fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

impl RuntimeEngine {
    pub(super) fn schedule(self: &Arc<Self>, plan: ExecutionPlan) -> Result<(), SatelleError> {
        let admitted_work = plan.work.clone();
        let engine = Arc::clone(self);
        let mut workers = self.workers.lock().map_err(|_| {
            model::integrity_failure("the detached runtime worker registry was poisoned")
        })?;
        workers.reap_finished()?;
        let spawned = std::thread::Builder::new()
            .name("satelle-runtime-turn".to_string())
            .spawn(move || {
                let subject = plan.work.subject.clone();
                let execution =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| engine.execute(plan)));
                if execution.is_err() {
                    let _preserved = engine.preserve_unknown_execution(&subject);
                }
            });
        match spawned {
            Ok(handle) => {
                workers.handles.push(handle);
                Ok(())
            }
            Err(error) => {
                drop(workers);
                let failure = model::background_execution_failure(error);
                self.fail_unstarted_dispatch(&admitted_work)?;
                Err(failure)
            }
        }
    }

    pub(super) fn execute(&self, plan: ExecutionPlan) -> Result<RuntimeTurnOutcome, SatelleError> {
        let subject = plan.work.subject.clone();
        let outcome = self.execute_once(plan);
        if outcome.is_err() {
            self.preserve_unknown_execution(&subject)?;
        }
        outcome
    }

    fn execute_once(&self, mut plan: ExecutionPlan) -> Result<RuntimeTurnOutcome, SatelleError> {
        let session_id = plan.work.subject.session_id().clone();
        let turn_id = plan.work.subject.turn_id().clone();
        let expected = model::expected_revisions(&plan.work.session, &turn_id)?;
        let (running, running_committed) = self.commit_or_terminal_winner(
            &session_id,
            &turn_id,
            expected,
            TurnTransition::Running,
            model::monotonic_now(&plan.work.session),
        )?;
        plan.work.session = running;
        if !running_committed {
            return model::turn_outcome(&plan.work.session, Vec::new());
        }

        // No runtime or SQLite mutex is held while the external adapter works.
        // The terminal storage compare-and-swap arbitrates with stop/recovery.
        let persist_upstream_ref =
            |reference| self.persist_upstream_ref(&plan.work.subject, reference);
        let execution_policy = plan
            .work
            .session
            .turn(&turn_id)
            .ok_or_else(|| model::integrity_failure("the executing Turn is missing"))?
            .execution_policy();
        let result = self.adapter.execute(ExecuteRequest::new(
            &plan.host,
            &plan.prompt,
            execution_policy,
            AdapterSubject::new(&plan.work.subject),
            &persist_upstream_ref,
        ))?;
        let transition = result.transition();
        if matches!(
            transition,
            TurnTransition::Running | TurnTransition::RecoveryPending
        ) {
            return Err(model::integrity_failure(
                "adapter execution did not produce a terminal outcome",
            ));
        }
        let expected = model::expected_revisions(&plan.work.session, &turn_id)?;
        let (session, execution_committed) = self.commit_or_terminal_winner(
            &session_id,
            &turn_id,
            expected,
            transition,
            model::monotonic_now(&plan.work.session),
        )?;
        let events = if execution_committed {
            result.into_events()
        } else {
            Vec::new()
        };
        model::turn_outcome(&session, events)
    }

    fn persist_upstream_ref(
        &self,
        subject: &RecoverySubject,
        reference: UpstreamReference,
    ) -> Result<(), SatelleError> {
        let observed = match reference {
            UpstreamReference::Thread(value) => ObservedUpstreamRef::thread(value),
            UpstreamReference::Turn(value) => ObservedUpstreamRef::turn(value),
        }
        .map_err(model::storage_failure)?;
        self.lock_storage()?
            .record_upstream_ref(subject.session_id(), subject.turn_id(), &observed)
            .map_err(model::storage_failure)
    }

    fn commit_or_terminal_winner(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
        expected: ExpectedRevisions,
        transition: TurnTransition,
        at: OffsetDateTime,
    ) -> Result<(Session, bool), SatelleError> {
        let mut storage = self.lock_storage()?;
        match storage.commit_lifecycle(session_id, turn_id, expected, transition, at) {
            Ok(session) => {
                self.publish_committed_turn(&session, turn_id);
                Ok((session, true))
            }
            Err(error) if error.kind() == StorageErrorKind::StateConflict => {
                let winner = storage
                    .load_session(session_id)
                    .map_err(model::storage_failure)?
                    .ok_or_else(|| SatelleError::session_not_found(session_id))?;
                let winner_turn = winner.turn(turn_id).ok_or_else(|| {
                    model::integrity_failure("the concurrently resolved Turn is missing")
                })?;
                if !winner_turn.state().is_terminal() {
                    return Err(model::storage_failure(error));
                }
                Ok((winner, false))
            }
            Err(error) => Err(model::storage_failure(error)),
        }
    }

    pub(super) fn fail_unstarted_dispatch(&self, work: &TurnWork) -> Result<(), SatelleError> {
        let session_id = work.subject.session_id();
        let turn_id = work.subject.turn_id();
        let mut session = work.session.clone();
        loop {
            let expected = model::expected_revisions(&session, turn_id)?;
            let mut storage = self.lock_storage()?;
            match storage.commit_lifecycle(
                session_id,
                turn_id,
                expected,
                TurnTransition::Failed,
                model::monotonic_now(&session),
            ) {
                Ok(session) => {
                    self.publish_committed_turn(&session, turn_id);
                    return Ok(());
                }
                Err(error) if error.kind() == StorageErrorKind::StateConflict => {
                    let winner = storage
                        .load_session(session_id)
                        .map_err(model::storage_failure)?
                        .ok_or_else(|| SatelleError::session_not_found(session_id))?;
                    let winner_turn = winner.turn(turn_id).ok_or_else(|| {
                        model::integrity_failure("the failed-dispatch Turn is missing")
                    })?;
                    if winner_turn.state().is_terminal() {
                        return Ok(());
                    }
                    // A concurrent nonterminal stop changed the CAS revision.
                    // No adapter execution was dispatched, so Failed remains
                    // the truthful terminal result and is retried fresh.
                    session = winner;
                }
                Err(error) => return Err(model::storage_failure(error)),
            }
        }
    }
}

#[cfg(test)]
pub(super) fn wait_for_background(workers: &Mutex<WorkerRegistry>) -> Result<(), SatelleError> {
    let handles = {
        let mut workers = workers.lock().map_err(|_| {
            model::integrity_failure("the detached runtime worker registry was poisoned")
        })?;
        std::mem::take(&mut workers.handles)
    };
    for handle in handles {
        handle.join().map_err(|_| {
            model::integrity_failure("a detached runtime worker terminated unexpectedly")
        })?;
    }
    Ok(())
}
