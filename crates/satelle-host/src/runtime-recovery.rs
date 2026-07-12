#[cfg(test)]
use super::RuntimeStartupState;
use super::adapter::{AdapterSubject, RecoveryObservation};
use super::{RuntimeEngine, model};
use crate::storage::{RecoverySubject, StorageErrorKind};
use satelle_core::session::{TurnState, TurnTransition};
use satelle_core::{ControlPlaneOperation, SatelleError, SessionId, TurnId};
use std::collections::VecDeque;
use std::sync::MutexGuard;

impl RuntimeEngine {
    pub(super) fn preserve_unknown_execution(
        &self,
        subject: &RecoverySubject,
    ) -> Result<(), SatelleError> {
        let recovery_subject = {
            let mut storage = self.lock_storage()?;
            let mut session = storage
                .load_session(subject.session_id())
                .map_err(model::storage_failure)?
                .ok_or_else(|| SatelleError::session_not_found(subject.session_id()))?;
            let state = session
                .turn(subject.turn_id())
                .ok_or_else(|| model::integrity_failure("the executing Turn is missing"))?
                .state();
            if state.is_terminal() {
                return Ok(());
            }
            if state != TurnState::RecoveryPending {
                let expected = model::expected_revisions(&session, subject.turn_id())?;
                match storage.commit_lifecycle(
                    subject.session_id(),
                    subject.turn_id(),
                    expected,
                    TurnTransition::RecoveryPending,
                    model::monotonic_now(&session),
                ) {
                    Ok(recovering) => {
                        self.publish_committed_turn(&recovering, subject.turn_id());
                        session = recovering;
                    }
                    Err(error) if error.kind() == StorageErrorKind::StateConflict => {
                        // A pending stop owns the next nonterminal transition
                        // and synchronizes this queue when observation commits.
                        return Ok(());
                    }
                    Err(error) => return Err(model::storage_failure(error)),
                }
            }
            storage
                .recovery_subject(session.id(), subject.turn_id())
                .map_err(model::storage_failure)?
        };
        self.enqueue_recovery_subject(recovery_subject)
    }

    pub(super) fn reconcile_pending(&self) -> Result<bool, SatelleError> {
        loop {
            let Some(subject) = self.claim_recovery_subject()? else {
                return Ok(true);
            };

            // The key remains in-flight, but no mutex is held while the
            // adapter inspects external ownership.
            if let Err(error) = self.adapter.admit_operation(ControlPlaneOperation::Status) {
                if self.restore_recovery_subject(subject)? {
                    return Err(error);
                }
                continue;
            }
            let observation = match self.adapter.observe_recovery(AdapterSubject::new(&subject)) {
                Ok(observation) => observation,
                Err(error) => {
                    if self.restore_recovery_subject(subject)? {
                        return Err(error);
                    }
                    continue;
                }
            };
            let transition = match observation {
                RecoveryObservation::Running => TurnTransition::Running,
                RecoveryObservation::Completed => TurnTransition::Completed,
                RecoveryObservation::Blocked => TurnTransition::Blocked,
                RecoveryObservation::Failed => TurnTransition::Failed,
                RecoveryObservation::Unknown => {
                    if self.restore_recovery_subject(subject)? {
                        return Ok(false);
                    }
                    continue;
                }
            };

            let commit = (|| -> Result<(), SatelleError> {
                let mut storage = self.lock_storage()?;
                let current = storage
                    .load_session(subject.session_id())
                    .map_err(model::storage_failure)?
                    .ok_or_else(|| SatelleError::session_not_found(subject.session_id()))?;
                let observed_at = time::OffsetDateTime::now_utc().max(current.updated_at());
                let committed = storage
                    .commit_lifecycle(
                        subject.session_id(),
                        subject.turn_id(),
                        subject.expected_revisions(),
                        transition,
                        observed_at,
                    )
                    .map_err(model::storage_failure)?;
                self.publish_committed_turn(&committed, subject.turn_id());
                Ok(())
            })();
            match commit {
                Ok(()) => {
                    self.finish_recovery_subject(&subject)?;
                }
                Err(error) => {
                    if self.restore_recovery_subject(subject)? {
                        return Err(error);
                    }
                }
            }
        }
    }

    pub(super) fn reconcile_before_admission(&self) -> Result<(), SatelleError> {
        if self.reconcile_pending()? {
            return Ok(());
        }
        let subject = self
            .first_recovery_subject()?
            .ok_or_else(|| model::integrity_failure("unresolved recovery has no subject"))?;
        Err(model::recovery_host_busy(&subject))
    }

    fn claim_recovery_subject(&self) -> Result<Option<RecoverySubject>, SatelleError> {
        let (key, newly_claimed) = {
            let mut recovery = self.lock_recovery()?;
            if let Some(key) = &recovery.in_flight {
                (key.clone(), false)
            } else {
                let Some(key) = recovery.pending.pop_front() else {
                    return Ok(None);
                };
                recovery.in_flight = Some(key.clone());
                (key, true)
            }
        };
        let subject = match self.load_recovery_subject(&key) {
            Ok(subject) => subject,
            Err(error) => {
                if newly_claimed {
                    let _restored = self.restore_recovery_key(&key)?;
                }
                return Err(error);
            }
        };
        if newly_claimed {
            Ok(Some(subject))
        } else {
            Err(model::recovery_host_busy(&subject))
        }
    }

    fn restore_recovery_subject(&self, subject: RecoverySubject) -> Result<bool, SatelleError> {
        self.restore_recovery_key(&RecoveryKey::from(&subject))
    }

    fn restore_recovery_key(&self, key: &RecoveryKey) -> Result<bool, SatelleError> {
        let mut recovery = self.lock_recovery()?;
        if recovery
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight == key)
        {
            recovery.in_flight = None;
            recovery.pending.push_front(key.clone());
            return Ok(true);
        }
        if recovery.in_flight.is_none() && !recovery.pending.iter().any(|pending| pending == key) {
            // A concurrent confirmed stop can durably resolve and remove the
            // subject while adapter observation is in flight.
            return Ok(false);
        }
        Err(model::integrity_failure(
            "the runtime recovery subject changed while observation was in flight",
        ))
    }

    fn finish_recovery_subject(&self, subject: &RecoverySubject) -> Result<bool, SatelleError> {
        let key = RecoveryKey::from(subject);
        let mut recovery = self.lock_recovery()?;
        if recovery
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight == &key)
        {
            recovery.in_flight = None;
            return Ok(true);
        }
        if recovery.in_flight.is_none() && !recovery.pending.iter().any(|pending| pending == &key) {
            return Ok(false);
        }
        Err(model::integrity_failure(
            "the runtime recovery subject changed while observation was in flight",
        ))
    }

    pub(super) fn remove_recovery_subject(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> Result<(), SatelleError> {
        let key = RecoveryKey::new(session_id.clone(), turn_id.clone());
        let mut recovery = self.lock_recovery()?;
        recovery.pending.retain(|pending| pending != &key);
        if recovery
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight == &key)
        {
            recovery.in_flight = None;
        }
        Ok(())
    }

    pub(super) fn enqueue_recovery_subject(
        &self,
        subject: RecoverySubject,
    ) -> Result<(), SatelleError> {
        let key = RecoveryKey::from(&subject);
        let mut recovery = self.lock_recovery()?;
        if recovery
            .in_flight
            .as_ref()
            .is_some_and(|current| current == &key)
            || recovery.pending.iter().any(|current| current == &key)
        {
            return Ok(());
        }
        recovery.pending.push_back(key);
        Ok(())
    }

    fn first_recovery_subject(&self) -> Result<Option<RecoverySubject>, SatelleError> {
        let key = {
            let recovery = self.lock_recovery()?;
            recovery
                .in_flight
                .as_ref()
                .or_else(|| recovery.pending.front())
                .cloned()
        };
        key.map(|key| self.load_recovery_subject(&key)).transpose()
    }

    fn load_recovery_subject(&self, key: &RecoveryKey) -> Result<RecoverySubject, SatelleError> {
        self.lock_storage()?
            .recovery_subject(&key.session_id, &key.turn_id)
            .map_err(model::storage_failure)
    }

    #[cfg(test)]
    pub(super) fn startup_state(&self) -> Result<RuntimeStartupState, SatelleError> {
        if self.first_recovery_subject()?.is_some() {
            Ok(RuntimeStartupState::RecoveryRequired)
        } else {
            Ok(RuntimeStartupState::Ready)
        }
    }

    fn lock_recovery(&self) -> Result<MutexGuard<'_, RecoveryQueue>, SatelleError> {
        self.recovery.lock().map_err(|_| {
            model::integrity_failure("the runtime recovery lock was poisoned by a failed operation")
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoveryKey {
    session_id: SessionId,
    turn_id: TurnId,
}

impl RecoveryKey {
    fn new(session_id: SessionId, turn_id: TurnId) -> Self {
        Self {
            session_id,
            turn_id,
        }
    }
}

impl From<&RecoverySubject> for RecoveryKey {
    fn from(subject: &RecoverySubject) -> Self {
        Self::new(subject.session_id().clone(), subject.turn_id().clone())
    }
}

pub(super) struct RecoveryQueue {
    pending: VecDeque<RecoveryKey>,
    in_flight: Option<RecoveryKey>,
}

impl RecoveryQueue {
    pub(super) fn new(subjects: Vec<RecoverySubject>) -> Self {
        Self {
            pending: subjects.iter().map(RecoveryKey::from).collect(),
            in_flight: None,
        }
    }
}
