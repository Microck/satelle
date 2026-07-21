use crate::runtime::{AdmissionCancellation, AdmissionCancellationState};
use crate::runtime::{RequestIdentity, RuntimeStopOutcome};
use crate::storage::IdempotentOperation;
use satelle_core::session::PublicSession;
use satelle_core::{SatelleError, TurnId};
use std::fmt;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

const RESOURCE: &str = "operation-concurrency";
const LIMIT: usize = 1;

type SharedResult = Result<OperationOutcome, SatelleError>;

/// The two daemon mutation result shapes that can participate in one shared
/// in-flight operation. Keeping this enum private to the capacity seam avoids
/// type-erased follower results while preserving one Host-global slot.
#[derive(Clone)]
pub(crate) enum OperationOutcome {
    Admission {
        session: PublicSession,
        turn_id: TurnId,
    },
    Stop(RuntimeStopOutcome),
}

impl OperationOutcome {
    pub(crate) fn admission(session: PublicSession, turn_id: TurnId) -> Self {
        Self::Admission { session, turn_id }
    }

    pub(crate) fn into_session(self) -> Result<PublicSession, SatelleError> {
        match self {
            Self::Admission { session, .. } => Ok(session),
            Self::Stop(_) => Err(crate::runtime::integrity_error(
                "the operation-capacity result had the wrong response type",
            )),
        }
    }

    pub(crate) fn into_stop(self) -> Result<RuntimeStopOutcome, SatelleError> {
        match self {
            Self::Stop(outcome) => Ok(outcome),
            Self::Admission { .. } => Err(crate::runtime::integrity_error(
                "the operation-capacity result had the wrong response type",
            )),
        }
    }

    fn into_admission_cancellation(self) -> Result<AdmissionCancellationOutcome, SatelleError> {
        match self {
            Self::Admission { session, turn_id } => {
                Ok(AdmissionCancellationOutcome::Admitted { session, turn_id })
            }
            Self::Stop(_) => Err(crate::runtime::integrity_error(
                "an admission cancellation received a stop result",
            )),
        }
    }
}

/// Coordinates daemon API mutations through one Host-global capacity slot.
///
/// Durable replay is probed before this module takes its mutex. The mutex then
/// performs only an in-memory install, join, conflict, or rejection decision.
/// Registered followers retain the shared entry after the global slot clears.
pub(crate) struct OperationCapacity {
    identity_gate: RwLock<()>,
    state: Mutex<CapacityState>,
    generation: AtomicU64,
    #[cfg(test)]
    registration_changed: Condvar,
    #[cfg(test)]
    test_cancellations: Mutex<Vec<(OperationRequest, AdmissionCancellationOutcome)>>,
    #[cfg(test)]
    cancellation_request_pause: TestCancellationRequestPause,
    #[cfg(test)]
    result_publication_pause: TestCancellationRequestPause,
}

impl fmt::Debug for OperationCapacity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationCapacity")
            .finish_non_exhaustive()
    }
}

impl Default for OperationCapacity {
    fn default() -> Self {
        Self {
            identity_gate: RwLock::new(()),
            state: Mutex::new(CapacityState::default()),
            generation: AtomicU64::new(0),
            #[cfg(test)]
            registration_changed: Condvar::new(),
            #[cfg(test)]
            test_cancellations: Mutex::new(Vec::new()),
            #[cfg(test)]
            cancellation_request_pause: TestCancellationRequestPause::default(),
            #[cfg(test)]
            result_publication_pause: TestCancellationRequestPause::default(),
        }
    }
}

impl OperationCapacity {
    pub(crate) fn lock_identity_read(&self) -> Result<RwLockReadGuard<'_, ()>, SatelleError> {
        self.identity_gate
            .read()
            .map_err(|_| crate::runtime::integrity_error("the request-identity gate was poisoned"))
    }

    pub(crate) fn lock_identity_write(&self) -> Result<RwLockWriteGuard<'_, ()>, SatelleError> {
        self.identity_gate
            .write()
            .map_err(|_| crate::runtime::integrity_error("the request-identity gate was poisoned"))
    }

    pub(crate) fn activity_snapshot(&self) -> Result<(bool, u64), SatelleError> {
        let state = self.lock()?;
        Ok((
            state.active.is_none(),
            self.generation.load(Ordering::Acquire),
        ))
    }

    pub(crate) fn execute(
        &self,
        request: OperationRequest,
        mut replay: impl FnMut() -> Result<Option<OperationOutcome>, SatelleError>,
        operation: impl FnOnce() -> SharedResult,
    ) -> SharedResult {
        self.execute_interruptible_durable(
            request.clone(),
            AdmissionCancellation::new(),
            || {
                if let Some(outcome) = replay()? {
                    return Ok(DurableAdmissionOutcome::Admitted(outcome));
                }
                #[cfg(test)]
                {
                    self.test_cancellation(&request)
                }
                #[cfg(not(test))]
                Ok(DurableAdmissionOutcome::Missing)
            },
            |_| Ok(DurableAdmissionOutcome::Missing),
            |_| operation(),
        )
    }

    #[cfg(test)]
    pub(crate) fn execute_interruptible(
        &self,
        request: OperationRequest,
        cancellation: AdmissionCancellation,
        mut replay: impl FnMut() -> Result<Option<OperationOutcome>, SatelleError>,
        operation: impl FnOnce(AdmissionCancellation) -> SharedResult,
    ) -> SharedResult {
        self.execute_interruptible_durable(
            request.clone(),
            cancellation,
            || {
                if let Some(outcome) = replay()? {
                    return Ok(DurableAdmissionOutcome::Admitted(outcome));
                }
                self.test_cancellation(&request)
            },
            |outcome| self.record_test_cancellation(request.clone(), outcome),
            operation,
        )
    }

    pub(crate) fn execute_interruptible_durable(
        &self,
        request: OperationRequest,
        cancellation: AdmissionCancellation,
        mut resolve: impl FnMut() -> Result<DurableAdmissionOutcome, SatelleError>,
        mut persist_cancellation: impl FnMut(
            AdmissionCancellationOutcome,
        ) -> Result<DurableAdmissionOutcome, SatelleError>,
        operation: impl FnOnce(AdmissionCancellation) -> SharedResult,
    ) -> SharedResult {
        loop {
            // An exact in-memory request owns the authoritative result until
            // it clears. Durable state may already contain an intermediate
            // snapshot that the leader can still replace with a dispatch
            // failure, so matching followers must join before replay.
            let (observed_generation, follower) = {
                let state = self.lock()?;
                let observed_generation = self.generation.load(Ordering::Acquire);
                let follower = self.matching_entry(&state, &request)?;
                (observed_generation, follower)
            };
            if let Some(follower) = follower {
                return follower.wait();
            }

            // The generation makes the replay probe and capacity decision one
            // optimistic read. SQLite work remains outside the mutex, while a
            // concurrent install or clear discards the probe and starts again.
            let replayed = resolve()?;
            if self.generation.load(Ordering::Acquire) != observed_generation {
                continue;
            }
            match replayed {
                DurableAdmissionOutcome::Admitted(replayed) => return Ok(replayed),
                DurableAdmissionOutcome::Cancelled | DurableAdmissionOutcome::RecoveryPending => {
                    return Err(SatelleError::interrupted_attached_command());
                }
                DurableAdmissionOutcome::Missing => {}
            }

            let role = {
                let mut state = self.lock()?;
                if self.generation.load(Ordering::Acquire) != observed_generation {
                    None
                } else if let Some(active) = self.matching_entry(&state, &request)? {
                    Some(Role::Follower(active))
                } else {
                    Some(match &state.active {
                        None => {
                            let entry =
                                Arc::new(InFlight::new(request.clone(), cancellation.clone()));
                            state.active = Some(ActiveOperation::Idempotent(Arc::clone(&entry)));
                            self.generation.fetch_add(1, Ordering::Release);
                            #[cfg(test)]
                            self.registration_changed.notify_all();
                            Role::Leader(entry)
                        }
                        Some(_) => {
                            return Err(SatelleError::capacity_exceeded(RESOURCE, LIMIT));
                        }
                    })
                }
            };
            let Some(role) = role else {
                continue;
            };

            return match role {
                Role::Leader(entry) => {
                    CapacityLeader::new(self, entry).run(operation, &mut persist_cancellation)
                }
                Role::Follower(entry) => entry.wait(),
            };
        }
    }

    #[cfg(test)]
    pub(crate) fn cancel(
        &self,
        request: OperationRequest,
        mut replay: impl FnMut() -> Result<Option<OperationOutcome>, SatelleError>,
    ) -> Result<AdmissionCancellationOutcome, SatelleError> {
        self.cancel_durable(
            request.clone(),
            || {
                if let Some(outcome) = replay()? {
                    return Ok(DurableAdmissionOutcome::Admitted(outcome));
                }
                self.test_cancellation(&request)
            },
            |outcome| self.record_test_cancellation(request.clone(), outcome),
        )
    }

    #[cfg(test)]
    fn test_cancellation(
        &self,
        request: &OperationRequest,
    ) -> Result<DurableAdmissionOutcome, SatelleError> {
        let cancellations = self.test_cancellations.lock().map_err(|_| {
            crate::runtime::integrity_error("the test cancellation lock was poisoned")
        })?;
        let Some((stored, outcome)) = cancellations
            .iter()
            .find(|(stored, _)| stored.same_base(request))
        else {
            return Ok(DurableAdmissionOutcome::Missing);
        };
        if stored != request {
            return Err(crate::runtime::idempotency_conflict());
        }
        Ok(match outcome {
            AdmissionCancellationOutcome::Cancelled
            | AdmissionCancellationOutcome::ReconciledCancelled => {
                DurableAdmissionOutcome::Cancelled
            }
            AdmissionCancellationOutcome::RecoveryPending => {
                DurableAdmissionOutcome::RecoveryPending
            }
            AdmissionCancellationOutcome::Admitted { .. } => DurableAdmissionOutcome::Missing,
        })
    }

    #[cfg(test)]
    fn record_test_cancellation(
        &self,
        request: OperationRequest,
        outcome: AdmissionCancellationOutcome,
    ) -> Result<DurableAdmissionOutcome, SatelleError> {
        let mut cancellations = self.test_cancellations.lock().map_err(|_| {
            crate::runtime::integrity_error("the test cancellation lock was poisoned")
        })?;
        let stored_outcome = if let Some((stored, stored_outcome)) = cancellations
            .iter_mut()
            .find(|(stored, _)| stored.same_base(&request))
        {
            if stored != &request {
                return Err(crate::runtime::idempotency_conflict());
            }
            match outcome {
                AdmissionCancellationOutcome::RecoveryPending => {
                    *stored_outcome = AdmissionCancellationOutcome::RecoveryPending;
                }
                AdmissionCancellationOutcome::ReconciledCancelled => {
                    *stored_outcome = AdmissionCancellationOutcome::Cancelled;
                }
                AdmissionCancellationOutcome::Cancelled
                | AdmissionCancellationOutcome::Admitted { .. } => {}
            }
            stored_outcome.clone()
        } else {
            let outcome = match outcome {
                AdmissionCancellationOutcome::ReconciledCancelled => {
                    AdmissionCancellationOutcome::Cancelled
                }
                outcome => outcome,
            };
            cancellations.push((request, outcome.clone()));
            outcome
        };
        Ok(match stored_outcome {
            AdmissionCancellationOutcome::Cancelled
            | AdmissionCancellationOutcome::ReconciledCancelled => {
                DurableAdmissionOutcome::Cancelled
            }
            AdmissionCancellationOutcome::RecoveryPending => {
                DurableAdmissionOutcome::RecoveryPending
            }
            AdmissionCancellationOutcome::Admitted { .. } => DurableAdmissionOutcome::Missing,
        })
    }

    pub(crate) fn cancel_durable(
        &self,
        request: OperationRequest,
        mut resolve: impl FnMut() -> Result<DurableAdmissionOutcome, SatelleError>,
        mut persist_cancellation: impl FnMut(
            AdmissionCancellationOutcome,
        ) -> Result<DurableAdmissionOutcome, SatelleError>,
    ) -> Result<AdmissionCancellationOutcome, SatelleError> {
        let entry = loop {
            let (observed_generation, active) = {
                let state = self.lock()?;
                (
                    self.generation.load(Ordering::Acquire),
                    self.matching_entry(&state, &request)?,
                )
            };
            if let Some(active) = active {
                #[cfg(test)]
                self.cancellation_request_pause.pause_if_armed();
                let registration = active.request_cancellation();
                #[cfg(test)]
                self.registration_changed.notify_all();
                match registration {
                    CancellationRegistration::Completed(result) => {
                        return completed_cancellation_outcome(
                            result,
                            &mut resolve,
                            &mut persist_cancellation,
                        );
                    }
                    CancellationRegistration::Requested => {
                        match persist_cancellation(AdmissionCancellationOutcome::RecoveryPending)? {
                            DurableAdmissionOutcome::Admitted(outcome) => {
                                return outcome.into_admission_cancellation();
                            }
                            DurableAdmissionOutcome::Missing
                            | DurableAdmissionOutcome::Cancelled
                            | DurableAdmissionOutcome::RecoveryPending => {}
                        }
                    }
                }
                break active;
            }
            match resolve()? {
                DurableAdmissionOutcome::Admitted(outcome) => {
                    return outcome.into_admission_cancellation();
                }
                DurableAdmissionOutcome::Cancelled => {
                    return Ok(AdmissionCancellationOutcome::Cancelled);
                }
                DurableAdmissionOutcome::RecoveryPending => {
                    return Ok(AdmissionCancellationOutcome::RecoveryPending);
                }
                DurableAdmissionOutcome::Missing => {}
            }
            if self.generation.load(Ordering::Acquire) != observed_generation {
                continue;
            }
            let persisted = persist_cancellation(AdmissionCancellationOutcome::Cancelled)?;
            let active = {
                let state = self.lock()?;
                // Persistence and registration linearize through this
                // generation advance. An admission that resolved Missing
                // before the tombstone but has not installed yet must retry
                // its durable resolve after taking the capacity mutex.
                self.generation.fetch_add(1, Ordering::Release);
                self.matching_entry(&state, &request)?
            };
            let Some(active) = active else {
                return match persisted {
                    DurableAdmissionOutcome::Admitted(outcome) => {
                        outcome.into_admission_cancellation()
                    }
                    DurableAdmissionOutcome::Cancelled | DurableAdmissionOutcome::Missing => {
                        Ok(AdmissionCancellationOutcome::Cancelled)
                    }
                    DurableAdmissionOutcome::RecoveryPending => {
                        Ok(AdmissionCancellationOutcome::RecoveryPending)
                    }
                };
            };
            #[cfg(test)]
            self.cancellation_request_pause.pause_if_armed();
            let registration = active.request_cancellation();
            #[cfg(test)]
            self.registration_changed.notify_all();
            match registration {
                CancellationRegistration::Completed(result) => {
                    return completed_cancellation_outcome(
                        result,
                        &mut resolve,
                        &mut persist_cancellation,
                    );
                }
                CancellationRegistration::Requested => {
                    match persist_cancellation(AdmissionCancellationOutcome::RecoveryPending)? {
                        DurableAdmissionOutcome::Admitted(outcome) => {
                            return outcome.into_admission_cancellation();
                        }
                        DurableAdmissionOutcome::Missing
                        | DurableAdmissionOutcome::Cancelled
                        | DurableAdmissionOutcome::RecoveryPending => {}
                    }
                }
            }
            break active;
        };
        let outcome = match entry.wait() {
            Ok(outcome) => outcome.into_admission_cancellation(),
            Err(_) => match entry.cancellation.state() {
                AdmissionCancellationState::Cancelled => {
                    Ok(AdmissionCancellationOutcome::Cancelled)
                }
                AdmissionCancellationState::Admitted { .. } => match resolve()? {
                    DurableAdmissionOutcome::Admitted(outcome) => {
                        outcome.into_admission_cancellation()
                    }
                    DurableAdmissionOutcome::Missing
                    | DurableAdmissionOutcome::Cancelled
                    | DurableAdmissionOutcome::RecoveryPending => {
                        Err(crate::runtime::integrity_error(
                            "an admitted cancellation had no durable admission replay",
                        ))
                    }
                },
                AdmissionCancellationState::Open
                | AdmissionCancellationState::Requested
                | AdmissionCancellationState::RecoveryPending => {
                    Ok(AdmissionCancellationOutcome::RecoveryPending)
                }
            },
        }?;
        if matches!(
            outcome,
            AdmissionCancellationOutcome::Cancelled | AdmissionCancellationOutcome::RecoveryPending
        ) {
            let persisted_outcome = match outcome {
                AdmissionCancellationOutcome::Cancelled => {
                    AdmissionCancellationOutcome::ReconciledCancelled
                }
                _ => outcome.clone(),
            };
            match persist_cancellation(persisted_outcome)? {
                DurableAdmissionOutcome::Admitted(admitted) => {
                    return admitted.into_admission_cancellation();
                }
                DurableAdmissionOutcome::RecoveryPending => {
                    return Ok(AdmissionCancellationOutcome::RecoveryPending);
                }
                DurableAdmissionOutcome::Cancelled => {
                    return Ok(AdmissionCancellationOutcome::Cancelled);
                }
                DurableAdmissionOutcome::Missing => {}
            }
        }
        Ok(outcome)
    }

    fn finalize_and_clear(&self, entry: &Arc<InFlight>) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.active.as_ref().is_some_and(
            |active| matches!(active, ActiveOperation::Idempotent(active) if Arc::ptr_eq(active, entry)),
        ) {
            state.active = None;
            self.generation.fetch_add(1, Ordering::Release);
        }
        #[cfg(test)]
        self.registration_changed.notify_all();
    }

    /// Runs a mutation whose durable idempotency is owned by another boundary
    /// while still sharing the Host-global operation slot.
    pub(crate) fn execute_exclusive<T>(
        &self,
        operation: impl FnOnce() -> Result<T, SatelleError>,
    ) -> Result<T, SatelleError> {
        {
            let mut state = self.lock()?;
            if state.active.is_some() {
                return Err(SatelleError::capacity_exceeded(RESOURCE, LIMIT));
            }
            state.active = Some(ActiveOperation::Exclusive);
            self.generation.fetch_add(1, Ordering::Release);
            #[cfg(test)]
            self.registration_changed.notify_all();
        }
        ExclusiveCapacityLeader::new(self).run(operation)
    }

    fn matching_entry(
        &self,
        state: &CapacityState,
        request: &OperationRequest,
    ) -> Result<Option<Arc<InFlight>>, SatelleError> {
        let Some(ActiveOperation::Idempotent(active)) = &state.active else {
            return Ok(None);
        };
        if active.request.same_base(request) && active.request != *request {
            return Err(crate::runtime::idempotency_conflict());
        }
        if active.request != *request {
            return Ok(None);
        }
        #[cfg(test)]
        {
            active.followers.fetch_add(1, Ordering::SeqCst);
            self.registration_changed.notify_all();
        }
        Ok(Some(Arc::clone(active)))
    }

    fn lock(&self) -> Result<MutexGuard<'_, CapacityState>, SatelleError> {
        self.state.lock().map_err(|_| {
            crate::runtime::integrity_error("the operation-capacity lock was poisoned")
        })
    }

    fn clear_exclusive(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if matches!(state.active, Some(ActiveOperation::Exclusive)) {
            state.active = None;
            self.generation.fetch_add(1, Ordering::Release);
        }
        #[cfg(test)]
        self.registration_changed.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn wait_for_follower_registration(&self, timeout: std::time::Duration) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok((state, _)) =
            self.registration_changed
                .wait_timeout_while(state, timeout, |state| {
                    !matches!(
                        state.active.as_ref(),
                        Some(ActiveOperation::Idempotent(active))
                            if active.followers.load(Ordering::SeqCst) > 0
                    )
                })
        else {
            return false;
        };
        matches!(
            state.active.as_ref(),
            Some(ActiveOperation::Idempotent(active))
                if active.followers.load(Ordering::SeqCst) > 0
        )
    }

    #[cfg(test)]
    pub(crate) fn wait_for_cancellation_request(&self, timeout: std::time::Duration) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        let Ok((state, _)) =
            self.registration_changed
                .wait_timeout_while(state, timeout, |state| {
                    !matches!(
                        state.active.as_ref(),
                        Some(ActiveOperation::Idempotent(active))
                            if active.cancellation.is_requested()
                    )
                })
        else {
            return false;
        };
        matches!(
            state.active.as_ref(),
            Some(ActiveOperation::Idempotent(active)) if active.cancellation.is_requested()
        )
    }

    #[cfg(test)]
    pub(crate) fn pause_next_cancellation_before_request(&self) {
        self.cancellation_request_pause.arm();
    }

    #[cfg(test)]
    pub(crate) fn wait_for_cancellation_before_request(
        &self,
        timeout: std::time::Duration,
    ) -> bool {
        self.cancellation_request_pause.wait_until_paused(timeout)
    }

    #[cfg(test)]
    pub(crate) fn release_cancellation_before_request(&self) {
        self.cancellation_request_pause.release();
    }

    #[cfg(test)]
    pub(crate) fn pause_next_result_before_clear(&self) {
        self.result_publication_pause.arm();
    }

    #[cfg(test)]
    pub(crate) fn wait_for_result_before_clear(&self, timeout: std::time::Duration) -> bool {
        self.result_publication_pause.wait_until_paused(timeout)
    }

    #[cfg(test)]
    pub(crate) fn release_result_before_clear(&self) {
        self.result_publication_pause.release();
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestCancellationRequestPause {
    state: Mutex<TestCancellationRequestPauseState>,
    changed: Condvar,
}

#[cfg(test)]
#[derive(Default)]
struct TestCancellationRequestPauseState {
    armed: bool,
    paused: bool,
    released: bool,
}

#[cfg(test)]
impl TestCancellationRequestPause {
    fn arm(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        *state = TestCancellationRequestPauseState {
            armed: true,
            paused: false,
            released: false,
        };
    }

    fn pause_if_armed(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.armed {
            return;
        }
        state.paused = true;
        self.changed.notify_all();
        while !state.released {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        state.armed = false;
    }

    fn wait_until_paused(&self, timeout: std::time::Duration) -> bool {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| !state.paused)
            .unwrap_or_else(|error| error.into_inner());
        state.paused
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.released = true;
        self.changed.notify_all();
    }
}

#[derive(Default)]
struct CapacityState {
    active: Option<ActiveOperation>,
}

enum ActiveOperation {
    Idempotent(Arc<InFlight>),
    Exclusive,
}

enum Role {
    Leader(Arc<InFlight>),
    Follower(Arc<InFlight>),
}

struct InFlight {
    request: OperationRequest,
    cancellation: AdmissionCancellation,
    result: Mutex<Option<SharedResult>>,
    completed: Condvar,
    #[cfg(test)]
    followers: AtomicUsize,
}

impl InFlight {
    fn new(request: OperationRequest, cancellation: AdmissionCancellation) -> Self {
        Self {
            request,
            cancellation,
            result: Mutex::new(None),
            completed: Condvar::new(),
            #[cfg(test)]
            followers: AtomicUsize::new(0),
        }
    }

    fn lock_result(&self) -> MutexGuard<'_, Option<SharedResult>> {
        match self.result.lock() {
            Ok(stored) => stored,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn request_cancellation(&self) -> CancellationRegistration {
        let stored = self.lock_result();
        if let Some(result) = stored.as_ref() {
            return CancellationRegistration::Completed(result.clone());
        }
        self.cancellation.request();
        CancellationRegistration::Requested
    }

    fn complete_locked(
        &self,
        stored: &mut MutexGuard<'_, Option<SharedResult>>,
        result: SharedResult,
    ) {
        if stored.is_none() {
            **stored = Some(result);
        }
        self.completed.notify_all();
    }

    fn wait(&self) -> SharedResult {
        let mut stored = self.result.lock().map_err(|_| {
            crate::runtime::integrity_error("the in-flight operation result lock was poisoned")
        })?;
        loop {
            if let Some(result) = stored.as_ref() {
                return result.clone();
            }
            stored = self.completed.wait(stored).map_err(|_| {
                crate::runtime::integrity_error("the in-flight operation wait lock was poisoned")
            })?;
        }
    }
}

enum CancellationRegistration {
    Requested,
    Completed(SharedResult),
}

fn completed_cancellation_outcome(
    result: SharedResult,
    resolve: &mut impl FnMut() -> Result<DurableAdmissionOutcome, SatelleError>,
    persist_cancellation: &mut impl FnMut(
        AdmissionCancellationOutcome,
    ) -> Result<DurableAdmissionOutcome, SatelleError>,
) -> Result<AdmissionCancellationOutcome, SatelleError> {
    if let Ok(outcome) = result {
        return outcome.into_admission_cancellation();
    }
    match resolve()? {
        DurableAdmissionOutcome::Admitted(outcome) => outcome.into_admission_cancellation(),
        DurableAdmissionOutcome::RecoveryPending => {
            Ok(AdmissionCancellationOutcome::RecoveryPending)
        }
        DurableAdmissionOutcome::Cancelled => Ok(AdmissionCancellationOutcome::Cancelled),
        DurableAdmissionOutcome::Missing => {
            match persist_cancellation(AdmissionCancellationOutcome::Cancelled)? {
                DurableAdmissionOutcome::Admitted(outcome) => outcome.into_admission_cancellation(),
                DurableAdmissionOutcome::RecoveryPending => {
                    Ok(AdmissionCancellationOutcome::RecoveryPending)
                }
                DurableAdmissionOutcome::Cancelled | DurableAdmissionOutcome::Missing => {
                    Ok(AdmissionCancellationOutcome::Cancelled)
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) enum AdmissionCancellationOutcome {
    Cancelled,
    ReconciledCancelled,
    Admitted {
        session: PublicSession,
        turn_id: TurnId,
    },
    RecoveryPending,
}

pub(crate) enum DurableAdmissionOutcome {
    Missing,
    Admitted(OperationOutcome),
    Cancelled,
    RecoveryPending,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OperationRequest {
    principal_ref: String,
    operation: IdempotentOperation,
    idempotency_key: String,
    request_digest: String,
    digest_schema_version: u16,
    hmac_key_version: u16,
}

impl OperationRequest {
    pub(crate) fn new(operation: IdempotentOperation, identity: &RequestIdentity) -> Self {
        Self {
            principal_ref: identity.principal_ref().to_string(),
            operation,
            idempotency_key: identity.key().to_string(),
            request_digest: identity.request_digest().to_string(),
            digest_schema_version: identity.digest_schema_version(),
            hmac_key_version: identity.hmac_key_version(),
        }
    }

    fn same_base(&self, other: &Self) -> bool {
        self.principal_ref == other.principal_ref
            && self.operation == other.operation
            && self.idempotency_key == other.idempotency_key
    }
}

struct CapacityLeader<'a> {
    capacity: &'a OperationCapacity,
    entry: Arc<InFlight>,
    finished: bool,
}

impl<'a> CapacityLeader<'a> {
    fn new(capacity: &'a OperationCapacity, entry: Arc<InFlight>) -> Self {
        Self {
            capacity,
            entry,
            finished: false,
        }
    }

    fn run(
        mut self,
        operation: impl FnOnce(AdmissionCancellation) -> SharedResult,
        persist_cancellation: &mut impl FnMut(
            AdmissionCancellationOutcome,
        ) -> Result<DurableAdmissionOutcome, SatelleError>,
    ) -> SharedResult {
        let mut result = operation(self.entry.cancellation.clone());
        let mut stored = self.entry.lock_result();
        let cancellation_outcome = match self.entry.cancellation.state() {
            AdmissionCancellationState::Cancelled => {
                Some(AdmissionCancellationOutcome::ReconciledCancelled)
            }
            AdmissionCancellationState::Requested => {
                self.entry
                    .cancellation
                    .finish(AdmissionCancellationState::Cancelled);
                Some(AdmissionCancellationOutcome::ReconciledCancelled)
            }
            AdmissionCancellationState::RecoveryPending => {
                Some(AdmissionCancellationOutcome::RecoveryPending)
            }
            AdmissionCancellationState::Open | AdmissionCancellationState::Admitted { .. } => None,
        };
        if let Some(outcome) = cancellation_outcome
            && let Err(error) = persist_cancellation(outcome)
        {
            result = Err(error);
        }
        self.entry.complete_locked(&mut stored, result.clone());
        #[cfg(test)]
        self.capacity.result_publication_pause.pause_if_armed();
        self.capacity.finalize_and_clear(&self.entry);
        self.finished = true;
        result
    }
}

impl Drop for CapacityLeader<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut stored = self.entry.lock_result();
        self.entry.complete_locked(
            &mut stored,
            Err(crate::runtime::integrity_error(
                "the in-flight operation terminated before producing a result",
            )),
        );
        #[cfg(test)]
        self.capacity.result_publication_pause.pause_if_armed();
        self.capacity.finalize_and_clear(&self.entry);
    }
}

struct ExclusiveCapacityLeader<'a> {
    capacity: &'a OperationCapacity,
    finished: bool,
}

impl<'a> ExclusiveCapacityLeader<'a> {
    fn new(capacity: &'a OperationCapacity) -> Self {
        Self {
            capacity,
            finished: false,
        }
    }

    fn run<T>(
        mut self,
        operation: impl FnOnce() -> Result<T, SatelleError>,
    ) -> Result<T, SatelleError> {
        let result = operation();
        self.capacity.clear_exclusive();
        self.finished = true;
        result
    }
}

impl Drop for ExclusiveCapacityLeader<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.capacity.clear_exclusive();
        }
    }
}
