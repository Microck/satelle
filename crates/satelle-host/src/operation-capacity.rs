use crate::runtime::{RequestIdentity, RuntimeStopOutcome};
use crate::storage::IdempotentOperation;
use satelle_core::SatelleError;
use satelle_core::session::PublicSession;
use std::fmt;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

const RESOURCE: &str = "operation-concurrency";
const LIMIT: usize = 1;

type SharedResult = Result<OperationOutcome, SatelleError>;

/// The two daemon mutation result shapes that can participate in one shared
/// in-flight operation. Keeping this enum private to the capacity seam avoids
/// type-erased follower results while preserving one Host-global slot.
#[derive(Clone)]
pub(crate) enum OperationOutcome {
    Session(PublicSession),
    Stop(RuntimeStopOutcome),
}

impl OperationOutcome {
    pub(crate) fn into_session(self) -> Result<PublicSession, SatelleError> {
        match self {
            Self::Session(session) => Ok(session),
            Self::Stop(_) => Err(crate::runtime::integrity_error(
                "the operation-capacity result had the wrong response type",
            )),
        }
    }

    pub(crate) fn into_stop(self) -> Result<RuntimeStopOutcome, SatelleError> {
        match self {
            Self::Stop(outcome) => Ok(outcome),
            Self::Session(_) => Err(crate::runtime::integrity_error(
                "the operation-capacity result had the wrong response type",
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
    state: Mutex<CapacityState>,
    generation: AtomicU64,
    #[cfg(test)]
    registration_changed: Condvar,
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
            state: Mutex::new(CapacityState::default()),
            generation: AtomicU64::new(0),
            #[cfg(test)]
            registration_changed: Condvar::new(),
        }
    }
}

impl OperationCapacity {
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
        loop {
            // An exact in-memory request owns the authoritative result until
            // it clears. Durable state may already contain an intermediate
            // snapshot that the leader can still replace with a dispatch
            // failure, so matching followers must join before replay.
            let (observed_generation, follower) = {
                let state = self.lock()?;
                let observed_generation = self.generation.load(Ordering::Acquire);
                let follower = self.matching_active(&state, &request)?;
                (observed_generation, follower)
            };
            if let Some(follower) = follower {
                return follower.wait();
            }

            // The generation makes the replay probe and capacity decision one
            // optimistic read. SQLite work remains outside the mutex, while a
            // concurrent install or clear discards the probe and starts again.
            let replayed = replay()?;
            if self.generation.load(Ordering::Acquire) != observed_generation {
                continue;
            }
            if let Some(replayed) = replayed {
                return Ok(replayed);
            }

            let role = {
                let mut state = self.lock()?;
                if self.generation.load(Ordering::Acquire) != observed_generation {
                    None
                } else if let Some(follower) = self.matching_active(&state, &request)? {
                    Some(Role::Follower(follower))
                } else {
                    Some(match &state.active {
                        None => {
                            let entry = Arc::new(InFlight::new(request.clone()));
                            state.active = Some(ActiveOperation::Idempotent(Arc::clone(&entry)));
                            self.generation.fetch_add(1, Ordering::Release);
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
                Role::Leader(entry) => CapacityLeader::new(self, entry).run(operation),
                Role::Follower(entry) => entry.wait(),
            };
        }
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
        }
        ExclusiveCapacityLeader::new(self).run(operation)
    }

    fn matching_active(
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

    fn clear(&self, entry: &Arc<InFlight>) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state
            .active
            .as_ref()
            .is_some_and(|active| {
                matches!(active, ActiveOperation::Idempotent(active) if Arc::ptr_eq(active, entry))
            })
        {
            state.active = None;
            self.generation.fetch_add(1, Ordering::Release);
        }
        #[cfg(test)]
        self.registration_changed.notify_all();
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
    result: Mutex<Option<SharedResult>>,
    completed: Condvar,
    #[cfg(test)]
    followers: AtomicUsize,
}

impl InFlight {
    fn new(request: OperationRequest) -> Self {
        Self {
            request,
            result: Mutex::new(None),
            completed: Condvar::new(),
            #[cfg(test)]
            followers: AtomicUsize::new(0),
        }
    }

    fn complete(&self, result: SharedResult) {
        let mut stored = match self.result.lock() {
            Ok(stored) => stored,
            Err(poisoned) => poisoned.into_inner(),
        };
        if stored.is_none() {
            *stored = Some(result);
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

    fn run(mut self, operation: impl FnOnce() -> SharedResult) -> SharedResult {
        let result = operation();
        self.entry.complete(result.clone());
        self.capacity.clear(&self.entry);
        self.finished = true;
        result
    }
}

impl Drop for CapacityLeader<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.entry.complete(Err(crate::runtime::integrity_error(
            "the in-flight operation terminated before producing a result",
        )));
        self.capacity.clear(&self.entry);
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
