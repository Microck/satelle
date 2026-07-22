use super::RuntimeTurnOutcome;
use super::adapter::{AdapterSubject, ExecuteRequest, UpstreamReference};
use super::{RuntimeEngine, model};
use crate::storage::{
    LeaseOwner, MaintenanceLeaseCapability, ObservedUpstreamRef, RecoverySubject, StorageErrorKind,
};
use satelle_core::session::{ExpectedRevisions, Session, TurnExecutionMode, TurnTransition};
use satelle_core::{SatelleError, SatelleEvent, SessionId, TurnId};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const LEASE_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn refresh_once(
    storage: &Arc<Mutex<crate::storage::Storage>>,
    owner: &LeaseOwner,
) -> Option<time::OffsetDateTime> {
    let mut storage = storage.lock().ok()?;
    // This is the single production timestamp boundary. A blocked mutex can
    // never make a later write persist an earlier heartbeat.
    let refreshed_at = time::OffsetDateTime::now_utc();
    let _refresh = storage.refresh_lease_heartbeat(owner, refreshed_at);
    Some(refreshed_at)
}

pub(super) struct LeaseHeartbeatGuard {
    commands: SyncSender<HeartbeatCommand>,
    handle: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    finished: Arc<AtomicBool>,
    #[cfg(test)]
    join_started: Option<SyncSender<()>>,
}

enum HeartbeatCommand {
    Shutdown,
    #[cfg(test)]
    Refresh {
        accepted: SyncSender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
        attempting: SyncSender<()>,
        refreshed: SyncSender<time::OffsetDateTime>,
    },
    #[cfg(test)]
    HoldExit {
        reached: SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    },
}

#[cfg(test)]
struct RefreshScheduleForTest {
    accepted: std::sync::mpsc::Receiver<()>,
    proceed: SyncSender<()>,
    attempting: std::sync::mpsc::Receiver<()>,
    refreshed: std::sync::mpsc::Receiver<time::OffsetDateTime>,
}

impl LeaseHeartbeatGuard {
    pub(super) fn start(
        storage: Arc<Mutex<crate::storage::Storage>>,
        owner: &LeaseOwner,
    ) -> Result<Self, std::io::Error> {
        let owner = owner.clone();
        let (commands, receiver) = mpsc::sync_channel(1);
        #[cfg(test)]
        let finished = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let thread_finished = Arc::clone(&finished);
        let handle = std::thread::Builder::new()
            .name(format!("satelle-lease-heartbeat-{}", owner.operation_id()))
            .spawn(move || {
                #[cfg(test)]
                struct Completion(Arc<AtomicBool>);
                #[cfg(test)]
                impl Drop for Completion {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                #[cfg(test)]
                let _completion = Completion(thread_finished);
                // Anchor refresh attempts to a fixed cadence. Waiting five
                // seconds after each database write would make the actual
                // heartbeat interval exceed five seconds by the write time.
                let mut next_refresh_at = std::time::Instant::now();
                loop {
                    // Failure to refresh never changes ownership. The next
                    // interval retries while the durable timestamp remains
                    // available to a future diagnostic status surface.
                    let _refreshed = refresh_once(&storage, &owner);
                    next_refresh_at += LEASE_HEARTBEAT_INTERVAL;
                    let wait = next_refresh_at.saturating_duration_since(std::time::Instant::now());
                    match receiver.recv_timeout(wait) {
                        Ok(HeartbeatCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                            return;
                        }
                        #[cfg(test)]
                        Ok(HeartbeatCommand::Refresh {
                            accepted,
                            proceed,
                            attempting,
                            refreshed,
                        }) => {
                            let _accepted = accepted.send(());
                            let _proceeding = proceed.recv();
                            let _attempting = attempting.send(());
                            if let Some(refreshed_at) = refresh_once(&storage, &owner) {
                                let _refreshed = refreshed.send(refreshed_at);
                            }
                        }
                        #[cfg(test)]
                        Ok(HeartbeatCommand::HoldExit { reached, release }) => {
                            let _reached = reached.send(());
                            let _released = release.recv();
                            return;
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                    }
                }
            })?;
        Ok(Self {
            commands,
            handle: Some(handle),
            #[cfg(test)]
            finished,
            #[cfg(test)]
            join_started: None,
        })
    }

    #[cfg(test)]
    fn request_refresh_for_test(&self) -> RefreshScheduleForTest {
        let (accepted, acceptance) = mpsc::sync_channel(1);
        let (proceed, proceeding) = mpsc::sync_channel(1);
        let (attempting, attempted) = mpsc::sync_channel(1);
        let (refreshed, refresh) = mpsc::sync_channel(1);
        self.commands
            .send(HeartbeatCommand::Refresh {
                accepted,
                proceed: proceeding,
                attempting,
                refreshed,
            })
            .expect("live heartbeat thread receives a deterministic refresh request");
        RefreshScheduleForTest {
            accepted: acceptance,
            proceed,
            attempting: attempted,
            refreshed: refresh,
        }
    }

    #[cfg(test)]
    fn finished_probe_for_test(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.finished)
    }

    #[cfg(test)]
    fn hold_worker_exit_for_test(
        &mut self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    ) {
        let (reached, exit_reached) = mpsc::sync_channel(1);
        let (release_exit, release) = mpsc::sync_channel(1);
        let (join_started, joining) = mpsc::sync_channel(1);
        self.commands
            .send(HeartbeatCommand::HoldExit { reached, release })
            .expect("live heartbeat thread receives its deterministic exit barrier");
        self.join_started = Some(join_started);
        (exit_reached, release_exit, joining)
    }
}

impl Drop for LeaseHeartbeatGuard {
    fn drop(&mut self) {
        let _sent = self.commands.send(HeartbeatCommand::Shutdown);
        let Some(handle) = self.handle.take() else {
            return;
        };
        #[cfg(test)]
        if let Some(join_started) = self.join_started.take() {
            let _joining = join_started.send(());
        }
        // The thread owns the final Storage Arc while it runs, so joining is
        // what makes RuntimeEngine drop synchronously release the SQLite owner.
        let _joined = handle.join();
    }
}

pub(super) struct MaintenanceOperationGuard {
    capability: Option<MaintenanceLeaseCapability>,
    heartbeat: Option<LeaseHeartbeatGuard>,
    storage: Arc<Mutex<crate::storage::Storage>>,
}

impl MaintenanceOperationGuard {
    pub(super) fn start(
        storage: Arc<Mutex<crate::storage::Storage>>,
        capability: MaintenanceLeaseCapability,
    ) -> Result<Self, (std::io::Error, MaintenanceLeaseCapability)> {
        let heartbeat =
            match LeaseHeartbeatGuard::start(Arc::clone(&storage), capability.lease_owner()) {
                Ok(heartbeat) => heartbeat,
                Err(error) => return Err((error, capability)),
            };
        Ok(Self {
            capability: Some(capability),
            heartbeat: Some(heartbeat),
            storage,
        })
    }

    pub(super) fn capability(&self) -> &MaintenanceLeaseCapability {
        self.capability
            .as_ref()
            .expect("live maintenance operation owns its capability")
    }

    pub(super) fn disarm(&mut self) {
        drop(self.heartbeat.take());
        drop(self.capability.take());
    }
}

impl Drop for MaintenanceOperationGuard {
    fn drop(&mut self) {
        // Stop refreshing before classifying the abandoned owner. Once this
        // returns, no heartbeat thread can make the lost operation look live.
        drop(self.heartbeat.take());
        let Some(capability) = self.capability.take() else {
            return;
        };
        if let Ok(mut storage) = self.storage.lock() {
            let _retained = storage.retain_lease_recovery(capability.lease_owner());
        }
    }
}

pub(super) struct TurnWork {
    pub(super) session: satelle_core::session::Session,
    pub(super) subject: RecoverySubject,
    pub(super) _heartbeat: LeaseHeartbeatGuard,
}

pub(super) struct ExecutionPlan {
    pub(super) host: String,
    pub(super) prompt: String,
    pub(super) execution_mode: TurnExecutionMode,
    pub(super) work: TurnWork,
    pub(super) provider_smoke_event: Option<satelle_core::SatelleEventBody>,
    pub(super) attachments: crate::attachment::StagedAttachments,
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
        let admitted_session = plan.work.session.clone();
        let admitted_subject = plan.work.subject.clone();
        // Dispatch defaults are thread-local. Capture the request's effective
        // subscriber before spawning so the detached prompt lifetime remains
        // inside the same non-global tracing boundary as admission.
        let dispatch = tracing::dispatcher::get_default(tracing::Dispatch::clone);
        let engine = Arc::clone(self);
        let mut workers = match self.workers.lock() {
            Ok(workers) => workers,
            Err(_) => {
                let failure =
                    model::integrity_failure("the detached runtime worker registry was poisoned");
                self.fail_unstarted_dispatch(&admitted_session, &admitted_subject)?;
                return Err(failure);
            }
        };
        if let Err(failure) = workers.reap_finished() {
            drop(workers);
            self.fail_unstarted_dispatch(&admitted_session, &admitted_subject)?;
            return Err(failure);
        }
        let spawned = std::thread::Builder::new()
            .name("satelle-runtime-turn".to_string())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, move || {
                    let subject = plan.work.subject.clone();
                    let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        engine.execute(plan)
                    }));
                    if execution.is_err() {
                        let _preserved = engine.preserve_unknown_execution(&subject);
                    }
                });
            });
        match spawned {
            Ok(handle) => {
                workers.handles.push(handle);
                Ok(())
            }
            Err(error) => {
                drop(workers);
                let failure = model::background_execution_failure(error);
                self.fail_unstarted_dispatch(&admitted_session, &admitted_subject)?;
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
            return Ok(model::turn_outcome(&plan.work.session, Vec::new()));
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
            plan.execution_mode,
            execution_policy,
            AdapterSubject::new(&plan.work.subject),
            &persist_upstream_ref,
            plan.attachments.images(),
        ))?;
        let Some(transition) = result.transition() else {
            let session = self
                .lock_storage()?
                .load_session(&session_id)
                .map_err(model::storage_failure)?
                .ok_or_else(|| SatelleError::session_not_found(&session_id))?;
            let turn = session
                .turn(&turn_id)
                .ok_or_else(|| model::integrity_failure("the controlled Turn is missing"))?;
            if turn.state() != satelle_core::session::TurnState::Stopped {
                return Err(model::integrity_failure(
                    "controlled execution returned before stop was durable",
                ));
            }
            return Ok(model::turn_outcome(&session, Vec::new()));
        };
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
            prepend_provider_smoke_event(plan.provider_smoke_event, result.into_events())?
        } else {
            Vec::new()
        };
        Ok(model::turn_outcome(&session, events))
    }

    fn persist_upstream_ref(
        &self,
        subject: &RecoverySubject,
        reference: UpstreamReference,
    ) -> Result<(), SatelleError> {
        let observed = match reference {
            UpstreamReference::Thread(value) => ObservedUpstreamRef::thread(value),
            UpstreamReference::Turn(value) => ObservedUpstreamRef::turn(value),
            UpstreamReference::Goal(value) => ObservedUpstreamRef::goal(value),
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

    pub(super) fn fail_unstarted_dispatch(
        &self,
        admitted_session: &Session,
        subject: &RecoverySubject,
    ) -> Result<(), SatelleError> {
        let session_id = subject.session_id();
        let turn_id = subject.turn_id();
        let mut session = admitted_session.clone();
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

fn prepend_provider_smoke_event(
    provider_smoke_event: Option<satelle_core::SatelleEventBody>,
    events: Vec<SatelleEvent>,
) -> Result<Vec<SatelleEvent>, SatelleError> {
    let Some(provider_smoke_event) = provider_smoke_event else {
        return Ok(events);
    };
    std::iter::once(provider_smoke_event)
        .chain(events.into_iter().map(SatelleEvent::into_body))
        .enumerate()
        .map(|(index, body)| {
            body.with_seq(u64::try_from(index + 1).expect("event count fits in u64"))
                .map_err(|_| model::integrity_failure("runtime event sequence is invalid"))
        })
        .collect()
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

#[cfg(test)]
mod heartbeat_tests {
    use super::*;
    use crate::storage::{LeaseOwner, SetupActionPlan, SetupOperationKind, SetupRunPlan, Storage};

    #[test]
    fn heartbeat_timestamp_is_captured_after_the_storage_mutex_and_drop_is_quiescent() {
        let state = crate::TestStateDir::new().expect("temporary state directory should exist");
        let (storage, _) = Storage::open(state.path()).expect("open storage");
        let storage = Arc::new(Mutex::new(storage));
        let acquired_at = time::OffsetDateTime::now_utc();
        let owner = LeaseOwner::new(
            "blocked-mutex-maintenance",
            std::process::id(),
            "blocked-mutex-process-start",
            "blocked-mutex-boot",
            acquired_at,
        )
        .unwrap();
        let plan = SetupRunPlan::new(
            owner.operation_id(),
            SetupOperationKind::Repair,
            None,
            acquired_at,
            vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
        )
        .unwrap();
        let _capability = storage
            .lock()
            .unwrap()
            .begin_setup_run(&plan, owner.clone())
            .unwrap();
        let heartbeat = LeaseHeartbeatGuard::start(Arc::clone(&storage), &owner).unwrap();
        let finished = heartbeat.finished_probe_for_test();

        // Wait until the worker has consumed the command before taking the
        // mutex. This keeps a cadence refresh from blocking command receipt.
        let refresh = heartbeat.request_refresh_for_test();
        refresh
            .accepted
            .recv()
            .expect("heartbeat accepts the deterministic refresh request");

        let locked_storage = storage.lock().unwrap();
        refresh
            .proceed
            .send(())
            .expect("heartbeat is released toward the held storage mutex");
        refresh
            .attempting
            .recv()
            .expect("heartbeat reaches the blocked storage mutex");
        let mutex_released_at = time::OffsetDateTime::now_utc();
        drop(locked_storage);
        let refreshed_at = refresh
            .refreshed
            .recv()
            .expect("heartbeat completes after the mutex is released");
        assert!(refreshed_at >= mutex_released_at);

        drop(heartbeat);
        assert!(
            finished.load(Ordering::Acquire),
            "guard drop joins the heartbeat thread before returning"
        );
    }

    #[test]
    fn heartbeat_drop_waits_for_the_real_worker_exit_barrier() {
        let state = crate::TestStateDir::new().expect("temporary state directory should exist");
        let (storage, _) = Storage::open(state.path()).expect("open storage");
        let storage = Arc::new(Mutex::new(storage));
        let acquired_at = time::OffsetDateTime::now_utc();
        let owner = LeaseOwner::new(
            "worker-exit-barrier",
            std::process::id(),
            "worker-exit-process-start",
            "worker-exit-boot",
            acquired_at,
        )
        .unwrap();
        let plan = SetupRunPlan::new(
            owner.operation_id(),
            SetupOperationKind::Repair,
            None,
            acquired_at,
            vec![SetupActionPlan::new("repair-runtime", "Repair runtime", false).unwrap()],
        )
        .unwrap();
        let _capability = storage
            .lock()
            .unwrap()
            .begin_setup_run(&plan, owner.clone())
            .unwrap();
        let mut heartbeat = LeaseHeartbeatGuard::start(Arc::clone(&storage), &owner).unwrap();
        let finished = heartbeat.finished_probe_for_test();
        let (exit_reached, release_exit, join_started) = heartbeat.hold_worker_exit_for_test();
        exit_reached
            .recv()
            .expect("the real heartbeat worker reaches its held exit boundary");
        let (drop_completed, dropped) = mpsc::sync_channel(1);
        let drop_thread = std::thread::spawn(move || {
            drop(heartbeat);
            drop_completed
                .send(())
                .expect("drop completion receiver remains connected");
        });
        join_started
            .recv()
            .expect("guard Drop reaches the production join boundary");
        assert_eq!(
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            dropped.recv_timeout(std::time::Duration::from_millis(100)),
            "Drop must remain blocked while the real worker is held before exit"
        );
        release_exit
            .send(())
            .expect("release the real heartbeat worker exit boundary");
        dropped
            .recv()
            .expect("Drop returns after the worker is allowed to exit");
        drop_thread.join().expect("drop thread exits cleanly");
        assert!(
            finished.load(Ordering::Acquire),
            "worker completion is acknowledged before Drop returns"
        );
    }
}
