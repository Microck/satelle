use super::{
    AttachedTurnOutcome, DirectTransport, direct_admission_error, direct_event_error,
    direct_run_admission_error, direct_run_event_error, direct_transport_error,
};
use satelle_core::session::{PublicSession, TurnAdmissionFailure, TurnState, TurnStateRevision};
use satelle_core::{
    ErrorCode, EventSource, EventStateSubject, EventSubject, EventType, SatelleError, SatelleEvent,
    SatelleEventBody, SessionId, TurnId,
};
use satelle_host::{LogPageQuery, LogSubject};
use satelle_transport::{
    DaemonClientError, DaemonEventError, DaemonEventStream, EventSubscription, TurnRequest,
};
use std::sync::Arc;
use std::time::Duration;

pub(super) const MAX_EVENT_RECONNECTS: usize = 3;
const MAX_RECONCILIATION_ATTEMPTS: usize = 3;
const RETRY_BACKOFF: Duration = Duration::from_millis(100);
const RECONCILIATION_LOG_LIMIT: usize = 10_000;

impl DirectTransport {
    fn invalid_response(&self) -> SatelleError {
        SatelleError::remote_api_error(&self.alias, "invalid-daemon-response")
    }

    fn target_turn<'session>(
        &self,
        session: &'session PublicSession,
        turn_id: &TurnId,
    ) -> Result<&'session satelle_core::session::PublicTurn, SatelleError> {
        session
            .turns()
            .iter()
            .find(|turn| turn.turn_id() == turn_id)
            .ok_or_else(|| self.invalid_response())
    }

    pub(super) fn reconciled_terminal_event(
        &self,
        session: &PublicSession,
        turn_id: &TurnId,
    ) -> Result<SatelleEvent, SatelleError> {
        let turn = self.target_turn(session, turn_id)?;
        let event_type =
            terminal_event_type(turn.state()).ok_or_else(|| self.invalid_response())?;
        SatelleEventBody::new(
            event_type,
            EventSource::Cli,
            turn.updated_at(),
            &self.alias,
            Some(EventSubject::Turn {
                session_id: session.session_id().clone(),
                turn_id: turn_id.clone(),
                session_state_revision: session.session_state_revision(),
                turn_state_revision: turn.turn_state_revision(),
            }),
            "reconciled terminal Turn status after event stream loss",
            serde_json::json!({
                "reconciled": true,
                "state": turn.state(),
            }),
        )
        .and_then(|body| body.with_seq(1))
        .map_err(|_| self.invalid_response())
    }

    pub(super) fn validate_terminal_event(
        &self,
        event: &SatelleEvent,
        session: &PublicSession,
        turn_id: &TurnId,
    ) -> Result<(), SatelleError> {
        let turn = self.target_turn(session, turn_id)?;
        if terminal_event_type(turn.state()) != Some(event.event_type()) {
            return Err(self.invalid_response());
        }
        Ok(())
    }

    async fn blocking_http<T, F>(&self, operation: F) -> Result<T, SatelleError>
    where
        T: Send + 'static,
        F: FnOnce(Arc<satelle_transport::DaemonClient>) -> Result<T, DaemonClientError>
            + Send
            + 'static,
    {
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || operation(client))
            .await
            .map_err(|_| SatelleError::host_unreachable(&self.alias))?
            .map_err(|error| direct_transport_error(&self.alias, error))
    }

    async fn blocking_admission_http<T, F>(
        &self,
        operation: F,
        map_error: fn(&str, DaemonClientError) -> TurnAdmissionFailure,
    ) -> Result<T, TurnAdmissionFailure>
    where
        T: Send + 'static,
        F: FnOnce(Arc<satelle_transport::DaemonClient>) -> Result<T, DaemonClientError>
            + Send
            + 'static,
    {
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || operation(client))
            .await
            .map_err(|_| {
                TurnAdmissionFailure::admission_unknown(SatelleError::host_unreachable(&self.alias))
            })?
            .map_err(|error| map_error(&self.alias, error))
    }

    pub(super) async fn reconcile(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
        minimum_revision: Option<TurnStateRevision>,
    ) -> Result<Option<PublicSession>, SatelleError> {
        let query = LogPageQuery::tail(RECONCILIATION_LOG_LIMIT)
            .map_err(|_| SatelleError::remote_api_error(&self.alias, "invalid-log-query"))?
            .with_session(session_id.clone());
        let session_id = session_id.clone();
        let (session, logs) = self
            .blocking_http(move |client| {
                let session = client.read_session(&session_id)?;
                let logs = client.logs(&query)?;
                Ok((session.session().clone(), logs.page().clone()))
            })
            .await?;
        let turn = self.target_turn(&session, turn_id)?;
        if let Some(minimum_revision) = minimum_revision
            && turn.turn_state_revision() < minimum_revision
        {
            return Err(self.invalid_response());
        }
        let has_matching_log = logs.entries().iter().any(|entry| {
            matches!(
                entry.subject(),
                LogSubject::Turn {
                    session_id: logged_session_id,
                    turn_id: logged_turn_id,
                    session_state_revision,
                    turn_state_revision,
                } if logged_session_id == session.session_id()
                    && logged_turn_id == turn_id
                    && *session_state_revision <= session.session_state_revision()
                    && *turn_state_revision == turn.turn_state_revision()
            )
        });
        if !has_matching_log {
            return Err(self.invalid_response());
        }
        Ok(turn.state().is_terminal().then_some(session))
    }

    async fn reconcile_retaining_stream(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
        minimum_revision: Option<TurnStateRevision>,
    ) -> Result<Option<PublicSession>, SatelleError> {
        let mut attempt = 1_usize;
        loop {
            match self.reconcile(session_id, turn_id, minimum_revision).await {
                Ok(session) => return Ok(session),
                Err(error)
                    if reconciliation_error_allows_retry(&error)
                        && attempt < MAX_RECONCILIATION_ATTEMPTS =>
                {
                    tokio::time::sleep(RETRY_BACKOFF * attempt as u32).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(super) async fn follow_turn(
        &self,
        mut stream: DaemonEventStream,
        admitted: PublicSession,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, SatelleError> {
        let session_id = admitted.session_id().clone();
        let turn_id = admitted
            .turns()
            .last()
            .ok_or_else(|| self.invalid_response())?
            .turn_id()
            .clone();
        let mut highest_event_revision: Option<TurnStateRevision> = None;
        let mut previous_stream_sequence = 0_u64;
        let mut reconnect_attempts = 0_usize;

        loop {
            match stream.next_event().await {
                Ok(event) => {
                    reconnect_attempts = 0;
                    let sequence_gap = previous_stream_sequence != 0
                        && event.seq() > previous_stream_sequence.saturating_add(1);
                    previous_stream_sequence = event.seq();
                    let event_revision = target_event_revision(&event, &session_id, &turn_id);
                    if sequence_gap {
                        let minimum_revision = match (highest_event_revision, event_revision) {
                            (Some(highest), Some(current)) => Some(highest.max(current)),
                            (highest, current) => highest.or(current),
                        };
                        if let Some(session) = self
                            .reconcile(&session_id, &turn_id, minimum_revision)
                            .await?
                        {
                            if let Some(revision) = event_revision
                                && highest_event_revision.is_none_or(|highest| revision > highest)
                            {
                                let terminal = event.event_type().is_terminal();
                                if terminal {
                                    self.validate_terminal_event(&event, &session, &turn_id)?;
                                }
                                on_event(event)?;
                                if terminal {
                                    return Ok(AttachedTurnOutcome { session, turn_id });
                                }
                            }
                            on_event(self.reconciled_terminal_event(&session, &turn_id)?)?;
                            return Ok(AttachedTurnOutcome { session, turn_id });
                        }
                    }
                    let Some(revision) = event_revision else {
                        continue;
                    };
                    if highest_event_revision.is_some_and(|highest| revision <= highest) {
                        continue;
                    }
                    let terminal = event.event_type().is_terminal();
                    highest_event_revision = Some(revision);
                    if terminal {
                        let session = self
                            .reconcile(&session_id, &turn_id, Some(revision))
                            .await?
                            .ok_or_else(|| self.invalid_response())?;
                        self.validate_terminal_event(&event, &session, &turn_id)?;
                        on_event(event)?;
                        return Ok(AttachedTurnOutcome { session, turn_id });
                    }
                    on_event(event)?;
                }
                Err(mut connection_error) => {
                    if !event_error_allows_reconciliation(&connection_error) {
                        return Err(direct_event_error(&self.alias, connection_error));
                    }
                    loop {
                        reconnect_attempts += 1;
                        if reconnect_attempts > MAX_EVENT_RECONNECTS {
                            return Err(direct_event_error(&self.alias, connection_error));
                        }
                        tokio::time::sleep(RETRY_BACKOFF * reconnect_attempts as u32).await;
                        match self
                            .event_client
                            .connect_events(vec![EventSubscription::Turn {
                                session_id: session_id.clone(),
                                turn_id: turn_id.clone(),
                            }])
                            .await
                        {
                            Ok(replacement) => {
                                // Subscribe before reading status because event streams are live-only.
                                // The replacement socket buffers a terminal commit that races this GET.
                                stream = replacement;
                                previous_stream_sequence = 0;
                                if let Some(session) = self
                                    .reconcile_retaining_stream(
                                        &session_id,
                                        &turn_id,
                                        highest_event_revision,
                                    )
                                    .await?
                                {
                                    on_event(self.reconciled_terminal_event(&session, &turn_id)?)?;
                                    return Ok(AttachedTurnOutcome { session, turn_id });
                                }
                                break;
                            }
                            Err(reconnect_error) => {
                                if !event_error_allows_reconciliation(&reconnect_error) {
                                    return Err(direct_event_error(&self.alias, reconnect_error));
                                }
                                connection_error = reconnect_error;
                                match self
                                    .reconcile(&session_id, &turn_id, highest_event_revision)
                                    .await
                                {
                                    Ok(Some(session)) => {
                                        on_event(
                                            self.reconciled_terminal_event(&session, &turn_id)?,
                                        )?;
                                        return Ok(AttachedTurnOutcome { session, turn_id });
                                    }
                                    Ok(None) => {}
                                    Err(error)
                                        if reconciliation_error_allows_retry(&error)
                                            && reconnect_attempts < MAX_EVENT_RECONNECTS =>
                                    {
                                        continue;
                                    }
                                    Err(error) => return Err(error),
                                }
                                if reconnect_attempts == MAX_EVENT_RECONNECTS {
                                    return Err(direct_event_error(&self.alias, connection_error));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub(super) async fn run_attached(
        &self,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let stream = self
            .event_client
            .connect_events(vec![EventSubscription::Host])
            .await
            .map_err(|error| {
                TurnAdmissionFailure::not_admitted(direct_run_event_error(&self.alias, error))
            })?;
        let request = request.clone();
        let idempotency_key = Self::idempotency_key();
        let admitted = self
            .blocking_admission_http(
                move |client| {
                    client
                        .create_session(&request, &idempotency_key)
                        .map(|response| response.session().clone())
                },
                direct_run_admission_error,
            )
            .await?;
        let turn_id = admitted
            .turns()
            .last()
            .ok_or_else(|| TurnAdmissionFailure::admission_unknown(self.invalid_response()))?
            .turn_id()
            .clone();
        let admitted_snapshot = admitted.clone();
        self.follow_turn(stream, admitted, on_event)
            .await
            .map_err(|error| TurnAdmissionFailure::admitted(error, admitted_snapshot, turn_id))
    }

    pub(super) async fn steer_attached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let stream = self
            .event_client
            .connect_events(vec![EventSubscription::Session {
                session_id: session_id.clone(),
            }])
            .await
            .map_err(|error| {
                TurnAdmissionFailure::not_admitted(direct_event_error(&self.alias, error))
            })?;
        let admitted_session_id = session_id.clone();
        let request = request.clone();
        let idempotency_key = Self::idempotency_key();
        let admitted = self
            .blocking_admission_http(
                move |client| {
                    client
                        .create_turn(&admitted_session_id, &request, &idempotency_key)
                        .map(|response| response.session().clone())
                },
                direct_admission_error,
            )
            .await?;
        if admitted.session_id() != session_id || admitted.turns().is_empty() {
            return Err(TurnAdmissionFailure::admission_unknown(
                self.invalid_response(),
            ));
        }
        let turn_id = admitted
            .turns()
            .last()
            .expect("a nonempty admitted Session has a target Turn")
            .turn_id()
            .clone();
        let admitted_snapshot = admitted.clone();
        self.follow_turn(stream, admitted, on_event)
            .await
            .map_err(|error| TurnAdmissionFailure::admitted(error, admitted_snapshot, turn_id))
    }
}

fn target_event_revision(
    event: &SatelleEvent,
    session_id: &SessionId,
    turn_id: &TurnId,
) -> Option<TurnStateRevision> {
    if event.session_id() != Some(session_id) || event.turn_id() != Some(turn_id) {
        return None;
    }
    match event.state_subject() {
        Some(EventStateSubject::Turn {
            turn_state_revision,
            ..
        }) => Some(*turn_state_revision),
        Some(EventStateSubject::Session { .. }) | None => None,
    }
}

fn terminal_event_type(state: TurnState) -> Option<EventType> {
    match state {
        TurnState::Completed => Some(EventType::TurnCompleted),
        TurnState::Blocked => Some(EventType::TurnBlocked),
        TurnState::Failed => Some(EventType::TurnFailed),
        TurnState::Stopped => Some(EventType::TurnStopped),
        TurnState::Starting | TurnState::Running | TurnState::RecoveryPending => None,
    }
}

pub(super) fn event_error_allows_reconciliation(error: &DaemonEventError) -> bool {
    error.is_recoverable_disconnect()
}

pub(super) fn reconciliation_error_allows_retry(error: &SatelleError) -> bool {
    error.code == ErrorCode::HostUnreachable
}
