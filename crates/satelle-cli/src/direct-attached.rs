use super::{
    AttachedTurnOutcome, DirectTransport, InterruptSource, ProcessInterrupt,
    direct_admission_error, direct_event_error, direct_transport_error,
    unconfirmed_interrupt_error,
};
use satelle_core::session::{PublicSession, TurnAdmissionFailure, TurnState, TurnStateRevision};
use satelle_core::{
    ErrorCode, EventSource, EventStateSubject, EventSubject, EventType, SatelleError, SatelleEvent,
    SatelleEventBody, SessionId, TurnId,
};
use satelle_host::{LogPageQuery, LogSubject};
use satelle_transport::{
    AdmissionCancellationOutcome, AdmissionCancellationResponse, DaemonClientError,
    DaemonEventError, DaemonEventStream, EventSubscription, TurnRequest,
};
use std::collections::VecDeque;
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
        buffered_events: Vec<SatelleEvent>,
        initial_connection_error: Option<DaemonEventError>,
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
        let mut provider_smoke = None;
        let mut buffered_events = VecDeque::from(buffered_events);
        let mut initial_connection_error = initial_connection_error;

        loop {
            let next_event = match buffered_events.pop_front() {
                Some(event) => Ok(event),
                None => match initial_connection_error.take() {
                    Some(error) => Err(error),
                    None => stream.next_event().await,
                },
            };
            match next_event {
                Ok(event) => {
                    reconnect_attempts = 0;
                    if event.event_type() == satelle_core::EventType::ProviderSmoke {
                        provider_smoke = Some(event.data().clone());
                    }
                    let sequence_gap = previous_stream_sequence != 0
                        && event.seq() > previous_stream_sequence.saturating_add(1);
                    previous_stream_sequence = event.seq();
                    let event_revision = target_event_revision(&event, &session_id, &turn_id);
                    if event.event_type() == satelle_core::EventType::ProviderSmoke {
                        on_event(event)?;
                        continue;
                    }
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
                                    return Ok(AttachedTurnOutcome {
                                        session,
                                        turn_id,
                                        provider_smoke,
                                    });
                                }
                            }
                            on_event(self.reconciled_terminal_event(&session, &turn_id)?)?;
                            return Ok(AttachedTurnOutcome {
                                session,
                                turn_id,
                                provider_smoke,
                            });
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
                        return Ok(AttachedTurnOutcome {
                            session,
                            turn_id,
                            provider_smoke,
                        });
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
                                    return Ok(AttachedTurnOutcome {
                                        session,
                                        turn_id,
                                        provider_smoke,
                                    });
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
                                        return Ok(AttachedTurnOutcome {
                                            session,
                                            turn_id,
                                            provider_smoke,
                                        });
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
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let interrupt = ProcessInterrupt::default();
        self.run_attached_with_interrupt(request, detach_on_interrupt, on_event, &interrupt)
            .await
    }

    pub(super) async fn run_attached_with_interrupt(
        &self,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
        interrupt: &dyn InterruptSource,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        interrupt.arm().await.map_err(|_| {
            TurnAdmissionFailure::not_admitted(SatelleError::host_unreachable(&self.alias))
        })?;
        let connection = self
            .event_client
            .connect_events(vec![EventSubscription::Host]);
        tokio::pin!(connection);
        let mut stream = tokio::select! {
            biased;
            signal = interrupt.wait() => {
                signal.map_err(|_| TurnAdmissionFailure::not_admitted(
                    SatelleError::host_unreachable(&self.alias),
                ))?;
                return Err(TurnAdmissionFailure::not_admitted(
                    pre_admission_interruption_error(None),
                ));
            }
            connected = &mut connection => connected
                .map_err(|error| TurnAdmissionFailure::not_admitted(self.run_event_error(error)))?,
        };
        let request = request.clone();
        let cancellation_request = request.clone();
        let idempotency_key = Self::idempotency_key();
        let cancellation_key = idempotency_key.clone();
        let (admitted, buffered_events, initial_connection_error) = stream
            .buffer_events_until(async {
                let admission = self.blocking_admission_http(
                    move |client| {
                        client
                            .create_session(&request, &idempotency_key)
                            .map(|response| response.session().clone())
                    },
                    self.run_admission_error(),
                );
                tokio::pin!(admission);
                tokio::select! {
                    biased;
                    signal = interrupt.wait() => {
                        signal.map_err(|_| {
                            TurnAdmissionFailure::admission_unknown(
                                SatelleError::host_unreachable(&self.alias),
                            )
                        })?;
                        let cancelled = self
                            .blocking_admission_http(
                                move |client| {
                                    client.cancel_session_admission(
                                        &cancellation_request,
                                        &cancellation_key,
                                    )
                                },
                                self.run_admission_error(),
                            )
                            .await;
                        Ok((admission.await, Some(cancelled)))
                    }
                    admitted = &mut admission => Ok((admitted, None)),
                }
            })
            .await;
        let (admitted, interruption) = admitted?;
        let admitted = match (admitted, interruption.as_ref()) {
            (Ok(admitted), _) => admitted,
            (Err(_), Some(Ok(cancelled)))
                if cancelled.outcome() == AdmissionCancellationOutcome::Admitted =>
            {
                return Err(self
                    .interrupted_replayed_admission(cancelled, None, detach_on_interrupt)
                    .await);
            }
            (Err(_), Some(Ok(cancelled))) => {
                return Err(TurnAdmissionFailure::not_admitted(
                    pre_admission_interruption_error(Some(cancelled.outcome())),
                ));
            }
            (Err(_), Some(Err(_))) => {
                return Err(TurnAdmissionFailure::admission_unknown(
                    interrupted_admission_unknown(&self.alias),
                ));
            }
            (Err(error), None) => return Err(error),
        };
        let turn_id = admitted
            .turns()
            .last()
            .ok_or_else(|| TurnAdmissionFailure::admission_unknown(self.invalid_response()))?
            .turn_id()
            .clone();
        let admitted_snapshot = admitted.clone();
        if interruption.is_some() {
            let error = self
                .interrupt_admitted(&admitted, &turn_id, detach_on_interrupt)
                .await;
            return Err(TurnAdmissionFailure::admitted(
                error,
                admitted_snapshot,
                turn_id,
            ));
        }
        let following = self.follow_turn(
            stream,
            admitted,
            buffered_events,
            initial_connection_error,
            on_event,
        );
        tokio::pin!(following);
        tokio::select! {
            biased;
            signal = interrupt.wait() => {
                signal.map_err(|_| TurnAdmissionFailure::admitted(
                    SatelleError::host_unreachable(&self.alias),
                    admitted_snapshot.clone(),
                    turn_id.clone(),
                ))?;
                let error = self.interrupt_admitted(
                    &admitted_snapshot,
                    &turn_id,
                    detach_on_interrupt,
                ).await;
                Err(TurnAdmissionFailure::admitted(error, admitted_snapshot, turn_id))
            }
            outcome = &mut following => outcome
                .map_err(|error| TurnAdmissionFailure::admitted(error, admitted_snapshot, turn_id)),
        }
    }

    pub(super) async fn steer_attached(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        let interrupt = ProcessInterrupt::default();
        self.steer_attached_with_interrupt(
            session_id,
            request,
            detach_on_interrupt,
            on_event,
            &interrupt,
        )
        .await
    }

    pub(super) async fn steer_attached_with_interrupt(
        &self,
        session_id: &SessionId,
        request: &TurnRequest,
        detach_on_interrupt: bool,
        on_event: &mut dyn FnMut(SatelleEvent) -> Result<(), SatelleError>,
        interrupt: &dyn InterruptSource,
    ) -> Result<AttachedTurnOutcome, TurnAdmissionFailure> {
        interrupt.arm().await.map_err(|_| {
            TurnAdmissionFailure::not_admitted(SatelleError::host_unreachable(&self.alias))
        })?;
        let connection = self
            .event_client
            .connect_events(vec![EventSubscription::Session {
                session_id: session_id.clone(),
            }]);
        tokio::pin!(connection);
        let mut stream = tokio::select! {
            biased;
            signal = interrupt.wait() => {
                signal.map_err(|_| TurnAdmissionFailure::not_admitted(
                    SatelleError::host_unreachable(&self.alias),
                ))?;
                return Err(TurnAdmissionFailure::not_admitted(
                    pre_admission_interruption_error(None),
                ));
            }
            connected = &mut connection => connected.map_err(|error| {
                TurnAdmissionFailure::not_admitted(direct_event_error(&self.alias, error))
            })?,
        };
        let admitted_session_id = session_id.clone();
        let request = request.clone();
        let cancellation_request = request.clone();
        let idempotency_key = Self::idempotency_key();
        let cancellation_key = idempotency_key.clone();
        let cancellation_session_id = session_id.clone();
        let (admitted, buffered_events, initial_connection_error) = stream
            .buffer_events_until(async {
                let admission = self.blocking_admission_http(
                    move |client| {
                        client
                            .create_turn(&admitted_session_id, &request, &idempotency_key)
                            .map(|response| response.session().clone())
                    },
                    direct_admission_error,
                );
                tokio::pin!(admission);
                tokio::select! {
                    biased;
                    signal = interrupt.wait() => {
                        signal.map_err(|_| TurnAdmissionFailure::admission_unknown(
                            SatelleError::host_unreachable(&self.alias),
                        ))?;
                        let cancelled = self.blocking_admission_http(
                            move |client| client.cancel_turn_admission(
                                &cancellation_session_id,
                                &cancellation_request,
                                &cancellation_key,
                            ),
                            direct_admission_error,
                        ).await;
                        Ok((admission.await, Some(cancelled)))
                    }
                    admitted = &mut admission => Ok((admitted, None)),
                }
            })
            .await;
        let (admitted, interruption) = admitted?;
        let admitted = match (admitted, interruption.as_ref()) {
            (Ok(admitted), _) => admitted,
            (Err(_), Some(Ok(cancelled)))
                if cancelled.outcome() == AdmissionCancellationOutcome::Admitted =>
            {
                return Err(self
                    .interrupted_replayed_admission(
                        cancelled,
                        Some(session_id),
                        detach_on_interrupt,
                    )
                    .await);
            }
            (Err(_), Some(Ok(cancelled))) => {
                return Err(TurnAdmissionFailure::not_admitted(
                    pre_admission_interruption_error(Some(cancelled.outcome())),
                ));
            }
            (Err(_), Some(Err(_))) => {
                return Err(TurnAdmissionFailure::admission_unknown(
                    interrupted_admission_unknown(&self.alias),
                ));
            }
            (Err(error), None) => return Err(error),
        };
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
        if interruption.is_some() {
            let error = self
                .interrupt_admitted(&admitted, &turn_id, detach_on_interrupt)
                .await;
            return Err(TurnAdmissionFailure::admitted(
                error,
                admitted_snapshot,
                turn_id,
            ));
        }
        let following = self.follow_turn(
            stream,
            admitted,
            buffered_events,
            initial_connection_error,
            on_event,
        );
        tokio::pin!(following);
        tokio::select! {
            biased;
            signal = interrupt.wait() => {
                signal.map_err(|_| TurnAdmissionFailure::admitted(
                    SatelleError::host_unreachable(&self.alias),
                    admitted_snapshot.clone(),
                    turn_id.clone(),
                ))?;
                let error = self.interrupt_admitted(
                    &admitted_snapshot,
                    &turn_id,
                    detach_on_interrupt,
                ).await;
                Err(TurnAdmissionFailure::admitted(error, admitted_snapshot, turn_id))
            }
            outcome = &mut following => outcome
                .map_err(|error| TurnAdmissionFailure::admitted(error, admitted_snapshot, turn_id)),
        }
    }

    async fn interrupted_replayed_admission(
        &self,
        response: &AdmissionCancellationResponse,
        expected_session_id: Option<&SessionId>,
        detach_on_interrupt: bool,
    ) -> TurnAdmissionFailure {
        let session_id = response
            .session_id()
            .cloned()
            .ok_or_else(|| TurnAdmissionFailure::admission_unknown(self.invalid_response()));
        let turn_id = response
            .turn_id()
            .cloned()
            .ok_or_else(|| TurnAdmissionFailure::admission_unknown(self.invalid_response()));
        let (session_id, turn_id) = match (session_id, turn_id) {
            (Ok(session_id), Ok(turn_id))
                if expected_session_id.is_none_or(|expected| expected == &session_id) =>
            {
                (session_id, turn_id)
            }
            _ => return TurnAdmissionFailure::admission_unknown(self.invalid_response()),
        };
        let interruption = if detach_on_interrupt {
            SatelleError::interrupted_attached_command()
        } else {
            self.interrupt_admitted_ids(&session_id, &turn_id).await
        };
        let read_session_id = session_id.clone();
        let session = match self
            .blocking_http(move |client| client.read_session(&read_session_id))
            .await
            .map(|response| response.session().clone())
        {
            Ok(session) => session,
            Err(error) => {
                return TurnAdmissionFailure::admission_unknown(
                    interrupted_admission_with_session(&self.alias, &session_id, error),
                );
            }
        };
        if session.session_id() != &session_id
            || !session
                .turns()
                .iter()
                .any(|turn| turn.turn_id() == &turn_id)
        {
            return TurnAdmissionFailure::admission_unknown(interrupted_admission_with_session(
                &self.alias,
                &session_id,
                self.invalid_response(),
            ));
        }
        TurnAdmissionFailure::admitted(interruption, session, turn_id)
    }

    async fn interrupt_admitted(
        &self,
        session: &PublicSession,
        turn_id: &TurnId,
        detach_on_interrupt: bool,
    ) -> SatelleError {
        if detach_on_interrupt {
            return SatelleError::interrupted_attached_command();
        }
        self.interrupt_admitted_ids(session.session_id(), turn_id)
            .await
    }

    async fn interrupt_admitted_ids(
        &self,
        session_id: &SessionId,
        turn_id: &TurnId,
    ) -> SatelleError {
        let session_id = session_id.clone();
        let stop_session_id = session_id.clone();
        let stop_turn_id = turn_id.clone();
        match self
            .blocking_http(move |client| {
                client.stop_session_for_turn(
                    &stop_session_id,
                    &stop_turn_id,
                    &format!("interrupt-{}", uuid::Uuid::now_v7()),
                )
            })
            .await
        {
            Ok(_) => SatelleError::interrupted_attached_command(),
            Err(stop_error) => unconfirmed_interrupt_error(&self.alias, &session_id, stop_error),
        }
    }
}

fn pre_admission_interruption_error(outcome: Option<AdmissionCancellationOutcome>) -> SatelleError {
    let mut error = SatelleError::interrupted_attached_command();
    if outcome == Some(AdmissionCancellationOutcome::RecoveryPending) {
        error.details.insert(
            "ownership".to_string(),
            serde_json::Value::String("recovery_pending".to_string()),
        );
    }
    error
}

fn interrupted_admission_unknown(alias: &str) -> SatelleError {
    let mut error = SatelleError::interrupted_attached_command();
    error.message =
        "attached command was interrupted, but admission cancellation could not be confirmed"
            .to_string();
    error.recovery_command = Some(format!("satelle host sessions --host {alias}"));
    error
}

fn interrupted_admission_with_session(
    alias: &str,
    session_id: &SessionId,
    source: SatelleError,
) -> SatelleError {
    let status_command = format!("satelle status {session_id} --host {alias}");
    let mut error = SatelleError::interrupted_attached_command();
    error.message = format!(
        "attached command was interrupted after Session {session_id} was admitted, but its status could not be read"
    );
    error.recovery_command = Some(status_command.clone());
    error.details.insert(
        "session_id".to_string(),
        serde_json::Value::String(session_id.to_string()),
    );
    error.details.insert(
        "status_command".to_string(),
        serde_json::Value::String(status_command),
    );
    error.details.insert(
        "status_error_code".to_string(),
        serde_json::Value::String(source.code.as_str().to_string()),
    );
    error
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

#[cfg(test)]
mod interrupt_output_tests {
    use super::*;

    #[test]
    fn unconfirmed_stop_preserves_interrupt_exit_and_recovery_details() {
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let stop_error = SatelleError {
            code: ErrorCode::StopNotConfirmed,
            message: "stop not confirmed".to_string(),
            recovery_command: None,
            source_detail: None,
            details: std::collections::BTreeMap::from([
                ("session_id".to_string(), serde_json::json!(session_id)),
                ("turn_id".to_string(), serde_json::json!(turn_id)),
                (
                    "ownership".to_string(),
                    serde_json::json!("recovery_pending"),
                ),
                ("state_changed".to_string(), serde_json::json!(true)),
                ("session_state_revision".to_string(), serde_json::json!(3)),
                ("turn_state_revision".to_string(), serde_json::json!(2)),
                ("retryable".to_string(), serde_json::json!(true)),
            ]),
        };

        let error = unconfirmed_interrupt_error("remote-host", &session_id, stop_error);

        assert_eq!(error.code, ErrorCode::Interrupted);
        assert_eq!(error.exit_code(), 130);
        assert!(error.message.contains(session_id.as_str()));
        assert_eq!(
            error.recovery_command.as_deref(),
            Some(format!("satelle status {session_id} --host remote-host").as_str())
        );
        assert_eq!(error.details["session_id"], session_id.as_str());
        assert_eq!(error.details["turn_id"], turn_id.as_str());
        assert_eq!(error.details["ownership"], "recovery_pending");
        assert_eq!(error.details["session_state_revision"], 3);
        assert_eq!(error.details["turn_state_revision"], 2);
        assert_eq!(error.details["stop_error_code"], "stop-not-confirmed");
    }

    #[test]
    fn ambiguous_probe_cancellation_reports_recovery_pending_ownership() {
        let error =
            pre_admission_interruption_error(Some(AdmissionCancellationOutcome::RecoveryPending));

        assert_eq!(error.code, ErrorCode::Interrupted);
        assert_eq!(error.exit_code(), 130);
        assert_eq!(error.details["ownership"], "recovery_pending");
    }
}
