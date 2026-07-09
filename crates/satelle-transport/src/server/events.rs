use super::auth::AuthorizedRequest;
use super::{ApiFailure, DaemonState, api_error_response};
use crate::contract::{
    ApiErrorCategory, ApiErrorCode, EventSubscription, MAX_EVENT_SUBSCRIPTIONS, RequestId,
    SubscribeRequest, SubscribedResponse, WsCloseReason, WsControlError,
};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::Response;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use satelle_host::{ApiPrincipal, LiveEventReceiveError, LiveEventSubscription};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::future::pending;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Error as WebSocketError;

const WRITER_CLOSE_GRACE: Duration = Duration::from_millis(250);

type EventSink = SplitSink<WebSocket, Message>;
type EventStream = SplitStream<WebSocket>;

pub(super) struct ConnectionRegistry {
    limit: usize,
    counts: Mutex<HashMap<String, usize>>,
}

impl ConnectionRegistry {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            counts: Mutex::new(HashMap::new()),
        })
    }

    fn acquire(self: &Arc<Self>, principal_ref: &str) -> Option<ConnectionPermit> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let count = counts.entry(principal_ref.to_string()).or_default();
        if *count >= self.limit {
            return None;
        }
        *count += 1;
        Some(ConnectionPermit {
            registry: Arc::clone(self),
            principal_ref: principal_ref.to_string(),
        })
    }
}

struct ConnectionPermit {
    registry: Arc<ConnectionRegistry>,
    principal_ref: String,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut counts = self
            .registry
            .counts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(count) = counts.get_mut(&self.principal_ref) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.principal_ref);
            }
        }
    }
}

pub(super) async fn get_events(
    websocket: WebSocketUpgrade,
    State(state): State<Arc<DaemonState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
) -> Response {
    let Some(permit) = state
        .websocket_connections
        .acquire(authorized.principal().principal_ref())
    else {
        return api_error_response(
            authorized.request_id().clone(),
            Some(state.host_identity.clone()),
            ApiFailure {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: ApiErrorCode::CapacityExceeded,
                category: ApiErrorCategory::Capacity,
                retryable: true,
                message: "the API Principal reached its WebSocket connection limit",
                details: None,
            },
        );
    };
    let maximum_message_bytes = state.limits.websocket_message_bytes();
    websocket
        .write_buffer_size(0)
        .max_write_buffer_size(maximum_message_bytes * 2)
        .max_message_size(maximum_message_bytes)
        .max_frame_size(maximum_message_bytes)
        .on_upgrade(move |socket| serve_socket(socket, state, authorized, permit))
}

async fn serve_socket(
    socket: WebSocket,
    state: Arc<DaemonState>,
    authorized: AuthorizedRequest,
    _permit: ConnectionPermit,
) {
    let principal = authorized.principal().clone();
    let handshake_request_id = authorized.request_id().clone();
    let (sink, stream) = socket.split();
    let (outbound, outbound_receiver) =
        mpsc::channel(state.limits.websocket_outbound_queue_messages());
    let (terminal_sender, terminal_receiver) = tokio::sync::oneshot::channel();
    let (writer_done_sender, writer_done) = tokio::sync::oneshot::channel();
    let delivered_sequence = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let writer_delivered_sequence = Arc::clone(&delivered_sequence);
    let writer = tokio::spawn(async move {
        writer_loop(
            sink,
            outbound_receiver,
            terminal_receiver,
            writer_delivered_sequence,
        )
        .await;
        let _ = writer_done_sender.send(());
    });
    let end = controller_loop(
        stream,
        outbound,
        writer_done,
        Arc::clone(&state),
        &principal,
        handshake_request_id,
        &delivered_sequence,
    )
    .await;
    let terminal = match end {
        ConnectionEnd::Failure { request_id, reason } => Some(TerminalClose::new(
            request_id,
            state.host_identity.clone(),
            reason,
        )),
        ConnectionEnd::PeerClosed | ConnectionEnd::WriterGone => None,
    };
    finish_writer(terminal_sender, terminal, writer).await;
}

async fn finish_writer(
    terminal_sender: tokio::sync::oneshot::Sender<Option<TerminalClose>>,
    terminal: Option<TerminalClose>,
    mut writer: tokio::task::JoinHandle<()>,
) {
    let _writer_may_have_closed = terminal_sender.send(terminal);
    if tokio::time::timeout(WRITER_CLOSE_GRACE, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
        let _writer_stopped = writer.await;
    }
}

enum OutboundFrame {
    Control(Message),
    Event { message: Message, sequence: u64 },
}

struct TerminalClose {
    control_json: String,
    reason: WsCloseReason,
}

impl TerminalClose {
    fn new(request_id: RequestId, host_identity: String, reason: WsCloseReason) -> Self {
        let control = WsControlError::new(request_id, host_identity, reason, None);
        Self {
            control_json: serde_json::to_string(&control)
                .expect("the closed WebSocket error contract is serializable"),
            reason,
        }
    }
}

enum ConnectionEnd {
    PeerClosed,
    WriterGone,
    Failure {
        request_id: RequestId,
        reason: WsCloseReason,
    },
}

async fn controller_loop(
    mut stream: EventStream,
    outbound: mpsc::Sender<OutboundFrame>,
    mut writer_done: tokio::sync::oneshot::Receiver<()>,
    state: Arc<DaemonState>,
    principal: &ApiPrincipal,
    handshake_request_id: RequestId,
    delivered_sequence: &std::sync::atomic::AtomicU64,
) -> ConnectionEnd {
    let rate_key = principal.principal_ref().to_string();
    let mut active_request_id = handshake_request_id;
    let mut subscriptions = Vec::new();
    let mut live_events = None;
    let mut sequence = 0_u64;
    let mut last_inbound = Instant::now();
    let mut shutdown = state.shutdown.subscribe();
    let mut ping = tokio::time::interval(Duration::from_millis(
        state.limits.websocket_ping_interval_ms(),
    ));
    ping.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ping.tick().await;

    loop {
        // A receiver created after shutdown was sent starts with `true` as its
        // current value, so check it before waiting for another change.
        if shutdown_requested(&shutdown) {
            return ConnectionEnd::Failure {
                request_id: active_request_id,
                reason: WsCloseReason::ServerShutdown,
            };
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                return ConnectionEnd::Failure {
                    request_id: active_request_id,
                    reason: WsCloseReason::ServerShutdown,
                };
            }
            _ = &mut writer_done => return ConnectionEnd::WriterGone,
            _ = ping.tick() => {
                if last_inbound.elapsed()
                    >= Duration::from_millis(state.limits.websocket_idle_timeout_ms())
                {
                    return ConnectionEnd::Failure {
                        request_id: active_request_id,
                        reason: WsCloseReason::IdleTimeout,
                    };
                }
                match principal_is_active(&state, principal).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::AuthenticationFailed,
                        };
                    }
                    Err(()) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::InternalError,
                        };
                    }
                }
                match queue_message(
                    &outbound,
                    OutboundFrame::Control(Message::Ping(Vec::new().into())),
                ) {
                    Ok(()) => {}
                    Err(QueueError::Full) => {
                        record_slow_consumer(
                            principal,
                            &subscriptions,
                            delivered_sequence.load(std::sync::atomic::Ordering::Acquire),
                            0,
                        );
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::SlowConsumer,
                        };
                    }
                    Err(QueueError::Closed | QueueError::Encode) => {
                        return ConnectionEnd::WriterGone;
                    }
                }
            }
            incoming = stream.next() => {
                let Some(incoming) = incoming else {
                    return ConnectionEnd::PeerClosed;
                };
                let message = match incoming {
                    Ok(message) => message,
                    Err(error) => {
                        return classify_receive_error(error).map_or(
                            ConnectionEnd::PeerClosed,
                            |reason| ConnectionEnd::Failure {
                                request_id: active_request_id,
                                reason,
                            },
                        );
                    }
                };
                if matches!(message, Message::Close(_)) {
                    return ConnectionEnd::PeerClosed;
                }
                if !state.websocket_inbound_limit.allow(rate_key.clone()) {
                    return ConnectionEnd::Failure {
                        request_id: active_request_id,
                        reason: WsCloseReason::RateLimited,
                    };
                }
                last_inbound = Instant::now();
                match principal_is_active(&state, principal).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::AuthenticationFailed,
                        };
                    }
                    Err(()) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::InternalError,
                        };
                    }
                }
                match message {
                    Message::Text(text) => {
                        let request = match decode_subscribe(&text, &active_request_id) {
                            Ok(request) => request,
                            Err((request_id, reason)) => {
                                return ConnectionEnd::Failure { request_id, reason };
                            }
                        };
                        let replacement = match subscribe_to_host(&state).await {
                            Ok(subscription) => subscription,
                            Err(()) => {
                                return ConnectionEnd::Failure {
                                    request_id: request.request_id().clone(),
                                    reason: WsCloseReason::InternalError,
                                };
                            }
                        };
                        let acknowledgement = SubscribedResponse::new(
                            request.request_id().clone(),
                            state.host_identity.clone(),
                            request.subscriptions().to_vec(),
                        );
                        match queue_json(&outbound, &acknowledgement, None) {
                            Ok(()) => {
                                active_request_id = request.request_id().clone();
                                subscriptions = request.subscriptions().to_vec();
                                live_events = Some(replacement);
                            }
                            Err(QueueError::Full) => {
                                record_slow_consumer(
                                    principal,
                                    &subscriptions,
                                    delivered_sequence
                                        .load(std::sync::atomic::Ordering::Acquire),
                                    0,
                                );
                                return ConnectionEnd::Failure {
                                    request_id: request.request_id().clone(),
                                    reason: WsCloseReason::SlowConsumer,
                                };
                            }
                            Err(QueueError::Closed) => return ConnectionEnd::WriterGone,
                            Err(QueueError::Encode) => {
                                return ConnectionEnd::Failure {
                                    request_id: request.request_id().clone(),
                                    reason: WsCloseReason::InternalError,
                                };
                            }
                        }
                    }
                    Message::Binary(_) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::InvalidRequest,
                        };
                    }
                    Message::Ping(payload) => {
                        match queue_message(
                            &outbound,
                            OutboundFrame::Control(Message::Pong(payload)),
                        ) {
                            Ok(()) => {}
                            Err(QueueError::Full) => {
                                record_slow_consumer(
                                    principal,
                                    &subscriptions,
                                    delivered_sequence
                                        .load(std::sync::atomic::Ordering::Acquire),
                                    0,
                                );
                                return ConnectionEnd::Failure {
                                    request_id: active_request_id,
                                    reason: WsCloseReason::SlowConsumer,
                                };
                            }
                            Err(QueueError::Closed | QueueError::Encode) => {
                                return ConnectionEnd::WriterGone;
                            }
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => unreachable!("close frames return before rate limiting"),
                }
            }
            event = receive_live_event(&mut live_events) => {
                let event = match event {
                    Ok(event) => event,
                    Err(LiveEventReceiveError::Lagged { dropped }) => {
                        record_slow_consumer(
                            principal,
                            &subscriptions,
                            delivered_sequence.load(std::sync::atomic::Ordering::Acquire),
                            dropped,
                        );
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::SlowConsumer,
                        };
                    }
                    Err(LiveEventReceiveError::Closed) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::InternalError,
                        };
                    }
                    Err(LiveEventReceiveError::Empty) => continue,
                };
                let Some(next_sequence) = sequence.checked_add(1) else {
                    return ConnectionEnd::Failure {
                        request_id: active_request_id,
                        reason: WsCloseReason::InternalError,
                    };
                };
                sequence = next_sequence;
                if !subscriptions
                    .iter()
                    .any(|subscription: &EventSubscription| subscription.matches(&event))
                {
                    continue;
                }
                let wire = event
                    .as_ref()
                    .clone()
                    .with_seq(sequence)
                    .expect("a positive stream sequence is valid");
                match queue_json(&outbound, &wire, Some(sequence)) {
                    Ok(()) => {}
                    Err(QueueError::Full) => {
                        record_slow_consumer(
                            principal,
                            &subscriptions,
                            delivered_sequence.load(std::sync::atomic::Ordering::Acquire),
                            1,
                        );
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::SlowConsumer,
                        };
                    }
                    Err(QueueError::Closed) => return ConnectionEnd::WriterGone,
                    Err(QueueError::Encode) => {
                        return ConnectionEnd::Failure {
                            request_id: active_request_id,
                            reason: WsCloseReason::InternalError,
                        };
                    }
                }
            }
        }
    }
}

async fn writer_loop(
    mut sink: EventSink,
    mut outbound: mpsc::Receiver<OutboundFrame>,
    mut terminal: tokio::sync::oneshot::Receiver<Option<TerminalClose>>,
    delivered_sequence: Arc<std::sync::atomic::AtomicU64>,
) {
    loop {
        tokio::select! {
            biased;
            terminal = &mut terminal => {
                if let Ok(Some(terminal)) = terminal {
                    let _ = sink
                        .send(Message::Text(terminal.control_json.into()))
                        .await;
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code: terminal.reason.close_code(),
                            reason: terminal.reason.as_str().into(),
                        })))
                        .await;
                }
                return;
            }
            frame = outbound.recv() => {
                let Some(frame) = frame else {
                    return;
                };
                let (message, event_sequence) = match frame {
                    OutboundFrame::Control(message) => (message, None),
                    OutboundFrame::Event { message, sequence } => (message, Some(sequence)),
                };
                if sink.send(message).await.is_err() {
                    return;
                }
                if let Some(sequence) = event_sequence {
                    delivered_sequence.store(sequence, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }
}

async fn receive_live_event(
    subscription: &mut Option<LiveEventSubscription>,
) -> Result<Arc<satelle_core::SatelleEventBody>, LiveEventReceiveError> {
    match subscription {
        Some(subscription) => subscription.recv().await,
        None => pending().await,
    }
}

async fn principal_is_active(
    state: &Arc<DaemonState>,
    principal: &ApiPrincipal,
) -> Result<bool, ()> {
    let service = Arc::clone(&state.service);
    let principal = principal.clone();
    tokio::task::spawn_blocking(move || service.api_principal_is_active(&principal))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

async fn subscribe_to_host(state: &Arc<DaemonState>) -> Result<LiveEventSubscription, ()> {
    let service = Arc::clone(&state.service);
    tokio::task::spawn_blocking(move || service.subscribe_live_events())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

#[derive(Deserialize)]
struct ControlProbe {
    schema_version: String,
    #[serde(rename = "type")]
    message_type: String,
    request_id: RequestId,
}

fn decode_subscribe(
    text: &str,
    fallback_request_id: &RequestId,
) -> Result<SubscribeRequest, (RequestId, WsCloseReason)> {
    let probe = serde_json::from_str::<ControlProbe>(text)
        .map_err(|_| (fallback_request_id.clone(), WsCloseReason::InvalidRequest))?;
    if probe.schema_version != "satelle.ws.control.v1" {
        return Err((probe.request_id, WsCloseReason::UnsupportedSchema));
    }
    if probe.message_type != "subscribe" {
        return Err((probe.request_id, WsCloseReason::InvalidRequest));
    }
    let value = serde_json::from_str::<Value>(text)
        .map_err(|_| (probe.request_id.clone(), WsCloseReason::InvalidRequest))?;
    if value
        .get("subscriptions")
        .and_then(Value::as_array)
        .is_some_and(|subscriptions| subscriptions.len() > MAX_EVENT_SUBSCRIPTIONS)
    {
        return Err((probe.request_id, WsCloseReason::CapacityExceeded));
    }
    serde_json::from_str::<SubscribeRequest>(text)
        .map_err(|_| (probe.request_id, WsCloseReason::InvalidRequest))
}

fn classify_receive_error(error: axum::Error) -> Option<WsCloseReason> {
    let Ok(error) = error.into_inner().downcast::<WebSocketError>() else {
        return Some(WsCloseReason::InternalError);
    };
    match *error {
        WebSocketError::Capacity(_) => Some(WsCloseReason::PayloadTooLarge),
        WebSocketError::Protocol(_) | WebSocketError::Utf8(_) | WebSocketError::AttackAttempt => {
            Some(WsCloseReason::InvalidRequest)
        }
        WebSocketError::ConnectionClosed
        | WebSocketError::AlreadyClosed
        | WebSocketError::Io(_) => None,
        _ => Some(WsCloseReason::InternalError),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueueError {
    Full,
    Closed,
    Encode,
}

fn queue_json(
    outbound: &mpsc::Sender<OutboundFrame>,
    value: &impl serde::Serialize,
    sequence: Option<u64>,
) -> Result<(), QueueError> {
    let message = Message::Text(
        serde_json::to_string(value)
            .map_err(|_| QueueError::Encode)?
            .into(),
    );
    let frame = match sequence {
        Some(sequence) => OutboundFrame::Event { message, sequence },
        None => OutboundFrame::Control(message),
    };
    queue_message(outbound, frame)
}

fn queue_message(
    outbound: &mpsc::Sender<OutboundFrame>,
    frame: OutboundFrame,
) -> Result<(), QueueError> {
    outbound.try_send(frame).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => QueueError::Full,
        mpsc::error::TrySendError::Closed(_) => QueueError::Closed,
    })
}

fn record_slow_consumer(
    principal: &ApiPrincipal,
    subscriptions: &[EventSubscription],
    last_delivered_sequence: u64,
    dropped_event_count: u64,
) {
    SlowConsumerDiagnostic::new(
        principal.token_id(),
        subscriptions,
        last_delivered_sequence,
        dropped_event_count,
    )
    .record();
}

struct SlowConsumerDiagnostic<'a> {
    principal_token_id: &'a str,
    subscription_scope: &'static str,
    last_delivered_sequence: u64,
    dropped_event_count: u64,
}

impl<'a> SlowConsumerDiagnostic<'a> {
    fn new(
        principal_token_id: &'a str,
        subscriptions: &[EventSubscription],
        last_delivered_sequence: u64,
        dropped_event_count: u64,
    ) -> Self {
        Self {
            principal_token_id,
            subscription_scope: subscription_scope(subscriptions),
            last_delivered_sequence,
            dropped_event_count,
        }
    }

    fn record(self) {
        tracing::warn!(
            target: "satelle::transport::events",
            principal_token_id = self.principal_token_id,
            subscription_scope = self.subscription_scope,
            last_delivered_seq = self.last_delivered_sequence,
            dropped_event_count = self.dropped_event_count,
            "WebSocket subscriber exceeded its outbound event capacity"
        );
    }
}

fn subscription_scope(subscriptions: &[EventSubscription]) -> &'static str {
    let mut kinds = 0_u8;
    for subscription in subscriptions {
        kinds |= match subscription {
            EventSubscription::Host => 1,
            EventSubscription::Session { .. } => 2,
            EventSubscription::Turn { .. } => 4,
        };
    }
    match kinds {
        0 => "none",
        1 => "host",
        2 => "session",
        4 => "turn",
        _ => "mixed",
    }
}

fn shutdown_requested(shutdown: &tokio::sync::watch::Receiver<bool>) -> bool {
    *shutdown.borrow()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receiver_created_after_shutdown_observes_the_current_value() {
        let (shutdown, _initial_receiver) = tokio::sync::watch::channel(false);
        shutdown.send(true).expect("publish shutdown");
        let late_receiver = shutdown.subscribe();

        assert!(shutdown_requested(&late_receiver));
    }

    #[tokio::test]
    async fn a_full_event_queue_cannot_block_or_suppress_terminal_signaling() {
        let (outbound, _outbound_receiver) = mpsc::channel(1);
        queue_json(&outbound, &serde_json::json!({"first": true}), Some(1))
            .expect("fill event queue");
        assert_eq!(
            queue_json(&outbound, &serde_json::json!({"second": true}), Some(2)),
            Err(QueueError::Full)
        );

        let (terminal, _terminal_receiver) = tokio::sync::oneshot::channel();
        assert!(
            terminal
                .send(Some(TerminalClose::new(
                    RequestId::new(),
                    "host-test".to_string(),
                    WsCloseReason::SlowConsumer,
                )))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_unresponsive_writer_is_aborted_within_the_close_grace() {
        let (terminal, terminal_receiver) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(async move {
            let _keep_terminal_open = terminal_receiver;
            pending::<()>().await;
        });

        tokio::time::timeout(
            Duration::from_secs(1),
            finish_writer(terminal, None, writer),
        )
        .await
        .expect("writer shutdown is bounded");
    }

    #[test]
    fn slow_consumer_diagnostics_have_only_the_safe_closed_shape() {
        let diagnostic =
            SlowConsumerDiagnostic::new("token-safe-id", &[EventSubscription::Host], 17, 3);

        assert_eq!(diagnostic.principal_token_id, "token-safe-id");
        assert_eq!(diagnostic.subscription_scope, "host");
        assert_eq!(diagnostic.last_delivered_sequence, 17);
        assert_eq!(diagnostic.dropped_event_count, 3);
    }
}
