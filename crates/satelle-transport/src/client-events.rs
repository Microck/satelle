use crate::contract::{
    ApiError, EventSubscription, RequestId, SubscribeRequest, SubscribedResponse, WsCloseReason,
    WsControlError, WsServerControl,
};
use crate::transport_tls::{
    TlsFailureKind, WebSocketTrustError, classify_tls_error, find_error_in_tree,
    websocket_tls_config,
};
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use satelle_core::{DirectHostBinding, SatelleEvent};
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async, connect_async_tls_with_config,
};
use zeroize::Zeroizing;

type EventSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub struct DaemonEventStream {
    socket: EventSocket,
    expected_host_identity: String,
    expected_request_id: RequestId,
    last_sequence: u64,
}

const CONTROL_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
const EVENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

pub struct DaemonEventClient {
    endpoint: EventEndpoint,
    token: satelle_host::ApiBearerToken,
    expected_host_identity: String,
}

enum EventEndpoint {
    Loopback(SocketAddr),
    Direct {
        url: String,
        tls_config: Arc<ClientConfig>,
    },
}

impl DaemonEventClient {
    pub fn loopback(
        address: SocketAddr,
        token: satelle_host::ApiBearerToken,
        expected_host_identity: impl Into<String>,
    ) -> Result<Self, DaemonEventError> {
        if !address.ip().is_loopback() {
            return Err(DaemonEventError::NonLoopbackPlaintextEndpoint);
        }
        let expected_host_identity = expected_host_identity.into();
        HeaderValue::from_str(&expected_host_identity)
            .map_err(|_| DaemonEventError::InvalidHeader)?;
        Ok(Self {
            endpoint: EventEndpoint::Loopback(address),
            token,
            expected_host_identity,
        })
    }

    pub fn wss(
        binding: &DirectHostBinding,
        token: satelle_host::ApiBearerToken,
        ca_bundle: Option<&[u8]>,
    ) -> Result<Self, DaemonEventError> {
        let expected_host_identity = binding.expected_host_identity().to_string();
        HeaderValue::from_str(&expected_host_identity)
            .map_err(|_| DaemonEventError::InvalidHeader)?;
        let url = format!(
            "{}/v1/events",
            binding.origin().replacen("https://", "wss://", 1)
        );
        let tls_config = websocket_tls_config(ca_bundle).map_err(|error| match error {
            WebSocketTrustError::InvalidCaBundle => DaemonEventError::InvalidCaBundle,
            WebSocketTrustError::EmptyCaBundle => DaemonEventError::EmptyCaBundle,
            WebSocketTrustError::TlsConfiguration(error) => {
                DaemonEventError::TlsConfiguration(error)
            }
        })?;
        Ok(Self {
            endpoint: EventEndpoint::Direct { url, tls_config },
            token,
            expected_host_identity,
        })
    }

    pub async fn connect_events(
        &self,
        subscriptions: Vec<EventSubscription>,
    ) -> Result<DaemonEventStream, DaemonEventError> {
        self.connect_events_with_timeout(subscriptions, EVENT_HANDSHAKE_TIMEOUT)
            .await
    }

    async fn connect_events_with_timeout(
        &self,
        subscriptions: Vec<EventSubscription>,
        handshake_timeout: Duration,
    ) -> Result<DaemonEventStream, DaemonEventError> {
        tokio::time::timeout(
            handshake_timeout,
            self.connect_events_without_timeout(subscriptions),
        )
        .await
        .map_err(|_| DaemonEventError::HandshakeTimeout)?
    }

    async fn connect_events_without_timeout(
        &self,
        subscriptions: Vec<EventSubscription>,
    ) -> Result<DaemonEventStream, DaemonEventError> {
        let request_id = RequestId::new();
        let subscribe = SubscribeRequest::new(request_id.clone(), subscriptions.clone())
            .map_err(|_| DaemonEventError::InvalidSubscriptions)?;
        let url = match &self.endpoint {
            EventEndpoint::Loopback(address) => format!("ws://{address}/v1/events"),
            EventEndpoint::Direct { url, .. } => url.clone(),
        };
        let mut request = url
            .into_client_request()
            .map_err(DaemonEventError::Transport)?;
        let exposed = self.token.expose();
        let authorization_value = Zeroizing::new(format!("Bearer {}", exposed.as_str()));
        let mut authorization = HeaderValue::from_str(authorization_value.as_str())
            .map_err(|_| DaemonEventError::InvalidHeader)?;
        authorization.set_sensitive(true);
        request.headers_mut().insert("authorization", authorization);
        request.headers_mut().insert(
            "satelle-expected-host-identity",
            HeaderValue::from_str(&self.expected_host_identity)
                .map_err(|_| DaemonEventError::InvalidHeader)?,
        );
        request.headers_mut().insert(
            "satelle-request-id",
            HeaderValue::from_str(request_id.as_str())
                .map_err(|_| DaemonEventError::InvalidHeader)?,
        );
        drop(exposed);
        let (mut socket, _) = match &self.endpoint {
            EventEndpoint::Loopback(address) => {
                let tcp = TcpStream::connect(address)
                    .await
                    .map_err(DaemonEventError::Connect)?;
                client_async(request, MaybeTlsStream::Plain(tcp)).await
            }
            EventEndpoint::Direct { tls_config, .. } => {
                connect_async_tls_with_config(
                    request,
                    None,
                    false,
                    Some(Connector::Rustls(Arc::clone(tls_config))),
                )
                .await
            }
        }
        .map_err(|error| map_connection_error(error, &request_id, &self.expected_host_identity))?;
        socket
            .send(Message::Text(
                serde_json::to_string(&subscribe)
                    .map_err(DaemonEventError::Encode)?
                    .into(),
            ))
            .await
            .map_err(DaemonEventError::Transport)?;
        let acknowledgement =
            read_control(&mut socket, &request_id, &self.expected_host_identity).await?;
        validate_acknowledgement(
            acknowledgement,
            &request_id,
            &self.expected_host_identity,
            &subscriptions,
        )?;
        Ok(DaemonEventStream {
            socket,
            expected_host_identity: self.expected_host_identity.clone(),
            expected_request_id: request_id,
            last_sequence: 0,
        })
    }
}

impl DaemonEventStream {
    pub async fn next_event(&mut self) -> Result<SatelleEvent, DaemonEventError> {
        self.next_event_with_timeout(EVENT_STREAM_IDLE_TIMEOUT)
            .await
    }

    async fn next_event_with_timeout(
        &mut self,
        idle_timeout: Duration,
    ) -> Result<SatelleEvent, DaemonEventError> {
        loop {
            // Bound each wait independently so heartbeat frames renew liveness
            // without extending a genuinely silent stream indefinitely.
            let message = tokio::time::timeout(idle_timeout, self.socket.next())
                .await
                .map_err(|_| DaemonEventError::StreamIdleTimeout)?
                .ok_or(DaemonEventError::Disconnected)?
                .map_err(DaemonEventError::Transport)?;
            match message {
                Message::Text(text) => {
                    let text = text.as_str();
                    match serde_json::from_str::<SatelleEvent>(text) {
                        Ok(event) => {
                            if event.host() != self.expected_host_identity {
                                return Err(DaemonEventError::HostIdentityMismatch);
                            }
                            if event.seq() <= self.last_sequence {
                                return Err(DaemonEventError::SequenceDidNotAdvance);
                            }
                            self.last_sequence = event.seq();
                            return Ok(event);
                        }
                        Err(event_error) => match serde_json::from_str::<WsServerControl>(text) {
                            Ok(WsServerControl::Subscribed(acknowledgement)) => {
                                validate_control_context(
                                    acknowledgement.request_id(),
                                    acknowledgement.host_identity(),
                                    &self.expected_request_id,
                                    &self.expected_host_identity,
                                )?;
                                return Err(DaemonEventError::UnexpectedFrame);
                            }
                            Ok(WsServerControl::Error(error)) => {
                                validate_control_context(
                                    error.request_id(),
                                    error.host_identity(),
                                    &self.expected_request_id,
                                    &self.expected_host_identity,
                                )?;
                                return Err(read_close_after_control(&mut self.socket, error).await);
                            }
                            Err(_) => return Err(DaemonEventError::InvalidEvent(event_error)),
                        },
                    }
                }
                Message::Ping(payload) => self
                    .socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(DaemonEventError::Transport)?,
                Message::Pong(_) => {}
                Message::Close(frame) => {
                    return Err(close_error(frame, None));
                }
                Message::Binary(_) | Message::Frame(_) => {
                    return Err(DaemonEventError::UnexpectedFrame);
                }
            }
        }
    }
}

async fn read_control(
    socket: &mut EventSocket,
    expected_request_id: &RequestId,
    expected_host_identity: &str,
) -> Result<SubscribedResponse, DaemonEventError> {
    loop {
        let message = socket
            .next()
            .await
            .ok_or(DaemonEventError::Disconnected)?
            .map_err(DaemonEventError::Transport)?;
        match message {
            Message::Text(text) => {
                return match serde_json::from_str::<WsServerControl>(&text)
                    .map_err(DaemonEventError::InvalidControl)?
                {
                    WsServerControl::Subscribed(acknowledgement) => Ok(acknowledgement),
                    WsServerControl::Error(error) => {
                        validate_control_context(
                            error.request_id(),
                            error.host_identity(),
                            expected_request_id,
                            expected_host_identity,
                        )?;
                        Err(read_close_after_control(socket, error).await)
                    }
                };
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(DaemonEventError::Transport)?,
            Message::Pong(_) => {}
            Message::Close(frame) => {
                return Err(close_error(frame, None));
            }
            Message::Binary(_) | Message::Frame(_) => {
                return Err(DaemonEventError::UnexpectedFrame);
            }
        }
    }
}

fn validate_acknowledgement(
    acknowledgement: SubscribedResponse,
    request_id: &RequestId,
    expected_host_identity: &str,
    subscriptions: &[EventSubscription],
) -> Result<(), DaemonEventError> {
    validate_control_context(
        acknowledgement.request_id(),
        acknowledgement.host_identity(),
        request_id,
        expected_host_identity,
    )?;
    if acknowledgement.subscriptions() != subscriptions {
        return Err(DaemonEventError::SubscriptionMismatch);
    }
    Ok(())
}

fn validate_control_context(
    request_id: &RequestId,
    host_identity: &str,
    expected_request_id: &RequestId,
    expected_host_identity: &str,
) -> Result<(), DaemonEventError> {
    if request_id != expected_request_id {
        return Err(DaemonEventError::RequestIdMismatch);
    }
    if host_identity != expected_host_identity {
        return Err(DaemonEventError::HostIdentityMismatch);
    }
    Ok(())
}

async fn read_close_after_control(
    socket: &mut EventSocket,
    control: WsControlError,
) -> DaemonEventError {
    match tokio::time::timeout(CONTROL_CLOSE_TIMEOUT, wait_for_close(socket)).await {
        Ok(Ok(frame)) => close_error(frame, Some(control)),
        Ok(Err(())) | Err(_) => DaemonEventError::ControlWithoutClose(Box::new(control)),
    }
}

async fn wait_for_close(socket: &mut EventSocket) -> Result<Option<CloseFrame>, ()> {
    loop {
        let message = socket.next().await.ok_or(())?.map_err(|_| ())?;
        match message {
            Message::Close(frame) => return Ok(frame),
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await.map_err(|_| ())?,
            Message::Pong(_) => {}
            Message::Text(_) | Message::Binary(_) | Message::Frame(_) => return Err(()),
        }
    }
}

fn close_error(frame: Option<CloseFrame>, control: Option<WsControlError>) -> DaemonEventError {
    let Some(frame) = frame else {
        return control.map_or(DaemonEventError::Disconnected, |control| {
            DaemonEventError::ControlWithoutClose(Box::new(control))
        });
    };
    let code = u16::from(frame.code);
    let reason_text = frame.reason.to_string();
    let Some(reason) = WsCloseReason::parse(&reason_text) else {
        return DaemonEventError::CloseContractMismatch {
            control: control.map(Box::new),
            code,
            reason: reason_text,
        };
    };
    if code != reason.close_code()
        || control.as_ref().is_some_and(|control| {
            control.reason() != reason || control.code() != reason.api_code()
        })
    {
        return DaemonEventError::CloseContractMismatch {
            control: control.map(Box::new),
            code,
            reason: reason_text,
        };
    }
    DaemonEventError::Closed {
        control: control.map(Box::new),
        code,
        reason,
    }
}

fn map_connection_error(
    error: WebSocketError,
    request_id: &RequestId,
    expected_host_identity: &str,
) -> DaemonEventError {
    if matches!(error, WebSocketError::Http(_)) {
        return map_handshake_error(error, request_id, expected_host_identity);
    }
    match find_error_in_tree::<rustls::Error>(&error, 16).map(classify_tls_error) {
        Some(TlsFailureKind::CertificateUntrusted) => DaemonEventError::CertificateUntrusted(error),
        Some(TlsFailureKind::CertificateHostnameMismatch) => {
            DaemonEventError::CertificateHostnameMismatch(error)
        }
        Some(TlsFailureKind::CertificateExpired) => DaemonEventError::CertificateExpired(error),
        Some(TlsFailureKind::VersionUnsupported) => DaemonEventError::TlsVersionUnsupported(error),
        Some(TlsFailureKind::Handshake) => DaemonEventError::TlsHandshake(error),
        None => DaemonEventError::Transport(error),
    }
}

fn map_handshake_error(
    error: WebSocketError,
    request_id: &RequestId,
    expected_host_identity: &str,
) -> DaemonEventError {
    let WebSocketError::Http(response) = error else {
        return DaemonEventError::Transport(error);
    };
    let status = response.status().as_u16();
    let Some(body) = response.into_body() else {
        return DaemonEventError::InvalidHandshakeResponse;
    };
    let Ok(error) = serde_json::from_slice::<ApiError>(&body) else {
        return DaemonEventError::InvalidHandshakeResponse;
    };
    if error.request_id() != request_id {
        return DaemonEventError::RequestIdMismatch;
    }
    if !super::api_error_host_identity_is_valid(&error, expected_host_identity) {
        return DaemonEventError::HostIdentityMismatch;
    }
    DaemonEventError::Handshake {
        status,
        error: Box::new(error),
    }
}

#[derive(Debug)]
pub enum DaemonEventError {
    NonLoopbackPlaintextEndpoint,
    InvalidSubscriptions,
    InvalidHeader,
    InvalidCaBundle,
    EmptyCaBundle,
    TlsConfiguration(rustls::Error),
    CertificateUntrusted(WebSocketError),
    CertificateHostnameMismatch(WebSocketError),
    CertificateExpired(WebSocketError),
    TlsVersionUnsupported(WebSocketError),
    TlsHandshake(WebSocketError),
    HandshakeTimeout,
    StreamIdleTimeout,
    InvalidHandshakeResponse,
    Connect(std::io::Error),
    Transport(WebSocketError),
    Encode(serde_json::Error),
    InvalidControl(serde_json::Error),
    InvalidEvent(serde_json::Error),
    Handshake {
        status: u16,
        error: Box<ApiError>,
    },
    ControlWithoutClose(Box<WsControlError>),
    CloseContractMismatch {
        control: Option<Box<WsControlError>>,
        code: u16,
        reason: String,
    },
    RequestIdMismatch,
    HostIdentityMismatch,
    SubscriptionMismatch,
    SequenceDidNotAdvance,
    UnexpectedFrame,
    Closed {
        control: Option<Box<WsControlError>>,
        code: u16,
        reason: WsCloseReason,
    },
    Disconnected,
}

impl DaemonEventError {
    /// Returns true only when the event contract remains trustworthy and the
    /// underlying connection itself was lost. Protocol, identity, TLS, frame,
    /// and sequence failures must never be hidden by status reconciliation.
    pub fn is_recoverable_disconnect(&self) -> bool {
        matches!(
            self,
            Self::Connect(_)
                | Self::HandshakeTimeout
                | Self::StreamIdleTimeout
                | Self::Disconnected
                | Self::Transport(WebSocketError::ConnectionClosed | WebSocketError::Io(_))
                | Self::Closed {
                    reason: WsCloseReason::IdleTimeout
                        | WsCloseReason::ServerShutdown
                        | WsCloseReason::SlowConsumer,
                    ..
                }
        )
    }
}

impl fmt::Display for DaemonEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonLoopbackPlaintextEndpoint => {
                "plaintext live event transport requires a loopback endpoint"
            }
            Self::InvalidSubscriptions => "the live event subscriptions are invalid",
            Self::InvalidHeader => "the live event handshake contains an invalid header",
            Self::InvalidCaBundle => "the configured CA bundle is invalid",
            Self::EmptyCaBundle => "the configured CA bundle contains no certificates",
            Self::TlsConfiguration(_) => "the live event TLS configuration failed",
            Self::CertificateUntrusted(_) => "the Host Daemon certificate is not trusted",
            Self::CertificateHostnameMismatch(_) => {
                "the Host Daemon certificate does not match the configured hostname"
            }
            Self::CertificateExpired(_) => "the Host Daemon certificate has expired",
            Self::TlsVersionUnsupported(_) => "the Host Daemon does not support TLS 1.2 or newer",
            Self::TlsHandshake(_) => "the Host Daemon TLS handshake failed",
            Self::HandshakeTimeout => "the live event handshake timed out",
            Self::StreamIdleTimeout => {
                "the live event stream timed out while waiting for the next frame"
            }
            Self::InvalidHandshakeResponse => {
                "the Host Daemon returned an invalid WebSocket handshake response"
            }
            Self::Connect(_) | Self::Transport(_) => "the live event transport failed",
            Self::Encode(_) => "the live event subscription could not be encoded",
            Self::InvalidControl(_) => "the Host Daemon returned an invalid control message",
            Self::InvalidEvent(_) => "the Host Daemon returned an invalid Satelle Event",
            Self::Handshake { .. } => {
                "the Host Daemon rejected the live event handshake with a typed error"
            }
            Self::ControlWithoutClose(_) => {
                "the Host Daemon sent a typed WebSocket error without its required close frame"
            }
            Self::CloseContractMismatch { .. } => {
                "the Host Daemon WebSocket error and close frame did not match"
            }
            Self::RequestIdMismatch => {
                "the live event protocol response did not match the request ID"
            }
            Self::HostIdentityMismatch => {
                "the live event stream did not match the pinned Host Identity"
            }
            Self::SubscriptionMismatch => {
                "the Host Daemon acknowledged different live event subscriptions"
            }
            Self::SequenceDidNotAdvance => "the live event sequence did not advance",
            Self::UnexpectedFrame => "the Host Daemon returned an unexpected WebSocket frame",
            Self::Closed { .. } => "the Host Daemon closed the live event stream",
            Self::Disconnected => "the live event stream disconnected without a close reason",
        })
    }
}

impl fmt::Debug for DaemonEventClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("DaemonEventClient");
        match &self.endpoint {
            EventEndpoint::Loopback(address) => {
                debug.field("endpoint", &format_args!("ws://{address}/v1/events"));
            }
            EventEndpoint::Direct { url, .. } => {
                debug.field("endpoint", url);
            }
        }
        debug
            .field("expected_host_identity", &self.expected_host_identity)
            .finish_non_exhaustive()
    }
}

impl std::error::Error for DaemonEventError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::TlsConfiguration(error) => Some(error),
            Self::CertificateUntrusted(error)
            | Self::CertificateHostnameMismatch(error)
            | Self::CertificateExpired(error)
            | Self::TlsVersionUnsupported(error)
            | Self::TlsHandshake(error)
            | Self::Transport(error) => Some(error),
            Self::Encode(error) | Self::InvalidControl(error) | Self::InvalidEvent(error) => {
                Some(error)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "client-events-tests.rs"]
mod tests;
