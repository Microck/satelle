use super::{ApiFailure, DaemonState, api_error_response, auth, request_id_or_new};
use crate::contract::{ApiErrorCategory, ApiErrorCode};
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::extract::{Request, State};
use axum::http::header::CONNECTION;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use axum::serve::Listener;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;
use tokio_rustls::Accept;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

const REJECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct LimitedTcpListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
    rejection_permits: Arc<Semaphore>,
    activity: ConnectionActivity,
    tls_acceptor: Option<TlsAcceptor>,
}

impl LimitedTcpListener {
    pub(super) fn new(inner: TcpListener, max_connections: usize) -> Self {
        Self {
            inner,
            permits: Arc::new(Semaphore::new(max_connections)),
            // One reserved response slot prevents connection floods from
            // creating unbounded Hyper tasks while still giving an ordinary
            // over-capacity caller a typed response.
            rejection_permits: Arc::new(Semaphore::new(1)),
            activity: ConnectionActivity::default(),
            tls_acceptor: None,
        }
    }

    pub(super) fn with_tls(
        inner: TcpListener,
        max_connections: usize,
        server_config: Arc<rustls::ServerConfig>,
    ) -> Self {
        let mut listener = Self::new(inner, max_connections);
        listener.tls_acceptor = Some(TlsAcceptor::from(server_config));
        listener
    }

    pub(super) fn activity(&self) -> ConnectionActivity {
        self.activity.clone()
    }

    async fn acquire_admission(&self) -> ConnectionAdmission {
        if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
            return ConnectionAdmission::Admitted { _permit: permit };
        }
        if let Ok(permit) = Arc::clone(&self.rejection_permits).try_acquire_owned() {
            return ConnectionAdmission::Rejected { _permit: permit };
        }
        // Keep this one accepted socket outside Hyper until either normal
        // capacity or the single typed-rejection lane becomes available.
        // The kernel backlog remains the outer bound for later connections.
        tokio::select! {
            permit = Arc::clone(&self.permits).acquire_owned() => {
                ConnectionAdmission::Admitted {
                    _permit: permit.expect("the connection semaphore is never closed"),
                }
            }
            permit = Arc::clone(&self.rejection_permits).acquire_owned() => {
                ConnectionAdmission::Rejected {
                    _permit: permit.expect("the rejection semaphore is never closed"),
                }
            }
        }
    }
}

impl Listener for LimitedTcpListener {
    type Io = PermitIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, address)) => {
                    let activity = self.activity.connect();
                    let admission = self.acquire_admission().await;
                    let _ = stream.set_nodelay(true);
                    let stream = match &self.tls_acceptor {
                        // Hyper polls each handshake in its own bounded
                        // connection task. The deadline prevents silent peers
                        // from retaining every admission permit indefinitely.
                        Some(acceptor) => TransportIo::TlsHandshake {
                            handshake: Box::pin(acceptor.accept(stream)),
                            deadline: Box::pin(tokio::time::sleep(TLS_HANDSHAKE_TIMEOUT)),
                        },
                        None => TransportIo::Plain(stream),
                    };
                    return (PermitIo::new(stream, admission, activity), address);
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

pub(super) struct PermitIo {
    stream: TransportIo,
    admission: ConnectionAdmission,
    _activity: ConnectedClient,
    rejection_deadline: Option<Pin<Box<Sleep>>>,
    start_rejection_deadline_after_handshake: bool,
}

enum TransportIo {
    Plain(TcpStream),
    TlsHandshake {
        handshake: Pin<Box<Accept<TcpStream>>>,
        deadline: Pin<Box<Sleep>>,
    },
    Tls(Box<TlsStream<TcpStream>>),
    TlsFailed {
        kind: io::ErrorKind,
        message: String,
    },
}

impl TransportIo {
    const fn handshake_pending(&self) -> bool {
        matches!(self, Self::TlsHandshake { .. })
    }

    fn poll_handshake(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Self::TlsFailed { kind, message } = self {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        let Self::TlsHandshake {
            handshake,
            deadline,
        } = self
        else {
            return Poll::Ready(Ok(()));
        };
        match handshake.as_mut().poll(context) {
            Poll::Ready(Ok(stream)) => {
                *self = Self::Tls(Box::new(stream));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                let kind = error.kind();
                let message = error.to_string();
                *self = Self::TlsFailed {
                    kind,
                    message: message.clone(),
                };
                Poll::Ready(Err(io::Error::new(kind, message)))
            }
            Poll::Pending if deadline.as_mut().poll(context).is_ready() => {
                let kind = io::ErrorKind::TimedOut;
                let message = "TLS handshake did not complete before the deadline".to_string();
                *self = Self::TlsFailed {
                    kind,
                    message: message.clone(),
                };
                Poll::Ready(Err(io::Error::new(kind, message)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

enum ConnectionAdmission {
    Admitted { _permit: OwnedSemaphorePermit },
    Rejected { _permit: OwnedSemaphorePermit },
}

impl PermitIo {
    fn new(stream: TransportIo, admission: ConnectionAdmission, activity: ConnectedClient) -> Self {
        let rejected = !admission.admitted();
        let start_rejection_deadline_after_handshake = rejected && stream.handshake_pending();
        let rejection_deadline = (rejected && !start_rejection_deadline_after_handshake)
            .then(|| Box::pin(tokio::time::sleep(REJECTION_IDLE_TIMEOUT)));
        Self {
            stream,
            admission,
            _activity: activity,
            rejection_deadline,
            start_rejection_deadline_after_handshake,
        }
    }

    const fn admitted(&self) -> bool {
        self.admission.admitted()
    }

    fn poll_handshake(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.stream.poll_handshake(context) {
            Poll::Ready(Ok(())) => {
                if self.start_rejection_deadline_after_handshake {
                    self.start_rejection_deadline_after_handshake = false;
                    self.rejection_deadline =
                        Some(Box::pin(tokio::time::sleep(REJECTION_IDLE_TIMEOUT)));
                }
                Poll::Ready(Ok(()))
            }
            outcome => outcome,
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct ConnectionActivity {
    state: Arc<Mutex<ConnectionActivityState>>,
}

impl ConnectionActivity {
    fn connect(&self) -> ConnectedClient {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.connected += 1;
        state.generation = state.generation.wrapping_add(1);
        ConnectedClient {
            activity: self.clone(),
        }
    }

    pub(super) fn snapshot(&self) -> (usize, u64) {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        (state.connected, state.generation)
    }
}

#[derive(Default)]
struct ConnectionActivityState {
    connected: usize,
    generation: u64,
}

pub(super) struct ConnectedClient {
    activity: ConnectionActivity,
}

impl Drop for ConnectedClient {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.connected -= 1;
        state.generation = state.generation.wrapping_add(1);
    }
}

impl ConnectionAdmission {
    const fn admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

impl AsyncRead for PermitIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_handshake(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if this
            .rejection_deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "over-capacity connection did not send an HTTP request before the deadline",
            )));
        }
        match &mut this.stream {
            TransportIo::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            TransportIo::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
            TransportIo::TlsHandshake { .. } | TransportIo::TlsFailed { .. } => {
                unreachable!("a completed TLS handshake changes state")
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ConnectionContext {
    peer_address: SocketAddr,
    admitted: bool,
}

impl ConnectionContext {
    pub(super) const fn peer_ip(self) -> IpAddr {
        self.peer_address.ip()
    }
}

impl Connected<IncomingStream<'_, LimitedTcpListener>> for ConnectionContext {
    fn connect_info(stream: IncomingStream<'_, LimitedTcpListener>) -> Self {
        Self {
            peer_address: *stream.remote_addr(),
            admitted: stream.io().admitted(),
        }
    }
}

pub(super) async fn enforce_capacity(
    State(state): State<Arc<DaemonState>>,
    request: Request,
    next: Next,
) -> Response {
    let admitted = request
        .extensions()
        .get::<ConnectInfo<ConnectionContext>>()
        .is_some_and(|connection| connection.0.admitted);
    if admitted {
        return next.run(request).await;
    }

    // Capacity rejection runs before authentication. Echo Host Identity only
    // when a protected request already carries the exact pin, so a legitimate
    // DaemonClient can validate the error without disclosing identity to an
    // unpinned caller or weakening mismatch detection.
    let host_identity = (request.uri().path() != "/v1/live"
        && auth::expected_host_identity_matches(request.headers(), &state.host_identity))
    .then(|| state.host_identity.clone());
    let mut response = api_error_response(
        request_id_or_new(request.headers()),
        host_identity,
        ApiFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: ApiErrorCode::CapacityExceeded,
            category: ApiErrorCategory::Capacity,
            retryable: true,
            message: "the Host Daemon HTTP connection capacity is occupied",
            details: None,
        },
    );
    // The over-capacity connection has no permit. Closing it after the typed
    // response prevents idle keep-alive sockets from bypassing the limit.
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

impl AsyncWrite for PermitIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        match this.poll_handshake(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match &mut this.stream {
            TransportIo::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            TransportIo::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
            TransportIo::TlsHandshake { .. } | TransportIo::TlsFailed { .. } => {
                unreachable!("a completed TLS handshake changes state")
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        match this.poll_handshake(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match &mut this.stream {
            TransportIo::Plain(stream) => Pin::new(stream).poll_flush(context),
            TransportIo::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
            TransportIo::TlsHandshake { .. } | TransportIo::TlsFailed { .. } => {
                unreachable!("a completed TLS handshake changes state")
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        match this.poll_handshake(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match &mut this.stream {
            TransportIo::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            TransportIo::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
            TransportIo::TlsHandshake { .. } | TransportIo::TlsFailed { .. } => {
                unreachable!("a completed TLS handshake changes state")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::DaemonTlsConfig;
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    #[tokio::test]
    async fn idle_rejected_connection_releases_its_bounded_response_lane() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let mut listener = LimitedTcpListener::new(listener, 0);
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let _client = client.expect("open idle over-capacity connection");
        let (mut rejected, _) = accepted;
        let mut byte = [0_u8; 1];

        let error = tokio::time::timeout(
            REJECTION_IDLE_TIMEOUT + Duration::from_secs(1),
            rejected.read(&mut byte),
        )
        .await
        .expect("rejected connection must have a finite pre-request deadline")
        .expect_err("idle rejected connection must time out");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(rejected);

        let (next_client, (next_rejected, _)) =
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(TcpStream::connect(address), listener.accept())
            })
            .await
            .expect("the next connection must acquire the released rejection lane");
        let _next_client = next_client.expect("open next over-capacity connection");
        assert!(!next_rejected.admitted());
    }

    #[tokio::test]
    async fn tls_rejection_timeout_begins_after_the_handshake() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate direct transport certificate");
        let tls = DaemonTlsConfig::from_pem(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
        )
        .expect("build validated TLS configuration");
        let client_config =
            crate::transport_tls::websocket_tls_config(Some(certified.cert.pem().as_bytes()))
                .unwrap_or_else(|_| panic!("build trusted TLS client configuration"));
        let connector = TlsConnector::from(client_config);
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let mut listener = LimitedTcpListener::with_tls(listener, 0, tls.0);
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let client = client.expect("open over-capacity TLS connection");
        let (mut rejected, _) = accepted;
        assert!(!rejected.admitted());

        let server_read = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let count = rejected.read(&mut byte).await?;
            Ok::<_, io::Error>((rejected, byte, count))
        });
        tokio::time::sleep(REJECTION_IDLE_TIMEOUT + Duration::from_millis(100)).await;

        let server_name = ServerName::try_from("localhost").expect("valid test server name");
        let mut client = connector
            .connect(server_name, client)
            .await
            .expect("TLS handshake may use the full handshake deadline");
        client
            .write_all(b"x")
            .await
            .expect("send the first post-handshake request byte");
        let (rejected, byte, count) = tokio::time::timeout(Duration::from_secs(1), server_read)
            .await
            .expect("post-handshake request byte must retain its own deadline")
            .expect("join rejected connection reader")
            .expect("read post-handshake request byte");

        assert_eq!(count, 1);
        assert_eq!(byte, [b'x']);
        drop(rejected);
    }

    #[tokio::test]
    async fn idle_tls_handshake_releases_its_admission_permit() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate direct transport certificate");
        let tls = DaemonTlsConfig::from_pem(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
        )
        .expect("build validated TLS configuration");
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let mut listener = LimitedTcpListener::with_tls(listener, 1, tls.0);
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let _client = client.expect("open idle TLS connection");
        let (mut stalled, _) = accepted;
        let mut byte = [0_u8; 1];

        let error = tokio::time::timeout(Duration::from_secs(6), stalled.read(&mut byte))
            .await
            .expect("an incomplete TLS handshake must have a finite deadline")
            .expect_err("an incomplete TLS handshake must time out");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let repeated_error = stalled
            .write_all(b"x")
            .await
            .expect_err("a timed-out handshake must remain terminal");
        assert_eq!(repeated_error.kind(), io::ErrorKind::TimedOut);
        drop(stalled);

        let (next_client, (next_admitted, _)) =
            tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(TcpStream::connect(address), listener.accept())
            })
            .await
            .expect("the next connection must acquire the released admission permit");
        let _next_client = next_client.expect("open next TLS connection");
        assert!(next_admitted.admitted());
    }

    #[tokio::test]
    async fn malformed_tls_handshake_remains_terminal_for_later_io() {
        let certified = rcgen::generate_simple_self_signed(["localhost".to_string()])
            .expect("generate direct transport certificate");
        let tls = DaemonTlsConfig::from_pem(
            certified.cert.pem().as_bytes(),
            certified.signing_key.serialize_pem().as_bytes(),
        )
        .expect("build validated TLS configuration");
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("read test listener address");
        let mut listener = LimitedTcpListener::with_tls(listener, 1, tls.0);
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client.expect("open malformed TLS connection");
        let (mut server, _) = accepted;
        client
            .write_all(b"not a TLS client hello")
            .await
            .expect("send malformed handshake bytes");

        let mut byte = [0_u8; 1];
        server
            .read(&mut byte)
            .await
            .expect_err("malformed TLS handshake must fail");
        server
            .write_all(b"x")
            .await
            .expect_err("a malformed handshake must remain terminal");
    }
}
