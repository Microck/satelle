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

const REJECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) struct LimitedTcpListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
    rejection_permits: Arc<Semaphore>,
    activity: ConnectionActivity,
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
        }
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
    stream: TcpStream,
    admission: ConnectionAdmission,
    _activity: ConnectedClient,
    rejection_deadline: Option<Pin<Box<Sleep>>>,
}

enum ConnectionAdmission {
    Admitted { _permit: OwnedSemaphorePermit },
    Rejected { _permit: OwnedSemaphorePermit },
}

impl PermitIo {
    fn new(stream: TcpStream, admission: ConnectionAdmission, activity: ConnectedClient) -> Self {
        let rejection_deadline =
            (!admission.admitted()).then(|| Box::pin(tokio::time::sleep(REJECTION_IDLE_TIMEOUT)));
        Self {
            stream,
            admission,
            _activity: activity,
            rejection_deadline,
        }
    }

    const fn admitted(&self) -> bool {
        self.admission.admitted()
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
        Pin::new(&mut this.stream).poll_read(context, buffer)
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
        Pin::new(&mut self.get_mut().stream).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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
}
