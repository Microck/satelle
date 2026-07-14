use super::{EXPECTED_OPERATIONS, RunningServer};
use reqwest::StatusCode;
use satelle_core::SessionId;
use satelle_host::{ApiBearerToken, ApiScopes};
use satelle_transport::{ApiErrorCode, DaemonClient, DaemonClientError, TurnRequest};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};

/// The SSH-specific bootstrap, authentication, and host-key checks happen
/// before this boundary. This fixture exercises the established tunnel as a
/// real full-duplex TCP stream while keeping the test local and deterministic.
struct EstablishedTunnel {
    address: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl EstablishedTunnel {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind established-tunnel fixture");
        let address = listener
            .local_addr()
            .expect("read established-tunnel address");
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(serve_forwarder(listener, target, receiver));
        Self {
            address,
            shutdown,
            task,
        }
    }

    async fn shutdown(self) -> io::Result<()> {
        // The task can close the receiver after an I/O failure. Signaling is
        // therefore advisory; the task result is the authoritative outcome.
        let _ = self.shutdown.send(());
        self.task.await.map_err(io::Error::other)?
    }
}

async fn serve_forwarder(
    listener: TcpListener,
    target: SocketAddr,
    mut shutdown: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (downstream, _) = accepted?;
                connections.spawn(forward_connection(downstream, target));
            }
            Some(connection) = connections.join_next(), if !connections.is_empty() => {
                connection.map_err(io::Error::other)??;
            }
        }
    }

    // The blocking client is dropped before shutdown, so its pooled sockets
    // have closed and every forwarding task can finish without cancellation.
    while let Some(connection) = connections.join_next().await {
        connection.map_err(io::Error::other)??;
    }
    Ok(())
}

async fn forward_connection(mut downstream: TcpStream, target: SocketAddr) -> io::Result<()> {
    let mut upstream = TcpStream::connect(target).await?;
    copy_bidirectional(&mut downstream, &mut upstream).await?;
    downstream.shutdown().await?;
    upstream.shutdown().await
}

fn assert_api_and_session_conformance(
    endpoint: SocketAddr,
    token: ApiBearerToken,
    host_identity: String,
) {
    let client = DaemonClient::loopback(endpoint, token, &host_identity)
        .expect("construct loopback daemon client");

    assert!(client.live().expect("read liveness").alive());

    let capabilities = client.capabilities().expect("read capabilities");
    assert_eq!(capabilities.host_identity(), host_identity);
    assert_eq!(capabilities.operations(), EXPECTED_OPERATIONS);

    let status = client.host_status().expect("read Host status");
    assert_eq!(status.host_identity(), host_identity);

    let idempotency_key = format!("established-tunnel-conformance-{}", endpoint.port());
    let request = TurnRequest::new("PRIVATE_ESTABLISHED_TUNNEL_CONFORMANCE_CANARY");
    let created = client
        .create_session(&request, &idempotency_key)
        .expect("create durable Session");
    assert_eq!(created.host_identity(), host_identity);
    assert_eq!(created.session().turns().len(), 1);

    let replay = client
        .create_session(&request, &idempotency_key)
        .expect("replay the same Session admission");
    assert_eq!(
        replay.session().session_id(),
        created.session().session_id()
    );
    assert_eq!(replay.session().turns().len(), 1);
    assert_eq!(
        replay.session().turns()[0].turn_id(),
        created.session().turns()[0].turn_id()
    );

    let read = client
        .read_session(created.session().session_id())
        .expect("read the durable Session");
    assert_eq!(read.session().session_id(), created.session().session_id());
    assert_eq!(read.session().turns().len(), 1);
    let status_after_create = client.host_status().expect("read updated Host status");
    assert_eq!(
        status_after_create.session_count(),
        status.session_count() + 1
    );

    let conflict = client
        .create_session(
            &TurnRequest::new("PRIVATE_CHANGED_TUNNEL_CONFORMANCE_CANARY"),
            &idempotency_key,
        )
        .expect_err("changed payload must conflict with the existing admission");
    assert_api_error(
        conflict,
        StatusCode::CONFLICT,
        ApiErrorCode::IdempotencyKeyConflict,
        &host_identity,
    );

    let missing = client
        .read_session(&SessionId::new())
        .expect_err("missing Session must return a typed not-found error");
    assert_api_error(
        missing,
        StatusCode::NOT_FOUND,
        ApiErrorCode::SessionNotFound,
        &host_identity,
    );
}

fn assert_api_error(
    actual: DaemonClientError,
    expected_status: StatusCode,
    expected_code: ApiErrorCode,
    expected_host_identity: &str,
) {
    match actual {
        DaemonClientError::Api { status, error } => {
            assert_eq!(status, expected_status);
            assert_eq!(error.code(), expected_code);
            assert_eq!(error.host_identity(), Some(expected_host_identity));
        }
        other => panic!("expected typed API error, got {other:?}"),
    }
}

fn copy_token(token: &ApiBearerToken) -> ApiBearerToken {
    let exposed = token.expose();
    ApiBearerToken::parse(exposed.as_str()).expect("copy fixture token into the client")
}

#[tokio::test]
async fn direct_and_established_ssh_tunnel_share_api_and_session_contract() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let daemon_address = running.server.local_addr();

    let direct_token = copy_token(&running.token);
    let direct_host_identity = running.host_identity.clone();
    tokio::task::spawn_blocking(move || {
        assert_api_and_session_conformance(daemon_address, direct_token, direct_host_identity);
    })
    .await
    .expect("join direct conformance runner");

    let tunnel = EstablishedTunnel::start(daemon_address).await;
    let tunnel_token = copy_token(&running.token);
    let tunnel_host_identity = running.host_identity.clone();
    let tunnel_address = tunnel.address;
    tokio::task::spawn_blocking(move || {
        assert_api_and_session_conformance(tunnel_address, tunnel_token, tunnel_host_identity);
    })
    .await
    .expect("join established-tunnel conformance runner");

    tunnel
        .shutdown()
        .await
        .expect("stop established-tunnel fixture");
    running.server.shutdown().await.expect("stop daemon server");
}

#[tokio::test]
async fn failed_upstream_is_reported_during_established_tunnel_shutdown() {
    let unavailable_target = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut tunnel = EstablishedTunnel::start(unavailable_target).await;
    let mut downstream = TcpStream::connect(tunnel.address)
        .await
        .expect("connect to established-tunnel fixture");

    let mut response = Vec::new();
    downstream
        .read_to_end(&mut response)
        .await
        .expect("read forwarded connection closure");
    tunnel.shutdown.closed().await;

    let error = tunnel
        .shutdown()
        .await
        .expect_err("failed upstream must remain visible during shutdown");
    assert!(
        error.raw_os_error().is_some(),
        "expected the upstream socket error, got {error:?}"
    );
}
