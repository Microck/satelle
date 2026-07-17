use super::{EXPECTED_OPERATIONS, RunningServer};
use reqwest::StatusCode;
use satelle_core::{
    ApiTokenSource, DirectHostBinding, EventStateSubject, EventType, SatelleConfig, SessionId,
    TransportKind, TurnId,
};
use satelle_host::{ApiBearerToken, ApiScopes};
use satelle_transport::{
    ApiErrorCode, DaemonClient, DaemonClientError, DaemonEventClient, DaemonEventError,
    EventSubscription, TurnRequest,
};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

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

/// Terminates the direct transport's real TLS connection before forwarding
/// the decrypted HTTP or WebSocket stream to the loopback daemon fixture.
struct TlsForwarder {
    address: SocketAddr,
    ca_bundle: String,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl TlsForwarder {
    async fn start(target: SocketAddr) -> Self {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![Ipv4Addr::LOCALHOST.to_string()])
                .expect("generate direct transport certificate");
        let ca_bundle = cert.pem();
        let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], private_key.into())
            .expect("configure direct TLS fixture");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind direct TLS fixture");
        let address = listener.local_addr().expect("read direct TLS address");
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(serve_tls_forwarder(listener, target, acceptor, receiver));
        Self {
            address,
            ca_bundle,
            shutdown,
            task,
        }
    }

    fn ca_bundle(&self) -> &[u8] {
        self.ca_bundle.as_bytes()
    }

    async fn shutdown(self) -> io::Result<()> {
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

async fn serve_tls_forwarder(
    listener: TcpListener,
    target: SocketAddr,
    acceptor: TlsAcceptor,
    mut shutdown: oneshot::Receiver<()>,
) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (downstream, _) = accepted?;
                connections.spawn(forward_tls_connection(
                    downstream,
                    target,
                    acceptor.clone(),
                ));
            }
            Some(connection) = connections.join_next(), if !connections.is_empty() => {
                connection.map_err(io::Error::other)??;
            }
        }
    }

    while let Some(connection) = connections.join_next().await {
        connection.map_err(io::Error::other)??;
    }
    Ok(())
}

async fn forward_tls_connection(
    downstream: TcpStream,
    target: SocketAddr,
    acceptor: TlsAcceptor,
) -> io::Result<()> {
    let mut downstream = acceptor.accept(downstream).await?;
    let mut upstream = TcpStream::connect(target).await?;
    match copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok(_) => {}
        // The public clients own no explicit TLS close operation. Dropping a
        // completed HTTP pool or event stream therefore closes the socket
        // without a close_notify alert, which rustls reports as EOF.
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error),
    }
    downstream.shutdown().await?;
    upstream.shutdown().await
}

fn assert_api_and_session_conformance(
    client: DaemonClient,
    host_identity: &str,
    idempotency_key: &str,
) -> (SessionId, TurnId) {
    assert!(client.live().expect("read liveness").alive());

    let capabilities = client.capabilities().expect("read capabilities");
    assert_eq!(capabilities.host_identity(), host_identity);
    assert_eq!(capabilities.operations(), EXPECTED_OPERATIONS);

    let status = client.host_status().expect("read Host status");
    assert_eq!(status.host_identity(), host_identity);

    let request = TurnRequest::new("PRIVATE_ESTABLISHED_TUNNEL_CONFORMANCE_CANARY");
    let created = client
        .create_session(&request, idempotency_key)
        .expect("create durable Session");
    assert_eq!(created.host_identity(), host_identity);
    assert_eq!(created.session().turns().len(), 1);

    let replay = client
        .create_session(&request, idempotency_key)
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
            idempotency_key,
        )
        .expect_err("changed payload must conflict with the existing admission");
    assert_api_error(
        conflict,
        StatusCode::CONFLICT,
        ApiErrorCode::IdempotencyKeyConflict,
        host_identity,
    );

    let missing = client
        .read_session(&SessionId::new())
        .expect_err("missing Session must return a typed not-found error");
    assert_api_error(
        missing,
        StatusCode::NOT_FOUND,
        ApiErrorCode::SessionNotFound,
        host_identity,
    );

    (
        created.session().session_id().clone(),
        created.session().turns()[0].turn_id().clone(),
    )
}

async fn assert_transport_conformance(
    client: DaemonClient,
    event_client: DaemonEventClient,
    host_identity: String,
    idempotency_key: &'static str,
) {
    let mut event_stream = event_client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("subscribe to Host events before Session admission");
    let asserted_host_identity = host_identity.clone();
    let (session_id, turn_id) = tokio::task::spawn_blocking(move || {
        assert_api_and_session_conformance(client, &asserted_host_identity, idempotency_key)
    })
    .await
    .expect("join blocking API conformance runner");

    let mut events = Vec::with_capacity(4);
    for _ in 0..4 {
        events.push(
            event_stream
                .next_event()
                .await
                .expect("read conformance event"),
        );
    }
    assert_eq!(
        events
            .iter()
            .map(|event| event.event_type())
            .collect::<Vec<_>>(),
        [
            EventType::TurnStarted,
            EventType::ProviderSmoke,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert_eq!(
        events.iter().map(|event| event.seq()).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert!(events.iter().all(|event| {
        event.session_id() == Some(&session_id)
            && event.turn_id() == Some(&turn_id)
            && matches!(event.state_subject(), Some(EventStateSubject::Turn { .. }))
    }));

    drop(event_stream);
    drop(event_client);
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
async fn direct_and_established_ssh_tunnel_share_session_error_and_event_contracts() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let daemon_address = running.server.local_addr();

    let direct = TlsForwarder::start(daemon_address).await;
    let binding = direct_binding(direct.address, &running.host_identity);
    let direct_api_binding = binding.clone();
    let direct_api_token = copy_token(&running.token);
    let direct_ca_bundle = direct.ca_bundle().to_vec();
    let direct_client = tokio::task::spawn_blocking(move || {
        DaemonClient::https(
            &direct_api_binding,
            direct_api_token,
            Some(&direct_ca_bundle),
        )
        .expect("construct direct HTTPS client")
    })
    .await
    .expect("join direct HTTPS client construction");
    let direct_event_client = DaemonEventClient::wss(
        &binding,
        copy_token(&running.token),
        Some(direct.ca_bundle()),
    )
    .expect("construct direct WSS client");
    assert_transport_conformance(
        direct_client,
        direct_event_client,
        running.host_identity.clone(),
        "direct-transport-conformance",
    )
    .await;
    direct.shutdown().await.expect("stop direct TLS fixture");

    let tunnel = EstablishedTunnel::start(daemon_address).await;
    let tunnel_address = tunnel.address;
    let tunnel_api_token = copy_token(&running.token);
    let tunnel_api_identity = running.host_identity.clone();
    let tunnel_client = tokio::task::spawn_blocking(move || {
        DaemonClient::loopback(tunnel_address, tunnel_api_token, tunnel_api_identity)
            .expect("construct established-tunnel HTTP client")
    })
    .await
    .expect("join established-tunnel HTTP client construction");
    let tunnel_event_client = DaemonEventClient::loopback(
        tunnel.address,
        copy_token(&running.token),
        &running.host_identity,
    )
    .expect("construct established-tunnel event client");
    assert_transport_conformance(
        tunnel_client,
        tunnel_event_client,
        running.host_identity.clone(),
        "established-tunnel-conformance",
    )
    .await;

    tunnel
        .shutdown()
        .await
        .expect("stop established-tunnel fixture");
    running.server.shutdown().await.expect("stop daemon server");
}

#[tokio::test]
async fn established_ssh_tunnel_requires_api_authentication_for_http_and_websocket() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let tunnel = EstablishedTunnel::start(running.server.local_addr()).await;
    let unregistered_token =
        ApiBearerToken::generate().expect("generate valid unregistered API token");

    let tunnel_address = tunnel.address;
    let expected_host_identity = running.host_identity.clone();
    let api_token = copy_token(&unregistered_token);
    let api_error = tokio::task::spawn_blocking(move || {
        let client = DaemonClient::loopback(tunnel_address, api_token, expected_host_identity)
            .expect("construct established-tunnel HTTP client");
        client
            .host_status()
            .expect_err("an unregistered credential must not read Host status")
    })
    .await
    .expect("join established-tunnel authentication request");
    assert!(matches!(
        api_error,
        DaemonClientError::Api { status, error }
            if status == StatusCode::UNAUTHORIZED
                && error.code() == ApiErrorCode::AuthenticationFailed
                && error.host_identity().is_none()
    ));

    let event_client =
        DaemonEventClient::loopback(tunnel.address, unregistered_token, &running.host_identity)
            .expect("construct established-tunnel event client");
    let event_error = match event_client
        .connect_events(vec![EventSubscription::Host])
        .await
    {
        Ok(_) => panic!("an unregistered credential must not complete the event handshake"),
        Err(error) => error,
    };
    assert!(matches!(
        event_error,
        DaemonEventError::Handshake { status, error }
            if status == StatusCode::UNAUTHORIZED.as_u16()
                && error.code() == ApiErrorCode::AuthenticationFailed
                && error.host_identity().is_none()
    ));

    drop(event_client);
    tunnel
        .shutdown()
        .await
        .expect("stop established-tunnel fixture");
    running.server.shutdown().await.expect("stop daemon server");
}

fn direct_binding(address: SocketAddr, expected_host_identity: &str) -> DirectHostBinding {
    let mut config = SatelleConfig::defaults()
        .hosts
        .remove("local-demo")
        .expect("default local Host config");
    config.transport = TransportKind::Direct;
    config.address = Some(format!("https://127.0.0.1:{}", address.port()));
    config.expected_host_id = Some(expected_host_identity.to_string());
    config.api_token = Some(ApiTokenSource::File {
        path: std::env::temp_dir().join("satelle-conformance.token"),
    });
    DirectHostBinding::from_host_config(&config).expect("construct direct Host Binding")
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
