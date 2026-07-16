use super::*;
use satelle_core::session::PublicSession;
use satelle_transport::{DaemonEventStream, EventSubscription, WsCloseReason};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

impl DirectFixture {
    fn connect_host_stream(&self) -> DaemonEventStream {
        self.transport()
            .event_runtime
            .block_on(
                self.transport()
                    .event_client
                    .connect_events(vec![EventSubscription::Host]),
            )
            .expect("connect Host event stream")
    }

    fn shutdown_server(&mut self) {
        let server = self.server.take().expect("daemon server is running");
        self.server_runtime
            .block_on(server.shutdown())
            .expect("shut down loopback daemon");
    }

    fn restart_server(&mut self) {
        self.restart_server_with_config(DaemonServerConfig::loopback(self.address));
    }

    fn restart_server_with_connection_limit(&mut self, max_connections: usize) {
        self.restart_server_with_config(
            DaemonServerConfig::loopback(self.address).with_max_connections(max_connections),
        );
    }

    fn restart_server_with_config(&mut self, config: DaemonServerConfig) {
        assert!(self.server.is_none(), "daemon server must be stopped");
        let server = self
            .server_runtime
            .block_on(DaemonServer::bind(self.service.clone(), config))
            .expect("restart loopback daemon on the same address");
        assert_eq!(server.local_addr(), self.address);
        self.server = Some(server);
    }

    fn replace_http_client(&mut self, address: SocketAddr, principal: &str) {
        let (http_token, _event_token) = register_client_tokens(&self.service, principal);
        let client = DaemonClient::loopback(address, http_token, &self.host_identity)
            .expect("construct replacement HTTP client");
        self.transport
            .as_mut()
            .expect("fixture transport is present")
            .client = Arc::new(client);
    }

    fn replace_event_client(&mut self, address: SocketAddr, principal: &str) {
        let (_http_token, event_token) = register_client_tokens(&self.service, principal);
        let event_client = DaemonEventClient::loopback(address, event_token, &self.host_identity)
            .expect("construct replacement event client");
        self.transport
            .as_mut()
            .expect("fixture transport is present")
            .event_client = event_client;
    }

    fn complete_while_server_is_down(&self, prompt: &str) -> PublicSession {
        let request = TurnRequest::new(prompt);
        let intent = satelle_host::TurnIntent::new(request.prompt(), request.execution_mode())
            .expect("construct local Turn intent");
        self.service
            .run(satelle_core::LOCAL_DEMO_HOST, &intent)
            .expect("admit and complete the target through the cloned Host service")
            .session
    }
}

struct DropFirstHttpConnection {
    address: SocketAddr,
    serving: Receiver<()>,
    shutdown: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl DropFirstHttpConnection {
    fn start(service: HostService) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind transient HTTP listener");
        listener
            .set_nonblocking(true)
            .expect("make transient HTTP listener nonblocking");
        let address = listener.local_addr().expect("read transient HTTP address");
        let (serving_sender, serving) = mpsc::channel();
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            // Keep the first real client connection open while replacing this listener. Closing
            // it only after the real daemon binds makes the resulting retry deterministic: the
            // client cannot observe a connection-refused gap between the two listeners.
            let first_connection = loop {
                match listener.accept() {
                    Ok((connection, _)) => break connection,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        match shutdown_receiver.try_recv() {
                            Ok(()) | Err(TryRecvError::Disconnected) => return,
                            Err(TryRecvError::Empty) => thread::sleep(Duration::from_millis(5)),
                        }
                    }
                    Err(error) => panic!("accept transient HTTP connection: {error}"),
                }
            };
            drop(listener);

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("construct transient HTTP runtime");
            runtime.block_on(async move {
                let server = DaemonServer::bind(service, DaemonServerConfig::loopback(address))
                    .await
                    .expect("start real HTTP daemon after transient failure");
                drop(first_connection);
                serving_sender
                    .send(())
                    .expect("report transient HTTP daemon readiness");
                tokio::task::spawn_blocking(move || shutdown_receiver.recv())
                    .await
                    .expect("join transient HTTP shutdown waiter")
                    .expect("receive transient HTTP shutdown");
                server
                    .shutdown()
                    .await
                    .expect("shut down transient HTTP daemon");
            });
        });
        Self {
            address,
            serving,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn wait_until_serving(&self) {
        self.serving
            .recv_timeout(Duration::from_secs(2))
            .expect("transient HTTP daemon started after dropping one connection");
    }

    fn stop(mut self) {
        self.stop_inner()
            .expect("join transient HTTP daemon thread");
    }

    fn stop_inner(&mut self) -> thread::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let _ = self.shutdown.send(());
        thread.join()
    }
}

impl Drop for DropFirstHttpConnection {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

struct DropSubscribedStreams {
    address: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    shutdown: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl DropSubscribedStreams {
    fn start(backend: SocketAddr) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind subscribed-stream proxy");
        listener
            .set_nonblocking(true)
            .expect("make subscribed-stream proxy nonblocking");
        let address = listener
            .local_addr()
            .expect("read subscribed-stream proxy address");
        let handshakes = Arc::new(AtomicUsize::new(0));
        let observed_handshakes = Arc::clone(&handshakes);
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((client, _)) => {
                        proxy_one_subscribed_stream(client, backend);
                        observed_handshakes.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        match shutdown_receiver.try_recv() {
                            Ok(()) | Err(TryRecvError::Disconnected) => return,
                            Err(TryRecvError::Empty) => thread::sleep(Duration::from_millis(2)),
                        }
                    }
                    Err(error) => panic!("accept subscribed-stream proxy connection: {error}"),
                }
            }
        });
        Self {
            address,
            handshakes,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn handshake_count(&self) -> usize {
        self.handshakes.load(Ordering::SeqCst)
    }

    fn stop(mut self) {
        self.stop_inner().expect("join subscribed-stream proxy");
    }

    fn stop_inner(&mut self) -> thread::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let _ = self.shutdown.send(());
        thread.join()
    }
}

impl Drop for DropSubscribedStreams {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

struct ActiveReconciliationServer {
    address: SocketAddr,
    shutdown: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl ActiveReconciliationServer {
    fn start(
        host_identity: String,
        session_response: serde_json::Value,
        logs_response: serde_json::Value,
    ) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind active reconciliation fixture");
        listener
            .set_nonblocking(true)
            .expect("make active reconciliation fixture nonblocking");
        let address = listener
            .local_addr()
            .expect("read active reconciliation fixture address");
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((connection, _)) => serve_reconciliation_response(
                        connection,
                        &host_identity,
                        &session_response,
                        &logs_response,
                    ),
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        match shutdown_receiver.try_recv() {
                            Ok(()) | Err(TryRecvError::Disconnected) => return,
                            Err(TryRecvError::Empty) => thread::sleep(Duration::from_millis(2)),
                        }
                    }
                    Err(error) => panic!("accept active reconciliation connection: {error}"),
                }
            }
        });
        Self {
            address,
            shutdown,
            thread: Some(thread),
        }
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn stop(mut self) {
        self.stop_inner()
            .expect("join active reconciliation fixture");
    }

    fn stop_inner(&mut self) -> thread::Result<()> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let _ = self.shutdown.send(());
        thread.join()
    }
}

impl Drop for ActiveReconciliationServer {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

fn proxy_one_subscribed_stream(mut client: TcpStream, backend: SocketAddr) {
    client
        .set_nonblocking(false)
        .expect("make accepted proxy client blocking");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound proxy client reads");
    let mut server = TcpStream::connect(backend).expect("connect proxy to real daemon");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound proxy server reads");

    let request = read_http_headers(&mut client);
    server.write_all(&request).expect("forward WSS upgrade");
    let response = read_http_headers(&mut server);
    assert!(
        response.starts_with(b"HTTP/1.1 101"),
        "real daemon must accept the WSS upgrade"
    );
    client
        .write_all(&response)
        .expect("forward WSS upgrade response");

    let subscribe = read_websocket_frame(&mut client);
    server
        .write_all(&subscribe)
        .expect("forward WSS subscribe frame");
    let subscribed = read_websocket_frame(&mut server);
    client
        .write_all(&subscribed)
        .expect("forward WSS subscribed frame");
    write_websocket_close(&mut client, WsCloseReason::ServerShutdown);
    client
        .flush()
        .expect("flush WSS subscription and close frames");
    let _ = client.shutdown(Shutdown::Both);
    let _ = server.shutdown(Shutdown::Both);
}

fn write_websocket_close(stream: &mut TcpStream, reason: WsCloseReason) {
    let close_code = reason.close_code();
    let reason_text = reason.as_str().as_bytes();
    let payload_length = reason_text.len() + size_of::<u16>();
    assert!(payload_length <= 125, "WebSocket close payload is bounded");
    stream
        .write_all(&[0x88, payload_length as u8])
        .expect("write WebSocket close header");
    stream
        .write_all(&close_code.to_be_bytes())
        .expect("write WebSocket close code");
    stream
        .write_all(reason_text)
        .expect("write WebSocket close reason");
}

fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(2))
        .expect("HTTP fixture read deadline is representable");
    let original_read_timeout = stream
        .read_timeout()
        .expect("read HTTP fixture socket timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "HTTP fixture timed out before completing headers"
        );
        stream
            .set_read_timeout(Some(remaining))
            .expect("bound HTTP fixture header read");
        match stream.read(&mut buffer) {
            Ok(0) => panic!("HTTP peer closed before completing headers"),
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                assert!(bytes.len() <= 16 * 1024, "HTTP fixture headers are bounded");
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                assert!(
                    Instant::now() < deadline,
                    "HTTP fixture timed out before completing headers"
                );
                thread::yield_now();
            }
            Err(error) => panic!("read HTTP headers: {error}"),
        }
    }
    stream
        .set_read_timeout(original_read_timeout)
        .expect("restore HTTP fixture socket timeout");
    bytes
}

fn read_websocket_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut frame = vec![0_u8; 2];
    stream
        .read_exact(&mut frame)
        .expect("read WebSocket frame header");
    let masked = frame[1] & 0x80 != 0;
    let mut payload_length = u64::from(frame[1] & 0x7f);
    if payload_length == 126 {
        let mut extended = [0_u8; 2];
        stream
            .read_exact(&mut extended)
            .expect("read 16-bit WebSocket length");
        frame.extend_from_slice(&extended);
        payload_length = u64::from(u16::from_be_bytes(extended));
    } else if payload_length == 127 {
        let mut extended = [0_u8; 8];
        stream
            .read_exact(&mut extended)
            .expect("read 64-bit WebSocket length");
        frame.extend_from_slice(&extended);
        payload_length = u64::from_be_bytes(extended);
    }
    if masked {
        let mut mask = [0_u8; 4];
        stream.read_exact(&mut mask).expect("read WebSocket mask");
        frame.extend_from_slice(&mask);
    }
    let payload_length = usize::try_from(payload_length).expect("WebSocket frame fits in memory");
    assert!(
        payload_length <= 64 * 1024,
        "WebSocket fixture frame is bounded"
    );
    let payload_start = frame.len();
    frame.resize(payload_start + payload_length, 0);
    stream
        .read_exact(&mut frame[payload_start..])
        .expect("read WebSocket payload");
    frame
}

fn serve_reconciliation_response(
    mut connection: TcpStream,
    host_identity: &str,
    session_response: &serde_json::Value,
    logs_response: &serde_json::Value,
) {
    connection
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound reconciliation request reads");
    let request = read_http_headers(&mut connection);
    let request = String::from_utf8(request).expect("HTTP request headers are UTF-8");
    let request_line = request.lines().next().expect("HTTP request line");
    let is_logs = request_line.starts_with("GET /v1/logs?");
    let request_id = request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("satelle-request-id"))
        .map(|(_, value)| value.trim())
        .expect("daemon client sends request ID");
    let mut response = if is_logs {
        logs_response.clone()
    } else {
        session_response.clone()
    };
    response["request_id"] = serde_json::Value::String(request_id.to_string());
    let body = serde_json::to_vec(&response).expect("encode reconciliation response");
    write!(
        connection,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nsatelle-request-id: {}\r\nsatelle-host-identity: {}\r\nconnection: close\r\n\r\n",
        body.len(),
        request_id,
        host_identity,
    )
    .expect("write reconciliation response headers");
    connection
        .write_all(&body)
        .expect("write reconciliation response body");
}

#[test]
fn server_restart_reconciles_the_exact_attached_turn_once() {
    let mut fixture = DirectFixture::start();
    let stream = fixture.connect_host_stream();
    fixture.shutdown_server();

    // Commit the target while its original live stream is down. Restarting the same daemon state
    // must recover through authoritative status and logs rather than inventing a second Turn.
    let admitted = fixture.complete_while_server_is_down("complete while offline");
    let expected_session_id = admitted.session_id().clone();
    let expected_turn_id = admitted
        .turns()
        .last()
        .expect("admitted Session contains the target Turn")
        .turn_id()
        .clone();

    fixture.restart_server();
    let mut events = Vec::new();
    let outcome = fixture
        .transport()
        .event_runtime
        .block_on(
            fixture
                .transport()
                .follow_turn(stream, admitted, &mut |event| {
                    events.push(event);
                    Ok(())
                }),
        )
        .expect("reconnect and reconcile the attached Turn");

    assert_eq!(outcome.session.session_id(), &expected_session_id);
    assert_eq!(outcome.turn_id, expected_turn_id);
    assert_eq!(events.len(), 1, "reconciliation emits one terminal event");
    let terminal = &events[0];
    assert_eq!(terminal.event_type(), EventType::TurnCompleted);
    assert_eq!(terminal.source(), EventSource::Cli);
    assert_eq!(terminal.session_id(), Some(&expected_session_id));
    assert_eq!(terminal.turn_id(), Some(&outcome.turn_id));
    assert_eq!(terminal.data()["reconciled"], true);
}

#[test]
fn transient_http_reconciliation_failure_retains_the_reconnected_stream() {
    let mut fixture = DirectFixture::start();
    let stream = fixture.connect_host_stream();
    fixture.shutdown_server();
    let admitted = fixture.complete_while_server_is_down("retain replacement stream");
    let expected_session_id = admitted.session_id().clone();
    let expected_turn_id = admitted
        .turns()
        .last()
        .expect("admitted Session contains the target Turn")
        .turn_id()
        .clone();

    // One connection admits the replacement WSS but rejects any buggy attempt to reacquire it.
    // HTTP uses a separate real loopback daemon that drops only its first TCP connection.
    fixture.restart_server_with_connection_limit(1);
    let transient_http = DropFirstHttpConnection::start(fixture.service.clone());
    fixture.replace_http_client(
        transient_http.address(),
        "principal-cli-transient-http-test",
    );

    let mut events = Vec::new();
    let outcome = fixture
        .transport()
        .event_runtime
        .block_on(
            fixture
                .transport()
                .follow_turn(stream, admitted, &mut |event| {
                    events.push(event);
                    Ok(())
                }),
        )
        .expect("retry HTTP reconciliation while retaining replacement WSS");
    transient_http.wait_until_serving();
    transient_http.stop();

    assert_eq!(outcome.session.session_id(), &expected_session_id);
    assert_eq!(outcome.turn_id, expected_turn_id);
    assert_eq!(events.len(), 1, "the terminal event must not be lost");
    assert_eq!(events[0].event_type(), EventType::TurnCompleted);
    assert_eq!(events[0].session_id(), Some(&expected_session_id));
    assert_eq!(events[0].turn_id(), Some(&outcome.turn_id));
    assert_eq!(events[0].data()["reconciled"], true);
}

#[test]
fn subscribed_replacements_that_close_before_events_exhaust_the_reconnect_budget() {
    let mut fixture = DirectFixture::start();
    let intent = satelle_host::TurnIntent::new(
        "build active reconciliation fixture",
        satelle_core::session::TurnExecutionMode::Standard,
    )
    .expect("construct local Turn intent");
    let terminal = fixture
        .service
        .run(satelle_core::LOCAL_DEMO_HOST, &intent)
        .expect("create a real durable Session fixture")
        .session;
    let target = terminal
        .turns()
        .last()
        .expect("the fixture Session contains its Turn");
    let turn_id = target.turn_id().clone();
    let turn_state_revision = target.turn_state_revision();

    let mut active_value = serde_json::to_value(&terminal).expect("encode public Session fixture");
    active_value["activity"] = serde_json::json!({
        "state": "running",
        "turn_id": turn_id,
        "turn_state_revision": turn_state_revision,
    });
    let target_index = active_value["turns"]
        .as_array()
        .expect("public Session Turns are an array")
        .len()
        - 1;
    active_value["turns"][target_index]["state"] = serde_json::json!("running");
    active_value["turns"][target_index]["terminal_at"] = serde_json::Value::Null;
    active_value["turns"][target_index]["safe_summary"] = serde_json::Value::Null;
    let active: PublicSession =
        serde_json::from_value(active_value.clone()).expect("decode active public Session fixture");

    let real_session_response = fixture
        .transport()
        .client
        .read_session(terminal.session_id())
        .expect("read real Session response template");
    let query = satelle_host::LogPageQuery::tail(10_000)
        .expect("construct logs query")
        .with_session(terminal.session_id().clone());
    let real_logs_response = fixture
        .transport()
        .client
        .logs(&query)
        .expect("read real logs response template");
    let mut session_response =
        serde_json::to_value(real_session_response).expect("encode Session response template");
    for (key, value) in active_value
        .as_object()
        .expect("public Session is an object")
    {
        session_response[key] = value.clone();
    }
    let logs_response =
        serde_json::to_value(real_logs_response).expect("encode logs response template");

    let reconciliation = ActiveReconciliationServer::start(
        fixture.host_identity.clone(),
        session_response,
        logs_response,
    );
    let dropping_streams = DropSubscribedStreams::start(fixture.address);
    fixture.replace_http_client(
        reconciliation.address(),
        "principal-cli-active-reconciliation-test",
    );
    fixture.replace_event_client(
        dropping_streams.address(),
        "principal-cli-drop-subscribed-stream-test",
    );
    let stream = fixture.connect_host_stream();

    let mut events = Vec::new();
    let result = fixture.transport().event_runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(5),
            fixture
                .transport()
                .follow_turn(stream, active, &mut |event| {
                    events.push(event);
                    Ok(())
                }),
        )
        .await
        .expect("reconnect exhaustion must remain bounded")
    });
    let error = match result {
        Ok(_) => panic!("event-free replacement streams must exhaust the budget"),
        Err(error) => error,
    };

    assert_eq!(error.code, ErrorCode::HostUnreachable);
    assert!(events.is_empty(), "no authoritative terminal event exists");
    assert_eq!(
        dropping_streams.handshake_count(),
        direct_attached::MAX_EVENT_RECONNECTS + 1,
        "the original subscribed stream plus exactly the bounded replacements succeed"
    );
    dropping_streams.stop();
    reconciliation.stop();
}

#[test]
fn server_loss_exhaustion_emits_nothing_and_returns_host_unreachable() {
    let mut fixture = DirectFixture::start();
    let stream = fixture.connect_host_stream();
    fixture.shutdown_server();
    let admitted = fixture.complete_while_server_is_down("remain offline");

    let mut events = Vec::new();
    let result = fixture
        .transport()
        .event_runtime
        .block_on(
            fixture
                .transport()
                .follow_turn(stream, admitted, &mut |event| {
                    events.push(event);
                    Ok(())
                }),
        );
    let error = match result {
        Ok(_) => panic!("reconnect exhaustion must fail conservatively"),
        Err(error) => error,
    };

    assert_eq!(error.code, ErrorCode::HostUnreachable);
    assert!(events.is_empty(), "no terminal state was reconciled");
}
