use super::*;
use satelle_core::{
    ApiTokenSource, DirectHostBinding, DirectHostBindingError, HostConfig, SatelleConfig,
    TransportKind,
};
use satelle_host::ApiBearerToken;
use std::net::TcpListener;
use std::sync::Arc;

#[test]
fn subscription_acknowledgement_must_echo_the_exact_context() {
    let request_id = RequestId::new();
    let subscriptions = vec![EventSubscription::Host];
    let acknowledgement = SubscribedResponse::new(
        request_id.clone(),
        "host-expected".to_string(),
        subscriptions.clone(),
    );
    assert!(
        validate_acknowledgement(
            acknowledgement,
            &request_id,
            "host-expected",
            &subscriptions
        )
        .is_ok()
    );

    let wrong_request = SubscribedResponse::new(
        RequestId::new(),
        "host-expected".to_string(),
        subscriptions.clone(),
    );
    assert!(matches!(
        validate_acknowledgement(wrong_request, &request_id, "host-expected", &subscriptions),
        Err(DaemonEventError::RequestIdMismatch)
    ));

    let wrong_host = SubscribedResponse::new(
        request_id.clone(),
        "host-other".to_string(),
        subscriptions.clone(),
    );
    assert!(matches!(
        validate_acknowledgement(wrong_host, &request_id, "host-expected", &subscriptions),
        Err(DaemonEventError::HostIdentityMismatch)
    ));

    let wrong_subscriptions = SubscribedResponse::new(
        request_id.clone(),
        "host-expected".to_string(),
        vec![EventSubscription::Session {
            session_id: satelle_core::SessionId::new(),
        }],
    );
    assert!(matches!(
        validate_acknowledgement(
            wrong_subscriptions,
            &request_id,
            "host-expected",
            &subscriptions
        ),
        Err(DaemonEventError::SubscriptionMismatch)
    ));
}

#[test]
fn request_id_mismatch_diagnostic_covers_every_protocol_phase() {
    assert_eq!(
        "the live event protocol response did not match the request ID",
        DaemonEventError::RequestIdMismatch.to_string()
    );
}

#[test]
fn direct_event_client_rejects_invalid_ca_bundles() {
    let binding = direct_binding("https://localhost:8443").expect("construct direct Host Binding");

    assert!(matches!(
        DaemonEventClient::wss(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            Some(b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n"),
        ),
        Err(DaemonEventError::InvalidCaBundle)
    ));
    assert!(matches!(
        DaemonEventClient::wss(
            &binding,
            ApiBearerToken::generate().expect("generate token"),
            Some(b""),
        ),
        Err(DaemonEventError::EmptyCaBundle)
    ));
}

#[tokio::test]
async fn direct_event_client_completes_a_pinned_authenticated_wss_handshake() {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate test certificate");
    let token = ApiBearerToken::generate().expect("generate token");
    let expected_authorization = format!("Bearer {}", token.expose().as_str());
    let (address, server) = spawn_wss_server(
        vec![cert.der().clone()],
        signing_key,
        expected_authorization,
    );
    let binding = direct_binding(&format!("https://localhost:{}", address.port()))
        .expect("construct trusted direct Host Binding");
    let client = DaemonEventClient::wss(&binding, token, Some(cert.pem().as_bytes()))
        .expect("construct WSS event client");

    let stream = client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("complete authenticated WSS subscription");
    drop(stream);
    server.join().expect("join WSS server");
}

#[tokio::test]
async fn direct_event_client_bounds_the_entire_handshake_with_a_silent_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent WSS peer");
    let address = listener.local_addr().expect("read silent peer address");
    let (accepted, await_acceptance) = tokio::sync::oneshot::channel();
    let (release_server, await_release) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept WSS client");
        accepted.send(()).expect("report accepted WSS client");
        await_release.await.expect("await client timeout");
    });
    // A numeric loopback address and explicit acceptance prove the deadline is exercised during
    // the TLS handshake. They also prevent a fast DNS timeout from leaving a blocking accept
    // thread behind on Windows.
    let binding = direct_binding(&format!("https://127.0.0.1:{}", address.port()))
        .expect("construct silent direct Host Binding");
    let client = DaemonEventClient::wss(
        &binding,
        ApiBearerToken::generate().expect("generate token"),
        None,
    )
    .expect("construct bounded WSS event client");

    let mut connection = tokio::spawn(async move {
        client
            .connect_events_with_timeout(vec![EventSubscription::Host], Duration::from_millis(200))
            .await
    });
    let acceptance = tokio::select! {
        biased;
        connection_result = &mut connection => {
            server.abort();
            let _ = server.await;
            match connection_result {
                Ok(Err(DaemonEventError::HandshakeTimeout)) => {
                    panic!("the handshake deadline expired before peer acceptance");
                }
                Ok(_) => panic!("the connection ended before peer acceptance"),
                Err(_) => panic!("the connection task ended before peer acceptance"),
            }
        }
        acceptance = tokio::time::timeout(Duration::from_secs(5), await_acceptance) => acceptance,
    };
    if !matches!(acceptance, Ok(Ok(()))) {
        connection.abort();
        server.abort();
        let _ = connection.await;
        let _ = server.await;
        panic!("the client did not reach the silent TLS peer");
    }
    let connection_result =
        match tokio::time::timeout(Duration::from_secs(5), &mut connection).await {
            Ok(result) => result.expect("join bounded WSS connection"),
            Err(_) => {
                connection.abort();
                let _ = connection.await;
                let _ = release_server.send(());
                let _ = server.await;
                panic!("a silent peer stalled beyond the outer test watchdog");
            }
        };
    release_server.send(()).expect("release silent WSS peer");
    server.await.expect("join silent WSS peer");
    let error = match connection_result {
        Err(error) => error,
        Ok(_) => panic!("a silent peer must not complete the handshake"),
    };

    assert!(matches!(&error, DaemonEventError::HandshakeTimeout));
    assert!(error.is_recoverable_disconnect());
}

#[tokio::test]
async fn post_handshake_silence_is_a_recoverable_stream_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent event peer");
    let address = listener.local_addr().expect("read silent peer address");
    let (release_server, await_release) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept event client");
        let mut socket =
            tokio_tungstenite::tungstenite::accept(stream).expect("accept WebSocket handshake");
        let message = socket.read().expect("read subscription");
        let subscribe: SubscribeRequest = serde_json::from_str(
            message
                .to_text()
                .expect("subscription should be a text message"),
        )
        .expect("decode subscription");
        let acknowledgement = SubscribedResponse::new(
            subscribe.request_id().clone(),
            "host-loopback".to_string(),
            subscribe.subscriptions().to_vec(),
        );
        socket
            .send(Message::Text(
                serde_json::to_string(&acknowledgement)
                    .expect("encode acknowledgement")
                    .into(),
            ))
            .expect("send subscription acknowledgement");

        // Keep the admitted stream open and silent until the client observes
        // its own deadline. A channel avoids a timing-dependent server sleep.
        await_release.recv().expect("await client timeout");
    });
    let client = DaemonEventClient::loopback(
        address,
        ApiBearerToken::generate().expect("generate token"),
        "host-loopback",
    )
    .expect("construct loopback event client");
    let mut stream = client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("complete event subscription");

    let error = stream
        .next_event_with_timeout(Duration::from_millis(50))
        .await
        .expect_err("a silent admitted stream must not wait indefinitely");

    assert!(matches!(&error, DaemonEventError::StreamIdleTimeout));
    assert!(error.is_recoverable_disconnect());
    release_server.send(()).expect("release silent event peer");
    server.join().expect("join silent event peer");
}

#[tokio::test]
async fn direct_event_client_classifies_real_tls_failures() {
    let (address, _certificate_pem, server) = spawn_handshake_tls_server();
    let binding = direct_binding(&format!("https://localhost:{}", address.port()))
        .expect("construct untrusted direct Host Binding");
    let client = DaemonEventClient::wss(
        &binding,
        ApiBearerToken::generate().expect("generate token"),
        None,
    )
    .expect("construct platform-trust WSS client");
    assert!(matches!(
        client.connect_events(vec![EventSubscription::Host]).await,
        Err(DaemonEventError::CertificateUntrusted(_))
    ));
    server.join().expect("join untrusted TLS server");

    let (address, certificate_pem, server) = spawn_handshake_tls_server();
    let binding = direct_binding(&format!("https://127.0.0.1:{}", address.port()))
        .expect("construct hostname-mismatch direct Host Binding");
    let client = DaemonEventClient::wss(
        &binding,
        ApiBearerToken::generate().expect("generate token"),
        Some(certificate_pem.as_bytes()),
    )
    .expect("construct pinned WSS client");
    assert!(matches!(
        client.connect_events(vec![EventSubscription::Host]).await,
        Err(DaemonEventError::CertificateHostnameMismatch(_))
    ));
    server.join().expect("join hostname-mismatch TLS server");

    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("CA certificate params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::KeyCertSign);
    let ca_key = rcgen::KeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .expect("generate CA certificate");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("expired certificate params");
    params.not_before = rcgen::date_time_ymd(2019, 1, 1);
    params.not_after = rcgen::date_time_ymd(2020, 1, 1);
    let signing_key = rcgen::KeyPair::generate().expect("generate expired certificate key");
    let certificate = params
        .signed_by(&signing_key, &issuer)
        .expect("generate expired certificate");
    let (address, server) =
        spawn_tls_handshake_server(vec![certificate.der().clone()], signing_key);
    let binding = direct_binding(&format!("https://localhost:{}", address.port()))
        .expect("construct expired-certificate direct Host Binding");
    let client = DaemonEventClient::wss(
        &binding,
        ApiBearerToken::generate().expect("generate token"),
        Some(ca_cert.pem().as_bytes()),
    )
    .expect("construct expired-certificate WSS client");
    assert!(matches!(
        client.connect_events(vec![EventSubscription::Host]).await,
        Err(DaemonEventError::CertificateExpired(_))
    ));
    server.join().expect("join expired-certificate TLS server");
}

// tungstenite's callback API fixes a large HTTP response as its error
// type; this test fixture cannot reduce that external type.
#[allow(clippy::result_large_err)]
fn spawn_wss_server(
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    signing_key: rcgen::KeyPair,
    expected_authorization: String,
) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key.into())
        .expect("configure TLS server");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind WSS server");
    let address = listener.local_addr().expect("read WSS server address");
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept WSS client");
        let connection = rustls::ServerConnection::new(Arc::new(server_config))
            .expect("create TLS server connection");
        let stream = rustls::StreamOwned::new(connection, stream);
        let mut socket = tokio_tungstenite::tungstenite::accept_hdr(
            stream,
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                assert_eq!(request.uri().path(), "/v1/events");
                assert_eq!(
                    request
                        .headers()
                        .get("authorization")
                        .and_then(|value| value.to_str().ok()),
                    Some(expected_authorization.as_str())
                );
                assert_eq!(
                    request
                        .headers()
                        .get("satelle-expected-host-identity")
                        .and_then(|value| value.to_str().ok()),
                    Some("host-windows-11")
                );
                assert!(request.headers().contains_key("satelle-request-id"));
                Ok(response)
            },
        )
        .expect("accept WebSocket handshake");
        let message = socket.read().expect("read subscription");
        let subscribe: SubscribeRequest = serde_json::from_str(
            message
                .to_text()
                .expect("subscription should be a text message"),
        )
        .expect("decode subscription");
        let acknowledgement = SubscribedResponse::new(
            subscribe.request_id().clone(),
            "host-windows-11".to_string(),
            subscribe.subscriptions().to_vec(),
        );
        socket
            .send(Message::Text(
                serde_json::to_string(&acknowledgement)
                    .expect("encode acknowledgement")
                    .into(),
            ))
            .expect("send subscription acknowledgement");
    });
    (address, server)
}

fn spawn_handshake_tls_server() -> (std::net::SocketAddr, String, std::thread::JoinHandle<()>) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate test certificate");
    let certificate_pem = cert.pem();
    let (address, server) = spawn_tls_handshake_server(vec![cert.der().clone()], signing_key);
    (address, certificate_pem, server)
}

fn spawn_tls_handshake_server(
    certificate_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    signing_key: rcgen::KeyPair,
) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key.into())
        .expect("configure TLS server");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS server");
    let address = listener.local_addr().expect("read TLS server address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept WSS client");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set TLS server timeout");
        let mut connection = rustls::ServerConnection::new(Arc::new(server_config))
            .expect("create TLS server connection");
        while connection.is_handshaking() {
            if connection.complete_io(&mut stream).is_err() {
                break;
            }
        }
    });
    (address, server)
}

fn direct_binding(endpoint: &str) -> Result<DirectHostBinding, DirectHostBindingError> {
    DirectHostBinding::from_host_config(&direct_host_config(endpoint))
}

fn direct_host_config(endpoint: &str) -> HostConfig {
    let mut config = SatelleConfig::defaults()
        .hosts
        .remove("local-demo")
        .expect("default local Host config");
    config.transport = TransportKind::Direct;
    config.address = Some(endpoint.to_string());
    config.expected_host_id = Some("host-windows-11".to_string());
    config.api_token = Some(ApiTokenSource::File {
        path: std::env::temp_dir().join("satelle.token"),
    });
    config
}

#[test]
fn only_connection_loss_is_recoverable_after_event_admission() {
    assert!(
        DaemonEventError::Transport(WebSocketError::ConnectionClosed).is_recoverable_disconnect()
    );
    assert!(DaemonEventError::Disconnected.is_recoverable_disconnect());
    assert!(DaemonEventError::StreamIdleTimeout.is_recoverable_disconnect());
    assert!(
        !DaemonEventError::Transport(WebSocketError::Protocol(
            tokio_tungstenite::tungstenite::error::ProtocolError::WrongHttpMethod,
        ))
        .is_recoverable_disconnect()
    );
    assert!(!DaemonEventError::SequenceDidNotAdvance.is_recoverable_disconnect());
    assert!(!DaemonEventError::HostIdentityMismatch.is_recoverable_disconnect());
}
