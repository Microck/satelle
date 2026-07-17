use super::*;
use futures_util::{SinkExt, StreamExt};
use satelle_core::{EventStateSubject, EventType, SatelleEvent};
use satelle_test_contract::assert_privacy_canaries_absent;
use satelle_transport::{EventSubscription, SessionResponse, SubscribeRequest, WsServerControl};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Response as WebSocketResponse;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};
use tokio_tungstenite::{WebSocketStream, client_async};

#[path = "events/limits.rs"]
mod limits;

type EventSocket = WebSocketStream<TcpStream>;

async fn connect_events(running: &RunningServer) -> EventSocket {
    connect_events_at(
        running.server.local_addr(),
        &running.token,
        &running.host_identity,
    )
    .await
}

async fn connect_events_at(
    address: SocketAddr,
    token: &ApiBearerToken,
    host_identity: &str,
) -> EventSocket {
    try_connect_events_at(address, token, host_identity)
        .await
        .expect("upgrade authenticated event socket")
}

async fn try_connect_events_at(
    address: SocketAddr,
    token: &ApiBearerToken,
    host_identity: &str,
) -> Result<EventSocket, WebSocketError> {
    try_connect_events_with_id_at(address, token, host_identity, RequestId::new())
        .await
        .map(|connected| connected.0)
}

async fn try_connect_events_with_id_at(
    address: SocketAddr,
    token: &ApiBearerToken,
    host_identity: &str,
    request_id: RequestId,
) -> Result<(EventSocket, WebSocketResponse), WebSocketError> {
    let mut request = format!("ws://{address}/v1/events")
        .into_client_request()
        .expect("build WebSocket request");
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&bearer(token)).expect("valid bearer header"),
    );
    request.headers_mut().insert(
        "satelle-expected-host-identity",
        HeaderValue::from_str(host_identity).expect("valid Host Identity header"),
    );
    request.headers_mut().insert(
        "satelle-request-id",
        HeaderValue::from_str(request_id.as_str()).expect("valid request ID header"),
    );
    let stream = TcpStream::connect(address)
        .await
        .expect("connect WebSocket TCP stream");
    client_async(request, stream).await
}

async fn try_connect_events_without_id_at(
    address: SocketAddr,
    token: &ApiBearerToken,
    host_identity: &str,
) -> Result<EventSocket, WebSocketError> {
    let mut request = format!("ws://{address}/v1/events")
        .into_client_request()
        .expect("build WebSocket request");
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&bearer(token)).expect("valid bearer header"),
    );
    request.headers_mut().insert(
        "satelle-expected-host-identity",
        HeaderValue::from_str(host_identity).expect("valid Host Identity header"),
    );
    let stream = TcpStream::connect(address)
        .await
        .expect("connect WebSocket TCP stream");
    client_async(request, stream)
        .await
        .map(|connected| connected.0)
}

#[tokio::test]
async fn event_upgrade_echoes_request_correlation_id() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let request_id = RequestId::new();
    let (_socket, response) = try_connect_events_with_id_at(
        running.server.local_addr(),
        &running.token,
        &running.host_identity,
        request_id.clone(),
    )
    .await
    .expect("upgrade authenticated event socket");

    assert_eq!(
        response.headers()["satelle-request-id"],
        request_id.as_str()
    );
    assert_eq!(
        response.headers()["satelle-host-identity"],
        running.host_identity
    );
}

#[tokio::test]
async fn event_upgrade_requires_a_caller_request_id() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let error = try_connect_events_without_id_at(
        running.server.local_addr(),
        &running.token,
        &running.host_identity,
    )
    .await
    .expect_err("an event upgrade without a request ID must be rejected");

    let WebSocketError::Http(response) = error else {
        panic!("expected HTTP request-ID rejection, got {error:?}");
    };
    assert_eq!(response.status().as_u16(), StatusCode::BAD_REQUEST);
    let response_request_id = RequestId::parse(
        response.headers()["satelle-request-id"]
            .to_str()
            .expect("generated response request ID is ASCII"),
    )
    .expect("the rejection response carries a canonical UUIDv7");
    let error: ApiError = serde_json::from_slice(
        response
            .body()
            .as_deref()
            .expect("the rejection response has a JSON body"),
    )
    .expect("decode request-ID rejection");
    assert_eq!(error.code().as_str(), "invalid-request");
    assert_eq!(error.request_id(), &response_request_id);
}

#[tokio::test]
async fn malformed_event_upgrades_return_correlated_typed_errors() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let response = running
        .request("/v1/events")
        .send()
        .await
        .expect("send authenticated plain GET to the event route");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()["satelle-host-identity"],
        running.host_identity
    );
    let response_request_id = RequestId::parse(
        response.headers()["satelle-request-id"]
            .to_str()
            .expect("response request ID is ASCII"),
    )
    .expect("the rejection response carries a canonical UUIDv7");
    let error: ApiError = response.json().await.expect("decode upgrade rejection");
    assert_eq!(error.code().as_str(), "invalid-request");
    assert_eq!(error.request_id(), &response_request_id);
    assert_eq!(error.host_identity(), Some(running.host_identity.as_str()));
}

async fn send_subscribe(socket: &mut EventSocket, subscriptions: Vec<EventSubscription>) {
    send_subscribe_with_id(socket, RequestId::new(), subscriptions).await;
}

async fn send_subscribe_with_id(
    socket: &mut EventSocket,
    request_id: RequestId,
    subscriptions: Vec<EventSubscription>,
) {
    let request =
        SubscribeRequest::new(request_id, subscriptions).expect("construct valid subscription");
    socket
        .send(Message::Text(
            serde_json::to_string(&request)
                .expect("serialize subscription")
                .into(),
        ))
        .await
        .expect("send subscription");
}

async fn next_text(socket: &mut EventSocket) -> String {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("WebSocket message timeout")
            .expect("WebSocket remains open")
            .expect("read WebSocket message");
        match message {
            Message::Text(text) => return text.to_string(),
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .expect("answer ping"),
            Message::Pong(_) => {}
            other => panic!("expected text frame, got {other:?}"),
        }
    }
}

async fn expect_subscribed(
    socket: &mut EventSocket,
    host_identity: &str,
) -> satelle_transport::SubscribedResponse {
    let message: WsServerControl =
        serde_json::from_str(&next_text(socket).await).expect("decode control acknowledgement");
    let WsServerControl::Subscribed(acknowledgement) = message else {
        panic!("expected subscribed acknowledgement");
    };
    assert_eq!(acknowledgement.host_identity(), host_identity);
    acknowledgement
}

async fn wait_for_workers(running: &RunningServer) {
    for _ in 0..100 {
        if running
            .service
            .daemon_workers_idle()
            .expect("inspect daemon workers")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon workers did not become idle");
}

#[tokio::test]
async fn event_socket_streams_only_post_subscription_commits_in_order() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let mut socket = connect_events(&running).await;
    send_subscribe(&mut socket, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut socket, &running.host_identity).await;

    let secret = "PRIVATE_WS_SECRET_CANARY";
    let prompt_canary = "PRIVATE_WS_PROMPT_CANARY";
    let prompt = format!("{prompt_canary} secret={secret}");
    let admitted = running
        .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66ea1")
        .json(&satelle_transport::TurnRequest::new(&prompt))
        .send()
        .await
        .expect("admit Session over HTTP");
    assert_eq!(admitted.status(), StatusCode::ACCEPTED);
    let admitted: SessionResponse = admitted.json().await.expect("decode admitted Session");

    let mut events = Vec::new();
    for _ in 0..3 {
        let frame = next_text(&mut socket).await;
        assert_privacy_canaries_absent(
            "WebSocket raw event frame",
            frame.as_bytes(),
            &[prompt_canary, secret],
        );
        events.push(serde_json::from_str(&frame).expect("decode Satelle Event"));
    }
    assert_eq!(
        events
            .iter()
            .map(SatelleEvent::event_type)
            .collect::<Vec<_>>(),
        [
            EventType::TurnStarted,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert_eq!(
        events.iter().map(SatelleEvent::seq).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(events.iter().all(|event| {
        event.session_id() == Some(admitted.session().session_id())
            && matches!(event.state_subject(), Some(EventStateSubject::Turn { .. }))
    }));

    let terminal = events.last().expect("terminal event");
    let EventStateSubject::Turn {
        session_state_revision,
        turn_state_revision,
    } = terminal.state_subject().expect("terminal state subject")
    else {
        panic!("terminal event requires a Turn subject");
    };
    let authoritative = running
        .request(&format!("/v1/sessions/{}", admitted.session().session_id()))
        .send()
        .await
        .expect("read authoritative Session")
        .json::<SessionResponse>()
        .await
        .expect("decode authoritative Session");
    let authoritative_turn = authoritative
        .session()
        .turns()
        .last()
        .expect("Session has a Turn");
    assert_eq!(
        *session_state_revision,
        authoritative.session().session_state_revision()
    );
    assert_eq!(
        *turn_state_revision,
        authoritative_turn.turn_state_revision()
    );
}

#[tokio::test]
async fn event_socket_closes_on_invalid_control_or_revoked_credentials() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let mut binary = connect_events(&running).await;
    binary
        .send(Message::Binary(Vec::new().into()))
        .await
        .expect("send binary control frame");
    let error: WsServerControl =
        serde_json::from_str(&next_text(&mut binary).await).expect("decode invalid-request error");
    assert!(matches!(
        error,
        WsServerControl::Error(error) if error.code().as_str() == "invalid-request"
    ));
    let close = binary
        .next()
        .await
        .expect("receive binary control close")
        .expect("decode binary control close");
    assert!(matches!(
        close,
        Message::Close(Some(frame)) if frame.code == CloseCode::Policy && frame.reason == "invalid-request"
    ));

    let mut unsupported = connect_events(&running).await;
    unsupported
        .send(Message::Text(
            serde_json::json!({
                "schema_version": "satelle.ws.control.v2",
                "type": "subscribe",
                "request_id": RequestId::new(),
                "subscriptions": [{"kind":"host"}]
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("send unsupported control schema");
    let error: WsServerControl = serde_json::from_str(&next_text(&mut unsupported).await)
        .expect("decode unsupported-schema error");
    assert!(matches!(
        error,
        WsServerControl::Error(error) if error.code().as_str() == "unsupported-schema"
    ));
    let close = unsupported
        .next()
        .await
        .expect("receive close")
        .expect("decode close");
    assert!(matches!(
        close,
        Message::Close(Some(frame)) if frame.code == CloseCode::Policy && frame.reason == "unsupported-schema"
    ));

    let mut revoked = connect_events(&running).await;
    send_subscribe_with_id(
        &mut revoked,
        RequestId::new(),
        vec![EventSubscription::Host],
    )
    .await;
    expect_subscribed(&mut revoked, &running.host_identity).await;
    let active_request_id = RequestId::new();
    send_subscribe_with_id(
        &mut revoked,
        active_request_id.clone(),
        vec![EventSubscription::Host],
    )
    .await;
    expect_subscribed(&mut revoked, &running.host_identity).await;
    running
        .service
        .revoke_api_token(running.token.token_id())
        .expect("revoke live socket credential");
    revoked
        .send(Message::Pong(Vec::new().into()))
        .await
        .expect("trigger credential revalidation");
    let error: WsServerControl = serde_json::from_str(&next_text(&mut revoked).await)
        .expect("decode authentication failure");
    assert!(matches!(
        error,
        WsServerControl::Error(error)
            if error.code().as_str() == "authentication-failed"
                && error.request_id() == &active_request_id
    ));
    let close = revoked
        .next()
        .await
        .expect("receive revoked close")
        .expect("decode revoked close");
    assert!(matches!(
        close,
        Message::Close(Some(frame)) if frame.code == CloseCode::Policy && frame.reason == "authentication-failed"
    ));
}

#[tokio::test]
async fn event_subscriptions_reject_bearer_token_fields() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let mut socket = connect_events(&running).await;
    let exposed = running.token.expose();
    socket
        .send(Message::Text(
            serde_json::json!({
                "schema_version": "satelle.ws.control.v1",
                "type": "subscribe",
                "request_id": RequestId::new(),
                "subscriptions": [{"kind":"host"}],
                "api_token": exposed.as_str(),
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("send subscription containing a bearer token");

    let error: WsServerControl =
        serde_json::from_str(&next_text(&mut socket).await).expect("decode invalid-request error");
    assert!(matches!(
        error,
        WsServerControl::Error(error) if error.code().as_str() == "invalid-request"
    ));
    let close = socket
        .next()
        .await
        .expect("receive token-carrier close")
        .expect("decode token-carrier close");
    assert!(matches!(
        close,
        Message::Close(Some(frame)) if frame.code == CloseCode::Policy && frame.reason == "invalid-request"
    ));

    let mut socket = connect_events(&running).await;
    socket
        .send(Message::Text(
            format!(
                r#"{{"schema_version":"satelle.ws.control.v1","type":"subscribe","request_id":"{}","api_token":"{}","api_token":"safe","subscriptions":[{{"kind":"host"}}]}}"#,
                RequestId::new(),
                exposed.as_str()
            )
            .into(),
        ))
        .await
        .expect("send duplicate-key subscription containing a bearer token");

    let error: WsServerControl = serde_json::from_str(&next_text(&mut socket).await)
        .expect("decode duplicate-key invalid-request error");
    assert!(matches!(
        error,
        WsServerControl::Error(error) if error.code().as_str() == "invalid-request"
    ));

    let mut socket = connect_events(&running).await;
    send_subscribe(&mut socket, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut socket, &running.host_identity).await;
    let rejected_request_id = RequestId::new();
    socket
        .send(Message::Text(
            serde_json::json!({
                "schema_version": "satelle.ws.control.v1",
                "type": "subscribe",
                "request_id": rejected_request_id,
                "subscriptions": [{"kind":"host"}],
                "api_token": exposed.as_str(),
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("send correlated subscription containing a bearer token");
    let error: WsServerControl =
        serde_json::from_str(&next_text(&mut socket).await).expect("decode correlated rejection");
    assert!(matches!(
        error,
        WsServerControl::Error(error)
            if error.code().as_str() == "invalid-request"
                && error.request_id() == &rejected_request_id
    ));
}

#[tokio::test]
async fn replacing_event_subscriptions_filters_live_events_without_resetting_sequence() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let prior = running
        .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66ea2")
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_PRIOR_SCOPE_PROMPT",
        ))
        .send()
        .await
        .expect("admit prior Session")
        .json::<SessionResponse>()
        .await
        .expect("decode prior Session");
    wait_for_workers(&running).await;

    let mut socket = connect_events(&running).await;
    send_subscribe(
        &mut socket,
        vec![EventSubscription::Session {
            session_id: prior.session().session_id().clone(),
        }],
    )
    .await;
    expect_subscribed(&mut socket, &running.host_identity).await;

    let prior_follow_up = running
        .mutation(
            &format!("/v1/sessions/{}/turns", prior.session().session_id()),
            "01890a5d-ac96-7b7c-8f89-37c3d0a66eb6",
        )
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_PRIOR_VISIBLE_PROMPT",
        ))
        .send()
        .await
        .expect("admit visible follow-up for prior scope");
    assert_eq!(prior_follow_up.status(), StatusCode::ACCEPTED);
    for expected_sequence in 1..=3 {
        let event = serde_json::from_str::<SatelleEvent>(&next_text(&mut socket).await)
            .expect("decode prior matching event");
        assert_eq!(event.seq(), expected_sequence);
        assert_eq!(event.session_id(), Some(prior.session().session_id()));
    }

    let admitted = running
        .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66ea3")
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_FILTERED_PROMPT",
        ))
        .send()
        .await
        .expect("admit filtered Session")
        .json::<SessionResponse>()
        .await
        .expect("decode filtered Session");
    wait_for_workers(&running).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_text(&mut socket))
            .await
            .is_err(),
        "a nonmatching Session scope must receive no event"
    );

    let replacement_request_id = RequestId::new();
    let replacement = vec![EventSubscription::Session {
        session_id: admitted.session().session_id().clone(),
    }];
    send_subscribe_with_id(
        &mut socket,
        replacement_request_id.clone(),
        replacement.clone(),
    )
    .await;
    let acknowledgement = expect_subscribed(&mut socket, &running.host_identity).await;
    assert_eq!(acknowledgement.request_id(), &replacement_request_id);
    assert_eq!(acknowledgement.subscriptions(), replacement);
    let follow_up = running
        .mutation(
            &format!("/v1/sessions/{}/turns", admitted.session().session_id()),
            "01890a5d-ac96-7b7c-8f89-37c3d0a66ea4",
        )
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_VISIBLE_PROMPT",
        ))
        .send()
        .await
        .expect("admit visible follow-up");
    assert_eq!(follow_up.status(), StatusCode::ACCEPTED);

    let mut events = Vec::new();
    for _ in 0..3 {
        events.push(
            serde_json::from_str::<SatelleEvent>(&next_text(&mut socket).await)
                .expect("decode matching event"),
        );
    }
    assert_eq!(
        events.iter().map(SatelleEvent::seq).collect::<Vec<_>>(),
        [4, 5, 6]
    );
    assert!(
        events
            .iter()
            .all(|event| event.session_id() == Some(admitted.session().session_id()))
    );

    let filtered_prior = running
        .mutation(
            &format!("/v1/sessions/{}/turns", prior.session().session_id()),
            "01890a5d-ac96-7b7c-8f89-37c3d0a66ea5",
        )
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_REPLACED_SCOPE_PROMPT",
        ))
        .send()
        .await
        .expect("admit follow-up for replaced scope");
    assert_eq!(filtered_prior.status(), StatusCode::ACCEPTED);
    wait_for_workers(&running).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_text(&mut socket))
            .await
            .is_err(),
        "the replacement must discard the complete prior subscription set"
    );

    let overlap = vec![
        EventSubscription::Host,
        EventSubscription::Session {
            session_id: admitted.session().session_id().clone(),
        },
    ];
    send_subscribe(&mut socket, overlap).await;
    expect_subscribed(&mut socket, &running.host_identity).await;
    let overlap_follow_up = running
        .mutation(
            &format!("/v1/sessions/{}/turns", admitted.session().session_id()),
            "01890a5d-ac96-7b7c-8f89-37c3d0a66ea6",
        )
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_OVERLAP_PROMPT",
        ))
        .send()
        .await
        .expect("admit overlapping-scope follow-up");
    assert_eq!(overlap_follow_up.status(), StatusCode::ACCEPTED);
    let mut overlap_events = Vec::new();
    for _ in 0..3 {
        overlap_events.push(
            serde_json::from_str::<SatelleEvent>(&next_text(&mut socket).await)
                .expect("decode overlapping-scope event"),
        );
    }
    assert_eq!(
        overlap_events
            .iter()
            .map(SatelleEvent::seq)
            .collect::<Vec<_>>(),
        [7, 8, 9]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next_text(&mut socket))
            .await
            .is_err(),
        "overlapping scopes must not duplicate matching events"
    );
}

#[tokio::test]
async fn event_handshakes_reject_unexpected_query_cookie_and_body_shapes() {
    let running = RunningServer::start(ApiScopes::READ).await;
    for request in [
        running.request("/v1/events?unexpected=true"),
        running
            .request("/v1/events")
            .header("Cookie", "forbidden=true"),
        running.request("/v1/events").body("forbidden"),
    ] {
        let response = request.send().await.expect("request invalid handshake");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .json::<ApiError>()
                .await
                .expect("decode handshake error")
                .code()
                .as_str(),
            "invalid-request"
        );
    }
}

#[tokio::test]
async fn daemon_shutdown_closes_event_sockets_with_a_typed_reason() {
    let state = TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let token = ApiBearerToken::generate().expect("generate API token");
    service
        .register_api_token(&token, "principal-shutdown", ApiScopes::READ, None)
        .expect("register API token");
    let server = DaemonServer::bind(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
    )
    .await
    .expect("bind daemon server");
    let mut socket =
        connect_events_at(server.local_addr(), &token, initialized.host_identity()).await;
    send_subscribe(&mut socket, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut socket, initialized.host_identity()).await;

    let shutdown = tokio::spawn(server.shutdown());
    let error: WsServerControl =
        serde_json::from_str(&next_text(&mut socket).await).expect("decode shutdown control error");
    assert!(matches!(
        error,
        WsServerControl::Error(error) if error.code().as_str() == "host-unreachable"
    ));
    let close = socket
        .next()
        .await
        .expect("receive shutdown close")
        .expect("decode shutdown close");
    assert!(matches!(
        close,
        Message::Close(Some(frame)) if frame.code == CloseCode::Away && frame.reason == "server-shutdown"
    ));
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("daemon shutdown timeout")
        .expect("join daemon shutdown")
        .expect("daemon shutdown succeeds");
}

#[tokio::test]
async fn daemon_event_client_validates_the_subscription_and_event_stream() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let token = {
        let exposed = running.token.expose();
        ApiBearerToken::parse(exposed.as_str()).expect("copy token for event client")
    };
    let client = satelle_transport::DaemonEventClient::loopback(
        running.server.local_addr(),
        token,
        running.host_identity.clone(),
    )
    .expect("construct pinned daemon client");
    let mut events = client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("connect daemon event client");

    let admitted = running
        .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66ea4")
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_CLIENT_EVENT_PROMPT",
        ))
        .send()
        .await
        .expect("admit client-observed Session");
    assert_eq!(admitted.status(), StatusCode::ACCEPTED);

    assert_eq!(
        events
            .next_event()
            .await
            .expect("receive starting event")
            .event_type(),
        EventType::TurnStarted
    );
    assert_eq!(
        events
            .next_event()
            .await
            .expect("receive running event")
            .event_type(),
        EventType::TurnProgress
    );
    assert_eq!(
        events
            .next_event()
            .await
            .expect("receive terminal event")
            .event_type(),
        EventType::TurnCompleted
    );
}

#[tokio::test]
async fn daemon_event_client_preserves_typed_handshake_rejections() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let unknown_token = ApiBearerToken::generate().expect("generate unregistered API token");
    let client = satelle_transport::DaemonEventClient::loopback(
        running.server.local_addr(),
        unknown_token,
        running.host_identity.clone(),
    )
    .expect("construct pinned daemon client");

    let error = match client.connect_events(vec![EventSubscription::Host]).await {
        Ok(_) => panic!("an unregistered credential must not complete the handshake"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        satelle_transport::DaemonEventError::Handshake { status, error }
            if status == StatusCode::UNAUTHORIZED.as_u16()
                && error.code().as_str() == "authentication-failed"
                && error.host_identity().is_none()
    ));
}
