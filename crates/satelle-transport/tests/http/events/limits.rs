use super::*;

const INBOUND_MESSAGES_PER_MINUTE: usize = 120;

async fn expect_control_failure(
    socket: &mut EventSocket,
    expected_reason: satelle_transport::WsCloseReason,
) {
    let control: WsServerControl = serde_json::from_str(&next_text(socket).await)
        .expect("decode terminal WebSocket control error");
    assert!(matches!(
        control,
        WsServerControl::Error(error) if error.reason() == expected_reason
    ));
    let close = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("WebSocket close timeout")
        .expect("receive terminal WebSocket close")
        .expect("decode terminal WebSocket close");
    assert!(matches!(
        close,
        Message::Close(Some(frame))
            if u16::from(frame.code) == expected_reason.close_code()
                && frame.reason == expected_reason.as_str()
    ));
}

async fn send_pongs(socket: &mut EventSocket, count: usize) {
    for _ in 0..count {
        socket
            .send(Message::Pong(Vec::new().into()))
            .await
            .expect("send inbound pong frame");
    }
}

async fn expect_pong(socket: &mut EventSocket, expected_payload: &[u8]) {
    let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .expect("WebSocket pong timeout")
        .expect("WebSocket remains open")
        .expect("read WebSocket pong");
    assert!(matches!(
        message,
        Message::Pong(payload) if payload.as_ref() == expected_payload
    ));
}

fn oversized_subscriptions() -> Vec<Value> {
    (0..17)
        .map(|_| {
            serde_json::json!({
                "kind": "session",
                "session_id": satelle_core::SessionId::new()
            })
        })
        .collect()
}

async fn send_oversized_subscription(socket: &mut EventSocket) {
    socket
        .send(Message::Text(
            serde_json::json!({
                "schema_version": "satelle.ws.control.v1",
                "type": "subscribe",
                "request_id": RequestId::new(),
                "subscriptions": oversized_subscriptions()
            })
            .to_string()
            .into(),
        ))
        .await
        .expect("send oversized subscription set");
}

#[tokio::test]
async fn connection_capacity_is_four_per_principal_across_token_ids() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let second_token = ApiBearerToken::generate().expect("generate second Principal token");
    running
        .service
        .register_api_token(&second_token, "principal-http-test", ApiScopes::READ, None)
        .expect("register second token for the same Principal");
    let other_principal = ApiBearerToken::generate().expect("generate other Principal token");
    running
        .service
        .register_api_token(&other_principal, "principal-other", ApiScopes::READ, None)
        .expect("register token for another Principal");

    let mut principal_sockets = Vec::new();
    for token in [&running.token, &running.token, &second_token, &second_token] {
        principal_sockets.push(
            connect_events_at(running.server.local_addr(), token, &running.host_identity).await,
        );
    }
    let error = try_connect_events_at(
        running.server.local_addr(),
        &second_token,
        &running.host_identity,
    )
    .await
    .expect_err("the fifth same-Principal connection must be rejected");
    assert!(matches!(
        error,
        WebSocketError::Http(response)
            if response.status().as_u16() == StatusCode::TOO_MANY_REQUESTS
    ));

    let _other_principal_socket = connect_events_at(
        running.server.local_addr(),
        &other_principal,
        &running.host_identity,
    )
    .await;
    assert_eq!(principal_sockets.len(), 4);
}

#[tokio::test]
async fn inbound_allowance_is_shared_across_token_ids_for_one_principal() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let second_token = ApiBearerToken::generate().expect("generate second Principal token");
    running
        .service
        .register_api_token(&second_token, "principal-http-test", ApiScopes::READ, None)
        .expect("register second token for the same Principal");
    let mut first = connect_events(&running).await;
    let mut second = connect_events_at(
        running.server.local_addr(),
        &second_token,
        &running.host_identity,
    )
    .await;

    send_pongs(&mut first, 59).await;
    send_subscribe(&mut first, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut first, &running.host_identity).await;
    send_pongs(&mut second, 59).await;
    send_subscribe(&mut second, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut second, &running.host_identity).await;

    send_subscribe(&mut first, vec![EventSubscription::Host]).await;
    expect_control_failure(&mut first, satelle_transport::WsCloseReason::RateLimited).await;
}

#[tokio::test]
async fn custom_inbound_message_allowance_is_enforced() {
    let limit = |value| NonZeroUsize::new(value).expect("test rate limit is nonzero");
    let running = RunningServer::start_with_config(
        ApiScopes::READ,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .with_api_rate_limits(ApiRateLimits::new(
                limit(10),
                limit(10),
                limit(10),
                limit(2),
            )),
    )
    .await;
    let mut socket = connect_events(&running).await;

    send_pongs(&mut socket, 2).await;
    send_subscribe(&mut socket, vec![EventSubscription::Host]).await;
    expect_control_failure(&mut socket, satelle_transport::WsCloseReason::RateLimited).await;
}

#[tokio::test]
async fn every_non_close_frame_kind_consumes_inbound_allowance() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let mut survivor = connect_events(&running).await;
    let mut binary = connect_events(&running).await;

    send_pongs(&mut survivor, INBOUND_MESSAGES_PER_MINUTE - 4).await;

    send_subscribe(&mut survivor, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut survivor, &running.host_identity).await;

    survivor
        .send(Message::Pong(Vec::new().into()))
        .await
        .expect("send counted pong frame");
    survivor
        .send(Message::Ping(b"counted-ping".to_vec().into()))
        .await
        .expect("send counted ping frame");
    expect_pong(&mut survivor, b"counted-ping").await;

    binary
        .send(Message::Binary(b"counted-binary".to_vec().into()))
        .await
        .expect("send counted binary frame");
    expect_control_failure(
        &mut binary,
        satelle_transport::WsCloseReason::InvalidRequest,
    )
    .await;

    send_subscribe(&mut survivor, vec![EventSubscription::Host]).await;
    expect_control_failure(&mut survivor, satelle_transport::WsCloseReason::RateLimited).await;
}

#[tokio::test]
async fn close_frames_terminate_without_consuming_inbound_allowance() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let mut survivor = connect_events(&running).await;
    let mut closing = connect_events(&running).await;

    send_pongs(&mut survivor, INBOUND_MESSAGES_PER_MINUTE - 2).await;
    send_subscribe(&mut survivor, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut survivor, &running.host_identity).await;

    closing.close(None).await.expect("send close frame");
    let termination = tokio::time::timeout(Duration::from_secs(2), closing.next())
        .await
        .expect("peer termination timeout");
    assert!(
        termination.is_none() || matches!(termination, Some(Ok(Message::Close(_))) | Some(Err(_))),
        "the peer must terminate after the close frame"
    );

    send_subscribe(&mut survivor, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut survivor, &running.host_identity).await;
}

#[tokio::test]
async fn failing_sockets_do_not_interrupt_an_unrelated_live_subscriber() {
    let running = RunningServer::start(ApiScopes::CONTROL).await;
    let mut subscriber = connect_events(&running).await;
    send_subscribe(&mut subscriber, vec![EventSubscription::Host]).await;
    expect_subscribed(&mut subscriber, &running.host_identity).await;

    let admitted = running
        .mutation("/v1/sessions", "01890a5d-ac96-7b7c-8f89-37c3d0a66eaa")
        .json(&satelle_transport::TurnRequest::new(
            "PRIVATE_ISOLATED_FAILURE_PROMPT",
        ))
        .send()
        .await
        .expect("admit Session before unrelated socket failures");
    assert_eq!(admitted.status(), StatusCode::ACCEPTED);
    let admitted: SessionResponse = admitted.json().await.expect("decode admitted Session");

    let capacity_principal = ApiBearerToken::generate().expect("generate capacity token");
    running
        .service
        .register_api_token(
            &capacity_principal,
            "principal-capacity-offender",
            ApiScopes::READ,
            None,
        )
        .expect("register capacity offender");
    let mut capacity_offender = connect_events_at(
        running.server.local_addr(),
        &capacity_principal,
        &running.host_identity,
    )
    .await;
    send_oversized_subscription(&mut capacity_offender).await;
    expect_control_failure(
        &mut capacity_offender,
        satelle_transport::WsCloseReason::CapacityExceeded,
    )
    .await;

    let rate_principal = ApiBearerToken::generate().expect("generate rate-limit token");
    running
        .service
        .register_api_token(
            &rate_principal,
            "principal-rate-offender",
            ApiScopes::READ,
            None,
        )
        .expect("register rate-limit offender");
    let mut rate_offender = connect_events_at(
        running.server.local_addr(),
        &rate_principal,
        &running.host_identity,
    )
    .await;
    send_pongs(&mut rate_offender, INBOUND_MESSAGES_PER_MINUTE).await;
    send_subscribe(&mut rate_offender, vec![EventSubscription::Host]).await;
    expect_control_failure(
        &mut rate_offender,
        satelle_transport::WsCloseReason::RateLimited,
    )
    .await;

    let mut events = Vec::new();
    for _ in 0..5 {
        events.push(
            serde_json::from_str::<SatelleEvent>(&next_text(&mut subscriber).await)
                .expect("decode live event after unrelated socket failures"),
        );
    }
    assert_eq!(
        events
            .iter()
            .map(SatelleEvent::event_type)
            .collect::<Vec<_>>(),
        [
            EventType::Readiness,
            EventType::TurnStarted,
            EventType::ProviderSmoke,
            EventType::TurnProgress,
            EventType::TurnCompleted,
        ]
    );
    assert_eq!(
        events.iter().map(SatelleEvent::seq).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    let readiness = &events[0];
    assert_eq!(readiness.data()["source"], "live");
    assert_eq!(readiness.data()["status"], "passed");
    let file_management = readiness.data()["checks"]
        .as_array()
        .expect("readiness carries structured checks")
        .iter()
        .find(|check| check["kind"] == "file_management")
        .expect("readiness includes file-management status");
    assert_eq!(file_management["status"], "not_evaluated");
    assert_eq!(
        file_management["reason"],
        "not_required_for_prompt_admission"
    );
    assert!(
        events
            .iter()
            .all(|event| event.session_id() == Some(admitted.session().session_id()))
    );
}

#[tokio::test]
async fn oversized_subscription_sets_are_capacity_failures() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let mut socket = connect_events(&running).await;
    send_oversized_subscription(&mut socket).await;
    expect_control_failure(
        &mut socket,
        satelle_transport::WsCloseReason::CapacityExceeded,
    )
    .await;
}

#[tokio::test]
async fn oversized_messages_are_payload_too_large_failures() {
    let running = RunningServer::start(ApiScopes::READ).await;
    let mut socket = connect_events(&running).await;
    socket
        .send(Message::Text("x".repeat(65_537).into()))
        .await
        .expect("send oversized WebSocket message");

    expect_control_failure(
        &mut socket,
        satelle_transport::WsCloseReason::PayloadTooLarge,
    )
    .await;
}
