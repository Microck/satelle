use super::*;
use satelle_transport::EventSubscription;

async fn spawn_event_protocol_fixture<F>(
    build_messages: F,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(Value) -> Vec<axum::extract::ws::Message> + Clone + Send + Sync + 'static,
{
    use axum::Router;
    use axum::extract::ws::{Message as AxumMessage, WebSocketUpgrade};
    use axum::routing::get;

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind WebSocket protocol fixture");
    let address = listener.local_addr().expect("read fixture address");
    let app = Router::new().route(
        "/v1/events",
        get(move |websocket: WebSocketUpgrade| {
            let build_messages = build_messages.clone();
            async move {
                websocket.on_upgrade(move |mut socket| async move {
                    let request = socket
                        .recv()
                        .await
                        .expect("receive subscription")
                        .expect("decode subscription");
                    let AxumMessage::Text(request) = request else {
                        panic!("expected text subscription");
                    };
                    let request: Value =
                        serde_json::from_str(&request).expect("parse subscription fixture");
                    for message in build_messages(request) {
                        socket
                            .send(message)
                            .await
                            .expect("send protocol fixture message");
                    }
                })
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve WebSocket protocol fixture");
    });
    (address, server)
}

fn subscribed_fixture(request: &Value, host_identity: &str) -> Value {
    serde_json::json!({
        "schema_version": "satelle.ws.control.v1",
        "type": "subscribed",
        "request_id": request["request_id"],
        "host_identity": host_identity,
        "subscriptions": request["subscriptions"]
    })
}

fn control_error_fixture(
    request_id: Value,
    host_identity: &str,
    reason: satelle_transport::WsCloseReason,
) -> Value {
    let (code, category, retryable) = match reason {
        satelle_transport::WsCloseReason::SlowConsumer => ("capacity-exceeded", "capacity", false),
        satelle_transport::WsCloseReason::IdleTimeout => ("rate-limited", "rate_limit", true),
        satelle_transport::WsCloseReason::AuthenticationFailed => {
            ("authentication-failed", "authentication", false)
        }
        satelle_transport::WsCloseReason::ServerShutdown => ("host-unreachable", "readiness", true),
        other => panic!("unsupported protocol fixture reason {other:?}"),
    };
    serde_json::json!({
        "schema_version": "satelle.ws.control.v1",
        "type": "error",
        "request_id": request_id,
        "host_identity": host_identity,
        "reason": reason.as_str(),
        "code": code,
        "category": category,
        "retryable": retryable,
        "message": "closed by protocol fixture",
        "details": null,
        "docs_url": null,
        "suggested_commands": []
    })
}

#[tokio::test]
async fn daemon_event_client_rejects_a_mismatched_acknowledgement_identity() {
    let (address, server) = spawn_event_protocol_fixture(|request| {
        vec![axum::extract::ws::Message::Text(
            subscribed_fixture(&request, "host-other")
                .to_string()
                .into(),
        )]
    })
    .await;
    let token = ApiBearerToken::generate().expect("generate fixture token");
    let client = satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
        .expect("construct event client");
    let error = match client.connect_events(vec![EventSubscription::Host]).await {
        Ok(_) => panic!("the mismatched acknowledgement must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        satelle_transport::DaemonEventError::HostIdentityMismatch
    ));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn daemon_event_client_validates_post_ack_subscribed_request_id() {
    let (address, server) = spawn_event_protocol_fixture(|request| {
        let acknowledgement = subscribed_fixture(&request, "host-expected");
        let mut unsolicited = subscribed_fixture(&request, "host-expected");
        unsolicited["request_id"] =
            serde_json::to_value(RequestId::new()).expect("serialize wrong request ID");
        vec![
            axum::extract::ws::Message::Text(acknowledgement.to_string().into()),
            axum::extract::ws::Message::Text(unsolicited.to_string().into()),
        ]
    })
    .await;
    let token = ApiBearerToken::generate().expect("generate fixture token");
    let client = satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
        .expect("construct event client");
    let mut stream = client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("accept valid fixture acknowledgement");
    let error = stream
        .next_event()
        .await
        .expect_err("the mismatched subscribed request ID must be rejected");
    assert!(
        matches!(
            &error,
            satelle_transport::DaemonEventError::RequestIdMismatch
        ),
        "unexpected event client error: {error:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn daemon_event_client_validates_post_ack_subscribed_host_identity() {
    let (address, server) = spawn_event_protocol_fixture(|request| {
        vec![
            axum::extract::ws::Message::Text(
                subscribed_fixture(&request, "host-expected")
                    .to_string()
                    .into(),
            ),
            axum::extract::ws::Message::Text(
                subscribed_fixture(&request, "host-other")
                    .to_string()
                    .into(),
            ),
        ]
    })
    .await;
    let token = ApiBearerToken::generate().expect("generate fixture token");
    let client = satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
        .expect("construct event client");
    let mut stream = client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("accept valid fixture acknowledgement");
    let error = stream
        .next_event()
        .await
        .expect_err("the mismatched subscribed Host Identity must be rejected");
    assert!(
        matches!(
            &error,
            satelle_transport::DaemonEventError::HostIdentityMismatch
        ),
        "unexpected event client error: {error:?}"
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn daemon_event_client_rejects_context_valid_unsolicited_subscribed_frame() {
    let (address, server) = spawn_event_protocol_fixture(|request| {
        let acknowledgement = subscribed_fixture(&request, "host-expected");
        vec![
            axum::extract::ws::Message::Text(acknowledgement.to_string().into()),
            axum::extract::ws::Message::Text(acknowledgement.to_string().into()),
        ]
    })
    .await;
    let token = ApiBearerToken::generate().expect("generate fixture token");
    let client = satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
        .expect("construct event client");
    let mut stream = client
        .connect_events(vec![EventSubscription::Host])
        .await
        .expect("accept valid fixture acknowledgement");
    let error = stream
        .next_event()
        .await
        .expect_err("an unsolicited acknowledgement must be rejected");
    assert!(matches!(
        error,
        satelle_transport::DaemonEventError::UnexpectedFrame
    ));
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn daemon_event_client_validates_pre_ack_error_context() {
    for wrong_request_id in [false, true] {
        let (address, server) = spawn_event_protocol_fixture(move |request| {
            let request_id = if wrong_request_id {
                serde_json::to_value(RequestId::new()).expect("serialize wrong request ID")
            } else {
                request["request_id"].clone()
            };
            let host_identity = if wrong_request_id {
                "host-expected"
            } else {
                "host-other"
            };
            let reason = satelle_transport::WsCloseReason::AuthenticationFailed;
            vec![
                axum::extract::ws::Message::Text(
                    control_error_fixture(request_id, host_identity, reason)
                        .to_string()
                        .into(),
                ),
                axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: reason.close_code(),
                    reason: reason.as_str().into(),
                })),
            ]
        })
        .await;
        let token = ApiBearerToken::generate().expect("generate fixture token");
        let client =
            satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
                .expect("construct event client");
        let error = match client.connect_events(vec![EventSubscription::Host]).await {
            Ok(_) => panic!("a mismatched error context must be rejected"),
            Err(error) => error,
        };
        if wrong_request_id {
            assert!(matches!(
                error,
                satelle_transport::DaemonEventError::RequestIdMismatch
            ));
        } else {
            assert!(matches!(
                error,
                satelle_transport::DaemonEventError::HostIdentityMismatch
            ));
        }
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn daemon_event_client_preserves_every_ambiguous_close_reason() {
    for reason in [
        satelle_transport::WsCloseReason::SlowConsumer,
        satelle_transport::WsCloseReason::IdleTimeout,
        satelle_transport::WsCloseReason::AuthenticationFailed,
        satelle_transport::WsCloseReason::ServerShutdown,
    ] {
        let (address, server) = spawn_event_protocol_fixture(move |request| {
            vec![
                axum::extract::ws::Message::Text(
                    subscribed_fixture(&request, "host-expected")
                        .to_string()
                        .into(),
                ),
                axum::extract::ws::Message::Text(
                    control_error_fixture(request["request_id"].clone(), "host-expected", reason)
                        .to_string()
                        .into(),
                ),
                axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: reason.close_code(),
                    reason: reason.as_str().into(),
                })),
            ]
        })
        .await;
        let token = ApiBearerToken::generate().expect("generate fixture token");
        let client =
            satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
                .expect("construct event client");
        let mut stream = client
            .connect_events(vec![EventSubscription::Host])
            .await
            .expect("accept valid fixture acknowledgement");
        let error = stream
            .next_event()
            .await
            .expect_err("the fixture must close the event stream");
        assert!(matches!(
            error,
            satelle_transport::DaemonEventError::Closed {
                code,
                reason: actual,
                control: Some(control),
            } if code == reason.close_code()
                && actual == reason
                && control.reason() == reason
        ));
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn daemon_event_client_validates_post_ack_error_context() {
    for wrong_request_id in [false, true] {
        let reason = satelle_transport::WsCloseReason::ServerShutdown;
        let (address, server) = spawn_event_protocol_fixture(move |request| {
            let request_id = if wrong_request_id {
                serde_json::to_value(RequestId::new()).expect("serialize wrong request ID")
            } else {
                request["request_id"].clone()
            };
            let host_identity = if wrong_request_id {
                "host-expected"
            } else {
                "host-other"
            };
            vec![
                axum::extract::ws::Message::Text(
                    subscribed_fixture(&request, "host-expected")
                        .to_string()
                        .into(),
                ),
                axum::extract::ws::Message::Text(
                    control_error_fixture(request_id, host_identity, reason)
                        .to_string()
                        .into(),
                ),
                axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: reason.close_code(),
                    reason: reason.as_str().into(),
                })),
            ]
        })
        .await;
        let token = ApiBearerToken::generate().expect("generate fixture token");
        let client =
            satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
                .expect("construct event client");
        let mut stream = client
            .connect_events(vec![EventSubscription::Host])
            .await
            .expect("accept valid fixture acknowledgement");
        let error = stream
            .next_event()
            .await
            .expect_err("the mismatched error context must be rejected");
        if wrong_request_id {
            assert!(matches!(
                error,
                satelle_transport::DaemonEventError::RequestIdMismatch
            ));
        } else {
            assert!(matches!(
                error,
                satelle_transport::DaemonEventError::HostIdentityMismatch
            ));
        }
        server.abort();
        let _ = server.await;
    }
}

#[tokio::test]
async fn daemon_event_client_rejects_control_and_close_mismatches() {
    for (control_reason, close_reason, close_code) in [
        (
            satelle_transport::WsCloseReason::SlowConsumer,
            satelle_transport::WsCloseReason::IdleTimeout,
            satelle_transport::WsCloseReason::IdleTimeout.close_code(),
        ),
        (
            satelle_transport::WsCloseReason::ServerShutdown,
            satelle_transport::WsCloseReason::ServerShutdown,
            satelle_transport::WsCloseReason::SlowConsumer.close_code(),
        ),
    ] {
        let (address, server) = spawn_event_protocol_fixture(move |request| {
            vec![
                axum::extract::ws::Message::Text(
                    subscribed_fixture(&request, "host-expected")
                        .to_string()
                        .into(),
                ),
                axum::extract::ws::Message::Text(
                    control_error_fixture(
                        request["request_id"].clone(),
                        "host-expected",
                        control_reason,
                    )
                    .to_string()
                    .into(),
                ),
                axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: close_code,
                    reason: close_reason.as_str().into(),
                })),
            ]
        })
        .await;
        let token = ApiBearerToken::generate().expect("generate fixture token");
        let client =
            satelle_transport::DaemonEventClient::loopback(address, token, "host-expected")
                .expect("construct event client");
        let mut stream = client
            .connect_events(vec![EventSubscription::Host])
            .await
            .expect("accept valid fixture acknowledgement");
        let error = stream
            .next_event()
            .await
            .expect_err("the mismatched close must fail validation");
        assert!(matches!(
            error,
            satelle_transport::DaemonEventError::CloseContractMismatch { .. }
        ));
        server.abort();
        let _ = server.await;
    }
}
