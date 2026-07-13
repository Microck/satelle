use super::*;
use crate::{DaemonClient, DaemonEventClient, DaemonServer, DaemonServerConfig, TurnRequest};
use satelle_core::session::PublicSession;
use satelle_core::{SatelleEvent, SessionId, TurnId};
use satelle_host::{ApiBearerToken, ApiScopes, HostService, test_support::TestStateDir};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[test]
fn scoped_subscription_sequences_only_events_delivered_to_that_scope() {
    let state = TestStateDir::new().expect("temporary Host state");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic Host service");
    let initialized = service.initialize_daemon().expect("initialize Host state");
    let host_identity = initialized.host_identity().to_string();
    let generated = ApiBearerToken::generate().expect("generate API token");
    let exposed = generated.expose();
    let registry_token = ApiBearerToken::parse(exposed.as_str()).expect("parse registry token");
    let http_token = ApiBearerToken::parse(exposed.as_str()).expect("parse HTTP token");
    let event_token = ApiBearerToken::parse(exposed.as_str()).expect("parse event token");
    service
        .register_api_token(
            &registry_token,
            "principal-scoped-sequence-test",
            ApiScopes::CONTROL,
            None,
        )
        .expect("register API token");

    let server_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("construct server runtime");
    let server = server_runtime
        .block_on(DaemonServer::bind(
            service,
            DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        ))
        .expect("bind loopback daemon");
    let address = server.local_addr();
    let client =
        DaemonClient::loopback(address, http_token, &host_identity).expect("construct HTTP client");
    let event_client = DaemonEventClient::loopback(address, event_token, &host_identity)
        .expect("construct event client");
    let event_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("construct event runtime");

    let target = client
        .create_session(&TurnRequest::new("target initial Turn"), &idempotency_key())
        .expect("create target Session")
        .session()
        .clone();
    let target_session_id = target.session_id().clone();
    wait_for_terminal(&client, &target_session_id);
    let mut stream = event_runtime
        .block_on(
            event_client.connect_events(vec![EventSubscription::Session {
                session_id: target_session_id.clone(),
            }]),
        )
        .expect("subscribe to target Session");

    // These committed events reach the same live receiver but do not match
    // the target Session subscription. They must not consume wire sequence.
    let unrelated = client
        .create_session(&TurnRequest::new("unrelated Turn"), &idempotency_key())
        .expect("create unrelated Session")
        .session()
        .clone();
    wait_for_terminal(&client, unrelated.session_id());

    let admitted = client
        .create_turn(
            &target_session_id,
            &TurnRequest::new("target follow-up Turn"),
            &idempotency_key(),
        )
        .expect("create target follow-up Turn")
        .session()
        .clone();
    let target_turn_id = admitted
        .turns()
        .last()
        .expect("admitted Session contains target Turn")
        .turn_id()
        .clone();
    let events = event_runtime.block_on(read_target_turn_events(&mut stream, &target_turn_id));

    assert_eq!(
        events.iter().map(SatelleEvent::seq).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(events.iter().all(|event| {
        event.session_id() == Some(&target_session_id) && event.turn_id() == Some(&target_turn_id)
    }));

    drop(stream);
    drop(event_client);
    drop(client);
    server_runtime
        .block_on(server.shutdown())
        .expect("shut down daemon");
}

fn wait_for_terminal(client: &DaemonClient, session_id: &SessionId) -> PublicSession {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let session = client
            .read_session(session_id)
            .expect("read Session")
            .session()
            .clone();
        if session
            .turns()
            .last()
            .is_some_and(|turn| turn.state().is_terminal())
        {
            return session;
        }
        assert!(Instant::now() < deadline, "Turn did not become terminal");
        std::thread::sleep(Duration::from_millis(5));
    }
}

async fn read_target_turn_events(
    stream: &mut crate::DaemonEventStream,
    target_turn_id: &TurnId,
) -> Vec<SatelleEvent> {
    let mut events = Vec::new();
    while events.len() < 3 {
        let event = tokio::time::timeout(Duration::from_secs(2), stream.next_event())
            .await
            .expect("target event timeout")
            .expect("read target event");
        if event.turn_id() == Some(target_turn_id) {
            events.push(event);
        }
    }
    events
}

fn idempotency_key() -> String {
    Uuid::now_v7().hyphenated().to_string()
}
