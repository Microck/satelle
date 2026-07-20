use super::*;
use crate::{LiveEventReceiveError, LogEvent, LogPageQuery, LogSubject};
use satelle_core::session::TurnExecutionMode;

#[test]
fn daemon_reconnect_restores_current_state_and_cursor_logs_without_event_replay() {
    let state = crate::TestStateDir::new().expect("temporary state directory");
    let service = HostService::local_demo_for_tests_at(state.path())
        .expect("construct deterministic service");
    let initialized = service.initialize_daemon().expect("initialize daemon");
    let token = ApiBearerToken::generate().expect("generate API token");
    let principal = service
        .register_api_token(&token, "principal-reconnect", ApiScopes::CONTROL, None)
        .expect("register durable token");
    let first_prompt = "PRIVATE_RECONNECT_FIRST_PROMPT";
    let first_intent = TurnIntent::new(first_prompt, TurnExecutionMode::Standard)
        .expect("construct first Turn intent");
    let first_authority = MutationAuthority::new(principal, "01890a5d-ac96-7b7c-8f89-37c3d0a66ea0")
        .expect("construct first authority");

    let first = service
        .admit_run(&first_intent, &first_authority)
        .expect("admit first Turn");
    service
        .runtime
        .wait_for_background()
        .expect("finish first Turn");
    let first_turn_id = first.turns()[0].turn_id().clone();
    let first_log_page = service
        .daemon_log_page(
            &LogPageQuery::forward(None, 100)
                .expect("valid first log query")
                .with_session(first.session_id().clone()),
        )
        .expect("read first Turn logs");
    let reconnect_cursor = first_log_page.next_cursor();

    let second_prompt = "PRIVATE_RECONNECT_SECOND_PROMPT";
    let second_intent = TurnIntent::new(second_prompt, TurnExecutionMode::Standard)
        .expect("construct follow-up Turn intent");
    let second_authority = MutationAuthority::new(
        first_authority.principal().clone(),
        "01890a5d-ac96-7b7c-8f89-37c3d0a66ea1",
    )
    .expect("construct follow-up authority");
    let admitted_follow_up = service
        .admit_steer(first.session_id(), &second_intent, &second_authority)
        .expect("admit follow-up Turn");
    service
        .runtime
        .wait_for_background()
        .expect("finish follow-up Turn");
    let second_turn_id = admitted_follow_up
        .turns()
        .last()
        .expect("follow-up admission contains its Turn")
        .turn_id()
        .clone();
    let expected_current = service
        .session_status(first.session_id())
        .expect("read current Session before disconnect");
    assert_eq!(expected_current.turns().len(), 2);
    drop(service);

    let restarted =
        HostService::local_demo_for_tests_at(state.path()).expect("construct restarted daemon");
    let restarted_status = restarted
        .initialize_daemon()
        .expect("initialize restarted daemon");
    assert_eq!(
        initialized.host_identity(),
        restarted_status.host_identity()
    );
    let mut live_after_reconnect = restarted
        .subscribe_live_events()
        .expect("subscribe after reconnect");
    let invalid_limit = restarted
        .daemon_session_reconnect(first.session_id(), Some(reconnect_cursor), 0)
        .expect_err("reject an invalid reconnect log limit");
    assert_eq!(invalid_limit.code, satelle_core::ErrorCode::InvalidUsage);
    let reconnect = restarted
        .daemon_session_reconnect(first.session_id(), Some(reconnect_cursor), 100)
        .expect("read reconnect snapshot");

    assert_eq!(reconnect.host_identity(), restarted_status.host_identity());
    assert_eq!(reconnect.session(), &expected_current);
    assert!(reconnect.session().session_id().as_str().starts_with("rs_"));
    assert!(
        reconnect
            .session()
            .turns()
            .iter()
            .all(|turn| turn.turn_id().as_str().starts_with("rt_"))
    );
    assert_eq!(
        reconnect
            .logs()
            .entries()
            .iter()
            .map(|entry| entry.event())
            .collect::<Vec<_>>(),
        [
            LogEvent::FollowUpStarted,
            LogEvent::TurnStateCommitted,
            LogEvent::TurnStateCommitted,
        ]
    );
    assert!(reconnect.logs().entries().iter().all(|entry| {
        matches!(
            entry.subject(),
            LogSubject::Turn {
                session_id,
                turn_id,
                ..
            } if session_id.as_str() == first.session_id().as_str()
                && turn_id.as_str() == second_turn_id.as_str()
        )
    }));
    assert!(matches!(
        live_after_reconnect.try_recv(),
        Err(LiveEventReceiveError::Empty)
    ));

    let foreign_state = crate::TestStateDir::new().expect("second Host state directory");
    let foreign_host =
        HostService::local_demo_for_tests_at(foreign_state.path()).expect("construct second Host");
    foreign_host
        .initialize_daemon()
        .expect("initialize second Host");
    let foreign_error = foreign_host
        .daemon_session_reconnect(first.session_id(), None, 100)
        .expect_err("a different Host cannot return the Session");
    assert_eq!(foreign_error.code, satelle_core::ErrorCode::SessionNotFound);

    let public_wire = serde_json::to_string(&(reconnect.session(), reconnect.logs()))
        .expect("serialize reconnect public values");
    for private_value in [
        first_prompt,
        second_prompt,
        first_authority.idempotency_key(),
        second_authority.idempotency_key(),
    ] {
        assert!(!public_wire.contains(private_value));
    }
    for private_field in [
        "host_alias",
        "upstream_thread_ref",
        "upstream_turn_ref",
        "request_token",
        "events",
    ] {
        assert!(!public_wire.contains(private_field));
    }
    assert!(public_wire.contains(first.session_id().as_str()));
    assert!(public_wire.contains(first_turn_id.as_str()));
    assert!(public_wire.contains(second_turn_id.as_str()));

    let restarted_principal = restarted
        .authenticate_api_token(&token)
        .expect("authenticate durable token after restart")
        .expect("durable token remains active");
    let replay_authority =
        MutationAuthority::new(restarted_principal, first_authority.idempotency_key())
            .expect("reconstruct first authority");
    let replay = restarted
        .admit_run(&first_intent, &replay_authority)
        .expect("replay original admission after restart");
    assert_eq!(replay.session_id(), first.session_id());
    assert_eq!(replay.turns().len(), 1);
    assert_eq!(replay.turns()[0].turn_id(), &first_turn_id);
    assert_eq!(
        replay.turns()[0].state(),
        satelle_core::session::TurnState::Completed
    );
    assert_eq!(
        restarted
            .session_status(first.session_id())
            .expect("read current Session after replay"),
        expected_current
    );
    assert!(matches!(
        live_after_reconnect.try_recv(),
        Err(LiveEventReceiveError::Empty)
    ));
}
