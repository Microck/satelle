use super::RuntimeHandle;
use crate::storage::{
    AdmissionContext, AdmissionOutcome, IDEMPOTENCY_RETENTION, IdempotencyInput,
    IdempotentOperation, LeaseOwner, PrivateRequestToken, Storage,
};
use crate::test_runtime::FakeComputerUseAdapter;
use satelle_core::session::{
    ApprovalPolicy, DesktopBindingRef, DesktopTarget, EffectiveModelRef, ExecutionPolicy,
    ExperimentalFeatureChoices, FeatureChoice, ProviderBindingRef, SandboxPolicy, Session,
    TimeoutPolicy, TurnTransition,
};
use satelle_core::{ErrorCode, SessionId, TurnId};

#[test]
fn normal_status_use_hides_and_deletes_expired_session_metadata() {
    let (state, storage, session_id) = expired_session_fixture();
    drop(storage);

    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter);
    let error = runtime
        .status(session_id)
        .expect_err("expired Session must be absent on normal status use");
    assert_eq!(ErrorCode::SessionNotFound, error.code);
    assert_eq!(0, runtime.snapshot().unwrap().session_count());
}

#[test]
fn due_retention_failure_blocks_status_and_logs_and_rolls_back() {
    let (state, storage, session_id) = expired_session_fixture();
    storage
        .connection_for_test()
        .execute_batch(&format!(
            "CREATE TRIGGER fail_runtime_retention BEFORE DELETE ON sessions
             WHEN OLD.session_id = '{}'
             BEGIN
                 SELECT RAISE(ABORT, 'forced runtime retention failure');
             END;",
            session_id.as_str()
        ))
        .expect("install retention failure fixture");
    let rows_before = retention_row_counts(&storage, &session_id);
    let expired_through_before = expired_through_cursor(&storage);
    drop(storage);

    let runtime = RuntimeHandle::new(Ok(state.path().to_path_buf()), FakeComputerUseAdapter);
    let status_error = runtime
        .status(session_id.clone())
        .expect_err("status must fail closed when due retention fails");
    assert_eq!(ErrorCode::HostUnreachable, status_error.code);
    let logs_error = runtime
        .log_page(&crate::LogPageQuery::default())
        .expect_err("logs must fail closed when due retention fails");
    assert_eq!(ErrorCode::HostUnreachable, logs_error.code);
    drop(runtime);

    let (storage, _) = Storage::open(state.path()).expect("reopen rolled-back storage");
    assert_eq!(rows_before, retention_row_counts(&storage, &session_id));
    assert_eq!(expired_through_before, expired_through_cursor(&storage));
}

fn expired_session_fixture() -> (crate::TestStateDir, Storage, SessionId) {
    let state = crate::TestStateDir::new().expect("temporary state directory should exist");
    let (mut storage, _) = Storage::open(state.path()).expect("open storage");
    let observed_at = time::OffsetDateTime::now_utc();
    let terminal_at = observed_at - time::Duration::days(8);
    let started_at = terminal_at - time::Duration::seconds(1);
    let session_id = SessionId::new();
    let turn_id = TurnId::new();
    let initial = Session::start(
        session_id.clone(),
        storage.host_identity().expect("load Host Identity"),
        DesktopBindingRef::new("desktop-binding-retention").unwrap(),
        turn_id.clone(),
        execution_policy(),
        started_at,
    )
    .unwrap();
    let context = AdmissionContext::new(
        LeaseOwner::new(
            "operation-retention",
            std::process::id(),
            "process-start-retention",
            "boot-retention",
            started_at,
        )
        .unwrap(),
        IdempotencyInput::new(
            "principal-retention",
            IdempotentOperation::Run,
            "runtime-retention",
            "operation-retention",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1,
            1,
            started_at,
            started_at + IDEMPOTENCY_RETENTION,
        )
        .unwrap(),
        PrivateRequestToken::new("request-retention").unwrap(),
    );
    let AdmissionOutcome::Execute {
        session: admitted, ..
    } = storage
        .begin_session(&initial, &context)
        .expect("admit retention fixture")
    else {
        panic!("new Session admission must execute");
    };
    storage
        .commit_lifecycle(
            &session_id,
            &turn_id,
            satelle_core::session::ExpectedRevisions::new(
                admitted.session_state_revision(),
                admitted
                    .turn(&turn_id)
                    .expect("fixture Turn")
                    .turn_state_revision(),
            ),
            TurnTransition::Completed,
            terminal_at,
        )
        .expect("complete retention fixture");
    (state, storage, session_id)
}

fn retention_row_counts(storage: &Storage, session_id: &SessionId) -> [i64; 4] {
    ["sessions", "turns", "idempotency_records", "logs"].map(|table| {
        storage
            .connection_for_test()
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE session_id = ?1"),
                [session_id.as_str()],
                |row| row.get(0),
            )
            .expect("count retained Session rows")
    })
}

fn expired_through_cursor(storage: &Storage) -> i64 {
    storage
        .connection_for_test()
        .query_row(
            "SELECT expired_through_cursor FROM log_retention_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("load log retention cursor")
}

fn execution_policy() -> ExecutionPolicy {
    ExecutionPolicy::new(
        EffectiveModelRef::new("model-retention").unwrap(),
        ProviderBindingRef::new("provider-retention").unwrap(),
        DesktopTarget::new(DesktopBindingRef::new("desktop-binding-retention").unwrap()),
        ApprovalPolicy::OnRequest,
        SandboxPolicy::WorkspaceWrite,
        TimeoutPolicy::bounded_seconds(120).unwrap(),
        ExperimentalFeatureChoices::new(FeatureChoice::Enabled, FeatureChoice::Disabled),
    )
}
