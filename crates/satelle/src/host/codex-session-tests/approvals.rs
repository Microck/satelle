use super::*;

#[test]
fn server_requests_are_classified_correlated_and_declined_without_raw_payloads() {
    let run = run_scenario("server-requests", None, Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.native_approval_requests, 5);
    assert_eq!(run.requests.len(), 13);
    assert_eq!(
        run.requests[5],
        json!({"id": "approval-1", "result": {"decision": "decline"}})
    );
    assert_eq!(
        run.requests[6],
        json!({"id": "file-1", "result": {"decision": "decline"}})
    );
    assert_eq!(
        run.requests[7],
        json!({"id": "permissions-1", "result": {"permissions": {}}})
    );
    assert_eq!(
        run.requests[8],
        json!({"id": "legacy-patch", "result": {"decision": "denied"}})
    );
    assert_eq!(
        run.requests[9],
        json!({"id": "legacy-command", "result": {"decision": "denied"}})
    );
    assert_eq!(
        run.requests[10],
        json!({
            "id": "input-1",
            "error": {
                "code": -32601,
                "message": "server request is not supported by the Satelle adapter"
            }
        })
    );
    assert_eq!(run.requests[11]["error"]["code"], -32601);
    assert_eq!(
        run.requests[12],
        json!({
            "id": 99,
            "error": {
                "code": -32601,
                "message": "server request is not supported by the Satelle adapter"
            }
        })
    );
    let rendered = serde_json::to_string(&run.requests[5..]).unwrap();
    assert!(!rendered.contains("questions"));
    assert!(!rendered.contains("item-"));
}

#[test]
fn approval_observation_matches_the_decline_write_outcome() {
    let run = run_scenario("approval-write-failure", None, Duration::from_secs(3));

    match run.result {
        Err(CodexSessionError::Write) => assert_eq!(run.native_approval_requests, 0),
        Err(CodexSessionError::PrematureExit) => assert_eq!(run.native_approval_requests, 1),
        result => {
            panic!("the fixture must fail at the decline write or the following read: {result:?}")
        }
    }
}

#[test]
fn yolo_approves_only_the_pinned_callback_allowlist_for_the_current_turn() {
    let run = run_yolo_scenario("server-requests", Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.native_approval_requests, 0);
    assert_eq!(run.requests.len(), 13);
    assert_eq!(run.requests[2]["params"]["approvalPolicy"], "never");
    assert_eq!(run.requests[2]["params"]["sandbox"], "danger-full-access");
    assert_eq!(run.requests[4]["params"]["approvalPolicy"], "never");
    assert_eq!(
        run.requests[4]["params"]["sandboxPolicy"],
        json!({"type": "dangerFullAccess"})
    );
    assert_eq!(
        run.requests[5],
        json!({"id": "approval-1", "result": {"decision": "accept"}})
    );
    assert_eq!(
        run.requests[6],
        json!({"id": "file-1", "result": {"decision": "accept"}})
    );
    assert_eq!(
        run.requests[7],
        json!({
            "id": "permissions-1",
            "result": {
                "permissions": {
                    "fileSystem": {"entries": []},
                    "network": {"enabled": true}
                },
                "scope": "turn"
            }
        })
    );
    assert_eq!(
        run.requests[8],
        json!({"id": "legacy-patch", "result": {"decision": "approved"}})
    );
    assert_eq!(
        run.requests[9],
        json!({"id": "legacy-command", "result": {"decision": "approved"}})
    );
    for unsupported in [&run.requests[10], &run.requests[11], &run.requests[12]] {
        assert_eq!(unsupported["error"]["code"], -32601);
    }
}

#[test]
fn yolo_turn_start_rejection_is_typed_as_unsupported_policy() {
    let run = run_yolo_scenario("turn-policy-response-error", Duration::from_secs(3));

    assert_eq!(run.result, Err(CodexSessionError::YoloNotSupported));
}

#[test]
fn yolo_preserves_an_unrelated_turn_start_error() {
    let run = run_yolo_scenario("response-error", Duration::from_secs(3));

    assert_eq!(run.result, Err(CodexSessionError::ResponseError));
}

#[test]
fn yolo_thread_policy_rejection_is_typed_as_unsupported_policy() {
    let run = run_yolo_scenario("thread-policy-response-error", Duration::from_secs(3));

    assert_eq!(run.result, Err(CodexSessionError::YoloNotSupported));
}

#[test]
fn yolo_rejects_permission_profiles_outside_the_pinned_schema() {
    for scenario in ["unsupported-permission", "malformed-permission"] {
        let run = run_yolo_scenario(scenario, Duration::from_secs(3));
        assert_eq!(
            run.result,
            Err(CodexSessionError::MalformedMessage),
            "scenario {scenario}"
        );
    }
}

#[test]
fn standard_mode_denies_an_unsupported_permission_profile() {
    let run = run_scenario("unsupported-permission", None, Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(
        run.requests[5],
        json!({"id": "permissions-unsupported", "result": {"permissions": {}}})
    );
}

#[test]
fn yolo_rejects_a_legacy_callback_for_another_thread() {
    let run = run_yolo_scenario("legacy-server-request-conflict", Duration::from_secs(3));
    assert_eq!(run.result, Err(CodexSessionError::ConflictingIdentity));
}

#[test]
fn partial_policy_override_does_not_activate_the_yolo_allowlist() {
    let run = run_scenario_with_options(
        "server-requests",
        None,
        Duration::from_secs(3),
        "perform the harmless action PRIVATE_PROMPT_CANARY",
        PersistFailure::None,
        ScenarioExecution::new(
            TurnExecutionMode::Standard,
            CodexApprovalPolicy::Never,
            CodexSandboxPolicy::WorkspaceWrite,
        ),
    );

    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.requests[5]["result"]["decision"], "decline");
    assert_eq!(run.requests[6]["result"]["decision"], "decline");
    assert_eq!(run.requests[8]["result"]["decision"], "denied");
    assert_eq!(run.requests[9]["result"]["decision"], "denied");
}

#[test]
fn standard_mode_does_not_activate_yolo_for_an_identical_effective_policy() {
    let run = run_scenario_with_options(
        "server-requests",
        None,
        Duration::from_secs(3),
        "perform the harmless action PRIVATE_PROMPT_CANARY",
        PersistFailure::None,
        ScenarioExecution::new(
            TurnExecutionMode::Standard,
            CodexApprovalPolicy::Never,
            CodexSandboxPolicy::DangerFullAccess,
        ),
    );

    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(run.requests[5]["result"]["decision"], "decline");
    assert_eq!(run.requests[6]["result"]["decision"], "decline");
    assert_eq!(run.requests[7]["result"], json!({"permissions": {}}));
    assert_eq!(run.requests[8]["result"]["decision"], "denied");
    assert_eq!(run.requests[9]["result"]["decision"], "denied");
}

#[test]
fn native_turn_completion_requires_a_successful_correlated_script_item() {
    let success = run_native_scenario("native-task-success", Duration::from_secs(3));
    assert_eq!(success.result, Ok(CodexSessionTerminal::Completed));
    assert_eq!(success.native_approval_requests, 0);
    assert_eq!(
        success.requests[5],
        json!({
            "id": "native-script",
            "result": {
                "action": "accept",
                "content": null,
                "_meta": null
            }
        })
    );

    for scenario in ["native-task-missing", "native-task-failed"] {
        let run = run_native_scenario(scenario, Duration::from_secs(3));
        assert_eq!(
            run.result,
            Err(CodexSessionError::NativeActionUnavailable),
            "scenario {scenario}"
        );
        assert_eq!(run.native_approval_requests, 0);
    }

    let recovered = run_native_scenario("native-task-failed-then-success", Duration::from_secs(3));
    assert_eq!(recovered.result, Ok(CodexSessionTerminal::Completed));

    for scenario in ["native-task-script-conflict", "native-task-thread-conflict"] {
        let run = run_native_scenario(scenario, Duration::from_secs(3));
        assert_eq!(
            run.result,
            Err(CodexSessionError::ConflictingIdentity),
            "scenario {scenario}"
        );
    }
}

#[test]
fn native_turn_accepts_the_official_result_shape_without_duplicate_elicitation() {
    let run = run_native_scenario("native-task-no-approval", Duration::from_secs(3));
    assert_eq!(run.result, Ok(CodexSessionTerminal::Completed));
}
