use super::CodexSessionError;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

/// Validates the supported stable Codex approval payload before selecting a
/// response. Unknown methods remain outside this closed dispatcher.
pub(super) fn approval_result(
    method: &str,
    object: &Map<String, Value>,
    auto_approve: bool,
    expected_thread: Option<&str>,
    expected_turn: Option<&str>,
) -> Result<Option<Value>, CodexSessionError> {
    let result = match method {
        "item/commandExecution/requestApproval" => {
            let params: CommandExecutionParams = decode_params(object)?;
            correlate_turn(
                expected_thread,
                expected_turn,
                &params.thread_id,
                &params.turn_id,
            )?;
            json!({"decision": if auto_approve { "accept" } else { "decline" }})
        }
        "item/fileChange/requestApproval" => {
            let params: FileChangeParams = decode_params(object)?;
            correlate_turn(
                expected_thread,
                expected_turn,
                &params.thread_id,
                &params.turn_id,
            )?;
            json!({"decision": if auto_approve { "accept" } else { "decline" }})
        }
        "item/permissions/requestApproval" => {
            if auto_approve {
                // A grant can echo only the exact supported permission
                // vocabulary. Unknown authority must fail closed.
                let params: PermissionsParams = decode_params(object)?;
                correlate_turn(
                    expected_thread,
                    expected_turn,
                    &params.thread_id,
                    &params.turn_id,
                )?;
                let raw_permissions = object
                    .get("params")
                    .and_then(Value::as_object)
                    .and_then(|params| params.get("permissions"))
                    .and_then(Value::as_object)
                    .ok_or(CodexSessionError::MalformedMessage)?;
                json!({"permissions": raw_permissions, "scope": "turn"})
            } else {
                // Standard mode grants nothing, so future permission shapes are
                // safe to deny after authenticating their thread and turn.
                let params: PermissionCorrelationParams = decode_params(object)?;
                correlate_turn(
                    expected_thread,
                    expected_turn,
                    &params.thread_id,
                    &params.turn_id,
                )?;
                json!({"permissions": {}})
            }
        }
        "applyPatchApproval" => {
            let params: ApplyPatchParams = decode_params(object)?;
            correlate_thread(expected_thread, &params.conversation_id)?;
            json!({"decision": if auto_approve { "approved" } else { "denied" }})
        }
        "execCommandApproval" => {
            let params: ExecCommandParams = decode_params(object)?;
            correlate_thread(expected_thread, &params.conversation_id)?;
            json!({"decision": if auto_approve { "approved" } else { "denied" }})
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ComputerUseAuthorization {
    Declined,
    App,
    Script(String),
}

impl ComputerUseAuthorization {
    pub(super) const fn accepted(&self) -> bool {
        !matches!(self, Self::Declined)
    }
}

/// Accepts only a supported Computer Use prompt bound to either an app in the
/// canonical allowlist or an exact-Turn script whose app authority was frozen
/// at admission. Readiness keeps the stricter exact-script and exact-app check.
pub(super) fn computer_use_elicitation_result(
    object: &Map<String, Value>,
    allowed_app_ids: &BTreeSet<String>,
    expected_native_action: Option<(&str, &str)>,
    expected_thread: Option<&str>,
    expected_turn: Option<&str>,
) -> Result<(Value, ComputerUseAuthorization), CodexSessionError> {
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or(CodexSessionError::MalformedMessage)?;
    let thread_id = required_value_string(params, "threadId")?;
    correlate_thread(expected_thread, thread_id)?;
    let turn_matches = params
        .get("turnId")
        .and_then(Value::as_str)
        .zip(expected_turn)
        .is_some_and(|(observed, expected)| observed == expected);
    if params.get("turnId").is_some_and(|turn| !turn.is_null()) && !turn_matches {
        return Err(CodexSessionError::ConflictingIdentity);
    }

    let app_authorized = (params.get("turnId").is_none_or(Value::is_null) || turn_matches)
        && exact_computer_use_app_prompt(params, allowed_app_ids);
    let authorized_script = turn_matches
        .then(|| validated_computer_use_script(params))
        .flatten()
        .filter(|script| {
            expected_native_action.map_or_else(
                || !allowed_app_ids.is_empty(),
                |(expected_script, expected_app_id)| {
                    allowed_app_ids.contains(expected_app_id) && *script == expected_script
                },
            )
        });
    let authorization = if app_authorized {
        ComputerUseAuthorization::App
    } else if let Some(script) = authorized_script {
        ComputerUseAuthorization::Script(script.to_owned())
    } else {
        ComputerUseAuthorization::Declined
    };
    Ok((
        json!({
            "action": if authorization.accepted() { "accept" } else { "decline" },
            "content": null,
            "_meta": null,
        }),
        authorization,
    ))
}

fn validated_computer_use_script(params: &Map<String, Value>) -> Option<&str> {
    const REQUIRED_PARAM_KEYS: [&str; 7] = [
        "_meta",
        "message",
        "mode",
        "requestedSchema",
        "serverName",
        "threadId",
        "turnId",
    ];
    if params.len() != REQUIRED_PARAM_KEYS.len()
        || !REQUIRED_PARAM_KEYS
            .iter()
            .all(|key| params.contains_key(*key))
        || params.get("serverName").and_then(Value::as_str) != Some("node_repl")
        || params.get("mode").and_then(Value::as_str) != Some("form")
        || params.get("message").and_then(Value::as_str)
            != Some("Allow the node_repl MCP server to run tool \"js\"?")
        || params.get("requestedSchema") != Some(&json!({"type": "object", "properties": {}}))
    {
        return None;
    }

    let metadata = params.get("_meta").and_then(Value::as_object)?;
    const REQUIRED_METADATA_KEYS: [&str; 5] = [
        "codex_approval_kind",
        "persist",
        "tool_description",
        "tool_params",
        "tool_params_display",
    ];
    if metadata.len() != REQUIRED_METADATA_KEYS.len()
        || !REQUIRED_METADATA_KEYS
            .iter()
            .all(|key| metadata.contains_key(*key))
        || metadata.get("codex_approval_kind").and_then(Value::as_str) != Some("mcp_tool_call")
        || metadata.get("persist") != Some(&json!(["session", "always"]))
        || !metadata
            .get("tool_description")
            .and_then(Value::as_str)
            .is_some_and(|description| !description.is_empty())
    {
        return None;
    }

    let tool_params = metadata.get("tool_params").and_then(Value::as_object)?;
    let script = tool_params
        .get("code")
        .and_then(Value::as_str)
        .filter(|script| !script.is_empty())?;
    let title = match tool_params.get("title") {
        Some(title) => Some(title.as_str().filter(|title| !title.is_empty())?),
        None => None,
    };
    let expected_param_count = if title.is_some() { 2 } else { 1 };
    if tool_params.len() != expected_param_count {
        return None;
    }

    let display = metadata
        .get("tool_params_display")
        .and_then(Value::as_array)
        .filter(|display| display.len() == expected_param_count)?;
    (exact_tool_param_display(&display[0], "code", script)
        && title.is_none_or(|title| exact_tool_param_display(&display[1], "title", title)))
    .then_some(script)
}

fn exact_tool_param_display(display: &Value, name: &str, value: &str) -> bool {
    let Some(display) = display.as_object() else {
        return false;
    };
    display.len() == 3
        && display.get("name").and_then(Value::as_str) == Some(name)
        && display.get("display_name").and_then(Value::as_str) == Some(name)
        && display.get("value").and_then(Value::as_str) == Some(value)
}

fn exact_computer_use_app_prompt(
    params: &Map<String, Value>,
    allowed_app_ids: &BTreeSet<String>,
) -> bool {
    const REQUIRED_PARAM_KEYS: [&str; 6] = [
        "_meta",
        "message",
        "mode",
        "requestedSchema",
        "serverName",
        "threadId",
    ];
    if !matches!(params.len(), 6 | 7)
        || !REQUIRED_PARAM_KEYS
            .iter()
            .all(|key| params.contains_key(*key))
        || (params.len() == 7 && !params.contains_key("turnId"))
        || !matches!(
            params.get("serverName").and_then(Value::as_str),
            Some("node_repl" | "computer-use")
        )
        || !matches!(
            params.get("mode").and_then(Value::as_str),
            Some("form" | "openai/form")
        )
    {
        return false;
    }
    let Some(metadata) = params.get("_meta").and_then(Value::as_object) else {
        return false;
    };
    if metadata.get("connector_id").and_then(Value::as_str) != Some("computer-use") {
        return false;
    }
    let Some(tool_params) = metadata.get("tool_params").and_then(Value::as_object) else {
        return false;
    };
    if tool_params.len() != 1 {
        return false;
    }
    let Some(app_id) = tool_params.get("app").and_then(Value::as_str) else {
        return false;
    };
    let Some(display) = metadata
        .get("tool_params_display")
        .and_then(Value::as_array)
        .filter(|display| display.len() == 1)
        .and_then(|display| display[0].as_object())
    else {
        return false;
    };
    let display_value = display.get("value").and_then(Value::as_str);
    display_value.is_some()
        && params.get("message").and_then(Value::as_str)
            == display_value
                .map(|value| format!("Allow Codex to use {value}?"))
                .as_deref()
        && allowed_app_ids.contains(app_id)
}

fn required_value_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, CodexSessionError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(CodexSessionError::MalformedMessage)
}

fn decode_params<T: DeserializeOwned>(object: &Map<String, Value>) -> Result<T, CodexSessionError> {
    object
        .get("params")
        .cloned()
        .ok_or(CodexSessionError::MalformedMessage)
        .and_then(|params| {
            serde_json::from_value(params).map_err(|_| CodexSessionError::MalformedMessage)
        })
}

fn correlate_turn(
    expected_thread: Option<&str>,
    expected_turn: Option<&str>,
    observed_thread: &str,
    observed_turn: &str,
) -> Result<(), CodexSessionError> {
    correlate_thread(expected_thread, observed_thread)?;
    expected_turn
        .is_some_and(|expected| expected == observed_turn)
        .then_some(())
        .ok_or(CodexSessionError::ConflictingIdentity)
}

fn correlate_thread(
    expected_thread: Option<&str>,
    observed_thread: &str,
) -> Result<(), CodexSessionError> {
    expected_thread
        .is_some_and(|expected| expected == observed_thread)
        .then_some(())
        .ok_or(CodexSessionError::ConflictingIdentity)
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CommandExecutionParams {
    additional_permissions: Option<RequestPermissionProfile>,
    approval_id: Option<String>,
    available_decisions: Option<Vec<CommandExecutionApprovalDecision>>,
    command: Option<String>,
    command_actions: Option<Vec<CommandAction>>,
    cwd: Option<String>,
    environment_id: Option<String>,
    item_id: String,
    network_approval_context: Option<NetworkApprovalContext>,
    proposed_execpolicy_amendment: Option<Vec<String>>,
    proposed_network_policy_amendments: Option<Vec<NetworkPolicyAmendment>>,
    reason: Option<String>,
    started_at_ms: i64,
    thread_id: String,
    turn_id: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
enum CommandExecutionApprovalDecision {
    Accept,
    AcceptForSession,
    AcceptWithExecpolicyAmendment {
        execpolicy_amendment: Vec<String>,
    },
    ApplyNetworkPolicyAmendment {
        network_policy_amendment: NetworkPolicyAmendment,
    },
    Decline,
    Cancel,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FileChangeParams {
    grant_root: Option<String>,
    item_id: String,
    reason: Option<String>,
    started_at_ms: i64,
    thread_id: String,
    turn_id: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PermissionsParams {
    cwd: String,
    environment_id: Option<String>,
    item_id: String,
    permissions: RequestPermissionProfile,
    reason: Option<String>,
    started_at_ms: i64,
    thread_id: String,
    turn_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionCorrelationParams {
    thread_id: String,
    turn_id: String,
}

/// These fields are decoded to enforce the pinned schema before the original
/// permission map is echoed in a turn-scoped response.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RequestPermissionProfile {
    file_system: Option<AdditionalFileSystemPermissions>,
    network: Option<AdditionalNetworkPermissions>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AdditionalFileSystemPermissions {
    entries: Option<Vec<FileSystemSandboxEntry>>,
    glob_scan_max_depth: Option<NonZeroU32>,
    read: Option<Vec<String>>,
    write: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdditionalNetworkPermissions {
    enabled: Option<bool>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSystemSandboxEntry {
    access: FileSystemAccessMode,
    path: FileSystemPath,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileSystemAccessMode {
    Read,
    Write,
    Deny,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
enum FileSystemPath {
    #[serde(rename = "path")]
    Path { path: String },
    #[serde(rename = "glob_pattern")]
    GlobPattern { pattern: String },
    #[serde(rename = "special")]
    Special { value: FileSystemSpecialPath },
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "kind")]
enum FileSystemSpecialPath {
    #[serde(rename = "root")]
    Root,
    #[serde(rename = "minimal")]
    Minimal,
    #[serde(rename = "project_roots")]
    ProjectRoots { subpath: Option<String> },
    #[serde(rename = "tmpdir")]
    Tmpdir,
    #[serde(rename = "slash_tmp")]
    SlashTmp,
    #[serde(rename = "unknown")]
    Unknown {
        path: String,
        subpath: Option<String>,
    },
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
enum CommandAction {
    #[serde(rename = "read")]
    Read {
        command: String,
        name: String,
        path: String,
    },
    #[serde(rename = "listFiles")]
    ListFiles {
        command: String,
        path: Option<String>,
    },
    #[serde(rename = "search")]
    Search {
        command: String,
        path: Option<String>,
        query: Option<String>,
    },
    #[serde(rename = "unknown")]
    Unknown { command: String },
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkApprovalContext {
    host: String,
    protocol: NetworkApprovalProtocol,
}

#[allow(dead_code)]
#[derive(Deserialize)]
enum NetworkApprovalProtocol {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "https")]
    Https,
    #[serde(rename = "socks5Tcp")]
    Socks5Tcp,
    #[serde(rename = "socks5Udp")]
    Socks5Udp,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyAmendment {
    action: NetworkPolicyRuleAction,
    host: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum NetworkPolicyRuleAction {
    Allow,
    Deny,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ApplyPatchParams {
    call_id: String,
    conversation_id: String,
    file_changes: BTreeMap<String, LegacyFileChange>,
    grant_root: Option<String>,
    reason: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExecCommandParams {
    approval_id: Option<String>,
    call_id: String,
    command: Vec<String>,
    conversation_id: String,
    cwd: String,
    parsed_cmd: Vec<ParsedCommand>,
    reason: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
enum LegacyFileChange {
    #[serde(rename = "add")]
    Add { content: String },
    #[serde(rename = "delete")]
    Delete { content: String },
    #[serde(rename = "update")]
    Update {
        move_path: Option<String>,
        unified_diff: String,
    },
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type")]
enum ParsedCommand {
    #[serde(rename = "read")]
    Read {
        cmd: String,
        name: String,
        path: String,
    },
    #[serde(rename = "list_files")]
    ListFiles { cmd: String, path: Option<String> },
    #[serde(rename = "search")]
    Search {
        cmd: String,
        path: Option<String>,
        query: Option<String>,
    },
    #[serde(rename = "unknown")]
    Unknown { cmd: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn computer_use_app_prompt(app_id: &str) -> Value {
        json!({
            "params": {
                "_meta": {
                    "codex_approval_kind": "mcp_tool_call",
                    "connector_id": "computer-use",
                    "connector_name": "Computer Use",
                    "persist": ["session", "always"],
                    "riskLevel": "low",
                    "tool_params": {"app": app_id},
                    "tool_params_display": [{
                        "name": "app",
                        "display_name": "App",
                        "value": "Firefox"
                    }]
                },
                "message": "Allow Codex to use Firefox?",
                "mode": "openai/form",
                "requestedSchema": {},
                "serverName": "node_repl",
                "threadId": "thread-1",
                "turnId": "turn-1"
            }
        })
    }

    fn computer_use_script_prompt(script: &str, title: &str) -> Value {
        json!({
            "params": {
                "_meta": {
                    "codex_approval_kind": "mcp_tool_call",
                    "persist": ["session", "always"],
                    "tool_description": "Run JavaScript in a persistent Node-backed kernel.",
                    "tool_params": {"code": script, "title": title},
                    "tool_params_display": [
                        {"name": "code", "display_name": "code", "value": script},
                        {"name": "title", "display_name": "title", "value": title}
                    ]
                },
                "message": "Allow the node_repl MCP server to run tool \"js\"?",
                "mode": "form",
                "requestedSchema": {"type": "object", "properties": {}},
                "serverName": "node_repl",
                "threadId": "thread-1",
                "turnId": "turn-1"
            }
        })
    }

    #[test]
    fn admitted_app_policy_authorizes_a_generated_script_for_the_exact_turn() {
        let script = "generated native task script";
        let request = computer_use_script_prompt(script, "Use Calculator");

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::from(["calculator.exe".to_string()]),
                None,
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::Script(script.to_string())
            ))
        );
    }

    #[test]
    fn exact_preapproved_computer_use_script_elicitation_uses_carried_authority() {
        let script = "exact native readiness script";
        let request = computer_use_script_prompt(script, "Activate Microsoft Edge");

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::from(["MSEdge".to_string()]),
                Some((script, "MSEdge")),
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::Script(script.to_string())
            ))
        );
    }

    #[test]
    fn exact_preapproved_computer_use_script_without_optional_title_is_accepted() {
        let script = "exact native readiness script";
        let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
        request["params"]["_meta"]["tool_params"]
            .as_object_mut()
            .unwrap()
            .remove("title");
        request["params"]["_meta"]["tool_params_display"]
            .as_array_mut()
            .unwrap()
            .pop();

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::from(["MSEdge".to_string()]),
                Some((script, "MSEdge")),
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::Script(script.to_string())
            ))
        );
    }

    #[test]
    fn generated_script_authority_requires_an_exact_non_null_turn() {
        let script = "exact native readiness script";
        for turn_id in [Value::Null, json!("different-turn")] {
            let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
            request["params"]["turnId"] = turn_id;

            let result = computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::from(["MSEdge".to_string()]),
                Some((script, "MSEdge")),
                Some("thread-1"),
                Some("turn-1"),
            );
            if request["params"]["turnId"].is_null() {
                assert_eq!(
                    result,
                    Ok((
                        json!({"action": "decline", "content": null, "_meta": null}),
                        ComputerUseAuthorization::Declined,
                    ))
                );
            } else {
                assert_eq!(result, Err(CodexSessionError::ConflictingIdentity));
            }
        }
    }

    #[test]
    fn computer_use_script_elicitation_rejects_changed_or_missing_authority() {
        let script = "exact native readiness script";
        let allowed = BTreeSet::from(["MSEdge".to_string()]);
        let cases = [
            {
                let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
                let tool_params = request["params"]["_meta"]["tool_params"]
                    .as_object_mut()
                    .unwrap();
                let code = tool_params.remove("code").unwrap();
                tool_params.insert("source".to_string(), code);
                request["params"]["_meta"]["tool_params_display"][0]["name"] = json!("source");
                request["params"]["_meta"]["tool_params_display"][0]["display_name"] =
                    json!("source");
                request
            },
            {
                let mut request =
                    computer_use_script_prompt("different script", "Activate Microsoft Edge");
                request["params"]["_meta"]["tool_params_display"][0]["value"] =
                    json!("different script");
                request
            },
            {
                let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
                request["params"]["_meta"]["tool_params"]["extra"] = json!(true);
                request
            },
            {
                let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
                request["params"]["_meta"]["tool_params_display"][0]["value"] =
                    json!("different script");
                request
            },
            {
                let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
                request["params"]["_meta"]["tool_params"]
                    .as_object_mut()
                    .unwrap()
                    .remove("title");
                request
            },
            {
                let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
                request["params"]["_meta"]["tool_params_display"]
                    .as_array_mut()
                    .unwrap()
                    .pop();
                request
            },
            {
                let mut request = computer_use_script_prompt(script, "Activate Microsoft Edge");
                request["params"]["_meta"]["tool_params"]["title"] = json!("");
                request["params"]["_meta"]["tool_params_display"][1]["value"] = json!("");
                request
            },
        ];

        for request in cases {
            assert_eq!(
                computer_use_elicitation_result(
                    request.as_object().unwrap(),
                    &allowed,
                    Some((script, "MSEdge")),
                    Some("thread-1"),
                    Some("turn-1"),
                ),
                Ok((
                    json!({"action": "decline", "content": null, "_meta": null}),
                    ComputerUseAuthorization::Declined
                ))
            );
        }

        let request = computer_use_script_prompt(script, "Activate Microsoft Edge");
        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::new(),
                None,
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "decline", "content": null, "_meta": null}),
                ComputerUseAuthorization::Declined
            ))
        );

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::from(["calculator.exe".to_string()]),
                Some((script, "MSEdge")),
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "decline", "content": null, "_meta": null}),
                ComputerUseAuthorization::Declined
            ))
        );
    }

    #[test]
    fn exact_preapproved_computer_use_app_elicitation_is_accepted() {
        let mut request = computer_use_app_prompt("firefox.exe");
        let allowed = BTreeSet::from(["firefox.exe".to_string()]);

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &allowed,
                None,
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::App
            ))
        );
        request["params"]["_meta"]["riskLevel"] = json!("high");
        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &allowed,
                None,
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::App
            )),
            "risk presentation must not override an exact prior app decision"
        );
    }

    #[test]
    fn exact_preapproved_macos_computer_use_elicitation_is_accepted() {
        let mut request = computer_use_app_prompt("com.apple.Safari");
        request["params"]["serverName"] = json!("computer-use");
        request["params"]["_meta"]["tool_params_display"][0]["value"] = json!("Safari");
        request["params"]["message"] = json!("Allow Codex to use Safari?");

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &BTreeSet::from(["com.apple.Safari".to_string()]),
                None,
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::App
            ))
        );
    }

    #[test]
    fn documented_nullable_turn_and_opaque_metadata_preserve_preapproval() {
        let mut request = computer_use_app_prompt("Firefox");
        request["params"]["turnId"] = Value::Null;
        request["params"]["mode"] = json!("form");
        request["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove("riskLevel");
        request["params"]["_meta"]["protocol_annotation"] = json!("opaque");
        let allowed = BTreeSet::from(["Firefox".to_string()]);

        assert_eq!(
            computer_use_elicitation_result(
                request.as_object().unwrap(),
                &allowed,
                None,
                Some("thread-1"),
                Some("turn-1"),
            ),
            Ok((
                json!({"action": "accept", "content": null, "_meta": null}),
                ComputerUseAuthorization::App
            ))
        );
    }

    #[test]
    fn computer_use_elicitation_declines_unlisted_or_changed_authority() {
        let allowed = BTreeSet::from(["firefox.exe".to_string()]);
        for request in [
            computer_use_app_prompt("other.exe"),
            {
                let mut request = computer_use_app_prompt("firefox.exe");
                request["params"]["_meta"]["connector_id"] = json!("other-connector");
                request
            },
            {
                let mut request = computer_use_app_prompt("firefox.exe");
                request["params"]["_meta"]["tool_params"]["sensitiveAction"] =
                    json!("delete files");
                request
            },
            {
                let mut request = computer_use_app_prompt("firefox.exe");
                request["params"]["undocumentedAuthority"] = json!(true);
                request
            },
            {
                let mut request = computer_use_app_prompt("firefox.exe");
                request["params"]["message"] = json!("Allow a different action?");
                request
            },
        ] {
            assert_eq!(
                computer_use_elicitation_result(
                    request.as_object().unwrap(),
                    &allowed,
                    None,
                    Some("thread-1"),
                    Some("turn-1"),
                ),
                Ok((
                    json!({"action": "decline", "content": null, "_meta": null}),
                    ComputerUseAuthorization::Declined
                ))
            );
        }
    }

    #[test]
    fn every_allowlisted_callback_rejects_a_missing_required_field() {
        let malformed = [
            (
                "item/commandExecution/requestApproval",
                json!({
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1"
                }),
            ),
            (
                "item/fileChange/requestApproval",
                json!({
                    "itemId": "item-1",
                    "threadId": "thread-1",
                    "turnId": "turn-1"
                }),
            ),
            (
                "item/permissions/requestApproval",
                json!({
                    "itemId": "item-1",
                    "permissions": {"network": {"enabled": true}},
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1"
                }),
            ),
            (
                "applyPatchApproval",
                json!({
                    "callId": "call-1",
                    "conversationId": "thread-1"
                }),
            ),
            (
                "execCommandApproval",
                json!({
                    "callId": "call-1",
                    "command": ["true"],
                    "conversationId": "thread-1",
                    "cwd": "/tmp"
                }),
            ),
        ];

        for (method, params) in malformed {
            let request = json!({"params": params});
            let object = request.as_object().unwrap();
            assert_eq!(
                approval_result(method, object, true, Some("thread-1"), Some("turn-1"),),
                Err(CodexSessionError::MalformedMessage),
                "method {method}"
            );
        }
    }

    #[test]
    fn permission_glob_depth_must_fit_the_pinned_positive_uint_type() {
        for invalid_depth in [json!(0), json!(u64::from(u32::MAX) + 1)] {
            let request = json!({
                "params": {
                    "cwd": "/tmp",
                    "itemId": "item-1",
                    "permissions": {
                        "fileSystem": {"globScanMaxDepth": invalid_depth}
                    },
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1"
                }
            });
            assert_eq!(
                approval_result(
                    "item/permissions/requestApproval",
                    request.as_object().unwrap(),
                    true,
                    Some("thread-1"),
                    Some("turn-1"),
                ),
                Err(CodexSessionError::MalformedMessage),
                "depth {invalid_depth}"
            );
        }
    }

    #[test]
    fn every_allowlisted_callback_rejects_unknown_top_level_fields() {
        let cases = [
            (
                "item/commandExecution/requestApproval",
                json!({
                    "itemId": "item-1",
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "undocumentedAuthority": true
                }),
            ),
            (
                "item/fileChange/requestApproval",
                json!({
                    "itemId": "item-1",
                    "startedAtMs": 1,
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "undocumentedAuthority": true
                }),
            ),
            (
                "applyPatchApproval",
                json!({
                    "callId": "call-1",
                    "conversationId": "thread-1",
                    "fileChanges": {},
                    "undocumentedAuthority": true
                }),
            ),
            (
                "execCommandApproval",
                json!({
                    "callId": "call-1",
                    "command": [],
                    "conversationId": "thread-1",
                    "cwd": "/tmp",
                    "parsedCmd": [],
                    "undocumentedAuthority": true
                }),
            ),
        ];

        for (method, params) in cases {
            let request = json!({"params": params});
            assert_eq!(
                approval_result(
                    method,
                    request.as_object().unwrap(),
                    true,
                    Some("thread-1"),
                    Some("turn-1"),
                ),
                Err(CodexSessionError::MalformedMessage),
                "method {method}"
            );
        }
    }
}
