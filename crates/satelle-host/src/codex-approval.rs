use super::CodexSessionError;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::num::NonZeroU32;

/// Validates the pinned Codex 0.144.0 approval payload before selecting a
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
                // A grant can echo only the exact permission vocabulary pinned
                // to this Codex version. Unknown authority must fail closed.
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
