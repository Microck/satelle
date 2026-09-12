//! Explicit diagnostic export contracts. Normal diagnostics never use this
//! module to retain protocol bodies or expand their collection scope.

use crate::{SessionId, TurnId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

pub const RAW_DIAGNOSTICS_SCHEMA_VERSION: &str = "satelle.raw-diagnostics.v1";
pub const RAW_SUBPROCESS_DIAGNOSTICS_SCHEMA_VERSION: &str = "satelle.raw-subprocess-diagnostics.v1";
pub const REDACTION_POLICY_VERSION: &str = "satelle.redaction.v1";
pub const MAX_RAW_PROTOCOL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PENDING_RAW_EXPORTS: usize = 8;
pub const RAW_EXPORT_RETENTION_SECONDS: u64 = 600;
pub const REDACTION_CATEGORIES: &[&str] = &[
    "known_provider_secrets",
    "bearer_tokens",
    "authorization_headers",
    "secret_source_references",
    "provider_credentials",
    "schema_sensitive_fields",
];
pub const RAW_DIAGNOSTIC_RISKS: &[&str] = &[
    "unknown_secrets",
    "prompts",
    "transcripts",
    "provider_payloads",
    "visible_desktop_content",
    "file_paths",
    "user_names",
    "host_names",
    "internal_addresses",
    "other_sensitive_diagnostic_data",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawDiagnosticCommand {
    Run,
    Steer,
}

impl RawDiagnosticCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Steer => "steer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawSubprocessCommand {
    Setup,
    Repair,
}

impl RawSubprocessCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawDiagnosticFailure {
    RedactionFailed,
    StagingFailed,
    ExportFailed,
}

impl RawDiagnosticFailure {
    pub const fn code(self) -> crate::ErrorCode {
        match self {
            Self::RedactionFailed => crate::ErrorCode::RawDiagnosticsRedactionFailed,
            Self::StagingFailed => crate::ErrorCode::RawDiagnosticsStagingFailed,
            Self::ExportFailed => crate::ErrorCode::RawDiagnosticsExportFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RawDiagnosticExportOutcome {
    Exported,
    Failed,
}

impl RawDiagnosticExportOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exported => "exported",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawDiagnosticManifest {
    pub artifact_format_version: String,
    pub source_host: String,
    pub host_identity: String,
    pub command: RawDiagnosticCommand,
    pub session_id: SessionId,
    pub turn_id: TurnId,
    pub included: Vec<String>,
    pub redaction_policy_version: String,
    pub redaction_categories_applied: Vec<String>,
    pub known_unredacted_risk_categories: Vec<String>,
    pub created_at: String,
}

impl RawDiagnosticManifest {
    pub fn new(
        source_host: impl Into<String>,
        host_identity: impl Into<String>,
        command: RawDiagnosticCommand,
        session_id: SessionId,
        turn_id: TurnId,
    ) -> Self {
        Self {
            artifact_format_version: "1".to_string(),
            source_host: source_host.into(),
            host_identity: host_identity.into(),
            command,
            session_id,
            turn_id,
            included: vec!["codex_app_server_protocol_json".to_string()],
            redaction_policy_version: REDACTION_POLICY_VERSION.to_string(),
            redaction_categories_applied: REDACTION_CATEGORIES
                .iter()
                .map(|category| (*category).to_string())
                .collect(),
            known_unredacted_risk_categories: RAW_DIAGNOSTIC_RISKS
                .iter()
                .map(|category| (*category).to_string())
                .collect(),
            created_at: crate::utc_now(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawSubprocessManifest {
    pub artifact_format_version: String,
    pub source_host: String,
    pub host_identity: String,
    pub command: RawSubprocessCommand,
    pub invocation_id: String,
    pub included: Vec<String>,
    pub redaction_policy_version: String,
    pub redaction_categories_applied: Vec<String>,
    pub known_unredacted_risk_categories: Vec<String>,
    pub created_at: String,
}

impl RawSubprocessManifest {
    pub fn new(
        source_host: impl Into<String>,
        host_identity: impl Into<String>,
        command: RawSubprocessCommand,
        invocation_id: impl Into<String>,
    ) -> Self {
        Self {
            artifact_format_version: "1".to_string(),
            source_host: source_host.into(),
            host_identity: host_identity.into(),
            command,
            invocation_id: invocation_id.into(),
            included: vec!["selected_subprocess_stdout".to_string()],
            redaction_policy_version: REDACTION_POLICY_VERSION.to_string(),
            redaction_categories_applied: REDACTION_CATEGORIES
                .iter()
                .map(|category| (*category).to_string())
                .collect(),
            known_unredacted_risk_categories: RAW_DIAGNOSTIC_RISKS
                .iter()
                .map(|category| (*category).to_string())
                .collect(),
            created_at: crate::utc_now(),
        }
    }
}

/// No Debug implementation: redacted subprocess streams remain sensitive.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSubprocessRecord {
    pub command_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub exit_status: Option<i32>,
    pub stdout: String,
}

/// No Debug implementation: redacted subprocess streams remain sensitive.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSubprocessArtifact {
    pub schema_version: String,
    pub manifest: RawSubprocessManifest,
    pub records: Vec<RawSubprocessRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawDiagnosticAuditMetadata {
    pub export_id: String,
    pub source_host: String,
    pub command: RawDiagnosticAuditCommand,
    pub scope_kind: RawDiagnosticAuditScopeKind,
    pub scope_ref: String,
    pub included: Vec<String>,
    pub redaction_policy_version: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawDiagnosticAuditCommand {
    Run,
    Steer,
    Setup,
    Repair,
}

impl RawDiagnosticAuditCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Steer => "steer",
            Self::Setup => "setup",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawDiagnosticAuditScopeKind {
    Turn,
    CommandInvocation,
}

impl RawDiagnosticAuditScopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Turn => "turn",
            Self::CommandInvocation => "command_invocation",
        }
    }
}

impl From<&RawDiagnosticManifest> for RawDiagnosticAuditMetadata {
    fn from(manifest: &RawDiagnosticManifest) -> Self {
        Self {
            export_id: manifest.turn_id.as_str().to_string(),
            source_host: manifest.source_host.clone(),
            command: match manifest.command {
                RawDiagnosticCommand::Run => RawDiagnosticAuditCommand::Run,
                RawDiagnosticCommand::Steer => RawDiagnosticAuditCommand::Steer,
            },
            scope_kind: RawDiagnosticAuditScopeKind::Turn,
            scope_ref: manifest.turn_id.as_str().to_string(),
            included: manifest.included.clone(),
            redaction_policy_version: manifest.redaction_policy_version.clone(),
        }
    }
}

impl From<&RawSubprocessManifest> for RawDiagnosticAuditMetadata {
    fn from(manifest: &RawSubprocessManifest) -> Self {
        Self {
            export_id: manifest.invocation_id.clone(),
            source_host: manifest.source_host.clone(),
            command: match manifest.command {
                RawSubprocessCommand::Setup => RawDiagnosticAuditCommand::Setup,
                RawSubprocessCommand::Repair => RawDiagnosticAuditCommand::Repair,
            },
            scope_kind: RawDiagnosticAuditScopeKind::CommandInvocation,
            scope_ref: manifest.invocation_id.clone(),
            included: manifest.included.clone(),
            redaction_policy_version: manifest.redaction_policy_version.clone(),
        }
    }
}

/// No Debug implementation: even redacted protocol messages remain sensitive.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawProtocolRecord {
    pub direction: ProtocolDirection,
    pub captured_at: String,
    pub message: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDirection {
    ToCodex,
    FromCodex,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawProtocolArtifact {
    pub schema_version: String,
    pub manifest: RawDiagnosticManifest,
    pub records: Vec<RawProtocolRecord>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("diagnostic input is not bounded valid JSON; no artifact was produced")]
pub struct DiagnosticRedactionError;

/// Resolved secrets stay in memory and are erased when the capture ends.
/// Descriptor fields are removed as whole values; discovering a credential
/// reference never causes this redactor to resolve or read it.
#[derive(Default)]
pub struct DiagnosticRedactor {
    known_secrets: Vec<Zeroizing<String>>,
}

impl DiagnosticRedactor {
    pub fn add_known_secret(&mut self, secret: &str) {
        if !secret.is_empty() && !self.known_secrets.iter().any(|known| **known == secret) {
            self.known_secrets.push(Zeroizing::new(secret.to_string()));
            // Redact an overlapping longer secret before any of its prefixes.
            self.known_secrets
                .sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        }
    }

    pub fn redact_json(&self, bytes: &[u8]) -> Result<Value, DiagnosticRedactionError> {
        if bytes.len() > MAX_RAW_PROTOCOL_BYTES {
            return Err(DiagnosticRedactionError);
        }
        let message: Value = serde_json::from_slice(bytes).map_err(|_| DiagnosticRedactionError)?;
        self.redact_message(message, bytes.len())
    }

    /// Redacts one bounded UTF-8 subprocess stream. Invalid text fails closed
    /// because replacing unknown byte sequences could hide secret boundaries.
    pub fn redact_text(&self, bytes: &[u8]) -> Result<String, DiagnosticRedactionError> {
        if bytes.len() > MAX_RAW_PROTOCOL_BYTES {
            return Err(DiagnosticRedactionError);
        }
        let mut text = std::str::from_utf8(bytes)
            .map_err(|_| DiagnosticRedactionError)?
            .to_string();
        for secret in &self.known_secrets {
            text = text.replace(secret.as_str(), "[REDACTED]");
        }
        redact_authorization_text(&mut text);
        redact_sensitive_assignments(&mut text);
        Ok(text)
    }

    /// Redacts a message already parsed by the protocol reader or writer.
    /// `wire_len` keeps the capture limit tied to the original JSON bytes.
    pub fn redact_message(
        &self,
        mut message: Value,
        wire_len: usize,
    ) -> Result<Value, DiagnosticRedactionError> {
        if wire_len > MAX_RAW_PROTOCOL_BYTES {
            return Err(DiagnosticRedactionError);
        }
        self.redact_value(&mut message);
        Ok(message)
    }

    fn redact_value(&self, value: &mut Value) {
        match value {
            Value::Object(fields) => {
                let is_secret_descriptor =
                    fields
                        .get("kind")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| {
                            matches!(
                                kind,
                                "environment" | "file" | "credential-store" | "executable-helper"
                            )
                        });
                // A secret used as an object key must not survive serialization.
                if is_secret_descriptor || fields.keys().any(|name| self.contains_secret(name)) {
                    *value = Value::String("[REDACTED]".to_string());
                    return;
                }
                for (name, field) in fields {
                    if sensitive_field(name) {
                        *field = Value::String("[REDACTED]".to_string());
                    } else {
                        self.redact_value(field);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.redact_value(value);
                }
            }
            Value::String(text) => {
                for secret in &self.known_secrets {
                    if text.contains(secret.as_str()) {
                        *text = text.replace(secret.as_str(), "[REDACTED]");
                    }
                }
                redact_authorization_text(text);
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn contains_secret(&self, text: &str) -> bool {
        self.known_secrets
            .iter()
            .any(|secret| text.contains(secret.as_str()))
    }
}

fn sensitive_field(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "headers"
            | "httpheaders"
            | "apikey"
            | "apitoken"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "bearertoken"
            | "token"
            | "password"
            | "secret"
            | "clientsecret"
            | "credentials"
            | "providercredentials"
            | "providerauth"
            | "authsource"
            | "secretsource"
            | "credentialstore"
            | "privatekey"
            | "privatekeyfile"
            | "clientcertificate"
            | "environment"
            | "env"
    ) || [
        "apikey",
        "apitoken",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "bearertoken",
        "password",
        "secret",
        "clientsecret",
        "credentials",
        "privatekey",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

fn redact_sensitive_assignments(text: &mut String) {
    let mut redacted = String::with_capacity(text.len());
    for segment in text.split_inclusive('\n') {
        let (line, newline) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        let separator = line.find(['=', ':']);
        if let Some(separator) = separator
            && sensitive_field(line[..separator].trim())
        {
            redacted.push_str(&line[..=separator]);
            redacted.push_str("[REDACTED]");
        } else {
            redacted.push_str(line);
        }
        redacted.push_str(newline);
    }
    *text = redacted;
}

fn redact_authorization_text(text: &mut String) {
    // Protocol strings can contain headers even when the surrounding JSON
    // property is not named authorization. ASCII folding preserves byte offsets.
    for scheme in ["bearer ", "basic "] {
        let mut offset = 0;
        while let Some(relative) = text.as_bytes()[offset..]
            .windows(scheme.len())
            .position(|window| window.eq_ignore_ascii_case(scheme.as_bytes()))
        {
            let start = offset + relative + scheme.len();
            let end = text[start..]
                .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\' | ',' | ';'))
                .map_or(text.len(), |length| start + length);
            if start < end {
                text.replace_range(start..end, "[REDACTED]");
                offset = start + "[REDACTED]".len();
            } else {
                offset = start;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_every_declared_secret_category_without_reading_descriptors() {
        let mut redactor = DiagnosticRedactor::default();
        redactor.add_known_secret("PROVIDER_CANARY");
        let message = json!({
            "prompt": "Explain this PROVIDER_CANARY result",
            "nested": [{"apiKey": "CREDENTIAL_CANARY"}],
            "authorization": "Bearer AUTH_CANARY",
            "text": "first bEaReR TOKEN_CANARY; next Basic BASIC_CANARY",
            "reference": {"kind": "file", "path": "/does-not-exist/REFERENCE_CANARY"},
            "hosts": {"demo": {"provider_auth": {"test": "SCHEMA_CANARY"}}},
            "private_key_file": "KEY_CANARY",
            "payload": "remaining prompt and path /home/person are intentionally visible"
        });
        let redacted = redactor
            .redact_json(&serde_json::to_vec(&message).unwrap())
            .unwrap();
        let artifact = serde_json::to_string(&redacted).unwrap();
        assert!(!artifact.contains("CANARY"), "{artifact}");
        assert_eq!(redacted["prompt"], "Explain this [REDACTED] result");
        assert_eq!(redacted["payload"], message["payload"]);
    }

    #[test]
    fn rejects_malformed_and_excessive_input_without_returning_partial_content() {
        let redactor = DiagnosticRedactor::default();
        assert!(redactor.redact_json(b"{\"secret\":\"CANARY\"").is_err());
        assert!(
            redactor
                .redact_json(&vec![b' '; MAX_RAW_PROTOCOL_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn handles_overlapping_secrets_secret_keys_and_unicode_header_text() {
        let mut redactor = DiagnosticRedactor::default();
        redactor.add_known_secret("token");
        redactor.add_known_secret("token-suffix");
        let message = br#"{"content":"token-suffix","nested":{"token":"value"}}"#;
        let redacted = redactor.redact_json(message).unwrap();
        assert_eq!(
            redacted,
            json!({"content":"[REDACTED]","nested":"[REDACTED]"})
        );
        let mut text = "日本語 Bearer CANARY\nBearER  Basic SECOND".to_string();
        redact_authorization_text(&mut text);
        assert_eq!(text, "日本語 Bearer [REDACTED]\nBearER  Basic [REDACTED]");
    }

    #[test]
    fn redacts_bounded_subprocess_text_and_fails_closed_on_invalid_utf8() {
        let mut redactor = DiagnosticRedactor::default();
        redactor.add_known_secret("KNOWN_CANARY");
        let redacted = redactor
            .redact_text(
                b"ordinary KNOWN_CANARY text\nOPENAI_API_KEY=KEY_CANARY\nAuthorization: custom CANARY\nerror: safe detail\n",
            )
            .unwrap();
        assert_eq!(
            redacted,
            "ordinary [REDACTED] text\nOPENAI_API_KEY=[REDACTED]\nAuthorization:[REDACTED]\nerror: safe detail\n"
        );
        assert!(redactor.redact_text(&[0xff]).is_err());
    }
}
