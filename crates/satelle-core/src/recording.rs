use crate::sensitive_diagnostics::{REDACTION_CATEGORIES, REDACTION_POLICY_VERSION};
use crate::{SessionId, TurnId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::OffsetDateTime;

pub const RECORDING_MANIFEST_SCHEMA_VERSION: &str = "satelle.recording.manifest.v1";
pub const RECORDING_PREFLIGHT_SCHEMA_VERSION: &str = "satelle.recording.preflight.v1";
pub const DEFAULT_RECORDING_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_RECORDING_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

pub const TEXT_RECORDING_RISKS: &[&str] = &[
    "unknown_secrets",
    "full_prompts",
    "full_transcripts",
    "file_paths",
    "user_names",
    "host_names",
    "other_sensitive_turn_data",
];

pub const VISUAL_RECORDING_RISKS: &[&str] = &[
    "visible_application_content",
    "notifications",
    "credentials_visible_on_screen",
    "personal_data_visible_on_screen",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingMode {
    Events,
    Transcript,
    Screenshots,
    Video,
}

impl RecordingMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Transcript => "transcript",
            Self::Screenshots => "screenshots",
            Self::Video => "video",
        }
    }

    pub const fn captures_pixels(self) -> bool {
        matches!(self, Self::Screenshots | Self::Video)
    }

    pub fn known_risks(self) -> Vec<String> {
        let risks = if self.captures_pixels() {
            VISUAL_RECORDING_RISKS
        } else {
            TEXT_RECORDING_RISKS
        };
        risks.iter().map(|risk| (*risk).to_string()).collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingRetention {
    raw: String,
    milliseconds: u64,
}

impl RecordingRetention {
    pub fn parse(value: &str) -> Option<Self> {
        let (count, multiplier) = if let Some(value) = value.strip_suffix("ms") {
            (value, 1)
        } else if let Some(value) = value.strip_suffix('s') {
            (value, 1_000)
        } else if let Some(value) = value.strip_suffix('m') {
            (value, 60_000)
        } else if let Some(value) = value.strip_suffix('h') {
            (value, 60 * 60_000)
        } else {
            (value.strip_suffix('d')?, 24 * 60 * 60_000)
        };
        let milliseconds = count.parse::<u64>().ok()?.checked_mul(multiplier)?;
        (1..=MAX_RECORDING_RETENTION_MS)
            .contains(&milliseconds)
            .then(|| Self {
                raw: value.to_string(),
                milliseconds,
            })
    }

    pub fn from_milliseconds(milliseconds: u64) -> Option<Self> {
        (1..=MAX_RECORDING_RETENTION_MS)
            .contains(&milliseconds)
            .then(|| Self {
                raw: format!("{milliseconds}ms"),
                milliseconds,
            })
    }

    pub fn default_24h() -> Self {
        Self {
            raw: "24h".to_string(),
            milliseconds: DEFAULT_RECORDING_RETENTION_MS,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub const fn milliseconds(&self) -> u64 {
        self.milliseconds
    }
}

impl Serialize for RecordingRetention {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for RecordingRetention {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(
                "recording retention must be a positive ms, s, m, h, or d duration of at most 30d",
            )
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingPolicy {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_modes: BTreeSet<RecordingMode>,
    #[serde(default = "RecordingRetention::default_24h")]
    pub default_retention: RecordingRetention,
    #[serde(default = "RecordingRetention::default_24h")]
    pub max_retention: RecordingRetention,
}

impl Default for RecordingPolicy {
    fn default() -> Self {
        Self {
            allowed_modes: BTreeSet::new(),
            default_retention: RecordingRetention::default_24h(),
            max_retention: RecordingRetention::default_24h(),
        }
    }
}

impl RecordingPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.default_retention.milliseconds() > self.max_retention.milliseconds() {
            return Err("recording.default_retention must not exceed recording.max_retention");
        }
        Ok(())
    }

    pub fn permits(&self, mode: RecordingMode, retention_ms: u64) -> bool {
        self.allowed_modes.contains(&mode)
            && (1..=self.max_retention.milliseconds()).contains(&retention_ms)
    }

    /// A selected profile may reduce capture authority, but it cannot add a
    /// mode or retention window that the Host did not already permit.
    pub fn narrow(&mut self, higher: &Self) {
        self.allowed_modes = self
            .allowed_modes
            .intersection(&higher.allowed_modes)
            .copied()
            .collect();
        let max_milliseconds = self
            .max_retention
            .milliseconds()
            .min(higher.max_retention.milliseconds());
        self.max_retention = RecordingRetention::from_milliseconds(max_milliseconds)
            .expect("validated recording retention remains positive");
        let default_milliseconds = higher
            .default_retention
            .milliseconds()
            .min(max_milliseconds);
        self.default_retention = RecordingRetention::from_milliseconds(default_milliseconds)
            .expect("validated recording retention remains positive");
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingRequest {
    pub mode: RecordingMode,
    pub retention_ms: u64,
    pub source_host: String,
}

impl RecordingRequest {
    pub fn new(mode: RecordingMode, retention_ms: u64, source_host: impl Into<String>) -> Self {
        Self {
            mode,
            retention_ms,
            source_host: source_host.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingPreflight {
    pub schema_version: String,
    pub mode: RecordingMode,
    pub source_host: String,
    pub allowed_modes: BTreeSet<RecordingMode>,
    pub default_retention_ms: u64,
    pub max_retention_ms: u64,
    pub recording_root: String,
    pub retention_ms: u64,
    pub expires_at: String,
    pub redaction_policy_version: String,
    pub known_unredacted_risk_categories: Vec<String>,
}

impl RecordingPreflight {
    pub fn new(
        mode: RecordingMode,
        source_host: impl Into<String>,
        policy: &RecordingPolicy,
        recording_root: impl Into<String>,
        retention_ms: u64,
        observed_at: OffsetDateTime,
    ) -> Option<Self> {
        policy.permits(mode, retention_ms).then(|| Self {
            schema_version: RECORDING_PREFLIGHT_SCHEMA_VERSION.to_string(),
            mode,
            source_host: source_host.into(),
            allowed_modes: policy.allowed_modes.clone(),
            default_retention_ms: policy.default_retention.milliseconds(),
            max_retention_ms: policy.max_retention.milliseconds(),
            recording_root: recording_root.into(),
            retention_ms,
            expires_at: format_timestamp(
                observed_at + time::Duration::milliseconds(retention_ms as i64),
            ),
            redaction_policy_version: REDACTION_POLICY_VERSION.to_string(),
            known_unredacted_risk_categories: mode.known_risks(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingArtifactMetadata {
    pub path: String,
    pub artifact_type: String,
    pub created_at: String,
    pub sha256: String,
    pub byte_size: u64,
    pub retention_state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingManifest {
    pub schema_version: String,
    pub recording_id: String,
    pub mode: RecordingMode,
    pub session_id: SessionId,
    pub turn_id: TurnId,
    pub source_host: String,
    pub created_at: String,
    pub manifest_path: String,
    pub artifacts: Vec<RecordingArtifactMetadata>,
    pub expires_at: String,
    pub cleanup_command: String,
    pub redaction_policy_version: String,
    pub redaction_categories_applied: Vec<String>,
    pub known_unredacted_risk_categories: Vec<String>,
}

impl RecordingManifest {
    // The arguments mirror the closed public manifest. Grouping them in a
    // second builder type would only move this required data one layer away.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recording_id: impl Into<String>,
        mode: RecordingMode,
        session_id: SessionId,
        turn_id: TurnId,
        source_host: impl Into<String>,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        manifest_path: impl Into<String>,
        artifacts: Vec<RecordingArtifactMetadata>,
        cleanup_command: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: RECORDING_MANIFEST_SCHEMA_VERSION.to_string(),
            recording_id: recording_id.into(),
            mode,
            session_id,
            turn_id,
            source_host: source_host.into(),
            created_at: format_timestamp(created_at),
            manifest_path: manifest_path.into(),
            artifacts,
            expires_at: format_timestamp(expires_at),
            cleanup_command: cleanup_command.into(),
            redaction_policy_version: REDACTION_POLICY_VERSION.to_string(),
            redaction_categories_applied: REDACTION_CATEGORIES
                .iter()
                .map(|category| (*category).to_string())
                .collect(),
            known_unredacted_risk_categories: mode.known_risks(),
        }
    }
}

pub fn format_timestamp(value: OffsetDateTime) -> String {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC recording timestamps are RFC 3339 representable")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_to_disabled_and_profiles_only_narrow() {
        let mut host = RecordingPolicy {
            allowed_modes: [RecordingMode::Events, RecordingMode::Transcript]
                .into_iter()
                .collect(),
            default_retention: RecordingRetention::parse("24h").unwrap(),
            max_retention: RecordingRetention::parse("7d").unwrap(),
        };
        let profile = RecordingPolicy {
            allowed_modes: [RecordingMode::Events].into_iter().collect(),
            default_retention: RecordingRetention::parse("12h").unwrap(),
            max_retention: RecordingRetention::parse("24h").unwrap(),
        };
        host.narrow(&profile);
        assert!(host.permits(RecordingMode::Events, 24 * 60 * 60 * 1_000));
        assert!(!host.permits(RecordingMode::Transcript, 1));

        let mut disabled = RecordingPolicy::default();
        disabled.narrow(&host);
        assert!(disabled.allowed_modes.is_empty());
    }

    #[test]
    fn retention_is_finite_bounded_and_round_trips() {
        assert!(RecordingRetention::parse("0s").is_none());
        assert!(RecordingRetention::parse("forever").is_none());
        assert!(RecordingRetention::parse("31d").is_none());
        let retention = RecordingRetention::parse("24h").unwrap();
        assert_eq!(retention.milliseconds(), DEFAULT_RECORDING_RETENTION_MS);
        assert_eq!(serde_json::to_string(&retention).unwrap(), "\"24h\"");
    }
}
