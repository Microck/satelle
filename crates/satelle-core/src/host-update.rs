use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HostUpdateSchemaVersion {
    #[serde(rename = "satelle.host.update.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateComponent {
    Host,
    Codex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateTarget {
    HostDaemon,
    HostDaemonService,
    CodexRuntime,
    CodexNativeComputerUse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateDisposition {
    Current,
    Install,
    Update,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateRestartImpact {
    None,
    HostDaemon,
    CodexRuntime,
    NativeComputerUse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostUpdateVersionSource {
    InvokingCliRelease,
    CodexCompatibilityRequirement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexComponentOwnership {
    CodexOwned,
    Ambiguous,
}

/// Typed Host evidence used to plan Codex-owned updates. Raw probe output does
/// not cross this boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CodexUpdateEvidence {
    pub ownership: CodexComponentOwnership,
    pub runtime_current_version: Option<String>,
    pub native_component_current_version: Option<String>,
    pub required_version: String,
    pub runtime_update_required: bool,
    pub native_update_required: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdateMutation {
    pub operation: String,
    pub remote_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdateTargetPlan {
    pub target: HostUpdateTarget,
    pub current_version: Option<String>,
    pub target_version: String,
    pub version_source: HostUpdateVersionSource,
    pub disposition: HostUpdateDisposition,
    pub restart_impact: HostUpdateRestartImpact,
    pub remote_mutations: Vec<HostUpdateMutation>,
}

impl HostUpdateTargetPlan {
    pub fn requires_mutation(&self) -> bool {
        !self.remote_mutations.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUpdateReport {
    pub schema_version: HostUpdateSchemaVersion,
    pub host: String,
    pub checked_components: Vec<HostUpdateComponent>,
    pub targets: Vec<HostUpdateTargetPlan>,
    pub confirmation_required: bool,
}

impl HostUpdateReport {
    pub fn new(
        host: impl Into<String>,
        checked_components: Vec<HostUpdateComponent>,
        targets: Vec<HostUpdateTargetPlan>,
    ) -> Self {
        let confirmation_required = targets.iter().any(HostUpdateTargetPlan::requires_mutation);
        Self {
            schema_version: HostUpdateSchemaVersion::V1,
            host: host.into(),
            checked_components,
            targets,
            confirmation_required,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairCompatibilityReason {
    Missing,
    Corrupted,
    Unsupported,
    BelowMinimumVersion,
    ControlPlaneIncompatible,
    NativeReadinessBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairUpgradeDisposition {
    NotNeeded,
    Required,
    ManualActionRequired,
    RecommendHostUpdate,
}
