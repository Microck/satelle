use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod authority;
#[path = "control-plane.rs"]
pub mod control_plane;
#[path = "daemon-service.rs"]
pub mod daemon_service;
#[path = "direct-host-binding.rs"]
mod direct_host_binding;
mod events;
pub mod ids;
mod profiles;
#[path = "project-config.rs"]
mod project_config;
#[path = "secure-file.rs"]
mod secure_file;
pub mod session;

pub use authority::{
    ApiPermissionScope, ApiPrincipalModel, ArtifactExportPolicy, AuthoritativeStateSubject,
    AuthorityModelError, AuthorityRoles, BridgeBoundary, BridgeControlPlane, ClientAuthority,
    ClientAuthorizationBoundary, ComputerUseHostPlatform, ControllerAuthority, ControllerPlatform,
    ControllerSurface, CorePublicModel, DaemonOsAccount, DeploymentBoundary,
    ExecutionPolicyAuthority, GoalAuthority, HostAuthorityModel, HostDaemonAccountAuthority,
    HostDaemonIdentityAuthority, HostDaemonResponsibility, HostDesktopBindingCardinality,
    LifecycleAuthorityModel, OpenComputerUseRole, OperatorAuthority, PhaseOneConformance,
    PhaseOneContractFreeze, PhaseOneSubject, PlatformSupport, PrincipalRef,
    ProductAuthorityBoundary, ProductDifferentiator, PublicPayloadGuard, SatelleHost,
    SessionMappingAuthority, SessionWorkflow, TurnCardinalityAuthority, UpstreamRuntimeBoundary,
};
pub use control_plane::{
    ControlPlaneCapability, ControlPlaneCapabilitySet, ControlPlaneFailureReason,
    ControlPlaneOperation, IncompatibleControlPlaneDetails, IncompatibleControlPlaneDetailsError,
};
pub use direct_host_binding::{
    ApiTokenSource, DirectHostBinding, DirectHostBindingError, SshHostBinding, SshHostBindingError,
};
pub use events::{
    EVENT_SCHEMA_VERSION, EventSource, EventStateSubject, EventSubject, EventType, SatelleEvent,
    SatelleEventBody, SatelleEventError,
};
pub use ids::{IdParseError, SESSION_ID_PATTERN, SessionId, TurnId};
pub use profiles::{ProfileField, ProfileSelectionSource, SelectedProfile};
pub use secure_file::{
    OwnerOnlyDirectory, SecureFileError, open_new_owner_only_file,
    open_or_create_owner_only_directory, open_or_create_owner_only_file, open_owner_only_directory,
    persist_new_owner_only_secret_file, read_bounded_regular_file_no_follow,
    read_owner_controlled_config_file, read_owner_only_secret_config_file,
    read_owner_only_secret_file, read_trusted_ca_bundle_file,
};

pub const PRODUCT_NAME: &str = "Satelle";
pub const CLI_NAME: &str = "satelle";
pub const LOCAL_DEMO_HOST: &str = "local-demo";
pub const BEACON_CORAL: &str = "#FF5E5B";
pub const ORBIT_INK: &str = "#0F0D17";
pub const PLATINUM: &str = "#D6D8E0";
pub const RELAY_ROSE: &str = "#FF8FB1";
pub const SUCCESS_GREEN: &str = "#A6E22E";
pub const ERROR_RED: &str = "#FF4D6D";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SatelleConfig {
    pub default_host: Option<String>,
    pub model_alias: Option<String>,
    pub provider_alias: Option<String>,
    pub experimental_provider_computer_use: Option<bool>,
    pub yolo: Option<bool>,
    pub command_history: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_rate_limits: Option<ApiRateLimits>,
    #[serde(default)]
    pub hosts: BTreeMap<String, HostConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trusted_profiles: BTreeMap<String, TrustedProfile>,
}

impl SatelleConfig {
    pub fn defaults() -> Self {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            LOCAL_DEMO_HOST.to_string(),
            HostConfig {
                transport: TransportKind::Local,
                adapter: AdapterKind::Codex,
                address: None,
                network: None,
                timeouts: None,
                native_readiness_cache_ttl: None,
                provider_smoke_success_cache_ttl: None,
                provider_smoke_failure_cache_ttl: None,
                daemon_idle_timeout: None,
                desktop_user: None,
                desktop_session_preference: None,
                desktop_session_native_selector: None,
                daemon_home: None,
                daemon_config_file: None,
                daemon_state_dir: None,
                daemon_cache_dir: None,
                daemon_log_dir: None,
                setup_mode: None,
                experimental_provider_computer_use: None,
                yolo: None,
                allow_project_selection: false,
                expected_host_id: None,
                api_token: None,
                ca_bundle: None,
                provider_auth: BTreeMap::new(),
            },
        );

        Self {
            default_host: Some(LOCAL_DEMO_HOST.to_string()),
            model_alias: None,
            provider_alias: None,
            experimental_provider_computer_use: None,
            yolo: None,
            command_history: None,
            api_rate_limits: None,
            hosts,
            trusted_profiles: BTreeMap::new(),
        }
    }

    pub fn merge(mut self, higher: SatelleConfig) -> Self {
        if higher.default_host.is_some() {
            self.default_host = higher.default_host;
        }
        if higher.model_alias.is_some() {
            self.model_alias = higher.model_alias;
        }
        if higher.provider_alias.is_some() {
            self.provider_alias = higher.provider_alias;
        }
        if higher.experimental_provider_computer_use.is_some() {
            self.experimental_provider_computer_use = higher.experimental_provider_computer_use;
        }
        if higher.yolo.is_some() {
            self.yolo = higher.yolo;
        }
        if higher.command_history.is_some() {
            self.command_history = higher.command_history;
        }
        if higher.api_rate_limits.is_some() {
            self.api_rate_limits = higher.api_rate_limits;
        }

        for (alias, host) in higher.hosts {
            self.hosts.insert(alias, host);
        }
        for (name, profile) in higher.trusted_profiles {
            self.trusted_profiles.insert(name, profile);
        }

        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiRateLimits {
    #[serde(default = "default_failed_auth_attempts_per_minute")]
    failed_auth_attempts_per_minute: NonZeroUsize,
    #[serde(default = "default_authenticated_requests_per_minute")]
    authenticated_requests_per_minute: NonZeroUsize,
    #[serde(default = "default_control_requests_per_minute")]
    control_requests_per_minute: NonZeroUsize,
    #[serde(default = "default_websocket_inbound_messages_per_minute")]
    websocket_inbound_messages_per_minute: NonZeroUsize,
}

impl ApiRateLimits {
    pub const fn new(
        failed_auth_attempts_per_minute: NonZeroUsize,
        authenticated_requests_per_minute: NonZeroUsize,
        control_requests_per_minute: NonZeroUsize,
        websocket_inbound_messages_per_minute: NonZeroUsize,
    ) -> Self {
        Self {
            failed_auth_attempts_per_minute,
            authenticated_requests_per_minute,
            control_requests_per_minute,
            websocket_inbound_messages_per_minute,
        }
    }

    pub const fn failed_auth_attempts_per_minute(self) -> usize {
        self.failed_auth_attempts_per_minute.get()
    }

    pub const fn authenticated_requests_per_minute(self) -> usize {
        self.authenticated_requests_per_minute.get()
    }

    pub const fn control_requests_per_minute(self) -> usize {
        self.control_requests_per_minute.get()
    }

    pub const fn websocket_inbound_messages_per_minute(self) -> usize {
        self.websocket_inbound_messages_per_minute.get()
    }
}

impl Default for ApiRateLimits {
    fn default() -> Self {
        Self::new(
            default_failed_auth_attempts_per_minute(),
            default_authenticated_requests_per_minute(),
            default_control_requests_per_minute(),
            default_websocket_inbound_messages_per_minute(),
        )
    }
}

fn default_failed_auth_attempts_per_minute() -> NonZeroUsize {
    NonZeroUsize::new(10).expect("the default failed-authentication rate is nonzero")
}

fn default_authenticated_requests_per_minute() -> NonZeroUsize {
    NonZeroUsize::new(600).expect("the default authenticated request rate is nonzero")
}

fn default_control_requests_per_minute() -> NonZeroUsize {
    NonZeroUsize::new(120).expect("the default control request rate is nonzero")
}

fn default_websocket_inbound_messages_per_minute() -> NonZeroUsize {
    NonZeroUsize::new(120).expect("the default WebSocket inbound message rate is nonzero")
}

/// Durable user-owned consent for an exact set of hosts and mutation workflows.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedProfile {
    pub hosts: BTreeSet<String>,
    pub command_families: BTreeSet<MutationCommandFamily>,
}

/// The complete MVP vocabulary that a Trusted Profile can authorize.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MutationCommandFamily {
    Setup,
    Repair,
    HostUpdate,
    SelfUpdateRemotes,
    DoctorFix,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub transport: TransportKind,
    pub adapter: AdapterKind,
    pub address: Option<String>,
    pub network: Option<NetworkConfig>,
    pub timeouts: Option<TimeoutConfig>,
    pub native_readiness_cache_ttl: Option<ExplicitDuration>,
    pub provider_smoke_success_cache_ttl: Option<ExplicitDuration>,
    pub provider_smoke_failure_cache_ttl: Option<ExplicitDuration>,
    pub daemon_idle_timeout: Option<ExplicitDuration>,
    pub desktop_user: Option<String>,
    pub desktop_session_preference: Option<DesktopSessionPreference>,
    pub desktop_session_native_selector: Option<DesktopSessionNativeSelector>,
    pub daemon_home: Option<PathBuf>,
    pub daemon_config_file: Option<PathBuf>,
    pub daemon_state_dir: Option<PathBuf>,
    pub daemon_cache_dir: Option<PathBuf>,
    pub daemon_log_dir: Option<PathBuf>,
    pub setup_mode: Option<SetupMode>,
    pub experimental_provider_computer_use: Option<bool>,
    pub yolo: Option<bool>,
    #[serde(default)]
    pub allow_project_selection: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token: Option<ApiTokenSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle: Option<PathBuf>,
    #[serde(default)]
    pub provider_auth: BTreeMap<String, ProviderSecretSource>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupMode {
    OnDemand,
    Persistent,
}

impl SetupMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnDemand => "on_demand",
            Self::Persistent => "persistent",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutConfig {
    pub native_readiness: Option<ExplicitDuration>,
    pub provider_smoke_test: Option<ExplicitDuration>,
    pub turn_execution: Option<TurnExecutionDuration>,
}

impl TimeoutConfig {
    fn merge(mut self, higher: TimeoutConfig) -> Self {
        if higher.native_readiness.is_some() {
            self.native_readiness = higher.native_readiness;
        }
        if higher.provider_smoke_test.is_some() {
            self.provider_smoke_test = higher.provider_smoke_test;
        }
        if let Some(higher_timeout) = higher.turn_execution {
            let current_limit = self.turn_execution.as_ref().map_or(
                DEFAULT_TURN_EXECUTION_TIMEOUT_MS,
                TurnExecutionDuration::milliseconds,
            );
            if higher_timeout.milliseconds() < current_limit {
                self.turn_execution = Some(higher_timeout);
            }
        }
        self
    }

    fn default_profile_overlay(profile: TimeoutConfig) -> Self {
        Self {
            native_readiness: profile.native_readiness,
            provider_smoke_test: profile.provider_smoke_test,
            turn_execution: profile
                .turn_execution
                .filter(|duration| duration.milliseconds() < DEFAULT_TURN_EXECUTION_TIMEOUT_MS),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DesktopSessionPreference {
    Only,
    Console,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DesktopSessionNativeSelector {
    pub platform: String,
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProviderSecretSource {
    Environment { variable: String },
    File { path: PathBuf },
    CredentialStore { service: String, account: String },
    HostStore { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplicitDuration {
    raw: String,
    milliseconds: u64,
}

impl ExplicitDuration {
    pub fn parse(value: &str) -> Option<Self> {
        parse_duration_millis(value).map(|milliseconds| Self {
            raw: value.to_string(),
            milliseconds,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn milliseconds(&self) -> u64 {
        self.milliseconds
    }
}

pub const DEFAULT_TURN_EXECUTION_TIMEOUT_MS: u64 = 30 * 60 * 1_000;
pub const MAX_TURN_EXECUTION_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;

/// A finite Turn deadline. It deliberately has its own grammar so supporting
/// hour-scale prompt execution does not broaden unrelated probe timeouts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnExecutionDuration {
    raw: String,
    seconds: u32,
}

impl TurnExecutionDuration {
    pub fn parse(value: &str) -> Option<Self> {
        let seconds = parse_turn_execution_seconds(value)?;
        if seconds > MAX_TURN_EXECUTION_TIMEOUT_MS / 1_000 {
            return None;
        }
        Some(Self {
            raw: value.to_string(),
            seconds: u32::try_from(seconds).ok()?,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn milliseconds(&self) -> u64 {
        u64::from(self.seconds) * 1_000
    }

    pub fn seconds(&self) -> u32 {
        self.seconds
    }
}

impl Serialize for TurnExecutionDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for TurnExecutionDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(
                "Turn execution timeout values require s, m, or h units and must not exceed 24h",
            )
        })
    }
}

impl Serialize for ExplicitDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ExplicitDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| {
            serde::de::Error::custom("duration values require explicit units such as 120s or 2m")
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransportKind {
    Local,
    Direct,
    Ssh,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterKind {
    Codex,
    #[cfg(any(test, feature = "test-support"))]
    Fake,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "kebab-case")]
pub enum NetworkConfig {
    Tailscale {
        tailnet_name: Option<String>,
        hostname: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SatellePathSet {
    pub config_file: PathBuf,
    pub cache_root: PathBuf,
    pub state_root: PathBuf,
    pub sqlite_store: PathBuf,
    pub operator_log_root: PathBuf,
    pub recording_root: PathBuf,
    pub project_config_file: PathBuf,
    pub install_receipt: PathBuf,
    pub sources: SatellePathSources,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SatellePathSources {
    pub config_file: PathSource,
    pub cache_root: PathSource,
    pub state_root: PathSource,
    pub sqlite_store: PathSource,
    pub operator_log_root: PathSource,
    pub recording_root: PathSource,
    pub project_config_file: PathSource,
    pub install_receipt: PathSource,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathSource {
    OsDefault,
    SatelleHome,
    ExplicitEnvironment,
    ProjectDiscovery,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub config: SatelleConfig,
    pub user_config_path: PathBuf,
    pub project_config_path: PathBuf,
    pub selected_profile: Option<SelectedProfile>,
    // The overlay follows the eventual host selection. Keeping it intact avoids mutating every
    // configured host before SATELLE_HOST or --host chooses one.
    #[serde(skip)]
    profile_overlay: Option<profiles::ProfileConfig>,
    #[serde(skip)]
    default_host_requires_project_permission: bool,
    // Preserve user authorization separately from shared project intent so only the exact
    // user-level Host Binding can permit implicit project selection.
    #[serde(skip)]
    project_selectable_hosts: BTreeSet<String>,
    // Config-check enumeration retains only selectors discovered from already validated files.
    // Effective HostConfig values continue to have a single owner in `config`.
    #[serde(skip)]
    config_check_metadata: ConfigCheckMetadata,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ConfigCheckMetadata {
    configured_hosts: Vec<String>,
    configured_profiles: Vec<(String, profiles::ProfileConfig)>,
    base_default_host: String,
    project_defaults: Option<(String, String)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigCheckContext {
    pub host: String,
    pub profile: Option<String>,
    pub source: String,
}

impl ResolvedConfig {
    pub fn resolve_host(
        &self,
        flag_host: Option<&str>,
    ) -> Result<(String, HostConfig), SatelleError> {
        let environment_host = optional_non_empty_env("SATELLE_HOST");
        let alias = flag_host
            .map(str::to_string)
            .or_else(|| environment_host.clone())
            .or_else(|| self.config.default_host.clone())
            .unwrap_or_else(|| LOCAL_DEMO_HOST.to_string());

        let mut host = self
            .config
            .hosts
            .get(&alias)
            .cloned()
            .ok_or_else(|| SatelleError::host_not_found(alias.clone()))?;

        if flag_host.is_none()
            && environment_host.is_none()
            && self.default_host_requires_project_permission
            && !self.project_selectable_hosts.contains(&alias)
        {
            return Err(SatelleError::project_host_selection_not_allowed(alias));
        }

        if let (Some(profile), Some(selected)) = (&self.profile_overlay, &self.selected_profile) {
            profile.apply_to_host(&alias, &mut host, selected.source);
        }

        Ok((alias, host))
    }

    pub fn profile_overrides_for_host(&self, field: ProfileField, host: &str) -> bool {
        match (&self.profile_overlay, &self.selected_profile) {
            (Some(profile), Some(selected)) => {
                profile.overrides_for_host(field, host, selected.source)
            }
            _ => false,
        }
    }

    pub fn config_check_contexts(
        &self,
        flag_host: Option<&str>,
        all: bool,
    ) -> Result<Vec<ConfigCheckContext>, SatelleError> {
        let (selected_host, _) = self.resolve_host(flag_host)?;
        let selected_profile = self
            .selected_profile
            .as_ref()
            .map(|profile| profile.name.clone());

        if !all {
            let source = self
                .selected_profile
                .as_ref()
                .map_or("default", |profile| profile.source.as_str());
            return Ok(vec![ConfigCheckContext {
                host: selected_host,
                profile: selected_profile,
                source: source.to_string(),
            }]);
        }

        let mut contexts = vec![ConfigCheckContext {
            host: selected_host,
            profile: selected_profile,
            source: "default_context".to_string(),
        }];

        contexts.extend(
            self.config_check_metadata
                .configured_hosts
                .iter()
                .map(|host| ConfigCheckContext {
                    host: host.clone(),
                    profile: None,
                    source: "configured_host".to_string(),
                }),
        );

        for (profile_name, profile) in &self.config_check_metadata.configured_profiles {
            let host = profile
                .selected_host()
                .unwrap_or(&self.config_check_metadata.base_default_host);
            let mut effective_host = self
                .config
                .hosts
                .get(host)
                .cloned()
                .ok_or_else(|| SatelleError::host_not_found(host.to_string()))?;
            profile.apply_to_host(host, &mut effective_host, ProfileSelectionSource::CliFlag);
            contexts.push(ConfigCheckContext {
                host: host.to_string(),
                profile: Some(profile_name.clone()),
                source: "configured_profile".to_string(),
            });
        }

        if let Some((project_host, profile_name)) = &self.config_check_metadata.project_defaults {
            let profile = self
                .config_check_metadata
                .configured_profiles
                .iter()
                .find_map(|(name, profile)| (name == profile_name).then_some(profile))
                .ok_or_else(|| {
                    SatelleError::profile_not_found(
                        &self.user_config_path,
                        profile_name,
                        self.config_check_metadata
                            .configured_profiles
                            .iter()
                            .map(|(name, _)| name.clone())
                            .collect(),
                    )
                })?;
            let host = profile.selected_host().unwrap_or(project_host);
            let mut effective_host = self
                .config
                .hosts
                .get(host)
                .cloned()
                .ok_or_else(|| SatelleError::host_not_found(host.to_string()))?;
            if !self.project_selectable_hosts.contains(host) {
                return Err(SatelleError::project_host_selection_not_allowed(
                    host.to_string(),
                ));
            }
            profile.apply_to_host(
                host,
                &mut effective_host,
                ProfileSelectionSource::ProjectConfig,
            );
            contexts.push(ConfigCheckContext {
                host: host.to_string(),
                profile: Some(profile_name.clone()),
                source: "project_defaults".to_string(),
            });
        }

        Ok(contexts)
    }
}

pub fn resolve_invocation_profile(
    cwd: &Path,
    flag_profile: Option<&str>,
) -> Result<Option<SelectedProfile>, SatelleError> {
    let Some(selected_profile) = profiles::select_profile(flag_profile, None, None) else {
        return Ok(None);
    };
    let user_config_path = resolve_path_set(cwd)?.config_file;
    let user_config = read_user_config_file(&user_config_path)?;
    selected_profile_definition(user_config.as_ref(), &user_config_path, &selected_profile)?;
    Ok(Some(selected_profile))
}

pub fn load_user_api_rate_limits(user_config_path: &Path) -> Result<ApiRateLimits, SatelleError> {
    Ok(read_user_config_file(user_config_path)?
        .and_then(|config| config.config.api_rate_limits)
        .unwrap_or_default())
}

pub fn load_config(cwd: &Path, flag_profile: Option<&str>) -> Result<ResolvedConfig, SatelleError> {
    let paths = resolve_path_set(cwd)?;
    let user_config_path = paths.config_file;
    let project_config_path = paths.project_config_file;

    let mut config = SatelleConfig::defaults();
    let user_config = read_user_config_file(&user_config_path)?;
    let project_config = project_config::read(&project_config_path)?;
    let user_bound_hosts = user_config
        .as_ref()
        .map(|config| config.config.hosts.keys().cloned().collect())
        .unwrap_or_default();
    let project_selectable_hosts = user_config
        .as_ref()
        .map(|config| {
            config
                .config
                .hosts
                .iter()
                .filter_map(|(alias, host)| host.allow_project_selection.then_some(alias.clone()))
                .collect()
        })
        .unwrap_or_default();
    let mut default_host_requires_project_permission = project_config
        .as_ref()
        .is_some_and(project_config::ParsedProjectConfig::selects_default_host);

    if let Some(user_config) = &user_config {
        config = config.merge(user_config.config.clone());
    }
    if let Some(project_config) = &project_config {
        config = project_config.apply_to(
            config,
            &user_bound_hosts,
            &user_config_path,
            &project_config_path,
        )?;
    }

    let configured_hosts = config.hosts.keys().cloned().collect();
    let default_host_without_profile = config
        .default_host
        .clone()
        .unwrap_or_else(|| LOCAL_DEMO_HOST.to_string());
    let configured_profiles = user_config
        .as_ref()
        .map(|user_config| {
            user_config
                .profiles
                .iter()
                .map(|(name, profile)| (name.clone(), profile.clone()))
                .collect()
        })
        .unwrap_or_default();
    let project_defaults = project_config.as_ref().and_then(|project_config| {
        let host = project_config.default_host()?;
        let profile_name = project_config.default_profile.as_deref()?;
        Some((host.to_string(), profile_name.to_string()))
    });

    let selected_profile = profiles::select_profile(
        flag_profile,
        user_config
            .as_ref()
            .and_then(|config| config.default_profile.as_deref()),
        project_config
            .as_ref()
            .and_then(|config| config.default_profile.as_deref()),
    );
    let profile_overlay = if let Some(selected) = &selected_profile {
        let profile =
            selected_profile_definition(user_config.as_ref(), &user_config_path, selected)?;
        if let Some(profile_host) = profile.selected_host() {
            if selected.source == profiles::ProfileSelectionSource::ProjectConfig {
                project_config::validate_selected_profile_host(
                    profile_host,
                    &user_bound_hosts,
                    &user_config_path,
                    &project_config_path,
                )?;
            }
            default_host_requires_project_permission =
                selected.source == profiles::ProfileSelectionSource::ProjectConfig;
        }
        profile.apply_to_base(&mut config, selected.source);
        Some(profile)
    } else {
        None
    };

    Ok(ResolvedConfig {
        config,
        user_config_path,
        project_config_path,
        selected_profile,
        profile_overlay,
        default_host_requires_project_permission,
        project_selectable_hosts,
        config_check_metadata: ConfigCheckMetadata {
            configured_hosts,
            configured_profiles,
            base_default_host: default_host_without_profile,
            project_defaults,
        },
    })
}

pub fn resolve_path_set(cwd: &Path) -> Result<SatellePathSet, SatelleError> {
    let project_dirs = ProjectDirs::from("dev", "Microck", "Satelle")
        .ok_or_else(SatelleError::platform_directories_unavailable)?;
    let satelle_home = optional_absolute_env_path("SATELLE_HOME")?;
    let config_override = optional_absolute_env_path("SATELLE_CONFIG_FILE")?;
    let state_override = optional_absolute_env_path("SATELLE_STATE_DIR")?;
    let cache_override = optional_absolute_env_path("SATELLE_CACHE_DIR")?;
    let log_override = optional_absolute_env_path("SATELLE_LOG_DIR")?;

    let (config_file, config_source) = if let Some(path) = config_override {
        (path, PathSource::ExplicitEnvironment)
    } else if let Some(home) = &satelle_home {
        (
            home.join("config").join("config.toml"),
            PathSource::SatelleHome,
        )
    } else {
        (
            project_dirs.config_dir().join("config.toml"),
            PathSource::OsDefault,
        )
    };

    let (state_root, state_source) = if let Some(path) = state_override {
        (path, PathSource::ExplicitEnvironment)
    } else if let Some(home) = &satelle_home {
        (home.join("state"), PathSource::SatelleHome)
    } else {
        (
            project_dirs
                .state_dir()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| project_dirs.data_local_dir().join("state")),
            PathSource::OsDefault,
        )
    };

    let (cache_root, cache_source) = if let Some(path) = cache_override {
        (path, PathSource::ExplicitEnvironment)
    } else if let Some(home) = &satelle_home {
        (home.join("cache"), PathSource::SatelleHome)
    } else {
        (
            project_dirs.cache_dir().to_path_buf(),
            PathSource::OsDefault,
        )
    };

    let (operator_log_root, operator_log_source) = if let Some(path) = log_override {
        (path, PathSource::ExplicitEnvironment)
    } else if let Some(home) = &satelle_home {
        (home.join("logs"), PathSource::SatelleHome)
    } else {
        #[cfg(target_os = "macos")]
        {
            let base_dirs = directories::BaseDirs::new()
                .ok_or_else(SatelleError::platform_directories_unavailable)?;
            (
                base_dirs
                    .home_dir()
                    .join("Library")
                    .join("Logs")
                    .join("dev.Microck.Satelle"),
                PathSource::OsDefault,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            (state_root.join("logs"), state_source)
        }
    };

    let (recording_root, recording_source) = if let Some(home) = &satelle_home {
        (
            home.join("state").join("recordings"),
            PathSource::SatelleHome,
        )
    } else {
        (state_root.join("recordings"), state_source)
    };
    let project_config_file = find_project_config(cwd);
    let sqlite_store = state_root.join("satelle.sqlite3");
    let install_receipt = state_root.join("install-receipt.json");

    Ok(SatellePathSet {
        config_file,
        cache_root,
        state_root,
        sqlite_store,
        operator_log_root,
        recording_root,
        project_config_file,
        install_receipt,
        sources: SatellePathSources {
            config_file: config_source,
            cache_root: cache_source,
            state_root: state_source,
            sqlite_store: state_source,
            operator_log_root: operator_log_source,
            recording_root: recording_source,
            project_config_file: PathSource::ProjectDiscovery,
            install_receipt: state_source,
        },
    })
}

pub fn user_config_path() -> Result<PathBuf, SatelleError> {
    resolve_path_set(&std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .map(|paths| paths.config_file)
}

pub fn state_dir() -> Result<PathBuf, SatelleError> {
    resolve_path_set(&std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .map(|paths| paths.state_root)
}

fn optional_absolute_env_path(name: &'static str) -> Result<Option<PathBuf>, SatelleError> {
    let Some(raw) = std::env::var_os(name) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }

    let path = PathBuf::from(raw);
    if path.is_absolute() && !path.starts_with("~") {
        return Ok(Some(path));
    }

    Err(SatelleError::path_override_not_absolute(
        name,
        path.display().to_string(),
    ))
}

fn optional_non_empty_env(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn find_project_config(cwd: &Path) -> PathBuf {
    for directory in cwd.ancestors() {
        let candidate = directory.join(".satelle").join("config.toml");
        if candidate.exists() {
            return candidate;
        }
        // A repository-local config may be discovered from any nested working
        // directory, but a parent repository or workspace must not silently
        // supply shared intent across this trust boundary. A `.git` directory
        // or worktree marker is sufficient; Git itself is not required.
        if directory.join(".git").exists() {
            break;
        }
    }

    cwd.join(".satelle").join("config.toml")
}

#[cfg(test)]
mod project_config_discovery_tests {
    use super::*;

    #[test]
    fn git_root_bounds_parent_project_config_discovery() {
        let root = tempfile::tempdir().expect("create project discovery root");
        let parent_config = root.path().join(".satelle").join("config.toml");
        std::fs::create_dir_all(parent_config.parent().expect("parent config directory"))
            .expect("create parent config directory");
        std::fs::write(&parent_config, "default_host = \"parent\"\n")
            .expect("write parent project config");

        let repository = root.path().join("repository");
        let nested = repository.join("nested");
        std::fs::create_dir_all(repository.join(".git")).expect("create Git repository marker");
        std::fs::create_dir_all(&nested).expect("create nested project directory");

        assert_eq!(
            find_project_config(&nested),
            nested.join(".satelle").join("config.toml")
        );
    }

    #[test]
    fn git_root_project_config_is_found_before_the_boundary() {
        let root = tempfile::tempdir().expect("create project discovery root");
        let parent_config = root.path().join(".satelle").join("config.toml");
        std::fs::create_dir_all(parent_config.parent().expect("parent config directory"))
            .expect("create parent config directory");
        std::fs::write(&parent_config, "default_host = \"parent\"\n")
            .expect("write parent project config");

        let repository = root.path().join("repository");
        let repository_config = repository.join(".satelle").join("config.toml");
        std::fs::create_dir_all(
            repository_config
                .parent()
                .expect("repository config directory"),
        )
        .expect("create repository config directory");
        std::fs::write(&repository_config, "default_host = \"repository\"\n")
            .expect("write repository project config");
        std::fs::create_dir_all(repository.join(".git")).expect("create Git repository marker");
        let nested = repository.join("nested");
        std::fs::create_dir_all(&nested).expect("create nested project directory");

        assert_eq!(find_project_config(&nested), repository_config);
    }

    #[test]
    fn project_config_discovery_still_walks_ancestors_without_git() {
        let root = tempfile::tempdir().expect("create project discovery root");
        let project_config = root.path().join(".satelle").join("config.toml");
        std::fs::create_dir_all(project_config.parent().expect("project config directory"))
            .expect("create project config directory");
        std::fs::write(&project_config, "default_host = \"project\"\n")
            .expect("write project config");
        let nested = root.path().join("one").join("two");
        std::fs::create_dir_all(&nested).expect("create nested project directory");

        assert_eq!(find_project_config(&nested), project_config);
    }
}

#[derive(Clone, Debug)]
struct ParsedUserConfig {
    config: SatelleConfig,
    default_profile: Option<String>,
    profiles: BTreeMap<String, profiles::ProfileConfig>,
}

#[cfg(test)]
mod api_rate_limit_config_tests {
    use super::*;

    #[test]
    fn user_config_accepts_all_api_rate_limits_and_defaults_omitted_fields() {
        let parsed = parse_user_config(
            Path::new("/test/config.toml"),
            r#"
[api_rate_limits]
failed_auth_attempts_per_minute = 7
authenticated_requests_per_minute = 321
control_requests_per_minute = 45
websocket_inbound_messages_per_minute = 67
"#,
        )
        .expect("parse user-owned API rate limits");
        let limits = parsed
            .config
            .api_rate_limits
            .expect("retain user-owned API rate limits");

        assert_eq!(limits.failed_auth_attempts_per_minute(), 7);
        assert_eq!(limits.authenticated_requests_per_minute(), 321);
        assert_eq!(limits.control_requests_per_minute(), 45);
        assert_eq!(limits.websocket_inbound_messages_per_minute(), 67);

        let partial = parse_user_config(
            Path::new("/test/config.toml"),
            "[api_rate_limits]\ncontrol_requests_per_minute = 30\n",
        )
        .expect("default omitted API rate limits")
        .config
        .api_rate_limits
        .expect("retain partial user-owned API rate limits");
        assert_eq!(partial.failed_auth_attempts_per_minute(), 10);
        assert_eq!(partial.authenticated_requests_per_minute(), 600);
        assert_eq!(partial.control_requests_per_minute(), 30);
        assert_eq!(partial.websocket_inbound_messages_per_minute(), 120);
    }

    #[test]
    fn user_config_rejects_zero_api_rate_limits() {
        for key in [
            "failed_auth_attempts_per_minute",
            "authenticated_requests_per_minute",
            "control_requests_per_minute",
            "websocket_inbound_messages_per_minute",
        ] {
            let raw = format!("[api_rate_limits]\n{key} = 0\n");
            let error = parse_user_config(Path::new("/test/config.toml"), &raw)
                .expect_err("reject a zero API rate limit");
            assert_eq!(error.code, ErrorCode::ConfigError, "key={key}");
        }
    }

    #[test]
    fn user_rate_limit_loader_reads_only_the_explicit_user_file() {
        let root = tempfile::tempdir().expect("create config root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("secure config root");
        }
        let config_root = root.path().join("config");
        let _config_root =
            open_or_create_owner_only_directory(&config_root).expect("create config boundary");
        let user_config = config_root.join("user.toml");
        let mut user_file =
            open_or_create_owner_only_file(&user_config).expect("create user config");
        std::io::Write::write_all(
            &mut user_file,
            b"[api_rate_limits]\ncontrol_requests_per_minute = 45\n",
        )
        .expect("write user rate policy");
        drop(user_file);
        std::fs::write(
            root.path().join("project.toml"),
            "default_host = \"missing\"\n",
        )
        .expect("write unrelated invalid project selection");

        let limits =
            load_user_api_rate_limits(&user_config).expect("load only user-owned rate policy");
        assert_eq!(limits.control_requests_per_minute(), 45);
    }

    #[test]
    fn higher_user_config_replaces_the_complete_api_rate_policy() {
        let base = parse_user_config(
            Path::new("/test/base.toml"),
            "[api_rate_limits]\nfailed_auth_attempts_per_minute = 25\n",
        )
        .expect("parse base API rate limits")
        .config;
        let higher = parse_user_config(
            Path::new("/test/higher.toml"),
            "[api_rate_limits]\ncontrol_requests_per_minute = 25\n",
        )
        .expect("parse higher API rate limits")
        .config;

        let merged = base
            .merge(higher)
            .api_rate_limits
            .expect("retain higher API rate policy");
        assert_eq!(merged.failed_auth_attempts_per_minute(), 10);
        assert_eq!(merged.authenticated_requests_per_minute(), 600);
        assert_eq!(merged.control_requests_per_minute(), 25);
        assert_eq!(merged.websocket_inbound_messages_per_minute(), 120);
    }
}

#[cfg(test)]
mod trusted_profile_config_tests {
    use super::*;

    const VALID_PROFILE: &str = r#"
[trusted_profiles.maintenance]
hosts = ["office-mac", "render-windows"]
command_families = ["setup", "repair", "host_update", "self_update_remotes", "doctor_fix"]
"#;

    #[test]
    fn trusted_profiles_round_trip_as_durable_typed_user_config() {
        let parsed = parse_user_config(Path::new("/test/config.toml"), VALID_PROFILE)
            .expect("parse trusted profile");
        let profile = parsed
            .config
            .trusted_profiles
            .get("maintenance")
            .expect("retain trusted profile");

        assert_eq!(
            profile.hosts,
            BTreeSet::from(["office-mac".to_string(), "render-windows".to_string()])
        );
        assert_eq!(
            profile.command_families,
            BTreeSet::from([
                MutationCommandFamily::Setup,
                MutationCommandFamily::Repair,
                MutationCommandFamily::HostUpdate,
                MutationCommandFamily::SelfUpdateRemotes,
                MutationCommandFamily::DoctorFix,
            ])
        );

        let encoded = toml::to_string(&parsed.config).expect("serialize trusted profile");
        let decoded: SatelleConfig = toml::from_str(&encoded).expect("deserialize trusted profile");
        assert_eq!(decoded.trusted_profiles, parsed.config.trusted_profiles);
        assert!(!encoded.contains("expires_at"));
    }

    #[test]
    fn trusted_profiles_require_both_explicit_nonempty_allowlists() {
        for (raw, expected_code) in [
            (
                "[trusted_profiles.maintenance]\ncommand_families = [\"setup\"]\n",
                ErrorCode::ConfigError,
            ),
            (
                "[trusted_profiles.maintenance]\nhosts = []\ncommand_families = [\"setup\"]\n",
                ErrorCode::ConfigError,
            ),
            (
                "[trusted_profiles.maintenance]\nhosts = [\"office-mac\"]\n",
                ErrorCode::ConfigError,
            ),
            (
                "[trusted_profiles.maintenance]\nhosts = [\"office-mac\"]\ncommand_families = []\n",
                ErrorCode::ConfigError,
            ),
        ] {
            let error = parse_user_config(Path::new("/test/config.toml"), raw)
                .expect_err("reject missing trusted profile allowlist");
            assert_eq!(error.code, expected_code);
        }
    }

    #[test]
    fn trusted_profile_unknown_keys_precede_required_allowlist_errors() {
        let error = parse_user_config(
            Path::new("/test/config.toml"),
            "[trusted_profiles.maintenance]\nhost = [\"office-mac\"]\n",
        )
        .expect_err("reject misspelled Trusted Profile key first");

        assert_eq!(error.code, ErrorCode::UnknownConfigKey);
        assert_eq!(
            error.details.get("path"),
            Some(&serde_json::json!("trusted_profiles.maintenance.host"))
        );
        assert_eq!(error.details.get("key"), Some(&serde_json::json!("host")));
        assert_eq!(
            error.details.get("suggestion"),
            Some(&serde_json::json!("hosts"))
        );
    }

    #[test]
    fn trusted_profiles_reject_nonexplicit_host_scopes() {
        for scope in ["all", "*", "office-*", "office.*", "project", "default"] {
            let raw = format!(
                "[trusted_profiles.maintenance]\nhosts = [\"{scope}\"]\ncommand_families = [\"setup\"]\n"
            );
            let error = parse_user_config(Path::new("/test/config.toml"), &raw)
                .expect_err("reject unsupported host scope");
            assert_eq!(error.code, ErrorCode::ConfigError);
            assert_eq!(error.details.get("value"), Some(&serde_json::json!(scope)));
        }
    }

    #[test]
    fn trusted_profiles_reject_open_or_future_command_scopes() {
        for scope in ["all", "*", "host_*", "host_.*", "future", "config_repair"] {
            let raw = format!(
                "[trusted_profiles.maintenance]\nhosts = [\"office-mac\"]\ncommand_families = [\"{scope}\"]\n"
            );
            let error = parse_user_config(Path::new("/test/config.toml"), &raw)
                .expect_err("reject unsupported command scope");
            assert_eq!(error.code, ErrorCode::ConfigError);
            assert_eq!(error.details.get("value"), Some(&serde_json::json!(scope)));
        }
    }

    #[test]
    fn trusted_profile_allowlists_reject_environment_interpolation() {
        for (raw, syntax) in [
            (
                "[trusted_profiles.maintenance]\nhosts = [\"${SATELLE_HOST}\"]\ncommand_families = [\"setup\"]\n",
                "${SATELLE_HOST}",
            ),
            (
                "[trusted_profiles.maintenance]\nhosts = [\"office-mac\"]\ncommand_families = [\"$SATELLE_COMMAND_FAMILY\"]\n",
                "$SATELLE_COMMAND_FAMILY",
            ),
        ] {
            let error = parse_user_config(Path::new("/test/config.toml"), raw)
                .expect_err("reject Trusted Profile interpolation");
            assert_eq!(error.code, ErrorCode::ConfigInterpolationNotSupported);
            assert_eq!(
                error.details.get("syntax"),
                Some(&serde_json::json!(syntax))
            );
        }
    }

    #[test]
    fn higher_user_config_replaces_only_the_edited_trusted_profile() {
        let base = parse_user_config(Path::new("/test/base.toml"), VALID_PROFILE)
            .expect("parse base config")
            .config;
        let higher = parse_user_config(
            Path::new("/test/higher.toml"),
            r#"
[trusted_profiles.maintenance]
hosts = ["office-mac"]
command_families = ["doctor_fix"]

[trusted_profiles.deploy]
hosts = ["render-windows"]
command_families = ["host_update"]
"#,
        )
        .expect("parse edited config")
        .config;

        let merged = base.merge(higher);
        assert_eq!(merged.trusted_profiles.len(), 2);
        assert_eq!(
            merged.trusted_profiles["maintenance"].command_families,
            BTreeSet::from([MutationCommandFamily::DoctorFix])
        );
        assert_eq!(
            merged.trusted_profiles["deploy"].hosts,
            BTreeSet::from(["render-windows".to_string()])
        );
    }

    #[test]
    fn project_config_cannot_define_trusted_profiles() {
        let root = tempfile::tempdir().expect("create project config root");
        let path = root.path().join("config.toml");
        std::fs::write(
            &path,
            "[trusted_profiles.maintenance]\nhosts = [\"office-mac\"]\ncommand_families = [\"setup\"]\n",
        )
        .expect("write project config");

        let error = match project_config::read(&path) {
            Err(error) => error,
            Ok(_) => panic!("project config must reject Trusted Profile definitions"),
        };
        assert_eq!(error.code, ErrorCode::ProjectMutationConsentNotAllowed);
        assert_eq!(
            error.details.get("key"),
            Some(&serde_json::json!("trusted_profiles"))
        );

        std::fs::write(
            &path,
            "[trusted_profiles.maintenance]\nhosts = [\"${SATELLE_HOST}\"]\ncommand_families = [\"setup\"]\n",
        )
        .expect("write interpolated project config");
        let error = match project_config::read(&path) {
            Err(error) => error,
            Ok(_) => panic!("project config must reject Trusted Profile definitions"),
        };
        assert_eq!(error.code, ErrorCode::ProjectMutationConsentNotAllowed);
    }
}

fn selected_profile_definition(
    user_config: Option<&ParsedUserConfig>,
    user_config_path: &Path,
    selected_profile: &SelectedProfile,
) -> Result<profiles::ProfileConfig, SatelleError> {
    user_config
        .and_then(|config| config.profiles.get(&selected_profile.name))
        .cloned()
        .ok_or_else(|| {
            let available_profiles = user_config
                .map(|config| config.profiles.keys().cloned().collect())
                .unwrap_or_default();
            SatelleError::profile_not_found(
                user_config_path,
                &selected_profile.name,
                available_profiles,
            )
        })
}

#[cfg(test)]
mod invocation_profile_tests {
    use super::*;

    #[test]
    fn invocation_profile_must_exist_in_the_user_config() {
        let selected = SelectedProfile {
            name: "missing".to_string(),
            source: ProfileSelectionSource::Environment,
        };

        let error = selected_profile_definition(None, Path::new("/test/config.toml"), &selected)
            .expect_err("an invocation-selected profile must be defined by the user");

        assert_eq!(error.code, ErrorCode::ProfileNotFound);
        assert_eq!(
            error.details.get("profile"),
            Some(&serde_json::json!("missing"))
        );
    }
}

fn read_user_config_file(path: &Path) -> Result<Option<ParsedUserConfig>, SatelleError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = read_owner_controlled_config_file(path).map_err(|error| {
        SatelleError::config_error(
            format!(
                "user config file {} does not satisfy the owner security policy",
                path.display()
            ),
            Some(error.to_string()),
        )
    })?;

    parse_user_config(path, &raw).map(Some)
}

fn parse_user_config(path: &Path, raw: &str) -> Result<ParsedUserConfig, SatelleError> {
    let mut value = toml::from_str::<toml::Value>(raw).map_err(|source| {
        SatelleError::config_error(
            format!("could not parse config file {}", path.display()),
            Some(source.to_string()),
        )
    })?;
    let profile_data = profiles::extract_profile_data(path, &mut value, true)?;
    reject_config_composition(path, &value)?;
    reject_trusted_profile_interpolation(path, &value)?;
    reject_interpolation(path, &value)?;
    reject_timeout_config_errors(path, &value)?;
    reject_desktop_session_selector_conflicts(path, &value)?;
    reject_provider_secret_source_errors(path, &value)?;
    reject_unknown_user_config_keys(path, &value)?;
    reject_trusted_profile_errors(path, &value)?;

    let config = value.try_into().map_err(|source: toml::de::Error| {
        SatelleError::config_error(
            format!("could not decode config file {}", path.display()),
            Some(source.to_string()),
        )
    })?;

    Ok(ParsedUserConfig {
        config,
        default_profile: profile_data.default_profile,
        profiles: profile_data.profiles,
    })
}

fn reject_trusted_profile_interpolation(
    path: &Path,
    value: &toml::Value,
) -> Result<(), SatelleError> {
    let Some(trusted_profiles) = value
        .get("trusted_profiles")
        .and_then(toml::Value::as_table)
    else {
        return Ok(());
    };
    let mut interpolations = Vec::new();
    for (name, profile_value) in trusted_profiles {
        let Some(profile) = profile_value.as_table() else {
            continue;
        };
        for key in ["hosts", "command_families"] {
            let Some(values) = profile.get(key).and_then(toml::Value::as_array) else {
                continue;
            };
            for (index, value) in values.iter().enumerate() {
                collect_interpolation_for_value(
                    &format!("trusted_profiles.{name}.{key}[{index}]"),
                    Some(value),
                    &mut interpolations,
                );
            }
        }
    }
    finish_interpolation_check(path, interpolations)
}

fn reject_trusted_profile_errors(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(profiles) = value
        .get("trusted_profiles")
        .and_then(toml::Value::as_table)
    else {
        return Ok(());
    };

    for (name, profile_value) in profiles {
        let profile_path = format!("trusted_profiles.{name}");
        let Some(profile) = profile_value.as_table() else {
            continue;
        };

        let hosts = profile.get("hosts").and_then(toml::Value::as_array);
        if hosts.is_none_or(Vec::is_empty) {
            return Err(SatelleError::trusted_profile_allowlist_required(
                path,
                &profile_path,
                "hosts",
            ));
        }
        for host in hosts.into_iter().flatten().filter_map(toml::Value::as_str) {
            if unsupported_host_scope(host) {
                return Err(SatelleError::unsupported_trusted_profile_scope(
                    path,
                    &format!("{profile_path}.hosts"),
                    host,
                ));
            }
        }

        let commands = profile
            .get("command_families")
            .and_then(toml::Value::as_array);
        if commands.is_none_or(Vec::is_empty) {
            return Err(SatelleError::trusted_profile_allowlist_required(
                path,
                &profile_path,
                "command_families",
            ));
        }
        for command in commands
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
        {
            if !matches!(
                command,
                "setup" | "repair" | "host_update" | "self_update_remotes" | "doctor_fix"
            ) {
                return Err(SatelleError::unsupported_trusted_profile_scope(
                    path,
                    &format!("{profile_path}.command_families"),
                    command,
                ));
            }
        }
    }

    Ok(())
}

fn unsupported_host_scope(host: &str) -> bool {
    host.is_empty()
        || matches!(
            host,
            "all"
                | "all_hosts"
                | "all-hosts"
                | "project"
                | "project_host"
                | "project-host"
                | "default"
                | "default_host"
                | "default-host"
        )
        || host.starts_with("glob:")
        || host.starts_with("regex:")
        || host
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']'))
}

fn reject_config_composition(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };

    for key in ["include", "imports", "extends", "fragments"] {
        if table.contains_key(key) {
            return Err(SatelleError::unsupported_config_composition(path, key));
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigInterpolation {
    pub toml_path: String,
    pub syntax: String,
}

fn reject_interpolation(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };

    let mut interpolations = Vec::new();
    collect_interpolation_for_value(
        "default_host",
        table.get("default_host"),
        &mut interpolations,
    );
    collect_interpolation_for_value("model_alias", table.get("model_alias"), &mut interpolations);
    collect_interpolation_for_value(
        "provider_alias",
        table.get("provider_alias"),
        &mut interpolations,
    );

    let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) else {
        return finish_interpolation_check(path, interpolations);
    };

    for (alias, host_value) in hosts {
        let host_path = format!("hosts.{alias}");
        let Some(host_table) = host_value.as_table() else {
            continue;
        };

        for key in [
            "transport",
            "adapter",
            "address",
            "expected_host_id",
            "ca_bundle",
            "desktop_user",
            "desktop_session_preference",
            "daemon_home",
            "daemon_config_file",
            "daemon_state_dir",
            "daemon_cache_dir",
            "daemon_log_dir",
            "setup_mode",
            "native_readiness_cache_ttl",
            "provider_smoke_success_cache_ttl",
            "provider_smoke_failure_cache_ttl",
            "daemon_idle_timeout",
        ] {
            collect_interpolation_for_value(
                &format!("{host_path}.{key}"),
                host_table.get(key),
                &mut interpolations,
            );
        }

        if let Some(network_table) = host_table.get("network").and_then(toml::Value::as_table) {
            for key in ["provider", "tailnet_name", "hostname"] {
                collect_interpolation_for_value(
                    &format!("{host_path}.network.{key}"),
                    network_table.get(key),
                    &mut interpolations,
                );
            }
        }

        if let Some(timeout_table) = host_table.get("timeouts").and_then(toml::Value::as_table) {
            for key in ["native_readiness", "provider_smoke_test", "turn_execution"] {
                collect_interpolation_for_value(
                    &format!("{host_path}.timeouts.{key}"),
                    timeout_table.get(key),
                    &mut interpolations,
                );
            }
        }

        if let Some(selector_table) = host_table
            .get("desktop_session_native_selector")
            .and_then(toml::Value::as_table)
        {
            for key in ["platform", "kind", "value"] {
                collect_interpolation_for_value(
                    &format!("{host_path}.desktop_session_native_selector.{key}"),
                    selector_table.get(key),
                    &mut interpolations,
                );
            }
        }

        if let Some(provider_auth_table) = host_table
            .get("provider_auth")
            .and_then(toml::Value::as_table)
        {
            for (provider_alias, source_value) in provider_auth_table {
                let source_path = format!("{host_path}.provider_auth.{provider_alias}");
                let Some(source_table) = source_value.as_table() else {
                    continue;
                };

                for key in ["kind", "variable", "path", "service", "account", "name"] {
                    collect_interpolation_for_value(
                        &format!("{source_path}.{key}"),
                        source_table.get(key),
                        &mut interpolations,
                    );
                }
            }
        }

        if let Some(api_token_table) = host_table.get("api_token").and_then(toml::Value::as_table) {
            for key in ["kind", "path"] {
                collect_interpolation_for_value(
                    &format!("{host_path}.api_token.{key}"),
                    api_token_table.get(key),
                    &mut interpolations,
                );
            }
        }
    }

    finish_interpolation_check(path, interpolations)
}

fn collect_interpolation_for_value(
    toml_path: &str,
    value: Option<&toml::Value>,
    interpolations: &mut Vec<ConfigInterpolation>,
) {
    let Some(value) = value.and_then(toml::Value::as_str) else {
        return;
    };
    let Some(syntax) = interpolation_syntax(value) else {
        return;
    };

    interpolations.push(ConfigInterpolation {
        toml_path: toml_path.to_string(),
        syntax,
    });
}

fn finish_interpolation_check(
    path: &Path,
    interpolations: Vec<ConfigInterpolation>,
) -> Result<(), SatelleError> {
    if interpolations.is_empty() {
        Ok(())
    } else {
        Err(SatelleError::config_interpolation_not_supported(
            path,
            interpolations,
        ))
    }
}

fn interpolation_syntax(value: &str) -> Option<String> {
    if let Some(syntax) = unix_braced_interpolation(value) {
        return Some(syntax);
    }
    if let Some(syntax) = unix_plain_interpolation(value) {
        return Some(syntax);
    }
    windows_percent_interpolation(value)
}

fn unix_braced_interpolation(value: &str) -> Option<String> {
    let start = value.find("${")?;
    let rest = &value[start + 2..];
    let end = rest.find('}')?;
    let name = &rest[..end];
    if is_env_name(name) {
        Some(format!("${{{name}}}"))
    } else {
        None
    }
}

fn unix_plain_interpolation(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'$' {
            continue;
        }
        let Some(next) = bytes.get(index + 1).copied() else {
            continue;
        };
        if !(next == b'_' || next.is_ascii_alphabetic()) {
            continue;
        }

        let mut end = index + 2;
        while let Some(byte) = bytes.get(end) {
            if *byte == b'_' || byte.is_ascii_alphanumeric() {
                end += 1;
            } else {
                break;
            }
        }
        return Some(value[index..end].to_string());
    }

    None
}

fn windows_percent_interpolation(value: &str) -> Option<String> {
    let mut start = 0;
    while let Some(offset) = value[start..].find('%') {
        let left = start + offset;
        let right_start = left + 1;
        let right_offset = value[right_start..].find('%')?;
        let right = right_start + right_offset;
        let name = &value[right_start..right];
        if is_env_name(name) {
            return Some(value[left..=right].to_string());
        }
        start = right + 1;
    }

    None
}

fn is_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn reject_timeout_config_errors(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) else {
        return Ok(());
    };

    for (alias, host_value) in hosts {
        let host_path = format!("hosts.{alias}");
        let Some(host_table) = host_value.as_table() else {
            continue;
        };
        if let Some(value) = host_table.get("native_readiness_cache_ttl") {
            let ttl_path = format!("{host_path}.native_readiness_cache_ttl");
            let Some(value) = value.as_str() else {
                return Err(SatelleError::duration_unit_required(path, &ttl_path));
            };
            if ExplicitDuration::parse(value).is_none() {
                return Err(SatelleError::duration_unit_required(path, &ttl_path));
            }
        }
        for key in [
            "provider_smoke_success_cache_ttl",
            "provider_smoke_failure_cache_ttl",
        ] {
            if let Some(value) = host_table.get(key) {
                let ttl_path = format!("{host_path}.{key}");
                let Some(value) = value.as_str() else {
                    return Err(SatelleError::duration_unit_required(path, &ttl_path));
                };
                if ExplicitDuration::parse(value).is_none() {
                    return Err(SatelleError::duration_unit_required(path, &ttl_path));
                }
            }
        }
        if let Some(value) = host_table.get("daemon_idle_timeout") {
            let timeout_path = format!("{host_path}.daemon_idle_timeout");
            let Some(value) = value.as_str() else {
                return Err(SatelleError::duration_unit_required(path, &timeout_path));
            };
            if ExplicitDuration::parse(value).is_none() {
                return Err(SatelleError::duration_unit_required(path, &timeout_path));
            }
        }
        let Some(timeouts) = host_table.get("timeouts").and_then(toml::Value::as_table) else {
            continue;
        };

        for (key, value) in timeouts {
            let timeout_path = format!("{host_path}.timeouts.{key}");
            if !["native_readiness", "provider_smoke_test", "turn_execution"]
                .contains(&key.as_str())
            {
                return Err(SatelleError::unknown_timeout_key(path, &timeout_path, key));
            }

            let Some(value) = value.as_str() else {
                return Err(SatelleError::duration_unit_required(path, &timeout_path));
            };
            if key == "turn_execution" {
                let Some(seconds) = parse_turn_execution_seconds(value) else {
                    return Err(SatelleError::turn_duration_unit_required(
                        path,
                        &timeout_path,
                    ));
                };
                if seconds > MAX_TURN_EXECUTION_TIMEOUT_MS / 1_000 {
                    return Err(SatelleError::turn_timeout_config_limit_exceeded(
                        path,
                        &timeout_path,
                    ));
                }
            } else if ExplicitDuration::parse(value).is_none() {
                return Err(SatelleError::duration_unit_required(path, &timeout_path));
            }
        }
    }

    Ok(())
}

fn reject_provider_secret_source_errors(
    path: &Path,
    value: &toml::Value,
) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) else {
        return Ok(());
    };

    for (alias, host_value) in hosts {
        let host_path = format!("hosts.{alias}");
        let Some(host_table) = host_value.as_table() else {
            continue;
        };
        if let Some(api_token) = host_table.get("api_token").and_then(toml::Value::as_table) {
            let source_path = format!("{host_path}.api_token");
            if let Some(kind) = api_token.get("kind").and_then(toml::Value::as_str)
                && kind != "file"
            {
                return Err(SatelleError::unsupported_secret_source_kind(
                    path,
                    &format!("{source_path}.kind"),
                    kind,
                ));
            }
            if let Some(file_path) = api_token.get("path").and_then(toml::Value::as_str) {
                let parsed = PathBuf::from(file_path);
                if parsed.starts_with("~") || !parsed.is_absolute() {
                    return Err(SatelleError::secret_file_path_not_absolute(
                        path,
                        &format!("{source_path}.path"),
                        file_path,
                    ));
                }
            }
        }
        if let Some(ca_bundle) = host_table.get("ca_bundle").and_then(toml::Value::as_str) {
            let parsed = PathBuf::from(ca_bundle);
            if parsed.starts_with("~") || !parsed.is_absolute() {
                return Err(SatelleError::secret_file_path_not_absolute(
                    path,
                    &format!("{host_path}.ca_bundle"),
                    ca_bundle,
                ));
            }
        }
        let Some(provider_auth) = host_table
            .get("provider_auth")
            .and_then(toml::Value::as_table)
        else {
            continue;
        };

        for (provider_alias, source_value) in provider_auth {
            let source_path = format!("{host_path}.provider_auth.{provider_alias}");
            let Some(source_table) = source_value.as_table() else {
                continue;
            };
            let Some(kind) = source_table.get("kind").and_then(toml::Value::as_str) else {
                continue;
            };

            if !SUPPORTED_SECRET_SOURCE_KINDS.contains(&kind) {
                return Err(SatelleError::unsupported_secret_source_kind(
                    path,
                    &format!("{source_path}.kind"),
                    kind,
                ));
            }

            if kind == "file" {
                let Some(file_path) = source_table.get("path").and_then(toml::Value::as_str) else {
                    continue;
                };
                let parsed = PathBuf::from(file_path);
                if parsed.starts_with("~") || !parsed.is_absolute() {
                    return Err(SatelleError::secret_file_path_not_absolute(
                        path,
                        &format!("{source_path}.path"),
                        file_path,
                    ));
                }
            }
        }
    }

    Ok(())
}

const SUPPORTED_SECRET_SOURCE_KINDS: &[&str] =
    &["environment", "file", "credential-store", "host-store"];

fn reject_desktop_session_selector_conflicts(
    path: &Path,
    value: &toml::Value,
) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) else {
        return Ok(());
    };

    for (alias, host_value) in hosts {
        let Some(host_table) = host_value.as_table() else {
            continue;
        };

        if host_table.contains_key("desktop_session_preference")
            && host_table.contains_key("desktop_session_native_selector")
        {
            return Err(SatelleError::desktop_session_selector_conflict(
                path,
                &format!("hosts.{alias}"),
            ));
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownConfigKey {
    pub toml_path: String,
    pub key: String,
    pub accepted_keys: Vec<String>,
    pub suggestion: Option<String>,
}

fn reject_unknown_user_config_keys(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };

    let mut unknown_keys = Vec::new();
    collect_unknown_keys_for_table(
        "",
        table,
        &[
            "default_host",
            "model_alias",
            "provider_alias",
            "experimental_provider_computer_use",
            "yolo",
            "command_history",
            "api_rate_limits",
            "profile",
            "profiles",
            "hosts",
            "trusted_profiles",
        ],
        &mut unknown_keys,
    );

    if let Some(rate_limits) = table.get("api_rate_limits").and_then(toml::Value::as_table) {
        collect_unknown_keys_for_table(
            "api_rate_limits",
            rate_limits,
            &[
                "failed_auth_attempts_per_minute",
                "authenticated_requests_per_minute",
                "control_requests_per_minute",
                "websocket_inbound_messages_per_minute",
            ],
            &mut unknown_keys,
        );
    }

    if let Some(profiles) = table
        .get("trusted_profiles")
        .and_then(toml::Value::as_table)
    {
        for (name, profile_value) in profiles {
            let Some(profile_table) = profile_value.as_table() else {
                continue;
            };
            collect_unknown_keys_for_table(
                &format!("trusted_profiles.{name}"),
                profile_table,
                &["hosts", "command_families"],
                &mut unknown_keys,
            );
        }
    }

    if let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) {
        for (alias, host_value) in hosts {
            let host_path = format!("hosts.{alias}");
            let Some(host_table) = host_value.as_table() else {
                continue;
            };

            collect_unknown_keys_for_table(
                &host_path,
                host_table,
                &[
                    "transport",
                    "adapter",
                    "address",
                    "network",
                    "timeouts",
                    "native_readiness_cache_ttl",
                    "provider_smoke_success_cache_ttl",
                    "provider_smoke_failure_cache_ttl",
                    "daemon_idle_timeout",
                    "desktop_user",
                    "desktop_session_preference",
                    "desktop_session_native_selector",
                    "daemon_home",
                    "daemon_config_file",
                    "daemon_state_dir",
                    "daemon_cache_dir",
                    "daemon_log_dir",
                    "setup_mode",
                    "experimental_provider_computer_use",
                    "yolo",
                    "allow_project_selection",
                    "expected_host_id",
                    "api_token",
                    "ca_bundle",
                    "provider_auth",
                ],
                &mut unknown_keys,
            );

            if let Some(network_table) = host_table.get("network").and_then(toml::Value::as_table) {
                collect_unknown_keys_for_table(
                    &format!("{host_path}.network"),
                    network_table,
                    &["provider", "tailnet_name", "hostname"],
                    &mut unknown_keys,
                );
            }

            if let Some(selector_table) = host_table
                .get("desktop_session_native_selector")
                .and_then(toml::Value::as_table)
            {
                collect_unknown_keys_for_table(
                    &format!("{host_path}.desktop_session_native_selector"),
                    selector_table,
                    &["platform", "kind", "value"],
                    &mut unknown_keys,
                );
            }

            if let Some(provider_auth_table) = host_table
                .get("provider_auth")
                .and_then(toml::Value::as_table)
            {
                for (provider_alias, source_value) in provider_auth_table {
                    let Some(source_table) = source_value.as_table() else {
                        continue;
                    };
                    collect_unknown_keys_for_table(
                        &format!("{host_path}.provider_auth.{provider_alias}"),
                        source_table,
                        &["kind", "variable", "path", "service", "account", "name"],
                        &mut unknown_keys,
                    );
                }
            }

            if let Some(api_token_table) =
                host_table.get("api_token").and_then(toml::Value::as_table)
            {
                collect_unknown_keys_for_table(
                    &format!("{host_path}.api_token"),
                    api_token_table,
                    &["kind", "path"],
                    &mut unknown_keys,
                );
            }
        }
    }

    if unknown_keys.is_empty() {
        Ok(())
    } else {
        Err(SatelleError::unknown_config_keys(path, unknown_keys))
    }
}

fn parse_duration_millis(value: &str) -> Option<u64> {
    if let Some(milliseconds) = value.strip_suffix("ms") {
        return parse_positive_u64(milliseconds);
    }

    if let Some(seconds) = value.strip_suffix('s') {
        return parse_positive_u64(seconds).map(|seconds| seconds.saturating_mul(1_000));
    }

    if let Some(minutes) = value.strip_suffix('m') {
        return parse_positive_u64(minutes).map(|minutes| minutes.saturating_mul(60_000));
    }

    None
}

fn parse_turn_execution_seconds(value: &str) -> Option<u64> {
    if let Some(seconds) = value.strip_suffix('s') {
        return parse_positive_u64(seconds);
    }
    if let Some(minutes) = value.strip_suffix('m') {
        return parse_positive_u64(minutes)?.checked_mul(60);
    }
    if let Some(hours) = value.strip_suffix('h') {
        return parse_positive_u64(hours)?.checked_mul(60 * 60);
    }
    None
}

fn parse_positive_u64(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|value| *value > 0)
}

#[cfg(test)]
mod pr08_turn_duration_tests {
    use super::*;

    #[test]
    fn turn_duration_hours_do_not_broaden_other_timeout_fields() {
        assert!(ExplicitDuration::parse("1h").is_none());
        assert_eq!(
            TurnExecutionDuration::parse("1h")
                .expect("Turn hours are valid")
                .milliseconds(),
            3_600_000
        );
        assert!(TurnExecutionDuration::parse("500ms").is_none());
        assert!(TurnExecutionDuration::parse("25h").is_none());
    }

    #[test]
    fn project_timeout_overlay_only_shortens_the_user_limit() {
        let base = TimeoutConfig {
            native_readiness: None,
            provider_smoke_test: None,
            turn_execution: TurnExecutionDuration::parse("10m"),
        };
        let longer = TimeoutConfig {
            native_readiness: None,
            provider_smoke_test: None,
            turn_execution: TurnExecutionDuration::parse("20m"),
        };
        let shorter = TimeoutConfig {
            native_readiness: None,
            provider_smoke_test: None,
            turn_execution: TurnExecutionDuration::parse("5m"),
        };

        assert_eq!(
            base.clone()
                .merge(longer)
                .turn_execution
                .expect("base limit remains")
                .as_str(),
            "10m"
        );
        assert_eq!(
            base.merge(shorter)
                .turn_execution
                .expect("shorter project limit wins")
                .as_str(),
            "5m"
        );
    }
}

fn collect_unknown_keys_for_table(
    table_path: &str,
    table: &toml::Table,
    accepted_keys: &[&str],
    unknown_keys: &mut Vec<UnknownConfigKey>,
) {
    let accepted = accepted_keys.iter().copied().collect::<BTreeSet<_>>();
    let accepted_values = accepted_keys
        .iter()
        .map(|key| (*key).to_string())
        .collect::<Vec<_>>();

    for key in table.keys() {
        if accepted.contains(key.as_str()) {
            continue;
        }

        unknown_keys.push(UnknownConfigKey {
            toml_path: if table_path.is_empty() {
                key.clone()
            } else {
                format!("{table_path}.{key}")
            },
            key: key.clone(),
            accepted_keys: accepted_values.clone(),
            suggestion: nearest_config_key(key, accepted_keys),
        });
    }
}

fn nearest_config_key(key: &str, accepted_keys: &[&str]) -> Option<String> {
    accepted_keys
        .iter()
        .map(|accepted| (*accepted, edit_distance(key, accepted)))
        .filter(|(_, distance)| *distance <= 3)
        .min_by_key(|(accepted, distance)| (*distance, *accepted))
        .map(|(accepted, _)| accepted.to_string())
}

fn edit_distance(left: &str, right: &str) -> usize {
    let right_len = right.chars().count();
    let mut previous = (0..=right_len).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut current = Vec::with_capacity(right_len + 1);
        current.push(left_index + 1);

        for (right_index, right_char) in right.chars().enumerate() {
            let insertion = current[right_index] + 1;
            let deletion = previous[right_index + 1] + 1;
            let substitution = previous[right_index] + usize::from(left_char != right_char);
            current.push(insertion.min(deletion).min(substitution));
        }

        previous = current;
    }

    previous[right_len]
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    InvalidUsage,
    PromptSourceConflict,
    CompletionInstallFailed,
    CompletionProfileUpdateFailed,
    ConfigError,
    ConfigNotFound,
    UnknownConfigKey,
    ProfileNotFound,
    ProjectProfileDefinitionNotAllowed,
    ConfigInterpolationNotSupported,
    UnknownTimeoutKey,
    DurationUnitRequired,
    UnsupportedConfigComposition,
    ProjectDaemonPathOverrideNotAllowed,
    ProjectDesktopBindingNotAllowed,
    ProjectYoloEnableNotAllowed,
    ProjectExperimentalProviderOptInNotAllowed,
    ProjectMutationConsentNotAllowed,
    ProjectHostBindingNotAllowed,
    ProjectHostSelectionNotAllowed,
    ProjectSecretSourceNotAllowed,
    ProjectCredentialHelperNotAllowed,
    UnsupportedSecretSourceKind,
    SecretFilePathNotAbsolute,
    DesktopSessionSelectorConflict,
    PlatformDirectoriesUnavailable,
    PathOverrideNotAbsolute,
    DaemonPathOverrideNotAbsolute,
    HostNotFound,
    HostUnreachable,
    BootstrapBusy,
    DirectDaemonUnreachable,
    SshHostKeyVerificationRequired,
    CertificateUntrusted,
    CertificateHostnameMismatch,
    CertificateExpired,
    TlsVersionUnsupported,
    TlsHandshakeFailed,
    AuthenticationFailed,
    AuthorizationInsufficientScope,
    HostIdentityMismatch,
    HostBusy,
    StoreInUse,
    StateConflict,
    StopNotConfirmed,
    IdempotencyKeyConflict,
    RemoteExecution,
    StorageBusy,
    StorageIntegrityFailed,
    IncompatibleControlPlane,
    ComputerUseNotReady,
    NativeReadinessTimeout,
    ProviderSmokeTestTimeout,
    UnsupportedProviderComputerUse,
    DoctorReadinessBlockersFound,
    DoctorRefreshScopeRequired,
    DoctorRefreshTimeoutWithoutRefresh,
    SessionNotFound,
    EventsWithDetach,
    InterruptModeConflict,
    OutputModeConflict,
    LogTailLimitExceeded,
    LogPositionConflict,
    LogsCursorExpired,
    CapacityExceeded,
    ConcurrencyLimitExceeded,
    ConcurrencyWithoutRemoteUpdate,
    ComponentSelectionConflict,
    UnsupportedUpdateComponent,
    PersistentServiceUnsupported,
    SetupConsentRequired,
    DoctorFixConsentRequired,
    InputRequired,
    Interrupted,
    NotImplemented,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUsage => "invalid-usage",
            Self::PromptSourceConflict => "prompt-source-conflict",
            Self::CompletionInstallFailed => "completion-install-failed",
            Self::CompletionProfileUpdateFailed => "completion-profile-update-failed",
            Self::ConfigError => "configuration-error",
            Self::ConfigNotFound => "config-not-found",
            Self::UnknownConfigKey => "unknown-config-key",
            Self::ProfileNotFound => "profile-not-found",
            Self::ProjectProfileDefinitionNotAllowed => "project-profile-definition-not-allowed",
            Self::ConfigInterpolationNotSupported => "config-interpolation-not-supported",
            Self::UnknownTimeoutKey => "unknown-timeout-key",
            Self::DurationUnitRequired => "duration-unit-required",
            Self::UnsupportedConfigComposition => "unsupported-config-composition",
            Self::ProjectDaemonPathOverrideNotAllowed => "project-daemon-path-override-not-allowed",
            Self::ProjectDesktopBindingNotAllowed => "project-desktop-binding-not-allowed",
            Self::ProjectYoloEnableNotAllowed => "project-yolo-enable-not-allowed",
            Self::ProjectExperimentalProviderOptInNotAllowed => {
                "project-experimental-provider-opt-in-not-allowed"
            }
            Self::ProjectMutationConsentNotAllowed => "project-mutation-consent-not-allowed",
            Self::ProjectHostBindingNotAllowed => "project-host-binding-not-allowed",
            Self::ProjectHostSelectionNotAllowed => "project-host-selection-not-allowed",
            Self::ProjectSecretSourceNotAllowed => "project-secret-source-not-allowed",
            Self::ProjectCredentialHelperNotAllowed => "project-credential-helper-not-allowed",
            Self::UnsupportedSecretSourceKind => "unsupported-secret-source-kind",
            Self::SecretFilePathNotAbsolute => "secret-file-path-not-absolute",
            Self::DesktopSessionSelectorConflict => "desktop-session-selector-conflict",
            Self::PlatformDirectoriesUnavailable => "platform-directories-unavailable",
            Self::PathOverrideNotAbsolute => "path-override-not-absolute",
            Self::DaemonPathOverrideNotAbsolute => "daemon-path-override-not-absolute",
            Self::HostNotFound => "host-not-found",
            Self::HostUnreachable => "host-unreachable",
            Self::BootstrapBusy => "bootstrap-busy",
            Self::DirectDaemonUnreachable => "direct-daemon-unreachable",
            Self::SshHostKeyVerificationRequired => "ssh-host-key-verification-required",
            Self::CertificateUntrusted => "certificate-untrusted",
            Self::CertificateHostnameMismatch => "certificate-hostname-mismatch",
            Self::CertificateExpired => "certificate-expired",
            Self::TlsVersionUnsupported => "tls-version-unsupported",
            Self::TlsHandshakeFailed => "tls-handshake-failed",
            Self::AuthenticationFailed => "authentication-failed",
            Self::AuthorizationInsufficientScope => "authorization-insufficient-scope",
            Self::HostIdentityMismatch => "host-identity-mismatch",
            Self::HostBusy => "host-busy",
            Self::StoreInUse => "store-in-use",
            Self::StateConflict => "state-conflict",
            Self::StopNotConfirmed => "stop-not-confirmed",
            Self::IdempotencyKeyConflict => "idempotency-key-conflict",
            Self::RemoteExecution => "remote-execution",
            Self::StorageBusy => "storage-busy",
            Self::StorageIntegrityFailed => "storage-integrity-failed",
            Self::IncompatibleControlPlane => "incompatible-control-plane",
            Self::ComputerUseNotReady => "computer-use-not-ready",
            Self::NativeReadinessTimeout => "native-readiness-timeout",
            Self::ProviderSmokeTestTimeout => "provider-smoke-test-timeout",
            Self::UnsupportedProviderComputerUse => "unsupported-provider-computer-use",
            Self::DoctorReadinessBlockersFound => "doctor-readiness-blockers-found",
            Self::DoctorRefreshScopeRequired => "refresh-scope-required",
            Self::DoctorRefreshTimeoutWithoutRefresh => "refresh-timeout-without-refresh",
            Self::SessionNotFound => "session-not-found",
            Self::EventsWithDetach => "events-with-detach",
            Self::InterruptModeConflict => "interrupt-mode-conflict",
            Self::OutputModeConflict => "output-mode-conflict",
            Self::LogTailLimitExceeded => "log-tail-limit-exceeded",
            Self::LogPositionConflict => "log-position-conflict",
            Self::LogsCursorExpired => "logs-cursor-expired",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::ConcurrencyLimitExceeded => "concurrency-limit-exceeded",
            Self::ConcurrencyWithoutRemoteUpdate => "concurrency-without-remote-update",
            Self::ComponentSelectionConflict => "component-selection-conflict",
            Self::UnsupportedUpdateComponent => "unsupported-update-component",
            Self::PersistentServiceUnsupported => "persistent-service-unsupported",
            Self::SetupConsentRequired => "setup-consent-required",
            Self::DoctorFixConsentRequired => "doctor-fix-consent-required",
            Self::InputRequired => "input-required",
            Self::Interrupted => "interrupted",
            Self::NotImplemented => "not-implemented",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Self::InvalidUsage
            | Self::PromptSourceConflict
            | Self::IdempotencyKeyConflict
            | Self::EventsWithDetach
            | Self::InterruptModeConflict
            | Self::OutputModeConflict
            | Self::LogTailLimitExceeded
            | Self::LogPositionConflict
            | Self::ConcurrencyLimitExceeded
            | Self::ConcurrencyWithoutRemoteUpdate
            | Self::ComponentSelectionConflict
            | Self::UnsupportedUpdateComponent
            | Self::PersistentServiceUnsupported
            | Self::SetupConsentRequired
            | Self::DoctorFixConsentRequired
            | Self::InputRequired
            | Self::DoctorRefreshScopeRequired
            | Self::DoctorRefreshTimeoutWithoutRefresh => 64,
            Self::Interrupted => 130,
            Self::CompletionInstallFailed | Self::CompletionProfileUpdateFailed => 73,
            Self::ConfigError
            | Self::ConfigNotFound
            | Self::UnknownConfigKey
            | Self::ProfileNotFound
            | Self::ProjectProfileDefinitionNotAllowed
            | Self::ConfigInterpolationNotSupported
            | Self::UnknownTimeoutKey
            | Self::DurationUnitRequired
            | Self::UnsupportedConfigComposition
            | Self::ProjectDaemonPathOverrideNotAllowed
            | Self::ProjectDesktopBindingNotAllowed
            | Self::ProjectYoloEnableNotAllowed
            | Self::ProjectExperimentalProviderOptInNotAllowed
            | Self::ProjectMutationConsentNotAllowed
            | Self::ProjectHostBindingNotAllowed
            | Self::ProjectHostSelectionNotAllowed
            | Self::ProjectSecretSourceNotAllowed
            | Self::ProjectCredentialHelperNotAllowed
            | Self::UnsupportedSecretSourceKind
            | Self::SecretFilePathNotAbsolute
            | Self::DesktopSessionSelectorConflict
            | Self::PlatformDirectoriesUnavailable
            | Self::PathOverrideNotAbsolute
            | Self::DaemonPathOverrideNotAbsolute
            | Self::HostNotFound
            | Self::SessionNotFound
            | Self::LogsCursorExpired => 66,
            Self::HostUnreachable | Self::DirectDaemonUnreachable => 69,
            Self::CertificateUntrusted
            | Self::CertificateHostnameMismatch
            | Self::CertificateExpired
            | Self::TlsVersionUnsupported
            | Self::TlsHandshakeFailed
            | Self::SshHostKeyVerificationRequired
            | Self::AuthenticationFailed
            | Self::AuthorizationInsufficientScope
            | Self::HostIdentityMismatch
            | Self::StoreInUse
            | Self::RemoteExecution
            | Self::StorageBusy
            | Self::StorageIntegrityFailed => 74,
            Self::BootstrapBusy
            | Self::CapacityExceeded
            | Self::HostBusy
            | Self::IncompatibleControlPlane
            | Self::ComputerUseNotReady
            | Self::NativeReadinessTimeout
            | Self::ProviderSmokeTestTimeout
            | Self::UnsupportedProviderComputerUse
            | Self::DoctorReadinessBlockersFound
            | Self::StateConflict
            | Self::StopNotConfirmed => 75,
            Self::NotImplemented => 70,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Error, Serialize, Deserialize)]
#[error("{code}: {message}")]
pub struct SatelleError {
    pub code: ErrorCode,
    pub message: String,
    pub recovery_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_detail: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl SatelleError {
    pub fn invalid_usage(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidUsage,
            message: message.into(),
            recovery_command: Some("satelle --help".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn prompt_source_conflict() -> Self {
        Self {
            code: ErrorCode::PromptSourceConflict,
            message: "pass exactly one prompt source: PROMPT_OR_DASH or --prompt-file".to_string(),
            recovery_command: Some(
                "pass a positional prompt, use '-' for standard input, or pass --prompt-file"
                    .to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn provider_smoke_test_timeout() -> Self {
        Self {
            code: ErrorCode::ProviderSmokeTestTimeout,
            message: "the live provider Computer Use smoke test timed out".to_string(),
            recovery_command: Some(
                "rerun the original satelle run or steer command with --refresh-provider-smoke-test"
                    .to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn native_readiness_timeout() -> Self {
        Self {
            code: ErrorCode::NativeReadinessTimeout,
            message: "the native Computer Use readiness smoke test timed out".to_string(),
            recovery_command: Some(
                "satelle doctor --scope computer-use --refresh --json".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn unsupported_provider_computer_use() -> Self {
        Self {
            code: ErrorCode::UnsupportedProviderComputerUse,
            message: "the selected provider does not support native Computer Use".to_string(),
            recovery_command: Some(
                "rerun the original satelle run or steer command with --refresh-provider-smoke-test"
                    .to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn config_error(message: impl Into<String>, source_detail: Option<String>) -> Self {
        Self {
            code: ErrorCode::ConfigError,
            message: message.into(),
            recovery_command: Some("edit the TOML file or run satelle config check".to_string()),
            source_detail,
            details: BTreeMap::new(),
        }
    }

    fn trusted_profile_allowlist_required(
        config_file: &Path,
        profile_path: &str,
        allowlist: &str,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(profile_path.to_string()));
        details.insert(
            "allowlist".to_string(),
            Value::String(allowlist.to_string()),
        );
        Self {
            code: ErrorCode::ConfigError,
            message: format!(
                "config file {} Trusted Profile at {profile_path} requires a non-empty {allowlist} allowlist",
                config_file.display()
            ),
            recovery_command: Some(format!(
                "add at least one explicit value to {profile_path}.{allowlist}"
            )),
            source_detail: None,
            details,
        }
    }

    fn unsupported_trusted_profile_scope(config_file: &Path, toml_path: &str, value: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert("value".to_string(), Value::String(value.to_string()));
        Self {
            code: ErrorCode::ConfigError,
            message: format!(
                "config file {} uses unsupported Trusted Profile scope '{value}' at {toml_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "replace the scope with explicit Host Aliases and MVP Mutation Command Family values"
                    .to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn unknown_config_keys(path: &Path, unknown_keys: Vec<UnknownConfigKey>) -> Self {
        let first = unknown_keys
            .first()
            .expect("unknown_config_keys requires at least one unknown key");
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(path.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(first.toml_path.clone()));
        details.insert("key".to_string(), Value::String(first.key.clone()));
        details.insert(
            "accepted_keys".to_string(),
            Value::Array(
                first
                    .accepted_keys
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        details.insert(
            "suggestion".to_string(),
            first
                .suggestion
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "unknown_keys".to_string(),
            Value::Array(
                unknown_keys
                    .iter()
                    .map(|unknown| {
                        object_value([
                            ("path", Value::String(unknown.toml_path.clone())),
                            ("key", Value::String(unknown.key.clone())),
                            (
                                "accepted_keys",
                                Value::Array(
                                    unknown
                                        .accepted_keys
                                        .iter()
                                        .cloned()
                                        .map(Value::String)
                                        .collect(),
                                ),
                            ),
                            (
                                "suggestion",
                                unknown
                                    .suggestion
                                    .clone()
                                    .map(Value::String)
                                    .unwrap_or(Value::Null),
                            ),
                        ])
                    })
                    .collect(),
            ),
        );

        Self {
            code: ErrorCode::UnknownConfigKey,
            message: format!(
                "config file {} contains unknown key '{}' at {}",
                path.display(),
                first.key,
                first.toml_path
            ),
            recovery_command: Some("remove or rename unsupported configuration keys".to_string()),
            source_detail: None,
            details,
        }
    }

    pub fn config_interpolation_not_supported(
        path: &Path,
        interpolations: Vec<ConfigInterpolation>,
    ) -> Self {
        let first = interpolations
            .first()
            .expect("config_interpolation_not_supported requires at least one interpolation");
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(path.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(first.toml_path.clone()));
        details.insert("syntax".to_string(), Value::String(first.syntax.clone()));
        details.insert(
            "unsupported_syntax".to_string(),
            Value::Array(
                interpolations
                    .iter()
                    .map(|interpolation| {
                        object_value([
                            ("path", Value::String(interpolation.toml_path.clone())),
                            ("syntax", Value::String(interpolation.syntax.clone())),
                        ])
                    })
                    .collect(),
            ),
        );

        Self {
            code: ErrorCode::ConfigInterpolationNotSupported,
            message: format!(
                "config file {} uses unsupported interpolation syntax '{}' at {}",
                path.display(),
                first.syntax,
                first.toml_path
            ),
            recovery_command: Some(
                "replace interpolation with an explicit Satelle-owned environment override"
                    .to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn unknown_timeout_key(config_file: &Path, toml_path: &str, key: &str) -> Self {
        let accepted_keys = ["native_readiness", "provider_smoke_test", "turn_execution"];
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert("key".to_string(), Value::String(key.to_string()));
        details.insert(
            "accepted_keys".to_string(),
            Value::Array(
                accepted_keys
                    .iter()
                    .map(|key| Value::String((*key).to_string()))
                    .collect(),
            ),
        );
        details.insert(
            "suggestion".to_string(),
            nearest_config_key(key, &accepted_keys)
                .map(Value::String)
                .unwrap_or(Value::Null),
        );

        Self {
            code: ErrorCode::UnknownTimeoutKey,
            message: format!(
                "config file {} contains unknown timeout key '{key}' at {toml_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "use timeouts.native_readiness, timeouts.provider_smoke_test, or timeouts.turn_execution"
                    .to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn duration_unit_required(config_file: &Path, toml_path: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert(
            "supported_units".to_string(),
            Value::Array(
                ["ms", "s", "m", "h"]
                    .into_iter()
                    .map(|unit| Value::String(unit.to_string()))
                    .collect(),
            ),
        );

        Self {
            code: ErrorCode::DurationUnitRequired,
            message: format!(
                "config file {} has a timeout at {toml_path} without an explicit supported unit",
                config_file.display()
            ),
            recovery_command: Some("use an explicit duration such as 120s, 2m, or 1h".to_string()),
            source_detail: None,
            details,
        }
    }

    fn turn_timeout_config_limit_exceeded(config_file: &Path, toml_path: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert(
            "maximum_timeout_ms".to_string(),
            Value::from(MAX_TURN_EXECUTION_TIMEOUT_MS),
        );
        Self {
            code: ErrorCode::ConfigError,
            message: format!(
                "config file {} has a Turn execution timeout above the 24 hour hard maximum at {toml_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "set timeouts.turn_execution to a finite duration no greater than 24h".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    fn turn_duration_unit_required(config_file: &Path, toml_path: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert(
            "accepted_units".to_string(),
            Value::Array(
                ["s", "m", "h"]
                    .into_iter()
                    .map(|unit| Value::String(unit.to_string()))
                    .collect(),
            ),
        );
        Self {
            code: ErrorCode::DurationUnitRequired,
            message: format!(
                "config file {} requires an explicit Turn timeout unit at {toml_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "use a Turn execution duration such as 30s, 30m, or 1h".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn unsupported_config_composition(path: &Path, key: &str) -> Self {
        Self {
            code: ErrorCode::UnsupportedConfigComposition,
            message: format!(
                "config file {} uses unsupported composition key '{key}'",
                path.display()
            ),
            recovery_command: Some(
                "remove include, imports, extends, or fragments keys".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn unsupported_secret_source_kind(config_file: &Path, toml_path: &str, kind: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert("kind".to_string(), Value::String(kind.to_string()));
        details.insert(
            "supported_kinds".to_string(),
            Value::Array(
                SUPPORTED_SECRET_SOURCE_KINDS
                    .iter()
                    .map(|kind| Value::String((*kind).to_string()))
                    .collect(),
            ),
        );

        Self {
            code: ErrorCode::UnsupportedSecretSourceKind,
            message: format!(
                "config file {} uses unsupported provider authentication Secret Source kind '{kind}' at {toml_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "use environment, file, credential-store, or host-store Secret Sources".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn secret_file_path_not_absolute(
        config_file: &Path,
        toml_path: &str,
        file_path: &str,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert("value".to_string(), Value::String(file_path.to_string()));
        details.insert(
            "secret_source_kind".to_string(),
            Value::String("file".to_string()),
        );

        Self {
            code: ErrorCode::SecretFilePathNotAbsolute,
            message: format!(
                "config file {} uses non-absolute File Secret Source path '{file_path}' at {toml_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "use an absolute target-host file path for file Secret Sources".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn desktop_session_selector_conflict(config_file: &Path, host_path: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(host_path.to_string()));
        details.insert(
            "conflicting_keys".to_string(),
            Value::Array(
                [
                    "desktop_session_preference",
                    "desktop_session_native_selector",
                ]
                .into_iter()
                .map(|key| Value::String(key.to_string()))
                .collect(),
            ),
        );

        Self {
            code: ErrorCode::DesktopSessionSelectorConflict,
            message: format!(
                "config file {} defines both portable and native desktop session selectors at {host_path}",
                config_file.display()
            ),
            recovery_command: Some(
                "keep either desktop_session_preference or desktop_session_native_selector"
                    .to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn platform_directories_unavailable() -> Self {
        Self {
            code: ErrorCode::PlatformDirectoriesUnavailable,
            message: "could not resolve OS-native Satelle user directories".to_string(),
            recovery_command: Some(
                "set SATELLE_HOME or explicit SATELLE_* path overrides".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn path_override_not_absolute(name: &str, value: String) -> Self {
        Self {
            code: ErrorCode::PathOverrideNotAbsolute,
            message: format!("{name} must be an absolute path when set, got '{value}'"),
            recovery_command: Some(format!("unset {name} or set it to an absolute path")),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn daemon_path_override_not_absolute(flag: &str, value: String) -> Self {
        let mut details = BTreeMap::new();
        details.insert("flag".to_string(), Value::String(flag.to_string()));
        details.insert("value".to_string(), Value::String(value.clone()));

        Self {
            code: ErrorCode::DaemonPathOverrideNotAbsolute,
            message: format!("{flag} must be an absolute remote daemon path, got '{value}'"),
            recovery_command: Some(format!("set {flag} to an absolute path or omit it")),
            source_detail: None,
            details,
        }
    }

    pub fn persistent_service_unsupported(platform: &str) -> Self {
        Self {
            code: ErrorCode::PersistentServiceUnsupported,
            message: format!(
                "persistent Host Daemon services are not supported on {platform} in the Satelle MVP"
            ),
            recovery_command: Some("rerun satelle setup with --on-demand".to_string()),
            source_detail: None,
            details: BTreeMap::from([
                ("platform".to_string(), Value::String(platform.to_string())),
                (
                    "requested_setup_mode".to_string(),
                    Value::String("persistent".to_string()),
                ),
                ("mutated".to_string(), Value::Bool(false)),
            ]),
        }
    }

    pub fn host_not_found(alias: String) -> Self {
        Self {
            code: ErrorCode::HostNotFound,
            message: format!("host '{alias}' is not configured"),
            recovery_command: Some("satelle setup --host local-demo --dry-run".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn project_host_selection_not_allowed(alias: String) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(alias.clone()));
        details.insert(
            "selection_source".to_string(),
            Value::String("project".to_string()),
        );
        Self {
            code: ErrorCode::ProjectHostSelectionNotAllowed,
            message: format!(
                "project configuration selected host '{alias}', but its user-level Host Binding does not allow project selection"
            ),
            recovery_command: Some(format!(
                "set hosts.{alias}.allow_project_selection = true in user-level configuration or pass --host {alias} explicitly"
            )),
            source_detail: None,
            details,
        }
    }

    pub fn host_unreachable(alias: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(alias.to_string()));
        Self {
            code: ErrorCode::HostUnreachable,
            message: format!("host '{alias}' is configured but unreachable"),
            recovery_command: Some("satelle config check --json".to_string()),
            source_detail: None,
            details,
        }
    }

    pub fn bootstrap_busy(alias: &str, operation_id: Option<&str>) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(alias.to_string()));
        if let Some(operation_id) = operation_id {
            details.insert(
                "operation_id".to_string(),
                Value::String(operation_id.to_string()),
            );
        }
        Self {
            code: ErrorCode::BootstrapBusy,
            message: format!("host '{alias}' already has an active bootstrap operation"),
            recovery_command: Some(format!(
                "wait for recovery or reconcile the active operation, then retry for host '{alias}'"
            )),
            source_detail: None,
            details,
        }
    }

    pub fn direct_daemon_unreachable(alias: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(alias.to_string()));
        Self {
            code: ErrorCode::DirectDaemonUnreachable,
            message: format!("direct Host Daemon for host '{alias}' is not reachable"),
            recovery_command: Some(format!(
                "start the configured Host Daemon, then retry satelle run --host {alias}"
            )),
            source_detail: None,
            details,
        }
    }

    pub fn ssh_host_key_verification_required(alias: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(alias.to_string()));
        Self {
            code: ErrorCode::SshHostKeyVerificationRequired,
            message: format!(
                "system OpenSSH could not verify the Host key for host '{alias}' without prompting"
            ),
            recovery_command: None,
            source_detail: None,
            details,
        }
    }

    pub fn authentication_failed(alias: &str) -> Self {
        host_access_error(
            ErrorCode::AuthenticationFailed,
            alias,
            "the Host Daemon rejected the configured bearer token",
            "replace the configured api_token file with a valid scoped token",
        )
    }

    pub fn tls_handshake_failed(alias: &str) -> Self {
        host_access_error(
            ErrorCode::TlsHandshakeFailed,
            alias,
            "the Host Daemon TLS handshake failed",
            "verify the Host endpoint certificate, hostname, and TLS configuration",
        )
    }

    pub fn certificate_untrusted(alias: &str) -> Self {
        host_access_error(
            ErrorCode::CertificateUntrusted,
            alias,
            "the Host Daemon certificate is not trusted",
            "verify the certificate chain or configure an owner-controlled ca_bundle",
        )
    }

    pub fn certificate_hostname_mismatch(alias: &str) -> Self {
        host_access_error(
            ErrorCode::CertificateHostnameMismatch,
            alias,
            "the Host Daemon certificate does not match the configured hostname",
            "use the certificate's verified hostname or replace the certificate",
        )
    }

    pub fn certificate_expired(alias: &str) -> Self {
        host_access_error(
            ErrorCode::CertificateExpired,
            alias,
            "the Host Daemon certificate has expired",
            "renew the Host Daemon certificate before reconnecting",
        )
    }

    pub fn tls_version_unsupported(alias: &str) -> Self {
        host_access_error(
            ErrorCode::TlsVersionUnsupported,
            alias,
            "the Host Daemon does not support TLS 1.2 or newer",
            "enable TLS 1.2 or newer on the Host Daemon TLS terminator",
        )
    }

    pub fn authorization_insufficient_scope(alias: &str) -> Self {
        host_access_error(
            ErrorCode::AuthorizationInsufficientScope,
            alias,
            "the configured Host Daemon token lacks the required scope",
            "issue a token with the required scope and replace the configured api_token file",
        )
    }

    pub fn host_identity_mismatch(alias: &str) -> Self {
        host_access_error(
            ErrorCode::HostIdentityMismatch,
            alias,
            "the reached Host Daemon does not match the pinned Host Identity",
            "run satelle host trust only after verifying the intended Host",
        )
    }

    pub fn remote_api_error(alias: &str, remote_code: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(alias.to_string()));
        details.insert(
            "remote_code".to_string(),
            Value::String(remote_code.to_string()),
        );
        Self {
            code: ErrorCode::RemoteExecution,
            message: "the Host Daemon rejected the operation".to_string(),
            recovery_command: Some("satelle doctor --scope transport --json".to_string()),
            source_detail: None,
            details,
        }
    }

    pub fn host_busy(host: &str, active_session_id: &SessionId) -> Self {
        let mut details = BTreeMap::new();
        details.insert("host".to_string(), Value::String(host.to_string()));
        details.insert(
            "active_session_id".to_string(),
            Value::String(active_session_id.to_string()),
        );

        Self {
            code: ErrorCode::HostBusy,
            message: format!(
                "host '{host}' already has an active Computer Use turn in session {active_session_id}"
            ),
            recovery_command: Some(format!("satelle stop {active_session_id}")),
            source_detail: None,
            details,
        }
    }

    pub fn computer_use_not_ready() -> Self {
        Self {
            code: ErrorCode::ComputerUseNotReady,
            message:
                "native Computer Use is blocked because required capability evidence is incomplete"
                    .to_string(),
            recovery_command: Some(
                "satelle doctor --scope computer-use --refresh --json".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn storage_busy() -> Self {
        Self {
            code: ErrorCode::StorageBusy,
            message: "the Host state store is temporarily busy".to_string(),
            recovery_command: Some("retry the operation after a short delay".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn store_in_use() -> Self {
        Self {
            code: ErrorCode::StoreInUse,
            message: "the Host state store is already owned by another daemon process".to_string(),
            recovery_command: Some(
                "stop the other Host Daemon or select a different state directory".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn state_conflict() -> Self {
        Self {
            code: ErrorCode::StateConflict,
            message: "the Host state changed before the operation could commit".to_string(),
            recovery_command: Some("retry the operation against current Host state".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn incompatible_control_plane(details: IncompatibleControlPlaneDetails) -> Self {
        Self {
            code: ErrorCode::IncompatibleControlPlane,
            message: format!(
                "the Codex control plane cannot admit the {} operation",
                details.operation().as_str()
            ),
            recovery_command: Some("satelle doctor --scope codex --refresh --json".to_string()),
            source_detail: None,
            details: details.into_error_details(),
        }
    }

    pub fn session_not_found(session_id: &SessionId) -> Self {
        Self {
            code: ErrorCode::SessionNotFound,
            message: format!("session '{}' was not found", session_id.as_str()),
            recovery_command: Some(
                "satelle run --host local-demo \"Open the browser\"".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn events_with_detach() -> Self {
        Self {
            code: ErrorCode::EventsWithDetach,
            message: "--events human and --events json require an attached run".to_string(),
            recovery_command: Some("remove --detach or use --events none".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn interrupt_mode_conflict() -> Self {
        Self {
            code: ErrorCode::InterruptModeConflict,
            message: "--detach-on-interrupt cannot be combined with --detach".to_string(),
            recovery_command: Some("remove --detach or remove --detach-on-interrupt".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn doctor_readiness_blockers_found(recovery_commands: &[String]) -> Self {
        Self {
            code: ErrorCode::DoctorReadinessBlockersFound,
            message: "doctor completed and found readiness-blocking findings".to_string(),
            recovery_command: recovery_commands
                .first()
                .cloned()
                .or_else(|| Some("satelle doctor --host local-demo --scope all".to_string())),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn doctor_refresh_scope_required() -> Self {
        Self {
            code: ErrorCode::DoctorRefreshScopeRequired,
            message: "--refresh requires doctor scope computer-use, provider, or all".to_string(),
            recovery_command: Some(
                "rerun with --scope computer-use, --scope provider, or --scope all".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn doctor_refresh_timeout_without_refresh() -> Self {
        Self {
            code: ErrorCode::DoctorRefreshTimeoutWithoutRefresh,
            message: "--timeout requires --refresh and doctor scope computer-use, provider, or all"
                .to_string(),
            recovery_command: Some(
                "rerun with --refresh and --scope computer-use, --scope provider, or --scope all"
                    .to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn output_mode_conflict(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::OutputModeConflict,
            message: message.into(),
            recovery_command: Some("remove all but one conflicting output selector".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn log_tail_limit_exceeded(value: usize) -> Self {
        let mut details = BTreeMap::new();
        details.insert("tail".to_string(), Value::from(value));
        details.insert("minimum".to_string(), Value::from(1));
        details.insert("maximum".to_string(), Value::from(10_000));

        Self {
            code: ErrorCode::LogTailLimitExceeded,
            message: format!("--tail must be between 1 and 10000, got {value}"),
            recovery_command: Some("rerun with --tail between 1 and 10000".to_string()),
            source_detail: None,
            details,
        }
    }

    pub fn log_position_conflict(conflicting_selector: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "conflicting_selectors".to_string(),
            Value::Array(
                ["--after", conflicting_selector]
                    .into_iter()
                    .map(|selector| Value::String(selector.to_string()))
                    .collect(),
            ),
        );

        Self {
            code: ErrorCode::LogPositionConflict,
            message: format!("--after cannot be combined with {conflicting_selector}"),
            recovery_command: Some(format!("remove either --after or {conflicting_selector}")),
            source_detail: None,
            details,
        }
    }

    pub fn logs_cursor_expired(
        earliest_available_cursor: Option<String>,
        resume_cursor: String,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "earliest_available_cursor".to_string(),
            earliest_available_cursor.map_or(Value::Null, Value::String),
        );
        details.insert("resume_cursor".to_string(), Value::String(resume_cursor));
        Self {
            code: ErrorCode::LogsCursorExpired,
            message: "the Log Cursor is older than retained Host history".to_string(),
            recovery_command: Some(
                "restart log reading from the earliest available cursor".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn concurrency_limit_exceeded(value: u8) -> Self {
        let mut details = BTreeMap::new();
        details.insert("concurrency".to_string(), Value::from(value));
        details.insert("minimum".to_string(), Value::from(1));
        details.insert("maximum".to_string(), Value::from(16));

        Self {
            code: ErrorCode::ConcurrencyLimitExceeded,
            message: format!("--concurrency must be between 1 and 16, got {value}"),
            recovery_command: Some("rerun with --concurrency between 1 and 16".to_string()),
            source_detail: None,
            details,
        }
    }

    pub fn capacity_exceeded(resource: &str, limit: usize) -> Self {
        let mut details = BTreeMap::new();
        details.insert("resource".to_string(), Value::String(resource.to_string()));
        details.insert("limit".to_string(), Value::from(limit));
        details.insert("retryable".to_string(), Value::Bool(true));

        Self {
            code: ErrorCode::CapacityExceeded,
            message: format!("the {resource} capacity limit of {limit} is currently occupied"),
            recovery_command: Some(
                "wait for the active operation to finish, then retry".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn concurrency_without_remote_update() -> Self {
        Self {
            code: ErrorCode::ConcurrencyWithoutRemoteUpdate,
            message: "--concurrency requires --update-remotes".to_string(),
            recovery_command: Some("add --update-remotes or remove --concurrency".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn component_selection_conflict() -> Self {
        Self {
            code: ErrorCode::ComponentSelectionConflict,
            message: "--component all cannot be combined with other setup components".to_string(),
            recovery_command: Some(
                "use --component all by itself or list specific setup components".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn unsupported_update_component(component: &str) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "component".to_string(),
            Value::String(component.to_string()),
        );
        details.insert(
            "supported_components".to_string(),
            Value::Array(
                ["host", "codex", "all"]
                    .into_iter()
                    .map(|component| Value::String(component.to_string()))
                    .collect(),
            ),
        );

        Self {
            code: ErrorCode::UnsupportedUpdateComponent,
            message: format!("unsupported host update component '{component}'"),
            recovery_command: Some(
                "use --component host, --component codex, or --component all".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn input_required(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InputRequired,
            message: message.into(),
            recovery_command: Some("pass a prompt argument or pipe prompt text to '-'".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn setup_consent_required(
        planned_actions: &[String],
        recovery_command: impl Into<String>,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "planned_actions".to_string(),
            Value::Array(planned_actions.iter().cloned().map(Value::String).collect()),
        );
        details.insert("applied_actions".to_string(), Value::Array(Vec::new()));
        details.insert("mutated".to_string(), Value::Bool(false));

        Self {
            code: ErrorCode::SetupConsentRequired,
            message:
                "setup has planned mutations that require explicit consent; no changes were applied"
                    .to_string(),
            recovery_command: Some(recovery_command.into()),
            source_detail: None,
            details,
        }
    }

    pub fn doctor_fix_consent_required(
        planned_actions: &[String],
        recovery_command: impl Into<String>,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "planned_actions".to_string(),
            Value::Array(planned_actions.iter().cloned().map(Value::String).collect()),
        );
        details.insert("applied_actions".to_string(), Value::Array(Vec::new()));
        details.insert("mutated".to_string(), Value::Bool(false));

        Self {
            code: ErrorCode::DoctorFixConsentRequired,
            message:
                "doctor fix has planned mutations that require explicit consent; no changes were applied"
                    .to_string(),
            recovery_command: Some(recovery_command.into()),
            source_detail: None,
            details,
        }
    }

    pub fn interrupted_attached_command() -> Self {
        Self {
            code: ErrorCode::Interrupted,
            message: "attached command was interrupted after applying the interruption contract"
                .to_string(),
            recovery_command: Some("rerun the command or inspect the Session status".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn not_implemented(feature: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::NotImplemented,
            message: feature.into(),
            recovery_command: Some("satelle setup --dry-run --json".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.code.exit_code()
    }
}

#[cfg(test)]
mod error_contract_tests {
    use super::*;

    #[test]
    fn bootstrap_busy_has_a_stable_typed_contract() {
        assert_eq!(ErrorCode::BootstrapBusy.as_str(), "bootstrap-busy");
        assert_eq!(ErrorCode::BootstrapBusy.exit_code(), 75);

        let error = SatelleError::bootstrap_busy("remote", Some("bootstrap-operation"));
        assert_eq!(error.code, ErrorCode::BootstrapBusy);
        assert_eq!(error.exit_code(), 75);
        assert_eq!(
            error.message,
            "host 'remote' already has an active bootstrap operation"
        );
        assert_eq!(
            error.recovery_command.as_deref(),
            Some(
                "wait for recovery or reconcile the active operation, then retry for host 'remote'"
            )
        );
        assert_eq!(error.source_detail, None);
        assert_eq!(
            error.details.get("host"),
            Some(&Value::String("remote".to_string()))
        );
        assert_eq!(
            error.details.get("operation_id"),
            Some(&Value::String("bootstrap-operation".to_string()))
        );

        let without_operation = SatelleError::bootstrap_busy("remote", None);
        assert_eq!(without_operation.details.len(), 1);
        assert!(!without_operation.details.contains_key("operation_id"));
    }

    #[test]
    fn native_readiness_timeout_has_a_stable_readiness_contract() {
        assert_eq!(
            ErrorCode::NativeReadinessTimeout.as_str(),
            "native-readiness-timeout"
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::NativeReadinessTimeout)
                .expect("serialize native readiness timeout code"),
            serde_json::json!("native-readiness-timeout")
        );
        assert_eq!(ErrorCode::NativeReadinessTimeout.exit_code(), 75);

        let error = SatelleError::native_readiness_timeout();
        assert_eq!(error.code, ErrorCode::NativeReadinessTimeout);
        assert_eq!(
            error.message,
            "the native Computer Use readiness smoke test timed out"
        );
        assert_eq!(
            error.recovery_command.as_deref(),
            Some("satelle doctor --scope computer-use --refresh --json")
        );
        assert_eq!(error.source_detail, None);
        assert!(error.details.is_empty());
    }

    #[test]
    fn ssh_host_key_verification_required_is_a_typed_transport_failure() {
        let error = SatelleError::ssh_host_key_verification_required("remote");
        assert_eq!(error.code.as_str(), "ssh-host-key-verification-required");
        assert_eq!(error.exit_code(), 74);
        assert_eq!(
            error.details.get("host"),
            Some(&serde_json::json!("remote"))
        );
        assert_eq!(error.source_detail, None);
    }

    #[test]
    fn canonical_broad_exit_classes_cover_security_storage_and_internal_errors() {
        for (code, expected) in [
            (ErrorCode::InvalidUsage, 64),
            (ErrorCode::ConfigError, 66),
            (ErrorCode::HostUnreachable, 69),
            (ErrorCode::NotImplemented, 70),
            (ErrorCode::CompletionInstallFailed, 73),
            (ErrorCode::RemoteExecution, 74),
            (ErrorCode::StorageIntegrityFailed, 74),
            (ErrorCode::SshHostKeyVerificationRequired, 74),
            (ErrorCode::CertificateUntrusted, 74),
            (ErrorCode::CertificateHostnameMismatch, 74),
            (ErrorCode::CertificateExpired, 74),
            (ErrorCode::TlsVersionUnsupported, 74),
            (ErrorCode::TlsHandshakeFailed, 74),
            (ErrorCode::AuthenticationFailed, 74),
            (ErrorCode::AuthorizationInsufficientScope, 74),
            (ErrorCode::HostIdentityMismatch, 74),
            (ErrorCode::ComputerUseNotReady, 75),
            (ErrorCode::CapacityExceeded, 75),
            (ErrorCode::HostBusy, 75),
            (ErrorCode::StateConflict, 75),
            (ErrorCode::StopNotConfirmed, 75),
            (ErrorCode::StoreInUse, 74),
            (ErrorCode::StorageBusy, 74),
            (ErrorCode::DoctorFixConsentRequired, 64),
            (ErrorCode::Interrupted, 130),
        ] {
            assert_eq!(
                code.exit_code(),
                expected,
                "unexpected broad exit class for {}",
                code.as_str()
            );
        }
    }

    #[test]
    fn direct_daemon_unreachable_has_a_stable_unreachable_host_contract() {
        assert_eq!(
            ErrorCode::DirectDaemonUnreachable.as_str(),
            "direct-daemon-unreachable"
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::DirectDaemonUnreachable)
                .expect("serialize direct daemon unreachable code"),
            serde_json::json!("direct-daemon-unreachable")
        );
        assert_eq!(ErrorCode::DirectDaemonUnreachable.exit_code(), 69);

        let error = SatelleError::direct_daemon_unreachable("remote");
        assert_eq!(error.code, ErrorCode::DirectDaemonUnreachable);
        assert_eq!(
            error.message,
            "direct Host Daemon for host 'remote' is not reachable"
        );
        assert_eq!(
            error.recovery_command.as_deref(),
            Some("start the configured Host Daemon, then retry satelle run --host remote")
        );
        assert_eq!(error.source_detail, None);
        assert_eq!(
            error.details,
            BTreeMap::from([("host".to_string(), serde_json::json!("remote"))])
        );
        assert_eq!(error.exit_code(), 69);
    }

    #[test]
    fn consent_required_errors_are_usage_noops() {
        for (error, expected_code, expected_message, expected_action, expected_recovery) in [
            (
                SatelleError::setup_consent_required(
                    &["install host daemon".to_string()],
                    "satelle setup --yes",
                ),
                ErrorCode::SetupConsentRequired,
                "setup has planned mutations that require explicit consent; no changes were applied",
                "install host daemon",
                "satelle setup --yes",
            ),
            (
                SatelleError::doctor_fix_consent_required(
                    &["repair Host state".to_string()],
                    "satelle doctor --fix --yes",
                ),
                ErrorCode::DoctorFixConsentRequired,
                "doctor fix has planned mutations that require explicit consent; no changes were applied",
                "repair Host state",
                "satelle doctor --fix --yes",
            ),
        ] {
            assert_eq!(error.code, expected_code);
            assert_eq!(error.message, expected_message);
            assert_eq!(error.exit_code(), 64);
            assert_eq!(error.recovery_command.as_deref(), Some(expected_recovery));
            assert_eq!(
                error.details.get("planned_actions"),
                Some(&serde_json::json!([expected_action]))
            );
            assert_eq!(
                error.details.get("applied_actions"),
                Some(&serde_json::json!([]))
            );
            assert_eq!(
                error.details.get("mutated"),
                Some(&serde_json::json!(false))
            );
            assert_eq!(error.source_detail, None);
        }
    }

    #[test]
    fn interrupted_attached_command_has_a_stable_exit_class() {
        let error = SatelleError::interrupted_attached_command();

        assert_eq!(ErrorCode::Interrupted.as_str(), "interrupted");
        assert_eq!(
            serde_json::to_value(ErrorCode::Interrupted).expect("serialize interrupt code"),
            serde_json::json!("interrupted")
        );
        assert_eq!(error.exit_code(), 130);
        assert_eq!(error.source_detail, None);
        assert_eq!(
            error.recovery_command.as_deref(),
            Some("rerun the command or inspect the Session status")
        );
        assert!(error.details.is_empty());
        assert!(error.message.contains("interrupted"));
    }

    #[test]
    fn known_failures_keep_specific_user_facing_attribution() {
        let incompatible_control_plane = SatelleError::incompatible_control_plane(
            IncompatibleControlPlaneDetails::new(
                ControlPlaneOperation::Run,
                ControlPlaneFailureReason::RequiredCapabilityMissing,
                &[ControlPlaneCapability::EventObservation],
            )
            .expect("valid incompatible control-plane details"),
        );
        let session_id = SessionId::new();
        let session_attribution = format!("session '{}'", session_id.as_str());

        for (surface, error, expected) in [
            (
                "host",
                SatelleError::host_unreachable("remote"),
                "host 'remote'",
            ),
            (
                "transport",
                SatelleError::direct_daemon_unreachable("remote"),
                "direct Host Daemon",
            ),
            ("Codex", incompatible_control_plane, "Codex control plane"),
            (
                "Computer Use",
                SatelleError::native_readiness_timeout(),
                "native Computer Use",
            ),
            (
                "provider",
                SatelleError::unsupported_provider_computer_use(),
                "selected provider",
            ),
            (
                "session",
                SatelleError::session_not_found(&session_id),
                session_attribution.as_str(),
            ),
        ] {
            assert!(
                error.message.contains(expected),
                "{surface} failure should name {expected:?}: {}",
                error.message
            );
        }
    }

    #[test]
    fn log_position_conflict_has_a_stable_usage_error_contract() {
        assert_eq!(
            ErrorCode::LogPositionConflict.as_str(),
            "log-position-conflict"
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::LogPositionConflict)
                .expect("serialize log position conflict code"),
            serde_json::json!("log-position-conflict")
        );
        assert_eq!(ErrorCode::LogPositionConflict.exit_code(), 64);

        for conflicting_selector in ["--since", "--tail"] {
            let error = SatelleError::log_position_conflict(conflicting_selector);
            assert_eq!(error.code, ErrorCode::LogPositionConflict);
            assert_eq!(
                error.message,
                format!("--after cannot be combined with {conflicting_selector}")
            );
            assert_eq!(
                error.recovery_command,
                Some(format!("remove either --after or {conflicting_selector}"))
            );
            assert_eq!(
                error.details.get("conflicting_selectors"),
                Some(&serde_json::json!(["--after", conflicting_selector]))
            );
            assert_eq!(error.exit_code(), 64);
        }
    }
}

fn host_access_error(
    code: ErrorCode,
    alias: &str,
    message: &str,
    recovery_command: &str,
) -> SatelleError {
    let mut details = BTreeMap::new();
    details.insert("host".to_string(), Value::String(alias.to_string()));
    SatelleError {
        code,
        message: message.to_string(),
        recovery_command: Some(recovery_command.to_string()),
        source_detail: None,
        details,
    }
}

impl From<IdParseError> for SatelleError {
    fn from(error: IdParseError) -> Self {
        Self {
            code: ErrorCode::InvalidUsage,
            message: format!("invalid Satelle identifier: {error}"),
            recovery_command: Some(
                "use the exact Session or Turn identifier returned by Satelle".to_string(),
            ),
            source_detail: None,
            details: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum StopSchemaVersion {
    #[serde(rename = "satelle.stop.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopResultOutcome {
    Stopped,
    AlreadyTerminal,
}

impl StopResultOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::AlreadyTerminal => "already_terminal",
        }
    }
}

impl session::TurnState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::RecoveryPending => "recovery_pending",
            Self::Completed => "completed",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
            Self::Stopped => "stopped",
        }
    }
}

impl From<session::TerminalTurnState> for session::TurnState {
    fn from(state: session::TerminalTurnState) -> Self {
        match state {
            session::TerminalTurnState::Completed => Self::Completed,
            session::TerminalTurnState::Blocked => Self::Blocked,
            session::TerminalTurnState::Failed => Self::Failed,
            session::TerminalTurnState::Stopped => Self::Stopped,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StopResult {
    schema_version: StopSchemaVersion,
    outcome: StopResultOutcome,
    session_id: SessionId,
    turn_id: TurnId,
    previous_state: session::TurnState,
    current_state: session::TurnState,
    changed: bool,
    stopped_at: Option<String>,
}

impl StopResult {
    pub fn stopped(
        session_id: SessionId,
        turn_id: TurnId,
        previous_state: session::TurnState,
        stopped_at: String,
    ) -> Result<Self, StopResultInvariantError> {
        if previous_state.is_terminal() {
            return Err(StopResultInvariantError::StoppedPreviousStateIsTerminal);
        }
        if stopped_at.is_empty() {
            return Err(StopResultInvariantError::MissingStoppedAt);
        }
        Ok(Self {
            schema_version: StopSchemaVersion::V1,
            outcome: StopResultOutcome::Stopped,
            session_id,
            turn_id,
            previous_state,
            current_state: session::TurnState::Stopped,
            changed: true,
            stopped_at: Some(stopped_at),
        })
    }

    pub fn already_terminal(
        session_id: SessionId,
        turn_id: TurnId,
        state: session::TurnState,
    ) -> Result<Self, StopResultInvariantError> {
        if !state.is_terminal() {
            return Err(StopResultInvariantError::AlreadyTerminalStateIsActive);
        }
        Ok(Self {
            schema_version: StopSchemaVersion::V1,
            outcome: StopResultOutcome::AlreadyTerminal,
            session_id,
            turn_id,
            previous_state: state,
            current_state: state,
            changed: false,
            stopped_at: None,
        })
    }

    pub fn outcome(&self) -> StopResultOutcome {
        self.outcome
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn turn_id(&self) -> &TurnId {
        &self.turn_id
    }

    pub fn previous_state(&self) -> session::TurnState {
        self.previous_state
    }

    pub fn current_state(&self) -> session::TurnState {
        self.current_state
    }

    pub fn changed(&self) -> bool {
        self.changed
    }

    pub fn stopped_at(&self) -> Option<&str> {
        self.stopped_at.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum StopResultInvariantError {
    #[error("a stopped result requires a nonterminal previous state")]
    StoppedPreviousStateIsTerminal,
    #[error("a stopped result requires a timestamp")]
    MissingStoppedAt,
    #[error("an already-terminal result requires a terminal state")]
    AlreadyTerminalStateIsActive,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterReadiness {
    pub ready: bool,
    pub adapter: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorFinding {
    pub finding_id: String,
    pub scope: String,
    pub severity: String,
    pub fixability: DoctorFixability,
    pub readiness_impact: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub recovery_command: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DoctorFixability {
    Repairable,
    ManualActionRequired,
    Blocked,
    Informational,
}

impl DoctorFixability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repairable => "repairable",
            Self::ManualActionRequired => "manual_action_required",
            Self::Blocked => "blocked",
            Self::Informational => "informational",
        }
    }
}

impl fmt::Display for DoctorFixability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The only schema token accepted for doctor reports in this release line.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DoctorSchemaVersion {
    #[serde(rename = "satelle.doctor.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoctorOptions {
    refresh: bool,
    probe_timeout: Option<std::time::Duration>,
}

impl DoctorOptions {
    pub const fn new(refresh: bool, probe_timeout: Option<std::time::Duration>) -> Self {
        Self {
            refresh,
            probe_timeout,
        }
    }

    pub const fn refresh(self) -> bool {
        self.refresh
    }

    pub const fn probe_timeout(self) -> Option<std::time::Duration> {
        self.probe_timeout
    }
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self::new(false, None)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorReport {
    pub schema_version: DoctorSchemaVersion,
    pub status: String,
    pub target: String,
    pub host: String,
    pub scopes: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub summary: DoctorSummary,
    pub probe_results: Vec<DoctorProbeResult>,
    pub ready: bool,
    pub findings: Vec<DoctorFinding>,
    pub recovery_commands: Vec<String>,
    pub changed: bool,
    pub cache_updates: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorSummary {
    pub ready: bool,
    pub blocking_findings: usize,
    pub repairable_findings: usize,
    pub informational_findings: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorProbeResult {
    pub probe_id: String,
    pub scope: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub cache_status: String,
    pub dependency_status: String,
    pub finding_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DoctorEventRecord {
    pub schema_version: String,
    pub event_id: String,
    pub event_type: String,
    pub target: String,
    pub scope: String,
    pub probe_id: Option<String>,
    pub timestamp: String,
    pub status: String,
    pub data: Value,
}

/// The only schema token accepted for setup reports in this release line.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SetupSchemaVersion {
    #[serde(rename = "satelle.setup.v1")]
    V1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupReport {
    pub schema_version: SetupSchemaVersion,
    pub host: String,
    pub dry_run: bool,
    pub status: String,
    pub setup_mode: String,
    pub service_persistent: bool,
    pub service_scope: String,
    pub fallback_reason: Option<String>,
    pub target_platform: Option<String>,
    pub host_artifact: Option<daemon_service::DaemonArtifactPlan>,
    pub service_plan: Option<daemon_service::DaemonServicePlan>,
    pub current_daemon_paths: Option<daemon_service::DaemonResolvedPathSet>,
    pub planned_daemon_paths: Option<daemon_service::DaemonResolvedPathSet>,
    pub setup_components: Vec<String>,
    pub planned_actions: Vec<String>,
    pub applied_actions: Vec<String>,
    pub required_input: Vec<SetupRequiredInput>,
    pub recovery_commands: Vec<String>,
    pub readiness_summary: SetupReadinessSummary,
    pub daemon_path_overrides: Vec<DaemonPathOverride>,
    pub mutated: bool,
    pub native_computer_use_readiness: String,
    pub next_command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupRequiredInput {
    pub component: String,
    pub input_kind: String,
    pub reason: String,
    pub recovery_command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupReadinessSummary {
    pub transport: String,
    pub host_daemon: String,
    pub codex_runtime: String,
    pub native_computer_use: String,
    pub provider_auth: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonPathOverrides {
    pub home: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: BTreeMap<String, String>,
}

impl DaemonPathOverrides {
    pub fn is_empty(&self) -> bool {
        self.home.is_none()
            && self.config_file.is_none()
            && self.state_dir.is_none()
            && self.cache_dir.is_none()
            && self.log_dir.is_none()
    }

    pub fn entries(&self) -> Vec<DaemonPathOverride> {
        [
            ("SATELLE_HOME", &self.home),
            ("SATELLE_CONFIG_FILE", &self.config_file),
            ("SATELLE_STATE_DIR", &self.state_dir),
            ("SATELLE_CACHE_DIR", &self.cache_dir),
            ("SATELLE_LOG_DIR", &self.log_dir),
        ]
        .into_iter()
        .filter_map(|(environment_variable, value)| {
            value.as_ref().map(|value| DaemonPathOverride {
                environment_variable: environment_variable.to_string(),
                value: value.display().to_string(),
                source: self
                    .sources
                    .get(environment_variable)
                    .cloned()
                    .unwrap_or_else(|| "setup_flag".to_string()),
                service_configuration_surface: "satelle_service_configuration".to_string(),
            })
        })
        .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonPathOverride {
    pub environment_variable: String,
    pub value: String,
    pub source: String,
    pub service_configuration_surface: String,
}

/// The only schema token accepted for Host session reports in this release line.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostSessionsSchemaVersion {
    #[serde(rename = "satelle.host.sessions.v1")]
    V1,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostSessionsReport {
    pub schema_version: HostSessionsSchemaVersion,
    pub host: String,
    pub connection_mode: String,
    pub bootstrapped: bool,
    pub bootstrap_actions: Vec<String>,
    pub host_daemon_version: String,
    pub sessions: Vec<DesktopSessionRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopSessionRecord {
    pub session_id: String,
    pub desktop_user: String,
    pub state: String,
    pub session_kind: String,
    pub is_console: bool,
    pub is_remote: bool,
    pub display_summary: String,
    pub portable_selectors: Vec<String>,
    pub native_selectors: Vec<String>,
    pub selected_by_current_config: bool,
}

#[cfg(any(test, feature = "test-support"))]
pub trait ComputerUseAdapter {
    fn readiness(&self, host: &str) -> AdapterReadiness;

    fn execute_turn(
        &self,
        host: &str,
        session_id: &SessionId,
        turn_id: &TurnId,
        prompt: &str,
    ) -> Vec<SatelleEvent>;
}

pub fn utc_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub fn object_value(entries: impl IntoIterator<Item = (impl Into<String>, Value)>) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.into(), value);
    }
    Value::Object(object)
}
