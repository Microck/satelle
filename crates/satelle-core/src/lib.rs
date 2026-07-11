use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod events;
pub mod ids;
mod profiles;
pub mod session;

pub use events::{
    EVENT_SCHEMA_VERSION, EventSource, EventStateSubject, EventSubject, EventType, SatelleEvent,
    SatelleEventBody, SatelleEventError,
};
pub use ids::{IdParseError, SessionId, TurnId};
pub use profiles::{ProfileField, ProfileSelectionSource, SelectedProfile};

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
    #[serde(default)]
    pub hosts: BTreeMap<String, HostConfig>,
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
                desktop_user: None,
                desktop_session_preference: None,
                desktop_session_native_selector: None,
                daemon_home: None,
                daemon_config_file: None,
                daemon_state_dir: None,
                daemon_cache_dir: None,
                daemon_log_dir: None,
                experimental_provider_computer_use: None,
                yolo: None,
                provider_auth: BTreeMap::new(),
            },
        );

        Self {
            default_host: Some(LOCAL_DEMO_HOST.to_string()),
            model_alias: None,
            provider_alias: None,
            experimental_provider_computer_use: None,
            yolo: None,
            hosts,
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

        for (alias, host) in higher.hosts {
            self.hosts.insert(alias, host);
        }

        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    pub transport: TransportKind,
    pub adapter: AdapterKind,
    pub address: Option<String>,
    pub network: Option<NetworkConfig>,
    pub timeouts: Option<TimeoutConfig>,
    pub desktop_user: Option<String>,
    pub desktop_session_preference: Option<DesktopSessionPreference>,
    pub desktop_session_native_selector: Option<DesktopSessionNativeSelector>,
    pub daemon_home: Option<PathBuf>,
    pub daemon_config_file: Option<PathBuf>,
    pub daemon_state_dir: Option<PathBuf>,
    pub daemon_cache_dir: Option<PathBuf>,
    pub daemon_log_dir: Option<PathBuf>,
    pub experimental_provider_computer_use: Option<bool>,
    pub yolo: Option<bool>,
    #[serde(default)]
    pub provider_auth: BTreeMap<String, ProviderSecretSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutConfig {
    pub native_readiness: Option<ExplicitDuration>,
    pub provider_smoke_test: Option<ExplicitDuration>,
}

impl TimeoutConfig {
    fn merge(mut self, higher: TimeoutConfig) -> Self {
        if higher.native_readiness.is_some() {
            self.native_readiness = higher.native_readiness;
        }
        if higher.provider_smoke_test.is_some() {
            self.provider_smoke_test = higher.provider_smoke_test;
        }
        self
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
}

impl ResolvedConfig {
    pub fn resolve_host(
        &self,
        flag_host: Option<&str>,
    ) -> Result<(String, HostConfig), SatelleError> {
        let alias = flag_host
            .map(str::to_string)
            .or_else(|| optional_non_empty_env("SATELLE_HOST"))
            .or_else(|| self.config.default_host.clone())
            .unwrap_or_else(|| LOCAL_DEMO_HOST.to_string());

        let mut host = self
            .config
            .hosts
            .get(&alias)
            .cloned()
            .ok_or_else(|| SatelleError::host_not_found(alias.clone()))?;

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
}

pub fn load_config(cwd: &Path, flag_profile: Option<&str>) -> Result<ResolvedConfig, SatelleError> {
    let paths = resolve_path_set(cwd)?;
    let user_config_path = paths.config_file;
    let project_config_path = paths.project_config_file;

    let mut config = SatelleConfig::defaults();
    let user_config = read_config_file(&user_config_path, ConfigScope::User)?;
    let project_config = read_config_file(&project_config_path, ConfigScope::Project)?;

    if let Some(user_config) = &user_config {
        config = config.merge(user_config.config.clone());
    }
    if let Some(project_config) = &project_config {
        config = config.merge(project_config.config.clone());
    }

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
        let profile = user_config
            .as_ref()
            .and_then(|config| config.profiles.get(&selected.name))
            .cloned()
            .ok_or_else(|| {
                let available_profiles = user_config
                    .as_ref()
                    .map(|config| config.profiles.keys().cloned().collect())
                    .unwrap_or_default();
                SatelleError::profile_not_found(
                    &user_config_path,
                    &selected.name,
                    available_profiles,
                )
            })?;
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
        (state_root.join("logs"), state_source)
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
    }

    cwd.join(".satelle").join("config.toml")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigScope {
    User,
    Project,
}

#[derive(Clone, Debug)]
struct ParsedConfigFile {
    config: SatelleConfig,
    default_profile: Option<String>,
    profiles: BTreeMap<String, profiles::ProfileConfig>,
}

fn read_config_file(
    path: &Path,
    scope: ConfigScope,
) -> Result<Option<ParsedConfigFile>, SatelleError> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path).map_err(|source| SatelleError {
        code: ErrorCode::ConfigNotFound,
        message: format!("could not read config file {}", path.display()),
        recovery_command: Some("satelle setup --host local-demo --dry-run".to_string()),
        source_detail: Some(source.to_string()),
        details: BTreeMap::new(),
    })?;

    let mut value = toml::from_str::<toml::Value>(&raw).map_err(|source| {
        SatelleError::config_error(
            format!("could not parse config file {}", path.display()),
            Some(source.to_string()),
        )
    })?;
    let profile_data =
        profiles::extract_profile_data(path, &mut value, scope == ConfigScope::User)?;
    reject_config_composition(path, &value)?;
    reject_interpolation(path, &value)?;
    reject_timeout_config_errors(path, &value)?;
    if scope == ConfigScope::Project {
        reject_project_forbidden_keys(path, &value)?;
    }
    reject_desktop_session_selector_conflicts(path, &value)?;
    reject_provider_secret_source_errors(path, &value)?;
    reject_unknown_config_keys(path, &value)?;

    let config = value
        .clone()
        .try_into()
        .map_err(|source: toml::de::Error| {
            SatelleError::config_error(
                format!("could not decode config file {}", path.display()),
                Some(source.to_string()),
            )
        })?;

    Ok(Some(ParsedConfigFile {
        config,
        default_profile: profile_data.default_profile,
        profiles: profile_data.profiles,
    }))
}

fn reject_project_forbidden_keys(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };

    for key in [
        "yes",
        "assume_yes",
        "mutation_consent",
        "noninteractive_mutation_consent",
        "trusted_profiles",
    ] {
        if table.contains_key(key) {
            return Err(SatelleError::project_mutation_consent_not_allowed(
                path, key, key,
            ));
        }
    }

    for key in ["yolo", "yolo_mode"] {
        if toml_value_enables(table.get(key)) {
            return Err(SatelleError::project_yolo_enable_not_allowed(
                path, key, key,
            ));
        }
    }

    if table.contains_key("experimental_provider_computer_use") {
        return Err(
            SatelleError::project_experimental_provider_opt_in_not_allowed(
                path,
                "experimental_provider_computer_use",
                "experimental_provider_computer_use",
            ),
        );
    }

    for &key in PROJECT_CREDENTIAL_HELPER_KEYS {
        if table.contains_key(key) {
            return Err(SatelleError::project_credential_helper_not_allowed(
                path, key, key,
            ));
        }
    }

    for &key in PROJECT_SECRET_SOURCE_KEYS {
        if table.contains_key(key) {
            return Err(SatelleError::project_secret_source_not_allowed(
                path, key, key,
            ));
        }
    }

    let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) else {
        return Ok(());
    };

    for (alias, host_value) in hosts {
        let host_path = format!("hosts.{alias}");
        let Some(host_table) = host_value.as_table() else {
            continue;
        };

        for key in [
            "daemon_home",
            "daemon_config_file",
            "daemon_state_dir",
            "daemon_cache_dir",
            "daemon_log_dir",
        ] {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_daemon_path_override_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }

        for key in [
            "desktop_user",
            "desktop_session_preference",
            "desktop_session_native_selector",
        ] {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_desktop_binding_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }

        for key in ["yolo", "yolo_mode"] {
            if toml_value_enables(host_table.get(key)) {
                return Err(SatelleError::project_yolo_enable_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }

        if host_table.contains_key("experimental_provider_computer_use") {
            return Err(
                SatelleError::project_experimental_provider_opt_in_not_allowed(
                    path,
                    &format!("{host_path}.experimental_provider_computer_use"),
                    "experimental_provider_computer_use",
                ),
            );
        }

        for &key in PROJECT_CREDENTIAL_HELPER_KEYS {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_credential_helper_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }

        for &key in PROJECT_SECRET_SOURCE_KEYS {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_secret_source_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }
    }

    Ok(())
}

const PROJECT_SECRET_SOURCE_KEYS: &[&str] = &[
    "provider_auth",
    "provider_credentials",
    "provider_secret",
    "provider_secret_source",
    "provider_secret_sources",
    "secret_source",
    "secret_sources",
    "bearer_token",
    "provider_bearer_token",
    "authorization_header",
    "secret_environment",
    "secret_environment_variables",
    "provider_endpoint",
    "provider_endpoint_binding",
];

const PROJECT_CREDENTIAL_HELPER_KEYS: &[&str] = &[
    "credential_helper",
    "credential_helpers",
    "executable_credential_helper",
    "provider_credential_helper",
    "provider_auth_helper",
    "provider_auth_command",
    "helper_executable",
    "helper_argv",
    "helper_env",
    "helper_timeout",
    "helper_protocol",
];

fn toml_value_enables(value: Option<&toml::Value>) -> bool {
    match value {
        Some(toml::Value::Boolean(enabled)) => *enabled,
        Some(toml::Value::String(value)) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "enabled" | "on" | "always"
        ),
        _ => false,
    }
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
            "desktop_user",
            "desktop_session_preference",
            "daemon_home",
            "daemon_config_file",
            "daemon_state_dir",
            "daemon_cache_dir",
            "daemon_log_dir",
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
            for key in ["native_readiness", "provider_smoke_test"] {
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
        let Some(timeouts) = host_table.get("timeouts").and_then(toml::Value::as_table) else {
            continue;
        };

        for (key, value) in timeouts {
            let timeout_path = format!("{host_path}.timeouts.{key}");
            if !["native_readiness", "provider_smoke_test"].contains(&key.as_str()) {
                return Err(SatelleError::unknown_timeout_key(path, &timeout_path, key));
            }

            let Some(value) = value.as_str() else {
                return Err(SatelleError::duration_unit_required(path, &timeout_path));
            };
            if ExplicitDuration::parse(value).is_none() {
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

fn reject_unknown_config_keys(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
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
            "profile",
            "profiles",
            "hosts",
        ],
        &mut unknown_keys,
    );

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
                    "desktop_user",
                    "desktop_session_preference",
                    "desktop_session_native_selector",
                    "daemon_home",
                    "daemon_config_file",
                    "daemon_state_dir",
                    "daemon_cache_dir",
                    "daemon_log_dir",
                    "experimental_provider_computer_use",
                    "yolo",
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

fn parse_positive_u64(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|value| *value > 0)
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
    HostBusy,
    IdempotencyKeyConflict,
    RemoteExecution,
    StorageIntegrityFailed,
    ComputerUseNotReady,
    DoctorReadinessBlockersFound,
    SessionNotFound,
    EventsWithDetach,
    OutputModeConflict,
    LogTailLimitExceeded,
    LogsCursorExpired,
    CapacityExceeded,
    ConcurrencyLimitExceeded,
    ConcurrencyWithoutRemoteUpdate,
    ComponentSelectionConflict,
    UnsupportedUpdateComponent,
    InputRequired,
    NotImplemented,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUsage => "invalid-usage",
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
            Self::HostBusy => "host-busy",
            Self::IdempotencyKeyConflict => "idempotency-key-conflict",
            Self::RemoteExecution => "remote-execution",
            Self::StorageIntegrityFailed => "storage-integrity-failed",
            Self::ComputerUseNotReady => "computer-use-not-ready",
            Self::DoctorReadinessBlockersFound => "doctor-readiness-blockers-found",
            Self::SessionNotFound => "session-not-found",
            Self::EventsWithDetach => "events-with-detach",
            Self::OutputModeConflict => "output-mode-conflict",
            Self::LogTailLimitExceeded => "log-tail-limit-exceeded",
            Self::LogsCursorExpired => "logs-cursor-expired",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::ConcurrencyLimitExceeded => "concurrency-limit-exceeded",
            Self::ConcurrencyWithoutRemoteUpdate => "concurrency-without-remote-update",
            Self::ComponentSelectionConflict => "component-selection-conflict",
            Self::UnsupportedUpdateComponent => "unsupported-update-component",
            Self::InputRequired => "input-required",
            Self::NotImplemented => "not-implemented",
        }
    }

    pub fn exit_code(self) -> i32 {
        match self {
            Self::InvalidUsage
            | Self::IdempotencyKeyConflict
            | Self::EventsWithDetach
            | Self::OutputModeConflict
            | Self::LogTailLimitExceeded
            | Self::ConcurrencyLimitExceeded
            | Self::ConcurrencyWithoutRemoteUpdate
            | Self::ComponentSelectionConflict
            | Self::UnsupportedUpdateComponent
            | Self::InputRequired => 64,
            Self::CompletionInstallFailed | Self::CompletionProfileUpdateFailed => 73,
            Self::StorageIntegrityFailed => 65,
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
            Self::CapacityExceeded
            | Self::HostUnreachable
            | Self::HostBusy
            | Self::ComputerUseNotReady
            | Self::DoctorReadinessBlockersFound => 69,
            Self::RemoteExecution => 74,
            Self::NotImplemented => 78,
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

    pub fn config_error(message: impl Into<String>, source_detail: Option<String>) -> Self {
        Self {
            code: ErrorCode::ConfigError,
            message: message.into(),
            recovery_command: Some("edit the TOML file or run satelle config check".to_string()),
            source_detail,
            details: BTreeMap::new(),
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
        let accepted_keys = ["native_readiness", "provider_smoke_test"];
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
                "use timeouts.native_readiness or timeouts.provider_smoke_test".to_string(),
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
                ["ms", "s", "m"]
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
            recovery_command: Some("use an explicit duration such as 120s or 2m".to_string()),
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

    pub fn project_daemon_path_override_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectDaemonPathOverrideNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot define machine-local daemon path overrides",
        )
    }

    pub fn project_desktop_binding_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectDesktopBindingNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot define personal desktop session bindings",
        )
    }

    pub fn project_yolo_enable_not_allowed(config_file: &Path, toml_path: &str, key: &str) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectYoloEnableNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot enable YOLO mode",
        )
    }

    pub fn project_experimental_provider_opt_in_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectExperimentalProviderOptInNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot satisfy experimental provider Computer Use opt-in",
        )
    }

    pub fn project_mutation_consent_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectMutationConsentNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot grant noninteractive mutation consent",
        )
    }

    pub fn project_secret_source_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectSecretSourceNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot define provider authentication secret sources",
        )
    }

    pub fn project_credential_helper_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectCredentialHelperNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot define executable credential helper behavior",
        )
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

    fn project_forbidden_config_error(
        code: ErrorCode,
        config_file: &Path,
        toml_path: &str,
        key: &str,
        reason: &str,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(toml_path.to_string()));
        details.insert("key".to_string(), Value::String(key.to_string()));
        details.insert("scope".to_string(), Value::String("project".to_string()));

        Self {
            code,
            message: format!(
                "config file {} contains project-level key '{key}' at {toml_path}: {reason}",
                config_file.display()
            ),
            recovery_command: Some("move this setting to user-level configuration".to_string()),
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

    pub fn host_not_found(alias: String) -> Self {
        Self {
            code: ErrorCode::HostNotFound,
            message: format!("host '{alias}' is not configured"),
            recovery_command: Some("satelle setup --host local-demo --dry-run".to_string()),
            source_detail: None,
            details: BTreeMap::new(),
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    Started,
    Completed,
    Blocked,
    Failed,
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TurnRecord {
    pub turn_id: TurnId,
    pub status: TurnStatus,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub session_id: SessionId,
    pub host: String,
    pub status: TurnStatus,
    pub created_at: String,
    pub updated_at: String,
    pub turns: Vec<TurnRecord>,
}

impl SessionRecord {
    pub fn latest_turn(&self) -> Option<&TurnRecord> {
        self.turns.last()
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub timestamp: String,
    pub source: String,
    pub severity: String,
    pub host: String,
    pub session_id: Option<SessionId>,
    pub message: String,
    pub fields: BTreeMap<String, String>,
    pub redacted: bool,
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
