use super::{
    ConfigInterpolation, ErrorCode, ExplicitDuration, HostConfig, SatelleConfig, SatelleError,
    TimeoutConfig, UnknownConfigKey, collect_interpolation_for_value,
    collect_unknown_keys_for_table, finish_interpolation_check, interpolation_syntax,
    optional_non_empty_env,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

const PROFILE_KEYS: &[&str] = &[
    "host",
    "model_alias",
    "provider_alias",
    "experimental_provider_computer_use",
    "experimental_provider_computer_use_by_provider",
    "yolo",
    "timeouts",
    "native_readiness_cache_ttl",
    "provider_smoke_success_cache_ttl",
    "provider_smoke_failure_cache_ttl",
    "daemon_idle_timeout",
];
const TIMEOUT_KEYS: &[&str] = &["native_readiness", "provider_smoke_test", "turn_execution"];

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSelectionSource {
    UserConfig,
    ProjectConfig,
    Environment,
    CliFlag,
}

impl ProfileSelectionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserConfig => "user_config",
            Self::ProjectConfig => "project_config",
            Self::Environment => "environment",
            Self::CliFlag => "cli_flag",
        }
    }

    fn allows_user_policy(self) -> bool {
        matches!(self, Self::UserConfig | Self::CliFlag)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectedProfile {
    pub name: String,
    pub source: ProfileSelectionSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileField {
    ModelAlias,
    ProviderAlias,
    ExperimentalProviderComputerUse,
    Yolo,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ProfileConfig {
    host: Option<String>,
    model_alias: Option<String>,
    provider_alias: Option<String>,
    experimental_provider_computer_use: Option<bool>,
    #[serde(default)]
    experimental_provider_computer_use_by_provider: BTreeMap<String, bool>,
    yolo: Option<bool>,
    timeouts: Option<TimeoutConfig>,
    native_readiness_cache_ttl: Option<ExplicitDuration>,
    provider_smoke_success_cache_ttl: Option<ExplicitDuration>,
    provider_smoke_failure_cache_ttl: Option<ExplicitDuration>,
    daemon_idle_timeout: Option<ExplicitDuration>,
}

impl ProfileConfig {
    pub(super) fn selected_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn yolo_applies(&self, source: ProfileSelectionSource) -> bool {
        match self.yolo {
            Some(false) => true,
            Some(true) => source.allows_user_policy(),
            None => false,
        }
    }

    pub(super) fn apply_to_base(&self, config: &mut SatelleConfig, source: ProfileSelectionSource) {
        if let Some(host) = &self.host {
            config.default_host = Some(host.clone());
        }
        if let Some(model_alias) = &self.model_alias {
            config.model_alias = Some(model_alias.clone());
        }
        if let Some(provider_alias) = &self.provider_alias {
            config.provider_alias = Some(provider_alias.clone());
        }
        if source.allows_user_policy()
            && let Some(enabled) = self.experimental_provider_computer_use
        {
            config.experimental_provider_computer_use = Some(enabled);
        }
        if source.allows_user_policy() {
            for (provider_alias, enabled) in &self.experimental_provider_computer_use_by_provider {
                config
                    .experimental_provider_computer_use_by_provider
                    .insert(provider_alias.clone(), *enabled);
            }
        }
    }

    pub(super) fn apply_to_host(
        &self,
        alias: &str,
        host: &mut HostConfig,
        source: ProfileSelectionSource,
    ) {
        if let Some(timeouts) = &self.timeouts {
            host.timeouts = Some(host.timeouts.take().map_or_else(
                || TimeoutConfig::default_profile_overlay(timeouts.clone()),
                |base| base.merge(timeouts.clone()),
            ));
        }
        if let Some(ttl) = &self.native_readiness_cache_ttl {
            host.native_readiness_cache_ttl = Some(ttl.clone());
        }
        if let Some(ttl) = &self.provider_smoke_success_cache_ttl {
            host.provider_smoke_success_cache_ttl = Some(ttl.clone());
        }
        if let Some(ttl) = &self.provider_smoke_failure_cache_ttl {
            host.provider_smoke_failure_cache_ttl = Some(ttl.clone());
        }
        if let Some(timeout) = &self.daemon_idle_timeout {
            host.daemon_idle_timeout = Some(timeout.clone());
        }
        if source.allows_user_policy()
            && let Some(enabled) = self.experimental_provider_computer_use
        {
            host.experimental_provider_computer_use = Some(enabled);
        }
        if source.allows_user_policy() {
            for (provider_alias, enabled) in &self.experimental_provider_computer_use_by_provider {
                host.experimental_provider_computer_use_by_provider
                    .insert(provider_alias.clone(), *enabled);
            }
        }
        if self.host.as_deref() == Some(alias)
            && self.yolo_applies(source)
            && let Some(enabled) = self.yolo
        {
            host.yolo = Some(enabled);
        }
    }

    pub(super) fn overrides_for_host(
        &self,
        field: ProfileField,
        host: &str,
        source: ProfileSelectionSource,
    ) -> bool {
        match field {
            ProfileField::ModelAlias => self.model_alias.is_some(),
            ProfileField::ProviderAlias => self.provider_alias.is_some(),
            ProfileField::ExperimentalProviderComputerUse => {
                self.experimental_provider_computer_use.is_some() && source.allows_user_policy()
            }
            ProfileField::Yolo => self.host.as_deref() == Some(host) && self.yolo_applies(source),
        }
    }
}

pub(super) struct ProfileFileData {
    pub default_profile: Option<String>,
    pub profiles: BTreeMap<String, ProfileConfig>,
}

pub(super) fn extract_profile_data(
    path: &Path,
    value: &mut toml::Value,
    allow_definitions: bool,
) -> Result<ProfileFileData, SatelleError> {
    let table = value.as_table_mut().ok_or_else(|| {
        SatelleError::config_error(
            format!("config file {} must contain a TOML table", path.display()),
            None,
        )
    })?;
    let default_profile = table
        .remove("profile")
        .map(|value| parse_default_profile(path, value))
        .transpose()?;
    let raw_profiles = table.remove("profiles");

    if raw_profiles.is_some() && !allow_definitions {
        return Err(SatelleError::project_profile_definition_not_allowed(path));
    }

    let profiles = raw_profiles
        .map(|value| parse_profiles(path, value))
        .transpose()?
        .unwrap_or_default();

    Ok(ProfileFileData {
        default_profile,
        profiles,
    })
}

fn parse_default_profile(path: &Path, value: toml::Value) -> Result<String, SatelleError> {
    let profile = value
        .as_str()
        .filter(|profile| !profile.is_empty())
        .ok_or_else(|| {
            SatelleError::config_error(
                format!(
                    "config file {} profile must be a non-empty string",
                    path.display()
                ),
                None,
            )
        })?;
    if let Some(syntax) = interpolation_syntax(profile) {
        return Err(SatelleError::config_interpolation_not_supported(
            path,
            vec![ConfigInterpolation {
                toml_path: "profile".to_string(),
                syntax,
            }],
        ));
    }
    Ok(profile.to_string())
}

fn parse_profiles(
    path: &Path,
    value: toml::Value,
) -> Result<BTreeMap<String, ProfileConfig>, SatelleError> {
    let table = value.as_table().ok_or_else(|| {
        SatelleError::config_error(
            format!(
                "config file {} profiles must be a TOML table",
                path.display()
            ),
            None,
        )
    })?;
    let mut profiles = BTreeMap::new();

    for (name, value) in table {
        if name.is_empty() {
            return Err(SatelleError::config_error(
                format!(
                    "config file {} profile names must not be empty",
                    path.display()
                ),
                None,
            ));
        }
        validate_profile(path, name, value)?;
        let profile = value
            .clone()
            .try_into()
            .map_err(|source: toml::de::Error| {
                SatelleError::config_error(
                    format!(
                        "could not decode profile '{}' in config file {}",
                        name,
                        path.display()
                    ),
                    Some(source.to_string()),
                )
            })?;
        profiles.insert(name.clone(), profile);
    }

    Ok(profiles)
}

fn validate_profile(path: &Path, name: &str, value: &toml::Value) -> Result<(), SatelleError> {
    let profile_path = format!("profiles.{name}");
    let table = value.as_table().ok_or_else(|| {
        SatelleError::config_error(
            format!(
                "config file {} profile '{}' must be a TOML table",
                path.display(),
                name
            ),
            None,
        )
    })?;
    let mut unknown_keys = Vec::<UnknownConfigKey>::new();
    collect_unknown_keys_for_table(&profile_path, table, PROFILE_KEYS, &mut unknown_keys);

    if !unknown_keys.is_empty() {
        return Err(SatelleError::unknown_config_keys(path, unknown_keys));
    }

    let profile_host =
        match table.get("host") {
            Some(value) => Some(value.as_str().filter(|host| !host.is_empty()).ok_or_else(
                || {
                    SatelleError::config_error(
                        format!(
                            "config file {} profile '{}' host must be a non-empty string",
                            path.display(),
                            name
                        ),
                        None,
                    )
                },
            )?),
            None => None,
        };
    if table.contains_key("yolo") && profile_host.is_none() {
        return Err(SatelleError::config_error(
            format!(
                "config file {} profile '{}' must bind yolo to a non-empty host alias",
                path.display(),
                name
            ),
            None,
        ));
    }

    reject_profile_interpolation(path, &profile_path, table)?;
    reject_profile_duration_errors(path, &profile_path, table)
}

fn reject_profile_interpolation(
    path: &Path,
    profile_path: &str,
    table: &toml::Table,
) -> Result<(), SatelleError> {
    let mut interpolations = Vec::<ConfigInterpolation>::new();
    for key in ["host", "model_alias", "provider_alias"] {
        collect_interpolation_for_value(
            &format!("{profile_path}.{key}"),
            table.get(key),
            &mut interpolations,
        );
    }
    collect_interpolation_for_value(
        &format!("{profile_path}.native_readiness_cache_ttl"),
        table.get("native_readiness_cache_ttl"),
        &mut interpolations,
    );
    for key in [
        "provider_smoke_success_cache_ttl",
        "provider_smoke_failure_cache_ttl",
    ] {
        collect_interpolation_for_value(
            &format!("{profile_path}.{key}"),
            table.get(key),
            &mut interpolations,
        );
    }
    collect_interpolation_for_value(
        &format!("{profile_path}.daemon_idle_timeout"),
        table.get("daemon_idle_timeout"),
        &mut interpolations,
    );
    if let Some(timeouts) = table.get("timeouts").and_then(toml::Value::as_table) {
        for key in TIMEOUT_KEYS {
            collect_interpolation_for_value(
                &format!("{profile_path}.timeouts.{key}"),
                timeouts.get(*key),
                &mut interpolations,
            );
        }
    }
    finish_interpolation_check(path, interpolations)
}

fn reject_profile_duration_errors(
    path: &Path,
    profile_path: &str,
    table: &toml::Table,
) -> Result<(), SatelleError> {
    if let Some(value) = table.get("native_readiness_cache_ttl") {
        let ttl_path = format!("{profile_path}.native_readiness_cache_ttl");
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
        if let Some(value) = table.get(key) {
            let ttl_path = format!("{profile_path}.{key}");
            let Some(value) = value.as_str() else {
                return Err(SatelleError::duration_unit_required(path, &ttl_path));
            };
            if ExplicitDuration::parse(value).is_none() {
                return Err(SatelleError::duration_unit_required(path, &ttl_path));
            }
        }
    }
    if let Some(value) = table.get("daemon_idle_timeout") {
        let timeout_path = format!("{profile_path}.daemon_idle_timeout");
        let Some(value) = value.as_str() else {
            return Err(SatelleError::duration_unit_required(path, &timeout_path));
        };
        if ExplicitDuration::parse(value).is_none() {
            return Err(SatelleError::duration_unit_required(path, &timeout_path));
        }
    }
    let Some(timeouts) = table.get("timeouts").and_then(toml::Value::as_table) else {
        return Ok(());
    };

    for (key, value) in timeouts {
        let timeout_path = format!("{profile_path}.timeouts.{key}");
        if !TIMEOUT_KEYS.contains(&key.as_str()) {
            return Err(SatelleError::unknown_timeout_key(path, &timeout_path, key));
        }
        let Some(value) = value.as_str() else {
            return Err(SatelleError::duration_unit_required(path, &timeout_path));
        };
        if key == "turn_execution" {
            let Some(seconds) = super::parse_turn_execution_seconds(value) else {
                return Err(SatelleError::turn_duration_unit_required(
                    path,
                    &timeout_path,
                ));
            };
            if seconds > super::MAX_TURN_EXECUTION_TIMEOUT_MS / 1_000 {
                return Err(SatelleError::turn_timeout_config_limit_exceeded(
                    path,
                    &timeout_path,
                ));
            }
        } else if ExplicitDuration::parse(value).is_none() {
            return Err(SatelleError::duration_unit_required(path, &timeout_path));
        }
    }
    Ok(())
}

pub(super) fn select_profile(
    flag_profile: Option<&str>,
    user_default: Option<&str>,
    project_default: Option<&str>,
) -> Option<SelectedProfile> {
    if let Some(name) = flag_profile {
        return Some(SelectedProfile {
            name: name.to_string(),
            source: ProfileSelectionSource::CliFlag,
        });
    }
    if let Some(name) = optional_non_empty_env("SATELLE_PROFILE") {
        return Some(SelectedProfile {
            name,
            source: ProfileSelectionSource::Environment,
        });
    }
    if let Some(name) = project_default {
        return Some(SelectedProfile {
            name: name.to_string(),
            source: ProfileSelectionSource::ProjectConfig,
        });
    }
    user_default.map(|name| SelectedProfile {
        name: name.to_string(),
        source: ProfileSelectionSource::UserConfig,
    })
}

impl SatelleError {
    pub fn profile_not_found(path: &Path, profile: &str, available_profiles: Vec<String>) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(path.display().to_string()),
        );
        details.insert("profile".to_string(), Value::String(profile.to_string()));
        details.insert(
            "available_profiles".to_string(),
            Value::Array(available_profiles.into_iter().map(Value::String).collect()),
        );

        Self {
            code: ErrorCode::ProfileNotFound,
            message: format!(
                "profile '{}' is not defined in user config file {}",
                profile,
                path.display()
            ),
            recovery_command: Some(
                "define [profiles.<name>] in user config or select another profile".to_string(),
            ),
            source_detail: None,
            details,
        }
    }

    pub fn project_profile_definition_not_allowed(path: &Path) -> Self {
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(path.display().to_string()),
        );
        details.insert("path".to_string(), Value::String("profiles".to_string()));

        Self {
            code: ErrorCode::ProjectProfileDefinitionNotAllowed,
            message: format!(
                "project config file {} cannot define user-level profiles",
                path.display()
            ),
            recovery_command: Some(
                "move profile definitions to user config; projects may only set profile"
                    .to_string(),
            ),
            source_detail: None,
            details,
        }
    }
}

#[cfg(test)]
mod timeout_profile_tests {
    use super::*;

    fn profile(raw_timeouts: &str) -> ProfileConfig {
        toml::from_str(&format!("[timeouts]\n{raw_timeouts}"))
            .expect("parse profile timeout fixture")
    }

    fn timeout_config(raw: &str) -> TimeoutConfig {
        toml::from_str(raw).expect("parse base timeout fixture")
    }

    fn base_host() -> HostConfig {
        super::super::SatelleConfig::defaults()
            .hosts
            .remove(super::super::LOCAL_DEMO_HOST)
            .expect("default local Host")
    }

    #[test]
    fn profile_turn_timeout_above_the_hard_limit_reports_the_limit() {
        let path = Path::new("user-config.toml");
        let table = toml::from_str::<toml::Table>("[timeouts]\nturn_execution = \"25h\"\n")
            .expect("parse invalid profile timeout fixture");

        let error = reject_profile_duration_errors(path, "profiles.fast", &table)
            .expect_err("a profile Turn timeout above 24h must fail");

        assert_eq!(error.code, ErrorCode::ConfigError);
        assert_eq!(
            error.details["path"],
            serde_json::json!("profiles.fast.timeouts.turn_execution")
        );
        assert_eq!(
            error.details["maximum_timeout_ms"],
            serde_json::json!(super::super::MAX_TURN_EXECUTION_TIMEOUT_MS)
        );
    }

    #[test]
    fn every_profile_source_can_only_shorten_turn_execution() {
        let profile = profile(
            "native_readiness = \"20s\"\nprovider_smoke_test = \"30s\"\nturn_execution = \"1h\"\n",
        );

        for source in [
            ProfileSelectionSource::UserConfig,
            ProfileSelectionSource::Environment,
            ProfileSelectionSource::CliFlag,
            ProfileSelectionSource::ProjectConfig,
        ] {
            let mut host = base_host();
            host.timeouts = Some(timeout_config(
                "native_readiness = \"5s\"\nprovider_smoke_test = \"6s\"\nturn_execution = \"10m\"\n",
            ));

            profile.apply_to_host(super::super::LOCAL_DEMO_HOST, &mut host, source);

            let timeouts = host.timeouts.expect("retain merged profile timeouts");
            assert_eq!(
                timeouts.native_readiness.unwrap().milliseconds(),
                20_000,
                "source={source:?}"
            );
            assert_eq!(
                timeouts.provider_smoke_test.unwrap().milliseconds(),
                30_000,
                "source={source:?}"
            );
            assert_eq!(
                timeouts.turn_execution.unwrap().milliseconds(),
                10 * 60 * 1_000,
                "source={source:?}"
            );
        }
    }

    #[test]
    fn every_profile_source_respects_the_implicit_30_minute_default() {
        let lengthening = profile(
            "native_readiness = \"20s\"\nprovider_smoke_test = \"30s\"\nturn_execution = \"1h\"\n",
        );
        let shortening = profile("turn_execution = \"10m\"\n");

        for source in [
            ProfileSelectionSource::UserConfig,
            ProfileSelectionSource::Environment,
            ProfileSelectionSource::CliFlag,
            ProfileSelectionSource::ProjectConfig,
        ] {
            let mut host = base_host();
            lengthening.apply_to_host(super::super::LOCAL_DEMO_HOST, &mut host, source);
            let timeouts = host
                .timeouts
                .as_ref()
                .expect("retain unrelated profile timeouts");
            assert!(timeouts.turn_execution.is_none(), "source={source:?}");
            assert_eq!(
                timeouts.native_readiness.as_ref().unwrap().milliseconds(),
                20_000
            );
            assert_eq!(
                timeouts
                    .provider_smoke_test
                    .as_ref()
                    .unwrap()
                    .milliseconds(),
                30_000
            );

            shortening.apply_to_host(super::super::LOCAL_DEMO_HOST, &mut host, source);
            assert_eq!(
                host.timeouts
                    .unwrap()
                    .turn_execution
                    .unwrap()
                    .milliseconds(),
                10 * 60 * 1_000,
                "source={source:?}"
            );
        }
    }
}
