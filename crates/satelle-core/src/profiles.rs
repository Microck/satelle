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
    "yolo",
    "timeouts",
    "native_readiness_cache_ttl",
    "provider_smoke_success_cache_ttl",
    "provider_smoke_failure_cache_ttl",
    "daemon_idle_timeout",
];
const TIMEOUT_KEYS: &[&str] = &["native_readiness", "provider_smoke_test"];

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
    }

    pub(super) fn apply_to_host(
        &self,
        alias: &str,
        host: &mut HostConfig,
        source: ProfileSelectionSource,
    ) {
        if let Some(timeouts) = &self.timeouts {
            host.timeouts = Some(
                host.timeouts
                    .take()
                    .map_or_else(|| timeouts.clone(), |base| base.merge(timeouts.clone())),
            );
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
        if ExplicitDuration::parse(value).is_none() {
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
