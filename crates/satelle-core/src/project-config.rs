use super::{
    ErrorCode, SatelleConfig, SatelleError, TimeoutConfig, TransportKind,
    collect_unknown_keys_for_table, profiles, reject_config_composition, reject_interpolation,
    reject_timeout_config_errors,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const ACCEPTED_ROOT_KEYS: &[&str] = &[
    "default_host",
    "model_alias",
    "provider_alias",
    "profile",
    "hosts",
];
const ACCEPTED_HOST_KEYS: &[&str] = &["transport", "timeouts"];
const SECRET_SOURCE_KEYS: &[&str] = &[
    "api_token",
    "ca_bundle",
    "expected_host_id",
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
const CREDENTIAL_HELPER_KEYS: &[&str] = &[
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProjectConfig {
    default_host: Option<String>,
    model_alias: Option<String>,
    provider_alias: Option<String>,
    #[serde(default)]
    hosts: BTreeMap<String, ProjectHostIntent>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProjectHostIntent {
    transport: Option<TransportKind>,
    timeouts: Option<TimeoutConfig>,
}

pub(super) struct ParsedProjectConfig {
    config: ProjectConfig,
    pub(super) default_profile: Option<String>,
}

pub(super) fn validate_selected_profile_host(
    alias: &str,
    user_bound_hosts: &BTreeSet<String>,
    user_config_path: &Path,
    project_config_path: &Path,
) -> Result<(), SatelleError> {
    if user_bound_hosts.contains(alias) {
        return Ok(());
    }

    Err(SatelleError::project_host_binding_not_found_at(
        project_config_path,
        "profile",
        user_config_path,
        alias,
    ))
}

impl ParsedProjectConfig {
    pub(super) fn default_host(&self) -> Option<&str> {
        self.config.default_host.as_deref()
    }

    pub(super) fn selects_default_host(&self) -> bool {
        self.config.default_host.is_some()
    }

    pub(super) fn apply_to(
        &self,
        mut base: SatelleConfig,
        user_bound_hosts: &BTreeSet<String>,
        user_config_path: &Path,
        project_config_path: &Path,
    ) -> Result<SatelleConfig, SatelleError> {
        // Validate the complete overlay before mutating the effective config. Built-in defaults
        // are deliberately excluded from user_bound_hosts because repository intent never counts
        // as operator authorization for a concrete Host Binding.
        if let Some(alias) = &self.config.default_host
            && !user_bound_hosts.contains(alias)
        {
            return Err(SatelleError::project_host_binding_not_found_at(
                project_config_path,
                "default_host",
                user_config_path,
                alias,
            ));
        }

        for (alias, intent) in &self.config.hosts {
            if !user_bound_hosts.contains(alias) {
                return Err(SatelleError::project_host_binding_not_found(
                    project_config_path,
                    user_config_path,
                    alias,
                ));
            }
            let host = base.hosts.get(alias).ok_or_else(|| {
                SatelleError::project_host_binding_not_found(
                    project_config_path,
                    user_config_path,
                    alias,
                )
            })?;
            if let Some(project_transport) = &intent.transport
                && project_transport != &host.transport
            {
                return Err(SatelleError::project_transport_preference_not_allowed(
                    project_config_path,
                    alias,
                    project_transport,
                    &host.transport,
                ));
            }
        }

        if self.config.default_host.is_some() {
            base.default_host.clone_from(&self.config.default_host);
        }
        if self.config.model_alias.is_some() {
            base.model_alias.clone_from(&self.config.model_alias);
        }
        if self.config.provider_alias.is_some() {
            base.provider_alias.clone_from(&self.config.provider_alias);
        }

        for (alias, intent) in &self.config.hosts {
            if let Some(timeouts) = &intent.timeouts {
                let host = base
                    .hosts
                    .get_mut(alias)
                    .expect("project host intents were validated before application");
                host.timeouts = Some(
                    host.timeouts
                        .take()
                        .map_or_else(|| timeouts.clone(), |base| base.merge(timeouts.clone())),
                );
            }
        }

        Ok(base)
    }
}

pub(super) fn read(path: &Path) -> Result<Option<ParsedProjectConfig>, SatelleError> {
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

    let profile_data = profiles::extract_profile_data(path, &mut value, false)?;
    reject_config_composition(path, &value)?;
    reject_interpolation(path, &value)?;
    reject_timeout_config_errors(path, &value)?;
    reject_forbidden_keys(path, &value)?;
    reject_unknown_keys(path, &value)?;

    let config = value.try_into().map_err(|source: toml::de::Error| {
        SatelleError::config_error(
            format!("could not decode config file {}", path.display()),
            Some(source.to_string()),
        )
    })?;

    Ok(Some(ParsedProjectConfig {
        config,
        default_profile: profile_data.default_profile,
    }))
}

fn reject_forbidden_keys(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
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

    for &key in CREDENTIAL_HELPER_KEYS {
        if table.contains_key(key) {
            return Err(SatelleError::project_credential_helper_not_allowed(
                path, key, key,
            ));
        }
    }

    for &key in SECRET_SOURCE_KEYS {
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

        if host_table.contains_key("allow_project_selection") {
            return Err(SatelleError::project_host_selection_permission_not_allowed(
                path,
                &format!("{host_path}.allow_project_selection"),
            ));
        }

        for &key in CREDENTIAL_HELPER_KEYS {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_credential_helper_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }

        for &key in SECRET_SOURCE_KEYS {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_secret_source_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }

        for key in ["address", "adapter", "network"] {
            if host_table.contains_key(key) {
                return Err(SatelleError::project_host_binding_not_allowed(
                    path,
                    &format!("{host_path}.{key}"),
                    key,
                ));
            }
        }
    }

    Ok(())
}

fn reject_unknown_keys(path: &Path, value: &toml::Value) -> Result<(), SatelleError> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };

    let mut unknown_keys = Vec::new();
    collect_unknown_keys_for_table("", table, ACCEPTED_ROOT_KEYS, &mut unknown_keys);

    if let Some(hosts) = table.get("hosts").and_then(toml::Value::as_table) {
        for (alias, host_value) in hosts {
            let Some(host_table) = host_value.as_table() else {
                continue;
            };
            collect_unknown_keys_for_table(
                &format!("hosts.{alias}"),
                host_table,
                ACCEPTED_HOST_KEYS,
                &mut unknown_keys,
            );
        }
    }

    if unknown_keys.is_empty() {
        Ok(())
    } else {
        Err(SatelleError::unknown_config_keys(path, unknown_keys))
    }
}

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

fn transport_kind_name(transport: &TransportKind) -> &'static str {
    match transport {
        TransportKind::Local => "local",
        TransportKind::Direct => "direct",
        TransportKind::Ssh => "ssh",
    }
}

impl SatelleError {
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

    pub fn project_host_binding_not_allowed(
        config_file: &Path,
        toml_path: &str,
        key: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectHostBindingNotAllowed,
            config_file,
            toml_path,
            key,
            "project configuration cannot define or replace a concrete Host Binding",
        )
    }

    pub fn project_host_binding_not_found(
        project_config_file: &Path,
        user_config_file: &Path,
        alias: &str,
    ) -> Self {
        Self::project_host_binding_not_found_at(
            project_config_file,
            &format!("hosts.{alias}"),
            user_config_file,
            alias,
        )
    }

    fn project_host_binding_not_found_at(
        project_config_file: &Path,
        project_reference_path: &str,
        user_config_file: &Path,
        alias: &str,
    ) -> Self {
        let binding_path = format!("hosts.{alias}");
        let project_config_file = project_config_file.display().to_string();
        let user_config_file = user_config_file.display().to_string();
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(project_config_file.clone()),
        );
        details.insert(
            "path".to_string(),
            Value::String(project_reference_path.to_string()),
        );
        details.insert(
            "reference_file".to_string(),
            Value::String(project_config_file.clone()),
        );
        details.insert(
            "reference_path".to_string(),
            Value::String(project_reference_path.to_string()),
        );
        details.insert("host".to_string(), Value::String(alias.to_string()));
        details.insert("scope".to_string(), Value::String("project".to_string()));
        details.insert(
            "user_config_file".to_string(),
            Value::String(user_config_file.clone()),
        );
        details.insert(
            "binding_file".to_string(),
            Value::String(user_config_file.clone()),
        );
        details.insert(
            "binding_path".to_string(),
            Value::String(binding_path.clone()),
        );

        Self {
            code: ErrorCode::HostNotFound,
            message: format!(
                "config file {project_config_file} references host '{alias}' at {project_reference_path}, but no trusted user-level Host Binding exists at {binding_path} in {user_config_file}"
            ),
            recovery_command: Some(format!(
                "configure {binding_path} in user-level config {user_config_file}; set {binding_path}.allow_project_selection = true there when the project selects this host implicitly"
            )),
            source_detail: None,
            details,
        }
    }

    pub fn project_transport_preference_not_allowed(
        config_file: &Path,
        alias: &str,
        project_transport: &TransportKind,
        trusted_transport: &TransportKind,
    ) -> Self {
        let path = format!("hosts.{alias}.transport");
        let trusted_transport = transport_kind_name(trusted_transport);
        let mut details = BTreeMap::new();
        details.insert(
            "file".to_string(),
            Value::String(config_file.display().to_string()),
        );
        details.insert("path".to_string(), Value::String(path.clone()));
        details.insert("key".to_string(), Value::String("transport".to_string()));
        details.insert("scope".to_string(), Value::String("project".to_string()));
        details.insert("host".to_string(), Value::String(alias.to_string()));
        details.insert(
            "project_transport".to_string(),
            Value::String(transport_kind_name(project_transport).to_string()),
        );
        details.insert(
            "trusted_transport".to_string(),
            Value::String(trusted_transport.to_string()),
        );

        Self {
            code: ErrorCode::ProjectHostBindingNotAllowed,
            message: format!(
                "config file {} sets project transport '{}' at {path}, but trusted host '{alias}' uses '{trusted_transport}'",
                config_file.display(),
                transport_kind_name(project_transport)
            ),
            recovery_command: Some(format!(
                "remove {path} from {} or set it to \"{trusted_transport}\" to match the trusted Host Binding",
                config_file.display()
            )),
            source_detail: None,
            details,
        }
    }

    pub fn project_host_selection_permission_not_allowed(
        config_file: &Path,
        toml_path: &str,
    ) -> Self {
        Self::project_forbidden_config_error(
            ErrorCode::ProjectHostSelectionNotAllowed,
            config_file,
            toml_path,
            "allow_project_selection",
            "only the user-level Host Binding can authorize project selection",
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
}
