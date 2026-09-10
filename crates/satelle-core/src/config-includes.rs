use super::{
    ErrorCode, SatelleError, read_bounded_regular_file_no_follow, read_owner_controlled_config_file,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Preserve literal TOML keys in provenance, including aliases containing dots.
pub fn config_toml_key(key: &str) -> String {
    if !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        key.to_string()
    } else {
        serde_json::to_string(key).expect("a TOML key can be serialized as a string")
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSourceKind {
    UserConfig,
    ProjectConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigFileSource {
    pub path: PathBuf,
    pub parent: Option<PathBuf>,
    pub source: ConfigSourceKind,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigValueSource {
    pub config_file: PathBuf,
    pub toml_path: String,
    pub source: ConfigSourceKind,
}

/// File and field provenance from the same reads used to resolve configuration.
/// This deliberately contains no configuration values or resolved secrets.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigSources {
    pub files: Vec<ConfigFileSource>,
    pub values: BTreeMap<String, ConfigValueSource>,
}

impl ConfigSources {
    pub fn value_at(&self, keys: &[&str]) -> Option<&ConfigValueSource> {
        self.values.get(
            &keys
                .iter()
                .map(|key| config_toml_key(key))
                .collect::<Vec<_>>()
                .join("."),
        )
    }

    pub(super) fn record(&mut self, file: ConfigFileSource, value: &toml::Value) {
        // User-owned bindings and profiles replace complete objects. Drop their
        // previous field origins together with the values they used to describe.
        if file.source == ConfigSourceKind::UserConfig {
            for namespace in ["hosts", "profiles", "trusted_profiles"] {
                if let Some(entries) = value.get(namespace).and_then(toml::Value::as_table) {
                    for name in entries.keys() {
                        let prefix = format!("{namespace}.{}.", config_toml_key(name));
                        self.values.retain(|key, _| !key.starts_with(&prefix));
                    }
                }
            }
            if value.get("api_rate_limits").is_some() {
                self.values
                    .retain(|key, _| !key.starts_with("api_rate_limits."));
            }
        }
        self.record_fields("", value, &file);
        self.files.push(file);
    }

    fn record_fields(&mut self, prefix: &str, value: &toml::Value, file: &ConfigFileSource) {
        if let Some(table) = value.as_table() {
            for (key, child) in table {
                let helper_environment = key == "environment"
                    && value.get("kind").and_then(toml::Value::as_str) == Some("executable-helper");
                let key = config_toml_key(key);
                let path = if prefix.is_empty() {
                    key
                } else {
                    format!("{prefix}.{key}")
                };
                if helper_environment {
                    // A helper environment is one descriptor field. Recording
                    // its private key names as TOML paths would reveal them in
                    // config explain even after the descriptor is redacted.
                    self.record_field(&path, file);
                } else {
                    self.record_fields(&path, child, file);
                }
            }
        } else {
            self.record_field(prefix, file);
        }
    }

    fn record_field(&mut self, path: &str, file: &ConfigFileSource) {
        self.values.insert(
            path.to_string(),
            ConfigValueSource {
                config_file: file.path.clone(),
                toml_path: path.to_string(),
                source: file.source,
            },
        );
    }

    pub(super) fn extend(&mut self, higher: &Self) {
        self.files.extend(higher.files.iter().cloned());
        self.values.extend(higher.values.clone());
    }
}

pub(super) struct ConfigDocument {
    pub source: ConfigFileSource,
    pub value: toml::Value,
}

/// Load explicit includes in precedence order without following links or leaving
/// this source's directory. Schema validation happens on every document before
/// the typed user/project loader applies it.
pub(super) fn read(
    path: &Path,
    source: ConfigSourceKind,
) -> Result<Vec<ConfigDocument>, SatelleError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(include_error(
                path,
                ErrorCode::ConfigIncludeInvalid,
                &error.to_string(),
            ));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(include_error(
                path,
                ErrorCode::ConfigIncludeInvalid,
                "configuration must be a regular file, not a symbolic link or directory",
            ));
        }
        Ok(_) => {}
    }
    let root = path
        .parent()
        .expect("configuration paths are absolute")
        .canonicalize()
        .map_err(|error| {
            include_error(path, ErrorCode::ConfigIncludeInvalid, &error.to_string())
        })?;
    let mut documents = Vec::new();
    visit(path, &root, None, source, &mut Vec::new(), &mut documents)?;
    Ok(documents)
}

fn visit(
    path: &Path,
    root: &Path,
    parent: Option<&Path>,
    source: ConfigSourceKind,
    chain: &mut Vec<PathBuf>,
    documents: &mut Vec<ConfigDocument>,
) -> Result<(), SatelleError> {
    if chain.len() >= 64 || documents.len() + chain.len() >= 256 {
        return Err(include_error(
            path,
            ErrorCode::ConfigIncludeInvalid,
            "config includes exceed 64 levels or 256 files",
        ));
    }
    let normalized = path.canonicalize().map_err(|_| {
        include_error(
            path,
            ErrorCode::ConfigIncludeInvalid,
            "config include must name an existing regular TOML file",
        )
    })?;
    if !normalized.starts_with(root) {
        return Err(include_error(
            path,
            ErrorCode::ConfigIncludeOutsideSource,
            "config include is outside its source directory",
        ));
    }
    if chain.contains(&normalized) {
        let mut error = include_error(
            path,
            ErrorCode::ConfigIncludeCycle,
            "config includes form a cycle",
        );
        let mut include_chain = chain.clone();
        include_chain.push(normalized);
        error
            .details
            .insert("include_chain".into(), serde_json::json!(include_chain));
        return Err(error);
    }
    if parent.is_some() {
        // Check the declared path as well as its canonical target. Otherwise a
        // link inside the tree would become invisible after canonicalization.
        for ancestor in path.ancestors() {
            if ancestor == root {
                break;
            }
            let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| {
                include_error(
                    path,
                    ErrorCode::ConfigIncludeInvalid,
                    "config include path is not readable",
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(include_error(
                    path,
                    ErrorCode::ConfigIncludeInvalid,
                    "config include paths cannot contain symbolic links",
                ));
            }
        }
    }
    let raw = match source {
        ConfigSourceKind::UserConfig => read_owner_controlled_config_file(&normalized),
        ConfigSourceKind::ProjectConfig => {
            read_bounded_regular_file_no_follow(&normalized, 1024 * 1024).and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| super::SecureFileError::NotUtf8)
            })
        }
    }
    .map_err(|error| {
        let policy = match source {
            ConfigSourceKind::UserConfig => "owner security policy",
            ConfigSourceKind::ProjectConfig => "file security policy",
        };
        SatelleError::config_error(
            format!(
                "config file {} does not satisfy the {policy}",
                path.display()
            ),
            Some(error.to_string()),
        )
    })?;
    let mut value = toml::from_str::<toml::Value>(&raw).map_err(|error| {
        SatelleError::config_error(
            format!("could not parse config file {}", path.display()),
            Some(error.to_string()),
        )
    })?;
    let includes = value
        .as_table_mut()
        .and_then(|table| table.remove("include"));
    chain.push(normalized.clone());
    if let Some(includes) = includes {
        let paths = includes.as_array().ok_or_else(|| {
            include_error(
                path,
                ErrorCode::ConfigIncludeInvalid,
                "include must be an array of explicit TOML file paths",
            )
        })?;
        for entry in paths {
            let declared = entry.as_str().ok_or_else(|| {
                include_error(
                    path,
                    ErrorCode::ConfigIncludeInvalid,
                    "include entries must be TOML file paths",
                )
            })?;
            if declared.is_empty()
                || declared.contains(['~', '$', '*', '?', '[', ']'])
                || super::interpolation_syntax(declared).is_some()
                || declared.contains("://")
                || Path::new(declared)
                    .extension()
                    .is_none_or(|extension| extension != "toml")
            {
                return Err(include_error(
                    path,
                    ErrorCode::ConfigIncludeInvalid,
                    "include entries must name literal .toml files without URLs, globs, or shell syntax",
                ));
            }
            let target = normalized
                .parent()
                .expect("configuration files have a parent")
                .join(declared);
            visit(&target, root, Some(path), source, chain, documents)?;
        }
    }
    chain.pop();
    documents.push(ConfigDocument {
        source: ConfigFileSource {
            // Keep the selected spelling in diagnostics and provenance. The
            // canonical identity above is for boundary and cycle checks, and
            // can use a different drive or account spelling on Windows.
            path: path.to_path_buf(),
            parent: parent.map(Path::to_path_buf),
            source,
        },
        value,
    });
    Ok(())
}

fn include_error(path: &Path, code: ErrorCode, message: &str) -> SatelleError {
    SatelleError {
        code,
        message: message.to_string(),
        recovery_command: Some(
            "correct the include paths, then run satelle config check".to_string(),
        ),
        source_detail: None,
        details: BTreeMap::from([
            ("config_file".into(), serde_json::json!(path)),
            ("toml_path".into(), serde_json::json!("include")),
        ]),
    }
}
