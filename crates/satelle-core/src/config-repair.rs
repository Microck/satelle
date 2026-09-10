use crate::config_includes::{self, ConfigDocuments};
use crate::{ConfigFileSource, ConfigSourceKind, ErrorCode, ResolvedConfig, SatelleError};
use serde::Serialize;
use serde_json::json;
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct KeyRepair {
    pub path: Vec<String>,
    pub corrected_key: String,
}

/// Raw configuration stays private to the local repair operation. It is never
/// serialized or formatted as a diagnostic; only redacted projections leave it.
pub struct RepairFile {
    pub source: ConfigFileSource,
    pub original: String,
    pub repaired_value: toml::Value,
    pub repairs: Vec<KeyRepair>,
}

pub struct RepairPlan {
    pub file: Option<RepairFile>,
    pub resolved: ResolvedConfig,
    pub inputs: Vec<(ConfigFileSource, String)>,
}

/// Build a fresh local proposal and resolve it through the ordinary loader.
/// Selecting a file does not authorize it as a new config source: it must
/// already belong to the discovered user/project include graph.
pub fn plan(
    cwd: &Path,
    flag_profile: Option<&str>,
    selected_file: Option<&Path>,
) -> Result<RepairPlan, SatelleError> {
    let paths = crate::resolve_path_set(cwd)?;
    let target = selected_file
        .map(|path| cwd.join(path))
        .unwrap_or_else(|| paths.config_file.clone());
    let mut documents = ConfigDocuments {
        user: config_includes::read(&paths.config_file, ConfigSourceKind::UserConfig)
            .map_err(|error| manual_action(&target, error.code))?,
        project: config_includes::read(&paths.project_config_file, ConfigSourceKind::ProjectConfig)
            .map_err(|error| manual_action(&target, error.code))?,
    };
    let inputs = documents
        .user
        .iter()
        .chain(&documents.project)
        .map(|document| (document.source.clone(), document.raw.clone()))
        .collect();
    let canonical_target = target.canonicalize().ok();
    let mut file = None;
    for document in documents.user.iter_mut().chain(&mut documents.project) {
        if canonical_target.is_none()
            || document.source.path.canonicalize().ok() != canonical_target
        {
            continue;
        }
        if document.source.source == ConfigSourceKind::ProjectConfig && selected_file.is_none() {
            continue;
        }
        let repairs = repair_keys(&document.source, &mut document.value)?;
        // The same include can occur more than once in the precedence graph.
        // Update every occurrence, but publish only one write and one backup.
        if file.is_none() {
            file = Some(RepairFile {
                source: document.source.clone(),
                original: document.raw.clone(),
                repaired_value: document.value.clone(),
                repairs,
            });
        }
    }
    if file.is_none() && (selected_file.is_some() || canonical_target.is_some()) {
        return Err(manual_action(&target, ErrorCode::ConfigNotFound));
    }
    let resolved =
        crate::load_config_with_profile_selection(cwd, flag_profile, true, None, Some(documents))
            .map_err(|error| manual_action(&target, error.code))?;
    Ok(RepairPlan {
        file,
        resolved,
        inputs,
    })
}

fn validate_document(source: &ConfigFileSource, value: toml::Value) -> Result<(), SatelleError> {
    match source.source {
        ConfigSourceKind::UserConfig => {
            crate::parse_user_config_value(&source.path, value).map(|_| ())
        }
        ConfigSourceKind::ProjectConfig => {
            crate::project_config::parse(&source.path, value).map(|_| ())
        }
    }
}

fn repair_keys(
    source: &ConfigFileSource,
    value: &mut toml::Value,
) -> Result<Vec<KeyRepair>, SatelleError> {
    let mut repairs = Vec::new();
    loop {
        let error = match validate_document(source, value.clone()) {
            Ok(()) => return Ok(repairs),
            Err(error) => error,
        };
        if error.code != ErrorCode::UnknownConfigKey || repairs.len() >= 128 {
            return Err(manual_action(&source.path, error.code));
        }
        let unknown = error
            .details
            .get("unknown_keys")
            .and_then(|value| value.as_array())
            .and_then(|keys| keys.first())
            .ok_or_else(|| manual_action(&source.path, error.code))?;
        let key = unknown["key"].as_str().unwrap_or_default();
        let corrected = key.to_ascii_lowercase().replace('-', "_");
        let accepted = unknown["accepted_keys"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|key| key.as_str() == Some(&corrected)));
        if corrected == key || !accepted {
            return Err(manual_action(&source.path, error.code));
        }
        let mut matches = Vec::new();
        find_key_paths(
            value,
            &mut Vec::new(),
            unknown["path"].as_str().unwrap_or_default(),
            &mut matches,
        );
        let [path] = matches.as_slice() else {
            return Err(manual_action(&source.path, error.code));
        };
        let mut parent = &mut *value;
        for name in &path[..path.len() - 1] {
            parent = parent
                .get_mut(name)
                .expect("the discovered key path exists");
        }
        let table = parent.as_table_mut().expect("schema keys belong to tables");
        if table.contains_key(&corrected) {
            return Err(manual_action(&source.path, error.code));
        }
        let original = table.remove(key).expect("the discovered schema key exists");
        table.insert(corrected.clone(), original);
        repairs.push(KeyRepair {
            path: path.clone(),
            corrected_key: corrected,
        });
    }
}

fn find_key_paths(
    value: &toml::Value,
    prefix: &mut Vec<String>,
    diagnostic_path: &str,
    matches: &mut Vec<Vec<String>>,
) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, child) in table {
        prefix.push(key.clone());
        // Existing unknown-key diagnostics use dotted paths. Refuse an
        // ambiguous match rather than splitting a literal alias containing dots.
        if prefix.join(".") == diagnostic_path {
            matches.push(prefix.clone());
        }
        find_key_paths(child, prefix, diagnostic_path, matches);
        prefix.pop();
    }
}

pub fn manual_action(path: &Path, diagnostic: ErrorCode) -> SatelleError {
    SatelleError {
        code: ErrorCode::ConfigRepairManualActionRequired,
        message: "the local configuration needs a manual correction before repair can proceed".into(),
        recovery_command: Some("run satelle config check, correct the reported configuration, then retry satelle config repair --dry-run".into()),
        source_detail: None,
        details: [
            ("file".into(), json!(path)),
            ("diagnostic_code".into(), json!(diagnostic.as_str())),
            ("mutated".into(), json!(false)),
        ].into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn user_source() -> ConfigFileSource {
        ConfigFileSource {
            path: PathBuf::from("config.toml"),
            parent: None,
            source: ConfigSourceKind::UserConfig,
        }
    }

    #[test]
    fn repairs_schema_spelling_without_changing_values_or_literal_aliases() {
        let mut value: toml::Value = toml::from_str(
            r#"
default-host = "lab.one"
[hosts."lab.one"]
transport = "local"
adapter = "codex"
allow-project-selection = false
"#,
        )
        .unwrap();
        let repairs = repair_keys(&user_source(), &mut value).unwrap();
        assert_eq!(repairs.len(), 2);
        assert_eq!(value["default_host"].as_str(), Some("lab.one"));
        assert_eq!(
            value["hosts"]["lab.one"]["allow_project_selection"].as_bool(),
            Some(false)
        );
        assert_eq!(
            repairs[1].path,
            ["hosts", "lab.one", "allow-project-selection"]
        );
    }

    #[test]
    fn spelling_collisions_fuzzy_guesses_and_value_repairs_require_manual_action() {
        for raw in [
            "default-host = 'one'\ndefault_host = 'two'",
            "defalt_host = 'one'",
            "[hosts.local]\ntransport='local'\nadapter='codex'\ndaemon_idle_timeout=30",
        ] {
            let mut value = toml::from_str(raw).unwrap();
            let error = repair_keys(&user_source(), &mut value).unwrap_err();
            assert_eq!(error.code, ErrorCode::ConfigRepairManualActionRequired);
            assert_eq!(error.details["mutated"], false);
        }
    }
}
