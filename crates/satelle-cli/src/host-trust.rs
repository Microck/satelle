use satelle_core::{ErrorCode, SatelleError, read_owner_controlled_config_file};
use serde::Serialize;
use std::fs::{self, Permissions};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, value};

#[derive(Debug, Serialize)]
pub(crate) struct HostTrustReport {
    schema_version: &'static str,
    host: String,
    endpoint: String,
    observed_host_identity: String,
    previous_expected_host_identity: Option<String>,
    changed: bool,
}

impl HostTrustReport {
    pub(crate) fn new(
        host: impl Into<String>,
        endpoint: impl Into<String>,
        observed_host_identity: impl Into<String>,
        previous_expected_host_identity: Option<String>,
        changed: bool,
    ) -> Self {
        Self {
            schema_version: "satelle.host.trust.v1",
            host: host.into(),
            endpoint: endpoint.into(),
            observed_host_identity: observed_host_identity.into(),
            previous_expected_host_identity,
            changed,
        }
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn observed_host_identity(&self) -> &str {
        &self.observed_host_identity
    }

    pub(crate) fn previous_expected_host_identity(&self) -> Option<&str> {
        self.previous_expected_host_identity.as_deref()
    }

    pub(crate) const fn changed(&self) -> bool {
        self.changed
    }
}

pub(crate) fn persist_host_identity(
    config_path: &Path,
    host_alias: &str,
    observed_identity: &str,
) -> Result<bool, SatelleError> {
    let original = read_owner_controlled_config_file(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not read the user configuration securely",
            Some(error.to_string()),
        )
    })?;
    let mut document = original.parse::<DocumentMut>().map_err(|error| {
        trust_config_error(
            config_path,
            "could not parse the user configuration for Host trust",
            Some(error.to_string()),
        )
    })?;
    let hosts = document
        .get_mut("hosts")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                "the user configuration does not contain a hosts table",
                None,
            )
        })?;
    let host = hosts
        .get_mut(host_alias)
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                &format!("the user configuration does not contain Host Binding {host_alias}"),
                None,
            )
        })?;
    if host
        .get("expected_host_id")
        .and_then(toml_edit::Item::as_str)
        == Some(observed_identity)
    {
        return Ok(false);
    }
    host.insert("expected_host_id", value(observed_identity));
    persist_config(config_path, document.to_string().as_bytes())?;
    Ok(true)
}

fn persist_config(config_path: &Path, contents: &[u8]) -> Result<(), SatelleError> {
    let metadata = fs::symlink_metadata(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not inspect the user configuration",
            Some(error.to_string()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(trust_config_error(
            config_path,
            "the user configuration is not a regular file",
            None,
        ));
    }
    let parent = config_path.parent().ok_or_else(|| {
        trust_config_error(
            config_path,
            "the user configuration has no parent directory",
            None,
        )
    })?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        trust_config_error(
            config_path,
            "could not create a temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    temporary.write_all(contents).map_err(|error| {
        trust_config_error(
            config_path,
            "could not write the temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    preserve_permissions(temporary.as_file(), metadata.permissions()).map_err(|error| {
        trust_config_error(
            config_path,
            "could not preserve user configuration permissions",
            Some(error.to_string()),
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        trust_config_error(
            config_path,
            "could not synchronize the temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    temporary.persist(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not atomically replace the user configuration",
            Some(error.error.to_string()),
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn preserve_permissions(file: &fs::File, permissions: Permissions) -> std::io::Result<()> {
    file.set_permissions(permissions)
}

#[cfg(not(unix))]
fn preserve_permissions(_file: &fs::File, _permissions: Permissions) -> std::io::Result<()> {
    // A same-directory replacement inherits the user configuration directory's
    // ACL. Windows has no portable std API for copying an ACL from another file.
    Ok(())
}

fn trust_config_error(
    config_path: &Path,
    message: &str,
    source_detail: Option<String>,
) -> SatelleError {
    SatelleError {
        code: ErrorCode::ConfigError,
        message: format!("{message}: {}", config_path.display()),
        recovery_command: Some(
            "repair the user-level Host Binding and retry satelle host trust".to_string(),
        ),
        source_detail,
        details: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn host_identity_update_preserves_unrelated_toml_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        let original = concat!(
            "# keep this comment\n",
            "default_host = \"remote\"\n\n",
            "[hosts.remote]\n",
            "transport = \"direct\" # keep inline comment\n",
            "adapter = \"codex\"\n",
            "address = \"https://host.example.test\"\n",
        );
        fs::write(&config, original).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(persist_host_identity(&config, "remote", "host-observed").unwrap());
        let updated = fs::read_to_string(&config).unwrap();
        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("transport = \"direct\" # keep inline comment"));
        assert!(updated.contains("expected_host_id = \"host-observed\""));
        assert!(!persist_host_identity(&config, "remote", "host-observed").unwrap());
        assert_eq!(fs::read_to_string(&config).unwrap(), updated);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn host_identity_update_requires_an_existing_user_binding() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.toml");
        fs::write(
            &config,
            "[hosts.other]\ntransport = \"local\"\nadapter = \"fake\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

        let error = persist_host_identity(&config, "remote", "host-observed").unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigError);
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            "[hosts.other]\ntransport = \"local\"\nadapter = \"fake\"\n"
        );
    }
}
