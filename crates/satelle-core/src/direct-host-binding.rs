use crate::session::HostIdentityRef;
use crate::{HostConfig, TransportKind};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ApiTokenSource {
    File { path: PathBuf },
}

/// A direct Host Binding after all endpoint, identity, and file-reference
/// invariants have been validated at one boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectHostBinding {
    origin: HttpsOrigin,
    expected_host_identity: HostIdentityRef,
    api_token: ApiTokenSource,
    ca_bundle: Option<PathBuf>,
}

/// An SSH Host Binding after destination, identity, and file-reference
/// invariants have been validated at one boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshHostBinding {
    destination: String,
    expected_host_identity: HostIdentityRef,
    api_token: Option<ApiTokenSource>,
}

impl SshHostBinding {
    pub fn from_host_config(host: &HostConfig) -> Result<Self, SshHostBindingError> {
        Self::validate(host, true)
    }

    pub fn from_host_config_for_bootstrap(host: &HostConfig) -> Result<Self, SshHostBindingError> {
        Self::validate(host, false)
    }

    fn validate(host: &HostConfig, require_api_token: bool) -> Result<Self, SshHostBindingError> {
        if host.transport != TransportKind::Ssh {
            return Err(SshHostBindingError::WrongTransport);
        }
        let destination = host
            .address
            .as_deref()
            .ok_or(SshHostBindingError::MissingAddress)?;
        if destination.is_empty()
            || destination.starts_with('-')
            || destination.chars().any(char::is_control)
        {
            return Err(SshHostBindingError::InvalidDestination);
        }
        let identity = host
            .expected_host_id
            .as_deref()
            .ok_or(SshHostBindingError::MissingExpectedHostIdentity)?;
        let expected_host_identity = HostIdentityRef::new(identity)
            .map_err(|_| SshHostBindingError::InvalidExpectedHostIdentity)?;
        let api_token = host.api_token.clone();
        if require_api_token && api_token.is_none() {
            return Err(SshHostBindingError::MissingApiToken);
        }
        if let Some(ApiTokenSource::File { path: token_path }) = &api_token
            && !is_absolute_file_reference(token_path)
        {
            return Err(SshHostBindingError::InvalidApiTokenPath);
        }
        if host.ca_bundle.is_some() {
            return Err(SshHostBindingError::UnexpectedCaBundle);
        }
        Ok(Self {
            destination: destination.to_string(),
            expected_host_identity,
            api_token,
        })
    }

    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn expected_host_identity(&self) -> &HostIdentityRef {
        &self.expected_host_identity
    }

    pub const fn api_token(&self) -> Option<&ApiTokenSource> {
        self.api_token.as_ref()
    }
}

impl DirectHostBinding {
    pub fn from_host_config(host: &HostConfig) -> Result<Self, DirectHostBindingError> {
        if host.transport != TransportKind::Direct {
            return Err(DirectHostBindingError::WrongTransport);
        }
        let address = host
            .address
            .as_deref()
            .ok_or(DirectHostBindingError::MissingAddress)?;
        let identity = host
            .expected_host_id
            .as_deref()
            .ok_or(DirectHostBindingError::MissingExpectedHostIdentity)?;
        let expected_host_identity = HostIdentityRef::new(identity)
            .map_err(|_| DirectHostBindingError::InvalidExpectedHostIdentity)?;
        let api_token = host
            .api_token
            .clone()
            .ok_or(DirectHostBindingError::MissingApiToken)?;
        let ApiTokenSource::File { path: token_path } = &api_token;
        if !is_absolute_file_reference(token_path) {
            return Err(DirectHostBindingError::InvalidApiTokenPath);
        }
        if host
            .ca_bundle
            .as_ref()
            .is_some_and(|path| !is_absolute_file_reference(path))
        {
            return Err(DirectHostBindingError::InvalidCaBundlePath);
        }
        Ok(Self {
            origin: HttpsOrigin::parse(address)?,
            expected_host_identity,
            api_token,
            ca_bundle: host.ca_bundle.clone(),
        })
    }

    pub fn origin(&self) -> &str {
        self.origin.as_str()
    }

    pub fn expected_host_identity(&self) -> &HostIdentityRef {
        &self.expected_host_identity
    }

    pub const fn api_token(&self) -> &ApiTokenSource {
        &self.api_token
    }

    pub fn ca_bundle(&self) -> Option<&Path> {
        self.ca_bundle.as_deref()
    }
}

fn is_absolute_file_reference(path: &Path) -> bool {
    path.is_absolute() && !path.starts_with("~")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpsOrigin(String);

impl HttpsOrigin {
    fn parse(value: &str) -> Result<Self, DirectHostBindingError> {
        let url = url::Url::parse(value).map_err(|_| DirectHostBindingError::InvalidHttpsOrigin)?;
        if url.scheme() != "https" {
            return Err(DirectHostBindingError::InsecureOrigin);
        }
        if url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(DirectHostBindingError::InvalidHttpsOrigin);
        }
        Ok(Self(url.as_str().trim_end_matches('/').to_string()))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DirectHostBindingError {
    #[error("the selected Host Binding is not a direct transport")]
    WrongTransport,
    #[error("a direct Host Binding requires address = \"<https-url>\"")]
    MissingAddress,
    #[error("a direct Host Binding requires expected_host_id = \"<host-id>\"")]
    MissingExpectedHostIdentity,
    #[error("the direct Host Binding expected_host_id is invalid")]
    InvalidExpectedHostIdentity,
    #[error("a direct Host Binding requires a file-backed api_token descriptor")]
    MissingApiToken,
    #[error("the direct Host Binding api_token file path must be absolute")]
    InvalidApiTokenPath,
    #[error("the direct Host Binding ca_bundle path must be absolute")]
    InvalidCaBundlePath,
    #[error("direct Host Daemon transport requires HTTPS")]
    InsecureOrigin,
    #[error("the direct Host Daemon HTTPS origin is invalid")]
    InvalidHttpsOrigin,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SshHostBindingError {
    #[error("the selected Host Binding is not an SSH transport")]
    WrongTransport,
    #[error("an SSH Host Binding requires address = \"<ssh-destination>\"")]
    MissingAddress,
    #[error("the SSH Host Binding destination is invalid")]
    InvalidDestination,
    #[error("an SSH Host Binding requires expected_host_id = \"<host-id>\"")]
    MissingExpectedHostIdentity,
    #[error("the SSH Host Binding expected_host_id is invalid")]
    InvalidExpectedHostIdentity,
    #[error("an SSH Host Binding requires a file-backed api_token descriptor")]
    MissingApiToken,
    #[error("the SSH Host Binding api_token file path must be absolute")]
    InvalidApiTokenPath,
    #[error("an SSH Host Binding cannot configure ca_bundle")]
    UnexpectedCaBundle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SatelleConfig;

    fn ssh_config(destination: &str) -> HostConfig {
        let mut config = SatelleConfig::defaults()
            .hosts
            .remove("local-demo")
            .expect("built-in local Host config");
        config.transport = TransportKind::Ssh;
        config.address = Some(destination.to_string());
        config.expected_host_id = Some("host-ssh-test".to_string());
        config.api_token = Some(ApiTokenSource::File {
            path: std::env::temp_dir().join("satelle-ssh-token"),
        });
        config
    }

    #[test]
    fn ssh_destination_preserves_standard_openssh_forms() {
        for destination in ["prod-alias", "operator@example.test", "operator@[::1]"] {
            let binding = SshHostBinding::from_host_config(&ssh_config(destination))
                .expect("standard OpenSSH destination should be accepted");
            assert_eq!(binding.destination(), destination);
        }
    }

    #[test]
    fn initial_ssh_bootstrap_does_not_require_a_durable_token_descriptor() {
        let mut config = ssh_config("operator@example.test");
        config.api_token = None;
        assert_eq!(
            SshHostBinding::from_host_config(&config).unwrap_err(),
            SshHostBindingError::MissingApiToken
        );
        assert!(
            SshHostBinding::from_host_config_for_bootstrap(&config)
                .unwrap()
                .api_token()
                .is_none()
        );
    }

    #[test]
    fn ssh_destination_rejects_option_and_control_character_injection() {
        for destination in ["", "-oProxyCommand=payload", "host\nRemoteCommand payload"] {
            assert_eq!(
                SshHostBinding::from_host_config(&ssh_config(destination)),
                Err(SshHostBindingError::InvalidDestination)
            );
        }
    }

    #[test]
    fn ssh_binding_rejects_the_tls_only_ca_bundle_setting() {
        let mut config = ssh_config("prod-alias");
        config.ca_bundle = Some(std::env::temp_dir().join("satelle-ca.pem"));
        assert_eq!(
            SshHostBinding::from_host_config(&config),
            Err(SshHostBindingError::UnexpectedCaBundle)
        );
    }
}
