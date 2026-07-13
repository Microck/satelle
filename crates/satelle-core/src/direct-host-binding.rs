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
