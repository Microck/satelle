use crate::core::{SatelleError, read_owner_only_secret_file};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookNotifierConfig {
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<WebhookSecretSource>,
}

impl WebhookNotifierConfig {
    pub fn validate(&self, alias: &str) -> Result<Url, SatelleError> {
        if alias.is_empty()
            || !alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(notifier_config_error(
                alias,
                "alias must contain only ASCII letters, digits, dashes, or underscores",
            ));
        }
        let endpoint = Url::parse(&self.endpoint)
            .map_err(|_| notifier_config_error(alias, "endpoint must be an absolute HTTPS URL"))?;
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            return Err(notifier_config_error(
                alias,
                "endpoint must be an absolute HTTPS URL",
            ));
        }
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(notifier_config_error(
                alias,
                "endpoint cannot contain credentials, a query, or a fragment",
            ));
        }
        if let Some(source) = self.authorization.as_ref() {
            source.validate(alias)?;
        }
        Ok(endpoint)
    }

    pub fn resolve_authorization(
        &self,
        alias: &str,
    ) -> Result<Option<Zeroizing<String>>, SatelleError> {
        self.authorization
            .as_ref()
            .map(|source| source.resolve(alias))
            .transpose()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WebhookSecretSource {
    Environment { variable: String },
    File { path: PathBuf },
}

impl WebhookSecretSource {
    fn validate(&self, alias: &str) -> Result<(), SatelleError> {
        match self {
            Self::Environment { variable } if valid_environment_name(variable) => Ok(()),
            Self::File { path } if path.is_absolute() && !path.starts_with("~") => Ok(()),
            Self::Environment { .. } => Err(notifier_config_error(
                alias,
                "authorization environment variable must be a valid environment name",
            )),
            Self::File { .. } => Err(notifier_config_error(
                alias,
                "authorization file path must be absolute",
            )),
        }
    }

    fn resolve(&self, alias: &str) -> Result<Zeroizing<String>, SatelleError> {
        self.validate(alias)?;
        match self {
            Self::Environment { variable } => std::env::var(variable)
                .ok()
                .filter(|value| !value.is_empty())
                .map(Zeroizing::new)
                .ok_or_else(|| notifier_secret_unavailable(alias, "environment")),
            Self::File { path } => read_owner_only_secret_file(path)
                .map_err(|_| notifier_secret_unavailable(alias, "owner-only file")),
        }
    }
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn notifier_config_error(alias: &str, message: &str) -> SatelleError {
    SatelleError::config_error(format!("webhook notifier '{alias}' {message}"), None)
}

fn notifier_secret_unavailable(alias: &str, kind: &str) -> SatelleError {
    notifier_config_error(
        alias,
        &format!("authorization could not be resolved from its {kind} Secret Source"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifier_requires_https_and_externalizes_authorization() {
        for endpoint in [
            "http://hooks.example.test/events",
            "https://user:secret@hooks.example.test/events",
            "https://hooks.example.test/events?token=secret",
        ] {
            let config = WebhookNotifierConfig {
                endpoint: endpoint.to_string(),
                authorization: None,
            };
            assert!(config.validate("ops").is_err());
        }

        let config = WebhookNotifierConfig {
            endpoint: "https://hooks.example.test/satelle/events".to_string(),
            authorization: Some(WebhookSecretSource::Environment {
                variable: "SATELLE_WEBHOOK_TOKEN".to_string(),
            }),
        };
        assert_eq!(
            config.validate("ops").unwrap().as_str(),
            "https://hooks.example.test/satelle/events"
        );
    }
}
