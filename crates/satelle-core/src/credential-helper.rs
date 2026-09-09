use crate::{ExplicitDuration, is_env_name};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

/// A secret-free command descriptor. Deserialization enforces its contract
/// before it can enter a user or Host-owned provider binding.
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct CredentialHelper {
    argv: Vec<String>,
    timeout: ExplicitDuration,
    environment: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperConfig {
    argv: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout: ExplicitDuration,
    #[serde(default)]
    environment: BTreeMap<String, String>,
}

fn default_timeout() -> ExplicitDuration {
    ExplicitDuration::parse("10s").expect("the default helper timeout has explicit units")
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CredentialHelperDescriptorError {
    #[error("credential helper argv requires an absolute executable and literal arguments")]
    InvalidArgv,
    #[error("credential helper environment requires valid names and literal non-secret values")]
    InvalidEnvironment,
}

impl<'de> Deserialize<'de> for CredentialHelper {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let config = HelperConfig::deserialize(deserializer)?;
        Self::new(config.argv, config.timeout, config.environment).map_err(serde::de::Error::custom)
    }
}

impl CredentialHelper {
    pub fn new(
        argv: Vec<String>,
        timeout: ExplicitDuration,
        environment: BTreeMap<String, String>,
    ) -> Result<Self, CredentialHelperDescriptorError> {
        if !valid_argv(&argv) {
            return Err(CredentialHelperDescriptorError::InvalidArgv);
        }
        // Environment entries configure the helper, not a second channel for
        // provider or transport credentials. Satelle never expands their values.
        if environment.iter().any(|(name, value)| {
            !is_env_name(name)
                || value.contains('\0')
                || name.to_ascii_uppercase().starts_with("SATELLE_")
        }) {
            return Err(CredentialHelperDescriptorError::InvalidEnvironment);
        }
        Ok(Self {
            argv,
            timeout,
            environment,
        })
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }
    pub fn timeout(&self) -> &ExplicitDuration {
        &self.timeout
    }
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    /// Controller validation accepts either platform grammar. The Host calls
    /// this once at its descriptor boundary to select its native grammar.
    pub fn executable_is_absolute_for(&self, windows: bool) -> bool {
        absolute_executable(&self.argv[0], windows)
    }
}

impl fmt::Debug for CredentialHelper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialHelper")
            .field("argv", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("environment", &"[REDACTED]")
            .finish()
    }
}

pub(super) fn valid_argv(argv: &[String]) -> bool {
    let Some(executable) = argv.first() else {
        return false;
    };
    if !(absolute_executable(executable, false) || absolute_executable(executable, true))
        || argv.iter().any(|arg| arg.contains('\0'))
    {
        return false;
    }
    let name = executable
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    if matches!(
        name,
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "ksh"
            | "csh"
            | "tcsh"
            | "cmd"
            | "powershell"
            | "pwsh"
    ) {
        return false;
    }
    // A helper is an executable program, not an inline interpreter payload.
    // Other arguments remain literal, including spaces and punctuation.
    let interpreter = matches!(name, "node" | "nodejs" | "ruby" | "perl")
        || name.strip_prefix("python").is_some_and(|version| {
            version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        });
    if interpreter
        && argv[1..].iter().any(|arg| {
            matches!(
                arg.as_str(),
                "-c" | "-e" | "-E" | "-p" | "--eval" | "--print"
            )
        })
    {
        return false;
    }
    !argv[1..]
        .iter()
        .any(|arg| matches!(arg.as_str(), "|" | "||" | "&&" | ";" | ">" | ">>" | "<"))
}

fn absolute_executable(path: &str, windows: bool) -> bool {
    if !windows {
        return path.starts_with('/');
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
    {
        return true;
    }
    let Some(rest) = path.strip_prefix(r"\\").or_else(|| path.strip_prefix("//")) else {
        return false;
    };
    let mut parts = rest.split(['/', '\\']).filter(|part| !part.is_empty());
    matches!(parts.next(), Some(server) if !matches!(server, "." | ".." | "?"))
        && matches!(parts.next(), Some(share) if !matches!(share, "." | ".."))
        && parts.next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_descriptor_is_validated_and_debug_is_redacted() {
        let helper: CredentialHelper = serde_json::from_value(serde_json::json!({
            "argv": ["/opt/helpers/credential", "literal argument with spaces"],
            "environment": {"HELPER_PROFILE": "private-account"}
        }))
        .unwrap();
        assert_eq!(helper.timeout().milliseconds(), 10_000);
        assert!(helper.executable_is_absolute_for(false));
        assert!(!helper.executable_is_absolute_for(true));
        let debug = format!("{helper:?}");
        for reference in ["/opt", "literal", "HELPER_PROFILE", "private-account"] {
            assert!(!debug.contains(reference));
        }
        for argv in [
            vec![],
            vec!["helper"],
            vec!["/bin/sh", "-c", "secret"],
            vec!["/usr/bin/python3", "-c", "secret"],
            vec!["/usr/bin/python3.13", "-c", "secret"],
            vec!["/opt/helper", "|"],
            vec!["C:helper.exe"],
        ] {
            assert!(
                serde_json::from_value::<CredentialHelper>(serde_json::json!({"argv": argv}))
                    .is_err()
            );
        }
        for environment in [
            serde_json::json!({"BAD-KEY":"x"}),
            serde_json::json!({"SATELLE_TOKEN":"x"}),
        ] {
            assert!(
                serde_json::from_value::<CredentialHelper>(
                    serde_json::json!({"argv": ["/opt/helper"], "environment": environment})
                )
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<CredentialHelper>(
                serde_json::json!({"argv": ["/opt/helper"], "timeout": 10})
            )
            .is_err()
        );
    }
}
