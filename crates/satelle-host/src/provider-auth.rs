use satelle_core::{
    ProviderAuthValidationOutcome, ProviderSecretSource, read_owner_only_secret_file,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

/// A provider credential whose allocation is zeroized when dropped.
///
/// The field is private, the type is not cloneable or serializable, and
/// provider integrations can borrow the value only for the duration of a
/// callback.
pub(crate) struct ResolvedProviderSecret {
    value: Zeroizing<String>,
}

impl ResolvedProviderSecret {
    pub(crate) fn expose_to_provider<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        operation(self.value.as_str())
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: impl Into<String>) -> Self {
        Self {
            value: Zeroizing::new(value.into()),
        }
    }

    #[cfg(test)]
    fn matches_for_test(&self, expected: &str) -> bool {
        self.value.as_str() == expected
    }
}

/// Derives the only credential identity that may cross into provider-smoke
/// cache state. The binding digest scopes identical secret bytes to one exact
/// authorized provider binding, while the marker keeps no-secret bindings
/// distinct from bindings whose resolved secret happens to be empty.
pub(crate) fn provider_smoke_credential_fingerprint(
    binding_digest: &str,
    secret: Option<&ResolvedProviderSecret>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"satelle.provider-smoke-credential.v1\0");
    digest.update(
        u64::try_from(binding_digest.len())
            .expect("a provider binding digest length fits in u64")
            .to_be_bytes(),
    );
    digest.update(binding_digest.as_bytes());
    match secret {
        Some(secret) => {
            digest.update(b"present\0");
            digest.update(
                u64::try_from(secret.value.len())
                    .expect("a provider secret length fits in u64")
                    .to_be_bytes(),
            );
            digest.update(secret.value.as_bytes());
        }
        None => digest.update(b"absent\0"),
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl fmt::Debug for ResolvedProviderSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ResolvedProviderSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProviderAuthResolutionError {
    #[error("the provider secret source kind is not supported")]
    UnsupportedKind,
    #[error("the provider secret could not be resolved")]
    Unresolved,
    #[error("the provider secret file path is not absolute for the target Host")]
    InvalidFilePath,
}

/// Path grammar is selected from the target Host, not the Controller that
/// happens to parse or validate its configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderHostPlatform {
    Posix,
    Windows,
}

impl ProviderHostPlatform {
    pub(crate) const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Posix
        }
    }
}

/// Resolves a secret only at the explicit provider smoke/run boundary.
///
/// Callers must not invoke this function while rendering status or other
/// read-only diagnostics.
pub(crate) fn resolve_provider_secret(
    source: &ProviderSecretSource,
    target_platform: ProviderHostPlatform,
) -> Result<ResolvedProviderSecret, ProviderAuthResolutionError> {
    let value = match source {
        ProviderSecretSource::Environment { variable } => std::env::var_os(variable)
            .and_then(|value| value.into_string().ok())
            .map(Zeroizing::new)
            .ok_or(ProviderAuthResolutionError::Unresolved)?,
        ProviderSecretSource::File { path } => {
            if !is_absolute_for_target(path, target_platform) {
                return Err(ProviderAuthResolutionError::InvalidFilePath);
            }
            read_owner_only_secret_file(path)
                .map_err(|_| ProviderAuthResolutionError::Unresolved)?
        }
        ProviderSecretSource::CredentialStore { .. } | ProviderSecretSource::HostStore { .. } => {
            return Err(ProviderAuthResolutionError::UnsupportedKind);
        }
    };
    Ok(ResolvedProviderSecret { value })
}

fn is_absolute_for_target(path: &Path, target_platform: ProviderHostPlatform) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    if path.starts_with('~') {
        return false;
    }
    match target_platform {
        ProviderHostPlatform::Posix => path.starts_with('/'),
        ProviderHostPlatform::Windows => is_absolute_windows_path(path),
    }
}

/// Validates a descriptor's target-Host grammar without reading the
/// environment, filesystem, credential store, or Host store.
pub(crate) fn validate_provider_secret_source_descriptor(
    source: &ProviderSecretSource,
    target_platform: ProviderHostPlatform,
) -> Result<(), ProviderAuthResolutionError> {
    match source {
        ProviderSecretSource::Environment { variable } if !variable.trim().is_empty() => Ok(()),
        ProviderSecretSource::File { path } if is_absolute_for_target(path, target_platform) => {
            Ok(())
        }
        ProviderSecretSource::CredentialStore { service, account }
            if !service.trim().is_empty() && !account.trim().is_empty() =>
        {
            Ok(())
        }
        ProviderSecretSource::HostStore { name } if !name.trim().is_empty() => Ok(()),
        ProviderSecretSource::File { .. } => Err(ProviderAuthResolutionError::InvalidFilePath),
        _ => Err(ProviderAuthResolutionError::Unresolved),
    }
}

fn is_absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_qualified = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    if drive_qualified {
        return true;
    }

    let Some(remainder) = path.strip_prefix(r"\\").or_else(|| path.strip_prefix("//")) else {
        return false;
    };
    let mut components = remainder
        .split(['\\', '/'])
        .filter(|component| !component.is_empty());
    matches!(
        (components.next(), components.next()),
        (Some(server), Some(share)) if server != "." && server != ".." && share != "." && share != ".."
    )
}

/// Classifies already-observed provider-auth evidence without reading a
/// credential source. `resolution` carries only success or a closed error, so
/// resolved bytes cannot cross into diagnostic, status, or storage state.
pub(crate) fn diagnose_provider_secret(
    descriptor: Option<&ProviderSecretSource>,
    resolution: Option<Result<(), ProviderAuthResolutionError>>,
    smoke_failed: bool,
) -> ProviderAuthValidationOutcome {
    let Some(descriptor) = descriptor else {
        return ProviderAuthValidationOutcome::MissingDescriptor;
    };
    if matches!(
        descriptor,
        ProviderSecretSource::CredentialStore { .. } | ProviderSecretSource::HostStore { .. }
    ) {
        return ProviderAuthValidationOutcome::UnsupportedDescriptorKind;
    }

    match resolution {
        None => ProviderAuthValidationOutcome::ConfiguredDeferred,
        Some(Err(ProviderAuthResolutionError::UnsupportedKind)) => {
            ProviderAuthValidationOutcome::UnsupportedDescriptorKind
        }
        Some(Err(
            ProviderAuthResolutionError::Unresolved | ProviderAuthResolutionError::InvalidFilePath,
        )) => ProviderAuthValidationOutcome::UnresolvedHostSecret,
        Some(Ok(())) if smoke_failed => {
            ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed
        }
        Some(Ok(())) => ProviderAuthValidationOutcome::Resolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::ProviderSecretSource;
    #[cfg(unix)]
    use satelle_core::persist_new_owner_only_secret_file;
    use std::path::{Path, PathBuf};

    /// Owns one unique process-environment variable for the duration of a
    /// test. Unique names avoid cross-test interference while still exercising
    /// the real environment boundary rather than replacing it with a mock.
    struct ScopedEnvironmentVariable {
        name: String,
    }

    impl ScopedEnvironmentVariable {
        fn missing() -> Self {
            let name = format!(
                "SATELLE_PROVIDER_AUTH_TEST_{}",
                uuid::Uuid::now_v7().simple()
            );
            // SAFETY: every instance owns a UUID-qualified name that no other
            // test or production thread can know or access.
            unsafe {
                std::env::remove_var(&name);
            }
            Self { name }
        }

        fn set(&self, value: &str) {
            // SAFETY: this guard owns a UUID-qualified variable name and
            // removes it on drop.
            unsafe {
                std::env::set_var(&self.name, value);
            }
        }

        fn source(&self) -> ProviderSecretSource {
            ProviderSecretSource::Environment {
                variable: self.name.clone(),
            }
        }
    }

    impl Drop for ScopedEnvironmentVariable {
        fn drop(&mut self) {
            // SAFETY: the guard still owns this unique variable name.
            unsafe {
                std::env::remove_var(&self.name);
            }
        }
    }

    fn file_source(path: impl Into<PathBuf>) -> ProviderSecretSource {
        ProviderSecretSource::File { path: path.into() }
    }

    fn diagnostic(
        descriptor: Option<&ProviderSecretSource>,
        resolution: Option<Result<(), ProviderAuthResolutionError>>,
        smoke_failed: bool,
    ) -> ProviderAuthValidationOutcome {
        diagnose_provider_secret(descriptor, resolution, smoke_failed)
    }

    #[test]
    fn read_only_diagnostics_do_not_resolve_environment_or_file_descriptors() {
        let environment = ScopedEnvironmentVariable::missing();
        let environment_source = environment.source();
        assert_eq!(
            ProviderAuthValidationOutcome::ConfiguredDeferred,
            diagnostic(Some(&environment_source), None, false),
        );

        let directory = tempfile::tempdir().expect("create provider-auth test directory");
        let missing_path = directory.path().join("must-not-be-opened");
        let file_source = file_source(&missing_path);
        assert_eq!(
            ProviderAuthValidationOutcome::ConfiguredDeferred,
            diagnostic(Some(&file_source), None, false),
        );
        assert!(
            !missing_path.exists(),
            "read-only diagnostics must not create or rewrite credential files"
        );
    }

    #[test]
    fn environment_secrets_are_resolved_only_by_an_explicit_provider_request() {
        let environment = ScopedEnvironmentVariable::missing();
        let source = environment.source();

        assert_eq!(
            ProviderAuthValidationOutcome::ConfiguredDeferred,
            diagnostic(Some(&source), None, false),
            "descriptor diagnostics do not consult the process environment"
        );
        assert!(matches!(
            resolve_provider_secret(&source, ProviderHostPlatform::Posix),
            Err(ProviderAuthResolutionError::Unresolved)
        ));

        environment.set("provider-test-token");
        let resolved = resolve_provider_secret(&source, ProviderHostPlatform::Posix)
            .expect("smoke and run call sites can resolve configured auth");
        assert!(
            resolved.matches_for_test("provider-test-token"),
            "the provider receives the exact resolved credential"
        );
    }

    #[test]
    fn environment_secret_rotation_changes_the_private_smoke_cache_identity() {
        let environment = ScopedEnvironmentVariable::missing();
        let source = environment.source();
        let binding_digest = "a".repeat(64);

        environment.set("first-provider-token");
        let first = resolve_provider_secret(&source, ProviderHostPlatform::Posix)
            .expect("resolve the first environment credential");
        let first_fingerprint =
            provider_smoke_credential_fingerprint(&binding_digest, Some(&first));

        environment.set("rotated-provider-token");
        let rotated = resolve_provider_secret(&source, ProviderHostPlatform::Posix)
            .expect("resolve the rotated environment credential");
        let rotated_fingerprint =
            provider_smoke_credential_fingerprint(&binding_digest, Some(&rotated));

        assert_eq!(64, first_fingerprint.len());
        assert!(
            first_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_ne!(first_fingerprint, rotated_fingerprint);
        assert_ne!(
            first_fingerprint,
            provider_smoke_credential_fingerprint(&binding_digest, None)
        );
        assert!(!first_fingerprint.contains("first-provider-token"));
        assert!(!rotated_fingerprint.contains("rotated-provider-token"));
    }

    #[test]
    fn file_paths_follow_the_target_host_absolute_path_rules() {
        assert_eq!(
            Ok(()),
            validate_provider_secret_source_descriptor(
                &file_source(Path::new("/satelle/provider-token")),
                ProviderHostPlatform::Posix,
            )
        );
        assert!(matches!(
            resolve_provider_secret(
                &file_source(Path::new("relative/provider-token")),
                ProviderHostPlatform::Posix,
            ),
            Err(ProviderAuthResolutionError::InvalidFilePath)
        ));
        assert!(matches!(
            resolve_provider_secret(
                &file_source(Path::new("~/provider-token")),
                ProviderHostPlatform::Posix,
            ),
            Err(ProviderAuthResolutionError::InvalidFilePath)
        ));

        assert_eq!(
            Ok(()),
            validate_provider_secret_source_descriptor(
                &file_source(Path::new(r"C:\Satelle\provider-token")),
                ProviderHostPlatform::Windows,
            )
        );
        for invalid_path in [
            r"C:relative\provider-token",
            r"\rooted-on-current-drive",
            "relative/provider-token",
            "/posix/provider-token",
            r"~\provider-token",
        ] {
            assert!(matches!(
                resolve_provider_secret(
                    &file_source(Path::new(invalid_path)),
                    ProviderHostPlatform::Windows,
                ),
                Err(ProviderAuthResolutionError::InvalidFilePath)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_resolution_reuses_the_existing_owner_only_secret_policy() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("create provider-auth test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make provider-auth test directory owner-only");

        let secure_path = directory.path().join("secure-token");
        persist_new_owner_only_secret_file(&secure_path, "secure-provider-token")
            .expect("persist an owner-only provider credential");
        let resolved =
            resolve_provider_secret(&file_source(&secure_path), ProviderHostPlatform::Posix)
                .expect("resolve an owner-only credential file");
        assert!(resolved.matches_for_test("secure-provider-token"));

        let insecure_path = directory.path().join("insecure-token");
        std::fs::write(&insecure_path, "must-not-be-read")
            .expect("write an intentionally insecure credential");
        std::fs::set_permissions(&insecure_path, std::fs::Permissions::from_mode(0o644))
            .expect("make the credential readable by other users");
        assert!(matches!(
            resolve_provider_secret(&file_source(&insecure_path), ProviderHostPlatform::Posix,),
            Err(ProviderAuthResolutionError::Unresolved)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn file_secret_rotation_changes_the_private_smoke_cache_identity() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("create provider-auth test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make provider-auth test directory owner-only");
        let path = directory.path().join("rotating-token");
        persist_new_owner_only_secret_file(&path, "first-file-provider-token")
            .expect("persist the first owner-only provider credential");
        let source = file_source(&path);
        let binding_digest = "b".repeat(64);
        let first = resolve_provider_secret(&source, ProviderHostPlatform::Posix)
            .expect("resolve the first file credential");
        let first_fingerprint =
            provider_smoke_credential_fingerprint(&binding_digest, Some(&first));

        std::fs::write(&path, "rotated-file-provider-token")
            .expect("rotate the owner-only provider credential");
        let rotated = resolve_provider_secret(&source, ProviderHostPlatform::Posix)
            .expect("resolve the rotated file credential");
        let rotated_fingerprint =
            provider_smoke_credential_fingerprint(&binding_digest, Some(&rotated));

        assert_ne!(first_fingerprint, rotated_fingerprint);
        assert!(!first_fingerprint.contains("first-file-provider-token"));
        assert!(!rotated_fingerprint.contains("rotated-file-provider-token"));
    }

    #[test]
    fn credential_and_host_stores_fail_closed_as_unsupported_kinds() {
        for source in [
            ProviderSecretSource::CredentialStore {
                service: "satelle".to_string(),
                account: "provider".to_string(),
            },
            ProviderSecretSource::HostStore {
                name: "provider".to_string(),
            },
        ] {
            assert!(matches!(
                resolve_provider_secret(&source, ProviderHostPlatform::Posix),
                Err(ProviderAuthResolutionError::UnsupportedKind)
            ));
            assert_eq!(
                ProviderAuthValidationOutcome::UnsupportedDescriptorKind,
                diagnostic(Some(&source), None, false),
            );
        }
    }

    #[test]
    fn diagnostics_use_only_the_closed_public_outcomes() {
        let environment = ScopedEnvironmentVariable::missing();
        let source = environment.source();

        let cases = [
            (
                diagnostic(None, None, false),
                ProviderAuthValidationOutcome::MissingDescriptor,
            ),
            (
                diagnostic(
                    Some(&source),
                    Some(Err(ProviderAuthResolutionError::Unresolved)),
                    false,
                ),
                ProviderAuthValidationOutcome::UnresolvedHostSecret,
            ),
            (
                diagnostic(Some(&source), Some(Ok(())), false),
                ProviderAuthValidationOutcome::Resolved,
            ),
            (
                diagnostic(Some(&source), Some(Ok(())), true),
                ProviderAuthValidationOutcome::ProviderComputerUseSmokeTestFailed,
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn resolved_secrets_are_debug_redacted_and_erased_before_diagnostics() {
        let environment = ScopedEnvironmentVariable::missing();
        let source = environment.source();
        let resolved = ResolvedProviderSecret::for_test("never-print-this-provider-token");

        let debug = format!("{resolved:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("never-print-this-provider-token"));
        drop(resolved);

        // The diagnostic boundary accepts Result<(), _>, not the secret type.
        // Mapping to unit consumes no bytes and makes it impossible for status
        // or storage evidence to retain the opaque credential by accident.
        let byte_free_resolution = Ok::<(), ProviderAuthResolutionError>(());
        let outcome = diagnostic(Some(&source), Some(byte_free_resolution), false);
        let serialized = serde_json::to_string(&outcome).expect("serialize closed diagnostic");
        assert!(!serialized.contains("never-print-this-provider-token"));
    }

    #[test]
    fn read_only_diagnostics_neither_mutate_sources_nor_return_secret_bytes() {
        let directory = tempfile::tempdir().expect("create provider-auth test directory");
        let credential_path = directory.path().join("diagnostic-token");
        std::fs::write(&credential_path, "diagnostic-source-bytes")
            .expect("write diagnostic source");
        let before = std::fs::read(&credential_path).expect("read diagnostic source before");
        let source = file_source(&credential_path);

        let outcome = diagnostic(Some(&source), None, false);

        assert_eq!(ProviderAuthValidationOutcome::ConfiguredDeferred, outcome);
        assert_eq!(
            before,
            std::fs::read(&credential_path).expect("read diagnostic source after"),
            "diagnostics are observational and cannot repair or rewrite auth sources"
        );
        assert!(
            !serde_json::to_string(&outcome)
                .expect("serialize diagnostic outcome")
                .contains("diagnostic-source-bytes"),
            "the diagnostic return type contains classification only"
        );
    }
}
