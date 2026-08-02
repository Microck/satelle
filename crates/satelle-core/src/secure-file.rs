use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_SECRET_FILE_BYTES: usize = 64 * 1024;
const MAX_CONFIG_FILE_BYTES: usize = 1024 * 1024;
const SSH_IDENTITY_COMMIT_SCHEMA: &str = "satelle.ssh-host-identity-commit.v2";

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecureFileError {
    #[error("the file is unavailable or does not satisfy the required owner security policy")]
    UnsafeOrUnavailable,
    #[error("the file exceeds the maximum supported size")]
    TooLarge,
    #[error("the file is not valid UTF-8")]
    NotUtf8,
    #[error("the file contains a NUL byte")]
    ContainsNul,
    #[error("the destination appeared after overwrite intent was recorded")]
    OverwriteRequired,
    #[error("the published secret could not be removed after persistence failed")]
    PublishedCleanupFailed,
    #[error("the prior owner-only secret could not be restored")]
    RollbackFailed,
    #[error("the SSH identity operation record is invalid")]
    InvalidSshIdentityOperation,
}

/// Immutable recovery authority for one accepted fresh SSH Host identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshIdentityCommitRecord {
    operation_id: String,
    candidate_host_identity: crate::session::HostIdentityRef,
    target_id: String,
    canonical_state_root: String,
    artifact_version: String,
    archive_sha256: String,
    binary_sha256: String,
    exact_remote_path: String,
}

impl SshIdentityCommitRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: impl Into<String>,
        candidate_host_identity: crate::session::HostIdentityRef,
        target_id: impl Into<String>,
        canonical_state_root: impl Into<String>,
        artifact_version: impl Into<String>,
        archive_sha256: impl Into<String>,
        binary_sha256: impl Into<String>,
        exact_remote_path: impl Into<String>,
    ) -> Result<Self, SecureFileError> {
        let record = Self {
            operation_id: operation_id.into(),
            candidate_host_identity,
            target_id: target_id.into(),
            canonical_state_root: canonical_state_root.into(),
            artifact_version: artifact_version.into(),
            archive_sha256: archive_sha256.into(),
            binary_sha256: binary_sha256.into(),
            exact_remote_path: exact_remote_path.into(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn parse(encoded: &str) -> Result<Self, SecureFileError> {
        if encoded.len() > 4096 || encoded.contains('\0') {
            return Err(SecureFileError::InvalidSshIdentityOperation);
        }
        let mut lines = encoded.split('\n');
        if lines.next() != Some(SSH_IDENTITY_COMMIT_SCHEMA) {
            return Err(SecureFileError::InvalidSshIdentityOperation);
        }
        let field = |line: Option<&str>, prefix: &str| {
            line.and_then(|line| line.strip_prefix(prefix))
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or(SecureFileError::InvalidSshIdentityOperation)
        };
        let operation_id = field(lines.next(), "operation_id=")?;
        let candidate_host_identity =
            crate::session::HostIdentityRef::new(field(lines.next(), "candidate_host_identity=")?)
                .map_err(|_| SecureFileError::InvalidSshIdentityOperation)?;
        let target_id = field(lines.next(), "target_id=")?;
        let canonical_state_root = field(lines.next(), "canonical_state_root=")?;
        let artifact_version = field(lines.next(), "artifact_version=")?;
        let archive_sha256 = field(lines.next(), "archive_sha256=")?;
        let binary_sha256 = field(lines.next(), "binary_sha256=")?;
        let exact_remote_path = field(lines.next(), "exact_remote_path=")?;
        if lines.next().is_some() {
            return Err(SecureFileError::InvalidSshIdentityOperation);
        }
        Self::new(
            operation_id,
            candidate_host_identity,
            target_id,
            canonical_state_root,
            artifact_version,
            archive_sha256,
            binary_sha256,
            exact_remote_path,
        )
    }

    pub fn encode(&self) -> String {
        format!(
            concat!(
                "{}\n",
                "operation_id={}\n",
                "candidate_host_identity={}\n",
                "target_id={}\n",
                "canonical_state_root={}\n",
                "artifact_version={}\n",
                "archive_sha256={}\n",
                "binary_sha256={}\n",
                "exact_remote_path={}"
            ),
            SSH_IDENTITY_COMMIT_SCHEMA,
            self.operation_id,
            self.candidate_host_identity.as_str(),
            self.target_id,
            self.canonical_state_root,
            self.artifact_version,
            self.archive_sha256,
            self.binary_sha256,
            self.exact_remote_path,
        )
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn candidate_host_identity(&self) -> &crate::session::HostIdentityRef {
        &self.candidate_host_identity
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn canonical_state_root(&self) -> &str {
        &self.canonical_state_root
    }

    pub fn artifact_version(&self) -> &str {
        &self.artifact_version
    }

    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }

    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub fn exact_remote_path(&self) -> &str {
        &self.exact_remote_path
    }

    fn validate(&self) -> Result<(), SecureFileError> {
        let parsed = uuid::Uuid::parse_str(&self.operation_id)
            .map_err(|_| SecureFileError::InvalidSshIdentityOperation)?;
        if parsed.hyphenated().to_string() != self.operation_id
            || self.operation_id.as_bytes().get(14) != Some(&b'7')
            || !matches!(
                self.target_id.as_str(),
                "linux-arm64-gnu"
                    | "linux-x64-gnu"
                    | "darwin-arm64"
                    | "darwin-x64"
                    | "win32-arm64-msvc"
                    | "win32-x64-msvc"
            )
            || !valid_record_text(&self.canonical_state_root)
            || !valid_record_text(&self.artifact_version)
            || !valid_sha256(&self.archive_sha256)
            || !valid_sha256(&self.binary_sha256)
            || !valid_record_text(&self.exact_remote_path)
        {
            return Err(SecureFileError::InvalidSshIdentityOperation);
        }
        let executable = if self.target_id.starts_with("win32-") {
            "satelle.exe"
        } else {
            "satelle"
        };
        let normalized_path = self.exact_remote_path.replace('\\', "/");
        let absolute = if self.target_id.starts_with("win32-") {
            normalized_path.as_bytes().get(1) == Some(&b':')
                && normalized_path.as_bytes().get(2) == Some(&b'/')
        } else {
            normalized_path.starts_with('/')
        };
        let expected_suffix = format!(
            "/bootstrap/{}/{}/{}",
            self.operation_id, self.binary_sha256, executable
        );
        if !absolute || !normalized_path.ends_with(&expected_suffix) {
            return Err(SecureFileError::InvalidSshIdentityOperation);
        }
        Ok(())
    }
}

fn valid_record_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !matches!(byte, b'\0' | b'\n' | b'\r'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(not(windows))]
pub type OwnerOnlyDirectory = File;

#[cfg(windows)]
pub struct OwnerOnlyDirectory {
    _directory: File,
    _ancestors: Vec<File>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SecurityPolicy {
    OwnerOnly,
    OwnerPrivate,
    OwnerControlled,
    UserOrAdministratorControlled,
}

pub fn read_owner_only_secret_file(path: &Path) -> Result<Zeroizing<String>, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerOnly, MAX_SECRET_FILE_BYTES)?;
    if bytes.contains(&0) {
        return Err(SecureFileError::ContainsNul);
    }
    let value = std::str::from_utf8(bytes.as_slice()).map_err(|_| SecureFileError::NotUtf8)?;
    let value = value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value);
    Ok(Zeroizing::new(value.to_string()))
}

/// Computes a comparison digest over the exact bytes stored in an owner-only
/// secret file. Provider consumers normalize one trailing line ending, but
/// replacement recovery compares the persisted representation byte-for-byte.
pub fn keyed_owner_only_secret_file_comparison_digest(
    path: &Path,
    comparison_key: &[u8],
) -> Result<[u8; 32], SecureFileError> {
    let stored = read_secure_file(path, SecurityPolicy::OwnerOnly, MAX_SECRET_FILE_BYTES)?;
    keyed_secret_comparison_digest(comparison_key, stored.as_slice())
}

/// Persists a new secret without ever replacing an existing credential. The
/// no-replace rename publishes the secret atomically and consumes the staging
/// name, so a crash cannot leave a second hard link that makes the credential
/// unreadable under the owner-only policy.
pub fn persist_new_owner_only_secret_file(
    path: &Path,
    secret: &str,
) -> Result<(), SecureFileError> {
    if secret.len() > MAX_SECRET_FILE_BYTES {
        return Err(SecureFileError::TooLarge);
    }
    let parent = path.parent().ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let directory = open_or_create_owner_only_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.tmp",
        uuid::Uuid::now_v7().hyphenated()
    ));
    let mut published = false;
    let persisted = (|| {
        let mut temporary = open_or_create_owner_only_file(&temporary_path)?;
        temporary
            .write_all(secret.as_bytes())
            .and_then(|()| temporary.sync_all())
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
        // Windows owner-only handles intentionally deny delete sharing. Close
        // the staged file before publishing and unlinking its temporary name.
        drop(temporary);
        publish_new_file_without_replace(&temporary_path, path, &directory)?;
        published = true;
        sync_owner_only_directory(parent, &directory)?;
        let stored = read_owner_only_secret_file(path)?;
        (stored.as_str() == secret)
            .then_some(())
            .ok_or(SecureFileError::UnsafeOrUnavailable)
    })();
    match persisted {
        Ok(()) => Ok(()),
        Err(error) => {
            cleanup_failed_new_secret(&temporary_path, path, published)?;
            Err(error)
        }
    }
}

/// Deterministic sibling paths for one journaled secret-file provisioning
/// operation. The journal identifier must be an opaque ASCII token rather than
/// secret material. A durable caller can reconstruct these paths after a
/// restart without persisting a second copy of the credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerOnlySecretFilePaths {
    destination: PathBuf,
    staging: PathBuf,
    backup: PathBuf,
}

impl OwnerOnlySecretFilePaths {
    pub fn new(destination: &Path, journal_id: &str) -> Result<Self, SecureFileError> {
        if journal_id.is_empty()
            || journal_id.len() > 64
            || !journal_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let parent = destination
            .parent()
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let file_name = destination
            .file_name()
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let mut staging_name = file_name.to_os_string();
        staging_name.push(format!(".satelle-{journal_id}.staged"));
        let mut backup_name = file_name.to_os_string();
        backup_name.push(format!(".satelle-{journal_id}.backup"));
        Ok(Self {
            destination: destination.to_path_buf(),
            staging: parent.join(staging_name),
            backup: parent.join(backup_name),
        })
    }

    /// Reconstructs deterministic paths from the destination and the staged
    /// path stored in a durable provisioning journal. The staged name must be
    /// exactly one produced by `new`; a same-directory arbitrary path is not
    /// sufficient recovery authority.
    pub fn from_staged_path(destination: &Path, staged: &Path) -> Result<Self, SecureFileError> {
        if destination.parent() != staged.parent() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let destination_name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let staged_name = staged
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let prefix = format!("{destination_name}.satelle-");
        let journal_id = staged_name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".staged"))
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let paths = Self::new(destination, journal_id)?;
        (paths.staging == staged)
            .then_some(paths)
            .ok_or(SecureFileError::UnsafeOrUnavailable)
    }

    pub fn destination(&self) -> &Path {
        &self.destination
    }

    pub fn staging(&self) -> &Path {
        &self.staging
    }

    pub fn backup(&self) -> &Path {
        &self.backup
    }
}

/// Produces a keyed comparison value for a secret without creating a reusable
/// raw SHA-256 fingerprint. Callers may persist this HMAC in a redacted
/// provisioning journal and use the same per-installation key during recovery.
pub fn keyed_secret_comparison_digest(
    comparison_key: &[u8],
    secret: &[u8],
) -> Result<[u8; 32], SecureFileError> {
    if comparison_key.is_empty() {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }

    const BLOCK_BYTES: usize = 64;
    let mut key_block = Zeroizing::new([0_u8; BLOCK_BYTES]);
    if comparison_key.len() > BLOCK_BYTES {
        key_block[..32].copy_from_slice(&Sha256::digest(comparison_key));
    } else {
        key_block[..comparison_key.len()].copy_from_slice(comparison_key);
    }
    let mut inner_pad = Zeroizing::new([0_u8; BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0_u8; BLOCK_BYTES]);
    for index in 0..BLOCK_BYTES {
        inner_pad[index] = key_block[index] ^ 0x36;
        outer_pad[index] = key_block[index] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    inner.update(secret);
    let inner_digest = Zeroizing::new(inner.finalize().to_vec());
    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_digest.as_slice());
    Ok(outer.finalize().into())
}

/// Reports whether a destination already contains an owner-only regular file.
/// An occupied path that does not satisfy the policy is an error rather than a
/// misleading overwrite preview.
pub fn owner_only_secret_destination_exists(path: &Path) -> Result<bool, SecureFileError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            drop(open_secure_file(path, SecurityPolicy::OwnerOnly)?);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SecureFileError::UnsafeOrUnavailable),
    }
}

/// Creates and fsyncs the deterministic owner-only staging file, then verifies
/// it through a new no-follow read using the caller's keyed HMAC comparison.
/// Repeating the call after a crash accepts only an existing staged file with
/// the same comparison value.
pub fn stage_owner_only_secret_file(
    paths: &OwnerOnlySecretFilePaths,
    secret: &str,
    comparison_key: &[u8],
    expected_digest: &[u8; 32],
) -> Result<(), SecureFileError> {
    if secret.len() > MAX_SECRET_FILE_BYTES || secret.as_bytes().contains(&0) {
        return Err(if secret.len() > MAX_SECRET_FILE_BYTES {
            SecureFileError::TooLarge
        } else {
            SecureFileError::ContainsNul
        });
    }
    let source_digest = keyed_secret_comparison_digest(comparison_key, secret.as_bytes())?;
    if !constant_time_digest_eq(&source_digest, expected_digest) {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }

    let parent = paths
        .destination
        .parent()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let directory = open_or_create_owner_only_directory(parent)?;
    let mut staging = match open_new_owner_only_file(&paths.staging) {
        Ok(staging) => staging,
        Err(_) => {
            return verify_owner_only_secret_digest(
                &paths.staging,
                comparison_key,
                expected_digest,
            );
        }
    };
    let staged = staging
        .write_all(secret.as_bytes())
        .and_then(|()| staging.sync_all())
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)
        .and_then(|()| {
            drop(staging);
            sync_owner_only_directory(parent, &directory)?;
            verify_owner_only_secret_digest(&paths.staging, comparison_key, expected_digest)
        });
    if let Err(error) = staged {
        let _ = remove_sibling_file(&paths.staging, &directory);
        return Err(error);
    }
    Ok(())
}

/// Publishes a verified staging file without replacing an occupied pathname.
/// A replacement parks the observed destination at the journal's backup
/// pathname, verifies its exact prior digest, and then publishes into the
/// vacant destination pathname.
pub fn publish_owner_only_secret_file(
    paths: &OwnerOnlySecretFilePaths,
    expected_destination_exists: bool,
    overwrite_authorized: bool,
    candidate_comparison_key: &[u8],
    candidate_digest: &[u8; 32],
    prior_comparison_key: Option<&[u8]>,
    prior_digest: Option<&[u8; 32]>,
) -> Result<bool, SecureFileError> {
    verify_owner_only_secret_digest(&paths.staging, candidate_comparison_key, candidate_digest)?;
    if expected_destination_exists && !overwrite_authorized {
        return Err(SecureFileError::OverwriteRequired);
    }

    let parent = paths
        .destination
        .parent()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let directory = open_or_create_owner_only_directory(parent)?;

    if !expected_destination_exists {
        return match move_sibling_file_without_replace(
            &paths.staging,
            &paths.destination,
            &directory,
        )? {
            NoReplaceMoveOutcome::Moved => {
                sync_owner_only_directory(parent, &directory)?;
                verify_owner_only_secret_digest(
                    &paths.destination,
                    candidate_comparison_key,
                    candidate_digest,
                )?;
                Ok(false)
            }
            NoReplaceMoveOutcome::DestinationOccupied => Err(SecureFileError::OverwriteRequired),
            NoReplaceMoveOutcome::SourceMissing => Err(SecureFileError::UnsafeOrUnavailable),
        };
    }

    let prior_comparison_key = prior_comparison_key.ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let prior_digest = prior_digest.ok_or(SecureFileError::UnsafeOrUnavailable)?;
    match move_sibling_file_without_replace(&paths.destination, &paths.backup, &directory)? {
        NoReplaceMoveOutcome::Moved => sync_owner_only_directory(parent, &directory)?,
        NoReplaceMoveOutcome::SourceMissing | NoReplaceMoveOutcome::DestinationOccupied => {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
    }

    match secret_digest_matches(&paths.backup, prior_comparison_key, prior_digest) {
        Ok(true) => {}
        comparison => {
            restore_parked_secret(
                &paths.backup,
                &paths.destination,
                parent,
                &directory,
                SecretArtifactKind::Unowned,
                candidate_comparison_key,
                candidate_digest,
                Some((prior_comparison_key, prior_digest)),
            )?;
            return match comparison {
                Ok(false) => Err(SecureFileError::OverwriteRequired),
                Err(error) => Err(error),
                Ok(true) => unreachable!(),
            };
        }
    }

    match move_sibling_file_without_replace(&paths.staging, &paths.destination, &directory)? {
        NoReplaceMoveOutcome::Moved => {
            sync_owner_only_directory(parent, &directory)?;
            verify_owner_only_secret_digest(
                &paths.destination,
                candidate_comparison_key,
                candidate_digest,
            )?;
            Ok(true)
        }
        NoReplaceMoveOutcome::DestinationOccupied => {
            remove_verified_secret_artifact(
                &paths.staging,
                &directory,
                SecretArtifactKind::Candidate,
                candidate_comparison_key,
                candidate_digest,
                Some((prior_comparison_key, prior_digest)),
            )?;
            remove_verified_secret_artifact(
                &paths.backup,
                &directory,
                SecretArtifactKind::Prior,
                candidate_comparison_key,
                candidate_digest,
                Some((prior_comparison_key, prior_digest)),
            )?;
            sync_owner_only_directory(parent, &directory)?;
            Err(SecureFileError::OverwriteRequired)
        }
        NoReplaceMoveOutcome::SourceMissing => {
            restore_parked_secret(
                &paths.backup,
                &paths.destination,
                parent,
                &directory,
                SecretArtifactKind::Prior,
                candidate_comparison_key,
                candidate_digest,
                Some((prior_comparison_key, prior_digest)),
            )?;
            Err(SecureFileError::UnsafeOrUnavailable)
        }
    }
}

/// Restores the owner-only backup after a failed replacement, or removes a
/// newly published destination when no prior secret existed. Every artifact
/// is verified against a journal-supplied keyed digest before deletion or
/// replacement. Repeating rollback accepts only an already-restored prior
/// destination or an already-deleted new destination.
#[allow(clippy::too_many_arguments)]
pub fn rollback_owner_only_secret_file(
    paths: &OwnerOnlySecretFilePaths,
    overwritten: bool,
    candidate_comparison_key: &[u8],
    candidate_digest: &[u8; 32],
    prior_comparison_key: Option<&[u8]>,
    prior_digest: Option<&[u8; 32]>,
) -> Result<(), SecureFileError> {
    let parent = paths
        .destination
        .parent()
        .ok_or(SecureFileError::RollbackFailed)?;
    let directory =
        open_or_create_owner_only_directory(parent).map_err(|_| SecureFileError::RollbackFailed)?;
    let prior_evidence = match (prior_comparison_key, prior_digest) {
        (Some(key), Some(digest)) => Some((key, digest)),
        (None, None) => None,
        _ => return Err(SecureFileError::RollbackFailed),
    };
    let restores_prior = overwritten || prior_evidence.is_some();
    let classify = |path: &Path| {
        classify_secret_artifact(
            path,
            candidate_comparison_key,
            candidate_digest,
            prior_evidence,
        )
        .map_err(|_| SecureFileError::RollbackFailed)
    };
    let destination = classify(&paths.destination)?;
    let mut staging = classify(&paths.staging)?;
    let backup = classify(&paths.backup)?;

    if destination != SecretArtifactKind::Missing && staging != SecretArtifactKind::Missing {
        match (destination, staging, backup) {
            (
                SecretArtifactKind::Unowned | SecretArtifactKind::Prior,
                SecretArtifactKind::Candidate,
                SecretArtifactKind::Missing | SecretArtifactKind::Prior,
            ) => {
                remove_verified_secret_artifact(
                    &paths.staging,
                    &directory,
                    SecretArtifactKind::Candidate,
                    candidate_comparison_key,
                    candidate_digest,
                    prior_evidence,
                )
                .map_err(|_| SecureFileError::RollbackFailed)?;
                if backup == SecretArtifactKind::Prior {
                    remove_verified_secret_artifact(
                        &paths.backup,
                        &directory,
                        SecretArtifactKind::Prior,
                        candidate_comparison_key,
                        candidate_digest,
                        prior_evidence,
                    )
                    .map_err(|_| SecureFileError::RollbackFailed)?;
                }
                return sync_owner_only_directory(parent, &directory)
                    .map_err(|_| SecureFileError::RollbackFailed);
            }
            (SecretArtifactKind::Candidate, SecretArtifactKind::Candidate, _) => {
                remove_verified_secret_artifact(
                    &paths.staging,
                    &directory,
                    SecretArtifactKind::Candidate,
                    candidate_comparison_key,
                    candidate_digest,
                    prior_evidence,
                )
                .map_err(|_| SecureFileError::RollbackFailed)?;
                staging = SecretArtifactKind::Missing;
            }
            _ => return Err(SecureFileError::RollbackFailed),
        }
    }

    if destination != SecretArtifactKind::Missing {
        debug_assert_eq!(staging, SecretArtifactKind::Missing);
        match move_sibling_file_without_replace(&paths.destination, &paths.staging, &directory)
            .map_err(|_| SecureFileError::RollbackFailed)?
        {
            NoReplaceMoveOutcome::Moved => {
                sync_owner_only_directory(parent, &directory)
                    .map_err(|_| SecureFileError::RollbackFailed)?;
            }
            NoReplaceMoveOutcome::SourceMissing | NoReplaceMoveOutcome::DestinationOccupied => {
                return Err(SecureFileError::RollbackFailed);
            }
        }
    }

    staging = classify(&paths.staging)?;
    let backup = classify(&paths.backup)?;
    match (staging, backup) {
        (
            SecretArtifactKind::Candidate,
            SecretArtifactKind::Prior | SecretArtifactKind::Unowned,
        ) => {
            restore_parked_secret(
                &paths.backup,
                &paths.destination,
                parent,
                &directory,
                backup,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )
            .map_err(|_| SecureFileError::RollbackFailed)?;
            remove_verified_secret_artifact(
                &paths.staging,
                &directory,
                SecretArtifactKind::Candidate,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )
            .map_err(|_| SecureFileError::RollbackFailed)?;
        }
        (SecretArtifactKind::Candidate, SecretArtifactKind::Missing) if !restores_prior => {
            remove_verified_secret_artifact(
                &paths.staging,
                &directory,
                SecretArtifactKind::Candidate,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )
            .map_err(|_| SecureFileError::RollbackFailed)?;
        }
        (SecretArtifactKind::Unowned, SecretArtifactKind::Missing | SecretArtifactKind::Prior) => {
            restore_parked_secret(
                &paths.staging,
                &paths.destination,
                parent,
                &directory,
                SecretArtifactKind::Unowned,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )
            .map_err(|_| SecureFileError::RollbackFailed)?;
            if backup == SecretArtifactKind::Prior {
                remove_verified_secret_artifact(
                    &paths.backup,
                    &directory,
                    SecretArtifactKind::Prior,
                    candidate_comparison_key,
                    candidate_digest,
                    prior_evidence,
                )
                .map_err(|_| SecureFileError::RollbackFailed)?;
            }
        }
        (SecretArtifactKind::Prior, SecretArtifactKind::Missing | SecretArtifactKind::Prior) => {
            restore_parked_secret(
                &paths.staging,
                &paths.destination,
                parent,
                &directory,
                SecretArtifactKind::Prior,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )
            .map_err(|_| SecureFileError::RollbackFailed)?;
            if backup == SecretArtifactKind::Prior {
                remove_verified_secret_artifact(
                    &paths.backup,
                    &directory,
                    SecretArtifactKind::Prior,
                    candidate_comparison_key,
                    candidate_digest,
                    prior_evidence,
                )
                .map_err(|_| SecureFileError::RollbackFailed)?;
            }
        }
        (SecretArtifactKind::Missing, SecretArtifactKind::Prior | SecretArtifactKind::Unowned) => {
            restore_parked_secret(
                &paths.backup,
                &paths.destination,
                parent,
                &directory,
                backup,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )
            .map_err(|_| SecureFileError::RollbackFailed)?;
        }
        (SecretArtifactKind::Missing, SecretArtifactKind::Missing) if !restores_prior => {}
        _ => return Err(SecureFileError::RollbackFailed),
    }
    sync_owner_only_directory(parent, &directory).map_err(|_| SecureFileError::RollbackFailed)
}

/// Removes deterministic staging and backup artifacts after the journal has
/// durably recorded completion or a successful rollback.
pub fn cleanup_owner_only_secret_file(
    paths: &OwnerOnlySecretFilePaths,
    candidate_evidence: Option<(&[u8], &[u8; 32])>,
    prior_evidence: Option<(&[u8], &[u8; 32])>,
) -> Result<(), SecureFileError> {
    let parent = paths
        .destination
        .parent()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let staging_exists = owner_only_secret_destination_exists(&paths.staging)?;
    let backup_exists = owner_only_secret_destination_exists(&paths.backup)?;
    if !staging_exists && !backup_exists {
        return Ok(());
    }
    let directory = open_or_create_owner_only_directory(parent)?;
    if staging_exists {
        let (key, digest) = candidate_evidence.ok_or(SecureFileError::UnsafeOrUnavailable)?;
        verify_owner_only_secret_digest(&paths.staging, key, digest)?;
        remove_sibling_file(&paths.staging, &directory)?;
    }
    if backup_exists {
        let (key, digest) = prior_evidence.ok_or(SecureFileError::UnsafeOrUnavailable)?;
        verify_owner_only_secret_digest(&paths.backup, key, digest)?;
        remove_sibling_file(&paths.backup, &directory)?;
    }
    sync_owner_only_directory(parent, &directory)
}

fn verify_owner_only_secret_digest(
    path: &Path,
    comparison_key: &[u8],
    expected_digest: &[u8; 32],
) -> Result<(), SecureFileError> {
    let stored_digest = keyed_owner_only_secret_file_comparison_digest(path, comparison_key)?;
    constant_time_digest_eq(&stored_digest, expected_digest)
        .then_some(())
        .ok_or(SecureFileError::UnsafeOrUnavailable)
}

fn secret_digest_matches(
    path: &Path,
    comparison_key: &[u8],
    expected_digest: &[u8; 32],
) -> Result<bool, SecureFileError> {
    let stored = read_secure_file(path, SecurityPolicy::OwnerOnly, MAX_SECRET_FILE_BYTES)?;
    let stored_digest = keyed_secret_comparison_digest(comparison_key, stored.as_slice())?;
    Ok(constant_time_digest_eq(&stored_digest, expected_digest))
}

fn constant_time_digest_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

/// Atomically publishes one new owner-only sibling directory without
/// replacing an existing destination.
pub fn publish_new_owner_only_directory(
    source: &Path,
    destination: &Path,
) -> Result<(), SecureFileError> {
    let parent = source
        .parent()
        .filter(|parent| Some(*parent) == destination.parent())
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let directory = open_owner_only_directory(parent)?;
    // Validate the complete staging boundary before dropping its handle for
    // Windows rename semantics. The pinned parent still owns both names.
    drop(open_owner_only_directory(source)?);
    match move_sibling_file_without_replace(source, destination, &directory)? {
        NoReplaceMoveOutcome::Moved => {
            if let Err(error) = sync_owner_only_directory(parent, &directory) {
                return match move_sibling_file_without_replace(destination, source, &directory)? {
                    NoReplaceMoveOutcome::Moved => {
                        sync_owner_only_directory(parent, &directory)?;
                        Err(error)
                    }
                    NoReplaceMoveOutcome::SourceMissing
                    | NoReplaceMoveOutcome::DestinationOccupied => {
                        Err(SecureFileError::RollbackFailed)
                    }
                };
            }
            Ok(())
        }
        NoReplaceMoveOutcome::DestinationOccupied => Err(SecureFileError::OverwriteRequired),
        NoReplaceMoveOutcome::SourceMissing => Err(SecureFileError::UnsafeOrUnavailable),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretArtifactKind {
    Missing,
    Candidate,
    Prior,
    Unowned,
}

fn classify_secret_artifact(
    path: &Path,
    candidate_comparison_key: &[u8],
    candidate_digest: &[u8; 32],
    prior_evidence: Option<(&[u8], &[u8; 32])>,
) -> Result<SecretArtifactKind, SecureFileError> {
    if !owner_only_secret_destination_exists(path)? {
        return Ok(SecretArtifactKind::Missing);
    }
    if let Some((prior_comparison_key, prior_digest)) = prior_evidence
        && secret_digest_matches(path, prior_comparison_key, prior_digest)?
    {
        return Ok(SecretArtifactKind::Prior);
    }
    if secret_digest_matches(path, candidate_comparison_key, candidate_digest)? {
        return Ok(SecretArtifactKind::Candidate);
    }
    Ok(SecretArtifactKind::Unowned)
}

fn remove_verified_secret_artifact(
    path: &Path,
    directory: &OwnerOnlyDirectory,
    expected: SecretArtifactKind,
    candidate_comparison_key: &[u8],
    candidate_digest: &[u8; 32],
    prior_evidence: Option<(&[u8], &[u8; 32])>,
) -> Result<(), SecureFileError> {
    (classify_secret_artifact(
        path,
        candidate_comparison_key,
        candidate_digest,
        prior_evidence,
    )? == expected)
        .then_some(())
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    remove_sibling_file(path, directory)
}

#[allow(clippy::too_many_arguments)]
fn restore_parked_secret(
    source: &Path,
    destination: &Path,
    parent: &Path,
    directory: &OwnerOnlyDirectory,
    expected: SecretArtifactKind,
    candidate_comparison_key: &[u8],
    candidate_digest: &[u8; 32],
    prior_evidence: Option<(&[u8], &[u8; 32])>,
) -> Result<(), SecureFileError> {
    let source_kind = classify_secret_artifact(
        source,
        candidate_comparison_key,
        candidate_digest,
        prior_evidence,
    )?;
    if source_kind != expected {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    match move_sibling_file_without_replace(source, destination, directory)? {
        NoReplaceMoveOutcome::Moved => {
            sync_owner_only_directory(parent, directory)?;
            let restored_kind = classify_secret_artifact(
                destination,
                candidate_comparison_key,
                candidate_digest,
                prior_evidence,
            )?;
            (restored_kind == expected)
                .then_some(())
                .ok_or(SecureFileError::UnsafeOrUnavailable)
        }
        NoReplaceMoveOutcome::SourceMissing | NoReplaceMoveOutcome::DestinationOccupied => {
            Err(SecureFileError::UnsafeOrUnavailable)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NoReplaceMoveOutcome {
    Moved,
    SourceMissing,
    DestinationOccupied,
}

#[cfg(unix)]
fn move_sibling_file_without_replace(
    source: &Path,
    destination: &Path,
    directory: &OwnerOnlyDirectory,
) -> Result<NoReplaceMoveOutcome, SecureFileError> {
    let source_name = source
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let destination_name = destination
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    match rustix::fs::renameat_with(
        directory,
        source_name,
        directory,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(NoReplaceMoveOutcome::Moved),
        Err(rustix::io::Errno::NOENT) => Ok(NoReplaceMoveOutcome::SourceMissing),
        Err(rustix::io::Errno::EXIST) => Ok(NoReplaceMoveOutcome::DestinationOccupied),
        Err(_) => Err(SecureFileError::UnsafeOrUnavailable),
    }
}

#[cfg(windows)]
fn move_sibling_file_without_replace(
    source: &Path,
    destination: &Path,
    _directory: &OwnerOnlyDirectory,
) -> Result<NoReplaceMoveOutcome, SecureFileError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        GetLastError,
    };
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0
    {
        return Ok(NoReplaceMoveOutcome::Moved);
    }
    match unsafe { GetLastError() } {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(NoReplaceMoveOutcome::SourceMissing),
        ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => Ok(NoReplaceMoveOutcome::DestinationOccupied),
        _ => Err(SecureFileError::UnsafeOrUnavailable),
    }
}

#[cfg(not(any(unix, windows)))]
fn move_sibling_file_without_replace(
    _source: &Path,
    _destination: &Path,
    _directory: &OwnerOnlyDirectory,
) -> Result<NoReplaceMoveOutcome, SecureFileError> {
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(unix)]
fn remove_sibling_file(path: &Path, directory: &OwnerOnlyDirectory) -> Result<(), SecureFileError> {
    use rustix::fs::AtFlags;

    let file_name = path
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    match rustix::fs::unlinkat(directory, file_name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(_) => Err(SecureFileError::UnsafeOrUnavailable),
    }
}

#[cfg(not(unix))]
fn remove_sibling_file(
    path: &Path,
    _directory: &OwnerOnlyDirectory,
) -> Result<(), SecureFileError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SecureFileError::UnsafeOrUnavailable),
    }
}

fn cleanup_failed_new_secret(
    temporary_path: &Path,
    path: &Path,
    published: bool,
) -> Result<(), SecureFileError> {
    let _ = std::fs::remove_file(temporary_path);
    if !published {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SecureFileError::PublishedCleanupFailed),
    }
}

#[cfg(unix)]
fn publish_new_file_without_replace(
    temporary_path: &Path,
    path: &Path,
    directory: &OwnerOnlyDirectory,
) -> Result<(), SecureFileError> {
    let temporary_name = temporary_path
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let file_name = path
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    rustix::fs::renameat_with(
        directory,
        temporary_name,
        directory,
        file_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)
}

#[cfg(windows)]
fn publish_new_file_without_replace(
    temporary_path: &Path,
    path: &Path,
    _directory: &OwnerOnlyDirectory,
) -> Result<(), SecureFileError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let temporary = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // Omitting MOVEFILE_REPLACE_EXISTING preserves the no-replace guarantee.
    // WRITE_THROUGH supplies the durability barrier that directory sync gives
    // the Unix path after its atomic rename.
    (unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0)
        .then_some(())
        .ok_or(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(unix)]
pub fn sync_owner_only_directory(
    path: &Path,
    _directory: &OwnerOnlyDirectory,
) -> Result<(), SecureFileError> {
    File::open(path)
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)?
        .sync_all()
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)
}

#[cfg(not(unix))]
pub fn sync_owner_only_directory(
    _path: &Path,
    _directory: &OwnerOnlyDirectory,
) -> Result<(), SecureFileError> {
    Ok(())
}

/// Reads larger secret configuration material such as a PEM private key while
/// retaining the regular-file, ownership, link, and ACL requirements of
/// ordinary token files and allowing owner-read-only key material.
pub fn read_owner_only_secret_config_file(
    path: &Path,
) -> Result<Zeroizing<String>, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerPrivate, MAX_CONFIG_FILE_BYTES)?;
    let value = std::str::from_utf8(bytes.as_slice()).map_err(|_| SecureFileError::NotUtf8)?;
    Ok(Zeroizing::new(value.to_string()))
}

pub fn read_owner_controlled_config_file(path: &Path) -> Result<String, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerControlled, MAX_CONFIG_FILE_BYTES)?;
    std::str::from_utf8(bytes.as_slice())
        .map(str::to_string)
        .map_err(|_| SecureFileError::NotUtf8)
}

pub fn read_trusted_ca_bundle_file(path: &Path) -> Result<String, SecureFileError> {
    let bytes = read_secure_file(
        path,
        SecurityPolicy::UserOrAdministratorControlled,
        MAX_CONFIG_FILE_BYTES,
    )?;
    std::str::from_utf8(bytes.as_slice())
        .map(str::to_string)
        .map_err(|_| SecureFileError::NotUtf8)
}

/// Reads a user-selected regular file through one no-follow handle. Path
/// components are resolved beneath pinned directory handles, so validation and
/// reading cannot observe different filesystem objects.
pub fn read_bounded_regular_file_no_follow(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, SecureFileError> {
    let limit = maximum_bytes
        .checked_add(1)
        .and_then(|limit| u64::try_from(limit).ok())
        .ok_or(SecureFileError::TooLarge)?;
    let mut file = open_regular_file_no_follow(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(SecureFileError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_file_no_follow(path: &Path) -> Result<File, SecureFileError> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::path::Component;

    let absolute = path.is_absolute();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if absolute => {}
            Component::CurDir => {}
            Component::Normal(name) => names.push(name),
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
        }
    }
    let (leaf, parents) = names
        .split_last()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let flags = unix_directory_search_flags()?;
    let mut directory = rustix::fs::open(
        if absolute {
            Path::new("/")
        } else {
            Path::new(".")
        },
        flags,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    for parent in parents {
        let child = rustix::fs::openat(&directory, *parent, flags, Mode::empty())
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
        let metadata =
            rustix::fs::fstat(&child).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        directory = child;
    }
    let descriptor = rustix::fs::openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_regular_file_no_follow(path: &Path) -> Result<File, SecureFileError> {
    windows::open_regular_file_no_follow(path)
}

/// Creates a regular file with Satelle's owner-only policy, or opens an
/// existing file only when it already satisfies that policy.
#[cfg(unix)]
pub fn open_or_create_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
    use rustix::fs::{FileType, Mode, OFlags};

    require_macos_parent_without_extended_acl(path)?;
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (descriptor, created) = match rustix::fs::open(path, create_flags, Mode::RUSR | Mode::WUSR)
    {
        Ok(descriptor) => (descriptor, true),
        Err(rustix::io::Errno::EXIST) => (
            rustix::fs::open(
                path,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?,
            false,
        ),
        Err(_) => return Err(SecureFileError::UnsafeOrUnavailable),
    };
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || (!created && metadata.st_mode & 0o777 != 0o600)
    {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    require_no_macos_extended_acl(&descriptor)?;
    if created {
        rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    }
    Ok(File::from(descriptor))
}

/// Creates a new regular file under a pinned owner-only parent and fails if
/// any filesystem entry already occupies the generated name.
#[cfg(unix)]
pub fn open_new_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    let parent = path.parent().ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let directory = open_or_create_owner_only_directory(parent)?;
    let file_name = path
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let descriptor = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let validated = (|| {
        let metadata =
            rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
            || metadata.st_uid != rustix::process::geteuid().as_raw()
            || metadata.st_nlink != 1
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        require_no_macos_extended_acl(&descriptor)?;
        rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)
    })();
    if let Err(error) = validated {
        let _ = rustix::fs::unlinkat(&directory, file_name, AtFlags::empty());
        return Err(error);
    }
    Ok(File::from(descriptor))
}

/// Opens or creates an owner-only directory. Unix walks every absolute path
/// component without following symlinks and rejects ancestry that permits
/// unrelated replacement. Keeping the returned handle alive also pins the
/// directory against replacement on platforms that support that guarantee.
#[cfg(unix)]
pub fn open_or_create_owner_only_directory(
    path: &Path,
) -> Result<OwnerOnlyDirectory, SecureFileError> {
    open_owner_only_directory_impl(path, true)
}

/// Opens an existing owner-only directory with the same ancestry guarantees as
/// `open_or_create_owner_only_directory`, but never creates a missing path.
#[cfg(unix)]
pub fn open_owner_only_directory(path: &Path) -> Result<OwnerOnlyDirectory, SecureFileError> {
    open_owner_only_directory_impl(path, false)
}

#[cfg(unix)]
fn open_owner_only_directory_impl(
    path: &Path,
    create_if_missing: bool,
) -> Result<File, SecureFileError> {
    use rustix::fs::{AtFlags, FileType, Mode};
    use std::path::Component;

    if !path.is_absolute() {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    #[cfg(target_os = "macos")]
    let resolved_path = resolve_trusted_macos_ancestor_aliases(path)?;
    #[cfg(target_os = "macos")]
    let path = resolved_path.as_path();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => names.push(name),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
        }
    }
    if names.is_empty() {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }

    let flags = unix_directory_search_flags()?;
    let mut directory = rustix::fs::open("/", flags, Mode::empty())
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let effective_user = rustix::process::geteuid().as_raw();

    for (index, name) in names.iter().enumerate() {
        require_unix_directory_replacement_safety(&directory, effective_user)?;
        let final_component = index + 1 == names.len();
        let (child, created) = match rustix::fs::openat(&directory, *name, flags, Mode::empty()) {
            Ok(child) => (child, false),
            Err(rustix::io::Errno::NOENT) if final_component && create_if_missing => {
                let created = match rustix::fs::mkdirat(&directory, *name, Mode::RWXU) {
                    Ok(()) => {
                        // Search-only descriptors cannot be passed to fchmod.
                        // The safe parent is not writable by unrelated users,
                        // so set the exact boundary mode before reopening it.
                        rustix::fs::chmodat(&directory, *name, Mode::RWXU, AtFlags::empty())
                            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
                        true
                    }
                    // Another first-run process may create the boundary after
                    // openat reports NOENT. Reopen and validate it as existing.
                    Err(rustix::io::Errno::EXIST) => false,
                    Err(_) => return Err(SecureFileError::UnsafeOrUnavailable),
                };
                let child = rustix::fs::openat(&directory, *name, flags, Mode::empty())
                    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
                (child, created)
            }
            Err(_) => return Err(SecureFileError::UnsafeOrUnavailable),
        };
        let metadata =
            rustix::fs::fstat(&child).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
        if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
            || (metadata.st_uid != 0 && metadata.st_uid != effective_user)
            || (final_component
                && (metadata.st_uid != effective_user
                    || (!created && metadata.st_mode & 0o777 != 0o700)))
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        directory = child;
    }
    require_no_macos_extended_acl(&directory)?;
    Ok(File::from(directory))
}

#[cfg(unix)]
fn unix_directory_search_flags() -> Result<rustix::fs::OFlags, SecureFileError> {
    use rustix::fs::OFlags;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let search_only = OFlags::PATH;
    #[cfg(any(
        target_vendor = "apple",
        target_os = "aix",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "solaris"
    ))]
    let search_only = OFlags::from_bits_retain(libc::O_SEARCH as _);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "aix",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "solaris"
    )))]
    return Err(SecureFileError::UnsafeOrUnavailable);

    Ok(search_only | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC)
}

#[cfg(target_os = "macos")]
fn resolve_trusted_macos_ancestor_aliases(
    path: &Path,
) -> Result<std::path::PathBuf, SecureFileError> {
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, PathBuf};

    let parent = path.parent().ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let file_name = path
        .file_name()
        .ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let mut prefix = PathBuf::from("/");
    for component in parent.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => prefix.push(name),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
        }
        let metadata =
            std::fs::symlink_metadata(&prefix).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
        if metadata.file_type().is_symlink() {
            let containing_directory = prefix
                .parent()
                .ok_or(SecureFileError::UnsafeOrUnavailable)?;
            let containing_metadata = std::fs::symlink_metadata(containing_directory)
                .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
            if metadata.uid() != 0
                || containing_metadata.uid() != 0
                || containing_metadata.mode() & 0o022 != 0
            {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
        }
    }
    let resolved_parent =
        std::fs::canonicalize(parent).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    Ok(resolved_parent.join(file_name))
}

#[cfg(unix)]
fn require_unix_directory_replacement_safety(
    directory: &impl std::os::fd::AsFd,
    effective_user: u32,
) -> Result<(), SecureFileError> {
    use rustix::fs::FileType;

    let metadata =
        rustix::fs::fstat(directory).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let owner_is_trusted = metadata.st_uid == 0 || metadata.st_uid == effective_user;
    let writable_by_others = metadata.st_mode & 0o022 != 0;
    let replacement_is_sticky = metadata.st_mode & 0o1000 != 0;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || !owner_is_trusted
        || (writable_by_others && !replacement_is_sticky)
    {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    require_no_macos_replacement_acl(directory)
}

#[cfg(target_os = "macos")]
fn require_no_macos_replacement_acl(
    descriptor: &impl std::os::fd::AsFd,
) -> Result<(), SecureFileError> {
    use std::os::fd::AsRawFd;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    const ACL_ADD_FILE: u64 = 1 << 2;
    const ACL_DELETE: u64 = 1 << 4;
    const ACL_ADD_SUBDIRECTORY: u64 = 1 << 5;
    const ACL_DELETE_CHILD: u64 = 1 << 6;
    const REPLACEMENT_PERMISSIONS: u64 =
        ACL_ADD_FILE | ACL_DELETE | ACL_ADD_SUBDIRECTORY | ACL_DELETE_CHILD;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_get_permset_mask_np(entry: *mut libc::c_void, mask: *mut u64) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // Restrictive entries are common on otherwise safe macOS ancestors, such
    // as a home directory carrying `everyone deny delete`. Only an allow entry
    // with directory-replacement rights invalidates the mode-bit guarantee.
    unsafe {
        *libc::__error() = 0;
        let acl = acl_get_fd_np(descriptor.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            return (*libc::__error() == libc::ENOENT)
                .then_some(())
                .ok_or(SecureFileError::UnsafeOrUnavailable);
        }
        let validation = (|| {
            let mut entry_id = ACL_FIRST_ENTRY;
            loop {
                let mut entry = std::ptr::null_mut();
                *libc::__error() = 0;
                if acl_get_entry(acl, entry_id, &mut entry) != 0 {
                    return (*libc::__error() == libc::EINVAL)
                        .then_some(())
                        .ok_or(SecureFileError::UnsafeOrUnavailable);
                }
                let mut tag = 0;
                let mut permissions = 0;
                if acl_get_tag_type(entry, &mut tag) != 0
                    || acl_get_permset_mask_np(entry, &mut permissions) != 0
                {
                    return Err(SecureFileError::UnsafeOrUnavailable);
                }
                if tag == ACL_EXTENDED_ALLOW && permissions & REPLACEMENT_PERMISSIONS != 0 {
                    return Err(SecureFileError::UnsafeOrUnavailable);
                }
                entry_id = ACL_NEXT_ENTRY;
            }
        })();
        let _ = acl_free(acl);
        validation
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_no_macos_replacement_acl(
    _descriptor: &impl std::os::fd::AsFd,
) -> Result<(), SecureFileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_macos_parent_without_extended_acl(path: &Path) -> Result<(), SecureFileError> {
    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let descriptor = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    require_no_macos_extended_acl(&descriptor)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_macos_parent_without_extended_acl(_path: &Path) -> Result<(), SecureFileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_no_macos_extended_acl(
    descriptor: &impl std::os::fd::AsFd,
) -> Result<(), SecureFileError> {
    use std::os::fd::AsRawFd;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // acl_get_fd_np returns NULL with ENOENT when no extended ACL exists.
    // Any allocated ACL is non-canonical for Satelle's owner-only policy,
    // regardless of its allow/deny ordering.
    unsafe {
        *libc::__error() = 0;
        let acl = acl_get_fd_np(descriptor.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            return (*libc::__error() == libc::ENOENT)
                .then_some(())
                .ok_or(SecureFileError::UnsafeOrUnavailable);
        }
        let _ = acl_free(acl);
    }
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_no_macos_extended_acl(
    _descriptor: &impl std::os::fd::AsFd,
) -> Result<(), SecureFileError> {
    Ok(())
}

#[cfg(windows)]
pub fn open_or_create_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
    windows::open_or_create_owner_only_file(path)
}

#[cfg(windows)]
pub fn open_new_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
    let parent = path.parent().ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let _directory = open_or_create_owner_only_directory(parent)?;
    windows::open_new_owner_only_file(path)
}

#[cfg(windows)]
pub fn open_or_create_owner_only_directory(
    path: &Path,
) -> Result<OwnerOnlyDirectory, SecureFileError> {
    windows::open_or_create_owner_only_directory(path)
}

#[cfg(windows)]
pub fn open_owner_only_directory(path: &Path) -> Result<OwnerOnlyDirectory, SecureFileError> {
    windows::open_owner_only_directory(path)
}

#[cfg(not(any(unix, windows)))]
pub fn open_or_create_owner_only_file(_path: &Path) -> Result<File, SecureFileError> {
    // Satelle cannot claim owner-only persistence on a platform without an
    // implemented file-security policy.
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(not(any(unix, windows)))]
pub fn open_new_owner_only_file(_path: &Path) -> Result<File, SecureFileError> {
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(not(any(unix, windows)))]
pub fn open_or_create_owner_only_directory(
    _path: &Path,
) -> Result<OwnerOnlyDirectory, SecureFileError> {
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(not(any(unix, windows)))]
pub fn open_owner_only_directory(_path: &Path) -> Result<OwnerOnlyDirectory, SecureFileError> {
    Err(SecureFileError::UnsafeOrUnavailable)
}

fn read_secure_file(
    path: &Path,
    policy: SecurityPolicy,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureFileError> {
    let mut file = open_secure_file(path, policy)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum_bytes.min(4096)));
    Read::by_ref(&mut file)
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(SecureFileError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_secure_file(path: &Path, policy: SecurityPolicy) -> Result<File, SecureFileError> {
    use rustix::fs::{FileType, Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let mode = metadata.st_mode & 0o777;
    let permissions_are_safe = match policy {
        SecurityPolicy::OwnerOnly => mode == 0o600,
        SecurityPolicy::OwnerPrivate => matches!(mode, 0o400 | 0o600),
        SecurityPolicy::OwnerControlled | SecurityPolicy::UserOrAdministratorControlled => {
            mode & 0o022 == 0
        }
    };
    let owner_is_trusted = metadata.st_uid == rustix::process::geteuid().as_raw()
        || (policy == SecurityPolicy::UserOrAdministratorControlled && metadata.st_uid == 0);
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || !owner_is_trusted
        || metadata.st_nlink != 1
        || !permissions_are_safe
    {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    if matches!(
        policy,
        SecurityPolicy::OwnerOnly | SecurityPolicy::OwnerPrivate
    ) {
        require_no_macos_extended_acl(&descriptor)?;
    }
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_secure_file(path: &Path, policy: SecurityPolicy) -> Result<File, SecureFileError> {
    windows::open_secure_file(path, policy)
}

#[cfg(windows)]
mod windows {
    use super::{OwnerOnlyDirectory, SecureFileError, SecurityPolicy};
    use std::ffi::{OsString, c_void};
    use std::fs::File;
    use std::marker::PhantomData;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::path::{Component, Path, PathBuf};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE, LocalFree, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, CopySid,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
        GetTokenInformation, IsValidAcl, IsValidSid, IsWellKnownSid, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, DELETE, FILE_ALL_ACCESS,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        FileAttributeTagInfo, FileDispositionInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetFileType, GetVolumeInformationByHandleW, OPEN_ALWAYS,
        OPEN_EXISTING, READ_CONTROL, SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const DANGEROUS_WRITE_MASK: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;

    pub(super) fn open_or_create_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
        open_owner_only_file(path, OPEN_ALWAYS)
    }

    pub(super) fn open_new_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
        open_owner_only_file(path, CREATE_NEW)
    }

    fn open_owner_only_file(
        path: &Path,
        creation_disposition: u32,
    ) -> Result<File, SecureFileError> {
        let process_sid = current_user_sid()?;
        let descriptor = PrivateDescriptor::new(&process_sid, "")?;
        let attributes = descriptor.security_attributes();
        let wide = wide_path(path)?;
        let create_new = creation_disposition == CREATE_NEW;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ
                    | FILE_GENERIC_WRITE
                    | READ_CONTROL
                    | WRITE_DAC
                    | if create_new { DELETE } else { 0 },
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                creation_disposition,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let validated = (|| {
            require_persistent_acls(&handle)?;
            require_regular_single_link(&handle)?;
            verify_security(&handle, &process_sid, SecurityPolicy::OwnerOnly)
        })();
        if let Err(error) = validated {
            if create_new {
                let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                unsafe {
                    SetFileInformationByHandle(
                        raw_handle(&handle),
                        FileDispositionInfo,
                        (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                        size_of::<FILE_DISPOSITION_INFO>() as u32,
                    );
                }
            }
            return Err(error);
        }
        Ok(File::from(handle))
    }

    pub(super) fn open_regular_file_no_follow(path: &Path) -> Result<File, SecureFileError> {
        let (root, names) = if path.is_absolute() {
            windows_directory_components(path)?
        } else {
            let names = path
                .components()
                .filter_map(|component| match component {
                    Component::CurDir => None,
                    Component::Normal(name) => Some(Ok(name.to_os_string())),
                    Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                        Some(Err(SecureFileError::UnsafeOrUnavailable))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            (PathBuf::from("."), names)
        };
        let (leaf, parents) = names
            .split_last()
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let mut directory = open_absolute_directory(&root)?;
        require_directory(&directory)?;
        for parent in parents {
            let child = open_relative_directory(&directory, parent, false, null())?;
            require_directory(&child)?;
            directory = child;
        }
        let handle = open_relative_regular_file(&directory, leaf)?;
        require_regular_file(&handle)?;
        Ok(File::from(handle))
    }

    pub(super) fn open_or_create_owner_only_directory(
        path: &Path,
    ) -> Result<OwnerOnlyDirectory, SecureFileError> {
        open_owner_only_directory_impl(path, true)
    }

    pub(super) fn open_owner_only_directory(
        path: &Path,
    ) -> Result<OwnerOnlyDirectory, SecureFileError> {
        open_owner_only_directory_impl(path, false)
    }

    fn open_owner_only_directory_impl(
        path: &Path,
        create_if_missing: bool,
    ) -> Result<OwnerOnlyDirectory, SecureFileError> {
        let process_sid = current_user_sid()?;
        let descriptor = PrivateDescriptor::new(&process_sid, "OICI")?;
        let attributes = descriptor.security_attributes();
        let (root, names) = windows_directory_components(path)?;
        let mut directory = open_absolute_directory(&root)?;
        require_persistent_acls(&directory)?;
        require_directory(&directory)?;
        let mut ancestors = Vec::with_capacity(names.len());

        for (index, name) in names.iter().enumerate() {
            let final_component = index + 1 == names.len();
            let child = open_relative_directory(
                &directory,
                name,
                final_component && create_if_missing,
                if final_component {
                    attributes.lpSecurityDescriptor.cast_const()
                } else {
                    null()
                },
            )?;
            require_persistent_acls(&child)?;
            require_directory(&child)?;
            ancestors.push(File::from(directory));
            directory = child;
        }
        // NtCreateFile applies the protected DACL only when FILE_OPEN_IF creates
        // the final directory. Existing namespaces must already satisfy it.
        verify_owner_only_security(
            &directory,
            &process_sid,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )?;
        Ok(OwnerOnlyDirectory {
            _directory: File::from(directory),
            _ancestors: ancestors,
        })
    }

    fn windows_directory_components(
        path: &Path,
    ) -> Result<(PathBuf, Vec<OsString>), SecureFileError> {
        let mut components = path.components();
        let Component::Prefix(prefix) = components
            .next()
            .ok_or(SecureFileError::UnsafeOrUnavailable)?
        else {
            return Err(SecureFileError::UnsafeOrUnavailable);
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut root = PathBuf::from(prefix.as_os_str());
        root.push(r"\");
        let names = components
            .map(|component| match component {
                Component::Normal(name) => Ok(name.to_os_string()),
                Component::Prefix(_)
                | Component::RootDir
                | Component::CurDir
                | Component::ParentDir => Err(SecureFileError::UnsafeOrUnavailable),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if names.is_empty() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok((root, names))
    }

    fn open_absolute_directory(path: &Path) -> Result<OwnedHandle, SecureFileError> {
        let wide = wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    fn open_relative_directory(
        parent: &OwnedHandle,
        name: &OsString,
        create_if_missing: bool,
        security_descriptor: *const c_void,
    ) -> Result<OwnedHandle, SecureFileError> {
        let mut wide = name.encode_wide().collect::<Vec<_>>();
        let byte_length = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let object_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: wide.as_mut_ptr(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: raw_handle(parent),
            ObjectName: &object_name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: security_descriptor.cast(),
            SecurityQualityOfService: null(),
        };
        let mut raw = INVALID_HANDLE_VALUE;
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                &object_attributes,
                &mut io_status,
                null(),
                FILE_ATTRIBUTE_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                if create_if_missing {
                    FILE_OPEN_IF
                } else {
                    FILE_OPEN
                },
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
                null(),
                0,
            )
        };
        if status < 0 || raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    fn open_relative_regular_file(
        parent: &OwnedHandle,
        name: &OsString,
    ) -> Result<OwnedHandle, SecureFileError> {
        let mut wide = name.encode_wide().collect::<Vec<_>>();
        let byte_length = wide
            .len()
            .checked_mul(size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let object_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: wide.as_mut_ptr(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: raw_handle(parent),
            ObjectName: &object_name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null(),
        };
        let mut raw = INVALID_HANDLE_VALUE;
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                FILE_GENERIC_READ,
                &object_attributes,
                &mut io_status,
                null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                null(),
                0,
            )
        };
        if status < 0 || raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    pub(super) fn open_secure_file(
        path: &Path,
        policy: SecurityPolicy,
    ) -> Result<File, SecureFileError> {
        let wide = wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        require_persistent_acls(&handle)?;
        require_regular_single_link(&handle)?;
        let process_sid = current_user_sid()?;
        verify_security(&handle, &process_sid, policy)?;
        Ok(File::from(handle))
    }

    fn require_regular_single_link(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        require_regular_file(handle)?;
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(raw_handle(handle), &mut information) } == 0
            || information.nNumberOfLinks != 1
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn require_regular_file(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        if unsafe { GetFileType(raw_handle(handle)) } != FILE_TYPE_DISK {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let loaded = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(handle),
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if loaded == 0
            || attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn require_directory(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        if unsafe { GetFileType(raw_handle(handle)) } != FILE_TYPE_DISK {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let loaded = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(handle),
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if loaded == 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn require_persistent_acls(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        let mut flags = 0_u32;
        let loaded = unsafe {
            GetVolumeInformationByHandleW(
                raw_handle(handle),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                null_mut(),
                0,
            )
        };
        if loaded == 0 || flags & FILE_PERSISTENT_ACLS == 0 {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn verify_security(
        handle: &OwnedHandle,
        process_sid: &ProcessSid,
        policy: SecurityPolicy,
    ) -> Result<(), SecureFileError> {
        let security = read_security(handle)?;
        let owner_is_trusted = !security.owner.is_null()
            && (unsafe { EqualSid(security.owner, process_sid.as_psid()) } != 0
                || (policy == SecurityPolicy::UserOrAdministratorControlled
                    && unsafe {
                        IsWellKnownSid(security.owner, WinLocalSystemSid) != 0
                            || IsWellKnownSid(security.owner, WinBuiltinAdministratorsSid) != 0
                    }));
        if !owner_is_trusted || security.dacl.is_null() || unsafe { IsValidAcl(security.dacl) } == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        match policy {
            SecurityPolicy::OwnerOnly => {
                verify_owner_only_dacl(&security, process_sid, 0, OwnerAccess::Full)
            }
            SecurityPolicy::OwnerPrivate => {
                verify_owner_only_dacl(&security, process_sid, 0, OwnerAccess::ReadOrFull)
            }
            SecurityPolicy::OwnerControlled | SecurityPolicy::UserOrAdministratorControlled => {
                verify_owner_controlled_dacl(&security, process_sid)
            }
        }
    }

    #[derive(Clone, Copy)]
    enum OwnerAccess {
        Full,
        ReadOrFull,
    }

    impl OwnerAccess {
        const fn permits(self, access: u32) -> bool {
            match self {
                Self::Full => access == FILE_ALL_ACCESS,
                Self::ReadOrFull => access & FILE_GENERIC_READ == FILE_GENERIC_READ,
            }
        }
    }

    fn verify_owner_only_dacl(
        security: &SecurityView,
        process_sid: &ProcessSid,
        expected_ace_flags: u8,
        owner_access: OwnerAccess,
    ) -> Result<(), SecureFileError> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe {
            GetSecurityDescriptorControl(security.allocation.as_ptr(), &mut control, &mut revision)
        } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let dacl = unsafe { &*security.dacl };
        let mut owner_allow_seen = false;
        for index in 0..dacl.AceCount {
            match ace_entry(security, u32::from(index))? {
                // A deny ACE cannot grant access to another principal. Accept
                // it without making the owner-only invariant depend on one
                // serialized DACL shape.
                AceEntry::Denied => {}
                AceEntry::Allowed(ace) => {
                    if owner_allow_seen
                        || ace.flags != expected_ace_flags
                        || !owner_access.permits(normalized_file_access_mask(ace.mask))
                        || !ace_matches(&ace, process_sid)
                    {
                        return Err(SecureFileError::UnsafeOrUnavailable);
                    }
                    owner_allow_seen = true;
                }
                AceEntry::Unsupported => return Err(SecureFileError::UnsafeOrUnavailable),
            }
        }
        owner_allow_seen
            .then_some(())
            .ok_or(SecureFileError::UnsafeOrUnavailable)
    }

    fn verify_owner_only_security(
        handle: &OwnedHandle,
        process_sid: &ProcessSid,
        expected_ace_flags: u8,
    ) -> Result<(), SecureFileError> {
        let security = read_security(handle)?;
        if security.owner.is_null()
            || unsafe { EqualSid(security.owner, process_sid.as_psid()) } == 0
            || security.dacl.is_null()
            || unsafe { IsValidAcl(security.dacl) } == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        verify_owner_only_dacl(
            &security,
            process_sid,
            expected_ace_flags,
            OwnerAccess::Full,
        )
    }

    fn normalized_file_access_mask(mask: u32) -> u32 {
        let mut normalized = mask & !(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
        if mask & GENERIC_ALL != 0 {
            normalized |= FILE_ALL_ACCESS;
        }
        if mask & GENERIC_READ != 0 {
            normalized |= FILE_GENERIC_READ;
        }
        if mask & GENERIC_WRITE != 0 {
            normalized |= FILE_GENERIC_WRITE;
        }
        if mask & GENERIC_EXECUTE != 0 {
            normalized |= FILE_GENERIC_EXECUTE;
        }
        normalized
    }

    fn verify_owner_controlled_dacl(
        security: &SecurityView,
        process_sid: &ProcessSid,
    ) -> Result<(), SecureFileError> {
        let dacl = unsafe { &*security.dacl };
        for index in 0..dacl.AceCount {
            match ace_entry(security, u32::from(index))? {
                AceEntry::Denied => {}
                AceEntry::Allowed(ace) => {
                    if !trusted_config_writer(&ace, process_sid)
                        && ace.mask & DANGEROUS_WRITE_MASK != 0
                    {
                        return Err(SecureFileError::UnsafeOrUnavailable);
                    }
                }
                AceEntry::Unsupported => return Err(SecureFileError::UnsafeOrUnavailable),
            }
        }
        Ok(())
    }

    enum AceEntry<'security> {
        Allowed(ValidatedAllowedAce<'security>),
        Denied,
        Unsupported,
    }

    struct ValidatedAllowedAce<'security> {
        mask: u32,
        flags: u8,
        sid: PSID,
        _security: PhantomData<&'security SecurityView>,
    }

    fn ace_entry<'security>(
        security: &'security SecurityView,
        index: u32,
    ) -> Result<AceEntry<'security>, SecureFileError> {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(security.dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let acl_start = security.dacl as usize;
        let ace_start = raw_ace as usize;
        let ace_offset = ace_start
            .checked_sub(acl_start)
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let acl_size = usize::from(unsafe { &*security.dacl }.AclSize);
        if ace_offset
            .checked_add(size_of::<ACE_HEADER>())
            .is_none_or(|end| end > acl_size)
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let header = unsafe { raw_ace.cast::<ACE_HEADER>().read_unaligned() };
        if ace_offset
            .checked_add(usize::from(header.AceSize))
            .is_none_or(|end| end > acl_size)
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                validated_allowed_ace(security, raw_ace.cast(), header).map(AceEntry::Allowed)
            }
            ACCESS_DENIED_ACE_TYPE => Ok(AceEntry::Denied),
            _ => Ok(AceEntry::Unsupported),
        }
    }

    fn validated_allowed_ace<'security>(
        _security: &'security SecurityView,
        raw_ace: *const u8,
        header: ACE_HEADER,
    ) -> Result<ValidatedAllowedAce<'security>, SecureFileError> {
        const SID_HEADER_BYTES: usize = 8;
        let ace_size = usize::from(header.AceSize);
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if ace_size < sid_offset + SID_HEADER_BYTES {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let sid_bytes =
            unsafe { std::slice::from_raw_parts(raw_ace.add(sid_offset), ace_size - sid_offset) };
        let subauthority_bytes = usize::from(sid_bytes[1])
            .checked_mul(size_of::<u32>())
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let sid_length = SID_HEADER_BYTES
            .checked_add(subauthority_bytes)
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        if sid_length > sid_bytes.len() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let sid = unsafe { raw_ace.add(sid_offset) }.cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize != sid_length {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mask = unsafe {
            raw_ace
                .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                .cast::<u32>()
                .read_unaligned()
        };
        Ok(ValidatedAllowedAce {
            mask,
            flags: header.AceFlags,
            sid,
            _security: PhantomData,
        })
    }

    fn ace_matches(ace: &ValidatedAllowedAce<'_>, process_sid: &ProcessSid) -> bool {
        (unsafe { EqualSid(ace.sid, process_sid.as_psid()) }) != 0
    }

    fn trusted_config_writer(ace: &ValidatedAllowedAce<'_>, process_sid: &ProcessSid) -> bool {
        unsafe {
            EqualSid(ace.sid, process_sid.as_psid()) != 0
                || IsWellKnownSid(ace.sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(ace.sid, WinBuiltinAdministratorsSid) != 0
        }
    }

    fn current_user_sid() -> Result<ProcessSid, SecureFileError> {
        let mut raw_token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let information = token_information(&token, TokenUser, size_of::<TOKEN_USER>())?;
        let token_user = unsafe { &*information.as_ptr().cast::<TOKEN_USER>() };
        ProcessSid::copy_from(token_user.User.Sid)
    }

    fn token_information(
        token: &OwnedHandle,
        class: TOKEN_INFORMATION_CLASS,
        minimum: usize,
    ) -> Result<Vec<usize>, SecureFileError> {
        let mut required = 0_u32;
        unsafe { GetTokenInformation(raw_handle(token), class, null_mut(), 0, &mut required) };
        if (required as usize) < minimum {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut words = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                raw_handle(token),
                class,
                words.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(words)
    }

    struct ProcessSid(Box<[usize]>);

    impl ProcessSid {
        fn copy_from(sid: PSID) -> Result<Self, SecureFileError> {
            if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            let length = unsafe { GetLengthSid(sid) };
            let mut words =
                vec![0_usize; (length as usize).div_ceil(size_of::<usize>())].into_boxed_slice();
            if unsafe { CopySid(length, words.as_mut_ptr().cast(), sid) } == 0 {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            Ok(Self(words))
        }

        fn as_psid(&self) -> PSID {
            self.0.as_ptr().cast_mut().cast()
        }

        fn sddl(&self) -> Result<String, SecureFileError> {
            let mut raw = null_mut();
            if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut raw) } == 0 || raw.is_null() {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            let allocation = LocalWideString(raw);
            allocation.to_string()
        }
    }

    struct PrivateDescriptor(LocalMemory);

    impl PrivateDescriptor {
        fn new(process_sid: &ProcessSid, ace_flags: &str) -> Result<Self, SecureFileError> {
            let sid = process_sid.sddl()?;
            let sddl = format!("O:{sid}D:P(A;{ace_flags};FA;;;{sid})");
            let wide = wide_string(&sddl)?;
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
                || descriptor.is_null()
            {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            Ok(Self(LocalMemory(descriptor)))
        }

        fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0.as_ptr(),
                bInheritHandle: 0,
            }
        }
    }

    struct SecurityView {
        allocation: LocalMemory,
        owner: PSID,
        dacl: *mut ACL,
    }

    fn read_security(handle: &OwnedHandle) -> Result<SecurityView, SecureFileError> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                raw_handle(handle),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || descriptor.is_null() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(SecurityView {
            allocation: LocalMemory(descriptor),
            owner,
            dacl,
        })
    }

    struct LocalMemory(PSECURITY_DESCRIPTOR);

    impl LocalMemory {
        fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }
    }

    impl Drop for LocalMemory {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }

    struct LocalWideString(*mut u16);

    impl LocalWideString {
        fn to_string(&self) -> Result<String, SecureFileError> {
            const MAX_SID_STRING_UNITS: usize = 1024;

            let length = (0..MAX_SID_STRING_UNITS)
                .find(|index| unsafe { *self.0.add(*index) } == 0)
                .ok_or(SecureFileError::UnsafeOrUnavailable)?;
            String::from_utf16(unsafe { std::slice::from_raw_parts(self.0, length) })
                .map_err(|_| SecureFileError::UnsafeOrUnavailable)
        }
    }

    impl Drop for LocalWideString {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, SecureFileError> {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.is_empty() || wide.contains(&0) {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        wide.push(0);
        Ok(wide)
    }

    fn wide_string(value: &str) -> Result<Vec<u16>, SecureFileError> {
        let mut wide = value.encode_utf16().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        wide.push(0);
        Ok(wide)
    }

    fn raw_handle(handle: &OwnedHandle) -> HANDLE {
        use std::os::windows::io::AsRawHandle;
        handle.as_raw_handle()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn generic_access_masks_normalize_without_hiding_extra_rights() {
            const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

            assert_eq!(normalized_file_access_mask(GENERIC_ALL), FILE_ALL_ACCESS);
            assert_eq!(
                normalized_file_access_mask(FILE_ALL_ACCESS),
                FILE_ALL_ACCESS
            );
            assert_ne!(
                normalized_file_access_mask(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE),
                FILE_ALL_ACCESS
            );
            assert_eq!(
                normalized_file_access_mask(GENERIC_ALL | ACCESS_SYSTEM_SECURITY),
                FILE_ALL_ACCESS | ACCESS_SYSTEM_SECURITY
            );
            assert!(OwnerAccess::Full.permits(FILE_ALL_ACCESS));
            assert!(!OwnerAccess::Full.permits(FILE_GENERIC_READ));
            assert!(OwnerAccess::ReadOrFull.permits(FILE_GENERIC_READ));
            assert!(OwnerAccess::ReadOrFull.permits(FILE_ALL_ACCESS));
            assert!(
                OwnerAccess::ReadOrFull
                    .permits(normalized_file_access_mask(GENERIC_READ | GENERIC_WRITE))
            );
            assert!(!OwnerAccess::ReadOrFull.permits(FILE_GENERIC_WRITE));
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::*;
    #[cfg(any(unix, windows))]
    use std::fs;
    #[cfg(any(unix, windows))]
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    const SSH_IDENTITY_OPERATION_ID: &str = "0195f6d5-18da-7a80-8000-000000000001";
    const SSH_IDENTITY_BINARY_SHA256: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const SSH_IDENTITY_ARCHIVE_SHA256: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    #[cfg(any(unix, windows))]
    fn ssh_identity_record(
        target_id: &str,
        state_root: &str,
        exact_remote_path: &str,
    ) -> SshIdentityCommitRecord {
        SshIdentityCommitRecord::new(
            SSH_IDENTITY_OPERATION_ID,
            crate::session::HostIdentityRef::new(
                "host-0195f6d5-18da-7a80-8000-000000000002".to_string(),
            )
            .expect("valid Host Identity fixture"),
            target_id,
            state_root,
            "0.1.0",
            SSH_IDENTITY_ARCHIVE_SHA256,
            SSH_IDENTITY_BINARY_SHA256,
            exact_remote_path,
        )
        .expect("valid SSH identity operation record")
    }

    #[cfg(any(unix, windows))]
    fn posix_ssh_identity_record() -> SshIdentityCommitRecord {
        ssh_identity_record(
            "linux-x64-gnu",
            "/home/operator/.local/state/satelle",
            &format!(
                "/home/operator/.cache/satelle/bootstrap/{SSH_IDENTITY_OPERATION_ID}/{SSH_IDENTITY_BINARY_SHA256}/satelle"
            ),
        )
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ssh_identity_commit_record_v2_roundtrips_with_exact_field_order() {
        let record = posix_ssh_identity_record();
        let encoded = format!(
            concat!(
                "satelle.ssh-host-identity-commit.v2\n",
                "operation_id={0}\n",
                "candidate_host_identity=host-0195f6d5-18da-7a80-8000-000000000002\n",
                "target_id=linux-x64-gnu\n",
                "canonical_state_root=/home/operator/.local/state/satelle\n",
                "artifact_version=0.1.0\n",
                "archive_sha256={1}\n",
                "binary_sha256={2}\n",
                "exact_remote_path=/home/operator/.cache/satelle/bootstrap/",
                "{0}/{2}/satelle"
            ),
            SSH_IDENTITY_OPERATION_ID, SSH_IDENTITY_ARCHIVE_SHA256, SSH_IDENTITY_BINARY_SHA256,
        );

        assert_eq!(record.encode(), encoded);
        assert_eq!(
            SshIdentityCommitRecord::parse(&encoded).expect("parse exact v2 record"),
            record
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ssh_identity_commit_record_parser_rejects_schema_field_and_line_drift() {
        let encoded = posix_ssh_identity_record().encode();
        let lines = encoded.lines().collect::<Vec<_>>();
        let mut swapped = lines.clone();
        swapped.swap(2, 3);
        let missing = lines[..lines.len() - 1].join("\n");
        let duplicated = format!("{encoded}\n{}", lines[8]);

        for invalid in [
            encoded.replacen(
                "satelle.ssh-host-identity-commit.v2",
                "satelle.ssh-host-identity-commit.v1",
                1,
            ),
            swapped.join("\n"),
            missing,
            duplicated,
            format!("{encoded}\nunknown=value"),
            format!("{encoded}\n"),
        ] {
            assert!(
                SshIdentityCommitRecord::parse(&invalid).is_err(),
                "schema shape must fail closed: {invalid:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ssh_identity_commit_record_rejects_noncanonical_text_uuid_target_and_digests() {
        let encoded = posix_ssh_identity_record().encode();
        for invalid in [
            encoded.replace("artifact_version=0.1.0", "artifact_version=0.1.0\0"),
            encoded.replace("artifact_version=0.1.0", "artifact_version=0.1.0\r"),
            encoded.replace(
                "artifact_version=0.1.0",
                "artifact_version=0.1.0\ninjected=x",
            ),
            encoded.replace("artifact_version=0.1.0", "artifact_version=0.1.\u{e9}"),
            encoded.replace(
                SSH_IDENTITY_OPERATION_ID,
                "0195F6D5-18DA-7A80-8000-000000000001",
            ),
            encoded.replace(
                SSH_IDENTITY_OPERATION_ID,
                "0195f6d5-18da-4a80-8000-000000000001",
            ),
            encoded.replace("target_id=linux-x64-gnu", "target_id=linux-x64-musl"),
            encoded.replace(
                SSH_IDENTITY_ARCHIVE_SHA256,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            encoded.replace(SSH_IDENTITY_ARCHIVE_SHA256, &"1".repeat(63)),
            encoded.replace(
                SSH_IDENTITY_BINARY_SHA256,
                "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            ),
        ] {
            assert!(
                SshIdentityCommitRecord::parse(&invalid).is_err(),
                "noncanonical record text must fail closed: {invalid:?}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ssh_identity_commit_record_requires_exact_platform_operation_path() {
        let posix_path = format!(
            "/home/operator/.cache/satelle/bootstrap/{SSH_IDENTITY_OPERATION_ID}/{SSH_IDENTITY_BINARY_SHA256}/satelle"
        );
        let posix = ssh_identity_record(
            "darwin-arm64",
            "/Users/operator/.local/state/satelle",
            &posix_path,
        );
        assert_eq!(posix.exact_remote_path(), posix_path);

        let windows_path = format!(
            "C:\\Users\\operator\\AppData\\Local\\satelle\\bootstrap\\{SSH_IDENTITY_OPERATION_ID}\\{SSH_IDENTITY_BINARY_SHA256}\\satelle.exe"
        );
        let windows = ssh_identity_record("win32-x64-msvc", "C:\\Satelle\\state", &windows_path);
        assert_eq!(windows.exact_remote_path(), windows_path);

        for (target, state_root, invalid_path) in [
            (
                "linux-x64-gnu",
                "/home/operator/.local/state/satelle",
                format!(
                    "home/operator/.cache/satelle/bootstrap/{SSH_IDENTITY_OPERATION_ID}/{SSH_IDENTITY_BINARY_SHA256}/satelle"
                ),
            ),
            (
                "linux-x64-gnu",
                "/home/operator/.local/state/satelle",
                format!(
                    "/home/operator/.cache/satelle/bootstrap/0195f6d5-18da-7a80-8000-000000000099/{SSH_IDENTITY_BINARY_SHA256}/satelle"
                ),
            ),
            (
                "linux-x64-gnu",
                "/home/operator/.local/state/satelle",
                format!(
                    "/home/operator/.cache/satelle/bootstrap/{SSH_IDENTITY_OPERATION_ID}/{}/satelle",
                    "33".repeat(32)
                ),
            ),
            (
                "linux-x64-gnu",
                "/home/operator/.local/state/satelle",
                format!(
                    "/home/operator/.cache/satelle/bootstrap/{SSH_IDENTITY_OPERATION_ID}/{SSH_IDENTITY_BINARY_SHA256}/satelle.exe"
                ),
            ),
            (
                "win32-x64-msvc",
                "C:\\Satelle\\state",
                format!(
                    "C:Users\\operator\\AppData\\Local\\satelle\\bootstrap\\{SSH_IDENTITY_OPERATION_ID}\\{SSH_IDENTITY_BINARY_SHA256}\\satelle.exe"
                ),
            ),
            (
                "win32-x64-msvc",
                "C:\\Satelle\\state",
                format!(
                    "C:\\Users\\operator\\AppData\\Local\\satelle\\bootstrap\\{SSH_IDENTITY_OPERATION_ID}\\{SSH_IDENTITY_BINARY_SHA256}\\satelle"
                ),
            ),
        ] {
            assert!(
                SshIdentityCommitRecord::new(
                    SSH_IDENTITY_OPERATION_ID,
                    crate::session::HostIdentityRef::new(
                        "host-0195f6d5-18da-7a80-8000-000000000002".to_string(),
                    )
                    .expect("valid Host Identity fixture"),
                    target,
                    state_root,
                    "0.1.0",
                    SSH_IDENTITY_ARCHIVE_SHA256,
                    SSH_IDENTITY_BINARY_SHA256,
                    invalid_path,
                )
                .is_err(),
                "noncanonical platform path must fail closed"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn ssh_identity_commit_record_parser_enforces_maximum_encoded_size() {
        let mut oversized = posix_ssh_identity_record().encode();
        oversized.push_str(&"x".repeat(4_097 - oversized.len()));
        assert_eq!(oversized.len(), 4_097);
        assert!(SshIdentityCommitRecord::parse(&oversized).is_err());
    }

    #[cfg(unix)]
    fn secure_test_root(path: &Path) {
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("chmod")
                .arg("-N")
                .arg(path)
                .status()
                .expect("remove inherited macOS ACLs from the test root");
            assert!(status.success(), "macOS chmod must remove inherited ACLs");
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("make test root owner-only");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn owner_only_files_are_private_before_callers_write() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        #[cfg(unix)]
        secure_test_root(directory.path());
        let fresh = directory.path().join("fresh-owner-only");
        let mut file = open_or_create_owner_only_file(&fresh).expect("create owner-only file");
        file.write_all(b"fresh-secret")
            .expect("write newly private file");
        drop(file);
        assert_eq!(
            read_owner_only_secret_file(&fresh)
                .expect("read newly private file")
                .as_str(),
            "fresh-secret"
        );

        let existing = directory.path().join("existing-owner-only");
        let mut existing_file =
            open_or_create_owner_only_file(&existing).expect("create existing private file");
        existing_file
            .write_all(b"existing-secret")
            .expect("write existing private file");
        drop(existing_file);
        drop(open_or_create_owner_only_file(&existing).expect("reopen existing private file"));
        assert_eq!(
            read_owner_only_secret_file(&existing)
                .expect("read existing private file")
                .as_str(),
            "existing-secret"
        );

        #[cfg(unix)]
        {
            fs::set_permissions(&existing, fs::Permissions::from_mode(0o644))
                .expect("make existing file broadly readable");
            assert!(matches!(
                open_or_create_owner_only_file(&existing),
                Err(SecureFileError::UnsafeOrUnavailable)
            ));
        }

        let private_directory = directory.path().join("owner-only-directory");
        let _directory_guard = open_or_create_owner_only_directory(&private_directory)
            .expect("create owner-only directory");
        let nested = private_directory.join("nested-owner-only");
        let mut nested_file =
            open_or_create_owner_only_file(&nested).expect("create file in owner-only directory");
        nested_file
            .write_all(b"nested-secret")
            .expect("write nested owner-only file");
        drop(nested_file);
        assert_eq!(
            read_owner_only_secret_file(&nested)
                .expect("read nested owner-only file")
                .as_str(),
            "nested-secret"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_secret_values_preserve_utf8_and_strip_one_terminal_line_ending() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        #[cfg(unix)]
        secure_test_root(directory.path());

        for (name, stored, expected) in [
            ("lf", "  secret value  \n", "  secret value  "),
            ("crlf", "secret value\r\n", "secret value"),
            ("one-only", "secret value\r\n\n", "secret value\r\n"),
            ("unchanged", "\tsecret value\t", "\tsecret value\t"),
        ] {
            let path = directory.path().join(name);
            let mut file = open_or_create_owner_only_file(&path).expect("create owner-only secret");
            file.write_all(stored.as_bytes())
                .expect("write secret value");
            drop(file);

            assert_eq!(
                read_owner_only_secret_file(&path)
                    .expect("read owner-only secret")
                    .as_str(),
                expected,
                "unexpected normalization for {name}"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn file_secret_values_accept_64_kib_and_reject_nul_bytes() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        #[cfg(unix)]
        secure_test_root(directory.path());

        let maximum = directory.path().join("maximum-size");
        let mut maximum_file =
            open_or_create_owner_only_file(&maximum).expect("create maximum-size secret");
        let maximum_value = vec![b'x'; 64 * 1024];
        maximum_file
            .write_all(&maximum_value)
            .expect("write maximum-size secret");
        drop(maximum_file);
        assert_eq!(
            read_owner_only_secret_file(&maximum)
                .expect("64 KiB secret should be accepted")
                .len(),
            64 * 1024
        );

        let nul = directory.path().join("contains-nul");
        let mut nul_file = open_or_create_owner_only_file(&nul).expect("create NUL secret");
        nul_file
            .write_all(b"secret\0value")
            .expect("write NUL secret");
        drop(nul_file);
        assert_eq!(
            read_owner_only_secret_file(&nul),
            Err(SecureFileError::ContainsNul)
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn no_replace_publication_is_readable_at_the_crash_boundary() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        let directory_guard =
            open_or_create_owner_only_directory(&directory).expect("create owner-only directory");
        let staged = directory.join(".api-token.staged");
        let token = directory.join("api-token");
        let mut staged_file =
            open_or_create_owner_only_file(&staged).expect("create owner-only staging file");
        staged_file
            .write_all(b"crash-boundary-secret")
            .and_then(|()| staged_file.sync_all())
            .expect("sync staged secret");
        drop(staged_file);

        // Stop at the exact point where a process crash could occur: the
        // publication call has returned, but no caller cleanup or directory
        // sync has run. Atomic rename must already have consumed the staging
        // name and produced a single-link file accepted by the read policy.
        publish_new_file_without_replace(&staged, &token, &directory_guard)
            .expect("publish without replacing");

        assert!(!staged.exists());
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read token at publication boundary")
                .as_str(),
            "crash-boundary-secret"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn new_secret_persistence_is_owner_only_and_never_replaces() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let token = directory.join("api-token");

        persist_new_owner_only_secret_file(&token, "first-secret").expect("persist first secret");
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read persisted secret")
                .as_str(),
            "first-secret"
        );
        assert_eq!(
            persist_new_owner_only_secret_file(&token, "replacement-secret"),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read original after rejected replacement")
                .as_str(),
            "first-secret"
        );
        assert!(
            std::fs::read_dir(&directory)
                .expect("inspect token directory")
                .all(|entry| !entry
                    .expect("read token directory entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")),
            "atomic publication must consume or clean every staging name"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn journaled_secret_paths_are_deterministic_and_reject_unsafe_identifiers() {
        let destination = Path::new("/private/provider-token");
        let paths = OwnerOnlySecretFilePaths::new(destination, "019abc-operation_4")
            .expect("create deterministic journal paths");
        assert_eq!(paths.destination(), destination);
        assert_eq!(
            paths.staging(),
            Path::new("/private/provider-token.satelle-019abc-operation_4.staged")
        );
        assert_eq!(
            paths.backup(),
            Path::new("/private/provider-token.satelle-019abc-operation_4.backup")
        );
        assert!(OwnerOnlySecretFilePaths::new(destination, "../escape").is_err());
        assert!(OwnerOnlySecretFilePaths::new(destination, "raw secret").is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn keyed_secret_comparisons_are_not_raw_secret_hashes() {
        let first = keyed_secret_comparison_digest(b"installation-key-a", b"provider-secret")
            .expect("compute keyed digest");
        let second = keyed_secret_comparison_digest(b"installation-key-b", b"provider-secret")
            .expect("compute keyed digest");
        let raw: [u8; 32] = Sha256::digest(b"provider-secret").into();
        assert_ne!(first, second);
        assert_ne!(first, raw);
        assert!(keyed_secret_comparison_digest(b"", b"provider-secret").is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn journaled_secret_replacement_can_rollback_and_cleanup() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let destination = directory.join("provider-token");
        persist_new_owner_only_secret_file(&destination, "prior-secret")
            .expect("persist prior secret");
        let paths =
            OwnerOnlySecretFilePaths::new(&destination, "journal-1").expect("create journal paths");
        let candidate_key = b"candidate-comparison-key";
        let prior_key = b"prior-comparison-key";
        let candidate_digest = keyed_secret_comparison_digest(candidate_key, b"replacement-secret")
            .expect("compute replacement digest");
        let prior_digest = keyed_secret_comparison_digest(prior_key, b"prior-secret")
            .expect("compute prior digest");

        stage_owner_only_secret_file(
            &paths,
            "replacement-secret",
            candidate_key,
            &candidate_digest,
        )
        .expect("stage replacement");
        assert!(owner_only_secret_destination_exists(&destination).expect("preview destination"));
        assert!(
            publish_owner_only_secret_file(
                &paths,
                true,
                true,
                candidate_key,
                &candidate_digest,
                Some(prior_key),
                Some(&prior_digest),
            )
            .expect("publish replacement")
        );
        assert_eq!(
            read_owner_only_secret_file(&destination)
                .expect("read replacement")
                .as_str(),
            "replacement-secret"
        );
        assert!(paths.backup().exists());

        rollback_owner_only_secret_file(
            &paths,
            true,
            candidate_key,
            &candidate_digest,
            Some(prior_key),
            Some(&prior_digest),
        )
        .expect("restore prior secret");
        rollback_owner_only_secret_file(
            &paths,
            true,
            prior_key,
            &prior_digest,
            Some(prior_key),
            Some(&prior_digest),
        )
        .expect("repeat completed rollback");
        assert_eq!(
            read_owner_only_secret_file(&destination)
                .expect("read restored secret")
                .as_str(),
            "prior-secret"
        );
        cleanup_owner_only_secret_file(
            &paths,
            Some((candidate_key, &candidate_digest)),
            Some((prior_key, &prior_digest)),
        )
        .expect("remove journal artifacts");
        assert!(!paths.staging().exists());
        assert!(!paths.backup().exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn journaled_replacement_restores_a_rotation_observed_during_park() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let destination = directory.join("provider-token");
        persist_new_owner_only_secret_file(&destination, "prior-secret")
            .expect("persist prior secret");
        let paths = OwnerOnlySecretFilePaths::new(&destination, "journal-park-rotation")
            .expect("create journal paths");
        let candidate_key = b"candidate-comparison-key";
        let prior_key = b"prior-comparison-key";
        let candidate_digest = keyed_secret_comparison_digest(candidate_key, b"candidate-secret")
            .expect("compute candidate digest");
        let prior_digest = keyed_secret_comparison_digest(prior_key, b"prior-secret")
            .expect("compute prior digest");

        stage_owner_only_secret_file(&paths, "candidate-secret", candidate_key, &candidate_digest)
            .expect("stage candidate");
        std::fs::write(&destination, "rotated-secret").expect("rotate destination before park");

        assert!(matches!(
            publish_owner_only_secret_file(
                &paths,
                true,
                true,
                candidate_key,
                &candidate_digest,
                Some(prior_key),
                Some(&prior_digest),
            ),
            Err(SecureFileError::OverwriteRequired)
        ));
        assert_eq!(
            read_owner_only_secret_file(&destination)
                .expect("read restored rotation")
                .as_str(),
            "rotated-secret"
        );
        assert!(paths.staging().exists());
        assert!(!paths.backup().exists());
        cleanup_owner_only_secret_file(
            &paths,
            Some((candidate_key, &candidate_digest)),
            Some((prior_key, &prior_digest)),
        )
        .expect("discard candidate after rejected replacement");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn journaled_rollback_preserves_a_post_publish_rotation() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let destination = directory.join("provider-token");
        persist_new_owner_only_secret_file(&destination, "prior-secret")
            .expect("persist prior secret");
        let paths = OwnerOnlySecretFilePaths::new(&destination, "journal-post-publish-rotation")
            .expect("create journal paths");
        let candidate_key = b"candidate-comparison-key";
        let prior_key = b"prior-comparison-key";
        let candidate_digest = keyed_secret_comparison_digest(candidate_key, b"candidate-secret")
            .expect("compute candidate digest");
        let prior_digest = keyed_secret_comparison_digest(prior_key, b"prior-secret")
            .expect("compute prior digest");

        stage_owner_only_secret_file(&paths, "candidate-secret", candidate_key, &candidate_digest)
            .expect("stage candidate");
        assert!(
            publish_owner_only_secret_file(
                &paths,
                true,
                true,
                candidate_key,
                &candidate_digest,
                Some(prior_key),
                Some(&prior_digest),
            )
            .expect("publish candidate")
        );
        std::fs::write(&destination, "rotated-secret").expect("rotate published credential");

        rollback_owner_only_secret_file(
            &paths,
            true,
            candidate_key,
            &candidate_digest,
            Some(prior_key),
            Some(&prior_digest),
        )
        .expect("preserve post-publish rotation");
        assert_eq!(
            read_owner_only_secret_file(&destination)
                .expect("read preserved rotation")
                .as_str(),
            "rotated-secret"
        );
        assert!(!paths.staging().exists());
        assert!(!paths.backup().exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn journaled_new_secret_publish_is_atomic_and_idempotently_staged() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let destination = directory.join("provider-token");
        let paths =
            OwnerOnlySecretFilePaths::new(&destination, "journal-2").expect("create journal paths");
        let key = b"installation-comparison-key";
        let expected =
            keyed_secret_comparison_digest(key, b"new-secret").expect("compute secret digest");

        stage_owner_only_secret_file(&paths, "new-secret", key, &expected)
            .expect("stage new secret");
        stage_owner_only_secret_file(&paths, "new-secret", key, &expected)
            .expect("resume matching staged secret");
        assert!(
            !publish_owner_only_secret_file(&paths, false, false, key, &expected, None, None,)
                .expect("publish new secret")
        );
        assert_eq!(
            read_owner_only_secret_file(&destination)
                .expect("read new secret")
                .as_str(),
            "new-secret"
        );
        cleanup_owner_only_secret_file(&paths, Some((key, &expected)), None)
            .expect("cleanup completed operation");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn journaled_new_secret_publish_rejects_a_post_intent_overwrite_race() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        #[cfg(unix)]
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let destination = directory.join("provider-token");
        let paths = OwnerOnlySecretFilePaths::new(&destination, "journal-race")
            .expect("create journal paths");
        let key = b"installation-comparison-key";
        let expected =
            keyed_secret_comparison_digest(key, b"candidate").expect("compute candidate digest");
        stage_owner_only_secret_file(&paths, "candidate", key, &expected).expect("stage candidate");
        persist_new_owner_only_secret_file(&destination, "racing-prior")
            .expect("create destination after T0");

        assert_eq!(
            publish_owner_only_secret_file(&paths, false, true, key, &expected, None, None,),
            Err(SecureFileError::OverwriteRequired)
        );
        assert_eq!(
            read_owner_only_secret_file(&destination)
                .expect("read racing destination")
                .as_str(),
            "racing-prior"
        );
        cleanup_owner_only_secret_file(&paths, Some((key, &expected)), None)
            .expect("discard verified candidate");
    }

    #[cfg(unix)]
    #[test]
    fn journaled_staging_never_follows_a_preoccupied_symlink() {
        let temporary_root = tempfile::tempdir().expect("create temporary root");
        secure_test_root(temporary_root.path());
        let directory = temporary_root.path().join("owner-only");
        drop(open_or_create_owner_only_directory(&directory).expect("create owner-only directory"));
        let destination = directory.join("provider-token");
        let paths =
            OwnerOnlySecretFilePaths::new(&destination, "journal-3").expect("create journal paths");
        let victim = directory.join("victim");
        persist_new_owner_only_secret_file(&victim, "victim-secret").expect("create victim");
        std::os::unix::fs::symlink(&victim, paths.staging()).expect("preoccupy staging path");
        let key = b"installation-comparison-key";
        let expected =
            keyed_secret_comparison_digest(key, b"new-secret").expect("compute secret digest");

        assert_eq!(
            stage_owner_only_secret_file(&paths, "new-secret", key, &expected),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert_eq!(
            read_owner_only_secret_file(&victim)
                .expect("read untouched victim")
                .as_str(),
            "victim-secret"
        );
    }

    #[test]
    fn failed_published_secret_cleanup_is_distinct_and_removes_staging() {
        let root = tempfile::tempdir().expect("create temporary root");
        let staged = root.path().join("staged-secret");
        fs::write(&staged, b"pending-secret").expect("write staged secret");
        let published = root.path().join("published-secret");
        fs::create_dir(&published).expect("create unremovable file-shaped path");

        assert_eq!(
            cleanup_failed_new_secret(&staged, &published, true),
            Err(SecureFileError::PublishedCleanupFailed)
        );
        assert!(!staged.exists(), "staging cleanup remains best effort");
        assert!(
            published.is_dir(),
            "failed published cleanup remains visible"
        );
    }

    #[cfg(unix)]
    #[test]
    fn permissive_existing_directory_with_a_sidecar_is_rejected() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let history = directory.path().join("command-history");
        fs::create_dir(&history).expect("create permissive history directory");
        let sidecar = history.join("command-history.sqlite3-journal");
        fs::write(&sidecar, b"planted-sidecar").expect("plant SQLite sidecar");
        fs::set_permissions(&history, fs::Permissions::from_mode(0o770))
            .expect("make history directory group writable");

        assert!(matches!(
            open_or_create_owner_only_directory(&history),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert_eq!(
            fs::read(&sidecar).expect("read rejected sidecar"),
            b"planted-sidecar"
        );
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_directory_rejects_a_replaceable_ancestor() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let replaceable = directory.path().join("replaceable");
        fs::create_dir(&replaceable).expect("create replaceable ancestor");
        fs::set_permissions(&replaceable, fs::Permissions::from_mode(0o777))
            .expect("make ancestor replaceable by unrelated users");
        let boundary = replaceable.join("tls");

        assert!(matches!(
            open_or_create_owner_only_directory(&boundary),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert!(
            !boundary.exists(),
            "unsafe ancestry must fail before creation"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn existing_owner_only_directory_open_never_creates_a_missing_boundary() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        #[cfg(unix)]
        secure_test_root(directory.path());
        let boundary = directory.path().join("tls");

        assert!(matches!(
            open_owner_only_directory(&boundary),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert!(!boundary.exists(), "existing-only open must not create");

        drop(
            open_or_create_owner_only_directory(&boundary)
                .expect("create owner-only boundary explicitly"),
        );
        drop(open_owner_only_directory(&boundary).expect("reopen existing owner-only boundary"));
    }

    #[cfg(all(
        unix,
        any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "aix",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "illumos",
            target_os = "netbsd",
            target_os = "solaris"
        )
    ))]
    #[test]
    fn owner_only_directory_traverses_an_execute_only_ancestor() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let ancestor = directory.path().join("search-only");
        fs::create_dir(&ancestor).expect("create search-only ancestor");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("prepare writable ancestor");
        let boundary = ancestor.join("tls");
        drop(
            open_or_create_owner_only_directory(&boundary)
                .expect("create boundary before removing read permission"),
        );
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o100))
            .expect("make ancestor execute-only");

        let opened = open_owner_only_directory(&boundary);
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
            .expect("restore ancestor for fixture cleanup");
        drop(opened.expect("search-only handle traverses an execute-only ancestor"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owner_only_directory_accepts_the_root_owned_macos_tmp_alias() {
        let directory = tempfile::tempdir_in("/tmp").expect("create directory through /tmp alias");
        secure_test_root(directory.path());
        let boundary = directory.path().join("tls");

        drop(
            open_or_create_owner_only_directory(&boundary)
                .expect("root-owned macOS aliases preserve boundary security"),
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_restrictive_ancestor_acl_preserves_replacement_safety() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let add_status = std::process::Command::new("chmod")
            .arg("+a")
            .arg("everyone deny delete")
            .arg(directory.path())
            .status()
            .expect("add restrictive macOS ACL");
        assert!(add_status.success(), "macOS chmod must add the deny ACL");

        let boundary = directory.path().join("tls");
        let opened = open_or_create_owner_only_directory(&boundary);
        let remove_status = std::process::Command::new("chmod")
            .arg("-N")
            .arg(directory.path())
            .status()
            .expect("remove restrictive macOS ACL");
        assert!(
            remove_status.success(),
            "macOS chmod must remove the deny ACL"
        );

        drop(opened.expect("a deny-only ancestor ACL cannot enable replacement"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ancestor_acl_that_allows_replacement_is_rejected() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let add_status = std::process::Command::new("chmod")
            .arg("+a")
            .arg("everyone allow delete_child")
            .arg(directory.path())
            .status()
            .expect("add replacement-capable macOS ACL");
        assert!(add_status.success(), "macOS chmod must add the allow ACL");

        let boundary = directory.path().join("tls");
        let opened = open_or_create_owner_only_directory(&boundary);
        let remove_status = std::process::Command::new("chmod")
            .arg("-N")
            .arg(directory.path())
            .status()
            .expect("remove replacement-capable macOS ACL");
        assert!(
            remove_status.success(),
            "macOS chmod must remove the allow ACL"
        );

        assert!(matches!(opened, Err(SecureFileError::UnsafeOrUnavailable)));
        assert!(!boundary.exists(), "unsafe ACL must fail before creation");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_and_inherited_acls_are_rejected() {
        fn add_acl(path: &Path, entry: &str) {
            let status = std::process::Command::new("chmod")
                .arg("+a")
                .arg(entry)
                .arg(path)
                .status()
                .expect("run macOS chmod ACL command");
            assert!(status.success(), "macOS chmod must add the test ACL");
        }

        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let existing = directory.path().join("existing-owner-only");
        fs::write(&existing, b"existing-secret").expect("write existing private file");
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600))
            .expect("set owner-only mode");
        add_acl(&existing, "everyone allow read");
        assert!(matches!(
            open_or_create_owner_only_file(&existing),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert_eq!(
            read_owner_only_secret_config_file(&existing),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        let inheriting_parent = directory.path().join("inheriting-parent");
        fs::create_dir(&inheriting_parent).expect("create ACL inheritance parent");
        fs::set_permissions(&inheriting_parent, fs::Permissions::from_mode(0o700))
            .expect("set owner-only parent mode");
        add_acl(
            &inheriting_parent,
            "everyone allow read,file_inherit,directory_inherit",
        );
        let child = inheriting_parent.join("new-owner-only");
        assert!(matches!(
            open_or_create_owner_only_file(&child),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert!(
            !child.exists(),
            "ACL-bearing parents must be rejected before creation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_require_regular_owner_only_single_link_files() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let token = directory.path().join("satelle.token");
        fs::write(&token, "secret-value\n").expect("write token file");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("restrict token file");
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read private token")
                .as_str(),
            "secret-value"
        );

        fs::set_permissions(&token, fs::Permissions::from_mode(0o640))
            .expect("make token file unsafe");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("restore token permissions");
        let link = directory.path().join("token-link");
        symlink(&token, &link).expect("create token symlink");
        assert_eq!(
            read_owner_only_secret_file(&link),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        let private_key = directory.path().join("host-private-key.pem");
        let pem = "x".repeat(MAX_SECRET_FILE_BYTES + 1);
        fs::write(&private_key, &pem).expect("write larger private key fixture");
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
            .expect("restrict private key file");
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read larger owner-only secret configuration")
                .as_str(),
            pem
        );

        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o400))
            .expect("make private key owner-readable");
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read owner-private configuration without write access")
                .as_str(),
            pem
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_secret_paths_fail_without_blocking() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let fifo = directory.path().join("satelle.token");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success());
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600))
            .expect("restrict FIFO permissions");

        let started = std::time::Instant::now();
        assert_eq!(
            read_owner_only_secret_file(&fifo),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn owner_controlled_config_rejects_unrelated_write_access() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let config = directory.path().join("config.toml");
        fs::write(&config, "default_host = \"local-demo\"\n").expect("write config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))
            .expect("set normal user config permissions");
        assert!(read_owner_controlled_config_file(&config).is_ok());
        assert!(read_trusted_ca_bundle_file(&config).is_ok());

        fs::set_permissions(&config, fs::Permissions::from_mode(0o664))
            .expect("make config group-writable");
        assert_eq!(
            read_owner_controlled_config_file(&config),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_reads_are_bounded_and_require_utf8() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        secure_test_root(directory.path());
        let token = directory.path().join("satelle.token");
        fs::write(&token, vec![b'x'; MAX_SECRET_FILE_BYTES + 1]).expect("write large token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("restrict token file");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::TooLarge)
        );

        fs::write(&token, [0xff, 0xfe]).expect("write non-UTF-8 token");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::NotUtf8)
        );
    }

    #[test]
    fn bounded_user_file_reader_accepts_relative_regular_files_and_rejects_traversal() {
        let cwd = std::env::current_dir().expect("resolve test cwd");
        let directory = tempfile::tempdir_in(&cwd).expect("create cwd fixture directory");
        let absolute = directory.path().join("fixture.png");
        fs::write(&absolute, b"fixture").expect("write user-file fixture");
        let relative = absolute.strip_prefix(&cwd).expect("fixture is beneath cwd");

        assert_eq!(
            read_bounded_regular_file_no_follow(relative, 7),
            Ok(b"fixture".to_vec())
        );
        assert_eq!(
            read_bounded_regular_file_no_follow(relative, 6),
            Err(SecureFileError::TooLarge)
        );
        assert_eq!(
            read_bounded_regular_file_no_follow(Path::new("../fixture"), 7),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert_eq!(
            read_bounded_regular_file_no_follow(directory.path(), 7),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        #[cfg(unix)]
        {
            let link = directory.path().join("fixture-link.png");
            std::os::unix::fs::symlink(&absolute, &link).expect("create user-file symlink");
            assert_eq!(
                read_bounded_regular_file_no_follow(&link, 7),
                Err(SecureFileError::UnsafeOrUnavailable)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_secret_files_require_an_owner_only_acl_and_a_single_real_file() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let token = directory.path().join("satelle.token");
        fs::write(&token, "secret-value\n").expect("write token file");
        let user = current_windows_user_sid();
        set_windows_owner(&token, &user);
        set_windows_acl(&token, &[format!("*{user}:(F)")]);
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read private token")
                .as_str(),
            "secret-value"
        );

        set_windows_acl(&token, &[format!("*{user}:(R)")]);
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        set_windows_acl(&token, &[format!("*{user}:(F)")]);

        let private_key = directory.path().join("host-private-key.pem");
        let pem = "x".repeat(MAX_SECRET_FILE_BYTES + 1);
        fs::write(&private_key, &pem).expect("write larger private key fixture");
        set_windows_owner(&private_key, &user);
        set_windows_acl(&private_key, &[format!("*{user}:(R)")]);
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read owner-read-only private key")
                .as_str(),
            pem
        );
        set_windows_acl(&private_key, &[format!("*{user}:(M)")]);
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read owner-read-write private key")
                .as_str(),
            pem
        );

        add_windows_deny(&token, "*S-1-5-7:(R)");
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read token with an unrelated deny ACE")
                .as_str(),
            "secret-value"
        );

        set_windows_acl(
            &token,
            &[format!("*{user}:(F)"), "*S-1-1-0:(R)".to_string()],
        );
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        set_windows_acl(&token, &[format!("*{user}:(F)")]);
        let hard_link = directory.path().join("satelle-hard-link.token");
        fs::hard_link(&token, &hard_link).expect("create token hard link");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        fs::remove_file(hard_link).expect("remove token hard link");

        let symbolic_link = directory.path().join("satelle-symbolic-link.token");
        std::os::windows::fs::symlink_file(&token, &symbolic_link)
            .expect("create token symbolic link");
        assert_eq!(
            read_owner_only_secret_file(&symbolic_link),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_guard_rejects_junction_ancestry_and_pins_each_component() {
        let root = tempfile::tempdir().expect("create Windows directory guard fixture");
        let active = root.path().join("active");
        fs::create_dir(&active).expect("create active TLS ancestor");
        let boundary = active.join("tls");
        let guard = open_or_create_owner_only_directory(&boundary)
            .expect("open a regular owner-only TLS boundary");
        let retired = root.path().join("retired");
        assert!(
            fs::rename(&active, &retired).is_err(),
            "retained ancestor handles must block a namespace swap"
        );
        drop(guard);
        fs::rename(&active, &retired).expect("release every retained ancestor handle");

        let junction_target = root.path().join("junction-target");
        fs::create_dir(&junction_target).expect("create junction target");
        let target_boundary = junction_target.join("tls");
        drop(
            open_or_create_owner_only_directory(&target_boundary)
                .expect("create owner-only target boundary"),
        );
        let junction = root.path().join("junction");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&junction_target)
            .status()
            .expect("create Windows junction");
        assert!(status.success(), "mklink must create the test junction");

        assert!(matches!(
            open_owner_only_directory(&junction.join("tls")),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        fs::remove_dir(&junction).expect("remove test junction");
    }

    #[cfg(windows)]
    #[test]
    fn windows_owner_controlled_config_allows_only_trusted_writers() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let config = directory.path().join("config.toml");
        fs::write(&config, "default_host = \"local-demo\"\n").expect("write config");
        let user = current_windows_user_sid();
        set_windows_owner(&config, &user);
        let trusted_acl = [
            format!("*{user}:(F)"),
            "*S-1-5-18:(F)".to_string(),
            "*S-1-5-32-544:(F)".to_string(),
            "*S-1-1-0:(R)".to_string(),
        ];
        set_windows_acl(&config, &trusted_acl);
        assert!(read_owner_controlled_config_file(&config).is_ok());
        assert!(read_trusted_ca_bundle_file(&config).is_ok());

        set_windows_owner(&config, "S-1-5-32-544");
        assert_eq!(
            read_owner_controlled_config_file(&config),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert!(read_trusted_ca_bundle_file(&config).is_ok());
        set_windows_owner(&config, &user);

        let unsafe_acl = [
            format!("*{user}:(F)"),
            "*S-1-5-18:(F)".to_string(),
            "*S-1-5-32-544:(F)".to_string(),
            "*S-1-1-0:(M)".to_string(),
        ];
        set_windows_acl(&config, &unsafe_acl);
        assert_eq!(
            read_owner_controlled_config_file(&config),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
    }

    #[cfg(windows)]
    fn current_windows_user_sid() -> String {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ])
            .output()
            .expect("query current Windows user SID");
        assert!(output.status.success(), "PowerShell SID query failed");
        String::from_utf8(output.stdout)
            .expect("SID output should be UTF-8")
            .trim()
            .to_string()
    }

    #[cfg(windows)]
    fn set_windows_acl(path: &std::path::Path, entries: &[String]) {
        run_icacls(path, &["/inheritance:r"], "disable ACL inheritance");

        let mut principals = vec![
            "*S-1-5-18".to_string(),
            "*S-1-5-32-544".to_string(),
            "*S-1-1-0".to_string(),
        ];
        principals.extend(entries.iter().filter_map(|entry| {
            entry
                .split_once(":(")
                .map(|(principal, _)| principal.to_string())
        }));
        let mut remove_arguments = vec!["/remove:g".to_string()];
        remove_arguments.extend(principals);
        run_icacls(
            path,
            &remove_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "remove existing ACL grants",
        );

        let mut grant_arguments = vec!["/grant:r".to_string()];
        grant_arguments.extend(entries.iter().cloned());
        run_icacls(
            path,
            &grant_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "install requested ACL grants",
        );
    }

    #[cfg(windows)]
    fn run_icacls(path: &std::path::Path, arguments: &[&str], operation: &str) {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(arguments)
            .output()
            .expect(operation);
        assert!(
            output.status.success(),
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    fn set_windows_owner(path: &std::path::Path, sid: &str) {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/setowner", &format!("*{sid}")])
            .output()
            .expect("set Windows file owner");
        assert!(
            output.status.success(),
            "icacls owner update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    fn add_windows_deny(path: &std::path::Path, entry: &str) {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/deny", entry])
            .output()
            .expect("add Windows deny ACE");
        assert!(
            output.status.success(),
            "icacls deny update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
