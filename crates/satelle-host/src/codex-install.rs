use flate2::read::GzDecoder;
use reqwest::blocking::{Client, Response};
use satelle_core::{
    ErrorCode, SatelleError, SatellePathSet, open_new_owner_only_file,
    open_or_create_owner_only_directory, open_or_create_user_or_administrator_controlled_directory,
    open_owner_only_directory, open_user_or_administrator_controlled_directory,
    persist_new_owner_only_secret_file, read_owner_only_secret_config_file, resolve_path_set,
    sync_owner_only_directory,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const RECEIPT_FILE_NAME: &str = "codex-install-receipt.json";
const RECEIPT_SCHEMA: &str = "satelle.codex-install-receipt.v1";
const INSTALL_INTENT_FILE_NAME: &str = "codex-install-intent.json";
const INSTALL_INTENT_SCHEMA: &str = "satelle.codex-install-intent.v1";
const RECEIPT_MANAGER: &str = "satelle";
const BASELINE_CODEX_VERSION: &str = "0.144.0";
const BASELINE_CODEX_RELEASE_TAG: &str = "rust-v0.144.0";
const BASELINE_CHECKSUMS_SHA256: &str =
    "b651a02c474412bfc47707d3b12597f67ebaaf40665d81fe26a77488410302c1";
const MAX_CHECKSUMS_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
const SUPPORTED_TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "x86_64-pc-windows-msvc",
];

fn baseline_artifact_sha256(target: &str) -> Option<&'static str> {
    match target {
        "aarch64-apple-darwin" => {
            Some("4584a243ff8a671250bc716f89c5a50ed59917a98390acfdffa3ecb6cfe5bb34")
        }
        "x86_64-apple-darwin" => {
            Some("1056c80958863b13debd5daee5eb7b9bd6f86236a1171d21b009e2dceea8763e")
        }
        "aarch64-pc-windows-msvc" => {
            Some("a83d449d0a277af4ce1cf5fbb29376db707538266b993eab2560e3eaa42509eb")
        }
        "x86_64-pc-windows-msvc" => {
            Some("4046964ac24104bb79217077a86c96b20edae5a5f548a71442a164d3f9598a35")
        }
        _ => None,
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedCodexReceipt {
    schema: String,
    manager: String,
    version: String,
    target: String,
    release_tag: String,
    artifact_url: String,
    artifact_sha256: String,
    codex_home: PathBuf,
    immutable_package_root: PathBuf,
    immutable_binary_path: PathBuf,
    immutable_binary_sha256: String,
    installed_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedCodexInstallIntent {
    schema: String,
    version: String,
    target: String,
    transaction_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedCodexInstallOutcome {
    AlreadyInstalled,
    Installed,
}

impl ManagedCodexInstallOutcome {
    pub(crate) const fn changed(self) -> bool {
        matches!(self, Self::Installed)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CodexPackageManifest {
    layout_version: u32,
    version: String,
    target: String,
    variant: String,
    entrypoint: String,
    resources_dir: String,
    path_dir: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedCodexRuntime {
    binary_path: PathBuf,
    codex_home: PathBuf,
    package_root: PathBuf,
    binary_sha256: String,
}

impl VerifiedCodexRuntime {
    #[cfg(test)]
    pub(crate) fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    pub(crate) fn codex_home(&self) -> &Path {
        &self.codex_home
    }

    #[cfg(windows)]
    pub(crate) fn command(&self) -> Result<Command, SatelleError> {
        let [command] = self.commands()?;
        Ok(command)
    }

    /// Verifies the immutable runtime once immediately before constructing an
    /// atomic batch of child commands that belong to the same probe.
    pub(crate) fn commands<const COUNT: usize>(&self) -> Result<[Command; COUNT], SatelleError> {
        verify_runtime_identity(
            &self.codex_home,
            &self.package_root,
            &self.binary_path,
            &self.binary_sha256,
        )?;
        Ok(std::array::from_fn(|_| {
            let mut command = Command::new(&self.binary_path);
            command.env("CODEX_HOME", &self.codex_home);
            command
        }))
    }
}

pub(crate) fn admit_managed_codex(
    paths: &SatellePathSet,
) -> Result<VerifiedCodexRuntime, SatelleError> {
    admit_managed_codex_from_state_root(&paths.state_root)
}

pub(crate) fn admit_managed_codex_from_state_root(
    state_root: &Path,
) -> Result<VerifiedCodexRuntime, SatelleError> {
    admit_managed_codex_from_state_root_for_target(state_root, current_target()?)
}

pub(crate) fn admit_managed_codex_for_current_process() -> Result<VerifiedCodexRuntime, SatelleError>
{
    let current_directory =
        std::env::current_dir().map_err(|_| invalid_receipt("current_directory_unavailable"))?;
    let paths = resolve_path_set(&current_directory)?;
    admit_managed_codex(&paths)
}

fn managed_codex_home(user_home: Option<&Path>) -> Result<PathBuf, SatelleError> {
    user_home
        .map(|home| home.join(".codex"))
        .ok_or_else(|| install_error("prepare-codex-home", "current user home is unavailable"))
}

/// Acquires the independently attested baseline package and publishes its
/// receipt only after the immutable binary passes the live version probe.
/// An occupied but inadmissible receipt or package is never overwritten.
pub(crate) fn install_baseline_managed_codex(
    state_root: &Path,
) -> Result<ManagedCodexInstallOutcome, SatelleError> {
    let target = current_target()?;
    let receipt_path = state_root.join(RECEIPT_FILE_NAME);
    let intent_path = state_root.join(INSTALL_INTENT_FILE_NAME);
    match fs::symlink_metadata(&receipt_path) {
        Ok(_) => {
            admit_managed_codex_from_state_root_for_target(state_root, target)?;
            remove_install_intent(&intent_path, state_root);
            return Ok(ManagedCodexInstallOutcome::AlreadyInstalled);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(install_error("inspect-install-receipt", error)),
    }

    open_or_create_owner_only_directory(state_root)
        .map_err(|error| install_error("prepare-state-root", error))?;
    let canonical_state_root =
        fs::canonicalize(state_root).map_err(|error| install_error("prepare-state-root", error))?;
    let user_directories = directories::BaseDirs::new();
    let codex_home = managed_codex_home(
        user_directories
            .as_ref()
            .map(directories::BaseDirs::home_dir),
    )?;
    let packages_root = codex_home.join("packages");
    let standalone_root = packages_root.join("standalone");
    let releases_root = standalone_root.join("releases");
    // Keep the signed standalone package beside the current user's existing
    // authentication and provider state. The receipt still pins the exact
    // package and home used by every child process.
    open_or_create_user_or_administrator_controlled_directory(&codex_home)
        .map_err(|error| install_error("prepare-codex-home", error))?;
    for directory in [&packages_root, &standalone_root, &releases_root] {
        open_or_create_owner_only_directory(directory)
            .map_err(|error| install_error("prepare-package-root", error))?;
    }
    let package_root = releases_root.join(format!("{BASELINE_CODEX_VERSION}-{target}"));
    recover_interrupted_install(
        &intent_path,
        &canonical_state_root,
        &releases_root,
        &package_root,
        target,
    )?;
    match fs::symlink_metadata(&package_root) {
        Ok(_) => {
            return Err(install_error(
                "publish-codex-package",
                "the immutable package path is occupied without an admissible receipt",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(install_error("inspect-package-root", error)),
    }

    let artifact_name = format!("codex-package-{target}.tar.gz");
    let artifact_url = format!(
        "https://github.com/openai/codex/releases/download/{BASELINE_CODEX_RELEASE_TAG}/{artifact_name}"
    );
    let checksums_url = format!(
        "https://github.com/openai/codex/releases/download/{BASELINE_CODEX_RELEASE_TAG}/codex-package_SHA256SUMS"
    );
    let expected_artifact_sha256 = baseline_artifact_sha256(target)
        .ok_or_else(|| install_error("select-codex-package", "unsupported Host target"))?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(180))
        .user_agent(format!("satelle/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| install_error("prepare-download", error))?;
    let checksums = download_bounded(&client, &checksums_url, MAX_CHECKSUMS_BYTES)?;
    if sha256_bytes(&checksums) != BASELINE_CHECKSUMS_SHA256 {
        return Err(install_error(
            "verify-codex-checksums",
            "the official checksum manifest did not match Satelle's trust anchor",
        ));
    }
    let checksums_text = std::str::from_utf8(&checksums)
        .map_err(|error| install_error("verify-codex-checksums", error))?;
    let manifest_digest = checksum_for_artifact(checksums_text, &artifact_name)
        .ok_or_else(|| install_error("verify-codex-checksums", "package checksum is missing"))?;
    if !manifest_digest.eq_ignore_ascii_case(expected_artifact_sha256) {
        return Err(install_error(
            "verify-codex-checksums",
            "the package checksum disagrees with Satelle's trust anchor",
        ));
    }

    let artifact = download_bounded(&client, &artifact_url, MAX_ARTIFACT_BYTES)?;
    if sha256_bytes(&artifact) != expected_artifact_sha256 {
        return Err(install_error(
            "verify-codex-package",
            "the downloaded package digest is invalid",
        ));
    }

    let transaction_id = uuid::Uuid::now_v7();
    let staging_leaf = managed_codex_staging_leaf(target, transaction_id);
    let staging_root = releases_root.join(&staging_leaf);
    let intent_text = serde_json::to_string_pretty(&ManagedCodexInstallIntent {
        schema: INSTALL_INTENT_SCHEMA.to_string(),
        version: BASELINE_CODEX_VERSION.to_string(),
        target: target.to_string(),
        transaction_id: transaction_id.hyphenated().to_string(),
    })
    .map_err(|error| install_error("write-install-intent", error))?;
    persist_new_owner_only_secret_file(&intent_path, &intent_text)
        .map_err(|error| install_error("write-install-intent", error))?;
    if let Err(error) = open_or_create_owner_only_directory(&staging_root) {
        rollback_staged_install(&staging_root, &intent_path, &canonical_state_root);
        return Err(install_error("stage-codex-package", error));
    }
    let staged = extract_and_validate_package(&artifact, &staging_root, target);
    if let Err(error) = staged {
        rollback_staged_install(&staging_root, &intent_path, &canonical_state_root);
        return Err(error);
    }
    let receipt_text = (|| {
        let staged_binary_path = staging_root
            .join("bin")
            .join(binary_name_for_target(target));
        verify_installed_version(&staged_binary_path, &codex_home)?;
        let binary_sha256 = sha256_file(&staged_binary_path)
            .map_err(|error| install_error("verify-installed-codex", error))?;
        let canonical_codex_home = fs::canonicalize(&codex_home)
            .map_err(|error| install_error("verify-installed-codex", error))?;
        let canonical_releases_root = fs::canonicalize(&releases_root)
            .map_err(|error| install_error("verify-installed-codex", error))?;
        let canonical_package_root = canonical_releases_root.join(
            package_root
                .file_name()
                .expect("the versioned package path has one final component"),
        );
        let canonical_binary_path = canonical_package_root
            .join("bin")
            .join(binary_name_for_target(target));
        let installed_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| install_error("write-install-receipt", error))?;
        serde_json::to_string_pretty(&ManagedCodexReceipt {
            schema: RECEIPT_SCHEMA.to_string(),
            manager: RECEIPT_MANAGER.to_string(),
            version: BASELINE_CODEX_VERSION.to_string(),
            target: target.to_string(),
            release_tag: BASELINE_CODEX_RELEASE_TAG.to_string(),
            artifact_url,
            artifact_sha256: expected_artifact_sha256.to_string(),
            codex_home: canonical_codex_home,
            immutable_package_root: canonical_package_root,
            immutable_binary_path: canonical_binary_path,
            immutable_binary_sha256: binary_sha256,
            installed_at,
        })
        .map_err(|error| install_error("write-install-receipt", error))
    })();
    let receipt_text = match receipt_text {
        Ok(receipt_text) => receipt_text,
        Err(error) => {
            rollback_staged_install(&staging_root, &intent_path, &canonical_state_root);
            return Err(error);
        }
    };

    complete_published_install(
        &staging_root,
        &package_root,
        &receipt_path,
        &receipt_text,
        &canonical_state_root,
        &intent_path,
        target,
    )
}

fn recover_interrupted_install(
    intent_path: &Path,
    state_root: &Path,
    releases_root: &Path,
    package_root: &Path,
    target: &str,
) -> Result<(), SatelleError> {
    match fs::symlink_metadata(intent_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(install_error("read-install-intent", error)),
    }
    let intent_text = read_owner_only_secret_config_file(intent_path)
        .map_err(|error| install_error("read-install-intent", error))?;
    let intent: ManagedCodexInstallIntent = serde_json::from_str(&intent_text)
        .map_err(|error| install_error("validate-install-intent", error))?;
    let transaction_id = uuid::Uuid::parse_str(&intent.transaction_id)
        .map_err(|error| install_error("validate-install-intent", error))?;
    let expected_leaf = managed_codex_staging_leaf(target, transaction_id);
    if intent.schema != INSTALL_INTENT_SCHEMA
        || intent.version != BASELINE_CODEX_VERSION
        || intent.target != target
    {
        return Err(install_error(
            "validate-install-intent",
            "the interrupted install intent does not match this managed transaction",
        ));
    }

    remove_install_directory(&releases_root.join(expected_leaf))?;
    remove_install_directory(package_root)?;
    fs::remove_file(intent_path).map_err(|error| install_error("clear-install-intent", error))?;
    let directory = open_or_create_owner_only_directory(state_root)
        .map_err(|error| install_error("clear-install-intent", error))?;
    sync_owner_only_directory(state_root, &directory)
        .map_err(|error| install_error("clear-install-intent", error))
}

fn managed_codex_staging_leaf(target: &str, transaction_id: uuid::Uuid) -> String {
    format!(
        ".{BASELINE_CODEX_VERSION}-{target}.{}.tmp",
        transaction_id.hyphenated()
    )
}

fn remove_install_directory(path: &Path) -> Result<(), SatelleError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(|error| install_error("recover-install", error))
        }
        Ok(_) => Err(install_error(
            "recover-install",
            "the interrupted install path is not a regular directory",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(install_error("recover-install", error)),
    }
}

fn remove_install_intent(intent_path: &Path, state_root: &Path) {
    match fs::remove_file(intent_path) {
        Ok(()) => {
            if let Ok(directory) = open_or_create_owner_only_directory(state_root) {
                let _ = sync_owner_only_directory(state_root, &directory);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => tracing::debug!(
            ?error,
            "could not remove stale managed Codex install intent"
        ),
    }
}

fn rollback_staged_install(staging_root: &Path, intent_path: &Path, state_root: &Path) {
    if remove_install_directory(staging_root).is_ok() {
        remove_install_intent(intent_path, state_root);
    }
}

// Everything that can validate the package itself runs while it is still
// action-owned staging state. This narrow post-publish transaction either
// leaves both the immutable package and receipt admissible or removes the
// package so the exact same setup action can retry.
fn complete_published_install(
    staging_root: &Path,
    package_root: &Path,
    receipt_path: &Path,
    receipt_text: &str,
    canonical_state_root: &Path,
    intent_path: &Path,
    target: &str,
) -> Result<ManagedCodexInstallOutcome, SatelleError> {
    if let Err(error) = fs::rename(staging_root, package_root) {
        rollback_staged_install(staging_root, intent_path, canonical_state_root);
        return Err(install_error("publish-codex-package", error));
    }
    let releases_root = package_root
        .parent()
        .expect("the versioned package path has a releases parent");
    if let Err(error) = open_or_create_owner_only_directory(releases_root)
        .and_then(|directory| sync_owner_only_directory(releases_root, &directory))
    {
        return Err(rollback_published_install_and_clear_intent(
            package_root,
            None,
            install_error("publish-codex-package", error),
            intent_path,
            canonical_state_root,
        ));
    }
    if let Err(error) = persist_new_owner_only_secret_file(receipt_path, receipt_text) {
        return Err(rollback_published_install_and_clear_intent(
            package_root,
            None,
            install_error("write-install-receipt", error),
            intent_path,
            canonical_state_root,
        ));
    }
    if let Err(error) = admit_managed_codex_from_state_root_for_target(canonical_state_root, target)
    {
        return Err(rollback_published_install_and_clear_intent(
            package_root,
            Some(receipt_path),
            error,
            intent_path,
            canonical_state_root,
        ));
    }
    remove_install_intent(intent_path, canonical_state_root);
    Ok(ManagedCodexInstallOutcome::Installed)
}

fn rollback_published_install(
    package_root: &Path,
    published_receipt: Option<&Path>,
    mut error: SatelleError,
) -> SatelleError {
    let receipt_removed = published_receipt.is_none_or(|path| match fs::remove_file(path) {
        Ok(()) => true,
        Err(remove_error) if remove_error.kind() == io::ErrorKind::NotFound => true,
        Err(_) => false,
    });
    let package_removed = match fs::remove_dir_all(package_root) {
        Ok(()) => true,
        Err(remove_error) if remove_error.kind() == io::ErrorKind::NotFound => true,
        Err(_) => false,
    };
    let changed = !receipt_removed || !package_removed;
    error.details.insert("changed".to_string(), json!(changed));
    if changed {
        error.source_detail = Some(format!(
            "{}; failed to roll back the published managed Codex package",
            error.source_detail.as_deref().unwrap_or("setup failed")
        ));
    }
    error
}

fn rollback_published_install_and_clear_intent(
    package_root: &Path,
    published_receipt: Option<&Path>,
    error: SatelleError,
    intent_path: &Path,
    canonical_state_root: &Path,
) -> SatelleError {
    let error = rollback_published_install(package_root, published_receipt, error);
    if matches!(
        fs::symlink_metadata(package_root),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    ) {
        remove_install_intent(intent_path, canonical_state_root);
    }
    error
}

fn download_bounded(client: &Client, url: &str, limit: u64) -> Result<Vec<u8>, SatelleError> {
    let response = client
        .get(url)
        .send()
        .and_then(Response::error_for_status)
        .map_err(|error| install_error("download-codex-package", error))?;
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(install_error(
            "download-codex-package",
            "the download exceeds the accepted size limit",
        ));
    }
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| install_error("download-codex-package", error))?;
    if bytes.len() as u64 > limit {
        return Err(install_error(
            "download-codex-package",
            "the download exceeds the accepted size limit",
        ));
    }
    Ok(bytes)
}

fn checksum_for_artifact<'a>(contents: &'a str, artifact_name: &str) -> Option<&'a str> {
    contents.lines().find_map(|line| {
        let (digest, name) = line.split_once(char::is_whitespace)?;
        let name = name
            .trim_start()
            .strip_prefix('*')
            .unwrap_or(name.trim_start());
        (name == artifact_name && is_sha256(digest)).then_some(digest)
    })
}

fn extract_and_validate_package(
    artifact: &[u8],
    destination: &Path,
    expected_target: &str,
) -> Result<(), SatelleError> {
    drop(
        open_or_create_owner_only_directory(destination)
            .map_err(|error| install_error("extract-codex-package", error))?,
    );
    let decoder = GzDecoder::new(artifact);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| install_error("extract-codex-package", error))?;
    let mut extracted_paths = BTreeSet::new();
    let mut extracted_bytes = 0_u64;
    for entry in entries {
        let mut entry = entry.map_err(|error| install_error("extract-codex-package", error))?;
        let path = entry
            .path()
            .map_err(|error| install_error("extract-codex-package", error))?
            .into_owned();
        if !safe_archive_path(&path) {
            return Err(install_error(
                "extract-codex-package",
                "the package contains an unsafe path",
            ));
        }
        let path_key = path.to_string_lossy().replace('\\', "/");
        if !extracted_paths.insert(path_key) {
            return Err(install_error(
                "extract-codex-package",
                "the package contains a duplicate path",
            ));
        }
        let output_path = destination.join(&path);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            ensure_owner_only_archive_directories(destination, &path)?;
            continue;
        }
        if !entry_type.is_file() {
            return Err(install_error(
                "extract-codex-package",
                "the package contains a link or unsupported entry type",
            ));
        }
        extracted_bytes = extracted_bytes
            .checked_add(entry.size())
            .filter(|size| *size <= MAX_EXTRACTED_BYTES)
            .ok_or_else(|| {
                install_error(
                    "extract-codex-package",
                    "the extracted package exceeds the accepted size limit",
                )
            })?;
        if let Some(parent) = path.parent() {
            ensure_owner_only_archive_directories(destination, parent)?;
        }
        let mut output = open_new_owner_only_file(&output_path)
            .map_err(|error| install_error("extract-codex-package", error))?;
        #[cfg(unix)]
        let executable = entry
            .header()
            .mode()
            .map_err(|error| install_error("extract-codex-package", error))?
            & 0o111
            != 0;
        io::copy(&mut entry, &mut output)
            .map_err(|error| install_error("extract-codex-package", error))?;
        #[cfg(unix)]
        if executable {
            use std::os::unix::fs::PermissionsExt;
            output
                .set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(|error| install_error("extract-codex-package", error))?;
        }
        output
            .sync_all()
            .map_err(|error| install_error("extract-codex-package", error))?;
    }

    validate_package_manifest(destination, expected_target)
}

fn ensure_owner_only_archive_directories(
    destination: &Path,
    relative_path: &Path,
) -> Result<(), SatelleError> {
    let mut directory = destination.to_path_buf();
    for component in relative_path.components() {
        let Component::Normal(component) = component else {
            return Err(install_error(
                "extract-codex-package",
                "the package contains an unsafe directory path",
            ));
        };
        directory.push(component);
        drop(
            open_or_create_owner_only_directory(&directory)
                .map_err(|error| install_error("extract-codex-package", error))?,
        );
    }
    Ok(())
}

fn validate_package_manifest(
    package_root: &Path,
    expected_target: &str,
) -> Result<(), SatelleError> {
    let manifest_path = package_root.join("codex-package.json");
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|error| install_error("verify-codex-package", error))?;
    let manifest: CodexPackageManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| install_error("verify-codex-package", error))?;
    let expected_entrypoint = format!("bin/{}", binary_name_for_target(expected_target));
    if manifest.layout_version != 1
        || manifest.version != BASELINE_CODEX_VERSION
        || manifest.target != expected_target
        || manifest.variant != "codex"
        || manifest.entrypoint != expected_entrypoint
        || manifest.resources_dir != "codex-resources"
        || manifest.path_dir != "codex-path"
    {
        return Err(install_error(
            "verify-codex-package",
            "the package manifest does not match the selected Codex release",
        ));
    }
    let binary_path = package_root
        .join("bin")
        .join(binary_name_for_target(expected_target));
    let metadata = fs::symlink_metadata(&binary_path)
        .map_err(|error| install_error("verify-codex-package", error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(install_error(
            "verify-codex-package",
            "the package entrypoint is not a regular file",
        ));
    }
    Ok(())
}

fn safe_archive_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path.to_string_lossy().contains('\\')
}

fn verify_installed_version(binary_path: &Path, codex_home: &Path) -> Result<(), SatelleError> {
    let mut command = std::process::Command::new(binary_path);
    command.arg("--version").env("CODEX_HOME", codex_home);
    let expected_version = crate::codex_capabilities::CodexVersion::parse(BASELINE_CODEX_VERSION)
        .expect("the pinned baseline Codex version is valid");
    let evidence = crate::codex_capabilities::probe_codex_version_command(
        command,
        crate::codex_capabilities::VERSION_PROBE_TIMEOUT,
    );
    if !matches!(
        evidence,
        crate::codex_capabilities::CodexVersionEvidence::Detected { version }
            if version == expected_version
    ) {
        return Err(install_error(
            "verify-installed-codex",
            "the installed Codex binary did not report the expected version",
        ));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn install_error(action: &'static str, source: impl std::fmt::Display) -> SatelleError {
    SatelleError {
        code: ErrorCode::SetupActionFailed,
        message: format!("managed Codex setup action '{action}' failed"),
        recovery_command: None,
        source_detail: Some(source.to_string()),
        details: BTreeMap::from([
            ("failed_action".to_string(), json!(action)),
            ("changed".to_string(), json!(false)),
        ]),
    }
}

fn admit_managed_codex_from_state_root_for_target(
    state_root: &Path,
    expected_target: &str,
) -> Result<VerifiedCodexRuntime, SatelleError> {
    let receipt_path = state_root.join(RECEIPT_FILE_NAME);
    let receipt_text = read_owner_only_secret_config_file(&receipt_path)
        .map_err(|_| invalid_receipt("receipt_missing_or_not_owner_only"))?;
    let receipt: ManagedCodexReceipt = serde_json::from_str(receipt_text.as_str())
        .map_err(|_| invalid_receipt("receipt_schema_invalid"))?;

    validate_receipt_metadata(&receipt, expected_target)?;
    let codex_home = canonical_directory(&receipt.codex_home, "codex_home_invalid")?;
    let releases_root = canonical_directory(
        &codex_home
            .join("packages")
            .join("standalone")
            .join("releases"),
        "releases_root_invalid",
    )?;
    let package_root = canonical_directory(
        &receipt.immutable_package_root,
        "immutable_package_root_invalid",
    )?;
    let expected_package_root =
        releases_root.join(format!("{}-{}", receipt.version, receipt.target));
    if !same_path_identity(&package_root, &receipt.immutable_package_root)
        || !same_path_identity(&package_root, &expected_package_root)
        || has_mutable_component(&package_root)
    {
        return Err(invalid_receipt("immutable_package_root_invalid"));
    }
    verify_runtime_directories(&codex_home, &package_root)?;

    let expected_binary_path = package_root
        .join("bin")
        .join(binary_name_for_target(&receipt.target));
    if !same_path_identity(&receipt.immutable_binary_path, &expected_binary_path) {
        return Err(invalid_receipt("immutable_binary_path_invalid"));
    }
    let binary_path = verify_binary_identity(
        &receipt.immutable_binary_path,
        &package_root,
        &receipt.immutable_binary_sha256,
    )?;

    Ok(VerifiedCodexRuntime {
        binary_path,
        codex_home,
        package_root,
        binary_sha256: receipt.immutable_binary_sha256,
    })
}

fn validate_receipt_metadata(
    receipt: &ManagedCodexReceipt,
    expected_target: &str,
) -> Result<(), SatelleError> {
    let version = crate::codex_capabilities::CodexVersion::parse(&receipt.version)
        .filter(|version| crate::codex_capabilities::supports_codex_version(*version))
        .ok_or_else(|| invalid_receipt("receipt_metadata_invalid"))?;
    let expected_release_tag = format!("rust-v{version}");
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.manager != RECEIPT_MANAGER
        || receipt.release_tag != expected_release_tag
        || receipt.target != expected_target
        || !SUPPORTED_TARGETS.contains(&receipt.target.as_str())
        || !is_sha256(&receipt.artifact_sha256)
        || !is_sha256(&receipt.immutable_binary_sha256)
        || OffsetDateTime::parse(&receipt.installed_at, &Rfc3339).is_err()
    {
        return Err(invalid_receipt("receipt_metadata_invalid"));
    }
    let expected_url = format!(
        "https://github.com/openai/codex/releases/download/{}/codex-package-{}.tar.gz",
        receipt.release_tag, receipt.target
    );
    if receipt.artifact_url != expected_url {
        return Err(invalid_receipt("artifact_url_invalid"));
    }
    // Satelle ships the baseline digest as an independent trust anchor. A
    // newer receipt is an explicit Operator authorization for the exact
    // official release URL and immutable artifact digest it records. Runtime
    // admission then re-hashes the binary and runs the stable capability and
    // live-readiness gates before granting Computer Use authority.
    if receipt.version == BASELINE_CODEX_VERSION
        && baseline_artifact_sha256(&receipt.target) != Some(receipt.artifact_sha256.as_str())
    {
        return Err(invalid_receipt("artifact_digest_invalid"));
    }
    Ok(())
}

fn canonical_directory(path: &Path, reason: &'static str) -> Result<PathBuf, SatelleError> {
    if !path.is_absolute() {
        return Err(invalid_receipt(reason));
    }
    let canonical = fs::canonicalize(path).map_err(|_| invalid_receipt(reason))?;
    if !same_path_identity(&canonical, path)
        || !fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_dir())
    {
        return Err(invalid_receipt(reason));
    }
    Ok(canonical)
}

fn verify_binary_identity(
    receipt_path: &Path,
    package_root: &Path,
    expected_sha256: &str,
) -> Result<PathBuf, SatelleError> {
    let binary_path =
        fs::canonicalize(receipt_path).map_err(|_| invalid_receipt("immutable_binary_missing"))?;
    let binary_metadata =
        fs::metadata(&binary_path).map_err(|_| invalid_receipt("immutable_binary_missing"))?;
    if !same_path_identity(&binary_path, receipt_path)
        || !binary_metadata.is_file()
        || !binary_path.starts_with(package_root)
        || has_mutable_component(&binary_path)
    {
        return Err(invalid_receipt("immutable_binary_path_invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = binary_metadata.permissions().mode() & 0o777;
        if mode & 0o100 == 0 {
            return Err(invalid_receipt("immutable_binary_not_executable"));
        }
        if mode != 0o700 {
            return Err(invalid_receipt("immutable_binary_not_owner_only"));
        }
    }
    #[cfg(windows)]
    if binary_path
        .extension()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("exe"))
    {
        return Err(invalid_receipt("immutable_binary_not_executable"));
    }
    let binary_digest =
        sha256_file(&binary_path).map_err(|_| invalid_receipt("immutable_binary_unreadable"))?;
    if !binary_digest.eq_ignore_ascii_case(expected_sha256) {
        return Err(invalid_receipt("immutable_binary_digest_mismatch"));
    }
    Ok(binary_path)
}

fn verify_runtime_identity(
    codex_home: &Path,
    package_root: &Path,
    binary_path: &Path,
    expected_sha256: &str,
) -> Result<(), SatelleError> {
    verify_runtime_directories(codex_home, package_root)?;
    canonical_directory(codex_home, "codex_home_invalid")?;
    canonical_directory(package_root, "immutable_package_root_invalid")?;
    verify_binary_identity(binary_path, package_root, expected_sha256)?;
    Ok(())
}

fn verify_runtime_directories(codex_home: &Path, package_root: &Path) -> Result<(), SatelleError> {
    drop(
        open_user_or_administrator_controlled_directory(codex_home)
            .map_err(|_| invalid_receipt("codex_home_invalid"))?,
    );
    drop(
        open_owner_only_directory(package_root)
            .map_err(|_| invalid_receipt("immutable_package_root_invalid"))?,
    );
    Ok(())
}

fn binary_name_for_target(target: &str) -> &'static str {
    if target.ends_with("-pc-windows-msvc") {
        "codex.exe"
    } else {
        "codex"
    }
}

#[cfg(windows)]
fn same_path_identity(left: &Path, right: &Path) -> bool {
    normalize_windows_path(&left.to_string_lossy())
        .eq_ignore_ascii_case(&normalize_windows_path(&right.to_string_lossy()))
}

#[cfg(not(windows))]
fn same_path_identity(left: &Path, right: &Path) -> bool {
    left == right
}

#[cfg(any(windows, test))]
fn normalize_windows_path(value: &str) -> String {
    let normalized = value.replace('/', "\\");
    normalized
        .strip_prefix(r"\\?\UNC\")
        .map(|path| format!(r"\\{path}"))
        .or_else(|| normalized.strip_prefix(r"\\?\").map(str::to_string))
        .unwrap_or(normalized)
        .trim_end_matches('\\')
        .to_string()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("aarch64-apple-darwin")
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("x86_64-apple-darwin")
}

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("aarch64-pc-windows-msvc")
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn current_target() -> Result<&'static str, SatelleError> {
    Ok("x86_64-pc-windows-msvc")
}

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "aarch64"),
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn current_target() -> Result<&'static str, SatelleError> {
    Err(invalid_receipt("unsupported_host_target"))
}

fn has_mutable_component(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, Component::Normal(value) if value.eq_ignore_ascii_case("current"))
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn invalid_receipt(reason: &'static str) -> SatelleError {
    SatelleError {
        code: ErrorCode::StorageIntegrityFailed,
        message: "the managed Codex installation receipt is missing, unsafe, or inconsistent"
            .to_string(),
        recovery_command: None,
        source_detail: None,
        details: BTreeMap::from([("reason".to_string(), json!(reason))]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use satelle_core::open_or_create_owner_only_file;
    use serde_json::{Map, Value};
    use std::io::{Cursor, Write};
    use tempfile::TempDir;

    #[cfg(windows)]
    const BINARY_NAME: &str = "codex.exe";
    #[cfg(not(windows))]
    const BINARY_NAME: &str = "codex";

    #[cfg(windows)]
    const FIXTURE_TARGET: &str = "x86_64-pc-windows-msvc";
    #[cfg(not(windows))]
    const FIXTURE_TARGET: &str = "x86_64-apple-darwin";

    #[cfg(windows)]
    const FIXTURE_OTHER_TARGET: &str = "aarch64-pc-windows-msvc";
    #[cfg(not(windows))]
    const FIXTURE_OTHER_TARGET: &str = "aarch64-apple-darwin";

    #[cfg(windows)]
    const FIXTURE_ARTIFACT_SHA256: &str =
        "4046964ac24104bb79217077a86c96b20edae5a5f548a71442a164d3f9598a35";
    #[cfg(not(windows))]
    const FIXTURE_ARTIFACT_SHA256: &str =
        "1056c80958863b13debd5daee5eb7b9bd6f86236a1171d21b009e2dceea8763e";

    struct ReceiptFixture {
        _root: TempDir,
        state_root: PathBuf,
        codex_home: PathBuf,
        package_root: PathBuf,
        binary_path: PathBuf,
        receipt_path: PathBuf,
        receipt: Value,
    }

    fn package_artifact(manifest_target: &str, link_entrypoint: bool) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let manifest = json!({
            "layoutVersion": 1,
            "version": BASELINE_CODEX_VERSION,
            "target": manifest_target,
            "variant": "codex",
            "entrypoint": format!("bin/{BINARY_NAME}"),
            "resourcesDir": "codex-resources",
            "pathDir": "codex-path",
        })
        .to_string();
        let mut manifest_header = tar::Header::new_gnu();
        manifest_header.set_size(manifest.len() as u64);
        manifest_header.set_mode(0o600);
        manifest_header.set_cksum();
        archive
            .append_data(
                &mut manifest_header,
                "codex-package.json",
                Cursor::new(manifest),
            )
            .expect("append package manifest");

        let mut resources_header = tar::Header::new_gnu();
        resources_header.set_entry_type(tar::EntryType::Directory);
        resources_header.set_size(0);
        resources_header.set_mode(0o777);
        resources_header.set_cksum();
        archive
            .append_data(
                &mut resources_header,
                "codex-resources",
                Cursor::new(Vec::<u8>::new()),
            )
            .expect("append resource directory");

        let resource = b"fixture resource";
        let mut resource_header = tar::Header::new_gnu();
        resource_header.set_size(resource.len() as u64);
        resource_header.set_mode(0o666);
        resource_header.set_cksum();
        archive
            .append_data(
                &mut resource_header,
                "codex-resources/fixture.txt",
                Cursor::new(resource),
            )
            .expect("append package resource");

        let helper = b"fixture helper";
        let mut helper_header = tar::Header::new_gnu();
        helper_header.set_size(helper.len() as u64);
        helper_header.set_mode(0o755);
        helper_header.set_cksum();
        archive
            .append_data(
                &mut helper_header,
                "codex-path/nested/rg",
                Cursor::new(helper),
            )
            .expect("append package helper");

        let mut binary_header = tar::Header::new_gnu();
        if link_entrypoint {
            binary_header.set_entry_type(tar::EntryType::Symlink);
            binary_header.set_size(0);
            binary_header.set_mode(0o700);
            binary_header
                .set_link_name("outside")
                .expect("set link target");
            binary_header.set_cksum();
            archive
                .append_data(
                    &mut binary_header,
                    format!("bin/{BINARY_NAME}"),
                    Cursor::new(Vec::<u8>::new()),
                )
                .expect("append linked entrypoint");
        } else {
            let binary = b"fixture Codex binary";
            binary_header.set_size(binary.len() as u64);
            binary_header.set_mode(0o700);
            binary_header.set_cksum();
            archive
                .append_data(
                    &mut binary_header,
                    format!("bin/{BINARY_NAME}"),
                    Cursor::new(binary),
                )
                .expect("append package entrypoint");
        }
        archive.finish().expect("finish package archive");
        archive
            .into_inner()
            .expect("recover encoder")
            .finish()
            .expect("finish gzip stream")
    }

    /// Test roots must satisfy the owner-only ancestor policy regardless of
    /// the process umask; a group-writable temporary parent is rejected.
    fn owner_only_tempdir(purpose: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect(purpose);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect(purpose);
        }
        root
    }

    impl ReceiptFixture {
        fn new() -> Self {
            let root = owner_only_tempdir("temporary receipt root");
            let canonical_root =
                fs::canonicalize(root.path()).expect("canonical temporary receipt root");
            let state_root = canonical_root.join("state");
            let codex_home = canonical_root.join("codex-home");
            let packages_root = codex_home.join("packages");
            let standalone_root = packages_root.join("standalone");
            let releases_root = standalone_root.join("releases");
            for directory in [
                &state_root,
                &codex_home,
                &packages_root,
                &standalone_root,
                &releases_root,
            ] {
                open_or_create_owner_only_directory(directory)
                    .expect("create secure managed Codex directory");
            }
            let package_root =
                releases_root.join(format!("{BASELINE_CODEX_VERSION}-{FIXTURE_TARGET}"));
            let binary_path = package_root.join("bin").join(BINARY_NAME);
            open_or_create_owner_only_directory(&package_root)
                .expect("create secure fixture package root");
            fs::create_dir_all(binary_path.parent().expect("binary parent"))
                .expect("create package");
            fs::write(&binary_path, b"verified standalone codex binary").expect("write binary");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&binary_path, fs::Permissions::from_mode(0o700))
                    .expect("make binary executable");
            }
            let binary_sha256 = sha256_file(&binary_path).expect("binary digest");
            let receipt = json!({
                "schema": RECEIPT_SCHEMA,
                "manager": RECEIPT_MANAGER,
                "version": BASELINE_CODEX_VERSION,
                "target": FIXTURE_TARGET,
                "release_tag": BASELINE_CODEX_RELEASE_TAG,
                "artifact_url": format!(
                    "https://github.com/openai/codex/releases/download/{BASELINE_CODEX_RELEASE_TAG}/codex-package-{FIXTURE_TARGET}.tar.gz"
                ),
                "artifact_sha256": FIXTURE_ARTIFACT_SHA256,
                "codex_home": codex_home,
                "immutable_package_root": package_root,
                "immutable_binary_path": binary_path,
                "immutable_binary_sha256": binary_sha256,
                "installed_at": "2026-07-22T00:00:00Z",
            });
            let receipt_path = state_root.join(RECEIPT_FILE_NAME);
            let mut fixture = Self {
                _root: root,
                state_root,
                codex_home,
                package_root,
                binary_path,
                receipt_path,
                receipt,
            };
            fixture.write_receipt();
            fixture
        }

        fn receipt_object_mut(&mut self) -> &mut Map<String, Value> {
            self.receipt.as_object_mut().expect("receipt object")
        }

        fn write_receipt(&mut self) {
            let bytes = serde_json::to_vec_pretty(&self.receipt).expect("serialize receipt");
            let mut file = open_or_create_owner_only_file(&self.receipt_path)
                .expect("open owner-only receipt");
            file.set_len(0).expect("truncate receipt");
            file.write_all(&bytes).expect("write receipt");
        }

        fn restore_published_install(&mut self) {
            open_or_create_owner_only_directory(&self.package_root)
                .expect("restore secure fixture package root");
            fs::create_dir_all(self.binary_path.parent().expect("binary parent"))
                .expect("restore package");
            fs::write(&self.binary_path, b"verified standalone codex binary")
                .expect("restore binary");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.binary_path, fs::Permissions::from_mode(0o700))
                    .expect("restore executable mode");
            }
            self.write_receipt();
        }
    }

    #[test]
    fn post_publish_failure_removes_the_slot_and_allows_an_exact_rerun() {
        let mut fixture = ReceiptFixture::new();
        let staging_root = fixture.state_root.join("staged-package");
        fs::remove_file(&fixture.receipt_path).expect("remove initial receipt");
        fs::rename(&fixture.package_root, &staging_root).expect("restore staged package");
        let receipt_text = serde_json::to_string_pretty(&fixture.receipt).expect("receipt text");
        let unwritable_receipt = fixture
            .state_root
            .join("missing-parent")
            .join("receipt.json");
        let intent_path = fixture.state_root.join(INSTALL_INTENT_FILE_NAME);

        let error = complete_published_install(
            &staging_root,
            &fixture.package_root,
            &unwritable_receipt,
            &receipt_text,
            &fixture.state_root,
            &intent_path,
            FIXTURE_TARGET,
        )
        .expect_err("receipt persistence must fail after package publication");
        assert_eq!(error.details["changed"], false);
        assert!(!fixture.package_root.exists());
        assert!(!fixture.receipt_path.exists());

        fixture.restore_published_install();
        fs::remove_file(&fixture.receipt_path).expect("remove restored receipt");
        fs::rename(&fixture.package_root, &staging_root).expect("stage exact retry");
        assert_eq!(
            complete_published_install(
                &staging_root,
                &fixture.package_root,
                &fixture.receipt_path,
                &receipt_text,
                &fixture.state_root,
                &intent_path,
                FIXTURE_TARGET,
            )
            .expect("the exact package can be published and admitted after rollback"),
            ManagedCodexInstallOutcome::Installed
        );
    }

    #[test]
    fn exact_install_intent_recovers_an_interrupted_published_package() {
        let fixture = ReceiptFixture::new();
        fs::remove_file(&fixture.receipt_path).expect("remove receipt");
        let releases_root = fixture.package_root.parent().expect("releases root");
        let transaction_id = uuid::Uuid::now_v7();
        let intent_path = fixture.state_root.join(INSTALL_INTENT_FILE_NAME);
        let intent = serde_json::to_string_pretty(&ManagedCodexInstallIntent {
            schema: INSTALL_INTENT_SCHEMA.to_string(),
            version: BASELINE_CODEX_VERSION.to_string(),
            target: FIXTURE_TARGET.to_string(),
            transaction_id: transaction_id.hyphenated().to_string(),
        })
        .expect("serialize intent");
        persist_new_owner_only_secret_file(&intent_path, &intent).expect("persist intent");
        let staging_root =
            releases_root.join(managed_codex_staging_leaf(FIXTURE_TARGET, transaction_id));
        fs::create_dir(&staging_root).expect("create interrupted staging directory");
        fs::write(staging_root.join("partial-package"), b"partial package")
            .expect("write interrupted staging content");

        recover_interrupted_install(
            &intent_path,
            &fixture.state_root,
            releases_root,
            &fixture.package_root,
            FIXTURE_TARGET,
        )
        .expect("recover exact interrupted install");
        assert!(!staging_root.exists());
        assert!(!fixture.package_root.exists());
        assert!(!intent_path.exists());
        recover_interrupted_install(
            &intent_path,
            &fixture.state_root,
            releases_root,
            &fixture.package_root,
            FIXTURE_TARGET,
        )
        .expect("recovery is idempotent");
    }

    #[test]
    fn invalid_install_intent_never_authorizes_package_removal() {
        let fixture = ReceiptFixture::new();
        fs::remove_file(&fixture.receipt_path).expect("remove receipt");
        let intent_path = fixture.state_root.join(INSTALL_INTENT_FILE_NAME);
        let intent = serde_json::json!({
            "schema": INSTALL_INTENT_SCHEMA,
            "version": BASELINE_CODEX_VERSION,
            "target": FIXTURE_OTHER_TARGET,
            "transaction_id": uuid::Uuid::now_v7().hyphenated().to_string(),
        });
        persist_new_owner_only_secret_file(&intent_path, &intent.to_string())
            .expect("persist invalid intent");

        assert!(
            recover_interrupted_install(
                &intent_path,
                &fixture.state_root,
                fixture.package_root.parent().expect("releases root"),
                &fixture.package_root,
                FIXTURE_TARGET,
            )
            .is_err()
        );
        assert!(fixture.package_root.exists());
        assert!(intent_path.exists());
    }

    #[test]
    fn managed_install_errors_defer_the_exact_target_recovery_to_the_controller() {
        assert_eq!(install_error("fixture", "failure").recovery_command, None);
    }

    #[test]
    fn managed_install_uses_the_current_users_existing_codex_home() {
        assert_eq!(
            managed_codex_home(Some(Path::new("/Users/operator")))
                .expect("resolve the current user's Codex home"),
            Path::new("/Users/operator/.codex")
        );

        let error = managed_codex_home(None)
            .expect_err("setup cannot authenticate without a current user home");
        assert_eq!(error.details["failed_action"], "prepare-codex-home");
    }

    #[test]
    fn official_checksum_parser_requires_the_exact_artifact_name() {
        let contents = format!(
            "{FIXTURE_ARTIFACT_SHA256}  codex-package-{FIXTURE_TARGET}.tar.gz\n{}  another.tar.gz\n",
            "11".repeat(32)
        );
        assert_eq!(
            checksum_for_artifact(&contents, &format!("codex-package-{FIXTURE_TARGET}.tar.gz")),
            Some(FIXTURE_ARTIFACT_SHA256)
        );
        assert_eq!(
            checksum_for_artifact(&contents, "codex-package.tar.gz"),
            None
        );
    }

    #[test]
    fn package_extraction_accepts_the_exact_manifest_and_regular_entrypoint() {
        let root = owner_only_tempdir("temporary package root");
        let destination = root.path().join("staging");
        extract_and_validate_package(
            &package_artifact(FIXTURE_TARGET, false),
            &destination,
            FIXTURE_TARGET,
        )
        .expect("extract exact package");
        drop(open_owner_only_directory(&destination).expect("owner-only package root"));
        for directory in [
            destination.join("bin"),
            destination.join("codex-resources"),
            destination.join("codex-path"),
            destination.join("codex-path/nested"),
        ] {
            drop(open_owner_only_directory(&directory).expect("owner-only archive directory"));
        }
        assert!(destination.join("codex-package.json").is_file());
        assert!(destination.join("bin").join(BINARY_NAME).is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for executable in [
                destination.join("bin").join(BINARY_NAME),
                destination.join("codex-path/nested/rg"),
            ] {
                assert_eq!(
                    fs::metadata(executable)
                        .expect("executable metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
            for regular in [
                destination.join("codex-package.json"),
                destination.join("codex-resources/fixture.txt"),
            ] {
                assert_eq!(
                    fs::metadata(regular)
                        .expect("regular file metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn admission_rejects_package_or_binary_permission_drift() {
        use std::os::unix::fs::PermissionsExt;

        let package_drift = ReceiptFixture::new();
        fs::set_permissions(
            &package_drift.package_root,
            fs::Permissions::from_mode(0o755),
        )
        .expect("make package root unsafe");
        assert!(
            admit_managed_codex_from_state_root_for_target(
                &package_drift.state_root,
                FIXTURE_TARGET,
            )
            .is_err()
        );

        let binary_drift = ReceiptFixture::new();
        fs::set_permissions(&binary_drift.binary_path, fs::Permissions::from_mode(0o755))
            .expect("make binary permissions noncanonical");
        let owner_only_error = admit_managed_codex_from_state_root_for_target(
            &binary_drift.state_root,
            FIXTURE_TARGET,
        );
        assert_eq!(
            owner_only_error
                .expect_err("reject group-readable executable")
                .details["reason"],
            json!("immutable_binary_not_owner_only")
        );

        let non_executable = ReceiptFixture::new();
        fs::set_permissions(
            &non_executable.binary_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("remove binary execute permission");
        let executable_error = admit_managed_codex_from_state_root_for_target(
            &non_executable.state_root,
            FIXTURE_TARGET,
        );
        assert_eq!(
            executable_error
                .expect_err("reject non-executable binary")
                .details["reason"],
            json!("immutable_binary_not_executable")
        );
    }

    #[test]
    fn package_extraction_rejects_a_linked_entrypoint_and_wrong_target() {
        let linked_root = owner_only_tempdir("temporary linked package root");
        let linked = extract_and_validate_package(
            &package_artifact(FIXTURE_TARGET, true),
            linked_root.path(),
            FIXTURE_TARGET,
        )
        .expect_err("reject linked entrypoint");
        assert_eq!(linked.code, ErrorCode::SetupActionFailed);

        let wrong_target_root = owner_only_tempdir("temporary wrong-target root");
        extract_and_validate_package(
            &package_artifact(FIXTURE_OTHER_TARGET, false),
            wrong_target_root.path(),
            FIXTURE_TARGET,
        )
        .expect_err("reject wrong manifest target");
    }

    #[test]
    fn verified_receipt_returns_exact_immutable_binary_and_codex_home() {
        let fixture = ReceiptFixture::new();
        let runtime =
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .expect("admit managed Codex");
        assert_eq!(runtime.binary_path(), fixture.binary_path);
        assert_eq!(runtime.codex_home(), fixture.codex_home);
        let [command] = runtime.commands::<1>().expect("verified command");
        assert_eq!(command.get_program(), fixture.binary_path);
        assert!(command.get_envs().any(|(key, value)| {
            key == "CODEX_HOME" && value == Some(fixture.codex_home.as_os_str())
        }));
        let commands = runtime.commands::<3>().expect("verified command batch");
        assert!(commands.iter().all(|command| {
            command.get_program() == fixture.binary_path
                && command.get_envs().any(|(key, value)| {
                    key == "CODEX_HOME" && value == Some(fixture.codex_home.as_os_str())
                })
        }));
    }

    #[test]
    fn receipt_admission_rejects_missing_or_non_owner_only_receipt() {
        let mut fixture = ReceiptFixture::new();
        fs::remove_file(&fixture.receipt_path).expect("remove receipt");
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
        fixture.write_receipt();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fixture.receipt_path, fs::Permissions::from_mode(0o644))
                .expect("make receipt unsafe");
            assert!(
                admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                    .is_err()
            );
        }
    }

    #[test]
    fn receipt_admission_rejects_wrong_schema_manager_version_target_or_release() {
        for field in ["schema", "manager", "version", "target", "release_tag"] {
            let mut fixture = ReceiptFixture::new();
            fixture
                .receipt_object_mut()
                .insert(field.to_string(), json!("wrong"));
            fixture.write_receipt();
            assert!(
                admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                    .is_err(),
                "accepted wrong {field}"
            );
        }
    }

    #[test]
    fn receipt_admission_accepts_newer_official_release_metadata() {
        let mut fixture = ReceiptFixture::new();
        let version = "0.145.0";
        let release_tag = "rust-v0.145.0";
        let package_root = fixture
            .codex_home
            .join("packages")
            .join("standalone")
            .join("releases")
            .join(format!("{version}-{FIXTURE_TARGET}"));
        let binary_path = package_root.join("bin").join(BINARY_NAME);
        open_or_create_owner_only_directory(&package_root)
            .expect("create secure newer package root");
        fs::create_dir_all(binary_path.parent().expect("binary parent"))
            .expect("create newer package");
        fs::copy(&fixture.binary_path, &binary_path).expect("copy newer binary");
        fixture
            .receipt_object_mut()
            .insert("version".to_string(), json!(version));
        fixture
            .receipt_object_mut()
            .insert("release_tag".to_string(), json!(release_tag));
        fixture.receipt_object_mut().insert(
            "artifact_url".to_string(),
            json!(format!(
                "https://github.com/openai/codex/releases/download/{release_tag}/codex-package-{FIXTURE_TARGET}.tar.gz"
            )),
        );
        fixture
            .receipt_object_mut()
            .insert("immutable_package_root".to_string(), json!(package_root));
        fixture
            .receipt_object_mut()
            .insert("immutable_binary_path".to_string(), json!(binary_path));
        fixture.write_receipt();

        admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
            .expect("admit newer compatible Codex release");
    }

    #[test]
    fn receipt_admission_rejects_a_release_below_the_supported_floor() {
        let mut fixture = ReceiptFixture::new();
        fixture
            .receipt_object_mut()
            .insert("version".to_string(), json!("0.143.9"));
        fixture
            .receipt_object_mut()
            .insert("release_tag".to_string(), json!("rust-v0.143.9"));
        fixture.receipt_object_mut().insert(
            "artifact_url".to_string(),
            json!(format!(
                "https://github.com/openai/codex/releases/download/rust-v0.143.9/codex-package-{FIXTURE_TARGET}.tar.gz"
            )),
        );
        fixture.write_receipt();

        admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
            .expect_err("reject Codex below the supported floor");
    }

    #[cfg(unix)]
    #[test]
    fn receipt_admission_rejects_mutable_package_or_binary_paths() {
        use std::os::unix::fs::symlink;

        let mut fixture = ReceiptFixture::new();
        let current = fixture
            .codex_home
            .join("packages")
            .join("standalone")
            .join("current");
        symlink(&fixture.package_root, &current).expect("create mutable alias");
        fixture
            .receipt_object_mut()
            .insert("immutable_package_root".to_string(), json!(current));
        fixture.write_receipt();
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
    }

    #[test]
    fn receipt_admission_rejects_binary_digest_drift() {
        let fixture = ReceiptFixture::new();
        fs::write(&fixture.binary_path, b"drifted binary").expect("replace binary bytes");
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
    }

    #[test]
    fn admitted_runtime_rechecks_binary_before_every_child_command() {
        let fixture = ReceiptFixture::new();
        let runtime =
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .expect("admit managed Codex");

        fs::write(&fixture.binary_path, b"mutated after admission")
            .expect("mutate admitted binary");
        let error = runtime
            .commands::<1>()
            .expect_err("mutated binary must never produce a spawnable command");

        assert_eq!(error.code, ErrorCode::StorageIntegrityFailed);
        assert_eq!(
            error.details["reason"],
            json!("immutable_binary_digest_mismatch")
        );
    }

    #[test]
    fn receipt_admission_requires_exact_versioned_package_and_binary_locations() {
        let mut wrong_package = ReceiptFixture::new();
        let alias_root = wrong_package
            .codex_home
            .join("packages")
            .join("standalone")
            .join("releases")
            .join("another-package");
        let alias_binary = alias_root.join("bin").join(BINARY_NAME);
        fs::create_dir_all(alias_binary.parent().expect("alias binary parent"))
            .expect("create alias package");
        fs::copy(&wrong_package.binary_path, &alias_binary).expect("copy alias binary");
        wrong_package
            .receipt_object_mut()
            .insert("immutable_package_root".to_string(), json!(alias_root));
        wrong_package
            .receipt_object_mut()
            .insert("immutable_binary_path".to_string(), json!(alias_binary));
        wrong_package.write_receipt();
        let package_error = admit_managed_codex_from_state_root_for_target(
            &wrong_package.state_root,
            FIXTURE_TARGET,
        )
        .expect_err("a receipt cannot relabel an arbitrary package as version 0.144.0");
        assert_eq!(
            package_error.details["reason"],
            json!("immutable_package_root_invalid")
        );

        let mut wrong_binary = ReceiptFixture::new();
        let alternate_binary = wrong_binary.package_root.join("bin").join("codex-copy");
        fs::copy(&wrong_binary.binary_path, &alternate_binary).expect("copy alternate binary");
        wrong_binary
            .receipt_object_mut()
            .insert("immutable_binary_path".to_string(), json!(alternate_binary));
        wrong_binary.write_receipt();
        let binary_error = admit_managed_codex_from_state_root_for_target(
            &wrong_binary.state_root,
            FIXTURE_TARGET,
        )
        .expect_err("a receipt cannot select a second executable from the package");
        assert_eq!(
            binary_error.details["reason"],
            json!("immutable_binary_path_invalid")
        );
    }

    #[test]
    fn receipt_admission_ignores_path_npm_shims_and_mutable_aliases() {
        let fixture = ReceiptFixture::new();
        let npm_shim = fixture.state_root.join("node_modules").join(".bin");
        fs::create_dir_all(&npm_shim).expect("create npm shim directory");
        fs::write(npm_shim.join(BINARY_NAME), b"npm shim").expect("write npm shim");
        let runtime =
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .expect("receipt identity wins");
        assert_eq!(runtime.binary_path(), fixture.binary_path);
    }

    #[test]
    fn receipt_admission_requires_the_current_target_and_baseline_artifact_digest() {
        let mut fixture = ReceiptFixture::new();
        assert!(
            admit_managed_codex_from_state_root_for_target(
                &fixture.state_root,
                FIXTURE_OTHER_TARGET
            )
            .is_err()
        );

        fixture
            .receipt_object_mut()
            .insert("artifact_sha256".to_string(), json!("11".repeat(32)));
        fixture.write_receipt();
        assert!(
            admit_managed_codex_from_state_root_for_target(&fixture.state_root, FIXTURE_TARGET)
                .is_err()
        );
    }

    #[test]
    fn windows_path_identity_accepts_verbatim_prefixes_but_not_aliases() {
        assert_eq!(
            normalize_windows_path(r"\\?\C:\Codex\releases\0.144.0"),
            r"C:\Codex\releases\0.144.0"
        );
        assert_eq!(
            normalize_windows_path(r"\\?\UNC\server\share\Codex"),
            r"\\server\share\Codex"
        );
        assert_ne!(
            normalize_windows_path(r"C:\Codex\current"),
            normalize_windows_path(r"C:\Codex\releases\0.144.0")
        );
    }
}
