use flate2::read::GzDecoder;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zip::ZipArchive;

const RELEASE_REPOSITORY: &str = "Microck/satelle";
const RELEASE_BASE_URL: &str = "https://github.com/Microck/satelle/releases/download";
const NETWORK_TIMEOUT: Duration = Duration::from_secs(300);
const GH_OUTPUT_LIMIT: usize = 1_024;
const MANIFEST_LIMIT: u64 = 64 * 1024;
const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const BINARY_LIMIT: u64 = 256 * 1024 * 1024;
const RECEIPT_FILE_NAME: &str = ".satelle-install.json";
const LOCK_FILE_NAME: &str = ".satelle-install.lock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelfUpdateRequest {
    requested_version: Option<String>,
    dry_run: bool,
    current_executable: PathBuf,
    current_version: String,
    follow_up_host: Option<String>,
}

impl SelfUpdateRequest {
    pub(crate) fn current(
        requested_version: Option<String>,
        dry_run: bool,
        follow_up_host: Option<String>,
    ) -> Result<Self, SelfUpdateError> {
        Ok(Self {
            requested_version,
            dry_run,
            current_executable: std::env::current_exe()
                .map_err(SelfUpdateError::CurrentExecutable)?,
            current_version: env!("CARGO_PKG_VERSION").to_string(),
            follow_up_host,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SelfUpdateOutcome {
    UpToDate,
    WouldUpdate,
    Updated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SelfUpdateReport {
    schema_version: &'static str,
    outcome: SelfUpdateOutcome,
    current_version: String,
    latest_compatible_version: String,
    install_owner: String,
    target_artifact: String,
    planned_replacement: PathBuf,
    changed: bool,
    follow_up_host_update_command: Option<String>,
}

impl SelfUpdateReport {
    pub(crate) fn outcome(&self) -> SelfUpdateOutcome {
        self.outcome
    }

    pub(crate) fn changed(&self) -> bool {
        self.changed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RemoteHostChoice {
    pub(crate) alias: String,
    pub(crate) selected: bool,
    pub(crate) selection_reason: Option<&'static str>,
}

pub(crate) fn remote_host_choices(
    current_host: Option<&str>,
    default_host: Option<&str>,
    configured_remote_hosts: impl IntoIterator<Item = String>,
) -> Vec<RemoteHostChoice> {
    let hosts = configured_remote_hosts.into_iter().collect::<BTreeSet<_>>();
    let selected = current_host
        .filter(|host| hosts.contains(*host))
        .map(|host| (host, "current_command_target"))
        .or_else(|| {
            default_host
                .filter(|host| hosts.contains(*host))
                .map(|host| (host, "configured_default"))
        });

    hosts
        .into_iter()
        .map(|alias| {
            let selection_reason = selected
                .filter(|(selected, _)| *selected == alias)
                .map(|(_, reason)| reason);
            RemoteHostChoice {
                alias,
                selected: selection_reason.is_some(),
                selection_reason,
            }
        })
        .collect()
}

pub(crate) fn selected_remote_host(choices: &[RemoteHostChoice]) -> Option<&str> {
    choices
        .iter()
        .find(|choice| choice.selected)
        .map(|choice| choice.alias.as_str())
}

pub(crate) fn host_update_arguments(host: &str) -> Vec<String> {
    vec![
        "host".to_string(),
        "update".to_string(),
        "--host".to_string(),
        host.to_string(),
    ]
}

pub(crate) fn run(request: SelfUpdateRequest) -> Result<SelfUpdateReport, SelfUpdateError> {
    let source = GithubReleaseSource::new()?;
    run_with(
        request,
        &source,
        &RunningExecutableReplacer,
        OffsetDateTime::now_utc(),
    )
}

fn run_with(
    request: SelfUpdateRequest,
    source: &impl ReleaseSource,
    replacer: &impl ExecutableReplacer,
    installed_at: OffsetDateTime,
) -> Result<SelfUpdateReport, SelfUpdateError> {
    let executable = request
        .current_executable
        .canonicalize()
        .map_err(SelfUpdateError::CurrentExecutable)?;
    if let Some(managed) = detect_managed_install(&executable) {
        return Err(SelfUpdateError::ManagedInstall(managed));
    }
    let receipt_path = receipt_path(&executable)?;
    let receipt = read_receipt(&receipt_path)?;
    validate_receipt(&receipt, &executable, &request.current_version)?;

    let current = Version::parse(&request.current_version)?;
    let target_version = match request.requested_version {
        Some(version) => Version::parse(&version)?,
        None => {
            if current.prerelease.is_some() {
                return Err(SelfUpdateError::ExplicitVersionRequired {
                    current: current.to_string(),
                    candidate: "latest stable release".to_string(),
                });
            }
            let version = Version::parse(&source.latest_stable_version()?)?;
            if version.prerelease.is_some() || version.core() < current.core() {
                return Err(SelfUpdateError::ExplicitVersionRequired {
                    current: current.to_string(),
                    candidate: version.to_string(),
                });
            }
            version
        }
    };

    let target = LocalTarget::current()?;
    if receipt.target != target.id() {
        return Err(SelfUpdateError::ReceiptInvalid("target_mismatch"));
    }
    let artifact = target.archive_name(&target_version.to_string());
    let follow_up_host_update_command = request
        .follow_up_host
        .as_deref()
        .map(|host| format!("satelle host update --host {host}"));
    let same_version = target_version == current;
    let mut report = SelfUpdateReport {
        schema_version: "satelle.self.update.v1",
        outcome: if same_version {
            SelfUpdateOutcome::UpToDate
        } else if request.dry_run {
            SelfUpdateOutcome::WouldUpdate
        } else {
            SelfUpdateOutcome::Updated
        },
        current_version: current.to_string(),
        latest_compatible_version: target_version.to_string(),
        install_owner: receipt.install_method.clone(),
        target_artifact: artifact,
        planned_replacement: executable.clone(),
        changed: false,
        follow_up_host_update_command,
    };
    if same_version || request.dry_run {
        return Ok(report);
    }

    // The first receipt read builds a mutation-free plan. Revalidate under the
    // install lock before downloading so a waiting updater cannot commit from
    // stale installation state after another updater finishes.
    let parent = executable
        .parent()
        .ok_or(SelfUpdateError::ReceiptInvalid("binary_parent_missing"))?;
    let _lock = InstallLock::acquire(parent)?;
    let locked_receipt = read_receipt(&receipt_path)?;
    validate_receipt(&locked_receipt, &executable, &request.current_version)?;
    if locked_receipt.target != target.id() {
        return Err(SelfUpdateError::ReceiptInvalid("target_mismatch"));
    }

    let verified = source.fetch_verified_release(&target_version.to_string(), target)?;
    let new_receipt = InstallReceipt {
        install_method: locked_receipt.install_method,
        binary_path: executable.clone(),
        version: target_version.to_string(),
        target: target.id().to_string(),
        artifact_digest: digest_hex(&verified.archive_digest),
        installed_at: installed_at
            .format(&Rfc3339)
            .map_err(|_| SelfUpdateError::Timestamp)?,
    };
    replace_installation_locked(
        &executable,
        &receipt_path,
        &verified.executable,
        &new_receipt,
        replacer,
    )?;
    report.changed = true;
    Ok(report)
}

trait ReleaseSource {
    fn latest_stable_version(&self) -> Result<String, SelfUpdateError>;

    fn fetch_verified_release(
        &self,
        version: &str,
        target: LocalTarget,
    ) -> Result<VerifiedRelease, SelfUpdateError>;
}

trait ExecutableReplacer {
    fn replace(&self, current_executable: &Path, staged: &Path) -> io::Result<()>;
}

struct RunningExecutableReplacer;

impl ExecutableReplacer for RunningExecutableReplacer {
    fn replace(&self, current_executable: &Path, staged: &Path) -> io::Result<()> {
        if std::env::current_exe()?.canonicalize()? != current_executable {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the installation receipt does not identify the running executable",
            ));
        }
        self_replace::self_replace(staged)
    }
}

struct GithubReleaseSource {
    client: Client,
}

impl GithubReleaseSource {
    fn new() -> Result<Self, SelfUpdateError> {
        let client = Client::builder()
            .timeout(NETWORK_TIMEOUT)
            .user_agent(format!("satelle/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(SelfUpdateError::Http)?;
        Ok(Self { client })
    }

    fn download(&self, url: &str, limit: u64) -> Result<Vec<u8>, SelfUpdateError> {
        let response = self
            .client
            .get(url)
            .send()
            .and_then(Response::error_for_status)
            .map_err(SelfUpdateError::Http)?;
        read_response_bounded(response, limit)
    }
}

impl ReleaseSource for GithubReleaseSource {
    fn latest_stable_version(&self) -> Result<String, SelfUpdateError> {
        let tag = run_gh_line(&[
            "api",
            "repos/Microck/satelle/releases/latest",
            "--jq",
            ".tag_name",
        ])?;
        tag.strip_prefix('v')
            .filter(|version| !version.is_empty())
            .map(str::to_string)
            .ok_or(SelfUpdateError::ReleaseMetadataInvalid)
    }

    fn fetch_verified_release(
        &self,
        version: &str,
        target: LocalTarget,
    ) -> Result<VerifiedRelease, SelfUpdateError> {
        let archive_name = target.archive_name(version);
        let release_url = format!("{RELEASE_BASE_URL}/v{version}");
        let archive_bytes = self.download(
            &format!("{release_url}/{archive_name}"),
            ARCHIVE_LIMIT,
        )?;
        let manifest = self.download(&format!("{release_url}/SHA256SUMS"), MANIFEST_LIMIT)?;
        let expected_digest = manifest_digest(&manifest, &archive_name)?;
        let actual_digest: [u8; 32] = Sha256::digest(&archive_bytes).into();
        if actual_digest != expected_digest {
            return Err(SelfUpdateError::ArchiveDigestMismatch);
        }

        let directory = tempdir().map_err(SelfUpdateError::TemporaryDirectory)?;
        let archive_path = directory.path().join(&archive_name);
        write_private_file(&archive_path, &archive_bytes)?;
        verify_release_attestation(&archive_path, version)?;
        let executable = extract_executable(&archive_path, target, directory.path())?;
        verify_binary_version(&executable, version)?;
        Ok(VerifiedRelease {
            _directory: directory,
            executable,
            archive_digest: actual_digest,
        })
    }
}

struct VerifiedRelease {
    _directory: TempDir,
    executable: PathBuf,
    archive_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalTarget {
    LinuxArm64Gnu,
    LinuxX64Gnu,
    DarwinArm64,
    DarwinX64,
    WindowsArm64Msvc,
    WindowsX64Msvc,
}

impl LocalTarget {
    fn current() -> Result<Self, SelfUpdateError> {
        #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
        {
            return Ok(Self::LinuxArm64Gnu);
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            return Ok(Self::LinuxX64Gnu);
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            return Ok(Self::DarwinArm64);
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            return Ok(Self::DarwinX64);
        }
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            return Ok(Self::WindowsArm64Msvc);
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            return Ok(Self::WindowsX64Msvc);
        }
        #[allow(unreachable_code)]
        Err(SelfUpdateError::UnsupportedLocalPlatform)
    }

    const fn id(self) -> &'static str {
        match self {
            Self::LinuxArm64Gnu => "linux-arm64-gnu",
            Self::LinuxX64Gnu => "linux-x64-gnu",
            Self::DarwinArm64 => "darwin-arm64",
            Self::DarwinX64 => "darwin-x64",
            Self::WindowsArm64Msvc => "win32-arm64-msvc",
            Self::WindowsX64Msvc => "win32-x64-msvc",
        }
    }

    const fn executable_name(self) -> &'static str {
        match self {
            Self::WindowsArm64Msvc | Self::WindowsX64Msvc => "satelle.exe",
            _ => "satelle",
        }
    }

    const fn archive_extension(self) -> &'static str {
        match self {
            Self::WindowsArm64Msvc | Self::WindowsX64Msvc => "zip",
            _ => "tar.gz",
        }
    }

    fn archive_name(self, version: &str) -> String {
        format!(
            "satelle-v{version}-{}.{}",
            self.id(),
            self.archive_extension()
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallReceipt {
    install_method: String,
    binary_path: PathBuf,
    version: String,
    target: String,
    artifact_digest: String,
    installed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedInstall {
    pub(crate) install_method: &'static str,
    pub(crate) upgrade_command: &'static str,
}

fn detect_managed_install(executable: &Path) -> Option<ManagedInstall> {
    let components = executable
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let contains = |value: &str| components.iter().any(|component| component == value);
    let joined = components.join("/");

    if joined.contains("/.pnpm/") || contains(".pnpm") {
        return Some(ManagedInstall {
            install_method: "pnpm",
            upgrade_command: "pnpm update @microck/satelle",
        });
    }
    if joined.contains("/.bun/") || contains(".bun") {
        return Some(ManagedInstall {
            install_method: "bun",
            upgrade_command: "bun update @microck/satelle",
        });
    }
    if contains("node_modules") {
        return Some(ManagedInstall {
            install_method: "npm",
            upgrade_command: "npm update @microck/satelle",
        });
    }
    if contains("cellar") || joined.contains("/homebrew/") {
        return Some(ManagedInstall {
            install_method: "homebrew",
            upgrade_command: "brew upgrade satelle",
        });
    }
    if joined.contains("/scoop/apps/") {
        return Some(ManagedInstall {
            install_method: "scoop",
            upgrade_command: "scoop update satelle",
        });
    }
    None
}

fn receipt_path(executable: &Path) -> Result<PathBuf, SelfUpdateError> {
    executable
        .parent()
        .map(|parent| parent.join(RECEIPT_FILE_NAME))
        .ok_or(SelfUpdateError::ReceiptInvalid("binary_parent_missing"))
}

fn read_receipt(path: &Path) -> Result<InstallReceipt, SelfUpdateError> {
    let bytes = fs::read(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => SelfUpdateError::InstallOwnerUnknown,
        _ => SelfUpdateError::ReceiptRead(error),
    })?;
    if bytes.len() > 16 * 1024 {
        return Err(SelfUpdateError::ReceiptInvalid("receipt_too_large"));
    }
    serde_json::from_slice(&bytes).map_err(|_| SelfUpdateError::ReceiptInvalid("schema_invalid"))
}

fn validate_receipt(
    receipt: &InstallReceipt,
    executable: &Path,
    current_version: &str,
) -> Result<(), SelfUpdateError> {
    if !matches!(
        receipt.install_method.as_str(),
        "satelle-install-script" | "direct-github-release-archive"
    ) {
        return Err(SelfUpdateError::ReceiptInvalid("install_method_invalid"));
    }
    let receipt_binary = receipt
        .binary_path
        .canonicalize()
        .map_err(|_| SelfUpdateError::ReceiptInvalid("binary_path_invalid"))?;
    if receipt_binary != executable {
        return Err(SelfUpdateError::ReceiptInvalid("binary_path_mismatch"));
    }
    if receipt.version != current_version {
        return Err(SelfUpdateError::ReceiptInvalid("version_mismatch"));
    }
    if Version::parse(&receipt.version).is_err() {
        return Err(SelfUpdateError::ReceiptInvalid("version_invalid"));
    }
    if !is_sha256_hex(&receipt.artifact_digest) {
        return Err(SelfUpdateError::ReceiptInvalid("artifact_digest_invalid"));
    }
    if OffsetDateTime::parse(&receipt.installed_at, &Rfc3339).is_err() {
        return Err(SelfUpdateError::ReceiptInvalid("installed_at_invalid"));
    }
    Ok(())
}

fn replace_installation_locked(
    executable: &Path,
    receipt_path: &Path,
    staged_binary: &Path,
    receipt: &InstallReceipt,
    replacer: &impl ExecutableReplacer,
) -> Result<(), SelfUpdateError> {
    let parent = executable
        .parent()
        .ok_or(SelfUpdateError::ReceiptInvalid("binary_parent_missing"))?;
    let pid = std::process::id();
    let staged_receipt = parent.join(format!(".satelle-receipt.updating.{pid}"));
    let previous_receipt = parent.join(format!(".satelle-receipt.previous.{pid}"));
    let receipt_bytes =
        serde_json::to_vec_pretty(receipt).map_err(|_| SelfUpdateError::ReceiptSerialize)?;
    write_private_file(&staged_receipt, &receipt_bytes)?;

    if let Err(error) = fs::rename(receipt_path, &previous_receipt) {
        let _ = fs::remove_file(&staged_receipt);
        return Err(SelfUpdateError::ReceiptCommit(error));
    }
    if let Err(error) = fs::rename(&staged_receipt, receipt_path) {
        let _ = fs::remove_file(&staged_receipt);
        if let Err(rollback) = fs::rename(&previous_receipt, receipt_path) {
            return Err(SelfUpdateError::ReceiptRollback {
                backup_path: previous_receipt,
                receipt_path: receipt_path.to_path_buf(),
                source: rollback,
            });
        }
        return Err(SelfUpdateError::ReceiptCommit(error));
    }

    if let Err(error) = replacer.replace(executable, staged_binary) {
        if let Err(rollback) = fs::remove_file(receipt_path)
            .and_then(|()| fs::rename(&previous_receipt, receipt_path))
        {
            return Err(SelfUpdateError::ReceiptRollback {
                backup_path: previous_receipt,
                receipt_path: receipt_path.to_path_buf(),
                source: rollback,
            });
        }
        return Err(SelfUpdateError::BinaryCommit(error));
    }
    // The binary and new receipt are already committed. A stale private backup
    // must not turn a successful update into a false failure.
    let _ = fs::remove_file(&previous_receipt);
    Ok(())
}

struct InstallLock {
    path: PathBuf,
}

impl InstallLock {
    fn acquire(parent: &Path) -> Result<Self, SelfUpdateError> {
        let path = parent.join(LOCK_FILE_NAME);
        fs::create_dir(&path).map_err(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => SelfUpdateError::InstallLocked(path.clone()),
            _ => SelfUpdateError::InstallLock(error),
        })?;
        Ok(Self { path })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

impl Version {
    fn parse(raw: &str) -> Result<Self, SelfUpdateError> {
        let (core, prerelease) = raw
            .split_once('-')
            .map_or((raw, None), |(core, prerelease)| {
                (core, Some(prerelease))
            });
        if raw.contains('+')
            || prerelease.is_some_and(|value| {
                value.is_empty()
                    || value.split('.').any(|identifier| {
                        identifier.is_empty()
                            || !identifier
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                            || (identifier.len() > 1
                                && identifier.starts_with('0')
                                && identifier.bytes().all(|byte| byte.is_ascii_digit()))
                    })
            })
        {
            return Err(SelfUpdateError::VersionInvalid(raw.to_string()));
        }
        let mut numbers = core.split('.');
        let major = parse_version_number(numbers.next(), raw)?;
        let minor = parse_version_number(numbers.next(), raw)?;
        let patch = parse_version_number(numbers.next(), raw)?;
        if numbers.next().is_some() {
            return Err(SelfUpdateError::VersionInvalid(raw.to_string()));
        }
        Ok(Self {
            major,
            minor,
            patch,
            prerelease: prerelease.map(str::to_string),
        })
    }

    const fn core(&self) -> (u64, u64, u64) {
        (self.major, self.minor, self.patch)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(prerelease) = &self.prerelease {
            write!(formatter, "-{prerelease}")?;
        }
        Ok(())
    }
}

fn parse_version_number(value: Option<&str>, raw: &str) -> Result<u64, SelfUpdateError> {
    let value = value.ok_or_else(|| SelfUpdateError::VersionInvalid(raw.to_string()))?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SelfUpdateError::VersionInvalid(raw.to_string()));
    }
    value
        .parse()
        .map_err(|_| SelfUpdateError::VersionInvalid(raw.to_string()))
}

fn verify_release_attestation(archive: &Path, version: &str) -> Result<(), SelfUpdateError> {
    let tag_ref = run_gh_line(&[
        "api",
        &format!("repos/{RELEASE_REPOSITORY}/git/ref/tags/v{version}"),
        "--jq",
        ".object.type + \" \" + .object.sha",
    ])?;
    let (tag_type, tag_digest) = tag_ref
        .split_once(' ')
        .ok_or(SelfUpdateError::ReleaseMetadataInvalid)?;
    if tag_type != "tag" || !is_git_digest(tag_digest) {
        return Err(SelfUpdateError::ReleaseMetadataInvalid);
    }
    let source_digest = run_gh_line(&[
        "api",
        &format!("repos/{RELEASE_REPOSITORY}/git/tags/{tag_digest}"),
        "--jq",
        "select(.verification.verified == true and .object.type == \"commit\") | .object.sha",
    ])?;
    if !is_git_digest(&source_digest) {
        return Err(SelfUpdateError::ReleaseMetadataInvalid);
    }

    let mut command = Command::new("gh");
    command
        .args([
            "attestation",
            "verify",
            archive
                .to_str()
                .ok_or(SelfUpdateError::ReleaseMetadataInvalid)?,
            "--repo",
            RELEASE_REPOSITORY,
            "--signer-workflow",
            "Microck/satelle/.github/workflows/release.yml",
            "--source-ref",
            &format!("refs/tags/v{version}"),
            "--source-digest",
            &source_digest,
            "--signer-digest",
            &source_digest,
            "--cert-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--deny-self-hosted-runners",
            "--format",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| SelfUpdateError::GhUnavailable)?;
    let status = wait_bounded(&mut child, NETWORK_TIMEOUT)?;
    if !status.success() {
        return Err(SelfUpdateError::AttestationInvalid);
    }
    Ok(())
}

fn run_gh_line(arguments: &[&str]) -> Result<String, SelfUpdateError> {
    // Write bounded command output to a file instead of a pipe. Waiting for a
    // child before draining a pipe can deadlock if it fills the pipe buffer.
    let mut stdout = tempfile::tempfile().map_err(SelfUpdateError::GhOutput)?;
    let child_stdout = stdout.try_clone().map_err(SelfUpdateError::GhOutput)?;
    let mut child = Command::new("gh")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| SelfUpdateError::GhUnavailable)?;
    let status = wait_bounded(&mut child, NETWORK_TIMEOUT)?;
    if !status.success() {
        return Err(SelfUpdateError::ReleaseMetadataInvalid);
    }
    stdout
        .seek(SeekFrom::Start(0))
        .map_err(SelfUpdateError::GhOutput)?;
    let mut output = Vec::new();
    stdout
        .take(GH_OUTPUT_LIMIT as u64 + 1)
        .read_to_end(&mut output)
        .map_err(SelfUpdateError::GhOutput)?;
    if output.len() > GH_OUTPUT_LIMIT {
        return Err(SelfUpdateError::ReleaseMetadataInvalid);
    }
    let line = std::str::from_utf8(&output)
        .map_err(|_| SelfUpdateError::ReleaseMetadataInvalid)?
        .trim();
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return Err(SelfUpdateError::ReleaseMetadataInvalid);
    }
    Ok(line.to_string())
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus, SelfUpdateError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(SelfUpdateError::ProcessWait)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            child.kill().map_err(SelfUpdateError::ProcessWait)?;
            let _ = child.wait();
            return Err(SelfUpdateError::ProcessTimeout);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn extract_executable(
    archive_path: &Path,
    target: LocalTarget,
    directory: &Path,
) -> Result<PathBuf, SelfUpdateError> {
    let output = directory.join(format!("{}.verified", target.executable_name()));
    if target.archive_extension() == "zip" {
        let archive_file = File::open(archive_path).map_err(SelfUpdateError::ArchiveRead)?;
        let mut archive = ZipArchive::new(archive_file).map_err(SelfUpdateError::Zip)?;
        if archive.len() != 1 {
            return Err(SelfUpdateError::ArchiveLayoutInvalid);
        }
        let mut entry = archive.by_index(0).map_err(SelfUpdateError::Zip)?;
        if !entry.is_file()
            || entry.name() != target.executable_name()
            || entry.size() == 0
            || entry.size() > BINARY_LIMIT
        {
            return Err(SelfUpdateError::ArchiveLayoutInvalid);
        }
        let mut file = create_executable_file(&output)?;
        io::copy(&mut entry, &mut file).map_err(SelfUpdateError::ArchiveRead)?;
        file.sync_all().map_err(SelfUpdateError::ArchiveRead)?;
    } else {
        let archive_file = File::open(archive_path).map_err(SelfUpdateError::ArchiveRead)?;
        let decoder = GzDecoder::new(archive_file);
        let mut archive = tar::Archive::new(decoder);
        let mut entries = archive.entries().map_err(SelfUpdateError::ArchiveRead)?;
        let mut entry = entries
            .next()
            .ok_or(SelfUpdateError::ArchiveLayoutInvalid)?
            .map_err(SelfUpdateError::ArchiveRead)?;
        let path = entry.path().map_err(SelfUpdateError::ArchiveRead)?;
        if path.as_ref() != Path::new(target.executable_name())
            || !entry.header().entry_type().is_file()
            || entry.size() == 0
            || entry.size() > BINARY_LIMIT
        {
            return Err(SelfUpdateError::ArchiveLayoutInvalid);
        }
        let mut file = create_executable_file(&output)?;
        io::copy(&mut entry, &mut file).map_err(SelfUpdateError::ArchiveRead)?;
        file.sync_all().map_err(SelfUpdateError::ArchiveRead)?;
        if entries.next().is_some() {
            return Err(SelfUpdateError::ArchiveLayoutInvalid);
        }
    }
    Ok(output)
}

fn create_executable_file(path: &Path) -> Result<File, SelfUpdateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    options.open(path).map_err(SelfUpdateError::ArchiveRead)
}

fn verify_binary_version(executable: &Path, version: &str) -> Result<(), SelfUpdateError> {
    let mut stdout = tempfile::tempfile().map_err(SelfUpdateError::BinarySmoke)?;
    let child_stdout = stdout
        .try_clone()
        .map_err(SelfUpdateError::BinarySmoke)?;
    let mut child = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::null())
        .spawn()
        .map_err(SelfUpdateError::BinarySmoke)?;
    let status = wait_bounded(&mut child, Duration::from_secs(30))?;
    if !status.success() {
        return Err(SelfUpdateError::BinaryVersionMismatch);
    }
    stdout
        .seek(SeekFrom::Start(0))
        .map_err(SelfUpdateError::BinarySmoke)?;
    let mut output = String::new();
    stdout
        .take(256)
        .read_to_string(&mut output)
        .map_err(SelfUpdateError::BinarySmoke)?;
    if output.trim() != format!("satelle {version}") {
        return Err(SelfUpdateError::BinaryVersionMismatch);
    }
    Ok(())
}

fn read_response_bounded(response: Response, limit: u64) -> Result<Vec<u8>, SelfUpdateError> {
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(SelfUpdateError::ResponseRead)?;
    if bytes.len() as u64 > limit {
        return Err(SelfUpdateError::ResponseTooLarge);
    }
    Ok(bytes)
}

fn manifest_digest(manifest: &[u8], filename: &str) -> Result<[u8; 32], SelfUpdateError> {
    let text =
        std::str::from_utf8(manifest).map_err(|_| SelfUpdateError::ManifestInvalid)?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(SelfUpdateError::ManifestInvalid);
    }
    let mut previous = None;
    let mut selected = None;
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or(SelfUpdateError::ManifestInvalid)?;
        if !is_sha256_hex(digest)
            || name.is_empty()
            || name == "."
            || name == ".."
            || name == "SHA256SUMS"
            || name.bytes().any(u8::is_ascii_whitespace)
            || name.contains('/')
            || name.contains('\\')
            || previous.is_some_and(|previous| previous >= name)
        {
            return Err(SelfUpdateError::ManifestInvalid);
        }
        previous = Some(name);
        if name == filename {
            if selected.is_some() {
                return Err(SelfUpdateError::ManifestInvalid);
            }
            let bytes = hex_digest(digest).ok_or(SelfUpdateError::ManifestInvalid)?;
            selected = Some(bytes);
        }
    }
    selected.ok_or(SelfUpdateError::ManifestEntryMissing)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), SelfUpdateError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(SelfUpdateError::PrivateWrite)?;
    file.write_all(bytes).map_err(SelfUpdateError::PrivateWrite)?;
    file.sync_all().map_err(SelfUpdateError::PrivateWrite)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_git_digest(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(value: &str) -> Option<[u8; 32]> {
    if !is_sha256_hex(value) {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn digest_hex(digest: &[u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[derive(Debug, Error)]
pub(crate) enum SelfUpdateError {
    #[error("the running Satelle executable could not be identified")]
    CurrentExecutable(#[source] io::Error),
    #[error("self update is managed by {0:?}")]
    ManagedInstall(ManagedInstall),
    #[error("the Satelle installation owner could not be established")]
    InstallOwnerUnknown,
    #[error("the Satelle installation receipt is invalid: {0}")]
    ReceiptInvalid(&'static str),
    #[error("the Satelle installation receipt could not be read")]
    ReceiptRead(#[source] io::Error),
    #[error("the requested Satelle version is invalid: {0}")]
    VersionInvalid(String),
    #[error(
        "updating from {current} to {candidate} requires an explicit --version selection"
    )]
    ExplicitVersionRequired { current: String, candidate: String },
    #[error("the local platform does not have an MVP Controller artifact")]
    UnsupportedLocalPlatform,
    #[error("the GitHub CLI is required for signed tag and attestation verification")]
    GhUnavailable,
    #[error("GitHub release metadata is invalid")]
    ReleaseMetadataInvalid,
    #[error("GitHub command output could not be read")]
    GhOutput(#[source] io::Error),
    #[error("the GitHub command did not finish before the update deadline")]
    ProcessTimeout,
    #[error("the GitHub command could not be observed")]
    ProcessWait(#[source] io::Error),
    #[error("the release download failed")]
    Http(#[source] reqwest::Error),
    #[error("the release response could not be read")]
    ResponseRead(#[source] io::Error),
    #[error("the release response exceeded its size limit")]
    ResponseTooLarge,
    #[error("SHA256SUMS is not canonical")]
    ManifestInvalid,
    #[error("SHA256SUMS does not contain the selected artifact")]
    ManifestEntryMissing,
    #[error("the selected release archive does not match SHA256SUMS")]
    ArchiveDigestMismatch,
    #[error("the selected release archive failed canonical attestation verification")]
    AttestationInvalid,
    #[error("a private temporary directory could not be created")]
    TemporaryDirectory(#[source] io::Error),
    #[error("the release archive could not be read")]
    ArchiveRead(#[source] io::Error),
    #[error("the release ZIP archive is invalid")]
    Zip(#[source] zip::result::ZipError),
    #[error("the release archive contains an invalid executable layout")]
    ArchiveLayoutInvalid,
    #[error("the release binary smoke test could not start")]
    BinarySmoke(#[source] io::Error),
    #[error("the release binary version does not match the selected release")]
    BinaryVersionMismatch,
    #[error("the installation receipt timestamp could not be formatted")]
    Timestamp,
    #[error("the installation receipt could not be serialized")]
    ReceiptSerialize,
    #[error("the self-update lock could not be acquired")]
    InstallLock(#[source] io::Error),
    #[error("another Satelle installation operation is active at {0}")]
    InstallLocked(PathBuf),
    #[error("the staged update could not be written")]
    PrivateWrite(#[source] io::Error),
    #[error("the updated installation receipt could not be committed")]
    ReceiptCommit(#[source] io::Error),
    #[error(
        "the previous installation receipt at {backup_path} could not be restored to {receipt_path}"
    )]
    ReceiptRollback {
        backup_path: PathBuf,
        receipt_path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the updated executable could not be committed")]
    BinaryCommit(#[source] io::Error),
}

impl SelfUpdateError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::ManagedInstall(_) => "self-update-managed-install",
            Self::InstallOwnerUnknown => "self-update-install-owner-unknown",
            Self::VersionInvalid(_) => "self-update-version-invalid",
            Self::ExplicitVersionRequired { .. } => "self-update-explicit-version-required",
            Self::UnsupportedLocalPlatform => "unsupported-local-platform",
            Self::InstallLocked(_) => "self-update-locked",
            Self::ReceiptRollback { .. } => "self-update-rollback-failed",
            Self::ReceiptInvalid(_) | Self::ReceiptRead(_) => "self-update-receipt-invalid",
            Self::ArchiveDigestMismatch
            | Self::AttestationInvalid
            | Self::ManifestEntryMissing
            | Self::ManifestInvalid => "self-update-verification-failed",
            _ => "self-update-failed",
        }
    }

    pub(crate) fn details(&self) -> Value {
        match self {
            Self::ManagedInstall(managed) => json!({
                "install_method": managed.install_method,
                "upgrade_command": managed.upgrade_command,
            }),
            Self::ExplicitVersionRequired { current, candidate } => json!({
                "current_version": current,
                "candidate_version": candidate,
            }),
            Self::InstallLocked(path) => json!({
                "lock_path": path,
            }),
            Self::ReceiptInvalid(reason) => json!({
                "reason": reason,
            }),
            Self::ReceiptRollback {
                backup_path,
                receipt_path,
                ..
            } => json!({
                "backup_path": backup_path,
                "receipt_path": receipt_path,
            }),
            _ => json!({}),
        }
    }

    pub(crate) fn recovery_command(&self) -> Option<String> {
        match self {
            Self::ManagedInstall(managed) => Some(managed.upgrade_command.to_string()),
            Self::InstallOwnerUnknown | Self::ReceiptInvalid(_) | Self::ReceiptRead(_) => Some(
                "reinstall Satelle with the verified install script or direct archive receipt"
                    .to_string(),
            ),
            Self::ExplicitVersionRequired { candidate, .. } => {
                Some(format!("satelle self update --version {candidate}"))
            }
            Self::GhUnavailable => Some("install and authenticate gh, then retry".to_string()),
            Self::InstallLocked(path) => Some(format!(
                "remove {} only after confirming no Satelle install operation is running",
                path.display()
            )),
            Self::ReceiptRollback {
                backup_path,
                receipt_path,
                ..
            } => Some(format!(
                "restore {} to {} before retrying",
                backup_path.display(),
                receipt_path.display()
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use tempfile::tempdir;

    struct FixtureReleaseSource {
        latest: String,
        executable: PathBuf,
        digest: [u8; 32],
    }

    impl ReleaseSource for FixtureReleaseSource {
        fn latest_stable_version(&self) -> Result<String, SelfUpdateError> {
            Ok(self.latest.clone())
        }

        fn fetch_verified_release(
            &self,
            _version: &str,
            _target: LocalTarget,
        ) -> Result<VerifiedRelease, SelfUpdateError> {
            let directory = tempdir().map_err(SelfUpdateError::TemporaryDirectory)?;
            let executable = directory.path().join("verified-satelle");
            fs::copy(&self.executable, &executable).map_err(SelfUpdateError::ArchiveRead)?;
            Ok(VerifiedRelease {
                _directory: directory,
                executable,
                archive_digest: self.digest,
            })
        }
    }

    struct FixtureReplacer;

    impl ExecutableReplacer for FixtureReplacer {
        fn replace(&self, current_executable: &Path, staged: &Path) -> io::Result<()> {
            fs::copy(staged, current_executable).map(drop)
        }
    }

    struct FailingReleaseSource {
        failure: fn() -> SelfUpdateError,
    }

    impl ReleaseSource for FailingReleaseSource {
        fn latest_stable_version(&self) -> Result<String, SelfUpdateError> {
            Ok("1.1.0".to_string())
        }

        fn fetch_verified_release(
            &self,
            _version: &str,
            _target: LocalTarget,
        ) -> Result<VerifiedRelease, SelfUpdateError> {
            Err((self.failure)())
        }
    }

    struct BlockingReleaseSource {
        executable: PathBuf,
        digest: [u8; 32],
        started: SyncSender<()>,
        release: Receiver<()>,
    }

    impl ReleaseSource for BlockingReleaseSource {
        fn latest_stable_version(&self) -> Result<String, SelfUpdateError> {
            Ok("1.1.0".to_string())
        }

        fn fetch_verified_release(
            &self,
            _version: &str,
            _target: LocalTarget,
        ) -> Result<VerifiedRelease, SelfUpdateError> {
            self.started
                .send(())
                .expect("signal locked release verification");
            self.release
                .recv()
                .expect("release locked release verification");
            let directory = tempdir().map_err(SelfUpdateError::TemporaryDirectory)?;
            let executable = directory.path().join("verified-satelle");
            fs::copy(&self.executable, &executable).map_err(SelfUpdateError::ArchiveRead)?;
            Ok(VerifiedRelease {
                _directory: directory,
                executable,
                archive_digest: self.digest,
            })
        }
    }

    struct RecordingReplacer<'a> {
        called: &'a Cell<bool>,
    }

    impl ExecutableReplacer for RecordingReplacer<'_> {
        fn replace(&self, _current_executable: &Path, _staged: &Path) -> io::Result<()> {
            self.called.set(true);
            Ok(())
        }
    }

    #[test]
    fn remote_selection_prefers_current_then_one_unambiguous_default() {
        let choices = remote_host_choices(
            Some("workstation"),
            Some("laptop"),
            ["laptop".to_string(), "workstation".to_string()],
        );
        assert_eq!(selected_remote_host(&choices), Some("workstation"));
        assert_eq!(
            choices
                .iter()
                .find(|choice| choice.alias == "laptop")
                .map(|choice| choice.selected),
            Some(false)
        );

        let choices =
            remote_host_choices(None, Some("laptop"), ["laptop".to_string()]);
        assert_eq!(selected_remote_host(&choices), Some("laptop"));
        assert_eq!(choices[0].selection_reason, Some("configured_default"));

        let choices = remote_host_choices(
            None,
            Some("laptop"),
            ["laptop".to_string(), "workstation".to_string()],
        );
        assert_eq!(selected_remote_host(&choices), Some("laptop"));
        assert_eq!(
            choices
                .iter()
                .find(|choice| choice.alias == "workstation")
                .map(|choice| choice.selected),
            Some(false)
        );
    }

    #[test]
    fn package_manager_layouts_have_typed_owner_and_upgrade_commands() {
        for (path, method, command) in [
            (
                "/home/user/project/node_modules/@microck/satelle-linux-x64-gnu/bin/satelle",
                "npm",
                "npm update @microck/satelle",
            ),
            (
                "/home/user/project/node_modules/.pnpm/@microck+satelle/bin/satelle",
                "pnpm",
                "pnpm update @microck/satelle",
            ),
            (
                "/home/user/.bun/install/cache/node_modules/@microck/satelle/bin/satelle",
                "bun",
                "bun update @microck/satelle",
            ),
            (
                "/opt/homebrew/Cellar/satelle/0.1.0/bin/satelle",
                "homebrew",
                "brew upgrade satelle",
            ),
            (
                "C:/Users/operator/scoop/apps/satelle/current/satelle.exe",
                "scoop",
                "scoop update satelle",
            ),
        ] {
            let managed = detect_managed_install(Path::new(path)).expect("managed layout");
            assert_eq!(managed.install_method, method);
            assert_eq!(managed.upgrade_command, command);
            let error = SelfUpdateError::ManagedInstall(managed);
            assert_eq!(error.code(), "self-update-managed-install");
            assert_eq!(error.details()["install_method"], method);
            assert_eq!(error.details()["upgrade_command"], command);
        }
    }

    #[test]
    fn version_policy_requires_explicit_downgrade_or_prerelease_selection() {
        assert_eq!(Version::parse("1.2.3").unwrap().core(), (1, 2, 3));
        assert_eq!(
            Version::parse("1.2.3-rc.1").unwrap().prerelease.as_deref(),
            Some("rc.1")
        );
        for invalid in [
            "",
            "1",
            "1.2",
            "01.2.3",
            "1.2.3+",
            "1.2.3-",
            "1.2.3-01",
        ] {
            assert!(Version::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn version_policy_rejects_implicit_boundaries_and_accepts_explicit_verified_releases() {
        for candidate in ["0.9.0", "1.1.0-rc.1"] {
            let fixture = install_fixture("1.0.0");
            let source = FixtureReleaseSource {
                latest: candidate.to_string(),
                executable: fixture.updated_binary.clone(),
                digest: [7; 32],
            };
            let replacement_called = Cell::new(false);
            let before_binary = fs::read(&fixture.current_binary).unwrap();
            let before_receipt = fs::read(&fixture.receipt).unwrap();

            let error = run_with(
                SelfUpdateRequest {
                    requested_version: None,
                    dry_run: false,
                    current_executable: fixture.current_binary.clone(),
                    current_version: "1.0.0".to_string(),
                    follow_up_host: None,
                },
                &source,
                &RecordingReplacer {
                    called: &replacement_called,
                },
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect_err("implicit downgrade or prerelease must fail");

            assert!(matches!(
                error,
                SelfUpdateError::ExplicitVersionRequired { .. }
            ));
            assert!(!replacement_called.get());
            assert_eq!(fs::read(&fixture.current_binary).unwrap(), before_binary);
            assert_eq!(fs::read(&fixture.receipt).unwrap(), before_receipt);
        }

        for selected in ["0.9.0", "1.1.0-rc.1"] {
            let fixture = install_fixture("1.0.0");
            let source = FixtureReleaseSource {
                latest: "9.9.9".to_string(),
                executable: fixture.updated_binary.clone(),
                digest: [8; 32],
            };
            let report = run_with(
                SelfUpdateRequest {
                    requested_version: Some(selected.to_string()),
                    dry_run: false,
                    current_executable: fixture.current_binary.clone(),
                    current_version: "1.0.0".to_string(),
                    follow_up_host: None,
                },
                &source,
                &FixtureReplacer,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("an explicit verified release selection must be accepted");

            assert_eq!(report.outcome, SelfUpdateOutcome::Updated);
            let receipt: InstallReceipt =
                serde_json::from_slice(&fs::read(&fixture.receipt).unwrap()).unwrap();
            assert_eq!(receipt.version, selected);
        }
    }

    #[test]
    fn dry_run_reports_plan_without_fetching_or_mutating() {
        let fixture = install_fixture("1.0.0");
        let source = FixtureReleaseSource {
            latest: "1.1.0".to_string(),
            executable: fixture.updated_binary.clone(),
            digest: [7; 32],
        };
        let before = fs::read(&fixture.current_binary).unwrap();
        let report = run_with(
            SelfUpdateRequest {
                requested_version: None,
                dry_run: true,
                current_executable: fixture.current_binary.clone(),
                current_version: "1.0.0".to_string(),
                follow_up_host: Some("workstation".to_string()),
            },
            &source,
            &FixtureReplacer,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();

        assert_eq!(report.schema_version, "satelle.self.update.v1");
        assert_eq!(report.outcome, SelfUpdateOutcome::WouldUpdate);
        assert_eq!(report.current_version, "1.0.0");
        assert_eq!(report.latest_compatible_version, "1.1.0");
        assert_eq!(report.install_owner, "satelle-install-script");
        assert!(report.target_artifact.contains("satelle-v1.1.0-"));
        assert_eq!(report.planned_replacement, fixture.current_binary);
        assert_eq!(
            report.follow_up_host_update_command.as_deref(),
            Some("satelle host update --host workstation")
        );
        assert!(!report.changed);
        assert_eq!(fs::read(&fixture.current_binary).unwrap(), before);
    }

    #[test]
    fn verified_update_replaces_binary_and_receipt_as_one_locked_operation() {
        let fixture = install_fixture("1.0.0");
        let source = FixtureReleaseSource {
            latest: "1.1.0".to_string(),
            executable: fixture.updated_binary.clone(),
            digest: [9; 32],
        };
        let report = run_with(
            SelfUpdateRequest {
                requested_version: Some("1.1.0".to_string()),
                dry_run: false,
                current_executable: fixture.current_binary.clone(),
                current_version: "1.0.0".to_string(),
                follow_up_host: None,
            },
            &source,
            &FixtureReplacer,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();

        assert_eq!(report.outcome, SelfUpdateOutcome::Updated);
        assert!(report.changed);
        assert_eq!(
            fs::read(&fixture.current_binary).unwrap(),
            fs::read(&fixture.updated_binary).unwrap()
        );
        let receipt: InstallReceipt =
            serde_json::from_slice(&fs::read(&fixture.receipt).unwrap()).unwrap();
        assert_eq!(receipt.version, "1.1.0");
        assert_eq!(receipt.artifact_digest, "09".repeat(32));
        assert_eq!(receipt.install_method, "satelle-install-script");
    }

    #[test]
    fn concurrent_update_cannot_commit_from_stale_receipt_state() {
        let fixture = install_fixture("1.0.0");
        let (started_sender, started_receiver) = sync_channel(0);
        let (release_sender, release_receiver) = sync_channel(0);
        let first_source = BlockingReleaseSource {
            executable: fixture.updated_binary.clone(),
            digest: [9; 32],
            started: started_sender,
            release: release_receiver,
        };
        let first_request = SelfUpdateRequest {
            requested_version: Some("1.1.0".to_string()),
            dry_run: false,
            current_executable: fixture.current_binary.clone(),
            current_version: "1.0.0".to_string(),
            follow_up_host: None,
        };

        thread::scope(|scope| {
            let first =
                scope.spawn(move || {
                    run_with(
                        first_request,
                        &first_source,
                        &FixtureReplacer,
                        OffsetDateTime::UNIX_EPOCH,
                    )
                });
            started_receiver
                .recv()
                .expect("first updater reaches verification under the lock");

            let replacement_called = Cell::new(false);
            let second_source = FixtureReleaseSource {
                latest: "1.1.0".to_string(),
                executable: fixture.updated_binary.clone(),
                digest: [8; 32],
            };
            let second = run_with(
                SelfUpdateRequest {
                    requested_version: Some("0.9.0".to_string()),
                    dry_run: false,
                    current_executable: fixture.current_binary.clone(),
                    current_version: "1.0.0".to_string(),
                    follow_up_host: None,
                },
                &second_source,
                &RecordingReplacer {
                    called: &replacement_called,
                },
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect_err("a concurrent updater must stop at the install lock");

            assert!(matches!(second, SelfUpdateError::InstallLocked(_)));
            assert!(!replacement_called.get());
            release_sender
                .send(())
                .expect("allow first updater to finish");
            assert_eq!(
                first.join().expect("join first updater").unwrap().outcome,
                SelfUpdateOutcome::Updated
            );
        });
    }

    #[test]
    fn checksum_manifest_requires_one_sorted_canonical_entry() {
        let selected = "satelle-v1.0.0-linux-x64-gnu.tar.gz";
        let digest = "01".repeat(32);
        let manifest = format!(
            "{digest}  other.tar.gz\n{}  {selected}\n",
            "02".repeat(32)
        );
        assert_eq!(
            manifest_digest(manifest.as_bytes(), selected).unwrap(),
            [2; 32]
        );
        for invalid in [
            format!("{digest} *{selected}\n"),
            format!("{digest}  ../{selected}\n"),
            format!("{digest}  {selected}\r\n"),
            format!("{digest}  {selected}\n{digest}  {selected}\n"),
        ] {
            assert!(manifest_digest(invalid.as_bytes(), selected).is_err());
        }
    }

    #[test]
    fn verification_failures_preserve_the_binary_and_receipt() {
        let failures: [fn() -> SelfUpdateError; 4] = [
            || SelfUpdateError::ManifestInvalid,
            || SelfUpdateError::ArchiveDigestMismatch,
            || SelfUpdateError::AttestationInvalid,
            || SelfUpdateError::BinaryVersionMismatch,
        ];

        for failure in failures {
            let fixture = install_fixture("1.0.0");
            let replacement_called = Cell::new(false);
            let before_binary = fs::read(&fixture.current_binary).unwrap();
            let before_receipt = fs::read(&fixture.receipt).unwrap();

            let error = run_with(
                SelfUpdateRequest {
                    requested_version: Some("1.1.0".to_string()),
                    dry_run: false,
                    current_executable: fixture.current_binary.clone(),
                    current_version: "1.0.0".to_string(),
                    follow_up_host: None,
                },
                &FailingReleaseSource { failure },
                &RecordingReplacer {
                    called: &replacement_called,
                },
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect_err("verification failures must stop replacement");

            assert!(matches!(
                error,
                SelfUpdateError::ManifestInvalid
                    | SelfUpdateError::ArchiveDigestMismatch
                    | SelfUpdateError::AttestationInvalid
                    | SelfUpdateError::BinaryVersionMismatch
            ));
            assert!(!replacement_called.get());
            assert_eq!(fs::read(&fixture.current_binary).unwrap(), before_binary);
            assert_eq!(fs::read(&fixture.receipt).unwrap(), before_receipt);
        }
    }

    #[test]
    fn self_update_artifacts_match_the_authoritative_controller_matrix() {
        let platforms: Value =
            serde_json::from_str(include_str!("../../../npm/satelle/platforms.json"))
                .expect("parse authoritative release platforms");
        let mut release_targets = platforms
            .as_object()
            .expect("release platforms must be keyed by target")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        release_targets.sort();

        let targets = [
            LocalTarget::LinuxArm64Gnu,
            LocalTarget::LinuxX64Gnu,
            LocalTarget::DarwinArm64,
            LocalTarget::DarwinX64,
            LocalTarget::WindowsArm64Msvc,
            LocalTarget::WindowsX64Msvc,
        ];
        let mut self_update_targets = targets
            .iter()
            .map(|target| target.id().to_string())
            .collect::<Vec<_>>();
        self_update_targets.sort();
        assert_eq!(self_update_targets, release_targets);

        for target in targets {
            assert_eq!(
                target.archive_name("1.2.3"),
                format!(
                    "satelle-v1.2.3-{}.{}",
                    target.id(),
                    target.archive_extension()
                )
            );
        }
    }

    #[test]
    fn documented_direct_archive_receipt_is_owned() {
        let fixture = install_fixture("1.2.3");
        let mut receipt: InstallReceipt =
            serde_json::from_slice(&fs::read(&fixture.receipt).unwrap()).unwrap();
        receipt.install_method = "direct-github-release-archive".to_string();

        validate_receipt(
            &receipt,
            &fixture.current_binary.canonicalize().unwrap(),
            "1.2.3",
        )
        .unwrap();
    }

    struct InstallFixture {
        _directory: TempDir,
        current_binary: PathBuf,
        updated_binary: PathBuf,
        receipt: PathBuf,
    }

    fn install_fixture(version: &str) -> InstallFixture {
        let directory = tempdir().unwrap();
        let current_binary = directory.path().join(std::env::consts::EXE_EXTENSION).with_file_name(
            if cfg!(windows) { "satelle.exe" } else { "satelle" },
        );
        let updated_binary = directory.path().join(if cfg!(windows) {
            "satelle-new.exe"
        } else {
            "satelle-new"
        });
        fs::write(&current_binary, b"old binary").unwrap();
        fs::write(&updated_binary, b"new binary").unwrap();
        let receipt = directory.path().join(RECEIPT_FILE_NAME);
        let receipt_value = InstallReceipt {
            install_method: "satelle-install-script".to_string(),
            binary_path: current_binary.canonicalize().unwrap(),
            version: version.to_string(),
            target: LocalTarget::current().unwrap().id().to_string(),
            artifact_digest: "01".repeat(32),
            installed_at: "2026-07-23T00:00:00Z".to_string(),
        };
        fs::write(&receipt, serde_json::to_vec_pretty(&receipt_value).unwrap()).unwrap();
        InstallFixture {
            _directory: directory,
            current_binary,
            updated_binary,
            receipt,
        }
    }
}
