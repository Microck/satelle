use flate2::read::GzDecoder;
use reqwest::blocking::{Client, Response};
use satelle_host::ApiBearerToken;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use uuid::Uuid;

use super::ssh_tunnel::{SshStderrClassification, classify_stderr};

const PROBE_OUTPUT_LIMIT: usize = 4096;
const START_OUTPUT_LIMIT: u64 = 16 * 1024;
const MANIFEST_LIMIT: u64 = 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const RELEASE_BASE_URL: &str = "https://github.com/Microck/satelle/releases/download";

pub(super) struct SshBootstrapProcess {
    child: Child,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<SshStderrClassification>>,
}

impl SshBootstrapProcess {
    pub(super) fn launch(
        destination: &str,
        token: &ApiBearerToken,
    ) -> Result<Self, SshBootstrapError> {
        let target = RemoteTarget::probe(destination)?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let remote_binary = upload_artifact(destination, target, artifact.path())?;
        Self::start(destination, target, &remote_binary, token)
    }

    fn start(
        destination: &str,
        target: RemoteTarget,
        remote_binary: &str,
        token: &ApiBearerToken,
    ) -> Result<Self, SshBootstrapError> {
        let mut command = Command::new("ssh");
        command
            .arg("-T")
            .arg(destination)
            .arg(target.start_command(remote_binary))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(SshBootstrapError::SpawnSsh)?;
        let mut stdin = child
            .stdin
            .take()
            .expect("bootstrap SSH stdin was configured as piped");
        let raw_token = token.expose();
        stdin
            .write_all(raw_token.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|error| terminate_child(&mut child, SshBootstrapError::WriteToken(error)))?;
        drop(stdin);

        let stdout = child
            .stdout
            .take()
            .expect("bootstrap SSH stdout was configured as piped");
        let stderr = child
            .stderr
            .take()
            .expect("bootstrap SSH stderr was configured as piped");
        let stderr_reader = spawn_stderr_reader(stderr)?;
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let stdout_reader = thread::Builder::new()
            .name("satelle-ssh-bootstrap-stdout".to_string())
            .spawn(move || drain_bootstrap_stdout(stdout, ready_sender))
            .map_err(|error| terminate_child(&mut child, SshBootstrapError::ReaderThread(error)))?;

        let ready = ready_receiver
            .recv_timeout(PROCESS_TIMEOUT)
            .map_err(|_| terminate_child(&mut child, SshBootstrapError::StartTimedOut))?;
        let ready = match ready {
            Ok(ready) => ready,
            Err(error) => return Err(terminate_child(&mut child, error)),
        };
        if !ready.running || ready.bind != "127.0.0.1:3001" {
            return Err(terminate_child(
                &mut child,
                SshBootstrapError::InvalidStartResponse,
            ));
        }
        let child_status = child
            .try_wait()
            .map_err(|error| terminate_child(&mut child, SshBootstrapError::InspectSsh(error)))?;
        if child_status.is_some() {
            let classification = stderr_reader.join().unwrap_or_default();
            return Err(if classification.host_key_verification_failed() {
                SshBootstrapError::HostKeyVerificationRequired
            } else {
                SshBootstrapError::DaemonExited
            });
        }

        Ok(Self {
            child,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
        })
    }
}

impl Drop for SshBootstrapProcess {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteTarget {
    LinuxArm64Gnu,
    LinuxX64Gnu,
    DarwinArm64,
    DarwinX64,
    WindowsArm64Msvc,
    WindowsX64Msvc,
}

impl RemoteTarget {
    fn probe(destination: &str) -> Result<Self, SshBootstrapError> {
        let windows = run_ssh_command(
            destination,
            "cmd.exe /d /c \"echo satelle-platform-v1&&echo windows&&echo %PROCESSOR_ARCHITECTURE%\"",
        )?;
        if windows.status.success() {
            return Self::parse_probe(&windows.stdout);
        }

        let unix = run_ssh_command(
            destination,
            "sh -c 'printf \"satelle-platform-v1\\n\"; uname -s; uname -m; if [ \"$(uname -s)\" = Linux ]; then getconf GNU_LIBC_VERSION 2>/dev/null || true; fi'",
        )?;
        if !unix.status.success() {
            return Err(if unix.stderr.host_key_verification_failed() {
                SshBootstrapError::HostKeyVerificationRequired
            } else {
                SshBootstrapError::PlatformProbeFailed
            });
        }
        Self::parse_probe(&unix.stdout)
    }

    fn parse_probe(output: &[u8]) -> Result<Self, SshBootstrapError> {
        let output = std::str::from_utf8(output).map_err(|_| SshBootstrapError::InvalidProbe)?;
        let mut lines = output.lines().map(str::trim);
        if lines.next() != Some("satelle-platform-v1") {
            return Err(SshBootstrapError::InvalidProbe);
        }
        let system = lines.next().ok_or(SshBootstrapError::InvalidProbe)?;
        let architecture = lines.next().ok_or(SshBootstrapError::InvalidProbe)?;
        let libc = lines.next();
        if lines.next().is_some() {
            return Err(SshBootstrapError::InvalidProbe);
        }

        match (
            system.to_ascii_lowercase().as_str(),
            normalize_arch(architecture),
        ) {
            ("windows", Some(Architecture::Arm64)) => Ok(Self::WindowsArm64Msvc),
            ("windows", Some(Architecture::X64)) => Ok(Self::WindowsX64Msvc),
            ("darwin", Some(Architecture::Arm64)) => Ok(Self::DarwinArm64),
            ("darwin", Some(Architecture::X64)) => Ok(Self::DarwinX64),
            ("linux", Some(Architecture::Arm64)) if is_glibc(libc) => Ok(Self::LinuxArm64Gnu),
            ("linux", Some(Architecture::X64)) if is_glibc(libc) => Ok(Self::LinuxX64Gnu),
            _ => Err(SshBootstrapError::UnsupportedPlatform),
        }
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

    const fn is_windows(self) -> bool {
        matches!(self, Self::WindowsArm64Msvc | Self::WindowsX64Msvc)
    }

    const fn archive_extension(self) -> &'static str {
        if self.is_windows() { "zip" } else { "tar.gz" }
    }

    const fn executable_name(self) -> &'static str {
        if self.is_windows() {
            "satelle.exe"
        } else {
            "satelle"
        }
    }

    fn remote_directory(self) -> String {
        let version = env!("CARGO_PKG_VERSION");
        match self {
            Self::WindowsArm64Msvc | Self::WindowsX64Msvc => {
                format!("AppData/Local/Satelle/host/v{version}/{}", self.id())
            }
            Self::DarwinArm64 | Self::DarwinX64 => {
                format!("Library/Caches/Satelle/host/v{version}/{}", self.id())
            }
            Self::LinuxArm64Gnu | Self::LinuxX64Gnu => {
                format!(".cache/satelle/host/v{version}/{}", self.id())
            }
        }
    }

    fn create_directory_command(self, directory: &str) -> String {
        if self.is_windows() {
            format!("cmd.exe /d /c \"if not exist {directory} mkdir {directory}\"")
        } else {
            format!("sh -c 'umask 077; mkdir -p {directory}; chmod 700 {directory}'")
        }
    }

    fn promote_command(self, staged: &str, final_path: &str) -> String {
        if self.is_windows() {
            format!("cmd.exe /d /c \"move /y {staged} {final_path} >nul\"")
        } else {
            format!("sh -c 'mv -f {staged} {final_path}; chmod 700 {final_path}'")
        }
    }

    fn digest_command(self, staged: &str) -> String {
        match self {
            Self::WindowsArm64Msvc | Self::WindowsX64Msvc => format!(
                "powershell.exe -NoProfile -NonInteractive -Command \"(Get-FileHash -Algorithm SHA256 -LiteralPath '{staged}').Hash\""
            ),
            Self::DarwinArm64 | Self::DarwinX64 => {
                format!("sh -c 'shasum -a 256 {staged}'")
            }
            Self::LinuxArm64Gnu | Self::LinuxX64Gnu => {
                format!("sh -c 'sha256sum {staged}'")
            }
        }
    }

    fn start_command(self, remote_binary: &str) -> String {
        if self.is_windows() {
            format!("cmd.exe /d /c {remote_binary} host start --bootstrap-token-stdin --json")
        } else {
            format!("sh -c 'exec {remote_binary} host start --bootstrap-token-stdin --json'")
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Architecture {
    Arm64,
    X64,
}

fn normalize_arch(value: &str) -> Option<Architecture> {
    match value.to_ascii_lowercase().as_str() {
        "arm64" | "aarch64" => Some(Architecture::Arm64),
        "amd64" | "x64" | "x86_64" => Some(Architecture::X64),
        _ => None,
    }
}

fn is_glibc(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.to_ascii_lowercase().starts_with("glibc "))
}

struct DownloadedArtifact {
    _directory: TempDir,
    binary: PathBuf,
}

impl DownloadedArtifact {
    fn fetch(target: RemoteTarget) -> Result<Self, SshBootstrapError> {
        let version = env!("CARGO_PKG_VERSION");
        let filename = format!(
            "satelle-v{version}-{}.{}",
            target.id(),
            target.archive_extension()
        );
        let release_url = format!("{RELEASE_BASE_URL}/v{version}");
        let client = Client::builder()
            .timeout(DOWNLOAD_TIMEOUT)
            .user_agent(format!("satelle/{version}"))
            .build()
            .map_err(SshBootstrapError::Http)?;
        let manifest = client
            .get(format!("{release_url}/SHA256SUMS"))
            .send()
            .and_then(Response::error_for_status)
            .map_err(SshBootstrapError::Http)?;
        let manifest = read_response_bounded(manifest, MANIFEST_LIMIT)?;
        let expected_digest = manifest_digest(&manifest, &filename)?;

        let mut archive = NamedTempFile::new().map_err(SshBootstrapError::LocalFile)?;
        let mut response = client
            .get(format!("{release_url}/{filename}"))
            .send()
            .and_then(Response::error_for_status)
            .map_err(SshBootstrapError::Http)?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = response
                .read(&mut buffer)
                .map_err(SshBootstrapError::HttpBody)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(SshBootstrapError::ArchiveTooLarge)?;
            if total > ARCHIVE_LIMIT {
                return Err(SshBootstrapError::ArchiveTooLarge);
            }
            digest.update(&buffer[..count]);
            archive
                .write_all(&buffer[..count])
                .map_err(SshBootstrapError::LocalFile)?;
        }
        let actual_digest: [u8; 32] = digest.finalize().into();
        if actual_digest != expected_digest {
            return Err(SshBootstrapError::IntegrityMismatch);
        }
        archive.flush().map_err(SshBootstrapError::LocalFile)?;

        let directory = TempDir::new().map_err(SshBootstrapError::LocalFile)?;
        let binary = directory.path().join(target.executable_name());
        if target.is_windows() {
            extract_zip(archive.path(), target.executable_name(), &binary)?;
        } else {
            extract_tar_gz(archive.path(), target.executable_name(), &binary)?;
        }
        Ok(Self {
            _directory: directory,
            binary,
        })
    }

    fn path(&self) -> &Path {
        &self.binary
    }
}

fn read_response_bounded(mut response: Response, limit: u64) -> Result<Vec<u8>, SshBootstrapError> {
    let mut body = Vec::new();
    response
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut body)
        .map_err(SshBootstrapError::HttpBody)?;
    if body.len() as u64 > limit {
        return Err(SshBootstrapError::ManifestTooLarge);
    }
    Ok(body)
}

fn manifest_digest(manifest: &[u8], filename: &str) -> Result<[u8; 32], SshBootstrapError> {
    let manifest = std::str::from_utf8(manifest).map_err(|_| SshBootstrapError::InvalidManifest)?;
    let mut found = None;
    for line in manifest.lines() {
        let mut fields = line.split_whitespace();
        let Some(digest) = fields.next() else {
            continue;
        };
        let Some(candidate) = fields.next() else {
            continue;
        };
        if fields.next().is_some() || candidate.trim_start_matches('*') != filename {
            continue;
        }
        if found.is_some() || digest.len() != 64 {
            return Err(SshBootstrapError::InvalidManifest);
        }
        let mut decoded = [0_u8; 32];
        for (index, pair) in digest.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = decode_hex(pair).ok_or(SshBootstrapError::InvalidManifest)?;
        }
        found = Some(decoded);
    }
    found.ok_or(SshBootstrapError::MissingIntegrityEntry)
}

fn decode_hex(pair: &[u8]) -> Option<u8> {
    let high = (pair.first().copied()? as char).to_digit(16)?;
    let low = (pair.get(1).copied()? as char).to_digit(16)?;
    Some(((high << 4) | low) as u8)
}

fn extract_tar_gz(
    archive_path: &Path,
    executable_name: &str,
    destination: &Path,
) -> Result<(), SshBootstrapError> {
    let archive = File::open(archive_path).map_err(SshBootstrapError::LocalFile)?;
    let mut archive = tar::Archive::new(GzDecoder::new(archive));
    let mut found = false;
    for entry in archive.entries().map_err(SshBootstrapError::Archive)? {
        let mut entry = entry.map_err(SshBootstrapError::Archive)?;
        let path = entry.path().map_err(SshBootstrapError::Archive)?;
        if path == Path::new(executable_name) {
            if found || !entry.header().entry_type().is_file() {
                return Err(SshBootstrapError::InvalidArchive);
            }
            let mut output = File::create(destination).map_err(SshBootstrapError::LocalFile)?;
            io::copy(&mut entry, &mut output).map_err(SshBootstrapError::LocalFile)?;
            output.sync_all().map_err(SshBootstrapError::LocalFile)?;
            found = true;
        }
    }
    if !found
        || fs::metadata(destination)
            .map_err(SshBootstrapError::LocalFile)?
            .len()
            == 0
    {
        return Err(SshBootstrapError::InvalidArchive);
    }
    Ok(())
}

fn extract_zip(
    archive_path: &Path,
    executable_name: &str,
    destination: &Path,
) -> Result<(), SshBootstrapError> {
    let archive = File::open(archive_path).map_err(SshBootstrapError::LocalFile)?;
    let mut archive = zip::ZipArchive::new(archive).map_err(SshBootstrapError::Zip)?;
    let mut entry = archive
        .by_name(executable_name)
        .map_err(|_| SshBootstrapError::InvalidArchive)?;
    if entry.is_dir() || entry.size() == 0 {
        return Err(SshBootstrapError::InvalidArchive);
    }
    let mut output = File::create(destination).map_err(SshBootstrapError::LocalFile)?;
    io::copy(&mut entry, &mut output).map_err(SshBootstrapError::LocalFile)?;
    output.sync_all().map_err(SshBootstrapError::LocalFile)
}

fn upload_artifact(
    destination: &str,
    target: RemoteTarget,
    local_binary: &Path,
) -> Result<String, SshBootstrapError> {
    let local_digest = sha256_file(local_binary)?;
    let directory = target.remote_directory();
    let final_path = format!("{directory}/{}", target.executable_name());
    let staged = format!(
        "{directory}/.satelle-upload-{}",
        Uuid::now_v7().hyphenated()
    );
    let create = run_ssh_command(destination, &target.create_directory_command(&directory))?;
    require_success(create)?;

    let remote_spec = OsString::from(format!("{destination}:{staged}"));
    let copy = run_program(
        "scp",
        [
            OsStr::new("-q"),
            local_binary.as_os_str(),
            remote_spec.as_os_str(),
        ],
    )?;
    require_success(copy)?;

    let remote_digest = run_ssh_command(destination, &target.digest_command(&staged))?;
    if !remote_digest.status.success() {
        return Err(if remote_digest.stderr.host_key_verification_failed() {
            SshBootstrapError::HostKeyVerificationRequired
        } else {
            SshBootstrapError::RemoteOperationFailed
        });
    }
    if parse_digest_output(&remote_digest.stdout)? != local_digest {
        return Err(SshBootstrapError::UploadedIntegrityMismatch);
    }

    let promote = run_ssh_command(destination, &target.promote_command(&staged, &final_path))?;
    require_success(promote)?;
    Ok(final_path)
}

fn sha256_file(path: &Path) -> Result<[u8; 32], SshBootstrapError> {
    let mut file = File::open(path).map_err(SshBootstrapError::LocalFile)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(SshBootstrapError::LocalFile)?;
        if count == 0 {
            return Ok(digest.finalize().into());
        }
        digest.update(&buffer[..count]);
    }
}

fn parse_digest_output(output: &[u8]) -> Result<[u8; 32], SshBootstrapError> {
    let output = std::str::from_utf8(output).map_err(|_| SshBootstrapError::InvalidRemoteDigest)?;
    for token in output.split_whitespace() {
        if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            let mut decoded = [0_u8; 32];
            for (index, pair) in token.as_bytes().chunks_exact(2).enumerate() {
                decoded[index] = decode_hex(pair).ok_or(SshBootstrapError::InvalidRemoteDigest)?;
            }
            return Ok(decoded);
        }
    }
    Err(SshBootstrapError::InvalidRemoteDigest)
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: SshStderrClassification,
}

fn run_ssh_command(
    destination: &str,
    remote_command: &str,
) -> Result<CommandOutput, SshBootstrapError> {
    run_program(
        "ssh",
        [
            OsStr::new("-T"),
            OsStr::new(destination),
            OsStr::new(remote_command),
        ],
    )
}

fn run_program<const N: usize>(
    program: &str,
    arguments: [&OsStr; N],
) -> Result<CommandOutput, SshBootstrapError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(SshBootstrapError::SpawnSsh)?;
    let stdout = child
        .stdout
        .take()
        .expect("SSH stdout was configured as piped");
    let stderr = child
        .stderr
        .take()
        .expect("SSH stderr was configured as piped");
    let stdout_reader = thread::spawn(move || read_bounded(stdout, PROBE_OUTPUT_LIMIT));
    let stderr_reader = spawn_stderr_reader(stderr)?;
    let status = child.wait().map_err(SshBootstrapError::WaitSsh)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| SshBootstrapError::ReaderPanicked)??;
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn require_success(output: CommandOutput) -> Result<(), SshBootstrapError> {
    if output.status.success() {
        Ok(())
    } else if output.stderr.host_key_verification_failed() {
        Err(SshBootstrapError::HostKeyVerificationRequired)
    } else {
        Err(SshBootstrapError::RemoteOperationFailed)
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, SshBootstrapError> {
    let mut retained = Vec::new();
    reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut retained)
        .map_err(SshBootstrapError::ReadProcess)?;
    if retained.len() > limit {
        io::copy(&mut reader, &mut io::sink()).map_err(SshBootstrapError::ReadProcess)?;
        return Err(SshBootstrapError::ProcessOutputTooLarge);
    }
    Ok(retained)
}

fn drain_bootstrap_stdout(
    stdout: ChildStdout,
    ready_sender: mpsc::SyncSender<Result<HostStartReady, SshBootstrapError>>,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::new();
    let parsed = match reader
        .by_ref()
        .take(START_OUTPUT_LIMIT + 1)
        .read_until(b'\n', &mut line)
    {
        Ok(_) if line.len() as u64 <= START_OUTPUT_LIMIT && line.ends_with(b"\n") => {
            serde_json::from_slice::<HostStartReady>(&line)
                .map_err(|_| SshBootstrapError::InvalidStartResponse)
        }
        Ok(_) => Err(SshBootstrapError::ProcessOutputTooLarge),
        Err(error) => Err(SshBootstrapError::ReadProcess(error)),
    };
    let _ = ready_sender.send(parsed);
    let _ = io::copy(&mut reader, &mut io::sink());
}

#[derive(Deserialize)]
struct HostStartReady {
    running: bool,
    bind: String,
}

fn spawn_stderr_reader(
    stderr: ChildStderr,
) -> Result<JoinHandle<SshStderrClassification>, SshBootstrapError> {
    thread::Builder::new()
        .name("satelle-ssh-bootstrap-stderr".to_string())
        .spawn(move || classify_stderr(stderr))
        .map_err(SshBootstrapError::ReaderThread)
}

fn terminate_child(child: &mut Child, error: SshBootstrapError) -> SshBootstrapError {
    let _ = child.kill();
    let _ = child.wait();
    error
}

#[derive(Debug, Error)]
pub(super) enum SshBootstrapError {
    #[error("system OpenSSH Host-key verification is required")]
    HostKeyVerificationRequired,
    #[error("could not start a system OpenSSH process")]
    SpawnSsh(#[source] io::Error),
    #[error("could not wait for a system OpenSSH process")]
    WaitSsh(#[source] io::Error),
    #[error("could not inspect the SSH bootstrap process")]
    InspectSsh(#[source] io::Error),
    #[error("could not start an SSH output reader")]
    ReaderThread(#[source] io::Error),
    #[error("an SSH output reader stopped unexpectedly")]
    ReaderPanicked,
    #[error("could not read SSH process output")]
    ReadProcess(#[source] io::Error),
    #[error("SSH process output exceeded its protocol limit")]
    ProcessOutputTooLarge,
    #[error("could not write the bootstrap token to daemon stdin")]
    WriteToken(#[source] io::Error),
    #[error("the remote platform probe failed")]
    PlatformProbeFailed,
    #[error("the remote platform probe returned an invalid response")]
    InvalidProbe,
    #[error("the remote platform is not supported by an MVP Host artifact")]
    UnsupportedPlatform,
    #[error("the release artifact request failed")]
    Http(#[source] reqwest::Error),
    #[error("the release artifact body could not be read")]
    HttpBody(#[source] io::Error),
    #[error("the release integrity manifest exceeded its size limit")]
    ManifestTooLarge,
    #[error("the release archive exceeded its size limit")]
    ArchiveTooLarge,
    #[error("the release integrity manifest is invalid")]
    InvalidManifest,
    #[error("the release integrity manifest does not contain the selected artifact")]
    MissingIntegrityEntry,
    #[error("the selected release artifact failed SHA-256 verification")]
    IntegrityMismatch,
    #[error("the uploaded Host binary failed SHA-256 verification")]
    UploadedIntegrityMismatch,
    #[error("the remote Host returned an invalid SHA-256 result")]
    InvalidRemoteDigest,
    #[error("the release archive is invalid")]
    InvalidArchive,
    #[error("the release archive could not be read")]
    Archive(#[source] io::Error),
    #[error("the Windows release archive could not be read")]
    Zip(#[source] zip::result::ZipError),
    #[error("a local bootstrap artifact file operation failed")]
    LocalFile(#[source] io::Error),
    #[error("a remote bootstrap operation failed")]
    RemoteOperationFailed,
    #[error("the on-demand Host Daemon did not become ready in time")]
    StartTimedOut,
    #[error("the on-demand Host Daemon returned an invalid startup response")]
    InvalidStartResponse,
    #[error("the on-demand Host Daemon exited before it became usable")]
    DaemonExited,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_protocol_maps_the_six_release_targets() {
        for (protocol, target) in [
            (
                b"satelle-platform-v1\nLinux\naarch64\nglibc 2.39\n".as_slice(),
                RemoteTarget::LinuxArm64Gnu,
            ),
            (
                b"satelle-platform-v1\nLinux\nx86_64\nglibc 2.35\n".as_slice(),
                RemoteTarget::LinuxX64Gnu,
            ),
            (
                b"satelle-platform-v1\nDarwin\narm64\n".as_slice(),
                RemoteTarget::DarwinArm64,
            ),
            (
                b"satelle-platform-v1\nDarwin\nx86_64\n".as_slice(),
                RemoteTarget::DarwinX64,
            ),
            (
                b"satelle-platform-v1\nwindows\nARM64\n".as_slice(),
                RemoteTarget::WindowsArm64Msvc,
            ),
            (
                b"satelle-platform-v1\nwindows\nAMD64\n".as_slice(),
                RemoteTarget::WindowsX64Msvc,
            ),
        ] {
            assert_eq!(RemoteTarget::parse_probe(protocol).unwrap(), target);
        }
    }

    #[test]
    fn release_manifest_selects_one_exact_archive_digest() {
        let digest = "11".repeat(32);
        let manifest = format!("{digest}  satelle-v0.1.0-linux-x64-gnu.tar.gz\n");
        assert_eq!(
            manifest_digest(manifest.as_bytes(), "satelle-v0.1.0-linux-x64-gnu.tar.gz").unwrap(),
            [0x11; 32]
        );
    }

    #[test]
    fn remote_copy_digest_accepts_platform_command_output() {
        assert_eq!(
            parse_digest_output(
                b"1111111111111111111111111111111111111111111111111111111111111111  satelle\n"
            )
            .unwrap(),
            [0x11; 32]
        );
    }
}
