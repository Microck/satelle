use flate2::read::GzDecoder;
use reqwest::blocking::{Client, Response};
use satelle_core::{DaemonPathOverrides, HostConfig};
use satelle_host::{ApiBearerToken, readiness_probe_timeouts};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use uuid::Uuid;

use super::ssh_tunnel::{SshStderrClassification, classify_stderr};
use super::{SSH_BOOTSTRAP_LOCK_READY, SshBootstrapScope};

const PROBE_OUTPUT_LIMIT: usize = 4096;
const TAILSCALE_SERVE_STATUS_OUTPUT_LIMIT: usize = 1024 * 1024;
const START_OUTPUT_LIMIT: u64 = 16 * 1024;
const MANIFEST_LIMIT: u64 = 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const BOOTSTRAP_LOCK_EXIT_GRACE: Duration = Duration::from_millis(500);
const BOOTSTRAP_LOCK_EXIT_POLL: Duration = Duration::from_millis(10);
const RELEASE_BASE_URL: &str = "https://github.com/Microck/satelle/releases/download";
const DAEMON_PATH_ENVIRONMENT_VARIABLES: [&str; 5] = [
    "SATELLE_HOME",
    "SATELLE_CONFIG_FILE",
    "SATELLE_STATE_DIR",
    "SATELLE_CACHE_DIR",
    "SATELLE_LOG_DIR",
];
pub(super) struct SshBootstrapLock {
    child: Child,
    stdin: Option<ChildStdin>,
    response_receiver: mpsc::Receiver<String>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<SshStderrClassification>>,
    _helper: StagedRemoteArtifact,
}

impl SshBootstrapLock {
    pub(super) fn acquire(destination: &str) -> Result<Self, SshBootstrapError> {
        let target = RemoteTarget::probe(destination)?;
        let artifact = DownloadedArtifact::fetch(target)?;
        // The helper is copied to a unique path before locking. No shared
        // remote file is replaced until this process holds the OS file lock.
        let helper = stage_artifact(destination, target, artifact.path())?;
        let mut child = Command::new("ssh")
            .arg("-T")
            .arg(destination)
            .arg(target.bootstrap_lock_command(helper.path()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(SshBootstrapError::SpawnSsh)?;
        let stdin = child
            .stdin
            .take()
            .expect("bootstrap-lock SSH stdin was configured as piped");
        let stdout = child
            .stdout
            .take()
            .expect("bootstrap-lock SSH stdout was configured as piped");
        let stderr = child
            .stderr
            .take()
            .expect("bootstrap-lock SSH stderr was configured as piped");
        let stderr_reader = spawn_stderr_reader(stderr)?;
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (response_sender, response_receiver) = mpsc::channel();
        let stdout_reader = thread::Builder::new()
            .name("satelle-ssh-bootstrap-lock-stdout".to_string())
            .spawn(move || drain_bootstrap_lock_stdout(stdout, ready_sender, response_sender))
            .map_err(|error| terminate_child(&mut child, SshBootstrapError::ReaderThread(error)))?;

        let ready = match ready_receiver.recv_timeout(PROCESS_TIMEOUT) {
            Ok(ready) => ready,
            Err(_) => {
                let error = terminate_child(&mut child, SshBootstrapError::BootstrapLockTimedOut);
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(error);
            }
        };
        if let Err(error) = ready {
            let error = terminate_child(&mut child, error);
            let _ = stdout_reader.join();
            let classification = stderr_reader.join().unwrap_or_default();
            return Err(classify_bootstrap_lock_ready_error(error, classification));
        }
        if child
            .try_wait()
            .map_err(SshBootstrapError::InspectSsh)?
            .is_some()
        {
            let _ = stdout_reader.join();
            let classification = stderr_reader.join().unwrap_or_default();
            return Err(if classification.host_key_verification_failed() {
                SshBootstrapError::HostKeyVerificationRequired
            } else {
                SshBootstrapError::RemoteOperationFailed
            });
        }

        Ok(Self {
            child,
            stdin: Some(stdin),
            response_receiver,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            _helper: helper,
        })
    }

    pub(super) fn confirm_ownership(&mut self) -> Result<(), SshBootstrapError> {
        if self
            .child
            .try_wait()
            .map_err(SshBootstrapError::InspectSsh)?
            .is_some()
        {
            return Err(SshBootstrapError::BootstrapLockLost);
        }
        let challenge = format!("satelle-bootstrap-lock-{}", Uuid::now_v7());
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(SshBootstrapError::BootstrapLockLost)?;
        writeln!(stdin, "{challenge}")
            .and_then(|()| stdin.flush())
            .map_err(SshBootstrapError::BootstrapLockProtocol)?;
        match self.response_receiver.recv_timeout(PROCESS_TIMEOUT) {
            Ok(response) if response == challenge => Ok(()),
            Ok(_) => Err(SshBootstrapError::InvalidBootstrapLockResponse),
            Err(_) => Err(SshBootstrapError::BootstrapLockLost),
        }
    }
}

impl Drop for SshBootstrapLock {
    fn drop(&mut self) {
        drop(self.stdin.take());
        // EOF lets the remote helper release bootstrap.lock and unmap its
        // staged executable before cleanup. This matters on Windows, where a
        // running executable cannot be deleted.
        let deadline = Instant::now() + BOOTSTRAP_LOCK_EXIT_GRACE;
        let exited = loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break true,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(BOOTSTRAP_LOCK_EXIT_POLL);
                }
                Ok(None) | Err(_) => break false,
            }
        };
        if !exited {
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

pub(super) struct SshBootstrapProcess {
    child: Child,
    remote_addr: SocketAddr,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<SshStderrClassification>>,
}

impl SshBootstrapProcess {
    pub(super) fn launch(
        destination: &str,
        token: &ApiBearerToken,
        host_config: &HostConfig,
        bootstrap_scope: SshBootstrapScope,
    ) -> Result<Self, SshBootstrapError> {
        Self::launch_bound(
            destination,
            token,
            host_config,
            bootstrap_scope,
            "127.0.0.1:3001",
            Some(3001),
            None,
        )
    }

    pub(super) fn launch_ephemeral(
        destination: &str,
        token: &ApiBearerToken,
        host_config: &HostConfig,
        previous_host_config: &HostConfig,
        bootstrap_scope: SshBootstrapScope,
    ) -> Result<Self, SshBootstrapError> {
        Self::launch_bound(
            destination,
            token,
            host_config,
            bootstrap_scope,
            "127.0.0.1:0",
            None,
            Some(previous_host_config),
        )
    }

    fn launch_bound(
        destination: &str,
        token: &ApiBearerToken,
        host_config: &HostConfig,
        bootstrap_scope: SshBootstrapScope,
        bind: &str,
        expected_port: Option<u16>,
        release_host_config: Option<&HostConfig>,
    ) -> Result<Self, SshBootstrapError> {
        let target = RemoteTarget::probe(destination)?;
        let environment = target.validated_daemon_environment(host_config)?;
        let release_environment = release_host_config
            .map(|previous_host_config| target.validated_daemon_environment(previous_host_config))
            .transpose()?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let remote_binary = upload_artifact(destination, target, artifact.path())?;
        let (release_command, start_command) = target.state_owner_handoff_commands(
            &remote_binary,
            release_environment.as_deref(),
            host_config,
            &environment,
            bootstrap_scope,
            bind,
        );
        if let Some(release_command) = release_command {
            require_success(run_ssh_command(destination, &release_command)?)?;
        }
        Self::spawn(destination, start_command, Some(token), expected_port)
    }

    pub(super) const fn remote_port(&self) -> u16 {
        self.remote_addr.port()
    }

    pub(super) fn launch_durable(
        destination: &str,
        idle_timeout: Duration,
        host_config: &HostConfig,
    ) -> Result<(), SshBootstrapError> {
        let target = RemoteTarget::probe(destination)?;
        let environment = target.validated_daemon_environment(host_config)?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let remote_binary = upload_artifact(destination, target, artifact.path())?;
        let (native_timeout, provider_timeout) = readiness_probe_timeouts(host_config);
        let command = target.durable_start_command_with_environment(
            &remote_binary,
            idle_timeout,
            native_timeout,
            provider_timeout,
            &environment,
        );
        require_success(run_ssh_command(destination, &command)?)
    }

    fn spawn(
        destination: &str,
        start_command: String,
        token: Option<&ApiBearerToken>,
        expected_port: Option<u16>,
    ) -> Result<Self, SshBootstrapError> {
        let mut command = Command::new("ssh");
        command
            .arg("-T")
            .arg(destination)
            .arg(start_command)
            .stdin(if token.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(SshBootstrapError::SpawnSsh)?;
        if let Some(token) = token {
            let mut stdin = child
                .stdin
                .take()
                .expect("bootstrap SSH stdin was configured as piped");
            let raw_token = token.expose();
            stdin
                .write_all(raw_token.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|error| {
                    terminate_child(&mut child, SshBootstrapError::WriteToken(error))
                })?;
            drop(stdin);
        }

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
        let Some(remote_addr) = validated_start_address(&ready, expected_port) else {
            return Err(terminate_child(
                &mut child,
                SshBootstrapError::InvalidStartResponse,
            ));
        };
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
            remote_addr,
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
    fn state_owner_handoff_commands(
        self,
        remote_binary: &str,
        release_environment: Option<&[(&'static str, &Path)]>,
        host_config: &HostConfig,
        environment: &[(&'static str, &Path)],
        bootstrap_scope: SshBootstrapScope,
        bind: &str,
    ) -> (Option<String>, String) {
        let release_command = release_environment.map(|environment| {
            self.release_state_command_with_environment(remote_binary, environment)
        });
        let (native_timeout, provider_timeout) = readiness_probe_timeouts(host_config);
        let start_command = self.start_command_with_environment(
            remote_binary,
            bootstrap_scope,
            native_timeout,
            provider_timeout,
            bind,
            environment,
        );
        (release_command, start_command)
    }

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

    fn shared_executable_path(self, directory: &str) -> String {
        format!("{directory}/{}", self.executable_name())
    }

    fn promoted_executable_path(self, directory: &str, digest: &[u8; 32]) -> String {
        if !self.is_windows() {
            return self.shared_executable_path(directory);
        }

        // Windows does not allow replacing an executable image while a daemon
        // is running from it. A digest-addressed name is both immutable and
        // reusable, so setup never overwrites the live image or leaks one file
        // per retry.
        let mut digest_hex = String::with_capacity(64);
        for byte in digest {
            write!(&mut digest_hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        format!("{directory}/satelle-{digest_hex}.exe")
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

    fn bootstrap_lock_command(self, remote_binary: &str) -> String {
        if self.is_windows() {
            format!("cmd.exe /d /c {remote_binary} host bootstrap-lock")
        } else {
            format!("sh -c 'exec {remote_binary} host bootstrap-lock'")
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

    fn prepare_staged_command(self, staged: &str) -> Option<String> {
        (!self.is_windows()).then(|| format!("sh -c 'chmod 700 {staged}'"))
    }

    fn remove_staged_command(self, staged: &str) -> String {
        if self.is_windows() {
            format!("cmd.exe /d /c \"del /f /q {staged} >nul 2>nul\"")
        } else {
            format!("sh -c 'rm -f {staged}'")
        }
    }

    #[cfg(test)]
    fn start_command(
        self,
        remote_binary: &str,
        bootstrap_scope: SshBootstrapScope,
        native_timeout: Duration,
        provider_timeout: Duration,
        bind: &str,
    ) -> String {
        self.start_command_with_environment(
            remote_binary,
            bootstrap_scope,
            native_timeout,
            provider_timeout,
            bind,
            &[],
        )
    }

    fn start_command_with_environment(
        self,
        remote_binary: &str,
        bootstrap_scope: SshBootstrapScope,
        native_timeout: Duration,
        provider_timeout: Duration,
        bind: &str,
        environment: &[(&'static str, &Path)],
    ) -> String {
        let timeout_args = format!(
            "--bind {bind} --bootstrap-scope {} --bootstrap-native-readiness-timeout-ms {} --bootstrap-provider-smoke-timeout-ms {}",
            bootstrap_scope.as_cli_value(),
            native_timeout.as_millis(),
            provider_timeout.as_millis()
        );
        if self.is_windows() {
            let script = format!(
                "{}& {} host start --bootstrap-token-stdin {timeout_args} --json",
                powershell_environment(environment),
                powershell_quote(remote_binary),
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "{}exec {remote_binary} host start --bootstrap-token-stdin {timeout_args} --json",
                posix_environment(environment),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    #[cfg(test)]
    fn durable_start_command(
        self,
        remote_binary: &str,
        idle_timeout: Duration,
        native_timeout: Duration,
        provider_timeout: Duration,
    ) -> String {
        self.durable_start_command_with_environment(
            remote_binary,
            idle_timeout,
            native_timeout,
            provider_timeout,
            &[],
        )
    }

    fn validated_daemon_environment(
        self,
        host_config: &HostConfig,
    ) -> Result<Vec<(&'static str, &Path)>, SshBootstrapError> {
        let environment = daemon_environment(host_config);
        for (name, path) in &environment {
            self.validate_daemon_path(name, path)?;
        }
        Ok(environment)
    }

    fn validate_daemon_path_overrides(
        self,
        daemon_path_overrides: &DaemonPathOverrides,
    ) -> Result<(), SshBootstrapError> {
        for entry in daemon_path_overrides.entries() {
            let name = match (entry.environment_variable.as_str(), entry.source.as_str()) {
                ("SATELLE_HOME", "setup_flag") => "--daemon-home",
                ("SATELLE_CONFIG_FILE", "setup_flag") => "--daemon-config-file",
                ("SATELLE_STATE_DIR", "setup_flag") => "--daemon-state-dir",
                ("SATELLE_CACHE_DIR", "setup_flag") => "--daemon-cache-dir",
                ("SATELLE_LOG_DIR", "setup_flag") => "--daemon-log-dir",
                ("SATELLE_HOME", _) => "SATELLE_HOME",
                ("SATELLE_CONFIG_FILE", _) => "SATELLE_CONFIG_FILE",
                ("SATELLE_STATE_DIR", _) => "SATELLE_STATE_DIR",
                ("SATELLE_CACHE_DIR", _) => "SATELLE_CACHE_DIR",
                ("SATELLE_LOG_DIR", _) => "SATELLE_LOG_DIR",
                _ => unreachable!("DaemonPathOverrides exposes only canonical variables"),
            };
            self.validate_daemon_path(name, Path::new(&entry.value))?;
        }
        Ok(())
    }

    fn validate_daemon_path(
        self,
        name: &'static str,
        path: &Path,
    ) -> Result<(), SshBootstrapError> {
        let value = path.to_string_lossy();
        let absolute = if self.is_windows() {
            is_windows_absolute_path(&value)
        } else {
            value.starts_with('/')
        };
        if absolute && !value.starts_with('~') {
            return Ok(());
        }

        Err(SshBootstrapError::DaemonPathOverrideNotAbsolute {
            name,
            value: value.into_owned(),
        })
    }

    fn durable_start_command_with_environment(
        self,
        remote_binary: &str,
        idle_timeout: Duration,
        native_timeout: Duration,
        provider_timeout: Duration,
        environment: &[(&'static str, &Path)],
    ) -> String {
        let timeout_args = format!(
            "--on-demand-idle-timeout-ms {} --bootstrap-native-readiness-timeout-ms {} --bootstrap-provider-smoke-timeout-ms {}",
            idle_timeout.as_millis(),
            native_timeout.as_millis(),
            provider_timeout.as_millis()
        );
        if self.is_windows() {
            let script = format!(
                concat!(
                    "{}$binary = (Resolve-Path -LiteralPath {}).Path; ",
                    "$command = '\"' + $binary + '\" host start {} --json'; ",
                    "$environment = [System.Environment]::GetEnvironmentVariables('Process')",
                    ".GetEnumerator() | ForEach-Object {{ \"$($_.Key)=$($_.Value)\" }}; ",
                    "$startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly ",
                    "-Property @{{ EnvironmentVariables = @($environment) }}; ",
                    "$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create ",
                    "-Arguments @{{ CommandLine = $command; ",
                    "ProcessStartupInformation = $startup }}; ",
                    "if ($created.ReturnValue -ne 0) {{ exit $created.ReturnValue }}"
                ),
                powershell_environment(environment),
                powershell_quote(remote_binary),
                timeout_args,
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "{}nohup {remote_binary} host start {timeout_args} --json </dev/null >/dev/null 2>&1 &",
                posix_environment(environment),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    #[cfg(test)]
    fn release_state_command(self, remote_binary: &str) -> String {
        self.release_state_command_with_environment(remote_binary, &[])
    }

    fn release_state_command_with_environment(
        self,
        remote_binary: &str,
        environment: &[(&'static str, &Path)],
    ) -> String {
        if self.is_windows() {
            let script = format!(
                "{}& {} host release-state",
                powershell_environment(environment),
                powershell_quote(remote_binary),
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "{}exec {remote_binary} host release-state",
                posix_environment(environment),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    fn tailscale_serve_command(self, apply: bool) -> &'static str {
        match (self.is_windows(), apply) {
            (true, false) => "cmd.exe /d /c \"tailscale.exe serve status --json\"",
            (true, true) => concat!(
                "cmd.exe /d /c \"tailscale.exe serve --bg --yes --https 443 ",
                "http://127.0.0.1:3001 >nul\""
            ),
            (false, false) => "sh -c 'exec tailscale serve status --json'",
            (false, true) => concat!(
                "sh -c 'exec tailscale serve --bg --yes --https 443 ",
                "http://127.0.0.1:3001 >/dev/null'"
            ),
        }
    }

    fn tailscale_service_config_command(self) -> &'static str {
        if self.is_windows() {
            "cmd.exe /d /c \"tailscale.exe serve get-config --all\""
        } else {
            "sh -c 'exec tailscale serve get-config --all'"
        }
    }
}

fn daemon_environment(host_config: &HostConfig) -> Vec<(&'static str, &Path)> {
    [
        ("SATELLE_HOME", host_config.daemon_home.as_deref()),
        (
            "SATELLE_CONFIG_FILE",
            host_config.daemon_config_file.as_deref(),
        ),
        ("SATELLE_STATE_DIR", host_config.daemon_state_dir.as_deref()),
        ("SATELLE_CACHE_DIR", host_config.daemon_cache_dir.as_deref()),
        ("SATELLE_LOG_DIR", host_config.daemon_log_dir.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, path)| path.map(|path| (name, path)))
    .collect()
}

fn is_windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    if drive_absolute {
        return true;
    }

    let Some(remainder) = value
        .strip_prefix("\\\\")
        .or_else(|| value.strip_prefix("//"))
    else {
        return false;
    };
    let mut components = remainder.split(['/', '\\']);
    components.next().is_some_and(|server| !server.is_empty())
        && components.next().is_some_and(|share| !share.is_empty())
}

fn posix_environment(environment: &[(&'static str, &Path)]) -> String {
    let mut script = format!("unset {}; ", DAEMON_PATH_ENVIRONMENT_VARIABLES.join(" "));
    for (name, value) in environment {
        write!(script, "{name}={} ", posix_quote(&value.to_string_lossy()))
            .expect("writing to String cannot fail");
    }
    script
}

fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn powershell_environment(environment: &[(&'static str, &Path)]) -> String {
    let mut script = String::new();
    for name in DAEMON_PATH_ENVIRONMENT_VARIABLES {
        write!(
            script,
            "[System.Environment]::SetEnvironmentVariable('{name}', $null, 'Process'); "
        )
        .expect("writing to String cannot fail");
    }
    for (name, value) in environment {
        write!(
            script,
            "$env:{name} = {}; ",
            powershell_quote(&value.to_string_lossy())
        )
        .expect("writing to String cannot fail");
    }
    script
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn powershell_encoded_command(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    format!(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand {}",
        encode_base64(&bytes)
    )
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[(first >> 2) as usize] as char);
        encoded.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(third & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

#[cfg(test)]
fn decode_powershell_command(command: &str) -> Option<String> {
    let encoded = command.rsplit_once(' ')?.1;
    let mut bytes = Vec::with_capacity(encoded.len() / 4 * 3);
    for chunk in encoded.as_bytes().chunks_exact(4) {
        let decode = |byte| match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        };
        let values = [
            decode(chunk[0]),
            decode(chunk[1]),
            decode(chunk[2]),
            decode(chunk[3]),
        ];
        let [Some(first), Some(second), Some(third), Some(fourth)] = values else {
            return None;
        };
        bytes.push((first << 2) | (second >> 4));
        if chunk[2] != b'=' {
            bytes.push((second << 4) | (third >> 2));
        }
        if chunk[3] != b'=' {
            bytes.push((third << 6) | fourth);
        }
    }
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

pub(super) fn probe_tailscale_serve(
    destination: &str,
    daemon_path_overrides: &DaemonPathOverrides,
) -> Result<(Vec<u8>, Vec<u8>), SshBootstrapError> {
    let target = RemoteTarget::probe(destination)?;
    target.validate_daemon_path_overrides(daemon_path_overrides)?;
    let status = run_tailscale_serve(destination, target, false)?;
    let services = require_success_output(run_ssh_command_with_output_limit(
        destination,
        target.tailscale_service_config_command(),
        TAILSCALE_SERVE_STATUS_OUTPUT_LIMIT,
    )?)?
    .stdout;
    Ok((status, services))
}

pub(super) fn apply_tailscale_serve(destination: &str) -> Result<(), SshBootstrapError> {
    let target = RemoteTarget::probe(destination)?;
    run_tailscale_serve(destination, target, true).map(drop)
}

fn run_tailscale_serve(
    destination: &str,
    target: RemoteTarget,
    apply: bool,
) -> Result<Vec<u8>, SshBootstrapError> {
    let output_limit = if apply {
        PROBE_OUTPUT_LIMIT
    } else {
        TAILSCALE_SERVE_STATUS_OUTPUT_LIMIT
    };
    require_success_output(run_ssh_command_with_output_limit(
        destination,
        target.tailscale_serve_command(apply),
        output_limit,
    )?)
    .map(|output| output.stdout)
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
    let shared_path = target.shared_executable_path(&directory);
    let final_path = if target.is_windows() {
        if remote_artifact_matches(destination, target, &shared_path, &local_digest)? {
            return Ok(shared_path);
        }
        let content_addressed_path = target.promoted_executable_path(&directory, &local_digest);
        if remote_artifact_matches(destination, target, &content_addressed_path, &local_digest)? {
            return Ok(content_addressed_path);
        }
        content_addressed_path
    } else {
        shared_path
    };
    let staged = stage_artifact_with_digest(destination, target, local_binary, local_digest)?;
    let promote = run_ssh_command(
        destination,
        &target.promote_command(staged.path(), &final_path),
    )?;
    require_success(promote)?;
    Ok(final_path)
}

fn remote_artifact_matches(
    destination: &str,
    target: RemoteTarget,
    remote_path: &str,
    expected_digest: &[u8; 32],
) -> Result<bool, SshBootstrapError> {
    let digest = run_ssh_command(destination, &target.digest_command(remote_path))?;
    if !digest.status.success() {
        return if digest.stderr.host_key_verification_failed() {
            Err(SshBootstrapError::HostKeyVerificationRequired)
        } else {
            Ok(false)
        };
    }
    Ok(parse_digest_output(&digest.stdout).is_ok_and(|digest| digest == *expected_digest))
}

struct StagedRemoteArtifact {
    destination: String,
    target: RemoteTarget,
    path: String,
}

impl StagedRemoteArtifact {
    fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for StagedRemoteArtifact {
    fn drop(&mut self) {
        let attempts = if self.target.is_windows() { 3 } else { 1 };
        for attempt in 0..attempts {
            if run_ssh_command(
                &self.destination,
                &self.target.remove_staged_command(&self.path),
            )
            .is_ok_and(|output| output.status.success())
            {
                return;
            }
            if attempt + 1 < attempts {
                thread::sleep(BOOTSTRAP_LOCK_EXIT_POLL);
            }
        }
    }
}

fn stage_artifact(
    destination: &str,
    target: RemoteTarget,
    local_binary: &Path,
) -> Result<StagedRemoteArtifact, SshBootstrapError> {
    let local_digest = sha256_file(local_binary)?;
    stage_artifact_with_digest(destination, target, local_binary, local_digest)
}

fn stage_artifact_with_digest(
    destination: &str,
    target: RemoteTarget,
    local_binary: &Path,
    local_digest: [u8; 32],
) -> Result<StagedRemoteArtifact, SshBootstrapError> {
    let directory = target.remote_directory();
    let staged_suffix = if target.is_windows() { ".exe" } else { "" };
    // Own cleanup before the first remote mutation. Every later failure,
    // including directory creation and SCP, then attempts to remove the
    // staging path without changing the original error.
    let staged = StagedRemoteArtifact {
        destination: destination.to_string(),
        target,
        path: format!(
            "{directory}/.satelle-upload-{}{staged_suffix}",
            Uuid::now_v7().hyphenated()
        ),
    };
    let create = run_ssh_command(destination, &target.create_directory_command(&directory))?;
    require_success(create)?;

    let remote_spec = OsString::from(format!("{destination}:{}", staged.path()));
    let copy = run_program(
        "scp",
        [
            OsStr::new("-q"),
            local_binary.as_os_str(),
            remote_spec.as_os_str(),
        ],
    )?;
    require_success(copy)?;

    let remote_digest = run_ssh_command(destination, &target.digest_command(staged.path()))?;
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
    if let Some(command) = target.prepare_staged_command(staged.path()) {
        require_success(run_ssh_command(destination, &command)?)?;
    }
    Ok(staged)
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
    run_ssh_command_with_output_limit(destination, remote_command, PROBE_OUTPUT_LIMIT)
}

fn run_ssh_command_with_output_limit(
    destination: &str,
    remote_command: &str,
    output_limit: usize,
) -> Result<CommandOutput, SshBootstrapError> {
    run_program_with_output_limit(
        "ssh",
        [
            OsStr::new("-T"),
            OsStr::new(destination),
            OsStr::new(remote_command),
        ],
        output_limit,
    )
}

fn run_program<const N: usize>(
    program: &str,
    arguments: [&OsStr; N],
) -> Result<CommandOutput, SshBootstrapError> {
    run_program_with_output_limit(program, arguments, PROBE_OUTPUT_LIMIT)
}

fn run_program_with_output_limit<const N: usize>(
    program: &str,
    arguments: [&OsStr; N],
    output_limit: usize,
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
    let stdout_reader = thread::spawn(move || read_bounded(stdout, output_limit));
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
    require_success_output(output).map(drop)
}

fn require_success_output(output: CommandOutput) -> Result<CommandOutput, SshBootstrapError> {
    if output.status.success() {
        Ok(output)
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

fn drain_bootstrap_lock_stdout(
    stdout: ChildStdout,
    ready_sender: mpsc::SyncSender<Result<(), SshBootstrapError>>,
    response_sender: mpsc::Sender<String>,
) {
    let mut reader = BufReader::new(stdout);
    let ready = read_bootstrap_lock_ready(&mut reader);
    let valid = ready.is_ok();
    let _ = ready_sender.send(ready);
    if !valid {
        return;
    }
    for line in reader.lines() {
        let Ok(line) = line else {
            return;
        };
        if response_sender.send(line).is_err() {
            return;
        }
    }
}

fn read_bootstrap_lock_ready(reader: &mut impl BufRead) -> Result<(), SshBootstrapError> {
    let mut ready = String::new();
    reader
        .take(128)
        .read_line(&mut ready)
        .map_err(SshBootstrapError::ReadProcess)?;
    if ready.trim_end() == SSH_BOOTSTRAP_LOCK_READY {
        Ok(())
    } else {
        Err(SshBootstrapError::InvalidBootstrapLockResponse)
    }
}

#[derive(Deserialize)]
struct HostStartReady {
    running: bool,
    bind: String,
}

fn validated_start_address(
    ready: &HostStartReady,
    expected_port: Option<u16>,
) -> Option<SocketAddr> {
    let address = ready.bind.parse::<SocketAddr>().ok()?;
    (ready.running
        && address.ip().is_loopback()
        && address.port() != 0
        && expected_port.is_none_or(|port| address.port() == port))
    .then_some(address)
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

fn classify_bootstrap_lock_ready_error(
    error: SshBootstrapError,
    classification: SshStderrClassification,
) -> SshBootstrapError {
    if classification.host_key_verification_failed() {
        SshBootstrapError::HostKeyVerificationRequired
    } else {
        error
    }
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
    #[error("{name} is not an absolute path for the detected remote platform")]
    DaemonPathOverrideNotAbsolute { name: &'static str, value: String },
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
    #[error("timed out acquiring the remote SSH bootstrap lock")]
    BootstrapLockTimedOut,
    #[error("the remote SSH bootstrap lock was lost")]
    BootstrapLockLost,
    #[error("could not exchange the remote SSH bootstrap lock challenge")]
    BootstrapLockProtocol(#[source] io::Error),
    #[error("the remote SSH bootstrap lock returned an invalid response")]
    InvalidBootstrapLockResponse,
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

    const POSIX_DAEMON_ENVIRONMENT_CLEAR: &str = concat!(
        "unset SATELLE_HOME SATELLE_CONFIG_FILE SATELLE_STATE_DIR ",
        "SATELLE_CACHE_DIR SATELLE_LOG_DIR; "
    );

    fn assert_powershell_clears_daemon_environment(script: &str) {
        for name in DAEMON_PATH_ENVIRONMENT_VARIABLES {
            assert!(
                script.contains(&format!(
                    "[System.Environment]::SetEnvironmentVariable('{name}', $null, 'Process'); "
                )),
                "PowerShell command did not clear {name}: {script}"
            );
        }
    }

    fn assert_occurs_before(script: &str, first: &str, second: &str) {
        let first_index = script.find(first).expect("first command fragment");
        let second_index = script.find(second).expect("second command fragment");
        assert!(
            first_index < second_index,
            "{first:?} must precede {second:?}: {script}"
        );
    }

    #[test]
    fn windows_promotes_to_a_reusable_content_addressed_executable() {
        let digest = [0x1a; 32];
        assert_eq!(
            RemoteTarget::WindowsX64Msvc.promoted_executable_path("Satelle/host", &digest),
            format!("Satelle/host/satelle-{}.exe", "1a".repeat(32))
        );
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.promoted_executable_path(".cache/satelle", &digest),
            ".cache/satelle/satelle"
        );
    }

    #[test]
    fn bootstrap_lock_ready_error_preserves_host_key_classification() {
        let host_key_error = classify_bootstrap_lock_ready_error(
            SshBootstrapError::InvalidBootstrapLockResponse,
            classify_stderr(&b"Host key verification failed."[..]),
        );
        assert!(matches!(
            host_key_error,
            SshBootstrapError::HostKeyVerificationRequired
        ));

        let ordinary_error = classify_bootstrap_lock_ready_error(
            SshBootstrapError::InvalidBootstrapLockResponse,
            classify_stderr(&b"connection refused"[..]),
        );
        assert!(matches!(
            ordinary_error,
            SshBootstrapError::InvalidBootstrapLockResponse
        ));
    }

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
    fn remote_daemon_path_overrides_accept_windows_absolute_paths_for_windows_targets() {
        assert!(
            RemoteTarget::WindowsX64Msvc
                .validate_daemon_path("--daemon-state-dir", Path::new(r"C:\Satelle\State"))
                .is_ok()
        );
    }

    #[test]
    fn remote_daemon_path_overrides_reject_posix_paths_for_windows_targets() {
        let error = RemoteTarget::WindowsX64Msvc
            .validate_daemon_path("--daemon-state-dir", Path::new("/srv/satelle/state"))
            .expect_err("a POSIX absolute path is not absolute for a Windows Host");

        assert!(matches!(
            error,
            SshBootstrapError::DaemonPathOverrideNotAbsolute { name, value }
                if name == "--daemon-state-dir" && value == "/srv/satelle/state"
        ));
    }

    #[test]
    fn remote_daemon_path_overrides_apply_posix_rules_to_linux_and_macos_targets() {
        for target in [RemoteTarget::LinuxX64Gnu, RemoteTarget::DarwinArm64] {
            assert!(
                target
                    .validate_daemon_path("--daemon-state-dir", Path::new("/srv/satelle/state"))
                    .is_ok()
            );
            assert!(
                target
                    .validate_daemon_path("--daemon-state-dir", Path::new(r"C:\Satelle\State"))
                    .is_err()
            );
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

    #[test]
    fn tailscale_serve_commands_are_static_incremental_and_os_aware() {
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.tailscale_serve_command(false),
            "sh -c 'exec tailscale serve status --json'"
        );
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.tailscale_serve_command(true),
            concat!(
                "sh -c 'exec tailscale serve --bg --yes --https 443 ",
                "http://127.0.0.1:3001 >/dev/null'"
            )
        );
        assert_eq!(
            RemoteTarget::WindowsX64Msvc.tailscale_serve_command(true),
            concat!(
                "cmd.exe /d /c \"tailscale.exe serve --bg --yes --https 443 ",
                "http://127.0.0.1:3001 >nul\""
            )
        );
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.tailscale_service_config_command(),
            "sh -c 'exec tailscale serve get-config --all'"
        );
        assert_eq!(
            RemoteTarget::WindowsX64Msvc.tailscale_service_config_command(),
            "cmd.exe /d /c \"tailscale.exe serve get-config --all\""
        );
    }

    #[test]
    fn bootstrap_start_commands_forward_resolved_readiness_timeouts() {
        let native = Duration::from_millis(2_500);
        let provider = Duration::from_millis(7_500);
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.start_command(
                "/tmp/satelle",
                SshBootstrapScope::Read,
                native,
                provider,
                "127.0.0.1:3001",
            ),
            concat!(
                "sh -c 'unset SATELLE_HOME SATELLE_CONFIG_FILE SATELLE_STATE_DIR ",
                "SATELLE_CACHE_DIR SATELLE_LOG_DIR; ",
                "exec /tmp/satelle host start --bootstrap-token-stdin ",
                "--bind 127.0.0.1:3001 ",
                "--bootstrap-scope read ",
                "--bootstrap-native-readiness-timeout-ms 2500 ",
                "--bootstrap-provider-smoke-timeout-ms 7500 --json'"
            )
        );
        let windows = RemoteTarget::WindowsX64Msvc.start_command(
            "satelle.exe",
            SshBootstrapScope::Control,
            native,
            provider,
            "127.0.0.1:0",
        );
        let script = decode_powershell_command(&windows).expect("decode foreground command");
        assert_powershell_clears_daemon_environment(&script);
        assert!(script.contains("host start --bootstrap-token-stdin"));
        assert!(script.contains("--bind 127.0.0.1:0"));
        assert!(script.contains("--bootstrap-scope control"));
        assert!(script.contains("--bootstrap-native-readiness-timeout-ms 2500"));
        assert!(script.contains("--bootstrap-provider-smoke-timeout-ms 7500"));
    }

    #[test]
    fn path_change_releases_the_old_owner_before_the_new_daemon_becomes_authoritative() {
        let mut host = HostConfig {
            transport: satelle_core::TransportKind::Ssh,
            adapter: satelle_core::AdapterKind::Codex,
            address: Some("operator@host".to_string()),
            network: None,
            timeouts: None,
            native_readiness_cache_ttl: None,
            provider_smoke_success_cache_ttl: None,
            provider_smoke_failure_cache_ttl: None,
            daemon_idle_timeout: None,
            desktop_user: None,
            desktop_session_preference: None,
            desktop_session_native_selector: None,
            daemon_home: Some(PathBuf::from("/srv/satelle home")),
            daemon_config_file: None,
            daemon_state_dir: Some(PathBuf::from("/srv/selected-state")),
            daemon_cache_dir: None,
            daemon_log_dir: None,
            setup_mode: None,
            experimental_provider_computer_use: None,
            yolo: None,
            allow_project_selection: false,
            expected_host_id: Some("host-test".to_string()),
            api_token: None,
            ca_bundle: None,
            provider_auth: std::collections::BTreeMap::new(),
        };
        let unix_environment = RemoteTarget::LinuxX64Gnu
            .validated_daemon_environment(&host)
            .expect("validate POSIX daemon paths");
        let unix = RemoteTarget::LinuxX64Gnu.start_command_with_environment(
            "/tmp/satelle",
            SshBootstrapScope::Control,
            Duration::from_secs(1),
            Duration::from_secs(2),
            "127.0.0.1:3001",
            &unix_environment,
        );
        assert!(unix.contains("SATELLE_HOME"));
        assert!(unix.contains("/srv/satelle home"));
        assert!(unix.contains("SATELLE_STATE_DIR"));
        assert!(unix.contains("/srv/satelle"));

        let mut previous_host = host.clone();
        previous_host.daemon_state_dir = Some(PathBuf::from("/srv/previous-state"));
        let previous_environment = RemoteTarget::LinuxX64Gnu
            .validated_daemon_environment(&previous_host)
            .expect("validate the prior state-owner paths");
        let (release, start) = RemoteTarget::LinuxX64Gnu.state_owner_handoff_commands(
            "/tmp/satelle",
            Some(&previous_environment),
            &host,
            &unix_environment,
            SshBootstrapScope::Admin,
            "127.0.0.1:0",
        );
        let release = release.expect("a setup bootstrap releases the prior state owner");
        assert!(release.contains("/srv/previous-state"));
        assert!(!release.contains("/srv/selected-state"));
        assert!(start.contains("/srv/selected-state"));
        assert!(!start.contains("/srv/previous-state"));
        assert!(start.contains("--bind 127.0.0.1:0"));

        host.daemon_home = Some(PathBuf::from(r"C:\Satelle Home"));
        host.daemon_state_dir = Some(PathBuf::from(r"C:\Satelle State"));
        let windows_environment = RemoteTarget::WindowsX64Msvc
            .validated_daemon_environment(&host)
            .expect("validate Windows daemon paths");
        let windows = RemoteTarget::WindowsX64Msvc.start_command_with_environment(
            "satelle.exe",
            SshBootstrapScope::Control,
            Duration::from_secs(1),
            Duration::from_secs(2),
            "127.0.0.1:3001",
            &windows_environment,
        );
        let script = decode_powershell_command(&windows).expect("decode PowerShell command");
        assert_powershell_clears_daemon_environment(&script);
        assert!(script.contains("$env:SATELLE_HOME = 'C:\\Satelle Home'"));
        assert!(script.contains("$env:SATELLE_STATE_DIR = 'C:\\Satelle State'"));
        assert_occurs_before(
            &script,
            "SetEnvironmentVariable('SATELLE_STATE_DIR'",
            "$env:SATELLE_STATE_DIR =",
        );
        assert!(!script.contains("$env:SATELLE_CONFIG_FILE ="));
        assert!(!script.contains("$env:SATELLE_CACHE_DIR ="));
        assert!(!script.contains("$env:SATELLE_LOG_DIR ="));
    }

    #[test]
    fn remote_daemon_path_environment_clears_inherited_values_for_foreground_commands() {
        let empty_posix = RemoteTarget::LinuxX64Gnu.start_command_with_environment(
            "/tmp/satelle",
            SshBootstrapScope::Control,
            Duration::from_secs(1),
            Duration::from_secs(2),
            "127.0.0.1:3001",
            &[],
        );
        assert!(empty_posix.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));

        let posix_environment = [("SATELLE_STATE_DIR", Path::new("/srv/satelle state"))];
        let configured_posix = RemoteTarget::LinuxX64Gnu.start_command_with_environment(
            "/tmp/satelle",
            SshBootstrapScope::Control,
            Duration::from_secs(1),
            Duration::from_secs(2),
            "127.0.0.1:3001",
            &posix_environment,
        );
        assert!(configured_posix.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));
        assert!(configured_posix.contains("SATELLE_STATE_DIR="));
        assert_occurs_before(
            &configured_posix,
            POSIX_DAEMON_ENVIRONMENT_CLEAR,
            "SATELLE_STATE_DIR=",
        );

        let empty_windows = RemoteTarget::WindowsX64Msvc.start_command_with_environment(
            "satelle.exe",
            SshBootstrapScope::Control,
            Duration::from_secs(1),
            Duration::from_secs(2),
            "127.0.0.1:3001",
            &[],
        );
        let empty_script =
            decode_powershell_command(&empty_windows).expect("decode empty foreground command");
        assert_powershell_clears_daemon_environment(&empty_script);

        let windows_environment = [("SATELLE_STATE_DIR", Path::new(r"C:\Satelle State"))];
        let configured_windows = RemoteTarget::WindowsX64Msvc.start_command_with_environment(
            "satelle.exe",
            SshBootstrapScope::Control,
            Duration::from_secs(1),
            Duration::from_secs(2),
            "127.0.0.1:3001",
            &windows_environment,
        );
        let configured_script = decode_powershell_command(&configured_windows)
            .expect("decode configured foreground command");
        assert_powershell_clears_daemon_environment(&configured_script);
        assert!(configured_script.contains("$env:SATELLE_STATE_DIR = 'C:\\Satelle State'"));
        assert_occurs_before(
            &configured_script,
            "SetEnvironmentVariable('SATELLE_STATE_DIR'",
            "$env:SATELLE_STATE_DIR =",
        );
    }

    #[test]
    fn bootstrap_start_response_accepts_an_allocated_ephemeral_loopback_port() {
        let ready = HostStartReady {
            running: true,
            bind: "127.0.0.1:43123".to_string(),
        };

        assert_eq!(
            validated_start_address(&ready, None),
            Some("127.0.0.1:43123".parse().unwrap())
        );
        assert_eq!(validated_start_address(&ready, Some(3001)), None);
    }

    #[test]
    fn bootstrap_lock_commands_run_the_staged_cross_platform_lock_helper() {
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.bootstrap_lock_command(".cache/satelle/helper"),
            "sh -c 'exec .cache/satelle/helper host bootstrap-lock'"
        );
        assert_eq!(
            RemoteTarget::DarwinArm64.bootstrap_lock_command("Library/Caches/Satelle/helper"),
            "sh -c 'exec Library/Caches/Satelle/helper host bootstrap-lock'"
        );
        assert_eq!(
            RemoteTarget::WindowsX64Msvc.bootstrap_lock_command("AppData/Local/Satelle/helper.exe"),
            "cmd.exe /d /c AppData/Local/Satelle/helper.exe host bootstrap-lock"
        );
    }

    #[test]
    fn setup_bootstrap_requests_state_release_with_the_promoted_binary() {
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.release_state_command(".cache/satelle/satelle"),
            concat!(
                "sh -c 'unset SATELLE_HOME SATELLE_CONFIG_FILE SATELLE_STATE_DIR ",
                "SATELLE_CACHE_DIR SATELLE_LOG_DIR; ",
                "exec .cache/satelle/satelle host release-state'"
            )
        );
        let windows =
            RemoteTarget::WindowsX64Msvc.release_state_command("AppData/Local/Satelle/satelle.exe");
        let script = decode_powershell_command(&windows).expect("decode release-state command");
        assert_powershell_clears_daemon_environment(&script);
        assert!(script.contains("& 'AppData/Local/Satelle/satelle.exe' host release-state"));
    }

    #[test]
    fn remote_daemon_path_environment_reaches_release_state_commands() {
        let empty_posix =
            RemoteTarget::LinuxX64Gnu.release_state_command_with_environment("/tmp/satelle", &[]);
        assert!(empty_posix.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));

        let posix_environment = [("SATELLE_STATE_DIR", Path::new("/srv/satelle state"))];
        let posix = RemoteTarget::LinuxX64Gnu
            .release_state_command_with_environment("/tmp/satelle", &posix_environment);
        assert!(posix.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));
        assert!(posix.contains("SATELLE_STATE_DIR"));
        assert!(posix.contains("/srv/satelle state"));
        assert!(posix.contains("host release-state"));

        let empty_windows = RemoteTarget::WindowsX64Msvc
            .release_state_command_with_environment("Satelle/satelle.exe", &[]);
        let empty_script =
            decode_powershell_command(&empty_windows).expect("decode empty release-state command");
        assert_powershell_clears_daemon_environment(&empty_script);

        let windows_environment = [("SATELLE_STATE_DIR", Path::new(r"C:\Satelle State"))];
        let windows = RemoteTarget::WindowsX64Msvc
            .release_state_command_with_environment("Satelle/satelle.exe", &windows_environment);
        let script = decode_powershell_command(&windows).expect("decode release-state command");
        assert_powershell_clears_daemon_environment(&script);
        assert!(script.contains("$env:SATELLE_STATE_DIR = 'C:\\Satelle State'"));
        assert_occurs_before(
            &script,
            "SetEnvironmentVariable('SATELLE_STATE_DIR'",
            "$env:SATELLE_STATE_DIR =",
        );
        assert!(script.contains("host release-state"));
    }

    #[test]
    fn remote_daemon_path_environment_is_embedded_in_posix_durable_launch() {
        let empty = RemoteTarget::LinuxX64Gnu.durable_start_command_with_environment(
            "/tmp/satelle",
            Duration::from_secs(75),
            Duration::from_millis(2_500),
            Duration::from_millis(7_500),
            &[],
        );
        assert!(empty.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));

        let environment = [("SATELLE_STATE_DIR", Path::new("/srv/satelle state"))];
        let configured = RemoteTarget::LinuxX64Gnu.durable_start_command_with_environment(
            "/tmp/satelle",
            Duration::from_secs(75),
            Duration::from_millis(2_500),
            Duration::from_millis(7_500),
            &environment,
        );
        assert!(configured.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));
        assert!(configured.contains("SATELLE_STATE_DIR="));
        assert_occurs_before(
            &configured,
            POSIX_DAEMON_ENVIRONMENT_CLEAR,
            "SATELLE_STATE_DIR=",
        );
        assert!(configured.contains("/srv/satelle state"));
        assert!(configured.contains("nohup /tmp/satelle host start"));
    }

    #[test]
    fn remote_daemon_path_environment_is_embedded_in_windows_durable_launch() {
        let empty = RemoteTarget::WindowsX64Msvc.durable_start_command_with_environment(
            "Satelle/satelle.exe",
            Duration::from_secs(75),
            Duration::from_millis(2_500),
            Duration::from_millis(7_500),
            &[],
        );
        let empty_script = decode_powershell_command(&empty).expect("decode empty WMI launcher");
        assert_powershell_clears_daemon_environment(&empty_script);

        let environment = [("SATELLE_STATE_DIR", Path::new(r"C:\Satelle State"))];
        let command = RemoteTarget::WindowsX64Msvc.durable_start_command_with_environment(
            "Satelle/satelle.exe",
            Duration::from_secs(75),
            Duration::from_millis(2_500),
            Duration::from_millis(7_500),
            &environment,
        );
        let detached_script = decode_powershell_command(&command).expect("decode WMI launcher");

        assert_powershell_clears_daemon_environment(&detached_script);
        assert!(detached_script.contains("$env:SATELLE_STATE_DIR = 'C:\\Satelle State'"));
        assert_occurs_before(
            &detached_script,
            "SetEnvironmentVariable('SATELLE_STATE_DIR'",
            "$env:SATELLE_STATE_DIR =",
        );
        assert!(detached_script.contains("Win32_ProcessStartup"));
        assert!(detached_script.contains("EnvironmentVariables = @($environment)"));
        assert!(detached_script.contains("ProcessStartupInformation = $startup"));
        assert!(detached_script.contains("host start"));
    }

    #[test]
    fn durable_start_commands_detach_and_forward_the_resolved_timeouts() {
        let idle_timeout = Duration::from_secs(75);
        let native_timeout = Duration::from_millis(2_500);
        let provider_timeout = Duration::from_millis(7_500);
        assert_eq!(
            RemoteTarget::LinuxX64Gnu.durable_start_command(
                "/tmp/satelle",
                idle_timeout,
                native_timeout,
                provider_timeout,
            ),
            concat!(
                "sh -c 'unset SATELLE_HOME SATELLE_CONFIG_FILE SATELLE_STATE_DIR ",
                "SATELLE_CACHE_DIR SATELLE_LOG_DIR; ",
                "nohup /tmp/satelle host start --on-demand-idle-timeout-ms 75000 ",
                "--bootstrap-native-readiness-timeout-ms 2500 ",
                "--bootstrap-provider-smoke-timeout-ms 7500 --json ",
                "</dev/null >/dev/null 2>&1 &'"
            )
        );
        let windows = RemoteTarget::WindowsX64Msvc.durable_start_command(
            "AppData/Local/Satelle/satelle.exe",
            idle_timeout,
            native_timeout,
            provider_timeout,
        );
        let script = decode_powershell_command(&windows).expect("decode durable command");
        assert_powershell_clears_daemon_environment(&script);
        assert!(script.contains("--on-demand-idle-timeout-ms 75000"));
        assert!(script.contains("--bootstrap-native-readiness-timeout-ms 2500"));
        assert!(script.contains("--bootstrap-provider-smoke-timeout-ms 7500"));
        assert!(script.contains("ProcessStartupInformation = $startup"));
    }
}
