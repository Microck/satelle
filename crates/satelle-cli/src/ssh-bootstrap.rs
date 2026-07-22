use flate2::read::GzDecoder;
use reqwest::blocking::{Client, Response};
use satelle_core::{DaemonPathOverrides, HostConfig};
use satelle_host::{ApiBearerToken, readiness_probe_timeouts};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use uuid::Uuid;

use super::SshBootstrapScope;
use super::bootstrap_lock;
use super::ssh_tunnel::{SshStderrClassification, classify_stderr};

const PROBE_OUTPUT_LIMIT: usize = 4096;
const TAILSCALE_SERVE_STATUS_OUTPUT_LIMIT: usize = 1024 * 1024;
const START_OUTPUT_LIMIT: u64 = 16 * 1024;
const MANIFEST_LIMIT: u64 = 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const BOOTSTRAP_LOCK_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const MUTATION_EXECUTE: &str = "satelle-bootstrap-execute-v1";
const BOOTSTRAP_LOCK_EXIT_GRACE: Duration = Duration::from_millis(500);
const BOOTSTRAP_LOCK_EXIT_POLL: Duration = Duration::from_millis(10);
const RELEASE_BASE_URL: &str = "https://github.com/Microck/satelle/releases/download";
const CACHE_CLEANUP_PROTOCOL: &str = "satelle-cache-cleanup-v1";
const POSIX_CACHE_DIRECTORY_GUARD: &str = r#"safe_cache_directory() {
  expected_root=$1
  expected_directory=$2
  case "$expected_directory" in "$expected_root"|"$expected_root"/*) ;; *) return 1;; esac
  current=$expected_root
  suffix=${expected_directory#"$expected_root"}
  while :; do
    [ ! -L "$current" ] || return 1
    if [ -e "$current" ]; then [ -d "$current" ] || return 1; fi
    [ -z "$suffix" ] && return 0
    suffix=${suffix#/}
    component=${suffix%%/*}
    current=$current/$component
    if [ "$suffix" = "$component" ]; then suffix=; else suffix=${suffix#*/}; fi
  done
}"#;
const DAEMON_PATH_ENVIRONMENT_VARIABLES: [&str; 5] = [
    "SATELLE_HOME",
    "SATELLE_CONFIG_FILE",
    "SATELLE_STATE_DIR",
    "SATELLE_CACHE_DIR",
    "SATELLE_LOG_DIR",
];
pub(super) struct SshBootstrapLock {
    child: Child,
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    response_receiver: mpsc::Receiver<String>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<SshStderrClassification>>,
    heartbeat_stop: Arc<AtomicBool>,
    heartbeat: Option<JoinHandle<()>>,
    operation_id: String,
    operation_kind: bootstrap_lock::OperationKind,
    claim_identity: String,
    claim_basename: String,
    mutation_phase: Option<String>,
    mutation_attempt: Option<String>,
    #[cfg(all(test, unix))]
    exchanged_lock_lines: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CacheCleanupReport {
    pub(crate) removed_entries: u64,
    pub(crate) retained_entries: u64,
}

#[derive(Clone, Copy)]
pub(super) struct BootstrapMaintenanceContext<'a> {
    pub(super) operation_id: &'a str,
    pub(super) operation_kind: bootstrap_lock::OperationKind,
}

#[derive(Clone, Copy)]
struct ReadinessTimeouts {
    native: Duration,
    provider: Duration,
}

#[derive(Clone, Copy)]
enum BootstrapLaunchMode<'a> {
    Durable,
    Ephemeral {
        previous_host_config: &'a HostConfig,
    },
}

impl<'a> BootstrapLaunchMode<'a> {
    const fn bind(self) -> &'static str {
        match self {
            Self::Durable => "127.0.0.1:3001",
            Self::Ephemeral { .. } => "127.0.0.1:0",
        }
    }

    const fn expected_port(self) -> Option<u16> {
        match self {
            Self::Durable => Some(3001),
            Self::Ephemeral { .. } => None,
        }
    }

    const fn release_host_config(self) -> Option<&'a HostConfig> {
        match self {
            Self::Durable => None,
            Self::Ephemeral {
                previous_host_config,
            } => Some(previous_host_config),
        }
    }
}

struct BootstrapStartContext<'a> {
    bootstrap_scope: SshBootstrapScope,
    bind: &'a str,
    maintenance: BootstrapMaintenanceContext<'a>,
}

impl SshBootstrapLock {
    pub(super) fn acquire(
        destination: &str,
        request: bootstrap_lock::Request,
    ) -> Result<Self, SshBootstrapError> {
        Self::acquire_with_program(destination, request, OsStr::new("ssh"))
    }

    #[cfg(all(test, unix))]
    pub(super) fn acquire_for_tests(
        destination: &str,
        request: bootstrap_lock::Request,
        ssh_program: &Path,
    ) -> Result<Self, SshBootstrapError> {
        Self::acquire_with_program(destination, request, ssh_program.as_os_str())
    }

    fn acquire_with_program(
        destination: &str,
        request: bootstrap_lock::Request,
        ssh_program: &OsStr,
    ) -> Result<Self, SshBootstrapError> {
        let target = RemoteTarget::probe_with_program(destination, ssh_program)?;
        let mut child = Command::new(ssh_program)
            .arg("-T")
            .arg(destination)
            .arg(target.bootstrap_lock_command(&request))
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
        let ready_claim = match ready {
            Ok(ready_claim) => ready_claim,
            Err(error) => {
                let error = terminate_child(&mut child, error);
                let _ = stdout_reader.join();
                let classification = stderr_reader.join().unwrap_or_default();
                return Err(classify_bootstrap_lock_ready_error(error, classification));
            }
        };
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

        let stdin = Arc::new(Mutex::new(Some(stdin)));
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_stdin = Arc::clone(&stdin);
        let heartbeat_stopped = Arc::clone(&heartbeat_stop);
        let heartbeat = thread::Builder::new()
            .name("satelle-ssh-bootstrap-lock-heartbeat".to_string())
            .spawn(move || {
                while !heartbeat_stopped.load(Ordering::SeqCst) {
                    let deadline = Instant::now() + BOOTSTRAP_LOCK_HEARTBEAT_INTERVAL;
                    while Instant::now() < deadline {
                        if heartbeat_stopped.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(BOOTSTRAP_LOCK_EXIT_POLL);
                    }
                    let Ok(mut stdin) = heartbeat_stdin.lock() else {
                        return;
                    };
                    let Some(stdin) = stdin.as_mut() else {
                        return;
                    };
                    if writeln!(stdin, "{}", bootstrap_lock::HEARTBEAT)
                        .and_then(|()| stdin.flush())
                        .is_err()
                    {
                        return;
                    }
                }
            })
            .map_err(|error| terminate_child(&mut child, SshBootstrapError::ReaderThread(error)))?;

        Ok(Self {
            child,
            stdin,
            response_receiver,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            heartbeat_stop,
            heartbeat: Some(heartbeat),
            operation_id: request.operation_id().to_string(),
            operation_kind: request.operation_kind(),
            claim_identity: ready_claim.identity,
            claim_basename: ready_claim.basename,
            mutation_phase: None,
            mutation_attempt: None,
            #[cfg(all(test, unix))]
            exchanged_lock_lines: Vec::new(),
        })
    }

    pub(super) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(super) const fn operation_kind(&self) -> bootstrap_lock::OperationKind {
        self.operation_kind
    }

    pub(super) fn confirm_ownership(&mut self) -> Result<(), SshBootstrapError> {
        self.exchange_lock_line(format!("satelle-bootstrap-confirm-{}", Uuid::now_v7()))
    }

    pub(super) fn mark_mutation_started(&mut self, phase: &str) -> Result<(), SshBootstrapError> {
        let attempt = Uuid::now_v7().simple().to_string();
        self.mark_mutation_attempt_started(phase, &attempt)?;
        let executing = bootstrap_lock::mutation_executing_line(phase, &attempt)
            .map_err(SshBootstrapError::InvalidBootstrapLockRequest)?;
        self.exchange_lock_line(executing)
    }

    fn mark_mutation_attempt_started(
        &mut self,
        phase: &str,
        attempt: &str,
    ) -> Result<(), SshBootstrapError> {
        let line = bootstrap_lock::mutation_started_line(phase, attempt)
            .map_err(SshBootstrapError::InvalidBootstrapLockRequest)?;
        self.exchange_lock_line(line)?;
        self.mutation_phase = Some(phase.to_string());
        self.mutation_attempt = Some(attempt.to_string());
        Ok(())
    }

    fn fenced_command(
        &mut self,
        target: RemoteTarget,
        phase: &str,
        command: &str,
    ) -> Result<String, SshBootstrapError> {
        let attempt = Uuid::now_v7().simple().to_string();
        self.mark_mutation_attempt_started(phase, &attempt)?;
        Ok(target.fenced_mutation_command(
            &self.operation_id,
            &self.claim_identity,
            &self.claim_basename,
            phase,
            &attempt,
            command,
        ))
    }

    /// Releases a handoff whose exact completion attempt was already committed.
    pub(super) fn release_committed_handoff(&mut self) -> Result<(), SshBootstrapError> {
        self.exchange_lock_line(bootstrap_lock::RELEASE.to_string())
    }

    pub(super) fn release_unmodified(&mut self) -> Result<(), SshBootstrapError> {
        if self.mutation_phase.is_some() || self.mutation_attempt.is_some() {
            return Err(SshBootstrapError::BootstrapLockLost);
        }
        self.exchange_lock_line(bootstrap_lock::RELEASE.to_string())
    }

    pub(super) fn commit_current_mutation(&mut self) -> Result<(), SshBootstrapError> {
        let phase = self
            .mutation_phase
            .as_deref()
            .ok_or(SshBootstrapError::BootstrapLockLost)?;
        let attempt = self
            .mutation_attempt
            .as_deref()
            .ok_or(SshBootstrapError::BootstrapLockLost)?;
        let committed = bootstrap_lock::mutation_committed_line(phase, attempt)
            .map_err(SshBootstrapError::InvalidBootstrapLockRequest)?;
        self.exchange_lock_line(committed)
    }

    #[cfg(all(test, unix))]
    pub(super) fn exchanged_lock_lines(&self) -> &[String] {
        &self.exchanged_lock_lines
    }

    fn exchange_lock_line(&mut self, challenge: String) -> Result<(), SshBootstrapError> {
        if self
            .child
            .try_wait()
            .map_err(SshBootstrapError::InspectSsh)?
            .is_some()
        {
            return Err(SshBootstrapError::BootstrapLockLost);
        }
        {
            let mut stdin = self
                .stdin
                .lock()
                .map_err(|_| SshBootstrapError::BootstrapLockLost)?;
            let stdin = stdin.as_mut().ok_or(SshBootstrapError::BootstrapLockLost)?;
            writeln!(stdin, "{challenge}")
                .and_then(|()| stdin.flush())
                .map_err(SshBootstrapError::BootstrapLockProtocol)?;
        }
        match self.response_receiver.recv_timeout(PROCESS_TIMEOUT) {
            Ok(response) if response == challenge => {
                #[cfg(all(test, unix))]
                self.exchanged_lock_lines.push(challenge);
                Ok(())
            }
            Ok(_) => Err(SshBootstrapError::InvalidBootstrapLockResponse),
            Err(_) => Err(SshBootstrapError::BootstrapLockLost),
        }
    }
}

impl Drop for SshBootstrapLock {
    fn drop(&mut self) {
        self.heartbeat_stop.store(true, Ordering::SeqCst);
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        if let Ok(mut stdin) = self.stdin.lock() {
            drop(stdin.take());
        }
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
        bootstrap_lock: &mut SshBootstrapLock,
    ) -> Result<Self, SshBootstrapError> {
        let operation_id = bootstrap_lock.operation_id().to_string();
        let maintenance = BootstrapMaintenanceContext {
            operation_id: &operation_id,
            operation_kind: bootstrap_lock.operation_kind(),
        };
        Self::launch_bound(
            destination,
            token,
            host_config,
            bootstrap_scope,
            BootstrapLaunchMode::Durable,
            maintenance,
            bootstrap_lock,
        )
    }

    pub(super) fn launch_ephemeral(
        destination: &str,
        token: &ApiBearerToken,
        host_config: &HostConfig,
        previous_host_config: &HostConfig,
        bootstrap_scope: SshBootstrapScope,
        bootstrap_lock: &mut SshBootstrapLock,
    ) -> Result<Self, SshBootstrapError> {
        let operation_id = bootstrap_lock.operation_id().to_string();
        let maintenance = BootstrapMaintenanceContext {
            operation_id: &operation_id,
            operation_kind: bootstrap_lock.operation_kind(),
        };
        Self::launch_bound(
            destination,
            token,
            host_config,
            bootstrap_scope,
            BootstrapLaunchMode::Ephemeral {
                previous_host_config,
            },
            maintenance,
            bootstrap_lock,
        )
    }

    fn launch_bound(
        destination: &str,
        token: &ApiBearerToken,
        host_config: &HostConfig,
        bootstrap_scope: SshBootstrapScope,
        launch_mode: BootstrapLaunchMode<'_>,
        maintenance: BootstrapMaintenanceContext<'_>,
        bootstrap_lock: &mut SshBootstrapLock,
    ) -> Result<Self, SshBootstrapError> {
        let target = RemoteTarget::probe(destination)?;
        let environment = target.validated_daemon_environment(host_config)?;
        let release_environment = launch_mode
            .release_host_config()
            .map(|previous_host_config| target.validated_daemon_environment(previous_host_config))
            .transpose()?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let remote_binary = upload_artifact(destination, target, artifact.path(), bootstrap_lock)?;
        let (release_command, start_command) = target.state_owner_handoff_commands(
            &remote_binary,
            release_environment.as_deref(),
            host_config,
            &environment,
            BootstrapStartContext {
                bootstrap_scope,
                bind: launch_mode.bind(),
                maintenance,
            },
        );
        if let Some(release_command) = release_command {
            let command =
                bootstrap_lock.fenced_command(target, "state_owner_release", &release_command)?;
            require_success(run_fenced_ssh_command(destination, &command, None)?)?;
        }
        let start_command =
            bootstrap_lock.fenced_command(target, "daemon_start", &start_command)?;
        Self::spawn(
            destination,
            start_command,
            Some(token),
            launch_mode.expected_port(),
        )
    }

    pub(super) const fn remote_port(&self) -> u16 {
        self.remote_addr.port()
    }

    pub(super) fn launch_durable(
        destination: &str,
        token: &ApiBearerToken,
        idle_timeout: Duration,
        host_config: &HostConfig,
        bootstrap_lock: &mut SshBootstrapLock,
    ) -> Result<(), SshBootstrapError> {
        let operation_id = bootstrap_lock.operation_id().to_string();
        let maintenance = BootstrapMaintenanceContext {
            operation_id: &operation_id,
            operation_kind: bootstrap_lock.operation_kind(),
        };
        let target = RemoteTarget::probe(destination)?;
        let environment = target.validated_daemon_environment(host_config)?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let remote_binary = upload_artifact(destination, target, artifact.path(), bootstrap_lock)?;
        let (native_timeout, provider_timeout) = readiness_probe_timeouts(host_config);
        let command = target.durable_start_command_with_maintenance(
            &remote_binary,
            idle_timeout,
            native_timeout,
            provider_timeout,
            &environment,
            maintenance,
        );
        let command = bootstrap_lock.fenced_command(target, "daemon_start", &command)?;
        require_success(run_fenced_ssh_command(
            destination,
            &command,
            Some(FencedMutationInput::BootstrapToken(token)),
        )?)
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(SshBootstrapError::SpawnSsh)?;
        let stdout = child
            .stdout
            .take()
            .expect("bootstrap SSH stdout was configured as piped");
        let stderr = child
            .stderr
            .take()
            .expect("bootstrap SSH stderr was configured as piped");
        let stderr_reader =
            spawn_stderr_reader(stderr).map_err(|error| terminate_child(&mut child, error))?;
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let stdout_reader = match thread::Builder::new()
            .name("satelle-ssh-bootstrap-stdout".to_string())
            .spawn(move || drain_bootstrap_stdout(stdout, ready_sender))
        {
            Ok(reader) => reader,
            Err(error) => {
                let error = terminate_child(&mut child, SshBootstrapError::ReaderThread(error));
                let _ = stderr_reader.join();
                return Err(error);
            }
        };
        let mut stdin = child
            .stdin
            .take()
            .expect("bootstrap SSH stdin was configured as piped");
        let write_result = writeln!(stdin, "{MUTATION_EXECUTE}").and_then(|()| {
            if let Some(token) = token {
                let raw_token = token.expose();
                writeln!(stdin, "{}", raw_token.as_str())
            } else {
                Ok(())
            }
        });
        if let Err(error) = write_result {
            let error = terminate_child(&mut child, SshBootstrapError::WriteToken(error));
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(error);
        }
        drop(stdin);

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
        start_context: BootstrapStartContext<'_>,
    ) -> (Option<String>, String) {
        let release_command = release_environment.map(|environment| {
            self.release_state_command_with_environment(remote_binary, environment)
        });
        let (native, provider) = readiness_probe_timeouts(host_config);
        let start_command = self.start_command_with_maintenance(
            remote_binary,
            start_context.bootstrap_scope,
            ReadinessTimeouts { native, provider },
            start_context.bind,
            environment,
            start_context.maintenance,
        );
        (release_command, start_command)
    }

    fn probe(destination: &str) -> Result<Self, SshBootstrapError> {
        Self::probe_with_program(destination, OsStr::new("ssh"))
    }

    fn probe_with_program(
        destination: &str,
        ssh_program: &OsStr,
    ) -> Result<Self, SshBootstrapError> {
        let windows = run_ssh_command_with_program(
            ssh_program,
            destination,
            "cmd.exe /d /c \"echo satelle-platform-v1&&echo windows&&echo %PROCESSOR_ARCHITECTURE%\"",
        )?;
        if windows.status.success() {
            return Self::parse_probe(&windows.stdout);
        }

        let unix = run_ssh_command_with_program(
            ssh_program,
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
        format!("{}/v{version}/{}", self.remote_cache_root(), self.id())
    }

    fn remote_cache_root(self) -> &'static str {
        match self {
            Self::WindowsArm64Msvc | Self::WindowsX64Msvc => "AppData/Local/Satelle/host",
            Self::DarwinArm64 | Self::DarwinX64 => "Library/Caches/Satelle/host",
            Self::LinuxArm64Gnu | Self::LinuxX64Gnu => ".cache/satelle/host",
        }
    }

    fn bootstrap_lock_command(self, request: &bootstrap_lock::Request) -> String {
        if self.is_windows() {
            powershell_encoded_command(&request.windows_script())
        } else {
            request.posix_command()
        }
    }

    fn fenced_mutation_command(
        self,
        operation_id: &str,
        claim_identity: &str,
        claim_basename: &str,
        phase: &str,
        attempt: &str,
        command: &str,
    ) -> String {
        if self.is_windows() {
            let operation_id = powershell_quote(operation_id);
            let claim_identity = powershell_quote(claim_identity);
            let claim_basename = powershell_quote(claim_basename);
            let phase = powershell_quote(phase);
            let attempt = powershell_quote(attempt);
            let command = powershell_quote(command);
            return powershell_encoded_command(&format!(
                r#"$ErrorActionPreference = 'Stop'
$operationId = {operation_id}
$claimIdentity = {claim_identity}
$claimBasename = {claim_basename}
$phase = {phase}
$attempt = {attempt}
$innerCommand = {command}
$expectedGate = '{MUTATION_EXECUTE}'
$gateBytes = [Text.Encoding]::UTF8.GetBytes($expectedGate + "`n")
$inputStream = [Console]::OpenStandardInput()
$observedGate = New-Object byte[] $gateBytes.Length
$offset = 0
while ($offset -lt $observedGate.Length) {{
  $count = $inputStream.Read($observedGate, $offset, $observedGate.Length - $offset)
  if ($count -eq 0) {{ exit 75 }}
  $offset += $count
}}
if ([Convert]::ToBase64String($gateBytes) -cne [Convert]::ToBase64String($observedGate)) {{ exit 75 }}
$stateRoot = if ($env:SATELLE_STATE_DIR) {{ $env:SATELLE_STATE_DIR }} else {{ Join-Path $env:LOCALAPPDATA 'Satelle\state' }}
$lockRoot = Join-Path $stateRoot 'bootstrap.lock'
$claimPath = Join-Path $lockRoot $claimBasename
$claimItem = Get-Item -LiteralPath $claimPath -Force -ErrorAction Stop
if (-not $claimItem.PSIsContainer -or
    (($claimItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 75 }}
if ((((Get-Content -LiteralPath (Join-Path $claimPath 'operation_id') -Raw).Trim()) -cne $operationId) -or
    (((Get-Content -LiteralPath (Join-Path $claimPath 'claim_identity') -Raw).Trim()) -cne $claimIdentity)) {{ exit 75 }}
$state = (Get-Content -LiteralPath (Join-Path $claimPath 'state') -Raw).Trim()
$observedPhase = (Get-Content -LiteralPath (Join-Path $claimPath 'mutation_phase') -Raw).Trim()
$observedAttempt = (Get-Content -LiteralPath (Join-Path $claimPath 'mutation_attempt') -Raw).Trim()
if (($state -cne 'mutation_started') -or ($observedPhase -cne $phase) -or ($observedAttempt -cne $attempt)) {{ exit 75 }}
[IO.File]::Open((Join-Path $claimPath ('execution_started.' + $attempt)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
Invoke-Expression $innerCommand
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
if ($phase -cne 'daemon_start') {{
  [IO.File]::Open((Join-Path $claimPath ('execution_succeeded.' + $attempt)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
}}"#,
            ));
        }

        let operation_id = posix_quote(operation_id);
        let claim_identity = posix_quote(claim_identity);
        let claim_basename = posix_quote(claim_basename);
        let phase = posix_quote(phase);
        let attempt = posix_quote(attempt);
        let command = posix_quote(command);
        let script = format!(
            r#"set -eu
operation_id={operation_id}
claim_identity={claim_identity}
claim_basename={claim_basename}
phase={phase}
attempt={attempt}
inner_command={command}
gate="$(dd bs=1 count={execute_gate_length} 2>/dev/null)" || exit 75
[ "$gate" = '{MUTATION_EXECUTE}' ] || exit 75
state_root="${{SATELLE_STATE_DIR:-${{XDG_STATE_HOME:-$HOME/.local/state}}/satelle}}"
lock_root="$state_root/bootstrap.lock"
claim_path="$lock_root/$claim_basename"
[ -d "$claim_path" ] && [ ! -L "$claim_path" ] || exit 75
[ "$(cat "$claim_path/operation_id" 2>/dev/null)" = "$operation_id" ] || exit 75
[ "$(cat "$claim_path/claim_identity" 2>/dev/null)" = "$claim_identity" ] || exit 75
[ "$(cat "$claim_path/state" 2>/dev/null)" = mutation_started ] || exit 75
[ "$(cat "$claim_path/mutation_phase" 2>/dev/null)" = "$phase" ] || exit 75
[ "$(cat "$claim_path/mutation_attempt" 2>/dev/null)" = "$attempt" ] || exit 75
mkdir "$claim_path/execution_started.$attempt" || exit 75
set +e
eval "$inner_command"
status=$?
set -e
[ "$status" -eq 0 ] || exit "$status"
if [ "$phase" != daemon_start ]; then mkdir "$claim_path/execution_succeeded.$attempt" || exit 75; fi"#,
            execute_gate_length = MUTATION_EXECUTE.len() + 1,
        );
        format!("sh -c {}", posix_quote(&script))
    }

    fn upload_command(self, staged: &str, digest: &str) -> String {
        if self.is_windows() {
            let staged = powershell_quote(staged);
            return powershell_encoded_command(&format!(
                r#"$ErrorActionPreference = 'Stop'
$inputStream = [Console]::OpenStandardInput()
$outputStream = [IO.File]::Open({staged}, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {{ $inputStream.CopyTo($outputStream) }} finally {{ $outputStream.Dispose() }}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath {staged}).Hash.ToLowerInvariant() -cne {digest}) {{ exit 1 }}"#,
                staged = staged,
                digest = powershell_quote(digest),
            ));
        }
        let script = format!(
            "set -eu\numask 077\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\npath={}\nexpected={}\ndirectory=${{path%/*}}\nsafe_cache_directory \"$root\" \"$directory\"\n[ ! -e \"$path\" ] && [ ! -L \"$path\" ] || exit 1\nset -C\ncat >\"$path\"\nif command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum \"$path\" | awk '{{print $1}}'); elif command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 \"$path\" | awk '{{print $1}}'); else actual=$(openssl dgst -sha256 \"$path\" | awk '{{print $NF}}'); fi\n[ \"$actual\" = \"$expected\" ]",
            posix_quote(self.remote_cache_root()),
            posix_quote(staged),
            posix_quote(digest),
        );
        format!("sh -c {}", posix_quote(&script))
    }

    fn create_directory_command(self, directory: &str) -> String {
        if self.is_windows() {
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; ",
                    "$separator=[IO.Path]::DirectorySeparatorChar; ",
                    "$root=[IO.Path]::GetFullPath(({}).Replace('/', $separator)); ",
                    "$path=[IO.Path]::GetFullPath(({}).Replace('/', $separator)); ",
                    "$rootPrefix=$root.TrimEnd($separator)+$separator; ",
                    "if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path,$root) -and ",
                    "-not $path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit 1 }}; ",
                    "New-Item -ItemType Directory -Force -Path $path | Out-Null; ",
                    "$current=Get-Item -LiteralPath $path; while ($true) {{ ",
                    "$currentPath=[IO.Path]::GetFullPath($current.FullName); ",
                    "if (-not [StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$root) -and ",
                    "-not $currentPath.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit 1 }}; ",
                    "$acl=Get-Acl -LiteralPath $currentPath; $acl.SetAccessRuleProtection($true,$false); ",
                    "foreach ($rule in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleAll($rule) }}; ",
                    "$rule=New-Object System.Security.AccessControl.FileSystemAccessRule(",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl',",
                    "'ContainerInherit,ObjectInherit','None','Allow'); ",
                    "$acl.SetAccessRule($rule); Set-Acl -LiteralPath $currentPath -AclObject $acl; ",
                    "if ([StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$root)) {{ break }}; ",
                    "$current=$current.Parent; if ($null -eq $current) {{ exit 1 }} }}",
                ),
                powershell_quote(self.remote_cache_root()),
                powershell_quote(directory),
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "set -eu\numask 077\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\ndirectory={}\nsafe_cache_directory \"$root\" \"$directory\"\nmkdir -p \"$directory\"\nsafe_cache_directory \"$root\" \"$directory\"\ncurrent=\"$directory\"\nwhile :; do chmod 700 \"$current\"; [ \"$current\" = \"$root\" ] && break; current=\"${{current%/*}}\"; done",
                posix_quote(self.remote_cache_root()),
                posix_quote(directory),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    fn promote_command(self, staged: &str, final_path: &str) -> String {
        if self.is_windows() {
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; Move-Item -Force -LiteralPath {} -Destination {}; ",
                    "$acl=Get-Acl -LiteralPath {}; $acl.SetAccessRuleProtection($true,$false); ",
                    "foreach ($rule in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleAll($rule) }}; ",
                    "$rule=New-Object System.Security.AccessControl.FileSystemAccessRule(",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','Allow'); ",
                    "$acl.SetAccessRule($rule); Set-Acl -LiteralPath {} -AclObject $acl",
                ),
                powershell_quote(staged),
                powershell_quote(final_path),
                powershell_quote(final_path),
                powershell_quote(final_path),
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "set -eu\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\nstaged={}\nfinal_path={}\nstaged_directory=${{staged%/*}}\nfinal_directory=${{final_path%/*}}\nsafe_cache_directory \"$root\" \"$staged_directory\"\nsafe_cache_directory \"$root\" \"$final_directory\"\n[ -f \"$staged\" ] && [ ! -L \"$staged\" ] || exit 1\n[ ! -L \"$final_path\" ] || exit 1\nmv -f \"$staged\" \"$final_path\"",
                posix_quote(self.remote_cache_root()),
                posix_quote(staged),
                posix_quote(final_path),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    fn cache_validation_command(self, remote_path: &str) -> String {
        if self.is_windows() {
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; $root={}; $path={}; ",
                    "$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; ",
                    "$item=Get-Item -LiteralPath $path; ",
                    "if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 1 }}; ",
                    "$current=$item; while ($true) {{ ",
                    "if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ exit 1 }}; ",
                    "$acl=Get-Acl -LiteralPath $current.FullName; if ($acl.Owner -ne $identity) {{ exit 1 }}; ",
                    "foreach ($rule in $acl.Access) {{ if ($rule.AccessControlType -eq 'Allow' -and ",
                    "$rule.IdentityReference.Value -ne $identity) {{ exit 1 }} }}; ",
                    "if ($current.FullName -eq (Get-Item -LiteralPath $root).FullName) {{ break }}; ",
                    "$current=$current.Parent; if ($null -eq $current) {{ exit 1 }} }}",
                ),
                powershell_quote(self.remote_cache_root()),
                powershell_quote(remote_path),
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                concat!(
                    "path={path}; root={root}; uid=$(id -u); ",
                    "test -f \"$path\" && test ! -L \"$path\" || exit 1; ",
                    "owner=$(stat -c %u \"$path\" 2>/dev/null || stat -f %u \"$path\") || exit 1; ",
                    "mode=$(stat -c %a \"$path\" 2>/dev/null || stat -f %Lp \"$path\") || exit 1; ",
                    "[ \"$owner\" = \"$uid\" ] || exit 1; case \"$mode\" in 500|700) ;; *) exit 1;; esac; ",
                    "current=\"${{path%/*}}\"; while :; do test -d \"$current\" && test ! -L \"$current\" || exit 1; ",
                    "owner=$(stat -c %u \"$current\" 2>/dev/null || stat -f %u \"$current\") || exit 1; ",
                    "mode=$(stat -c %a \"$current\" 2>/dev/null || stat -f %Lp \"$current\") || exit 1; ",
                    "[ \"$owner\" = \"$uid\" ] && [ \"$mode\" = 700 ] || exit 1; ",
                    "[ \"$current\" = \"$root\" ] && break; current=\"${{current%/*}}\"; ",
                    "[ -n \"$current\" ] || exit 1; done",
                ),
                path = posix_quote(remote_path),
                root = posix_quote(self.remote_cache_root()),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    fn cache_cleanup_command(self) -> String {
        let current_version = format!("v{}", env!("CARGO_PKG_VERSION"));
        if self.is_windows() {
            let script = format!(
                r#"$ErrorActionPreference='Stop'
$root={root}
$currentVersion={current_version}
$targetId={target_id}
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
function Test-SafeEntry([System.IO.FileInfo]$Item) {{
  if ($null -eq $Item -or $Item.PSIsContainer -or (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ return $false }}
  $cursor=$Item
  while ($true) {{
    if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ return $false }}
    $acl=Get-Acl -LiteralPath $cursor.FullName
    if ($acl.Owner -ne $identity) {{ return $false }}
    foreach ($rule in $acl.Access) {{
      if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne $identity) {{ return $false }}
    }}
    if ($cursor.FullName -eq (Get-Item -LiteralPath $root).FullName) {{ return $true }}
    $cursor=$cursor.Parent
    if ($null -eq $cursor) {{ return $false }}
  }}
}}
$removed=0
$retained=0
Write-Output '{protocol}'
if (-not (Test-Path -LiteralPath $root -PathType Container)) {{
  Write-Output 'removed=0'
  Write-Output 'retained=0'
  exit 0
}}
$versions=@(Get-ChildItem -LiteralPath $root -Directory | Where-Object {{
  $_.Name -match '^v[0-9]+\.[0-9]+\.[0-9]+$' -and
  (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
}} | Sort-Object {{ [version]$_.Name.Substring(1) }})
$previous=$versions | Where-Object {{
  $_.Name -ne $currentVersion -and
  @(Get-ChildItem -LiteralPath (Join-Path $_.FullName $targetId) -File -ErrorAction SilentlyContinue |
    Where-Object {{ $_.Name -match '^satelle(-[0-9a-f]{{64}})?\.exe$' }}).Count -gt 0
}} | Select-Object -Last 1
foreach ($version in $versions) {{
  $entries=@(Get-ChildItem -LiteralPath $version.FullName -File -Recurse | Where-Object {{
    $_.Name -match '^satelle(-[0-9a-f]{{64}})?\.exe$'
  }})
  if ($version.Name -eq $currentVersion -or ($null -ne $previous -and $version.FullName -eq $previous.FullName)) {{
    $retained += $entries.Count
    continue
  }}
  foreach ($entry in $entries) {{
    if (-not (Test-SafeEntry $entry)) {{ $retained++; continue }}
    $fullPath=$entry.FullName
    $processActive=[bool](Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {{ $_.ExecutablePath -eq $fullPath }} | Select-Object -First 1)
    $serviceActive=[bool](Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {{ $_.PathName -like ('*' + $fullPath + '*') }} | Select-Object -First 1)
    if ($processActive -or $serviceActive) {{ $retained++; continue }}
    $fresh=Get-Item -LiteralPath $fullPath -ErrorAction SilentlyContinue
    if (-not (Test-SafeEntry $fresh)) {{ $retained++; continue }}
    Remove-Item -LiteralPath $fullPath -Force
    $removed++
  }}
}}
Write-Output ('removed=' + $removed)
Write-Output ('retained=' + $retained)"#,
                root = powershell_quote(self.remote_cache_root()),
                current_version = powershell_quote(&current_version),
                target_id = powershell_quote(self.id()),
                protocol = CACHE_CLEANUP_PROTOCOL,
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                r#"set -eu
root={root}
current_version={current_version}
target_id={target_id}
removed=0
retained=0
printf '%s\n' '{protocol}'
if [ ! -d "$root" ]; then printf 'removed=0\nretained=0\n'; exit 0; fi
previous="$(
  for version_dir in "$root"/v*; do
    [ -d "$version_dir" ] && [ ! -L "$version_dir" ] || continue
    [ -f "$version_dir/$target_id/satelle" ] && [ ! -L "$version_dir/$target_id/satelle" ] || continue
    basename "$version_dir"
  done | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | grep -Fvx "$current_version" | sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1 | sed 's/^/v/' || true
)"
safe_entry() {{
  path="$1"
  current="$path"
  uid="$(id -u)"
  [ -f "$path" ] && [ ! -L "$path" ] || return 1
  while :; do
    [ ! -L "$current" ] || return 1
    owner="$(stat -c %u "$current" 2>/dev/null || stat -f %u "$current")" || return 1
    mode="$(stat -c %a "$current" 2>/dev/null || stat -f %Lp "$current")" || return 1
    [ "$owner" = "$uid" ] || return 1
    case "$mode" in *00) ;; *) return 1;; esac
    [ "$current" = "$root" ] && return 0
    current="${{current%/*}}"
    [ -n "$current" ] || return 1
  done
}}
for version_dir in "$root"/v*; do
  [ -d "$version_dir" ] && [ ! -L "$version_dir" ] || continue
  version="${{version_dir##*/}}"
  for entry in "$version_dir"/*/satelle; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    if [ "$version" = "$current_version" ] || [ "$version" = "$previous" ]; then
      retained=$((retained + 1))
      continue
    fi
    if ! safe_entry "$entry"; then retained=$((retained + 1)); continue; fi
    process_active=false
    if ps -eo comm=,args= 2>/dev/null | awk -v path="$entry" '($1 == "satelle" || $1 == "satelle.exe") && index($0,path) {{ found=1 }} END {{ exit !found }}'; then process_active=true; fi
    service_active=false
    if command -v systemctl >/dev/null 2>&1 && systemctl --user cat satelle-host 2>/dev/null | grep -F -- "$entry" >/dev/null 2>&1; then service_active=true; fi
    if command -v launchctl >/dev/null 2>&1 && launchctl print "gui/$(id -u)" 2>/dev/null | grep -F -- "$entry" >/dev/null 2>&1; then service_active=true; fi
    if [ "$process_active" = true ] || [ "$service_active" = true ]; then retained=$((retained + 1)); continue; fi
    if ! safe_entry "$entry"; then retained=$((retained + 1)); continue; fi
    rm -f -- "$entry"
    removed=$((removed + 1))
  done
done
printf 'removed=%s\nretained=%s\n' "$removed" "$retained""#,
                root = posix_quote(self.remote_cache_root()),
                current_version = posix_quote(&current_version),
                target_id = posix_quote(self.id()),
                protocol = CACHE_CLEANUP_PROTOCOL,
            );
            format!("sh -c {}", posix_quote(&script))
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
        if self.is_windows() {
            let script = format!(
                concat!(
                    "$acl=Get-Acl -LiteralPath {}; $acl.SetAccessRuleProtection($true,$false); ",
                    "foreach ($rule in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleAll($rule) }}; ",
                    "$rule=New-Object System.Security.AccessControl.FileSystemAccessRule(",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','Allow'); ",
                    "$acl.SetAccessRule($rule); Set-Acl -LiteralPath {} -AclObject $acl",
                ),
                powershell_quote(staged),
                powershell_quote(staged),
            );
            Some(powershell_encoded_command(&script))
        } else {
            let script = format!(
                "set -eu\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\npath={}\ndirectory=${{path%/*}}\nsafe_cache_directory \"$root\" \"$directory\"\n[ -f \"$path\" ] && [ ! -L \"$path\" ] || exit 1\nchmod 700 \"$path\"",
                posix_quote(self.remote_cache_root()),
                posix_quote(staged),
            );
            Some(format!("sh -c {}", posix_quote(&script)))
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
            ReadinessTimeouts {
                native: native_timeout,
                provider: provider_timeout,
            },
            bind,
            &[],
        )
    }

    #[cfg(test)]
    fn start_command_with_environment(
        self,
        remote_binary: &str,
        bootstrap_scope: SshBootstrapScope,
        readiness_timeouts: ReadinessTimeouts,
        bind: &str,
        environment: &[(&'static str, &Path)],
    ) -> String {
        self.start_command_with_optional_maintenance(
            remote_binary,
            bootstrap_scope,
            readiness_timeouts,
            bind,
            environment,
            None,
        )
    }

    fn start_command_with_maintenance(
        self,
        remote_binary: &str,
        bootstrap_scope: SshBootstrapScope,
        readiness_timeouts: ReadinessTimeouts,
        bind: &str,
        environment: &[(&'static str, &Path)],
        maintenance: BootstrapMaintenanceContext<'_>,
    ) -> String {
        self.start_command_with_optional_maintenance(
            remote_binary,
            bootstrap_scope,
            readiness_timeouts,
            bind,
            environment,
            Some(maintenance),
        )
    }

    fn start_command_with_optional_maintenance(
        self,
        remote_binary: &str,
        bootstrap_scope: SshBootstrapScope,
        readiness_timeouts: ReadinessTimeouts,
        bind: &str,
        environment: &[(&'static str, &Path)],
        maintenance: Option<BootstrapMaintenanceContext<'_>>,
    ) -> String {
        let maintenance_args = maintenance.map_or_else(String::new, |maintenance| {
            format!(
                " --bootstrap-operation-id {} --bootstrap-operation-kind {}",
                maintenance.operation_id,
                maintenance.operation_kind.as_str()
            )
        });
        let timeout_args = format!(
            "--bind {bind} --bootstrap-scope {} --bootstrap-native-readiness-timeout-ms {} --bootstrap-provider-smoke-timeout-ms {}{maintenance_args}",
            bootstrap_scope.as_cli_value(),
            readiness_timeouts.native.as_millis(),
            readiness_timeouts.provider.as_millis(),
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

    #[cfg(test)]
    fn durable_start_command_with_environment(
        self,
        remote_binary: &str,
        idle_timeout: Duration,
        native_timeout: Duration,
        provider_timeout: Duration,
        environment: &[(&'static str, &Path)],
    ) -> String {
        self.durable_start_command_with_optional_maintenance(
            remote_binary,
            idle_timeout,
            native_timeout,
            provider_timeout,
            environment,
            None,
        )
    }

    fn durable_start_command_with_maintenance(
        self,
        remote_binary: &str,
        idle_timeout: Duration,
        native_timeout: Duration,
        provider_timeout: Duration,
        environment: &[(&'static str, &Path)],
        maintenance: BootstrapMaintenanceContext<'_>,
    ) -> String {
        self.durable_start_command_with_optional_maintenance(
            remote_binary,
            idle_timeout,
            native_timeout,
            provider_timeout,
            environment,
            Some(maintenance),
        )
    }

    fn durable_start_command_with_optional_maintenance(
        self,
        remote_binary: &str,
        idle_timeout: Duration,
        native_timeout: Duration,
        provider_timeout: Duration,
        environment: &[(&'static str, &Path)],
        maintenance: Option<BootstrapMaintenanceContext<'_>>,
    ) -> String {
        let maintenance_args = maintenance.map_or_else(String::new, |maintenance| {
            format!(
                " --bootstrap-operation-id {} --bootstrap-operation-kind {}",
                maintenance.operation_id,
                maintenance.operation_kind.as_str()
            )
        });
        let timeout_args = format!(
            "--bootstrap-token-stdin --bootstrap-scope {} --on-demand-idle-timeout-ms {} --bootstrap-native-readiness-timeout-ms {} --bootstrap-provider-smoke-timeout-ms {}{maintenance_args}",
            SshBootstrapScope::Read.as_cli_value(),
            idle_timeout.as_millis(),
            native_timeout.as_millis(),
            provider_timeout.as_millis(),
        );
        if self.is_windows() {
            let script = format!(
                concat!(
                    "{}$binary = (Resolve-Path -LiteralPath {}).Path; ",
                    "$startInfo = New-Object System.Diagnostics.ProcessStartInfo; ",
                    "$startInfo.FileName = $binary; $startInfo.Arguments = 'host start {} --json'; ",
                    "$startInfo.UseShellExecute = $false; $startInfo.CreateNoWindow = $true; ",
                    "$startInfo.RedirectStandardInput = $true; ",
                    "$process = New-Object System.Diagnostics.Process; $process.StartInfo = $startInfo; ",
                    "if (-not $process.Start()) {{ exit 1 }}; ",
                    "$token = [Console]::In.ReadLine(); ",
                    "if ([String]::IsNullOrEmpty($token)) {{ $process.Kill(); exit 1 }}; ",
                    "$process.StandardInput.WriteLine($token); $process.StandardInput.Close()"
                ),
                powershell_environment(environment),
                powershell_quote(remote_binary),
                timeout_args,
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "{}exec 3<&0; nohup {remote_binary} host start {timeout_args} --json <&3 3<&- >/dev/null 2>&1 & exec 3<&-",
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
    bootstrap_lock: &mut SshBootstrapLock,
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
    let staged = stage_artifact_with_digest(
        destination,
        target,
        local_binary,
        local_digest,
        bootstrap_lock,
    )?;
    let command = bootstrap_lock.fenced_command(
        target,
        "cache_promotion",
        &target.promote_command(&staged, &final_path),
    )?;
    let promote = run_fenced_ssh_command(destination, &command, None)?;
    require_success(promote)?;
    if remote_artifact_matches(destination, target, &final_path, &local_digest)? {
        Ok(final_path)
    } else {
        Err(SshBootstrapError::RemoteCacheEntryRejected)
    }
}

pub(super) fn cleanup_host_cache(
    destination: &str,
) -> Result<CacheCleanupReport, SshBootstrapError> {
    let target = RemoteTarget::probe(destination)?;
    let output = run_ssh_command(destination, &target.cache_cleanup_command())?;
    require_success_output(output).and_then(|output| parse_cache_cleanup_report(&output.stdout))
}

fn parse_cache_cleanup_report(stdout: &[u8]) -> Result<CacheCleanupReport, SshBootstrapError> {
    let output =
        std::str::from_utf8(stdout).map_err(|_| SshBootstrapError::InvalidCacheCleanupResponse)?;
    let mut lines = output.lines();
    if lines.next() != Some(CACHE_CLEANUP_PROTOCOL) {
        return Err(SshBootstrapError::InvalidCacheCleanupResponse);
    }
    let removed_entries = lines
        .next()
        .and_then(|line| line.strip_prefix("removed="))
        .and_then(|value| value.parse().ok())
        .ok_or(SshBootstrapError::InvalidCacheCleanupResponse)?;
    let retained_entries = lines
        .next()
        .and_then(|line| line.strip_prefix("retained="))
        .and_then(|value| value.parse().ok())
        .ok_or(SshBootstrapError::InvalidCacheCleanupResponse)?;
    if lines.next().is_some() {
        return Err(SshBootstrapError::InvalidCacheCleanupResponse);
    }
    Ok(CacheCleanupReport {
        removed_entries,
        retained_entries,
    })
}

fn remote_artifact_matches(
    destination: &str,
    target: RemoteTarget,
    remote_path: &str,
    expected_digest: &[u8; 32],
) -> Result<bool, SshBootstrapError> {
    let validation = run_ssh_command(destination, &target.cache_validation_command(remote_path))?;
    if !validation.status.success() {
        return if validation.stderr.host_key_verification_failed() {
            Err(SshBootstrapError::HostKeyVerificationRequired)
        } else {
            Ok(false)
        };
    }
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

fn stage_artifact_with_digest(
    destination: &str,
    target: RemoteTarget,
    local_binary: &Path,
    local_digest: [u8; 32],
    bootstrap_lock: &mut SshBootstrapLock,
) -> Result<String, SshBootstrapError> {
    let directory = target.remote_directory();
    let staged_suffix = if target.is_windows() { ".exe" } else { "" };
    let staged = format!(
        "{directory}/.satelle-upload-{}{staged_suffix}",
        Uuid::now_v7().hyphenated()
    );
    let local_digest_hex = local_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let command = bootstrap_lock.fenced_command(
        target,
        "cache_directory_creation",
        &target.create_directory_command(&directory),
    )?;
    let create = run_fenced_ssh_command(destination, &command, None)?;
    require_success(create)?;

    let input = File::open(local_binary).map_err(SshBootstrapError::LocalFile)?;
    let command = bootstrap_lock.fenced_command(
        target,
        "cache_upload",
        &target.upload_command(&staged, &local_digest_hex),
    )?;
    let copy = run_fenced_ssh_command(
        destination,
        &command,
        Some(FencedMutationInput::Artifact(input)),
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
    if let Some(command) = target.prepare_staged_command(&staged) {
        let command =
            bootstrap_lock.fenced_command(target, "cache_staging_permissions", &command)?;
        require_success(run_fenced_ssh_command(destination, &command, None)?)?;
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

enum FencedMutationInput<'a> {
    Artifact(File),
    BootstrapToken(&'a ApiBearerToken),
}

fn run_ssh_command(
    destination: &str,
    remote_command: &str,
) -> Result<CommandOutput, SshBootstrapError> {
    run_ssh_command_with_program(OsStr::new("ssh"), destination, remote_command)
}

fn run_ssh_command_with_program(
    ssh_program: &OsStr,
    destination: &str,
    remote_command: &str,
) -> Result<CommandOutput, SshBootstrapError> {
    run_program_with_output_limit(
        ssh_program,
        [
            OsStr::new("-T"),
            OsStr::new(destination),
            OsStr::new(remote_command),
        ],
        PROBE_OUTPUT_LIMIT,
    )
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

fn run_fenced_ssh_command(
    destination: &str,
    remote_command: &str,
    mut input: Option<FencedMutationInput<'_>>,
) -> Result<CommandOutput, SshBootstrapError> {
    let mut child = Command::new("ssh")
        .arg("-T")
        .arg(destination)
        .arg(remote_command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(SshBootstrapError::SpawnSsh)?;
    let stdout = child
        .stdout
        .take()
        .expect("SSH upload stdout was configured as piped");
    let stdout_reader = thread::Builder::new()
        .name("satelle-ssh-upload-stdout".to_string())
        .spawn(move || read_bounded(stdout, PROBE_OUTPUT_LIMIT))
        .map_err(|error| terminate_child(&mut child, SshBootstrapError::ReaderThread(error)))?;
    let stderr = child
        .stderr
        .take()
        .expect("SSH upload stderr was configured as piped");
    let stderr_reader = match spawn_stderr_reader(stderr) {
        Ok(reader) => reader,
        Err(error) => {
            let error = terminate_child(&mut child, error);
            let _ = stdout_reader.join();
            return Err(error);
        }
    };
    let mut stdin = child
        .stdin
        .take()
        .expect("fenced SSH stdin was configured as piped");
    let input_result = writeln!(stdin, "{MUTATION_EXECUTE}").and_then(|()| match input.as_mut() {
        Some(FencedMutationInput::Artifact(input)) => io::copy(input, &mut stdin).map(drop),
        Some(FencedMutationInput::BootstrapToken(token)) => {
            let raw_token = token.expose();
            writeln!(stdin, "{}", raw_token.as_str())
        }
        None => Ok(()),
    });
    if let Err(error) = input_result {
        let error = terminate_child(&mut child, SshBootstrapError::WriteMutationInput(error));
        let _ = stdout_reader.join();
        let _ = stderr_reader.join();
        return Err(error);
    }
    drop(stdin);
    let status = child.wait().map_err(SshBootstrapError::WaitSsh)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| SshBootstrapError::ReaderPanicked)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| SshBootstrapError::ReaderPanicked)?;
    Ok(CommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn run_program_with_output_limit<const N: usize>(
    program: impl AsRef<OsStr>,
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
    ready_sender: mpsc::SyncSender<Result<BootstrapLockReady, SshBootstrapError>>,
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

struct BootstrapLockReady {
    identity: String,
    basename: String,
}

fn read_bootstrap_lock_ready(
    reader: &mut impl BufRead,
) -> Result<BootstrapLockReady, SshBootstrapError> {
    let mut ready = String::new();
    reader
        .take(256)
        .read_line(&mut ready)
        .map_err(SshBootstrapError::ReadProcess)?;
    let ready = ready.trim_end();
    if let Some(fields) = ready
        .strip_prefix(bootstrap_lock::READY)
        .and_then(|ready| ready.strip_prefix(' '))
    {
        let mut fields = fields.split(' ');
        let identity = fields.next().unwrap_or_default();
        let basename = fields.next().unwrap_or_default();
        if fields.next().is_none()
            && identity.len() == 32
            && identity
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && basename.starts_with("claim.")
            && !basename.ends_with(".closing")
            && basename.len() <= 192
            && basename.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@')
            })
        {
            return Ok(BootstrapLockReady {
                identity: identity.to_string(),
                basename: basename.to_string(),
            });
        }
        Err(SshBootstrapError::InvalidBootstrapLockResponse)
    } else if ready == bootstrap_lock::BUSY {
        Err(SshBootstrapError::BootstrapBusy)
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
    #[error("could not stream a fenced remote mutation to system OpenSSH")]
    WriteMutationInput(#[source] io::Error),
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
    #[error("the remote Host binary cache entry is not an owner-only regular file")]
    RemoteCacheEntryRejected,
    #[error("the remote Host returned an invalid cache-cleanup result")]
    InvalidCacheCleanupResponse,
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
    #[error("another remote SSH bootstrap operation is already active")]
    BootstrapBusy,
    #[error("the remote SSH bootstrap lock was lost")]
    BootstrapLockLost,
    #[error("could not exchange the remote SSH bootstrap lock challenge")]
    BootstrapLockProtocol(#[source] io::Error),
    #[error("the remote SSH bootstrap lock returned an invalid response")]
    InvalidBootstrapLockResponse,
    #[error("the remote SSH bootstrap lock request was invalid")]
    InvalidBootstrapLockRequest(#[source] bootstrap_lock::InvalidRequest),
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
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

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

    #[cfg(unix)]
    fn run_posix_cache_command(home: &Path, command: &str, input: Option<&[u8]>) -> ExitStatus {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(home)
            .stdin(Stdio::piped())
            .spawn()
            .expect("run POSIX cache command");
        if let Some(input) = input {
            child
                .stdin
                .as_mut()
                .expect("piped cache command stdin")
                .write_all(input)
                .expect("write cache command input");
        }
        drop(child.stdin.take());
        child.wait().expect("wait for POSIX cache command")
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
    fn host_binary_cache_paths_are_versioned_and_target_specific() {
        for target in [
            RemoteTarget::LinuxArm64Gnu,
            RemoteTarget::LinuxX64Gnu,
            RemoteTarget::DarwinArm64,
            RemoteTarget::DarwinX64,
            RemoteTarget::WindowsArm64Msvc,
            RemoteTarget::WindowsX64Msvc,
        ] {
            let directory = target.remote_directory();
            assert!(directory.contains(&format!("/v{}/", env!("CARGO_PKG_VERSION"))));
            assert!(directory.ends_with(target.id()));
            assert!(directory.starts_with(target.remote_cache_root()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn posix_directory_creation_hardens_pre_existing_cache_descendants() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let cache_root = home.path().join(".cache/satelle/host");
        let version = cache_root.join(format!("v{}", env!("CARGO_PKG_VERSION")));
        let directory = version.join("linux-x64-gnu");
        fs::create_dir_all(&directory).expect("create cache directory");
        for path in [&cache_root, &version, &directory] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o777))
                .expect("broaden cache directory permissions");
        }

        let status = Command::new("sh")
            .arg("-c")
            .arg(
                RemoteTarget::LinuxX64Gnu
                    .create_directory_command(&RemoteTarget::LinuxX64Gnu.remote_directory()),
            )
            .current_dir(home.path())
            .status()
            .expect("run cache directory creation");
        assert!(status.success());

        for path in [&directory, &version, &cache_root] {
            let mode = fs::metadata(path)
                .expect("read cache directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} was not owner-only", path.display());
        }
    }

    #[cfg(unix)]
    #[test]
    fn posix_directory_creation_rejects_a_symlinked_cache_root_without_outside_mutation() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let outside = tempfile::tempdir().expect("outside directory");
        fs::create_dir_all(home.path().join(".cache/satelle")).expect("create cache parent");
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o755))
            .expect("set outside permissions");
        symlink(outside.path(), home.path().join(".cache/satelle/host"))
            .expect("symlink cache root");

        let command = RemoteTarget::LinuxX64Gnu
            .create_directory_command(&RemoteTarget::LinuxX64Gnu.remote_directory());
        assert!(!run_posix_cache_command(home.path(), &command, None).success());
        assert!(
            !outside
                .path()
                .join(format!("v{}/linux-x64-gnu", env!("CARGO_PKG_VERSION")))
                .exists()
        );
        assert_eq!(
            fs::metadata(outside.path())
                .expect("outside metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_staging_chmod_rejects_a_symlinked_version_without_outside_mutation() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let outside = tempfile::tempdir().expect("outside version directory");
        let cache_root = home.path().join(".cache/satelle/host");
        fs::create_dir_all(&cache_root).expect("create cache root");
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o700))
            .expect("secure cache root");
        let target = outside.path().join("linux-x64-gnu");
        fs::create_dir(&target).expect("create outside target");
        let outside_staged = target.join(".satelle-upload-test");
        fs::write(&outside_staged, b"outside").expect("write outside staged file");
        fs::set_permissions(&outside_staged, fs::Permissions::from_mode(0o600))
            .expect("set outside staged permissions");
        symlink(
            outside.path(),
            cache_root.join(format!("v{}", env!("CARGO_PKG_VERSION"))),
        )
        .expect("symlink cache version");

        let staged = format!(
            "{}/.satelle-upload-test",
            RemoteTarget::LinuxX64Gnu.remote_directory()
        );
        let command = RemoteTarget::LinuxX64Gnu
            .prepare_staged_command(&staged)
            .expect("POSIX staging command");
        assert!(!run_posix_cache_command(home.path(), &command, None).success());
        assert_eq!(
            fs::metadata(&outside_staged)
                .expect("outside staged metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read(outside_staged).expect("read outside staged file"),
            b"outside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_promotion_rejects_a_symlinked_target_directory_without_outside_mutation() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let outside = tempfile::tempdir().expect("outside target directory");
        let version = home.path().join(format!(
            ".cache/satelle/host/v{}",
            env!("CARGO_PKG_VERSION")
        ));
        fs::create_dir_all(&version).expect("create cache version");
        for directory in [home.path().join(".cache/satelle/host"), version.clone()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("secure cache directory");
        }
        let outside_staged = outside.path().join(".satelle-upload-test");
        let outside_final = outside.path().join("satelle");
        fs::write(&outside_staged, b"staged").expect("write outside staged file");
        fs::write(&outside_final, b"final").expect("write outside final file");
        symlink(outside.path(), version.join("linux-x64-gnu")).expect("symlink target directory");

        let directory = RemoteTarget::LinuxX64Gnu.remote_directory();
        let command = RemoteTarget::LinuxX64Gnu.promote_command(
            &format!("{directory}/.satelle-upload-test"),
            &format!("{directory}/satelle"),
        );
        assert!(!run_posix_cache_command(home.path(), &command, None).success());
        assert_eq!(
            fs::read(outside_staged).expect("read staged file"),
            b"staged"
        );
        assert_eq!(fs::read(outside_final).expect("read final file"), b"final");
    }

    #[cfg(unix)]
    #[test]
    fn posix_staged_leaf_symlinks_cannot_upload_chmod_or_promote_outside_the_cache() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let outside = tempfile::tempdir().expect("outside directory");
        let directory = home.path().join(format!(
            ".cache/satelle/host/v{}/linux-x64-gnu",
            env!("CARGO_PKG_VERSION")
        ));
        fs::create_dir_all(&directory).expect("create cache target");
        for directory in [
            home.path().join(".cache/satelle/host"),
            home.path().join(format!(
                ".cache/satelle/host/v{}",
                env!("CARGO_PKG_VERSION")
            )),
            directory.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("secure cache directory");
        }
        let outside_file = outside.path().join("artifact");
        fs::write(&outside_file, b"outside").expect("write outside artifact");
        let staged = format!(
            "{}/.satelle-upload-test",
            RemoteTarget::LinuxX64Gnu.remote_directory()
        );
        symlink(&outside_file, home.path().join(&staged)).expect("symlink staged artifact");

        let upload = RemoteTarget::LinuxX64Gnu.upload_command(&staged, &"00".repeat(32));
        assert!(!run_posix_cache_command(home.path(), &upload, Some(b"replacement")).success());
        let chmod = RemoteTarget::LinuxX64Gnu
            .prepare_staged_command(&staged)
            .expect("POSIX staging command");
        assert!(!run_posix_cache_command(home.path(), &chmod, None).success());
        let promote = RemoteTarget::LinuxX64Gnu.promote_command(
            &staged,
            &format!("{}/satelle", RemoteTarget::LinuxX64Gnu.remote_directory()),
        );
        assert!(!run_posix_cache_command(home.path(), &promote, None).success());
        assert_eq!(
            fs::read(outside_file).expect("read outside artifact"),
            b"outside"
        );
        assert!(
            fs::symlink_metadata(home.path().join(staged))
                .expect("staged symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_cache_validation_rejects_links_types_and_broad_permissions() {
        let root = tempfile::tempdir().expect("temporary remote home");
        let directory = root.path().join(".cache/satelle/host/v1/linux-x64-gnu");
        fs::create_dir_all(&directory).expect("create cache path");
        for ancestor in [
            root.path().join(".cache/satelle/host"),
            root.path().join(".cache/satelle/host/v1"),
            directory.clone(),
        ] {
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))
                .expect("secure cache directory");
        }
        let binary = directory.join("satelle");
        fs::write(&binary, b"binary").expect("write cache binary");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .expect("secure cache binary");
        let command = RemoteTarget::LinuxX64Gnu
            .cache_validation_command(".cache/satelle/host/v1/linux-x64-gnu/satelle");
        let validate = || {
            Command::new("sh")
                .arg("-c")
                .arg(&command)
                .current_dir(root.path())
                .status()
                .expect("run cache validation")
                .success()
        };
        assert!(validate());

        fs::set_permissions(&binary, fs::Permissions::from_mode(0o600))
            .expect("remove execute permission");
        assert!(!validate());
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o500))
            .expect("set read and execute permissions");
        assert!(validate());

        fs::set_permissions(&binary, fs::Permissions::from_mode(0o720))
            .expect("broaden cache permissions");
        assert!(!validate());
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
            .expect("restore cache permissions");
        fs::remove_file(&binary).expect("remove binary");
        symlink("real-satelle", &binary).expect("create cache symlink");
        assert!(!validate());
        fs::remove_file(&binary).expect("remove symlink");
        fs::create_dir(&binary).expect("create directory at binary path");
        assert!(!validate());
    }

    #[test]
    fn windows_cache_validation_requires_owner_only_non_reparse_entries() {
        let command = RemoteTarget::WindowsX64Msvc
            .cache_validation_command("AppData/Local/Satelle/host/v1/win32-x64-msvc/satelle.exe");
        let script = decode_powershell_command(&command).expect("decode validation command");
        for required in [
            "PSIsContainer",
            "ReparsePoint",
            "WindowsIdentity]::GetCurrent().Name",
            "$acl.Owner -ne $identity",
            "$rule.IdentityReference.Value -ne $identity",
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_posix_cleanup_retains_current_and_previous_versions() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let cache_root = home.path().join(".cache/satelle/host");
        let versions = [
            "v0.0.1".to_string(),
            "v0.0.2".to_string(),
            format!("v{}", env!("CARGO_PKG_VERSION")),
        ];
        for version in &versions {
            let target = cache_root.join(version).join("linux-x64-gnu");
            fs::create_dir_all(&target).expect("create cache target");
            for path in [cache_root.clone(), cache_root.join(version), target.clone()] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .expect("secure cache directory");
            }
            let binary = target.join("satelle");
            fs::write(&binary, b"binary").expect("write cache binary");
            fs::set_permissions(binary, fs::Permissions::from_mode(0o700))
                .expect("secure cache binary");
        }

        let output = Command::new("sh")
            .arg("-c")
            .arg(RemoteTarget::LinuxX64Gnu.cache_cleanup_command())
            .current_dir(home.path())
            .output()
            .expect("run explicit cache cleanup");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            parse_cache_cleanup_report(&output.stdout).expect("parse cleanup result"),
            CacheCleanupReport {
                removed_entries: 1,
                retained_entries: 2,
            }
        );
        assert!(!cache_root.join("v0.0.1/linux-x64-gnu/satelle").exists());
        assert!(cache_root.join("v0.0.2/linux-x64-gnu/satelle").exists());
        assert!(
            cache_root
                .join(format!(
                    "v{}/linux-x64-gnu/satelle",
                    env!("CARGO_PKG_VERSION")
                ))
                .exists()
        );
    }

    #[test]
    fn cleanup_probes_processes_and_persistent_services_before_deletion() {
        let posix = RemoteTarget::LinuxX64Gnu.cache_cleanup_command();
        assert_occurs_before(&posix, "ps -eo comm=,args=", "rm -f --");
        assert_occurs_before(&posix, "systemctl --user cat satelle-host", "rm -f --");
        assert_occurs_before(&posix, "launchctl print", "rm -f --");
        assert!(posix.matches("safe_entry \"$entry\"").count() >= 2);

        let windows =
            decode_powershell_command(&RemoteTarget::WindowsX64Msvc.cache_cleanup_command())
                .expect("decode cleanup command");
        assert_occurs_before(&windows, "Win32_Process", "Remove-Item -LiteralPath");
        assert_occurs_before(&windows, "Win32_Service", "Remove-Item -LiteralPath");
        assert!(windows.matches("Test-SafeEntry").count() >= 3);
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
            ReadinessTimeouts {
                native: Duration::from_secs(1),
                provider: Duration::from_secs(2),
            },
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
            BootstrapStartContext {
                bootstrap_scope: SshBootstrapScope::Admin,
                bind: "127.0.0.1:0",
                maintenance: BootstrapMaintenanceContext {
                    operation_id: "test-operation",
                    operation_kind: bootstrap_lock::OperationKind::InitialSetup,
                },
            },
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
            ReadinessTimeouts {
                native: Duration::from_secs(1),
                provider: Duration::from_secs(2),
            },
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
            ReadinessTimeouts {
                native: Duration::from_secs(1),
                provider: Duration::from_secs(2),
            },
            "127.0.0.1:3001",
            &[],
        );
        assert!(empty_posix.contains(POSIX_DAEMON_ENVIRONMENT_CLEAR));

        let posix_environment = [("SATELLE_STATE_DIR", Path::new("/srv/satelle state"))];
        let configured_posix = RemoteTarget::LinuxX64Gnu.start_command_with_environment(
            "/tmp/satelle",
            SshBootstrapScope::Control,
            ReadinessTimeouts {
                native: Duration::from_secs(1),
                provider: Duration::from_secs(2),
            },
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
            ReadinessTimeouts {
                native: Duration::from_secs(1),
                provider: Duration::from_secs(2),
            },
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
            ReadinessTimeouts {
                native: Duration::from_secs(1),
                provider: Duration::from_secs(2),
            },
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
    fn bootstrap_lock_commands_use_native_remote_primitives_before_upload() {
        let request = bootstrap_lock::Request::new(
            "repair-operation",
            bootstrap_lock::OperationKind::MissingDaemonRepair,
            Some("controller@test".to_string()),
        )
        .expect("valid lock request");
        let posix = RemoteTarget::LinuxX64Gnu.bootstrap_lock_command(&request);
        assert!(posix.starts_with("sh -c "));
        assert!(posix.contains("mkdir -p \"$lock_root\""));
        assert!(posix.contains("mv \"$pending_path\" \"$claim_path\""));
        assert!(!posix.contains("host bootstrap-lock"));
        let windows = RemoteTarget::WindowsX64Msvc.bootstrap_lock_command(&request);
        let script = decode_powershell_command(&windows).expect("decode lock command");
        assert!(script.contains("New-Item -ItemType Directory -Force -Path $lockRoot"));
        assert!(script.contains("[IO.Directory]::Move($pendingPath, $claimPath)"));
        assert!(!script.contains("host bootstrap-lock"));
    }

    #[test]
    fn remote_mutations_verify_the_exact_claim_generation_before_execution() {
        let identity = "0123456789abcdef0123456789abcdef";
        let attempt = "fedcba9876543210fedcba9876543210";
        let basename = "claim.repair-operation.0123456789abcdef";
        let posix = RemoteTarget::LinuxX64Gnu.fenced_mutation_command(
            "repair-operation",
            identity,
            basename,
            "cache_upload",
            attempt,
            "sh -c 'cat >/tmp/staged'",
        );
        assert!(posix.contains("repair-operation"));
        assert!(posix.contains(identity));
        assert!(posix.contains(basename));
        assert!(posix.contains("cache_upload"));
        assert!(posix.contains("mutation_started"));
        assert!(posix.contains("mutation_phase"));
        assert!(posix.contains("mutation_attempt"));
        assert!(posix.contains(attempt));
        assert!(posix.contains(MUTATION_EXECUTE));
        assert!(posix.contains("execution_started.$attempt"));
        assert!(posix.contains("execution_succeeded.$attempt"));
        assert!(posix.contains("claim_path=\"$lock_root/$claim_basename\""));
        assert!(!posix.contains("for candidate in"));

        let windows = RemoteTarget::WindowsX64Msvc.fenced_mutation_command(
            "repair-operation",
            identity,
            basename,
            "cache_upload",
            attempt,
            "cmd.exe /d /c exit 0",
        );
        let script = decode_powershell_command(&windows).expect("decode fenced mutation command");
        assert!(script.contains("repair-operation"));
        assert!(script.contains(identity));
        assert!(script.contains(basename));
        assert!(script.contains("cache_upload"));
        assert!(script.contains("mutation_started"));
        assert!(script.contains("mutation_phase"));
        assert!(script.contains("mutation_attempt"));
        assert!(script.contains(attempt));
        assert!(script.contains(MUTATION_EXECUTE));
        assert!(script.contains("execution_started."));
        assert!(script.contains("execution_succeeded."));
        assert!(script.contains("[IO.FileMode]::CreateNew"));
        assert!(script.contains("[IO.FileShare]::None).Dispose()"));
        assert!(
            !script
                .contains("New-Item -ItemType Directory -Path (Join-Path $claimPath ('execution_")
        );
        assert!(script.contains("$claimPath = Join-Path $lockRoot $claimBasename"));
        assert!(script.contains("[IO.FileAttributes]::ReparsePoint"));
        assert!(!script.contains("$claims = @("));
        assert!(script.contains("Invoke-Expression $innerCommand"));
    }

    #[test]
    fn bootstrap_ready_returns_only_the_exact_published_claim_basename() {
        let identity = "0123456789abcdef0123456789abcdef";
        let basename = "claim.repair-operation.0123456789abcdef";
        let mut valid =
            std::io::Cursor::new(format!("{} {identity} {basename}\n", bootstrap_lock::READY));
        let ready = read_bootstrap_lock_ready(&mut valid).expect("valid exact claim");
        assert_eq!(ready.identity, identity);
        assert_eq!(ready.basename, basename);

        for invalid in [
            format!("{} {identity} {basename}.closing\n", bootstrap_lock::READY),
            format!("{} {identity} ../{basename}\n", bootstrap_lock::READY),
            format!("{} {identity}\n", bootstrap_lock::READY),
        ] {
            assert!(read_bootstrap_lock_ready(&mut std::io::Cursor::new(invalid)).is_err());
        }
    }

    #[test]
    fn windows_cache_hardening_uses_canonical_case_insensitive_containment() {
        let command = RemoteTarget::WindowsX64Msvc
            .create_directory_command("AppData/Local/Satelle/host/v1/windows-x64");
        let script = decode_powershell_command(&command).expect("decode cache hardening command");
        assert!(script.contains("[IO.Path]::GetFullPath"));
        assert!(script.contains(".Replace('/', $separator)"));
        assert!(script.contains("[StringComparer]::OrdinalIgnoreCase.Equals"));
        assert!(script.contains("StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)"));
        assert!(script.contains("Set-Acl -LiteralPath $currentPath"));
    }

    #[test]
    fn atomic_attempt_marker_creation_cannot_recreate_a_missing_claim_parent() {
        let state = tempfile::tempdir().expect("temporary state");
        let missing_claim = state
            .path()
            .join("bootstrap.lock/claim.operation.generation");
        let marker = missing_claim.join("execution_started.attempt");
        let error = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
            .expect_err("atomic leaf creation requires the exact claim parent");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!missing_claim.exists());
    }

    #[test]
    fn artifact_upload_receivers_stream_ssh_stdin_without_scp() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let posix = RemoteTarget::LinuxX64Gnu.upload_command("/tmp/staged", digest);
        assert!(posix.contains("cat >"));
        assert!(posix.contains("set -C"));
        assert!(posix.contains(digest));
        assert!(!posix.contains("scp"));

        let windows = RemoteTarget::WindowsX64Msvc.upload_command("C:/Satelle/staged.exe", digest);
        let script = decode_powershell_command(&windows).expect("decode upload receiver");
        assert!(script.contains("[Console]::OpenStandardInput()"));
        assert!(script.contains("[IO.FileMode]::CreateNew"));
        assert!(script.contains("Get-FileHash"));
        assert!(!script.contains("scp"));
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
        assert!(detached_script.contains("System.Diagnostics.ProcessStartInfo"));
        assert!(detached_script.contains("RedirectStandardInput = $true"));
        assert!(detached_script.contains("StandardInput.WriteLine($token)"));
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
                "exec 3<&0; nohup /tmp/satelle host start --bootstrap-token-stdin ",
                "--bootstrap-scope read --on-demand-idle-timeout-ms 75000 ",
                "--bootstrap-native-readiness-timeout-ms 2500 ",
                "--bootstrap-provider-smoke-timeout-ms 7500 --json ",
                "<&3 3<&- >/dev/null 2>&1 & exec 3<&-'"
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
        assert!(script.contains("--bootstrap-token-stdin"));
        assert!(script.contains("--bootstrap-scope read"));
        assert!(script.contains("--bootstrap-native-readiness-timeout-ms 2500"));
        assert!(script.contains("--bootstrap-provider-smoke-timeout-ms 7500"));
        assert!(script.contains("RedirectStandardInput = $true"));
        assert!(script.contains("StandardInput.WriteLine($token)"));
    }
}
