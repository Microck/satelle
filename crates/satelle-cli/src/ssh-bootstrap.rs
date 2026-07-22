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
const SERVICE_DEFINITION_LIMIT: usize = 64 * 1024;
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
const STAGED_DIGEST_MISMATCH_EXIT_CODE: i32 = 65;
const POSIX_CACHE_DIRECTORY_GUARD: &str = r#"safe_cache_directory() {
  expected_root=$1
  expected_directory=$2
  case "$expected_directory" in "$expected_root"|"$expected_root"/*) ;; *) return 1;; esac
  case "$expected_root" in /*) return 1;; esac
  uid=$(id -u) || return 1
  current=.
  owner=$(stat -c %u "$current" 2>/dev/null || stat -f %u "$current") || return 1
  [ "$owner" = "$uid" ] || return 1
  suffix=$expected_directory
  while [ -n "$suffix" ]; do
    component=${suffix%%/*}
    case "$component" in ''|.|..) return 1;; esac
    current=$current/$component
    [ ! -L "$current" ] || return 1
    if [ -e "$current" ]; then
      [ -d "$current" ] || return 1
      owner=$(stat -c %u "$current" 2>/dev/null || stat -f %u "$current") || return 1
      [ "$owner" = "$uid" ] || return 1
    fi
    if [ "$suffix" = "$component" ]; then suffix=; else suffix=${suffix#*/}; fi
  done
  return 0
}"#;
const POSIX_STAGED_FAILURE_CLEANUP: &str = r#"cleanup_staged_on_failure() {
  original_status=$?
  trap - EXIT
  [ "$original_status" -ne 0 ] || return 0
  safe_cache_directory "$root" "$staged_directory" || exit 75
  if [ ! -e "$staged" ] && [ ! -L "$staged" ]; then exit "$original_status"; fi
  [ -f "$staged" ] && [ ! -L "$staged" ] || exit 75
  uid=$(id -u) || exit 75
  owner=$(stat -c %u "$staged" 2>/dev/null || stat -f %u "$staged") || exit 75
  [ "$owner" = "$uid" ] || exit 75
  rm -f -- "$staged" || exit 75
  exit "$original_status"
}
trap cleanup_staged_on_failure EXIT"#;
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
        Self::launch_bound(
            destination,
            token,
            host_config,
            bootstrap_scope,
            BootstrapLaunchMode::Durable,
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
        Self::launch_bound(
            destination,
            token,
            host_config,
            bootstrap_scope,
            BootstrapLaunchMode::Ephemeral {
                previous_host_config,
            },
            bootstrap_lock,
        )
    }

    fn launch_bound(
        destination: &str,
        token: &ApiBearerToken,
        host_config: &HostConfig,
        bootstrap_scope: SshBootstrapScope,
        launch_mode: BootstrapLaunchMode<'_>,
        bootstrap_lock: &mut SshBootstrapLock,
    ) -> Result<Self, SshBootstrapError> {
        let target = RemoteTarget::probe(destination)?;
        let environment = target.validated_daemon_environment(host_config)?;
        let release_environment = launch_mode
            .release_host_config()
            .map(|previous_host_config| target.validated_daemon_environment(previous_host_config))
            .transpose()?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let directory = target.remote_directory();
        let remote_binary = upload_artifact(
            destination,
            target,
            artifact.path(),
            &directory,
            artifact.release_digest(),
            bootstrap_lock,
        )?;
        let (release_command, start_command) = target.state_owner_handoff_commands(
            remote_binary.remote_path(),
            release_environment.as_deref(),
            host_config,
            &environment,
            BootstrapStartContext {
                bootstrap_scope,
                bind: launch_mode.bind(),
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
        let target = RemoteTarget::probe(destination)?;
        let environment = target.validated_daemon_environment(host_config)?;
        let artifact = DownloadedArtifact::fetch(target)?;
        let directory = target.remote_directory();
        let remote_binary = upload_artifact(
            destination,
            target,
            artifact.path(),
            &directory,
            artifact.release_digest(),
            bootstrap_lock,
        )?;
        let (native_timeout, provider_timeout) = readiness_probe_timeouts(host_config);
        let command = target.durable_start_command_with_environment(
            remote_binary.remote_path(),
            idle_timeout,
            native_timeout,
            provider_timeout,
            &environment,
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
pub(super) enum RemoteTarget {
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
        let start_command = self.start_command_with_environment(
            remote_binary,
            start_context.bootstrap_scope,
            ReadinessTimeouts { native, provider },
            start_context.bind,
            environment,
        );
        (release_command, start_command)
    }

    pub(super) fn probe(destination: &str) -> Result<Self, SshBootstrapError> {
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

    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::LinuxArm64Gnu => "linux-arm64-gnu",
            Self::LinuxX64Gnu => "linux-x64-gnu",
            Self::DarwinArm64 => "darwin-arm64",
            Self::DarwinX64 => "darwin-x64",
            Self::WindowsArm64Msvc => "win32-arm64-msvc",
            Self::WindowsX64Msvc => "win32-x64-msvc",
        }
    }

    pub(super) const fn service_platform(
        self,
    ) -> satelle_core::daemon_service::DaemonServicePlatform {
        match self {
            Self::DarwinArm64 | Self::DarwinX64 => {
                satelle_core::daemon_service::DaemonServicePlatform::Macos
            }
            Self::WindowsArm64Msvc | Self::WindowsX64Msvc => {
                satelle_core::daemon_service::DaemonServicePlatform::Windows
            }
            Self::LinuxArm64Gnu | Self::LinuxX64Gnu => {
                satelle_core::daemon_service::DaemonServicePlatform::Linux
            }
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

    pub(super) fn planned_install_path(
        self,
        directories: &RemoteUserDirectories,
        digest: &[u8; 32],
    ) -> Result<String, SshBootstrapError> {
        let directory = self.artifact_directory(directories)?;
        Ok(self.promoted_executable_path(&directory, digest))
    }

    fn artifact_directory(
        self,
        directories: &RemoteUserDirectories,
    ) -> Result<String, SshBootstrapError> {
        if directories.target != self {
            return Err(SshBootstrapError::InvalidPersistentServiceDefinition);
        }
        let cache_root = if self.is_windows() {
            join_target_path(
                self,
                directories
                    .local_app_data
                    .as_deref()
                    .ok_or(SshBootstrapError::InvalidPersistentServiceDefinition)?,
                "Satelle/host",
            )
        } else if matches!(self, Self::DarwinArm64 | Self::DarwinX64) {
            join_target_path(self, &directories.home, "Library/Caches/Satelle/host")
        } else {
            let cache = directories
                .xdg_cache_home
                .as_deref()
                .map(str::to_string)
                .unwrap_or_else(|| join_target_path(self, &directories.home, ".cache"));
            join_target_path(self, &cache, "satelle/host")
        };
        Ok(join_target_path(
            self,
            &cache_root,
            &format!("v{}/{}", env!("CARGO_PKG_VERSION"), self.id()),
        ))
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
$status = 0
try {{
  Invoke-Expression $innerCommand
  if ($null -ne $LASTEXITCODE) {{ $status = $LASTEXITCODE }}
}} catch {{
  $status = 1
}}
$terminalClaimExact = $false
try {{
  $terminalClaimItem = Get-Item -LiteralPath $claimPath -Force -ErrorAction Stop
  $terminalStartedItem = Get-Item -LiteralPath (Join-Path $claimPath ('execution_started.' + $attempt)) -Force -ErrorAction Stop
  $terminalClaimExact = $terminalClaimItem.PSIsContainer -and
    (($terminalClaimItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and
    (-not $terminalStartedItem.PSIsContainer) -and
    (($terminalStartedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and
    (-not (Test-Path -LiteralPath (Join-Path $claimPath ('execution_retiring.' + $attempt)))) -and
    ((((Get-Content -LiteralPath (Join-Path $claimPath 'operation_id') -Raw).Trim()) -ceq $operationId)) -and
    ((((Get-Content -LiteralPath (Join-Path $claimPath 'claim_identity') -Raw).Trim()) -ceq $claimIdentity)) -and
    ((((Get-Content -LiteralPath (Join-Path $claimPath 'state') -Raw).Trim()) -ceq 'mutation_started')) -and
    ((((Get-Content -LiteralPath (Join-Path $claimPath 'mutation_phase') -Raw).Trim()) -ceq $phase)) -and
    ((((Get-Content -LiteralPath (Join-Path $claimPath 'mutation_attempt') -Raw).Trim()) -ceq $attempt))
}} catch {{
  $terminalClaimExact = $false
}}
if ($terminalClaimExact) {{
  if (($status -eq 0) -or
      (($status -eq {digest_mismatch_exit_code}) -and
       (($phase -ceq 'cache_upload') -or ($phase -ceq 'cache_staging_permissions')))) {{
    [IO.File]::Open((Join-Path $claimPath ('execution_succeeded.' + $attempt)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
  }} elseif ($phase -ceq 'daemon_start') {{
    [IO.File]::Open((Join-Path $claimPath ('execution_failed.' + $attempt)), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None).Dispose()
  }}
}}
exit $status"#,
                digest_mismatch_exit_code = STAGED_DIGEST_MISMATCH_EXIT_CODE,
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
gate="$(dd bs=1 count={execute_gate_length} 2>/dev/null && printf x)" || exit 75
[ "$gate" = '{MUTATION_EXECUTE}
x' ] || exit 75
state_root="${{SATELLE_STATE_DIR:-${{XDG_STATE_HOME:-$HOME/.local/state}}/satelle}}"
lock_root="$state_root/bootstrap.lock"
claim_path="$lock_root/$claim_basename"
exact_claim_attempt() {{
  [ -d "$claim_path" ] && [ ! -L "$claim_path" ] &&
  [ "$(cat "$claim_path/operation_id" 2>/dev/null)" = "$operation_id" ] &&
  [ "$(cat "$claim_path/claim_identity" 2>/dev/null)" = "$claim_identity" ] &&
  [ "$(cat "$claim_path/state" 2>/dev/null)" = mutation_started ] &&
  [ "$(cat "$claim_path/mutation_phase" 2>/dev/null)" = "$phase" ] &&
  [ "$(cat "$claim_path/mutation_attempt" 2>/dev/null)" = "$attempt" ]
}}
exact_terminal_attempt() {{
  exact_claim_attempt &&
  [ -d "$claim_path/execution_started.$attempt" ] &&
  [ ! -L "$claim_path/execution_started.$attempt" ] &&
  [ ! -e "$claim_path/execution_retiring.$attempt" ] &&
  [ ! -L "$claim_path/execution_retiring.$attempt" ]
}}
exact_claim_attempt || exit 75
mkdir "$claim_path/execution_started.$attempt" || exit 75
set +e
( eval "$inner_command" )
status=$?
set -e
if exact_terminal_attempt; then
  if [ "$status" -eq 0 ] || {{ [ "$status" -eq {digest_mismatch_exit_code} ] &&
       {{ [ "$phase" = cache_upload ] || [ "$phase" = cache_staging_permissions ]; }}; }}; then
    mkdir "$claim_path/execution_succeeded.$attempt" || exit 75
  elif [ "$phase" = daemon_start ]; then
    mkdir "$claim_path/execution_failed.$attempt" || exit 75
  fi
fi
exit "$status""#,
            execute_gate_length = MUTATION_EXECUTE.len() + 1,
            digest_mismatch_exit_code = STAGED_DIGEST_MISMATCH_EXIT_CODE,
        );
        format!("sh -c {}", posix_quote(&script))
    }

    fn upload_command(self, staged: &str, digest: &str) -> String {
        if self.is_windows() {
            let cleanup = self.windows_staged_failure_cleanup(staged);
            let ancestry_guard = self.windows_cache_directory_guard(remote_parent(staged));
            return powershell_encoded_command(&format!(
                r#"$ErrorActionPreference = 'Stop'
{cleanup}
{ancestry_guard}
$digestMismatch = $false
try {{
$inputStream = [Console]::OpenStandardInput()
$outputStream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {{ $inputStream.CopyTo($outputStream) }} finally {{ $outputStream.Dispose() }}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -cne {digest}) {{
  $digestMismatch = $true
  throw 'staged artifact digest mismatch'
}}
}} catch {{
  $originalFailure = $_
  try {{ Remove-ExactStagedOnFailure }} catch {{ exit 75 }}
  if ($digestMismatch) {{ exit {digest_mismatch_exit_code} }}
  throw $originalFailure
}}"#,
                cleanup = cleanup,
                ancestry_guard = ancestry_guard,
                digest = powershell_quote(digest),
                digest_mismatch_exit_code = STAGED_DIGEST_MISMATCH_EXIT_CODE,
            ));
        }
        let script = format!(
            "set -eu\numask 077\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\nstaged={}\nexpected={}\nstaged_directory=${{staged%/*}}\n{POSIX_STAGED_FAILURE_CLEANUP}\nsafe_cache_directory \"$root\" \"$staged_directory\"\n[ ! -e \"$staged\" ] && [ ! -L \"$staged\" ] || exit 1\nset -C\ncat >\"$staged\"\nif command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum \"$staged\" | awk '{{print $1}}'); elif command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 \"$staged\" | awk '{{print $1}}'); else actual=$(openssl dgst -sha256 \"$staged\" | awk '{{print $NF}}'); fi\n[ \"$actual\" = \"$expected\" ] || exit {STAGED_DIGEST_MISMATCH_EXIT_CODE}",
            posix_quote(self.remote_cache_root()),
            posix_quote(staged),
            posix_quote(digest),
        );
        format!("sh -c {}", posix_quote(&script))
    }

    fn create_directory_command(self, directory: &str) -> String {
        if self.is_windows() {
            let ancestry_guard = self.windows_cache_directory_guard(directory);
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; {ancestry_guard}",
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
                    "if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ exit 1 }}; ",
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
                ancestry_guard = ancestry_guard,
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
            let cleanup = self.windows_staged_failure_cleanup(staged);
            let staged_guard = self.windows_cache_leaf_guard(staged);
            let final_parent_guard = self.windows_cache_directory_guard(remote_parent(final_path));
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; {cleanup}{staged_guard}{final_parent_guard}",
                    "$finalPath={}; if (Test-Path -LiteralPath $finalPath) {{ ",
                    "$finalItem=Get-Item -LiteralPath $finalPath -Force -ErrorAction Stop; ",
                    "if (($finalItem -isnot [IO.FileInfo]) -or $finalItem.PSIsContainer -or ",
                    "(($finalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 1 }} }}; ",
                    "try {{ Move-Item -Force -LiteralPath $path -Destination $finalPath; ",
                    "$acl=Get-Acl -LiteralPath $finalPath; $acl.SetAccessRuleProtection($true,$false); ",
                    "foreach ($rule in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleAll($rule) }}; ",
                    "$rule=New-Object System.Security.AccessControl.FileSystemAccessRule(",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','Allow'); ",
                    "$acl.SetAccessRule($rule); Set-Acl -LiteralPath $finalPath -AclObject $acl }} catch {{ ",
                    "$originalFailure=$_; try {{ Remove-ExactStagedOnFailure }} catch {{ exit 75 }}; ",
                    "throw $originalFailure }}",
                ),
                powershell_quote(final_path),
                cleanup = cleanup,
                staged_guard = staged_guard,
                final_parent_guard = final_parent_guard,
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "set -eu\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\nstaged={}\nfinal_path={}\nstaged_directory=${{staged%/*}}\nfinal_directory=${{final_path%/*}}\n{POSIX_STAGED_FAILURE_CLEANUP}\nsafe_cache_directory \"$root\" \"$staged_directory\"\nsafe_cache_directory \"$root\" \"$final_directory\"\n[ -f \"$staged\" ] && [ ! -L \"$staged\" ] || exit 1\n[ ! -L \"$final_path\" ] || exit 1\nmv -f \"$staged\" \"$final_path\"",
                posix_quote(self.remote_cache_root()),
                posix_quote(staged),
                posix_quote(final_path),
            );
            format!("sh -c {}", posix_quote(&script))
        }
    }

    fn windows_cache_path_context(self, remote_path: &str, failure_exit_code: u8) -> String {
        debug_assert!(self.is_windows());
        format!(
            concat!(
                "$separator=[IO.Path]::DirectorySeparatorChar; ",
                "$root=[IO.Path]::GetFullPath(({}).Replace('/', $separator)); ",
                "$path=[IO.Path]::GetFullPath(({}).Replace('/', $separator)); ",
                "$anchor=[IO.Path]::GetFullPath([IO.Path]::GetPathRoot($root)); ",
                "$anchorPrefix=$anchor.TrimEnd($separator)+$separator; ",
                "if (-not [StringComparer]::OrdinalIgnoreCase.Equals($root,$anchor) -and ",
                "-not $root.StartsWith($anchorPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit {failure_exit_code} }}; ",
                "$rootPrefix=$root.TrimEnd($separator)+$separator; ",
                "if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path,$root) -and ",
                "-not $path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit {failure_exit_code} }}; ",
            ),
            powershell_quote(self.remote_cache_root()),
            powershell_quote(remote_path),
            failure_exit_code = failure_exit_code,
        )
    }

    fn windows_cache_directory_guard(self, directory: &str) -> String {
        self.windows_cache_directory_guard_with_exit(directory, 1)
    }

    fn windows_cache_directory_guard_with_exit(
        self,
        directory: &str,
        failure_exit_code: u8,
    ) -> String {
        let path_context = self.windows_cache_path_context(directory, failure_exit_code);
        format!(
            concat!(
                "& {{ {path_context}",
                "$currentPath=$path; while ($true) {{ ",
                "if (Test-Path -LiteralPath $currentPath) {{ ",
                "$current=Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop; ",
                "if (-not $current.PSIsContainer -or ",
                "(($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit {failure_exit_code} }} }}; ",
                "if ([StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$anchor)) {{ break }}; ",
                "$parentPath=[IO.Path]::GetDirectoryName($currentPath); ",
                "if ([String]::IsNullOrEmpty($parentPath) -or ",
                "[StringComparer]::OrdinalIgnoreCase.Equals($parentPath,$currentPath)) {{ exit {failure_exit_code} }}; ",
                "$currentPath=$parentPath }} }}; ",
            ),
            path_context = path_context,
            failure_exit_code = failure_exit_code,
        )
    }

    fn windows_cache_leaf_guard(self, remote_path: &str) -> String {
        let path_context = self.windows_cache_path_context(remote_path, 1);
        format!(
            concat!(
                "{path_context}",
                "$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop; ",
                "if (($item -isnot [IO.FileInfo]) -or $item.PSIsContainer -or ",
                "(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 1 }}; ",
                "$current=$item; while ($true) {{ ",
                "$currentPath=[IO.Path]::GetFullPath($current.FullName); ",
                "if (-not [StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$anchor) -and ",
                "-not $currentPath.StartsWith($anchorPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit 1 }}; ",
                "if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ exit 1 }}; ",
                "if ([StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$anchor)) {{ break }}; ",
                "$current=$current.Parent; if ($null -eq $current) {{ exit 1 }} }}; ",
            ),
            path_context = path_context,
        )
    }

    fn windows_staged_failure_cleanup(self, staged: &str) -> String {
        debug_assert!(self.is_windows());
        let ancestry_guard =
            self.windows_cache_directory_guard_with_exit(remote_parent(staged), 75);
        format!(
            r#"$separator=[IO.Path]::DirectorySeparatorChar
$root=[IO.Path]::GetFullPath(({}).Replace('/', $separator))
$path=[IO.Path]::GetFullPath(({}).Replace('/', $separator))
$rootPrefix=$root.TrimEnd($separator)+$separator
$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
function Remove-ExactStagedOnFailure {{
  if (-not [StringComparer]::OrdinalIgnoreCase.Equals($path,$root) -and
      -not $path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit 75 }}
  if (-not (Test-Path -LiteralPath $path)) {{ return }}
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item -isnot [IO.FileInfo]) -or $item.PSIsContainer -or
      (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 75 }}
  $current=$item
  while ($true) {{
    $currentPath=[IO.Path]::GetFullPath($current.FullName)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$root) -and
        -not $currentPath.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) {{ exit 75 }}
    if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ exit 75 }}
    $acl=Get-Acl -LiteralPath $current.FullName
    if ($acl.Owner -ne $identity) {{ exit 75 }}
    foreach ($rule in $acl.Access) {{
      if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne $identity) {{ exit 75 }}
    }}
    if ([StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$root)) {{ break }}
    $current=$current.Parent
    if ($null -eq $current) {{ exit 75 }}
  }}
  {ancestry_guard}
  Remove-Item -LiteralPath $path -Force -ErrorAction Stop
}}"#,
            powershell_quote(self.remote_cache_root()),
            powershell_quote(staged),
            ancestry_guard = ancestry_guard,
        )
    }

    fn cache_validation_command(self, remote_path: &str) -> String {
        if self.is_windows() {
            let safety_guard = self.windows_cache_leaf_guard(remote_path);
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; {safety_guard}",
                    "$identity=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; ",
                    "$current=$item; while ($true) {{ ",
                    "$acl=Get-Acl -LiteralPath $current.FullName; if ($acl.Owner -ne $identity) {{ exit 1 }}; ",
                    "foreach ($rule in $acl.Access) {{ if ($rule.AccessControlType -eq 'Allow' -and ",
                    "$rule.IdentityReference.Value -ne $identity) {{ exit 1 }} }}; ",
                    "if ([StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($current.FullName),$root)) {{ break }}; ",
                    "$current=$current.Parent; if ($null -eq $current) {{ exit 1 }} }}",
                ),
                safety_guard = safety_guard,
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

    fn prepare_staged_command(self, staged: &str, digest: &str) -> Option<String> {
        if self.is_windows() {
            let safety_guard = self.windows_cache_leaf_guard(staged);
            let cleanup = self.windows_staged_failure_cleanup(staged);
            let script = format!(
                concat!(
                    "$ErrorActionPreference='Stop'; {cleanup}$digestMismatch=$false; try {{ ",
                    "{safety_guard}",
                    "if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant() -cne {digest}) {{ ",
                    "$digestMismatch=$true; throw 'staged artifact digest mismatch' }}; ",
                    "$acl=Get-Acl -LiteralPath $path; $acl.SetAccessRuleProtection($true,$false); ",
                    "foreach ($rule in @($acl.Access)) {{ [void]$acl.RemoveAccessRuleAll($rule) }}; ",
                    "$rule=New-Object System.Security.AccessControl.FileSystemAccessRule(",
                    "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,'FullControl','Allow'); ",
                    "$acl.SetAccessRule($rule); Set-Acl -LiteralPath $path -AclObject $acl }} catch {{ ",
                    "$originalFailure=$_; try {{ Remove-ExactStagedOnFailure }} catch {{ exit 75 }}; ",
                    "if ($digestMismatch) {{ exit {digest_mismatch_exit_code} }}; throw $originalFailure }}",
                ),
                cleanup = cleanup,
                safety_guard = safety_guard,
                digest = powershell_quote(digest),
                digest_mismatch_exit_code = STAGED_DIGEST_MISMATCH_EXIT_CODE,
            );
            Some(powershell_encoded_command(&script))
        } else {
            let script = format!(
                "set -eu\n{POSIX_CACHE_DIRECTORY_GUARD}\nroot={}\nstaged={}\nexpected={}\nstaged_directory=${{staged%/*}}\n{POSIX_STAGED_FAILURE_CLEANUP}\nsafe_cache_directory \"$root\" \"$staged_directory\"\n[ -f \"$staged\" ] && [ ! -L \"$staged\" ] || exit 1\nif command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum \"$staged\" | awk '{{print $1}}'); elif command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 \"$staged\" | awk '{{print $1}}'); else actual=$(openssl dgst -sha256 \"$staged\" | awk '{{print $NF}}'); fi\n[ \"$actual\" = \"$expected\" ] || exit {STAGED_DIGEST_MISMATCH_EXIT_CODE}\nchmod 700 \"$staged\"",
                posix_quote(self.remote_cache_root()),
                posix_quote(staged),
                posix_quote(digest),
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

    fn start_command_with_environment(
        self,
        remote_binary: &str,
        bootstrap_scope: SshBootstrapScope,
        readiness_timeouts: ReadinessTimeouts,
        bind: &str,
        environment: &[(&'static str, &Path)],
    ) -> String {
        let timeout_args = format!(
            "--bind {bind} --bootstrap-scope {} --bootstrap-native-readiness-timeout-ms {} --bootstrap-provider-smoke-timeout-ms {}",
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

    fn durable_start_command_with_environment(
        self,
        remote_binary: &str,
        idle_timeout: Duration,
        native_timeout: Duration,
        provider_timeout: Duration,
        environment: &[(&'static str, &Path)],
    ) -> String {
        let timeout_args = format!(
            "--bootstrap-token-stdin --bootstrap-scope {} --on-demand-idle-timeout-ms {} --bootstrap-native-readiness-timeout-ms {} --bootstrap-provider-smoke-timeout-ms {}",
            SshBootstrapScope::Read.as_cli_value(),
            idle_timeout.as_millis(),
            native_timeout.as_millis(),
            provider_timeout.as_millis(),
        );
        if self.is_windows() {
            let script = format!(
                concat!(
                    "{}Add-Type -TypeDefinition '",
                    "using System; using System.Runtime.InteropServices; ",
                    "public static class SatelleBootstrapNative {{ ",
                    "[DllImport(\"kernel32.dll\", SetLastError=true)] ",
                    "public static extern IntPtr GetStdHandle(int stream); ",
                    "[DllImport(\"kernel32.dll\", SetLastError=true)] ",
                    "public static extern bool GetHandleInformation(IntPtr handle, out uint flags); ",
                    "[DllImport(\"kernel32.dll\", SetLastError=true)] ",
                    "public static extern bool SetStdHandle(int stream, IntPtr handle); ",
                    "[DllImport(\"kernel32.dll\", SetLastError=true)] ",
                    "public static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags); ",
                    "}}'; ",
                    "$originalInput = [SatelleBootstrapNative]::GetStdHandle(-10); ",
                    "$originalOutput = [SatelleBootstrapNative]::GetStdHandle(-11); ",
                    "$originalError = [SatelleBootstrapNative]::GetStdHandle(-12); ",
                    "[uint32]$inputFlags = 0; [uint32]$outputFlags = 0; [uint32]$errorFlags = 0; ",
                    "if (-not [SatelleBootstrapNative]::GetHandleInformation($originalInput,[ref]$inputFlags)) {{ exit 1 }}; ",
                    "if (-not [SatelleBootstrapNative]::GetHandleInformation($originalOutput,[ref]$outputFlags)) {{ exit 1 }}; ",
                    "if (-not [SatelleBootstrapNative]::GetHandleInformation($originalError,[ref]$errorFlags)) {{ exit 1 }}; ",
                    "$nullOutput = [IO.File]::Open('NUL',[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite); ",
                    "$nullHandle = $nullOutput.SafeFileHandle.DangerousGetHandle(); ",
                    "$binary = (Resolve-Path -LiteralPath {}).Path; ",
                    "$process = $null; try {{ ",
                    "if (-not [SatelleBootstrapNative]::SetHandleInformation($originalInput,1,0)) {{ throw 'stdin inheritance' }}; ",
                    "if (-not [SatelleBootstrapNative]::SetHandleInformation($originalOutput,1,0)) {{ throw 'stdout inheritance' }}; ",
                    "if (-not [SatelleBootstrapNative]::SetHandleInformation($originalError,1,0)) {{ throw 'stderr inheritance' }}; ",
                    "if (-not [SatelleBootstrapNative]::SetHandleInformation($nullHandle,1,1)) {{ throw 'null inheritance' }}; ",
                    "if (-not [SatelleBootstrapNative]::SetStdHandle(-11,$nullHandle)) {{ throw 'stdout sink' }}; ",
                    "if (-not [SatelleBootstrapNative]::SetStdHandle(-12,$nullHandle)) {{ throw 'stderr sink' }}; ",
                    "$startInfo = New-Object System.Diagnostics.ProcessStartInfo; ",
                    "$startInfo.FileName = $binary; $startInfo.Arguments = 'host start {} --json'; ",
                    "$startInfo.UseShellExecute = $false; $startInfo.CreateNoWindow = $true; ",
                    "$startInfo.RedirectStandardInput = $true; ",
                    "$startInfo.RedirectStandardOutput = $false; ",
                    "$startInfo.RedirectStandardError = $false; ",
                    "$process = New-Object System.Diagnostics.Process; $process.StartInfo = $startInfo; ",
                    "if (-not $process.Start()) {{ throw 'process start' }}; ",
                    "$token = [Console]::In.ReadLine(); ",
                    "if ([String]::IsNullOrEmpty($token)) {{ $process.Kill(); throw 'bootstrap token' }}; ",
                    "$process.StandardInput.WriteLine($token); $process.StandardInput.Close() ",
                    "}} finally {{ ",
                    "$restoreInput = [SatelleBootstrapNative]::SetStdHandle(-10,$originalInput); ",
                    "$restoreOutput = [SatelleBootstrapNative]::SetStdHandle(-11,$originalOutput); ",
                    "$restoreError = [SatelleBootstrapNative]::SetStdHandle(-12,$originalError); ",
                    "$restoreInputFlags = [SatelleBootstrapNative]::SetHandleInformation($originalInput,1,($inputFlags -band 1)); ",
                    "$restoreOutputFlags = [SatelleBootstrapNative]::SetHandleInformation($originalOutput,1,($outputFlags -band 1)); ",
                    "$restoreErrorFlags = [SatelleBootstrapNative]::SetHandleInformation($originalError,1,($errorFlags -band 1)); ",
                    "$nullOutput.Dispose(); if ($null -ne $process) {{ $process.Dispose() }}; ",
                    "if (-not ($restoreInput -and $restoreOutput -and $restoreError -and $restoreInputFlags -and $restoreOutputFlags -and $restoreErrorFlags)) {{ throw 'standard handle restore' }} ",
                    "}}"
                ),
                powershell_environment(environment),
                powershell_quote(remote_binary),
                timeout_args,
            );
            powershell_encoded_command(&script)
        } else {
            let script = format!(
                "exec 3<&0; {}nohup {remote_binary} host start {timeout_args} --json <&3 3<&- >/dev/null 2>&1 & exec 3<&-",
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
            // The fence wrapper must remain alive to record the successful
            // release. Running the binary directly also keeps it as the
            // wrapper's child instead of inserting another shell process.
            format!(
                "{}{remote_binary} host release-state",
                posix_environment(environment),
                remote_binary = posix_quote(remote_binary),
            )
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RemoteUserDirectories {
    target: RemoteTarget,
    home: String,
    local_app_data: Option<String>,
    roaming_app_data: Option<String>,
    xdg_config_home: Option<String>,
    xdg_cache_home: Option<String>,
    xdg_state_home: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UploadedHostArtifact {
    remote_path: String,
    binary_sha256: String,
}

impl UploadedHostArtifact {
    pub(super) fn remote_path(&self) -> &str {
        &self.remote_path
    }

    pub(super) fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VerifiedCurrentWindowsTask {
    definition: satelle_core::daemon_service::WindowsTaskDefinition,
    executable_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PersistentServiceObservation {
    Absent,
    Matching,
    Drifted,
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LoopbackListenerObservation {
    Present,
    Absent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LaunchdServiceDefinition {
    plist_path: String,
    contents: String,
}

impl LaunchdServiceDefinition {
    pub(super) fn plist_path(&self) -> &str {
        &self.plist_path
    }

    pub(super) fn contents(&self) -> &str {
        &self.contents
    }
}

/// Executes persistent-service mutations only through the active bootstrap
/// fence. Transport orchestration selects phases and postconditions, while
/// this type owns target-native quoting, publication, and service-manager I/O.
pub(super) struct PersistentServiceRemote<'a> {
    destination: &'a str,
    target: RemoteTarget,
    directories: &'a RemoteUserDirectories,
    bootstrap_lock: &'a mut SshBootstrapLock,
}

impl<'a> PersistentServiceRemote<'a> {
    pub(super) fn new(
        destination: &'a str,
        target: RemoteTarget,
        directories: &'a RemoteUserDirectories,
        bootstrap_lock: &'a mut SshBootstrapLock,
    ) -> Result<Self, SshBootstrapError> {
        if target.service_platform() == satelle_core::daemon_service::DaemonServicePlatform::Linux
            || directories.target != target
        {
            return Err(SshBootstrapError::PersistentServiceUnsupported);
        }
        Ok(Self {
            destination,
            target,
            directories,
            bootstrap_lock,
        })
    }

    pub(super) fn install_current_host_artifact(
        &mut self,
    ) -> Result<UploadedHostArtifact, SshBootstrapError> {
        let artifact = DownloadedArtifact::fetch(self.target)?;
        let directory = self.target.artifact_directory(self.directories)?;
        upload_artifact(
            self.destination,
            self.target,
            artifact.path(),
            &directory,
            artifact.release_digest(),
            self.bootstrap_lock,
        )
    }

    pub(super) fn ensure_owner_only_directories(
        &mut self,
        directories: &[String],
    ) -> Result<(), SshBootstrapError> {
        if directories.is_empty()
            || directories
                .iter()
                .any(|path| !target_path_is_absolute(self.target, path))
        {
            return Err(SshBootstrapError::InvalidPersistentServiceDefinition);
        }
        let command = persistent_directory_command(self.target, directories);
        self.mutate("persistent_path_directories", &command, None)
    }

    pub(super) fn prepare_windows_task(
        &self,
        host_id: &str,
        artifact: &UploadedHostArtifact,
    ) -> Result<satelle_core::daemon_service::WindowsTaskDefinition, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        let account = self.observe_windows_account()?;
        let executable = self.observe_windows_executable(artifact)?;
        satelle_core::daemon_service::WindowsTaskDefinition::for_host(
            host_id,
            &account,
            &executable,
        )
        .map_err(|_| SshBootstrapError::InvalidPersistentServiceDefinition)
    }

    pub(super) fn current_windows_task_definition(
        &self,
        host_id: &str,
    ) -> Result<VerifiedCurrentWindowsTask, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        let artifact = DownloadedArtifact::fetch(self.target)?;
        let remote_path = self
            .target
            .planned_install_path(self.directories, &artifact.release_digest())?;
        let binary_sha256: String = sha256_file(artifact.path())?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let definition = self.prepare_windows_task(
            host_id,
            &UploadedHostArtifact {
                remote_path,
                binary_sha256: binary_sha256.clone(),
            },
        )?;
        Ok(VerifiedCurrentWindowsTask {
            definition,
            executable_sha256: binary_sha256,
        })
    }

    pub(super) fn publish_windows_service_config(
        &mut self,
        task: &satelle_core::daemon_service::WindowsTaskDefinition,
        config: &satelle_core::daemon_service::WindowsServiceConfigV1,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        let contents = serde_json::to_vec_pretty(config)
            .map_err(|_| SshBootstrapError::InvalidPersistentServiceDefinition)?;
        self.publish_definition(&task.service_config_path, &contents)
    }

    pub(super) fn register_windows_task(
        &mut self,
        task: &satelle_core::daemon_service::WindowsTaskDefinition,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        self.mutate(
            "persistent_service_register",
            &windows_task_register_command(task),
            None,
        )
    }

    pub(super) fn observe_windows_task(
        &self,
        task: &satelle_core::daemon_service::WindowsTaskDefinition,
    ) -> Result<PersistentServiceObservation, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        self.observe(&windows_task_observe_command(task))
    }

    pub(super) fn start_windows_task(
        &mut self,
        task: &satelle_core::daemon_service::WindowsTaskDefinition,
    ) -> Result<(), SshBootstrapError> {
        self.windows_task_mutation("persistent_service_start", task, "start")
    }

    pub(super) fn restart_windows_task(
        &mut self,
        task: &satelle_core::daemon_service::WindowsTaskDefinition,
    ) -> Result<(), SshBootstrapError> {
        self.windows_task_mutation("persistent_service_restart", task, "restart")
    }

    pub(super) fn restart_current_windows_task(
        &mut self,
        task: &VerifiedCurrentWindowsTask,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        self.mutate(
            "persistent_service_restart",
            &windows_task_lifecycle_command(task, "restart"),
            None,
        )
    }

    pub(super) fn stop_current_windows_task(
        &mut self,
        task: &VerifiedCurrentWindowsTask,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        self.mutate(
            "persistent_service_stop",
            &windows_task_lifecycle_command(task, "stop"),
            None,
        )
    }

    pub(super) fn observe_current_windows_task(
        &self,
        task: &VerifiedCurrentWindowsTask,
    ) -> Result<PersistentServiceObservation, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        self.observe(&windows_task_lifecycle_command(task, "observe"))
    }

    pub(super) fn launchd_definition(
        &self,
        artifact: &UploadedHostArtifact,
        overrides: &DaemonPathOverrides,
    ) -> Result<LaunchdServiceDefinition, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        let binary = self.absolute_artifact_path(artifact);
        let contents = satelle_core::daemon_service::render_launchd_user_plist(
            Path::new(&binary),
            "127.0.0.1:3001",
            overrides,
        )
        .map_err(|_| SshBootstrapError::InvalidPersistentServiceDefinition)?;
        Ok(LaunchdServiceDefinition {
            plist_path: join_target_path(
                self.target,
                &self.directories.home,
                "Library/LaunchAgents/dev.microck.satelle.host.plist",
            ),
            contents,
        })
    }

    pub(super) fn publish_launchd_definition(
        &mut self,
        definition: &LaunchdServiceDefinition,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        self.publish_definition(definition.plist_path(), definition.contents().as_bytes())
    }

    pub(super) fn register_launchd(
        &mut self,
        definition: &LaunchdServiceDefinition,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        self.mutate(
            "persistent_service_register",
            &launchd_register_command(definition.plist_path()),
            None,
        )
    }

    pub(super) fn observe_launchd(
        &self,
        definition: &LaunchdServiceDefinition,
    ) -> Result<PersistentServiceObservation, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        self.observe(&launchd_observe_command(definition))
    }

    pub(super) fn kickstart_launchd(&mut self) -> Result<(), SshBootstrapError> {
        self.launchd_mutation("persistent_service_start", "kickstart")
    }

    pub(super) fn restart_launchd(&mut self) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        let plist_path = join_target_path(
            self.target,
            &self.directories.home,
            "Library/LaunchAgents/dev.microck.satelle.host.plist",
        );
        self.mutate(
            "persistent_service_restart",
            &launchd_register_command(&plist_path),
            None,
        )
    }

    pub(super) fn bootout_launchd(&mut self) -> Result<(), SshBootstrapError> {
        self.launchd_mutation("persistent_service_stop", "bootout")
    }

    pub(super) fn observe_launchd_runtime(
        &self,
    ) -> Result<PersistentServiceObservation, SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        self.observe(&launchd_lifecycle_command("observe_runtime"))
    }

    pub(super) fn observe_loopback_listener(
        &self,
    ) -> Result<LoopbackListenerObservation, SshBootstrapError> {
        let output = require_success_output(run_ssh_command_with_output_limit(
            self.destination,
            &loopback_listener_observation_command(self.target),
            PROBE_OUTPUT_LIMIT,
        )?)?;
        parse_loopback_listener_observation(&output.stdout)
    }

    pub(super) fn observe_canonical_daemon_path_overrides(
        &self,
        host_id: &str,
    ) -> Result<DaemonPathOverrides, SshBootstrapError> {
        let command =
            service_path_overrides_observation_command(self.target, self.directories, host_id)?;
        let output = require_success_output(run_ssh_command_with_output_limit(
            self.destination,
            &command,
            SERVICE_DEFINITION_LIMIT,
        )?)?;
        parse_service_path_overrides(self.target, &output.stdout)
    }

    fn observe_windows_account(
        &self,
    ) -> Result<satelle_core::daemon_service::AuthenticatedWindowsAccount, SshBootstrapError> {
        let expected_local_app_data = self
            .directories
            .local_app_data
            .as_deref()
            .ok_or(SshBootstrapError::InvalidServiceObservation)?;
        let output = require_success_output(run_ssh_command_with_output_limit(
            self.destination,
            &windows_account_observation_command(),
            PROBE_OUTPUT_LIMIT,
        )?)?;
        let observation: WindowsAccountObservation = serde_json::from_slice(&output.stdout)
            .map_err(|_| SshBootstrapError::InvalidServiceObservation)?;
        if observation.protocol != "satelle-windows-account-v1"
            || !same_windows_path_text(
                &observation.requested_local_app_data,
                expected_local_app_data,
            )
        {
            return Err(SshBootstrapError::InvalidServiceObservation);
        }
        satelle_core::daemon_service::AuthenticatedWindowsAccount::from_observation(
            &observation.requested_sid,
            &observation.observed_sid,
            &observation.requested_local_app_data,
            &observation.observed_local_app_data,
        )
        .map_err(|_| SshBootstrapError::InvalidServiceObservation)
    }

    fn observe_windows_executable(
        &self,
        artifact: &UploadedHostArtifact,
    ) -> Result<satelle_core::daemon_service::VerifiedWindowsExecutable, SshBootstrapError> {
        let requested_path = self.absolute_artifact_path(artifact);
        let output = require_success_output(run_ssh_command_with_output_limit(
            self.destination,
            &windows_executable_observation_command(&requested_path),
            PROBE_OUTPUT_LIMIT,
        )?)?;
        let observation: WindowsExecutableObservation = serde_json::from_slice(&output.stdout)
            .map_err(|_| SshBootstrapError::InvalidServiceObservation)?;
        if observation.protocol != "satelle-windows-executable-v1"
            || !same_windows_path_text(&requested_path, &observation.requested_path)
        {
            return Err(SshBootstrapError::InvalidServiceObservation);
        }
        let kind = match observation.kind.as_str() {
            "regular_file" => satelle_core::daemon_service::WindowsObservedPathKind::RegularFile,
            "reparse_point" => satelle_core::daemon_service::WindowsObservedPathKind::ReparsePoint,
            "directory" => satelle_core::daemon_service::WindowsObservedPathKind::Directory,
            "missing" => satelle_core::daemon_service::WindowsObservedPathKind::Missing,
            _ => return Err(SshBootstrapError::InvalidServiceObservation),
        };
        satelle_core::daemon_service::VerifiedWindowsExecutable::from_observation(
            &observation.requested_path,
            &observation.canonical_path,
            kind,
            artifact.binary_sha256(),
            &observation.sha256,
        )
        .map_err(|_| SshBootstrapError::InvalidServiceObservation)
    }

    fn windows_task_mutation(
        &mut self,
        phase: &str,
        task: &satelle_core::daemon_service::WindowsTaskDefinition,
        action: &str,
    ) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Windows)?;
        self.mutate(phase, &windows_task_instance_command(task, action), None)
    }

    fn launchd_mutation(&mut self, phase: &str, action: &str) -> Result<(), SshBootstrapError> {
        self.require_platform(satelle_core::daemon_service::DaemonServicePlatform::Macos)?;
        self.mutate(phase, &launchd_lifecycle_command(action), None)
    }

    fn publish_definition(
        &mut self,
        remote_path: &str,
        contents: &[u8],
    ) -> Result<(), SshBootstrapError> {
        if contents.is_empty() || contents.len() > SERVICE_DEFINITION_LIMIT {
            return Err(SshBootstrapError::ServiceDefinitionTooLarge);
        }
        if !target_path_is_absolute(self.target, remote_path) {
            return Err(SshBootstrapError::InvalidPersistentServiceDefinition);
        }
        let command = service_definition_publish_command(self.target, remote_path);
        self.mutate(
            "persistent_service_definition",
            &command,
            Some(FencedMutationInput::ServiceDefinition(contents)),
        )
    }

    fn mutate(
        &mut self,
        phase: &str,
        command: &str,
        input: Option<FencedMutationInput<'_>>,
    ) -> Result<(), SshBootstrapError> {
        let command = self
            .bootstrap_lock
            .fenced_command(self.target, phase, command)?;
        require_success(run_fenced_ssh_command(self.destination, &command, input)?)
    }

    fn observe(&self, command: &str) -> Result<PersistentServiceObservation, SshBootstrapError> {
        let output = require_success_output(run_ssh_command_with_output_limit(
            self.destination,
            command,
            PROBE_OUTPUT_LIMIT,
        )?)?;
        parse_persistent_service_observation(&output.stdout)
    }

    fn require_platform(
        &self,
        expected: satelle_core::daemon_service::DaemonServicePlatform,
    ) -> Result<(), SshBootstrapError> {
        (self.target.service_platform() == expected)
            .then_some(())
            .ok_or(SshBootstrapError::PersistentServiceUnsupported)
    }

    fn absolute_artifact_path(&self, artifact: &UploadedHostArtifact) -> String {
        if target_path_is_absolute(self.target, artifact.remote_path()) {
            artifact.remote_path().to_string()
        } else {
            join_target_path(self.target, &self.directories.home, artifact.remote_path())
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsAccountObservation {
    protocol: String,
    requested_sid: String,
    observed_sid: String,
    requested_local_app_data: String,
    observed_local_app_data: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsExecutableObservation {
    protocol: String,
    requested_path: String,
    canonical_path: String,
    kind: String,
    sha256: String,
}

fn windows_account_observation_command() -> String {
    powershell_encoded_command(
        r#"$ErrorActionPreference='Stop'
$whoami=whoami.exe /user /fo csv /nh | ConvertFrom-Csv -Header Name,Sid
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$result=[ordered]@{
  protocol='satelle-windows-account-v1'
  requested_sid=$whoami.Sid
  observed_sid=$identity.User.Value
  requested_local_app_data=$env:LOCALAPPDATA
  observed_local_app_data=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
}
$result | ConvertTo-Json -Compress"#,
    )
}

fn windows_executable_observation_command(requested_path: &str) -> String {
    let script = format!(
        r#"$ErrorActionPreference='Stop'
$requested=[IO.Path]::GetFullPath(({}).Replace('/',[IO.Path]::DirectorySeparatorChar))
$kind='missing'; $canonical=''; $sha=''
if (Test-Path -LiteralPath $requested) {{
  $item=Get-Item -LiteralPath $requested -Force
  $canonical=[IO.Path]::GetFullPath($item.FullName)
  if ($item.PSIsContainer) {{ $kind='directory' }}
  elseif (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ $kind='reparse_point' }}
  else {{
    $current=$item.Directory
    while ($null -ne $current) {{
      if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ $kind='reparse_point'; break }}
      $current=$current.Parent
    }}
    if ($kind -ne 'reparse_point') {{
      $kind='regular_file'
      $sha=(Get-FileHash -Algorithm SHA256 -LiteralPath $requested).Hash.ToLowerInvariant()
    }}
  }}
}}
[ordered]@{{protocol='satelle-windows-executable-v1';requested_path=$requested;canonical_path=$canonical;kind=$kind;sha256=$sha}} | ConvertTo-Json -Compress"#,
        powershell_quote(requested_path),
    );
    powershell_encoded_command(&script)
}

fn persistent_directory_command(target: RemoteTarget, directories: &[String]) -> String {
    if target.is_windows() {
        let paths = directories
            .iter()
            .map(|path| powershell_quote(path))
            .collect::<Vec<_>>()
            .join(",");
        powershell_encoded_command(&format!(
            r#"$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
foreach ($path in @({paths})) {{
  $full=[IO.Path]::GetFullPath($path.Replace('/',[IO.Path]::DirectorySeparatorChar))
  if (-not (Test-Path -LiteralPath $full)) {{ New-Item -ItemType Directory -Path $full -Force | Out-Null }}
  $item=Get-Item -LiteralPath $full -Force
  if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 1 }}
  $security=New-Object Security.AccessControl.DirectorySecurity
  $security.SetOwner($identity.User)
  $security.SetAccessRuleProtection($true,$false)
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity.User,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $security.AddAccessRule($rule)
  Set-Acl -LiteralPath $full -AclObject $security
}}"#,
        ))
    } else {
        let paths = directories
            .iter()
            .map(|path| posix_quote(path))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "set -eu\numask 077\nuid=$(id -u)\nfor path in {paths}; do mkdir -p -- \"$path\"; chmod 700 -- \"$path\"; test -d \"$path\" && test ! -L \"$path\"; owner=$(stat -c %u \"$path\" 2>/dev/null || stat -f %u \"$path\"); [ \"$owner\" = \"$uid\" ]; done"
        )
    }
}

fn service_definition_publish_command(target: RemoteTarget, remote_path: &str) -> String {
    if target.is_windows() {
        let script = format!(
            r#"$ErrorActionPreference='Stop'
$path=[IO.Path]::GetFullPath(({}).Replace('/',[IO.Path]::DirectorySeparatorChar))
$parent=Split-Path -Parent $path
$contents=[Console]::In.ReadToEnd()
if ([Text.Encoding]::UTF8.GetByteCount($contents) -gt {SERVICE_DEFINITION_LIMIT}) {{ exit 1 }}
if (-not (Test-Path -LiteralPath $parent)) {{ exit 1 }}
$parentItem=Get-Item -LiteralPath $parent -Force
if (-not $parentItem.PSIsContainer -or (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {{ exit 1 }}
$temporary=Join-Path $parent ('.satelle-definition-'+[Guid]::NewGuid().ToString('N'))
[IO.File]::WriteAllText($temporary,$contents,(New-Object Text.UTF8Encoding($false)))
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$security=New-Object Security.AccessControl.FileSecurity
$security.SetOwner($identity.User); $security.SetAccessRuleProtection($true,$false)
$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity.User,'FullControl','Allow')))
Set-Acl -LiteralPath $temporary -AclObject $security
Move-Item -LiteralPath $temporary -Destination $path -Force"#,
            powershell_quote(remote_path),
        );
        powershell_encoded_command(&script)
    } else {
        let parent = remote_path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or("/");
        format!(
            "set -eu\numask 077\npath={}\nparent={}\ntest -d \"$parent\" && test ! -L \"$parent\"\ntemporary=\"$parent/.satelle-definition-$$\"\ntrap 'rm -f -- \"$temporary\"' EXIT\n[ ! -e \"$temporary\" ] && [ ! -L \"$temporary\" ]\nset -C\ncat >\"$temporary\"\n[ \"$(wc -c <\"$temporary\")\" -le {SERVICE_DEFINITION_LIMIT} ]\nchmod 600 \"$temporary\"\nmv -f -- \"$temporary\" \"$path\"\ntrap - EXIT",
            posix_quote(remote_path),
            posix_quote(parent),
        )
    }
}

fn windows_task_parts(
    task: &satelle_core::daemon_service::WindowsTaskDefinition,
) -> Result<(&str, &str), SshBootstrapError> {
    let name = task
        .task_path
        .strip_prefix(r"\Satelle\")
        .filter(|name| !name.is_empty() && !name.contains('\\'))
        .ok_or(SshBootstrapError::InvalidPersistentServiceDefinition)?;
    Ok((r"\Satelle\", name))
}

fn windows_task_arguments(task: &satelle_core::daemon_service::WindowsTaskDefinition) -> String {
    task.arguments
        .iter()
        .map(|argument| {
            if argument.contains([' ', '\t', '"']) {
                format!("\"{}\"", argument.replace('"', "\\\""))
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn xml_escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn windows_task_xml(
    task: &satelle_core::daemon_service::WindowsTaskDefinition,
) -> Result<String, SshBootstrapError> {
    windows_task_parts(task)?;
    if task.logon_type != "InteractiveToken"
        || task.run_level != "LeastPrivilege"
        || task.stores_password
        || task.multiple_instances_policy != "IgnoreNew"
        || task.principal_sid != task.trigger_user_sid
    {
        return Err(SshBootstrapError::InvalidPersistentServiceDefinition);
    }
    Ok(format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
            "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">",
            "<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>",
            "<Principals><Principal id=\"Author\"><UserId>{sid}</UserId>",
            "<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>",
            "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><Enabled>true</Enabled></Settings>",
            "<Actions Context=\"Author\"><Exec><Command>{executable}</Command>",
            "<Arguments>{arguments}</Arguments></Exec></Actions></Task>"
        ),
        sid = xml_escape_text(&task.principal_sid),
        executable = xml_escape_text(&task.executable),
        arguments = xml_escape_text(&windows_task_arguments(task)),
    ))
}

fn windows_task_register_command(
    task: &satelle_core::daemon_service::WindowsTaskDefinition,
) -> String {
    let (task_path, task_name) = windows_task_parts(task).expect("core task path is validated");
    let xml = windows_task_xml(task).expect("core task definition is validated");
    powershell_encoded_command(&format!(
        "$ErrorActionPreference='Stop'; Register-ScheduledTask -TaskPath {} -TaskName {} -Xml {} -Force | Out-Null",
        powershell_quote(task_path),
        powershell_quote(task_name),
        powershell_quote(&xml),
    ))
}

fn windows_task_definition_match_expression(
    task: &satelle_core::daemon_service::WindowsTaskDefinition,
) -> String {
    format!(
        concat!(
            "($xml.DocumentElement.GetAttribute('version') -eq '1.4') -and ",
            "($xml.DocumentElement.NamespaceURI -eq 'http://schemas.microsoft.com/windows/2004/02/mit/task') -and ",
            "(@($root.Principals.Principal).Count -eq 1) -and ",
            "($root.Principals.Principal.id -eq 'Author') -and ",
            "($root.Principals.Principal.UserId -eq {principal_sid}) -and ",
            "($root.Principals.Principal.LogonType -eq 'InteractiveToken') -and ",
            "($root.Principals.Principal.RunLevel -eq 'LeastPrivilege') -and ",
            "(@($root.Triggers.ChildNodes).Count -eq 1) -and ",
            "(@($root.Triggers.LogonTrigger).Count -eq 1) -and ",
            "(@($root.Triggers.LogonTrigger.ChildNodes).Count -eq 2) -and ",
            "($root.Triggers.LogonTrigger.Enabled -eq 'true') -and ",
            "($root.Triggers.LogonTrigger.UserId -eq {trigger_sid}) -and ",
            "($root.Settings.MultipleInstancesPolicy -eq 'IgnoreNew') -and ",
            "($root.Settings.DisallowStartIfOnBatteries -eq 'false') -and ",
            "($root.Settings.StopIfGoingOnBatteries -eq 'false') -and ",
            "($root.Settings.Enabled -eq 'true') -and ",
            "($root.Actions.Context -eq 'Author') -and ",
            "(@($root.Actions.ChildNodes).Count -eq 1) -and ",
            "(@($root.Actions.Exec).Count -eq 1) -and ",
            "(@($root.Actions.Exec.ChildNodes).Count -eq 2) -and ",
            "($root.Actions.Exec.Command -eq {executable}) -and ",
            "($root.Actions.Exec.Arguments -eq {arguments})"
        ),
        principal_sid = powershell_quote(&task.principal_sid),
        trigger_sid = powershell_quote(&task.trigger_user_sid),
        executable = powershell_quote(&task.executable),
        arguments = powershell_quote(&windows_task_arguments(task)),
    )
}

fn windows_task_observe_command(
    task: &satelle_core::daemon_service::WindowsTaskDefinition,
) -> String {
    let (task_path, task_name) = windows_task_parts(task).expect("core task path is validated");
    let definition_matches = windows_task_definition_match_expression(task);
    let script = format!(
        r#"$ErrorActionPreference='Stop'
$task=Get-ScheduledTask -TaskPath {} -TaskName {} -ErrorAction SilentlyContinue
if ($null -eq $task) {{ Write-Output 'satelle-persistent-service-v1'; Write-Output 'absent'; exit 0 }}
[xml]$xml=Export-ScheduledTask -TaskPath {} -TaskName {}
$root=$xml.Task
$matching={}
Write-Output 'satelle-persistent-service-v1'
if ($matching) {{ Write-Output 'matching' }} else {{ Write-Output 'drifted' }}"#,
        powershell_quote(task_path),
        powershell_quote(task_name),
        powershell_quote(task_path),
        powershell_quote(task_name),
        definition_matches,
    );
    powershell_encoded_command(&script)
}

fn windows_task_instance_command(
    task: &satelle_core::daemon_service::WindowsTaskDefinition,
    action: &str,
) -> String {
    let (task_path, task_name) = windows_task_parts(task).expect("core task path is validated");
    let lookup = format!(
        "-TaskPath {} -TaskName {}",
        powershell_quote(task_path),
        powershell_quote(task_name)
    );
    let script = match action {
        "start" => format!("$ErrorActionPreference='Stop'; Start-ScheduledTask {lookup}"),
        "restart" => format!(
            "$ErrorActionPreference='Stop'; Stop-ScheduledTask {lookup} -ErrorAction SilentlyContinue; Start-ScheduledTask {lookup}"
        ),
        "stop" => format!("$ErrorActionPreference='Stop'; Stop-ScheduledTask {lookup}"),
        "observe_stopped" => format!(
            "$task=Get-ScheduledTask {lookup} -ErrorAction SilentlyContinue; Write-Output 'satelle-persistent-service-v1'; if ($null -eq $task -or $task.State -ne 'Running') {{ Write-Output 'stopped' }} else {{ Write-Output 'running' }}"
        ),
        _ => unreachable!("closed Windows task action"),
    };
    powershell_encoded_command(&script)
}

fn windows_task_lifecycle_command(task: &VerifiedCurrentWindowsTask, action: &str) -> String {
    let (task_path, task_name) =
        windows_task_parts(&task.definition).expect("core task path is validated");
    let lookup = format!(
        "-TaskPath {} -TaskName {}",
        powershell_quote(task_path),
        powershell_quote(task_name),
    );
    let definition_matches = windows_task_definition_match_expression(&task.definition);
    let (missing, operation) = match action {
        "observe" => (
            "Write-Output 'satelle-persistent-service-v1'; Write-Output 'absent'; exit 0",
            concat!(
                "Write-Output 'satelle-persistent-service-v1'; ",
                "if (-not $matching) { Write-Output 'drifted' } ",
                "elseif ($task.State -eq 'Running') { Write-Output 'running' } ",
                "else { Write-Output 'stopped' }",
            )
            .to_string(),
        ),
        "restart" => (
            "exit 75",
            format!(
                "if (-not $matching) {{ exit 75 }}; Stop-ScheduledTask {lookup} -ErrorAction SilentlyContinue; Start-ScheduledTask {lookup}"
            ),
        ),
        "stop" => (
            "exit 75",
            format!("if (-not $matching) {{ exit 75 }}; Stop-ScheduledTask {lookup}"),
        ),
        _ => unreachable!("closed Windows task lifecycle action"),
    };
    let script = format!(
        r#"$ErrorActionPreference='Stop'
$task=Get-ScheduledTask {lookup} -ErrorAction SilentlyContinue
if ($null -eq $task) {{ {missing} }}
[xml]$xml=Export-ScheduledTask {lookup}
$root=$xml.Task
$command=[string]$root.Actions.Exec.Command
$executableIsExact=$false
try {{
  $item=Get-Item -LiteralPath $command -Force -ErrorAction Stop
  $canonical=[IO.Path]::GetFullPath($item.FullName)
  $requested=[IO.Path]::GetFullPath($command)
  $digest=(Get-FileHash -Algorithm SHA256 -LiteralPath $command).Hash.ToLowerInvariant()
  $executableIsExact=($item -is [IO.FileInfo]) -and (-not $item.PSIsContainer) -and
    (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and
    [StringComparer]::OrdinalIgnoreCase.Equals($requested,$canonical) -and
    ($digest -ceq {expected_digest})
}} catch {{ $executableIsExact=$false }}
$matching=$executableIsExact -and ({definition_matches})
{operation}"#,
        lookup = lookup,
        missing = missing,
        expected_digest = powershell_quote(&task.executable_sha256),
        definition_matches = definition_matches,
        operation = operation,
    );
    powershell_encoded_command(&script)
}

#[cfg(test)]
fn canonical_windows_task_command(
    host_id: &str,
    local_app_data: &str,
    action: &str,
) -> Result<String, SshBootstrapError> {
    if host_id.is_empty() || host_id.contains(['\\', '/', '\0']) {
        return Err(SshBootstrapError::InvalidPersistentServiceDefinition);
    }
    let task_name = format!("Host-{host_id}");
    let service_config_path = join_target_path(
        RemoteTarget::WindowsX64Msvc,
        local_app_data,
        &format!("Satelle/service/{host_id}.json"),
    );
    let service_config_argument = if service_config_path.contains([' ', '\t', '"']) {
        format!("\"{}\"", service_config_path.replace('"', "\\\""))
    } else {
        service_config_path
    };
    let expected_arguments = format!("host start --service-config {service_config_argument}");
    let lookup = format!(
        "-TaskPath {} -TaskName {}",
        powershell_quote(r"\Satelle\"),
        powershell_quote(&task_name),
    );
    let (missing, operation) = match action {
        "observe" => (
            "Write-Output 'satelle-persistent-service-v1'; Write-Output 'absent'; exit 0",
            concat!(
                "Write-Output 'satelle-persistent-service-v1'; ",
                "if (-not $matching) { Write-Output 'drifted' } ",
                "elseif ($task.State -eq 'Running') { Write-Output 'running' } ",
                "else { Write-Output 'stopped' }",
            )
            .to_string(),
        ),
        "restart" => (
            "exit 75",
            format!(
                "if (-not $matching) {{ exit 75 }}; Stop-ScheduledTask {lookup} -ErrorAction SilentlyContinue; Start-ScheduledTask {lookup}"
            ),
        ),
        "stop" => (
            "exit 75",
            format!("if (-not $matching) {{ exit 75 }}; Stop-ScheduledTask {lookup}"),
        ),
        _ => return Err(SshBootstrapError::InvalidPersistentServiceDefinition),
    };
    let script = format!(
        r#"$ErrorActionPreference='Stop'
$task=Get-ScheduledTask {lookup} -ErrorAction SilentlyContinue
if ($null -eq $task) {{ {missing} }}
[xml]$xml=Export-ScheduledTask {lookup}
$root=$xml.Task
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$command=[string]$root.Actions.Exec.Command
$executableIsSafe=$false
try {{
  $item=Get-Item -LiteralPath $command -Force -ErrorAction Stop
  $canonical=[IO.Path]::GetFullPath($item.FullName)
  $requested=[IO.Path]::GetFullPath($command)
  $executableIsSafe=($item -is [IO.FileInfo]) -and (-not $item.PSIsContainer) -and
    (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and
    [StringComparer]::OrdinalIgnoreCase.Equals($requested,$canonical)
}} catch {{ $executableIsSafe=$false }}
$matching=$executableIsSafe -and
  ($root.Principals.Principal.UserId -eq $sid) -and
  ($root.Principals.Principal.LogonType -eq 'InteractiveToken') -and
  ($root.Principals.Principal.RunLevel -eq 'LeastPrivilege') -and
  ($root.Triggers.LogonTrigger.UserId -eq $sid) -and
  ($root.Settings.MultipleInstancesPolicy -eq 'IgnoreNew') -and
  ($root.Actions.Exec.Arguments -eq {expected_arguments})
{operation}"#,
        lookup = lookup,
        missing = missing,
        expected_arguments = powershell_quote(&expected_arguments),
        operation = operation,
    );
    Ok(powershell_encoded_command(&script))
}

fn service_path_overrides_observation_command(
    target: RemoteTarget,
    directories: &RemoteUserDirectories,
    host_id: &str,
) -> Result<String, SshBootstrapError> {
    if host_id.is_empty() || host_id.contains(['\\', '/', '\0']) || directories.target != target {
        return Err(SshBootstrapError::InvalidPersistentServiceDefinition);
    }
    if target.is_windows() {
        let local_app_data = directories
            .local_app_data
            .as_deref()
            .ok_or(SshBootstrapError::InvalidPersistentServiceDefinition)?;
        let config_path = join_target_path(
            target,
            local_app_data,
            &format!("Satelle/service/{host_id}.json"),
        );
        let service_directory = config_path
            .rsplit_once('\\')
            .map(|(parent, _)| parent)
            .ok_or(SshBootstrapError::InvalidPersistentServiceDefinition)?;
        let expected_argument = if config_path.contains([' ', '\t', '"']) {
            format!("\"{}\"", config_path.replace('"', "\\\""))
        } else {
            config_path.clone()
        };
        let expected_arguments = format!("host start --service-config {expected_argument}");
        let task_name = format!("Host-{host_id}");
        let script = format!(
            r#"$ErrorActionPreference='Stop'
$task=Get-ScheduledTask -TaskPath '\Satelle\' -TaskName {task_name} -ErrorAction Stop
[xml]$xml=Export-ScheduledTask -TaskPath '\Satelle\' -TaskName {task_name}
if ($xml.Task.Actions.Exec.Arguments -ne {expected_arguments}) {{ exit 75 }}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$path={config_path}
$serviceDirectory={service_directory}
foreach ($candidate in @($serviceDirectory,$path)) {{
  $item=Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ exit 75 }}
  $acl=Get-Acl -LiteralPath $candidate
  if ($acl.Owner -ne $identity) {{ exit 75 }}
  foreach ($rule in $acl.Access) {{
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne $identity) {{ exit 75 }}
  }}
}}
$file=Get-Item -LiteralPath $path -Force
if (($file -isnot [IO.FileInfo]) -or $file.PSIsContainer -or $file.Length -eq 0 -or $file.Length -gt {limit}) {{ exit 75 }}
[Console]::Out.Write([IO.File]::ReadAllText($file.FullName,[Text.UTF8Encoding]::new($false,$true)))"#,
            task_name = powershell_quote(&task_name),
            expected_arguments = powershell_quote(&expected_arguments),
            config_path = powershell_quote(&config_path),
            service_directory = powershell_quote(service_directory),
            limit = SERVICE_DEFINITION_LIMIT,
        );
        return Ok(powershell_encoded_command(&script));
    }
    if target.service_platform() != satelle_core::daemon_service::DaemonServicePlatform::Macos {
        return Err(SshBootstrapError::PersistentServiceUnsupported);
    }
    let plist_path = join_target_path(
        target,
        &directories.home,
        "Library/LaunchAgents/dev.microck.satelle.host.plist",
    );
    let plist_directory = plist_path
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .ok_or(SshBootstrapError::InvalidPersistentServiceDefinition)?;
    Ok(format!(
        "set -eu\npath={}\ndirectory={}\nuid=$(id -u)\n[ -d \"$directory\" ] && [ ! -L \"$directory\" ]\n[ -f \"$path\" ] && [ ! -L \"$path\" ]\n[ \"$(stat -f %u \"$directory\")\" = \"$uid\" ] && [ \"$(stat -f %Lp \"$directory\")\" = 700 ]\n[ \"$(stat -f %u \"$path\")\" = \"$uid\" ] && [ \"$(stat -f %Lp \"$path\")\" = 600 ]\nsize=$(stat -f %z \"$path\")\n[ \"$size\" -gt 0 ] && [ \"$size\" -le {} ]\ncat \"$path\"",
        posix_quote(&plist_path),
        posix_quote(plist_directory),
        SERVICE_DEFINITION_LIMIT,
    ))
}

fn parse_service_path_overrides(
    target: RemoteTarget,
    output: &[u8],
) -> Result<DaemonPathOverrides, SshBootstrapError> {
    if target.is_windows() {
        let config: satelle_core::daemon_service::WindowsServiceConfigV1 =
            serde_json::from_slice(output)
                .map_err(|_| SshBootstrapError::InvalidServiceObservation)?;
        if config.bind() != "127.0.0.1:3001" {
            return Err(SshBootstrapError::InvalidServiceObservation);
        }
        return daemon_path_overrides_from_environment(target, config.environment());
    }
    if target.service_platform() != satelle_core::daemon_service::DaemonServicePlatform::Macos {
        return Err(SshBootstrapError::PersistentServiceUnsupported);
    }
    parse_launchd_path_overrides(output)
}

fn daemon_path_overrides_from_environment(
    target: RemoteTarget,
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<DaemonPathOverrides, SshBootstrapError> {
    let mut overrides = DaemonPathOverrides::default();
    for (key, value) in environment {
        if !target_path_is_absolute(target, value) {
            return Err(SshBootstrapError::InvalidServiceObservation);
        }
        let path = Some(PathBuf::from(value));
        match key.as_str() {
            "SATELLE_HOME" => overrides.home = path,
            "SATELLE_CONFIG_FILE" => overrides.config_file = path,
            "SATELLE_STATE_DIR" => overrides.state_dir = path,
            "SATELLE_CACHE_DIR" => overrides.cache_dir = path,
            "SATELLE_LOG_DIR" => overrides.log_dir = path,
            _ => return Err(SshBootstrapError::InvalidServiceObservation),
        }
    }
    Ok(overrides)
}

fn parse_launchd_path_overrides(output: &[u8]) -> Result<DaemonPathOverrides, SshBootstrapError> {
    const PREFIX: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
        "<plist version=\"1.0\"><dict>",
        "<key>Label</key><string>dev.microck.satelle.host</string>",
        "<key>ProgramArguments</key><array><string>",
    );
    const ARGUMENTS: &str = concat!(
        "</string><string>host</string><string>start</string>",
        "<string>--foreground</string><string>--bind</string>",
        "<string>127.0.0.1:3001</string></array>",
        "<key>EnvironmentVariables</key><dict>",
    );
    const SUFFIX: &str = concat!(
        "</dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>",
        "</dict></plist>",
    );
    let text =
        std::str::from_utf8(output).map_err(|_| SshBootstrapError::InvalidServiceObservation)?;
    let body = text
        .strip_prefix(PREFIX)
        .ok_or(SshBootstrapError::InvalidServiceObservation)?;
    let (binary, body) = body
        .split_once(ARGUMENTS)
        .ok_or(SshBootstrapError::InvalidServiceObservation)?;
    let binary = decode_plist_text(binary)?;
    if !target_path_is_absolute(RemoteTarget::DarwinArm64, &binary) {
        return Err(SshBootstrapError::InvalidServiceObservation);
    }
    let environment = body
        .strip_suffix(SUFFIX)
        .ok_or(SshBootstrapError::InvalidServiceObservation)?;
    let mut entries = std::collections::BTreeMap::new();
    let mut remaining = environment;
    while !remaining.is_empty() {
        let entry = remaining
            .strip_prefix("<key>")
            .ok_or(SshBootstrapError::InvalidServiceObservation)?;
        let (key, entry) = entry
            .split_once("</key><string>")
            .ok_or(SshBootstrapError::InvalidServiceObservation)?;
        let (value, rest) = entry
            .split_once("</string>")
            .ok_or(SshBootstrapError::InvalidServiceObservation)?;
        let key = decode_plist_text(key)?;
        let value = decode_plist_text(value)?;
        if entries.insert(key, value).is_some() || entries.len() > 5 {
            return Err(SshBootstrapError::InvalidServiceObservation);
        }
        remaining = rest;
    }
    daemon_path_overrides_from_environment(RemoteTarget::DarwinArm64, &entries)
}

fn decode_plist_text(value: &str) -> Result<String, SshBootstrapError> {
    let mut decoded = String::with_capacity(value.len());
    let mut remaining = value;
    while let Some(index) = remaining.find('&') {
        if remaining[..index].contains('<') {
            return Err(SshBootstrapError::InvalidServiceObservation);
        }
        decoded.push_str(&remaining[..index]);
        let entity = &remaining[index..];
        let (replacement, length) = if entity.starts_with("&amp;") {
            ('&', 5)
        } else if entity.starts_with("&lt;") {
            ('<', 4)
        } else if entity.starts_with("&gt;") {
            ('>', 4)
        } else if entity.starts_with("&quot;") {
            ('"', 6)
        } else if entity.starts_with("&apos;") {
            ('\'', 6)
        } else {
            return Err(SshBootstrapError::InvalidServiceObservation);
        };
        decoded.push(replacement);
        remaining = &entity[length..];
    }
    if remaining.contains('<') {
        return Err(SshBootstrapError::InvalidServiceObservation);
    }
    decoded.push_str(remaining);
    Ok(decoded)
}

const LAUNCHD_LABEL: &str = "dev.microck.satelle.host";

fn launchd_register_command(plist_path: &str) -> String {
    format!(
        "set -eu\ndomain=gui/$(id -u)\nlaunchctl bootout \"$domain/{LAUNCHD_LABEL}\" 2>/dev/null || true\nlaunchctl bootstrap \"$domain\" {}",
        posix_quote(plist_path),
    )
}

fn launchd_observe_command(definition: &LaunchdServiceDefinition) -> String {
    let digest = Sha256::digest(definition.contents.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "set -eu\npath={}\nexpected={}\nif ! launchctl print \"gui/$(id -u)/{LAUNCHD_LABEL}\" >/dev/null 2>&1; then printf 'satelle-persistent-service-v1\\nabsent\\n'; exit 0; fi\nactual=$(shasum -a 256 \"$path\" | awk '{{print $1}}')\nprintf 'satelle-persistent-service-v1\\n'\nif [ \"$actual\" = \"$expected\" ]; then printf 'matching\\n'; else printf 'drifted\\n'; fi",
        posix_quote(definition.plist_path()),
        posix_quote(&digest),
    )
}

fn launchd_lifecycle_command(action: &str) -> String {
    match action {
        "kickstart" => format!("set -eu\nlaunchctl kickstart -k \"gui/$(id -u)/{LAUNCHD_LABEL}\""),
        "bootout" => format!("set -eu\nlaunchctl bootout \"gui/$(id -u)/{LAUNCHD_LABEL}\""),
        "observe_absent" => format!(
            "printf 'satelle-persistent-service-v1\\n'; if launchctl print \"gui/$(id -u)/{LAUNCHD_LABEL}\" >/dev/null 2>&1; then printf 'running\\n'; else printf 'absent\\n'; fi"
        ),
        "observe_runtime" => format!(
            "set -eu\noutput=$(launchctl print \"gui/$(id -u)/{LAUNCHD_LABEL}\" 2>/dev/null) || {{ printf 'satelle-persistent-service-v1\\nabsent\\n'; exit 0; }}\nprintf 'satelle-persistent-service-v1\\n'\nif printf '%s\\n' \"$output\" | grep -Eq '^[[:space:]]*state = running[[:space:]]*$'; then printf 'running\\n'; else printf 'stopped\\n'; fi"
        ),
        _ => unreachable!("closed launchd action"),
    }
}

fn loopback_listener_observation_command(target: RemoteTarget) -> String {
    if target.is_windows() {
        powershell_encoded_command(
            r#"$ErrorActionPreference='Stop'
$client=[Net.Sockets.TcpClient]::new()
try {
  $pending=$client.BeginConnect('127.0.0.1',3001,$null,$null)
  if (-not $pending.AsyncWaitHandle.WaitOne(2000)) { exit 70 }
  try {
    $client.EndConnect($pending)
    Write-Output 'satelle-loopback-listener-v1'
    Write-Output 'present'
  } catch [Net.Sockets.SocketException] {
    if ($_.Exception.SocketErrorCode -ne [Net.Sockets.SocketError]::ConnectionRefused) { exit 71 }
    Write-Output 'satelle-loopback-listener-v1'
    Write-Output 'absent'
  }
} finally { $client.Dispose() }"#,
        )
    } else {
        "set -eu\noutput=$(LC_ALL=C /usr/bin/nc -G 2 -z 127.0.0.1 3001 2>&1) && { printf 'satelle-loopback-listener-v1\\npresent\\n'; exit 0; }\ncase \"$output\" in *'Connection refused'*) printf 'satelle-loopback-listener-v1\\nabsent\\n';; *) exit 70;; esac".to_string()
    }
}

fn parse_persistent_service_observation(
    output: &[u8],
) -> Result<PersistentServiceObservation, SshBootstrapError> {
    let text =
        std::str::from_utf8(output).map_err(|_| SshBootstrapError::InvalidServiceObservation)?;
    let mut lines = text.lines().map(str::trim);
    if lines.next() != Some("satelle-persistent-service-v1") {
        return Err(SshBootstrapError::InvalidServiceObservation);
    }
    let observation = match lines.next() {
        Some("absent") => PersistentServiceObservation::Absent,
        Some("matching") => PersistentServiceObservation::Matching,
        Some("drifted") => PersistentServiceObservation::Drifted,
        Some("running") => PersistentServiceObservation::Running,
        Some("stopped") => PersistentServiceObservation::Stopped,
        _ => return Err(SshBootstrapError::InvalidServiceObservation),
    };
    if lines.next().is_some() {
        return Err(SshBootstrapError::InvalidServiceObservation);
    }
    Ok(observation)
}

fn parse_loopback_listener_observation(
    output: &[u8],
) -> Result<LoopbackListenerObservation, SshBootstrapError> {
    let text =
        std::str::from_utf8(output).map_err(|_| SshBootstrapError::InvalidServiceObservation)?;
    let mut lines = text.lines().map(str::trim);
    if lines.next() != Some("satelle-loopback-listener-v1") {
        return Err(SshBootstrapError::InvalidServiceObservation);
    }
    let observation = match lines.next() {
        Some("present") => LoopbackListenerObservation::Present,
        Some("absent") => LoopbackListenerObservation::Absent,
        _ => return Err(SshBootstrapError::InvalidServiceObservation),
    };
    if lines.next().is_some() {
        return Err(SshBootstrapError::InvalidServiceObservation);
    }
    Ok(observation)
}

fn target_path_is_absolute(target: RemoteTarget, path: &str) -> bool {
    if target.is_windows() {
        is_windows_absolute_path(path)
    } else {
        path.starts_with('/') && !path.split('/').any(|part| part == "..")
    }
}

fn same_windows_path_text(left: &str, right: &str) -> bool {
    let normalize = |value: &str| {
        value
            .replace('/', "\\")
            .trim_start_matches(r"\\?\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    normalize(left) == normalize(right)
}

impl RemoteUserDirectories {
    pub(super) fn probe(
        destination: &str,
        target: RemoteTarget,
    ) -> Result<Self, SshBootstrapError> {
        let output = if target.is_windows() {
            let script = "$ErrorActionPreference = 'Stop'; [Console]::Out.WriteLine('satelle-user-dirs-v1'); [Console]::Out.WriteLine('HOME=' + $env:USERPROFILE); [Console]::Out.WriteLine('LOCALAPPDATA=' + $env:LOCALAPPDATA); [Console]::Out.WriteLine('APPDATA=' + $env:APPDATA)";
            run_ssh_command(destination, &powershell_encoded_command(script))?
        } else {
            run_ssh_command(
                destination,
                "sh -c 'printf \"satelle-user-dirs-v1\\nHOME=%s\\nXDG_CONFIG_HOME=%s\\nXDG_CACHE_HOME=%s\\nXDG_STATE_HOME=%s\\n\" \"$HOME\" \"${XDG_CONFIG_HOME:-}\" \"${XDG_CACHE_HOME:-}\" \"${XDG_STATE_HOME:-}\"'",
            )?
        };
        if !output.status.success() {
            return Err(SshBootstrapError::PlatformProbeFailed);
        }
        Self::parse(target, &output.stdout)
    }

    pub(super) fn for_tests(target: RemoteTarget) -> Self {
        match target.service_platform() {
            satelle_core::daemon_service::DaemonServicePlatform::Windows => Self {
                target,
                home: r"C:\Users\operator".to_string(),
                local_app_data: Some(r"C:\Users\operator\AppData\Local".to_string()),
                roaming_app_data: Some(r"C:\Users\operator\AppData\Roaming".to_string()),
                xdg_config_home: None,
                xdg_cache_home: None,
                xdg_state_home: None,
            },
            satelle_core::daemon_service::DaemonServicePlatform::Macos => Self {
                target,
                home: "/Users/operator".to_string(),
                local_app_data: None,
                roaming_app_data: None,
                xdg_config_home: None,
                xdg_cache_home: None,
                xdg_state_home: None,
            },
            satelle_core::daemon_service::DaemonServicePlatform::Linux => Self {
                target,
                home: "/home/operator".to_string(),
                local_app_data: None,
                roaming_app_data: None,
                xdg_config_home: None,
                xdg_cache_home: None,
                xdg_state_home: None,
            },
        }
    }

    pub(super) fn resolved_path_set(&self) -> satelle_core::daemon_service::DaemonResolvedPathSet {
        use satelle_core::daemon_service::DaemonServicePlatform;

        let (config_file, cache_root, state_root, operator_log_root) = match self
            .target
            .service_platform()
        {
            DaemonServicePlatform::Windows => {
                let local = self
                    .local_app_data
                    .as_deref()
                    .expect("validated Windows directories include LOCALAPPDATA");
                let roaming = self
                    .roaming_app_data
                    .as_deref()
                    .expect("validated Windows directories include APPDATA");
                (
                    join_target_path(self.target, roaming, "Microck/Satelle/config/config.toml"),
                    join_target_path(self.target, local, "Microck/Satelle/cache"),
                    join_target_path(self.target, local, "Microck/Satelle/data/state"),
                    join_target_path(self.target, local, "Microck/Satelle/data/state/logs"),
                )
            }
            DaemonServicePlatform::Macos => (
                join_target_path(
                    self.target,
                    &self.home,
                    "Library/Application Support/dev.Microck.Satelle/config.toml",
                ),
                join_target_path(
                    self.target,
                    &self.home,
                    "Library/Caches/dev.Microck.Satelle",
                ),
                join_target_path(
                    self.target,
                    &self.home,
                    "Library/Application Support/dev.Microck.Satelle/state",
                ),
                join_target_path(self.target, &self.home, "Library/Logs/dev.Microck.Satelle"),
            ),
            DaemonServicePlatform::Linux => {
                let config = self.xdg_config_home.as_deref().unwrap_or("");
                let cache = self.xdg_cache_home.as_deref().unwrap_or("");
                let state = self.xdg_state_home.as_deref().unwrap_or("");
                let config = if config.is_empty() {
                    join_target_path(self.target, &self.home, ".config")
                } else {
                    config.to_string()
                };
                let cache = if cache.is_empty() {
                    join_target_path(self.target, &self.home, ".cache")
                } else {
                    cache.to_string()
                };
                let state = if state.is_empty() {
                    join_target_path(self.target, &self.home, ".local/state")
                } else {
                    state.to_string()
                };
                (
                    join_target_path(self.target, &config, "satelle/config.toml"),
                    join_target_path(self.target, &cache, "satelle"),
                    join_target_path(self.target, &state, "satelle"),
                    join_target_path(self.target, &state, "satelle/logs"),
                )
            }
        };

        satelle_core::daemon_service::DaemonResolvedPathSet {
            sqlite_store: join_target_path(self.target, &state_root, "satelle.sqlite3"),
            recording_root: join_target_path(self.target, &state_root, "recordings"),
            install_receipt: join_target_path(self.target, &state_root, "install-receipt.json"),
            config_file,
            cache_root,
            state_root,
            operator_log_root,
        }
    }

    fn parse(target: RemoteTarget, output: &[u8]) -> Result<Self, SshBootstrapError> {
        let text = std::str::from_utf8(output).map_err(|_| SshBootstrapError::InvalidProbe)?;
        let mut lines = text.lines().map(str::trim_end);
        if lines.next() != Some("satelle-user-dirs-v1") {
            return Err(SshBootstrapError::InvalidProbe);
        }
        let home = required_directory(target, lines.next(), "HOME=")?;
        let directories = if target.is_windows() {
            Self {
                target,
                home,
                local_app_data: Some(required_directory(target, lines.next(), "LOCALAPPDATA=")?),
                roaming_app_data: Some(required_directory(target, lines.next(), "APPDATA=")?),
                xdg_config_home: None,
                xdg_cache_home: None,
                xdg_state_home: None,
            }
        } else {
            Self {
                target,
                home,
                local_app_data: None,
                roaming_app_data: None,
                xdg_config_home: optional_directory(target, lines.next(), "XDG_CONFIG_HOME=")?,
                xdg_cache_home: optional_directory(target, lines.next(), "XDG_CACHE_HOME=")?,
                xdg_state_home: optional_directory(target, lines.next(), "XDG_STATE_HOME=")?,
            }
        };
        if lines.next().is_some() {
            return Err(SshBootstrapError::InvalidProbe);
        }
        Ok(directories)
    }
}

fn required_directory(
    target: RemoteTarget,
    line: Option<&str>,
    prefix: &str,
) -> Result<String, SshBootstrapError> {
    optional_directory(target, line, prefix)?.ok_or(SshBootstrapError::InvalidProbe)
}

fn optional_directory(
    target: RemoteTarget,
    line: Option<&str>,
    prefix: &str,
) -> Result<Option<String>, SshBootstrapError> {
    let value = line
        .and_then(|line| line.strip_prefix(prefix))
        .ok_or(SshBootstrapError::InvalidProbe)?;
    if value.is_empty() {
        return Ok(None);
    }
    let absolute = if target.is_windows() {
        let bytes = value.as_bytes();
        (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'))
            || value.starts_with(r"\\")
    } else {
        value.starts_with('/')
    };
    absolute
        .then(|| value.to_string())
        .map(Some)
        .ok_or(SshBootstrapError::InvalidProbe)
}

fn join_target_path(target: RemoteTarget, base: &str, suffix: &str) -> String {
    let separator = if target.is_windows() { '\\' } else { '/' };
    let base = base.trim_end_matches(['/', '\\']);
    let suffix = suffix
        .trim_matches(['/', '\\'])
        .replace(['/', '\\'], &separator.to_string());
    format!("{base}{separator}{suffix}")
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

fn remote_parent(remote_path: &str) -> &str {
    remote_path
        .rfind(['/', '\\'])
        .map(|separator| &remote_path[..separator])
        .expect("remote cache paths always contain a parent directory")
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
    release_digest: [u8; 32],
}

#[derive(Clone, Copy)]
pub(super) struct ReleaseArtifactMetadata {
    digest: [u8; 32],
}

impl ReleaseArtifactMetadata {
    pub(super) fn fetch(target: RemoteTarget) -> Result<Self, SshBootstrapError> {
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
        Ok(Self {
            digest: manifest_digest(&manifest, &filename)?,
        })
    }

    pub(super) const fn from_digest(digest: [u8; 32]) -> Self {
        Self { digest }
    }

    pub(super) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub(super) fn digest_hex(self) -> String {
        let mut digest = String::with_capacity(64);
        for byte in self.digest {
            write!(&mut digest, "{byte:02x}").expect("writing to a String cannot fail");
        }
        digest
    }
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
        let expected_digest = ReleaseArtifactMetadata::fetch(target)?.digest();

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
            release_digest: expected_digest,
        })
    }

    fn path(&self) -> &Path {
        &self.binary
    }

    const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
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
    directory: &str,
    address_digest: [u8; 32],
    bootstrap_lock: &mut SshBootstrapLock,
) -> Result<UploadedHostArtifact, SshBootstrapError> {
    let local_digest = sha256_file(local_binary)?;
    let local_digest_hex = local_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let shared_path = target.shared_executable_path(directory);
    let final_path = if target.is_windows() {
        let content_addressed_path = target.promoted_executable_path(directory, &address_digest);
        if remote_artifact_matches(destination, target, &content_addressed_path, &local_digest)? {
            return Ok(UploadedHostArtifact {
                remote_path: content_addressed_path,
                binary_sha256: local_digest_hex,
            });
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
        directory,
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
        Ok(UploadedHostArtifact {
            remote_path: final_path,
            binary_sha256: local_digest_hex,
        })
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
    directory: &str,
    bootstrap_lock: &mut SshBootstrapLock,
) -> Result<String, SshBootstrapError> {
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
        &target.create_directory_command(directory),
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
    require_staged_mutation_success(copy)?;

    if let Some(command) = target.prepare_staged_command(&staged, &local_digest_hex) {
        let command =
            bootstrap_lock.fenced_command(target, "cache_staging_permissions", &command)?;
        require_staged_mutation_success(run_fenced_ssh_command(destination, &command, None)?)?;
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
    ServiceDefinition(&'a [u8]),
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
        Some(FencedMutationInput::ServiceDefinition(contents)) => stdin.write_all(contents),
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

fn require_staged_mutation_success(output: CommandOutput) -> Result<(), SshBootstrapError> {
    if output.status.code() == Some(STAGED_DIGEST_MISMATCH_EXIT_CODE) {
        Err(SshBootstrapError::UploadedIntegrityMismatch)
    } else {
        require_success(output)
    }
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
    #[error("persistent Host service setup is unsupported on this remote platform")]
    PersistentServiceUnsupported,
    #[error("the persistent Host service definition is invalid")]
    InvalidPersistentServiceDefinition,
    #[error("the persistent Host service observation is invalid")]
    InvalidServiceObservation,
    #[error("the persistent Host service definition exceeded its size limit")]
    ServiceDefinitionTooLarge,
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

    fn persistent_windows_task() -> satelle_core::daemon_service::WindowsTaskDefinition {
        satelle_core::daemon_service::WindowsTaskDefinition {
            task_path: r"\Satelle\Host-host-123".to_string(),
            principal_sid: "S-1-5-21-1000-1001-1002-1003".to_string(),
            logon_type: "InteractiveToken".to_string(),
            run_level: "LeastPrivilege".to_string(),
            trigger_user_sid: "S-1-5-21-1000-1001-1002-1003".to_string(),
            stores_password: false,
            multiple_instances_policy: "IgnoreNew".to_string(),
            executable:
                r"C:\Users\operator\AppData\Local\Satelle\host\v0.1.0\win32-x64-msvc\satelle.exe"
                    .to_string(),
            arguments: vec![
                "host".to_string(),
                "start".to_string(),
                "--service-config".to_string(),
                r"C:\Users\operator\AppData\Local\Satelle\service\host-123.json".to_string(),
            ],
            service_config_path: r"C:\Users\operator\AppData\Local\Satelle\service\host-123.json"
                .to_string(),
        }
    }

    #[test]
    fn persistent_service_windows_identity_and_binary_observations_are_independent() {
        let account = decode_powershell_command(&windows_account_observation_command())
            .expect("decode Windows account observation");
        assert!(account.contains("whoami.exe /user /fo csv /nh"));
        assert!(account.contains("WindowsIdentity]::GetCurrent()"));
        assert!(account.contains("$env:LOCALAPPDATA"));
        assert!(account.contains("GetFolderPath"));

        let executable = decode_powershell_command(&windows_executable_observation_command(
            r"C:\Users\operator\AppData\Local\Satelle\satelle.exe",
        ))
        .expect("decode Windows executable observation");
        assert!(executable.contains("GetFullPath"));
        assert!(executable.contains("Get-FileHash -Algorithm SHA256"));
        assert!(executable.contains("ReparsePoint"));
        assert!(executable.contains("$current=$item.Directory"));
    }

    #[test]
    fn persistent_service_windows_task_xml_is_exact_user_login_contract() {
        let task = persistent_windows_task();
        let xml = windows_task_xml(&task).expect("valid Windows task XML");
        assert!(xml.contains("<UserId>S-1-5-21-1000-1001-1002-1003</UserId>"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"));
        assert!(xml.contains("--service-config C:\\Users\\operator"));
        assert!(!xml.contains("Password"));
        assert!(!xml.contains("HighestAvailable"));
        assert!(!xml.contains("SYSTEM"));

        let register = decode_powershell_command(&windows_task_register_command(&task))
            .expect("decode task registration");
        assert!(register.contains("Register-ScheduledTask"));
        assert!(register.contains(r"'\Satelle\'"));
        assert!(register.contains("'Host-host-123'"));

        let observe = decode_powershell_command(&windows_task_observe_command(&task))
            .expect("decode task observation");
        assert!(observe.contains("Export-ScheduledTask"));
        assert!(observe.contains("InteractiveToken"));
        assert!(observe.contains("LeastPrivilege"));
        assert!(observe.contains("IgnoreNew"));
    }

    #[test]
    fn persistent_service_windows_task_lifecycle_is_exact_and_observable() {
        let task = persistent_windows_task();
        let start = decode_powershell_command(&windows_task_instance_command(&task, "start"))
            .expect("decode start");
        let restart = decode_powershell_command(&windows_task_instance_command(&task, "restart"))
            .expect("decode restart");
        let stop = decode_powershell_command(&windows_task_instance_command(&task, "stop"))
            .expect("decode stop");
        let absent =
            decode_powershell_command(&windows_task_instance_command(&task, "observe_stopped"))
                .expect("decode stopped observation");
        assert!(start.contains("Start-ScheduledTask"));
        assert!(restart.contains("Stop-ScheduledTask"));
        assert!(restart.contains("Start-ScheduledTask"));
        assert!(stop.contains("Stop-ScheduledTask"));
        assert!(absent.contains("$task.State -ne 'Running'"));
        for script in [&start, &restart, &stop, &absent] {
            assert!(script.contains(r"'\Satelle\'"));
            assert!(script.contains("'Host-host-123'"));
        }
    }

    #[test]
    fn persistent_service_windows_canonical_lifecycle_revalidates_before_mutation() {
        let restart = decode_powershell_command(
            &canonical_windows_task_command(
                "host-123",
                r"C:\Users\Satelle Operator\AppData\Local",
                "restart",
            )
            .expect("canonical restart command"),
        )
        .expect("decode canonical restart");
        assert!(restart.contains(r"'\Satelle\'"));
        assert!(restart.contains("'Host-host-123'"));
        assert!(restart.contains("WindowsIdentity]::GetCurrent().User.Value"));
        assert!(restart.contains("InteractiveToken"));
        assert!(restart.contains("LeastPrivilege"));
        assert!(restart.contains("IgnoreNew"));
        assert!(restart.contains("ReparsePoint"));
        assert!(restart.contains(
            r#"host start --service-config "C:\Users\Satelle Operator\AppData\Local\Satelle\service\host-123.json""#
        ));
        assert!(restart.contains("if ($null -eq $task) { exit 75 }"));
        assert!(restart.contains("if (-not $matching) { exit 75 }"));
        assert!(restart.contains("Stop-ScheduledTask"));
        assert!(restart.contains("Start-ScheduledTask"));

        let observe = decode_powershell_command(
            &canonical_windows_task_command(
                "host-123",
                r"C:\Users\operator\AppData\Local",
                "observe",
            )
            .expect("canonical observation command"),
        )
        .expect("decode canonical observation");
        assert!(observe.contains("Write-Output 'absent'; exit 0"));
        assert!(observe.contains("$task.State -eq 'Running'"));
        assert!(observe.contains("Write-Output 'stopped'"));
        assert!(canonical_windows_task_command("bad\\host", r"C:\Users\operator", "stop").is_err());
    }

    #[test]
    fn persistent_service_windows_current_task_lifecycle_binds_definition_and_digest() {
        let task = VerifiedCurrentWindowsTask {
            definition: persistent_windows_task(),
            executable_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        };
        let restart = decode_powershell_command(&windows_task_lifecycle_command(&task, "restart"))
            .expect("decode exact current-task restart");
        assert!(restart.contains("Get-FileHash -Algorithm SHA256"));
        assert!(restart.contains(&task.executable_sha256));
        assert!(restart.contains(&task.definition.executable));
        assert!(restart.contains(&windows_task_arguments(&task.definition)));
        assert!(restart.contains("LogonTrigger.ChildNodes).Count -eq 2"));
        assert!(restart.contains("LogonTrigger.Enabled -eq 'true'"));
        assert!(restart.contains("Settings.Enabled -eq 'true'"));
        assert!(restart.contains("DisallowStartIfOnBatteries -eq 'false'"));
        assert!(restart.contains("StopIfGoingOnBatteries -eq 'false'"));
        assert!(restart.contains("Actions.ChildNodes).Count -eq 1"));
        assert!(restart.contains("Actions.Exec.ChildNodes).Count -eq 2"));
        assert!(restart.contains("if (-not $matching) { exit 75 }"));
        assert!(restart.contains("Stop-ScheduledTask"));
        assert!(restart.contains("Start-ScheduledTask"));

        let observe = decode_powershell_command(&windows_task_lifecycle_command(&task, "observe"))
            .expect("decode exact current-task observation");
        assert!(observe.contains("Write-Output 'drifted'"));
        assert!(observe.contains("$task.State -eq 'Running'"));
        assert!(observe.contains("Write-Output 'stopped'"));
    }

    #[test]
    fn persistent_service_definitions_are_bounded_atomic_and_owner_only() {
        let windows = decode_powershell_command(&service_definition_publish_command(
            RemoteTarget::WindowsX64Msvc,
            r"C:\Users\operator\AppData\Local\Satelle\service\host-123.json",
        ))
        .expect("decode Windows publication");
        assert!(windows.contains(&SERVICE_DEFINITION_LIMIT.to_string()));
        assert!(windows.contains("FileSecurity"));
        assert!(windows.contains("SetAccessRuleProtection($true,$false)"));
        assert!(windows.contains("Move-Item"));

        let posix = service_definition_publish_command(
            RemoteTarget::DarwinArm64,
            "/Users/operator/Library/LaunchAgents/dev.microck.satelle.host.plist",
        );
        assert!(posix.contains(&SERVICE_DEFINITION_LIMIT.to_string()));
        assert!(posix.contains("umask 077"));
        assert!(posix.contains("[ ! -e \"$temporary\" ] && [ ! -L \"$temporary\" ]"));
        assert!(posix.contains("set -C"));
        assert!(posix.contains("chmod 600"));
        assert!(posix.contains("mv -f"));
    }

    #[test]
    fn persistent_service_directory_creation_is_owner_only_and_reparse_safe() {
        let windows = decode_powershell_command(&persistent_directory_command(
            RemoteTarget::WindowsX64Msvc,
            &[r"C:\Users\operator\AppData\Local\Satelle\service".to_string()],
        ))
        .expect("decode Windows directory creation");
        assert!(windows.contains("ReparsePoint"));
        assert!(windows.contains("DirectorySecurity"));
        assert!(windows.contains("SetOwner"));
        assert!(windows.contains("SetAccessRuleProtection($true,$false)"));

        let posix = persistent_directory_command(
            RemoteTarget::DarwinArm64,
            &["/Users/operator/Library/LaunchAgents".to_string()],
        );
        assert!(posix.contains("umask 077"));
        assert!(posix.contains("chmod 700"));
        assert!(posix.contains("test ! -L"));
        assert!(posix.contains("stat -f %u"));
    }

    #[test]
    fn persistent_service_launchd_commands_stay_in_authenticated_gui_domain() {
        let definition = LaunchdServiceDefinition {
            plist_path: "/Users/operator/Library/LaunchAgents/dev.microck.satelle.host.plist"
                .to_string(),
            contents: "<plist>satelle</plist>".to_string(),
        };
        let register = launchd_register_command(definition.plist_path());
        let observe = launchd_observe_command(&definition);
        let kickstart = launchd_lifecycle_command("kickstart");
        let bootout = launchd_lifecycle_command("bootout");
        let absent = launchd_lifecycle_command("observe_absent");
        for command in [&register, &observe, &kickstart, &bootout, &absent] {
            assert!(command.contains("gui/$(id -u)"));
            assert!(command.contains(LAUNCHD_LABEL));
            assert!(!command.contains("sudo"));
            assert!(!command.contains("system/"));
            assert!(!command.contains("LaunchDaemons"));
        }
        assert!(register.contains("launchctl bootstrap"));
        assert!(kickstart.contains("launchctl kickstart -k"));
        assert!(bootout.contains("launchctl bootout"));
        assert!(absent.contains("launchctl print"));
    }

    #[test]
    fn persistent_service_launchd_runtime_requires_actual_running_state() {
        let runtime = launchd_lifecycle_command("observe_runtime");
        assert!(runtime.contains("gui/$(id -u)"));
        assert!(runtime.contains("state = running"));
        assert!(runtime.contains("printf 'running\\n'"));
        assert!(runtime.contains("printf 'stopped\\n'"));
        assert!(runtime.contains("absent\\n"));
    }

    #[test]
    fn persistent_service_loopback_probe_distinguishes_absence_from_probe_errors() {
        let windows = decode_powershell_command(&loopback_listener_observation_command(
            RemoteTarget::WindowsX64Msvc,
        ))
        .expect("decode Windows listener probe");
        assert!(windows.contains("BeginConnect('127.0.0.1',3001"));
        assert!(windows.contains("WaitOne(2000)"));
        assert!(windows.contains("ConnectionRefused"));
        assert!(windows.contains("exit 70"));
        assert!(windows.contains("exit 71"));

        let macos = loopback_listener_observation_command(RemoteTarget::DarwinArm64);
        assert!(macos.contains("/usr/bin/nc -G 2 -z 127.0.0.1 3001"));
        assert!(macos.contains("Connection refused"));
        assert!(macos.contains("*) exit 70"));

        assert_eq!(
            parse_loopback_listener_observation(b"satelle-loopback-listener-v1\npresent\n")
                .unwrap(),
            LoopbackListenerObservation::Present
        );
        assert_eq!(
            parse_loopback_listener_observation(b"satelle-loopback-listener-v1\nabsent\n").unwrap(),
            LoopbackListenerObservation::Absent
        );
        assert!(
            parse_loopback_listener_observation(b"satelle-loopback-listener-v1\ntimeout\n")
                .is_err()
        );
        assert!(
            parse_loopback_listener_observation(
                b"satelle-loopback-listener-v1\nabsent\nssh-error\n"
            )
            .is_err()
        );
    }

    #[test]
    fn persistent_service_path_override_observation_is_owner_only_and_canonical() {
        let windows_directories = RemoteUserDirectories {
            target: RemoteTarget::WindowsX64Msvc,
            home: r"C:\Users\operator".to_string(),
            local_app_data: Some(r"C:\Users\operator\AppData\Local".to_string()),
            roaming_app_data: Some(r"C:\Users\operator\AppData\Roaming".to_string()),
            xdg_config_home: None,
            xdg_cache_home: None,
            xdg_state_home: None,
        };
        let windows = decode_powershell_command(
            &service_path_overrides_observation_command(
                RemoteTarget::WindowsX64Msvc,
                &windows_directories,
                "host-123",
            )
            .expect("Windows override observation"),
        )
        .expect("decode Windows override observation");
        assert!(windows.contains("Export-ScheduledTask"));
        assert!(windows.contains("Host-host-123"));
        assert!(windows.contains("host start --service-config"));
        assert!(windows.contains("ReparsePoint"));
        assert!(windows.contains("$acl.Owner -ne $identity"));
        assert!(windows.contains("$rule.IdentityReference.Value -ne $identity"));
        assert!(windows.contains(&SERVICE_DEFINITION_LIMIT.to_string()));

        let macos_directories = RemoteUserDirectories {
            target: RemoteTarget::DarwinArm64,
            home: "/Users/operator".to_string(),
            local_app_data: None,
            roaming_app_data: None,
            xdg_config_home: None,
            xdg_cache_home: None,
            xdg_state_home: None,
        };
        let macos = service_path_overrides_observation_command(
            RemoteTarget::DarwinArm64,
            &macos_directories,
            "host-123",
        )
        .expect("macOS override observation");
        assert!(macos.contains("[ ! -L"));
        assert!(macos.contains("stat -f %u"));
        assert!(macos.contains("stat -f %Lp"));
        assert!(macos.contains("= 700"));
        assert!(macos.contains("= 600"));
        assert!(macos.contains(&SERVICE_DEFINITION_LIMIT.to_string()));
    }

    #[test]
    fn persistent_service_path_override_parsers_are_closed() {
        let windows = br#"{
          "schema":"satelle.host-service.v1",
          "daemon_arguments":["host","start","--foreground","--bind","127.0.0.1:3001"],
          "environment":{"SATELLE_STATE_DIR":"C:\\Users\\operator\\AppData\\Local\\Satelle\\state"}
        }"#;
        let parsed = parse_service_path_overrides(RemoteTarget::WindowsX64Msvc, windows)
            .expect("valid Windows service config");
        assert_eq!(
            parsed.state_dir.as_deref(),
            Some(Path::new(r"C:\Users\operator\AppData\Local\Satelle\state"))
        );
        assert!(
            parse_service_path_overrides(
                RemoteTarget::WindowsX64Msvc,
                br#"{"schema":"satelle.host-service.v1","daemon_arguments":["host","start","--foreground","--bind","127.0.0.1:3001"],"environment":{"OTHER":"C:\\safe"}}"#,
            )
            .is_err()
        );

        let overrides = DaemonPathOverrides {
            state_dir: Some(PathBuf::from(
                "/Users/operator/Library/Application Support/Satelle",
            )),
            log_dir: Some(PathBuf::from("/Users/operator/Library/Logs/Satelle & Host")),
            ..DaemonPathOverrides::default()
        };
        let plist = satelle_core::daemon_service::render_launchd_user_plist(
            Path::new("/Users/operator/Applications/Satelle & Host/satelle"),
            "127.0.0.1:3001",
            &overrides,
        )
        .expect("valid launchd plist");
        let parsed = parse_service_path_overrides(RemoteTarget::DarwinArm64, plist.as_bytes())
            .expect("valid launchd service config");
        assert_eq!(parsed.state_dir, overrides.state_dir);
        assert_eq!(parsed.log_dir, overrides.log_dir);

        let unknown_key = plist.replace(
            "<key>EnvironmentVariables</key><dict>",
            "<key>EnvironmentVariables</key><dict><key>OTHER</key><string>/tmp</string>",
        );
        assert!(
            parse_service_path_overrides(RemoteTarget::DarwinArm64, unknown_key.as_bytes())
                .is_err()
        );
        let wrong_bind = plist.replace("127.0.0.1:3001", "127.0.0.1:3002");
        assert!(
            parse_service_path_overrides(RemoteTarget::DarwinArm64, wrong_bind.as_bytes()).is_err()
        );
    }

    #[test]
    fn persistent_service_observation_protocol_is_closed() {
        assert_eq!(
            parse_persistent_service_observation(b"satelle-persistent-service-v1\nmatching\n")
                .unwrap(),
            PersistentServiceObservation::Matching
        );
        assert!(
            parse_persistent_service_observation(
                b"satelle-persistent-service-v1\nmatching\nextra\n"
            )
            .is_err()
        );
        assert!(parse_persistent_service_observation(b"matching\n").is_err());
    }

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
    fn posix_cache_mutations_reject_symlinked_cache_ancestors_without_outside_mutation() {
        for ancestor in [".cache", ".cache/satelle"] {
            let home = tempfile::tempdir().expect("temporary remote home");
            let outside = tempfile::tempdir().expect("outside directory");
            let link = home.path().join(ancestor);
            fs::create_dir_all(link.parent().expect("cache ancestor parent"))
                .expect("create cache ancestor parent");
            symlink(outside.path(), &link).expect("symlink cache ancestor");

            let escaped_root = if ancestor == ".cache" {
                outside.path().join("satelle/host")
            } else {
                outside.path().join("host")
            };
            let escaped_directory = escaped_root
                .join(format!("v{}", env!("CARGO_PKG_VERSION")))
                .join("linux-x64-gnu");
            let remote_directory = RemoteTarget::LinuxX64Gnu.remote_directory();

            let create = RemoteTarget::LinuxX64Gnu.create_directory_command(&remote_directory);
            assert!(!run_posix_cache_command(home.path(), &create, None).success());
            assert!(!escaped_directory.exists());

            fs::create_dir_all(&escaped_directory).expect("create escaped cache fixture");
            let staged = format!("{remote_directory}/.satelle-upload-test");
            let escaped_staged = escaped_directory.join(".satelle-upload-test");
            let escaped_final = escaped_directory.join("satelle");
            fs::write(&escaped_final, b"outside final").expect("write escaped final file");

            let upload = RemoteTarget::LinuxX64Gnu.upload_command(&staged, &"00".repeat(32));
            assert!(!run_posix_cache_command(home.path(), &upload, Some(b"replacement")).success());
            assert!(!escaped_staged.exists());

            fs::write(&escaped_staged, b"outside staged").expect("write escaped staged file");
            fs::set_permissions(&escaped_staged, fs::Permissions::from_mode(0o600))
                .expect("set escaped staged permissions");
            let prepare = RemoteTarget::LinuxX64Gnu
                .prepare_staged_command(&staged, &"00".repeat(32))
                .expect("POSIX staging command");
            assert!(!run_posix_cache_command(home.path(), &prepare, None).success());
            let promote = RemoteTarget::LinuxX64Gnu
                .promote_command(&staged, &format!("{remote_directory}/satelle"));
            assert!(!run_posix_cache_command(home.path(), &promote, None).success());

            assert_eq!(
                fs::read(&escaped_staged).expect("read escaped staged file"),
                b"outside staged"
            );
            assert_eq!(
                fs::metadata(&escaped_staged)
                    .expect("escaped staged metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::read(&escaped_final).expect("read escaped final file"),
                b"outside final"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn posix_cache_mutations_accept_valid_owner_controlled_ancestors() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let remote_directory = RemoteTarget::LinuxX64Gnu.remote_directory();
        let create = RemoteTarget::LinuxX64Gnu.create_directory_command(&remote_directory);
        assert!(run_posix_cache_command(home.path(), &create, None).success());

        let staged = format!("{remote_directory}/.satelle-upload-test");
        let payload = b"verified artifact";
        let digest = Sha256::digest(payload)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let upload = RemoteTarget::LinuxX64Gnu.upload_command(&staged, &digest);
        assert!(run_posix_cache_command(home.path(), &upload, Some(payload)).success());

        let prepare = RemoteTarget::LinuxX64Gnu
            .prepare_staged_command(&staged, &digest)
            .expect("POSIX staging command");
        assert!(run_posix_cache_command(home.path(), &prepare, None).success());
        assert_eq!(
            fs::metadata(home.path().join(&staged))
                .expect("staged metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        let final_path = format!("{remote_directory}/satelle");
        let promote = RemoteTarget::LinuxX64Gnu.promote_command(&staged, &final_path);
        assert!(run_posix_cache_command(home.path(), &promote, None).success());
        assert_eq!(
            fs::read(home.path().join(final_path)).expect("read promoted artifact"),
            payload
        );
        assert!(!home.path().join(staged).exists());
    }

    #[cfg(unix)]
    #[test]
    fn posix_failed_staged_mutations_remove_only_the_exact_owned_attempt() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let remote_directory = RemoteTarget::LinuxX64Gnu.remote_directory();
        let create = RemoteTarget::LinuxX64Gnu.create_directory_command(&remote_directory);
        assert!(run_posix_cache_command(home.path(), &create, None).success());

        let digest_mismatch = format!("{remote_directory}/.satelle-upload-digest-mismatch");
        let upload = RemoteTarget::LinuxX64Gnu.upload_command(&digest_mismatch, &"00".repeat(32));
        assert!(!run_posix_cache_command(home.path(), &upload, Some(b"artifact")).success());
        assert!(!home.path().join(&digest_mismatch).exists());

        let final_path = format!("{remote_directory}/satelle");
        fs::write(home.path().join(&final_path), b"existing final").expect("write existing final");
        let staged_verification =
            format!("{remote_directory}/.satelle-upload-staging-verification");
        fs::write(home.path().join(&staged_verification), b"staged artifact")
            .expect("write staged verification artifact");
        fs::set_permissions(
            home.path().join(&staged_verification),
            fs::Permissions::from_mode(0o600),
        )
        .expect("secure staged verification artifact");
        let prepare = RemoteTarget::LinuxX64Gnu
            .prepare_staged_command(&staged_verification, &"00".repeat(32))
            .expect("POSIX staging command");
        let status = run_posix_cache_command(home.path(), &prepare, None);
        assert_eq!(status.code(), Some(STAGED_DIGEST_MISMATCH_EXIT_CODE));
        assert!(!home.path().join(&staged_verification).exists());
        assert_eq!(
            fs::read(home.path().join(&final_path)).expect("read existing final"),
            b"existing final"
        );
        fs::remove_file(home.path().join(&final_path)).expect("remove existing final");

        let outside = tempfile::tempdir().expect("outside directory");
        let outside_final = outside.path().join("final");
        fs::write(&outside_final, b"outside final").expect("write outside final");
        symlink(&outside_final, home.path().join(&final_path)).expect("symlink final path");

        for attempt in ["first", "second"] {
            let staged = format!("{remote_directory}/.satelle-upload-{attempt}");
            fs::write(home.path().join(&staged), attempt).expect("write staged attempt");
            fs::set_permissions(home.path().join(&staged), fs::Permissions::from_mode(0o700))
                .expect("secure staged attempt");
            let promote = RemoteTarget::LinuxX64Gnu.promote_command(&staged, &final_path);
            assert!(!run_posix_cache_command(home.path(), &promote, None).success());
            assert!(!home.path().join(staged).exists());
            assert_eq!(
                fs::read(&outside_final).expect("read outside final"),
                b"outside final"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn posix_staged_cleanup_fences_when_exact_leaf_safety_is_uncertain() {
        let home = tempfile::tempdir().expect("temporary remote home");
        let outside = tempfile::tempdir().expect("outside directory");
        let remote_directory = RemoteTarget::LinuxX64Gnu.remote_directory();
        let create = RemoteTarget::LinuxX64Gnu.create_directory_command(&remote_directory);
        assert!(run_posix_cache_command(home.path(), &create, None).success());

        let outside_file = outside.path().join("artifact");
        fs::write(&outside_file, b"outside").expect("write outside artifact");
        let staged = format!("{remote_directory}/.satelle-upload-unsafe");
        symlink(&outside_file, home.path().join(&staged)).expect("symlink staged leaf");
        let promote = RemoteTarget::LinuxX64Gnu
            .promote_command(&staged, &format!("{remote_directory}/satelle"));
        let status = run_posix_cache_command(home.path(), &promote, None);

        assert_eq!(status.code(), Some(75));
        assert_eq!(
            fs::read(&outside_file).expect("read outside artifact"),
            b"outside"
        );
        assert!(
            fs::symlink_metadata(home.path().join(staged))
                .expect("staged symlink metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn known_clean_digest_failures_retire_before_immediate_retry() {
        for phase in ["cache_upload", "cache_staging_permissions"] {
            let home = tempfile::tempdir().expect("temporary remote home");
            let state = home.path().join("state");
            let fake_ssh = home.path().join("ssh");
            fs::write(
                &fake_ssh,
                format!(
                    concat!(
                        "#!/bin/sh\n",
                        "remote_command=$3\n",
                        "case \"$remote_command\" in cmd.exe*) exit 1;; esac\n",
                        "cd {}\n",
                        "export HOME={}\n",
                        "export SATELLE_STATE_DIR={}\n",
                        "exec sh -c \"$remote_command\"\n",
                    ),
                    posix_quote(home.path().to_str().expect("UTF-8 home path")),
                    posix_quote(home.path().to_str().expect("UTF-8 home path")),
                    posix_quote(state.to_str().expect("UTF-8 state path")),
                ),
            )
            .expect("write fake SSH");
            fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700))
                .expect("make fake SSH executable");

            let request = bootstrap_lock::Request::new(
                format!("digest-failure-{phase}"),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                None,
            )
            .expect("valid bootstrap request");
            let mut bootstrap_lock =
                SshBootstrapLock::acquire_for_tests("test-host", request, &fake_ssh)
                    .expect("acquire bootstrap lock");
            let target = RemoteTarget::LinuxX64Gnu;
            let directory = target.remote_directory();
            assert!(
                run_posix_cache_command(
                    home.path(),
                    &target.create_directory_command(&directory),
                    None,
                )
                .success()
            );
            let staged = format!("{directory}/.satelle-upload-{phase}");
            let (inner_command, payload): (String, &[u8]) = if phase == "cache_upload" {
                (
                    target.upload_command(&staged, &"00".repeat(32)),
                    b"artifact",
                )
            } else {
                fs::write(home.path().join(&staged), b"artifact").expect("write staged artifact");
                fs::set_permissions(home.path().join(&staged), fs::Permissions::from_mode(0o600))
                    .expect("secure staged artifact");
                (
                    target
                        .prepare_staged_command(&staged, &"00".repeat(32))
                        .expect("POSIX staging command"),
                    b"",
                )
            };
            let fenced = bootstrap_lock
                .fenced_command(target, phase, &inner_command)
                .expect("start digest mismatch attempt");
            let run_fenced = |command: &str, payload: &[u8]| {
                let mut child = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .current_dir(home.path())
                    .env("HOME", home.path())
                    .env("SATELLE_STATE_DIR", &state)
                    .stdin(Stdio::piped())
                    .spawn()
                    .expect("run fenced mutation");
                writeln!(
                    child.stdin.as_mut().expect("piped mutation stdin"),
                    "{MUTATION_EXECUTE}"
                )
                .expect("write execution gate");
                child
                    .stdin
                    .as_mut()
                    .expect("piped mutation stdin")
                    .write_all(payload)
                    .expect("write mutation payload");
                drop(child.stdin.take());
                child.wait().expect("wait for fenced mutation")
            };
            let mismatch_status = run_fenced(&fenced, payload);
            assert_eq!(
                mismatch_status.code(),
                Some(STAGED_DIGEST_MISMATCH_EXIT_CODE)
            );
            assert!(matches!(
                require_staged_mutation_success(CommandOutput {
                    status: mismatch_status,
                    stdout: Vec::new(),
                    stderr: SshStderrClassification::default(),
                }),
                Err(SshBootstrapError::UploadedIntegrityMismatch)
            ));
            assert!(!home.path().join(&staged).exists());

            let retry = bootstrap_lock
                .fenced_command(target, phase, "sh -c 'exit 0'")
                .expect("known-clean attempt permits immediate retry");
            assert!(run_fenced(&retry, b"").success());
            drop(bootstrap_lock);

            let retry_request = bootstrap_lock::Request::new(
                format!("digest-reacquire-{phase}"),
                bootstrap_lock::OperationKind::MissingDaemonRepair,
                None,
            )
            .expect("valid retry request");
            let mut retry_lock =
                SshBootstrapLock::acquire_for_tests("test-host", retry_request, &fake_ssh)
                    .expect("completed retry does not leave BootstrapBusy");
            retry_lock.release_unmodified().expect("release retry lock");
        }
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
            .prepare_staged_command(&staged, &"00".repeat(32))
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
            .prepare_staged_command(&staged, &"00".repeat(32))
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

    #[test]
    fn windows_staged_acl_requires_a_contained_regular_non_reparse_file() {
        let staged = "AppData/Local/Satelle/host/v1/windows-x64/.satelle-upload-attempt.exe";
        let command = RemoteTarget::WindowsX64Msvc
            .prepare_staged_command(staged, &"00".repeat(32))
            .expect("Windows staging command");
        let script = decode_powershell_command(&command).expect("decode staging command");

        for required in [
            "$root=[IO.Path]::GetFullPath(('AppData/Local/Satelle/host').Replace('/', $separator))",
            "$path=[IO.Path]::GetFullPath(('AppData/Local/Satelle/host/v1/windows-x64/.satelle-upload-attempt.exe').Replace('/', $separator))",
            "[StringComparer]::OrdinalIgnoreCase.Equals($path,$root)",
            "$path.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)",
            "$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop",
            "$item -isnot [IO.FileInfo]",
            "$item.PSIsContainer",
            "($item.Attributes -band [IO.FileAttributes]::ReparsePoint)",
            "($current.Attributes -band [IO.FileAttributes]::ReparsePoint)",
            "[StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$root)",
            "$current=$current.Parent; if ($null -eq $current) { exit 1 }",
            "Set-Acl -LiteralPath $path -AclObject $acl",
        ] {
            assert!(script.contains(required), "missing {required:?}: {script}");
        }

        let leaf_check = script
            .find("$item -isnot [IO.FileInfo]")
            .expect("leaf type check");
        let ancestor_check = script
            .find("($current.Attributes -band [IO.FileAttributes]::ReparsePoint)")
            .expect("ancestor reparse check");
        let acl_read = script
            .find("$acl=Get-Acl -LiteralPath $path")
            .expect("staged ACL read");
        assert!(leaf_check < acl_read);
        assert!(ancestor_check < acl_read);
    }

    #[test]
    fn windows_staged_mutations_cleanup_only_the_exact_owned_attempt_on_failure() {
        let staged = "AppData/Local/Satelle/host/v1/windows-x64/.satelle-upload-attempt.exe";
        let commands = [
            RemoteTarget::WindowsX64Msvc.upload_command(staged, &"00".repeat(32)),
            RemoteTarget::WindowsX64Msvc
                .prepare_staged_command(staged, &"00".repeat(32))
                .expect("Windows staging command"),
            RemoteTarget::WindowsX64Msvc.promote_command(
                staged,
                "AppData/Local/Satelle/host/v1/windows-x64/satelle.exe",
            ),
        ];

        for command in commands {
            let script = decode_powershell_command(&command).expect("decode staged mutation");
            for required in [
                "catch",
                "Remove-Item -LiteralPath $path -Force -ErrorAction Stop",
                "WindowsIdentity]::GetCurrent().Name",
                "$acl.Owner -ne $identity",
                "[IO.FileAttributes]::ReparsePoint",
                "exit 75",
                "throw $originalFailure",
            ] {
                assert!(script.contains(required), "missing {required:?}: {script}");
            }
            assert!(script.contains(staged));
            assert!(!script.contains("Get-ChildItem"));
            assert!(!script.contains(".satelle-upload-*"));
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
        assert!(!script.contains("--bootstrap-operation-id"));
        assert!(!script.contains("--bootstrap-operation-kind"));
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
        assert!(posix.contains("execution_failed.$attempt"));
        assert!(posix.contains("[ \"$status\" -eq 65 ]"));
        assert!(posix.contains("[ \"$phase\" = cache_upload ]"));
        assert!(posix.contains("[ \"$phase\" = cache_staging_permissions ]"));
        assert!(posix.contains("exact_terminal_attempt"));
        assert!(posix.contains("[ -d \"$claim_path/execution_started.$attempt\" ]"));
        assert!(posix.contains("[ ! -e \"$claim_path/execution_retiring.$attempt\" ]"));
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
        assert!(script.contains("execution_failed."));
        assert!(script.contains("$status -eq 65"));
        assert!(script.contains("$phase -ceq 'cache_upload'"));
        assert!(script.contains("$phase -ceq 'cache_staging_permissions'"));
        assert!(script.contains("$terminalClaimExact"));
        assert!(script.contains("$terminalClaimItem.PSIsContainer"));
        assert!(script.contains("$terminalStartedItem.PSIsContainer"));
        assert!(script.contains("execution_retiring."));
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
        assert_occurs_before(
            &script,
            "Invoke-Expression $innerCommand",
            "$terminalClaimExact = $false",
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn posix_daemon_start_terminal_marker_requires_exact_postexecution_claim() {
        let state = tempfile::tempdir().expect("temporary state");
        let operation_id = "daemon-start-operation";
        let identity = "0123456789abcdef0123456789abcdef";
        let basename = "claim.daemon-start-operation.0123456789abcdef";
        let claim = state.path().join("bootstrap.lock").join(basename);
        fs::create_dir_all(&claim).expect("create claim");
        fs::write(claim.join("operation_id"), operation_id).expect("write operation id");
        fs::write(claim.join("claim_identity"), identity).expect("write claim identity");
        let failing_daemon = state.path().join("failing-satelle");
        fs::write(
            &failing_daemon,
            "#!/bin/sh\n[ \"$1\" = host ] && [ \"$2\" = start ] || exit 64\nIFS= read -r token || exit 65\ncase \"$token\" in successful-bootstrap-token) exit 0;; expected-bootstrap-token) exit 23;; *) exit 66;; esac\n",
        )
        .expect("write failing daemon");
        fs::set_permissions(&failing_daemon, fs::Permissions::from_mode(0o700))
            .expect("make failing daemon executable");

        for (attempt, exit_code, advance_phase, retire_attempt) in [
            ("11111111111111111111111111111111", 0, false, false),
            ("22222222222222222222222222222222", 23, false, false),
            ("33333333333333333333333333333333", 0, true, false),
            ("44444444444444444444444444444444", 0, false, true),
        ] {
            fs::write(claim.join("state"), "mutation_started").expect("write claim state");
            fs::write(claim.join("mutation_phase"), "daemon_start").expect("write mutation phase");
            fs::write(claim.join("mutation_attempt"), attempt).expect("write mutation attempt");
            let inner_command = if advance_phase {
                format!(
                    "printf '%s\\n' maintenance_handoff_begin >{}",
                    posix_quote(
                        claim
                            .join("mutation_phase")
                            .to_str()
                            .expect("UTF-8 temporary path")
                    )
                )
            } else if retire_attempt {
                format!(
                    "mv {} {}",
                    posix_quote(
                        claim
                            .join(format!("execution_started.{attempt}"))
                            .to_str()
                            .expect("UTF-8 started marker path")
                    ),
                    posix_quote(
                        claim
                            .join(format!("execution_retiring.{attempt}"))
                            .to_str()
                            .expect("UTF-8 retiring marker path")
                    )
                )
            } else {
                RemoteTarget::LinuxX64Gnu.start_command(
                    failing_daemon.to_str().expect("UTF-8 failing daemon path"),
                    SshBootstrapScope::Read,
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                    "127.0.0.1:0",
                )
            };
            if !advance_phase && !retire_attempt {
                assert!(inner_command.contains("exec "));
                assert!(inner_command.contains("host start --bootstrap-token-stdin"));
            }
            let fenced = RemoteTarget::LinuxX64Gnu.fenced_mutation_command(
                operation_id,
                identity,
                basename,
                "daemon_start",
                attempt,
                &inner_command,
            );
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(fenced)
                .env("SATELLE_STATE_DIR", state.path())
                .stdin(Stdio::piped())
                .spawn()
                .expect("run daemon start fence");
            writeln!(
                child.stdin.as_mut().expect("piped daemon fence stdin"),
                "{MUTATION_EXECUTE}"
            )
            .expect("write execution gate");
            if !advance_phase && !retire_attempt {
                writeln!(
                    child.stdin.as_mut().expect("piped daemon fence stdin"),
                    "{}",
                    if exit_code == 0 {
                        "successful-bootstrap-token"
                    } else {
                        "expected-bootstrap-token"
                    }
                )
                .expect("write bootstrap token");
            }
            drop(child.stdin.take());

            assert_eq!(
                child.wait().expect("wait for daemon start fence").code(),
                Some(exit_code)
            );
            assert_eq!(
                claim
                    .join(format!("execution_succeeded.{attempt}"))
                    .is_dir(),
                exit_code == 0 && !advance_phase && !retire_attempt,
            );
            assert_eq!(
                claim.join(format!("execution_failed.{attempt}")).is_dir(),
                exit_code != 0 && !advance_phase && !retire_attempt,
            );
            assert_eq!(
                claim.join(format!("execution_retiring.{attempt}")).is_dir(),
                retire_attempt,
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn posix_execution_gate_requires_newline_and_preserves_following_binary_stdin() {
        let state = tempfile::tempdir().expect("temporary state");
        let operation_id = "gate-operation";
        let identity = "0123456789abcdef0123456789abcdef";
        let basename = "claim.gate-operation.0123456789abcdef";
        let claim = state.path().join("bootstrap.lock").join(basename);
        fs::create_dir_all(&claim).expect("create claim");
        fs::write(claim.join("operation_id"), operation_id).expect("write operation id");
        fs::write(claim.join("claim_identity"), identity).expect("write claim identity");
        fs::write(claim.join("state"), "mutation_started").expect("write claim state");
        fs::write(claim.join("mutation_phase"), "cache_upload").expect("write mutation phase");

        let run = |attempt: &str, input: &[u8], output: &Path| {
            fs::write(claim.join("mutation_attempt"), attempt).expect("write mutation attempt");
            let inner_command = format!(
                "cat > {}",
                posix_quote(output.to_str().expect("UTF-8 output path"))
            );
            let fenced = RemoteTarget::LinuxX64Gnu.fenced_mutation_command(
                operation_id,
                identity,
                basename,
                "cache_upload",
                attempt,
                &inner_command,
            );
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(fenced)
                .env("SATELLE_STATE_DIR", state.path())
                .stdin(Stdio::piped())
                .spawn()
                .expect("run fenced mutation");
            child
                .stdin
                .as_mut()
                .expect("piped mutation stdin")
                .write_all(input)
                .expect("write mutation input");
            drop(child.stdin.take());
            child.wait().expect("wait for fenced mutation")
        };

        let rejected_attempt = "missing-newline";
        let rejected_output = state.path().join("rejected-output");
        let rejected = run(
            rejected_attempt,
            MUTATION_EXECUTE.as_bytes(),
            &rejected_output,
        );
        assert_eq!(rejected.code(), Some(75));
        assert!(!rejected_output.exists());
        assert!(
            !claim
                .join(format!("execution_started.{rejected_attempt}"))
                .exists()
        );
        assert!(
            !claim
                .join(format!("execution_succeeded.{rejected_attempt}"))
                .exists()
        );

        let accepted_attempt = "valid-newline";
        let accepted_output = state.path().join("accepted-output");
        let payload = b"token-line\n\0binary-after-gate\xff\n";
        let mut valid_input = format!("{MUTATION_EXECUTE}\n").into_bytes();
        valid_input.extend_from_slice(payload);
        let accepted = run(accepted_attempt, &valid_input, &accepted_output);
        assert!(accepted.success());
        assert_eq!(
            fs::read(accepted_output).expect("read accepted payload"),
            payload
        );
        assert!(
            claim
                .join(format!("execution_started.{accepted_attempt}"))
                .is_dir()
        );
        assert!(
            claim
                .join(format!("execution_succeeded.{accepted_attempt}"))
                .is_dir()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn posix_release_fence_retains_wrapper_ownership_and_records_only_success() {
        let state = tempfile::tempdir().expect("temporary state");
        let operation_id = "release-operation";
        let identity = "0123456789abcdef0123456789abcdef";
        let basename = "claim.release-operation.0123456789abcdef";
        let claim = state.path().join("bootstrap.lock").join(basename);
        fs::create_dir_all(&claim).expect("create claim");
        fs::write(claim.join("operation_id"), operation_id).expect("write operation id");
        fs::write(claim.join("claim_identity"), identity).expect("write claim identity");

        for (attempt, exit_code) in [("successful-attempt", 0), ("failed-attempt", 23)] {
            fs::write(claim.join("state"), "mutation_started").expect("write claim state");
            fs::write(claim.join("mutation_phase"), "state_owner_release")
                .expect("write mutation phase");
            fs::write(claim.join("mutation_attempt"), attempt).expect("write mutation attempt");

            let observed_parent = state.path().join(format!("parent-{attempt}"));
            let release_binary = state.path().join(format!("release-{attempt}"));
            fs::write(
                &release_binary,
                format!(
                    "#!/bin/sh\ntr '\\000' ' ' </proc/$PPID/cmdline >{}\nexit {exit_code}\n",
                    posix_quote(observed_parent.to_str().expect("UTF-8 temporary path")),
                ),
            )
            .expect("write release executable");
            fs::set_permissions(&release_binary, fs::Permissions::from_mode(0o700))
                .expect("make release executable");

            let release = RemoteTarget::LinuxX64Gnu
                .release_state_command(release_binary.to_str().expect("UTF-8 temporary path"));
            assert!(!release.contains("exec "));
            assert!(!release.starts_with("sh -c "));
            let fenced = RemoteTarget::LinuxX64Gnu.fenced_mutation_command(
                operation_id,
                identity,
                basename,
                "state_owner_release",
                attempt,
                &release,
            );
            let mut child = Command::new("sh")
                .arg("-c")
                .arg(fenced)
                .env("SATELLE_STATE_DIR", state.path())
                .stdin(Stdio::piped())
                .spawn()
                .expect("run release fence");
            writeln!(
                child.stdin.as_mut().expect("piped release fence stdin"),
                "{MUTATION_EXECUTE}"
            )
            .expect("write execution gate");
            drop(child.stdin.take());
            let status = child.wait().expect("wait for release fence");

            assert_eq!(status.code(), Some(exit_code));
            let parent = fs::read_to_string(&observed_parent).expect("read observed parent");
            assert!(
                parent.contains("operation_id='release-operation'"),
                "release binary was not a direct child of the fence wrapper: {parent}"
            );
            assert_eq!(
                claim
                    .join(format!("execution_succeeded.{attempt}"))
                    .is_dir(),
                exit_code == 0,
            );
        }
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
    fn windows_cache_mutations_preflight_existing_ancestor_reparse_points() {
        let directory = "AppData/Local/Satelle/host/v1/windows-x64";
        let staged = format!("{directory}/.satelle-upload-attempt.exe");
        let final_path = format!("{directory}/satelle.exe");

        let create = decode_powershell_command(
            &RemoteTarget::WindowsX64Msvc.create_directory_command(directory),
        )
        .expect("decode directory command");
        let upload = decode_powershell_command(
            &RemoteTarget::WindowsX64Msvc.upload_command(&staged, &"00".repeat(32)),
        )
        .expect("decode upload command");
        let promote = decode_powershell_command(
            &RemoteTarget::WindowsX64Msvc.promote_command(&staged, &final_path),
        )
        .expect("decode promotion command");

        for script in [&create, &upload, &promote] {
            for required in [
                "[IO.Path]::GetFullPath",
                "[IO.Path]::GetPathRoot($root)",
                "$anchorPrefix=$anchor.TrimEnd($separator)+$separator",
                "$root.StartsWith($anchorPrefix,[StringComparison]::OrdinalIgnoreCase)",
                "[StringComparer]::OrdinalIgnoreCase.Equals",
                "StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)",
                "Test-Path -LiteralPath $currentPath",
                "$current=Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop",
                "($current.Attributes -band [IO.FileAttributes]::ReparsePoint)",
                "$parentPath=[IO.Path]::GetDirectoryName($currentPath)",
                "[StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$anchor)",
            ] {
                assert!(script.contains(required), "missing {required:?}: {script}");
            }
        }

        assert_occurs_before(
            &create,
            "Test-Path -LiteralPath $currentPath",
            "New-Item -ItemType Directory",
        );
        assert_occurs_before(
            &upload,
            "Test-Path -LiteralPath $currentPath",
            "$outputStream = [IO.File]::Open",
        );
        assert_occurs_before(
            &promote,
            "$item=Get-Item -LiteralPath $path -Force -ErrorAction Stop",
            "Move-Item -Force",
        );
        assert_occurs_before(
            &promote,
            "Test-Path -LiteralPath $currentPath",
            "Move-Item -Force",
        );
        assert_occurs_before(
            &promote,
            "$finalItem=Get-Item -LiteralPath $finalPath -Force -ErrorAction Stop",
            "Move-Item -Force",
        );
        assert_occurs_before(
            &upload,
            "[StringComparer]::OrdinalIgnoreCase.Equals($currentPath,$anchor)",
            "Remove-Item -LiteralPath $path",
        );
        assert!(upload.matches("[IO.Path]::GetPathRoot($root)").count() >= 2);
        assert!(promote.matches("[IO.Path]::GetPathRoot($root)").count() >= 3);
        assert!(promote.contains("$finalItem -isnot [IO.FileInfo]"));
        assert!(
            promote.contains("($finalItem.Attributes -band [IO.FileAttributes]::ReparsePoint)")
        );
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
                "unset SATELLE_HOME SATELLE_CONFIG_FILE SATELLE_STATE_DIR ",
                "SATELLE_CACHE_DIR SATELLE_LOG_DIR; ",
                "'.cache/satelle/satelle' host release-state"
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

    #[cfg(target_os = "linux")]
    #[test]
    fn posix_durable_launch_passes_path_overrides_and_token_to_daemon() {
        let state = tempfile::tempdir().expect("temporary state");
        let operation_id = "durable-daemon-start-operation";
        let identity = "0123456789abcdef0123456789abcdef";
        let basename = "claim.durable-daemon-start-operation.0123456789abcdef";
        let attempt = "11111111111111111111111111111111";
        let claim = state.path().join("bootstrap.lock").join(basename);
        fs::create_dir_all(&claim).expect("create claim");
        fs::write(claim.join("operation_id"), operation_id).expect("write operation id");
        fs::write(claim.join("claim_identity"), identity).expect("write claim identity");
        fs::write(claim.join("state"), "mutation_started").expect("write claim state");
        fs::write(claim.join("mutation_phase"), "daemon_start").expect("write mutation phase");
        fs::write(claim.join("mutation_attempt"), attempt).expect("write mutation attempt");

        let selected_home = state.path().join("selected home");
        let selected_state = state.path().join("selected state");
        fs::create_dir_all(&selected_home).expect("create selected home");
        fs::create_dir_all(&selected_state).expect("create selected state");
        let observation = state.path().join("durable-observation");
        assert!(
            Command::new("mkfifo")
                .arg(&observation)
                .status()
                .expect("create observation fifo")
                .success()
        );

        let daemon = state.path().join("durable-satelle");
        fs::write(
            &daemon,
            format!(
                "#!/bin/sh\n[ \"$1\" = host ] && [ \"$2\" = start ] || exit 64\nIFS= read -r token || token='<missing>'\nprintf '%s\\n%s\\n%s\\n' \"$SATELLE_HOME\" \"$SATELLE_STATE_DIR\" \"$token\" > {}\n[ \"$token\" != '<missing>' ]\n",
                posix_quote(observation.to_str().expect("UTF-8 observation path")),
            ),
        )
        .expect("write durable daemon");
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o700))
            .expect("make durable daemon executable");

        let environment = [
            ("SATELLE_HOME", selected_home.as_path()),
            ("SATELLE_STATE_DIR", selected_state.as_path()),
        ];
        let durable = RemoteTarget::LinuxX64Gnu.durable_start_command_with_environment(
            daemon.to_str().expect("UTF-8 durable daemon path"),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            &environment,
        );
        assert_occurs_before(&durable, "exec 3<&0", POSIX_DAEMON_ENVIRONMENT_CLEAR);
        assert_occurs_before(&durable, "SATELLE_STATE_DIR=", "nohup ");

        let fenced = RemoteTarget::LinuxX64Gnu.fenced_mutation_command(
            operation_id,
            identity,
            basename,
            "daemon_start",
            attempt,
            &durable,
        );
        let observation_reader_path = observation.clone();
        let (observation_sender, observation_receiver) = std::sync::mpsc::sync_channel(1);
        let observation_reader = std::thread::spawn(move || {
            observation_sender
                .send(fs::read_to_string(observation_reader_path))
                .expect("send durable observation");
        });
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(fenced)
            .env("SATELLE_STATE_DIR", state.path())
            .stdin(Stdio::piped())
            .spawn()
            .expect("run durable daemon fence");
        writeln!(
            child.stdin.as_mut().expect("piped durable fence stdin"),
            "{MUTATION_EXECUTE}\nexpected-bootstrap-token"
        )
        .expect("write durable execution gate and token");
        drop(child.stdin.take());

        assert!(child.wait().expect("wait for durable fence").success());
        let observed = match observation_receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(observed) => observed.expect("read durable observation"),
            Err(error) => {
                drop(
                    fs::OpenOptions::new()
                        .write(true)
                        .open(&observation)
                        .expect("unblock observation reader"),
                );
                observation_reader
                    .join()
                    .expect("join unblocked observation reader");
                panic!("durable daemon did not publish its observation: {error}");
            }
        };
        observation_reader
            .join()
            .expect("join durable observation reader");
        assert_eq!(
            observed,
            format!(
                "{}\n{}\nexpected-bootstrap-token\n",
                selected_home.display(),
                selected_state.display(),
            )
        );
        assert!(
            claim
                .join(format!("execution_succeeded.{attempt}"))
                .is_dir()
        );
        assert!(!claim.join(format!("execution_failed.{attempt}")).exists());
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
    fn windows_durable_launch_inherits_persistent_null_output_handles() {
        let command = RemoteTarget::WindowsX64Msvc.durable_start_command(
            "AppData/Local/Satelle/satelle.exe",
            Duration::from_secs(75),
            Duration::from_millis(2_500),
            Duration::from_millis(7_500),
        );
        let script = decode_powershell_command(&command).expect("decode durable command");

        for required in [
            "Add-Type -TypeDefinition",
            "DllImport(\"kernel32.dll\", SetLastError=true)",
            "GetStdHandle(int stream)",
            "GetHandleInformation(IntPtr handle, out uint flags)",
            "SetHandleInformation(IntPtr handle, uint mask, uint flags)",
            "$originalInput = [SatelleBootstrapNative]::GetStdHandle(-10)",
            "$originalOutput = [SatelleBootstrapNative]::GetStdHandle(-11)",
            "$originalError = [SatelleBootstrapNative]::GetStdHandle(-12)",
            "GetHandleInformation($originalInput,[ref]$inputFlags)",
            "GetHandleInformation($originalOutput,[ref]$outputFlags)",
            "GetHandleInformation($originalError,[ref]$errorFlags)",
            "$nullOutput = [IO.File]::Open('NUL'",
            "$nullOutput.SafeFileHandle.DangerousGetHandle()",
            "SetHandleInformation($originalInput,1,0)",
            "SetHandleInformation($originalOutput,1,0)",
            "SetHandleInformation($originalError,1,0)",
            "SetHandleInformation($nullHandle,1,1)",
            "SetStdHandle(-11,$nullHandle)",
            "SetStdHandle(-12,$nullHandle)",
            "$startInfo.UseShellExecute = $false",
            "$startInfo.RedirectStandardInput = $true",
            "$startInfo.RedirectStandardOutput = $false",
            "$startInfo.RedirectStandardError = $false",
            "$token = [Console]::In.ReadLine()",
            "$process.StandardInput.WriteLine($token)",
            "$process.StandardInput.Close()",
            "finally {",
            "SetStdHandle(-10,$originalInput)",
            "SetStdHandle(-11,$originalOutput)",
            "SetStdHandle(-12,$originalError)",
            "SetHandleInformation($originalInput,1,($inputFlags -band 1))",
            "SetHandleInformation($originalOutput,1,($outputFlags -band 1))",
            "SetHandleInformation($originalError,1,($errorFlags -band 1))",
            "$nullOutput.Dispose()",
            "$process.Dispose()",
        ] {
            assert!(script.contains(required), "missing {required:?}: {script}");
        }

        for output_setup in [
            "SetHandleInformation($originalInput,1,0)",
            "SetHandleInformation($originalOutput,1,0)",
            "SetHandleInformation($originalError,1,0)",
            "SetHandleInformation($nullHandle,1,1)",
            "SetStdHandle(-11,$nullHandle)",
            "SetStdHandle(-12,$nullHandle)",
            "$startInfo.RedirectStandardOutput = $false",
            "$startInfo.RedirectStandardError = $false",
        ] {
            assert_occurs_before(&script, output_setup, "$process.Start()");
        }
        assert_occurs_before(
            &script,
            "$process.StandardInput.WriteLine($token)",
            "$process.StandardInput.Close()",
        );
        assert_occurs_before(
            &script,
            "$process.StandardInput.Close()",
            "SetStdHandle(-10,$originalInput)",
        );
        for restoration in [
            "SetStdHandle(-10,$originalInput)",
            "SetStdHandle(-11,$originalOutput)",
            "SetStdHandle(-12,$originalError)",
            "SetHandleInformation($originalInput,1,($inputFlags -band 1))",
            "SetHandleInformation($originalOutput,1,($outputFlags -band 1))",
            "SetHandleInformation($originalError,1,($errorFlags -band 1))",
        ] {
            assert_occurs_before(&script, restoration, "$nullOutput.Dispose()");
        }
        assert_occurs_before(
            &script,
            "$process.StandardInput.Close()",
            "$nullOutput.Dispose()",
        );
        assert!(script.contains("$startInfo.FileName = $binary"));
        assert!(!script.contains("RedirectStandardOutput = $true"));
        assert!(!script.contains("RedirectStandardError = $true"));
        assert!(!script.contains("StandardOutput.Close()"));
        assert!(!script.contains("StandardError.Close()"));
        assert!(!script.contains("cmd.exe"));
        assert!(!script.contains("$token = '"));
        assert!(!script.contains("SATELLE_BOOTSTRAP_TOKEN"));
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
                "sh -c 'exec 3<&0; unset SATELLE_HOME SATELLE_CONFIG_FILE SATELLE_STATE_DIR ",
                "SATELLE_CACHE_DIR SATELLE_LOG_DIR; ",
                "nohup /tmp/satelle host start --bootstrap-token-stdin ",
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
        assert!(!script.contains("--bootstrap-operation-id"));
        assert!(!script.contains("--bootstrap-operation-kind"));
        assert!(script.contains("RedirectStandardInput = $true"));
        assert!(script.contains("StandardInput.WriteLine($token)"));
    }
}
