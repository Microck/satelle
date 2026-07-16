use command_group::{CommandGroup, GroupChild};
use satelle_core::ControlPlaneFailureReason;
use serde::Serialize;
use std::fmt;
use std::io::ErrorKind;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[path = "runtime-codex.rs"]
mod control_plane;
pub(crate) use control_plane::{ControlPlaneAdmission, installed_app_server_command};

#[cfg(test)]
#[path = "runtime-codex-tests.rs"]
mod control_plane_tests;

const VERSION_OUTPUT_LIMIT: u64 = 129;
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Exact Codex release whose stable schema and native-host behavior define the
/// Phase 0 compatibility contract. Later patches require fresh acceptance.
pub(crate) const REQUIRED_CODEX_VERSION: CodexVersion = CodexVersion::new(0, 144, 0);

/// Every upstream capability required before native Computer Use can be
/// advertised as supported.
pub(crate) const REQUIRED_CAPABILITIES: [RequiredCapability; 12] = [
    RequiredCapability::Handshake,
    RequiredCapability::SessionThreadCreation,
    RequiredCapability::TurnStart,
    RequiredCapability::LifecycleEvents,
    RequiredCapability::ApprovalObservation,
    RequiredCapability::NativeReadiness,
    RequiredCapability::NativeHarmlessAction,
    RequiredCapability::Recovery,
    RequiredCapability::FollowUpTurn,
    RequiredCapability::DetachedTurnOwnership,
    RequiredCapability::InterruptRequest,
    RequiredCapability::ConfirmedStop,
];

/// A parsed Codex version. Numeric fields keep diagnostic blockers free of
/// arbitrary command output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CodexVersion {
    pub(crate) major: u16,
    pub(crate) minor: u16,
    pub(crate) patch: u16,
}

impl CodexVersion {
    pub(crate) const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for CodexVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Closed classification of the `codex --version` probe. Arbitrary command
/// output is parsed immediately and never retained in capability evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum CodexVersionEvidence {
    Detected { version: CodexVersion },
    Missing,
    Malformed,
    Unavailable,
}

impl CodexVersionEvidence {
    pub(crate) const fn status_name(self) -> &'static str {
        match self {
            Self::Detected { .. } => "detected",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Platforms that capability discovery can classify without retaining raw OS
/// strings. Linux remains a Controller platform only. `Other` is the
/// fail-closed classification for an unrecognized native Host platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostPlatform {
    Macos,
    Windows,
    Linux,
    Other,
}

impl HostPlatform {
    pub(crate) const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }

    pub(crate) const fn supports_native_computer_use(self) -> bool {
        matches!(self, Self::Macos | Self::Windows)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Other => "other",
        }
    }
}

/// Stable Satelle capability keys. These keys describe product requirements,
/// not upstream method names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequiredCapability {
    Handshake,
    SessionThreadCreation,
    TurnStart,
    LifecycleEvents,
    ApprovalObservation,
    NativeReadiness,
    NativeHarmlessAction,
    Recovery,
    FollowUpTurn,
    DetachedTurnOwnership,
    InterruptRequest,
    ConfirmedStop,
}

impl RequiredCapability {
    /// These capabilities cannot be established from a schema or feature flag.
    /// They require live proof through the same supported path used in
    /// production.
    const fn requires_live_proof(self) -> bool {
        match self {
            Self::ApprovalObservation
            | Self::NativeReadiness
            | Self::NativeHarmlessAction
            | Self::Recovery
            | Self::FollowUpTurn
            | Self::DetachedTurnOwnership
            | Self::ConfirmedStop => true,
            Self::Handshake
            | Self::SessionThreadCreation
            | Self::TurnStart
            | Self::LifecycleEvents
            | Self::InterruptRequest => false,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::SessionThreadCreation => "session_thread_creation",
            Self::TurnStart => "turn_start",
            Self::LifecycleEvents => "lifecycle_events",
            Self::ApprovalObservation => "approval_observation",
            Self::NativeReadiness => "native_readiness",
            Self::NativeHarmlessAction => "native_harmless_action",
            Self::Recovery => "recovery",
            Self::FollowUpTurn => "follow_up_turn",
            Self::DetachedTurnOwnership => "detached_turn_ownership",
            Self::InterruptRequest => "interrupt_request",
            Self::ConfirmedStop => "confirmed_stop",
        }
    }
}

/// Where a capability was observed. Only the documented stable surface can
/// contribute to a supported verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EvidenceSurface {
    Stable,
    #[cfg(test)]
    Experimental,
    #[cfg(test)]
    Undocumented,
    Absent,
}

impl EvidenceSurface {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            #[cfg(test)]
            Self::Experimental => "experimental",
            #[cfg(test)]
            Self::Undocumented => "undocumented",
            Self::Absent => "absent",
        }
    }
}

/// Whether the required live acceptance behavior was observed. This enum does
/// not carry prompt text, logs, or provider output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LiveProofStatus {
    NotRequired,
    Passed,
    NotObserved,
    #[cfg(test)]
    Failed,
}

impl LiveProofStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Passed => "passed",
            Self::NotObserved => "not_observed",
            #[cfg(test)]
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CapabilityEvidence {
    pub(crate) surface: EvidenceSurface,
    pub(crate) live_proof: LiveProofStatus,
}

impl CapabilityEvidence {
    pub(crate) const fn new(surface: EvidenceSurface, live_proof: LiveProofStatus) -> Self {
        Self {
            surface,
            live_proof,
        }
    }
}

/// A fixed matrix prevents omitted or duplicate capability observations. It
/// deliberately has no fallback-transport field: terminal scraping and
/// undocumented GUI automation are not valid evidence sources.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CapabilityMatrix {
    pub(crate) handshake: CapabilityEvidence,
    pub(crate) session_thread_creation: CapabilityEvidence,
    pub(crate) turn_start: CapabilityEvidence,
    pub(crate) lifecycle_events: CapabilityEvidence,
    pub(crate) approval_observation: CapabilityEvidence,
    pub(crate) native_readiness: CapabilityEvidence,
    pub(crate) native_harmless_action: CapabilityEvidence,
    pub(crate) recovery: CapabilityEvidence,
    pub(crate) follow_up_turn: CapabilityEvidence,
    pub(crate) detached_turn_ownership: CapabilityEvidence,
    pub(crate) interrupt_request: CapabilityEvidence,
    pub(crate) confirmed_stop: CapabilityEvidence,
}

impl CapabilityMatrix {
    /// Fail-closed fallback when the installed runtime cannot expose a version
    /// and stable schema. Native-host acceptance remains separately unproven.
    pub(crate) const fn unproven() -> Self {
        let absent = CapabilityEvidence::new(EvidenceSurface::Absent, LiveProofStatus::NotRequired);
        let unobserved =
            CapabilityEvidence::new(EvidenceSurface::Absent, LiveProofStatus::NotObserved);

        Self {
            handshake: absent,
            session_thread_creation: absent,
            turn_start: absent,
            lifecycle_events: absent,
            approval_observation: unobserved,
            native_readiness: unobserved,
            native_harmless_action: unobserved,
            recovery: unobserved,
            follow_up_turn: unobserved,
            detached_turn_ownership: unobserved,
            interrupt_request: absent,
            confirmed_stop: unobserved,
        }
    }

    fn evidence_for(self, capability: RequiredCapability) -> CapabilityEvidence {
        match capability {
            RequiredCapability::Handshake => self.handshake,
            RequiredCapability::SessionThreadCreation => self.session_thread_creation,
            RequiredCapability::TurnStart => self.turn_start,
            RequiredCapability::LifecycleEvents => self.lifecycle_events,
            RequiredCapability::ApprovalObservation => self.approval_observation,
            RequiredCapability::NativeReadiness => self.native_readiness,
            RequiredCapability::NativeHarmlessAction => self.native_harmless_action,
            RequiredCapability::Recovery => self.recovery,
            RequiredCapability::FollowUpTurn => self.follow_up_turn,
            RequiredCapability::DetachedTurnOwnership => self.detached_turn_ownership,
            RequiredCapability::InterruptRequest => self.interrupt_request,
            RequiredCapability::ConfirmedStop => self.confirmed_stop,
        }
    }
}

/// Sanitized output from version, schema, and live native-host probes.
/// Collection code must parse or classify raw output before constructing this
/// value; prompts, secrets, and free-form logs do not cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Phase0CapabilityEvidence {
    pub(crate) codex_version: CodexVersionEvidence,
    pub(crate) host_platform: HostPlatform,
    pub(crate) capabilities: CapabilityMatrix,
}

pub(crate) struct Phase0Discovery {
    pub(crate) evidence: Phase0CapabilityEvidence,
    pub(crate) control_plane_admission: control_plane::ControlPlaneAdmission,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockerReason {
    MissingCodexRuntime,
    MalformedCodexVersion,
    CodexVersionUnavailable,
    UnsupportedCodexVersion,
    UnsupportedHostPlatform,
    NativeExecutionPathUnavailable,
    NonStableSurface,
    IncompleteLiveProof,
}

impl BlockerReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MissingCodexRuntime => "missing_codex_runtime",
            Self::MalformedCodexVersion => "malformed_codex_version",
            Self::CodexVersionUnavailable => "codex_version_unavailable",
            Self::UnsupportedCodexVersion => "unsupported_codex_version",
            Self::UnsupportedHostPlatform => "unsupported_host_platform",
            Self::NativeExecutionPathUnavailable => "native_execution_path_unavailable",
            Self::NonStableSurface => "non_stable_surface",
            Self::IncompleteLiveProof => "incomplete_live_proof",
        }
    }
}

/// A diagnostic-safe blocker. Every field is a closed enum or numeric value;
/// it cannot retain prompt text, secret material, arbitrary logs, or upstream
/// method names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Phase0CapabilityBlocker {
    pub(crate) reason: BlockerReason,
    pub(crate) capability: RequiredCapability,
    pub(crate) codex_version: CodexVersionEvidence,
    pub(crate) host_platform: HostPlatform,
    pub(crate) observed_surface: EvidenceSurface,
    pub(crate) live_proof: LiveProofStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Phase0SupportVerdict {
    Supported {
        codex_version: CodexVersion,
        host_platform: HostPlatform,
    },
    Blocked {
        blockers: Vec<Phase0CapabilityBlocker>,
    },
}

impl Phase0SupportVerdict {
    pub(crate) fn blockers(&self) -> &[Phase0CapabilityBlocker] {
        match self {
            Self::Supported { .. } => &[],
            Self::Blocked { blockers } => blockers,
        }
    }

    pub(crate) const fn is_supported(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }
}

/// Collects the deliberately narrow evidence production can prove today. The
/// version command's bytes are classified and dropped inside this module.
pub(crate) fn discover_phase0(probe_timeout: Option<Duration>) -> Phase0Discovery {
    let host_platform = HostPlatform::current();
    if !host_platform.supports_native_computer_use() {
        return Phase0Discovery {
            evidence: Phase0CapabilityEvidence {
                codex_version: CodexVersionEvidence::Unavailable,
                host_platform,
                capabilities: CapabilityMatrix::unproven(),
            },
            // Linux and unknown platforms are native Computer Use readiness
            // failures. They must not be mislabeled as Codex protocol errors.
            control_plane_admission: control_plane::ControlPlaneAdmission::not_applicable(),
        };
    }

    let codex_version = probe_codex_version(probe_timeout.unwrap_or(VERSION_PROBE_TIMEOUT));
    let (capabilities, control_plane_admission) = match codex_version {
        CodexVersionEvidence::Detected { version } if version == REQUIRED_CODEX_VERSION => {
            let probe = control_plane::probe_installed_control_plane(probe_timeout);
            (
                CapabilityMatrix::from_control_plane(probe),
                control_plane::ControlPlaneAdmission::from_probe(probe),
            )
        }
        CodexVersionEvidence::Missing => (
            CapabilityMatrix::unproven(),
            control_plane::ControlPlaneAdmission::unavailable(
                ControlPlaneFailureReason::RuntimeMissing,
            ),
        ),
        CodexVersionEvidence::Malformed => (
            CapabilityMatrix::unproven(),
            control_plane::ControlPlaneAdmission::unavailable(
                ControlPlaneFailureReason::VersionMalformed,
            ),
        ),
        CodexVersionEvidence::Unavailable => (
            CapabilityMatrix::unproven(),
            control_plane::ControlPlaneAdmission::unavailable(
                ControlPlaneFailureReason::VersionUnavailable,
            ),
        ),
        CodexVersionEvidence::Detected { .. } => (
            CapabilityMatrix::unproven(),
            control_plane::ControlPlaneAdmission::unavailable(
                ControlPlaneFailureReason::VersionUnsupported,
            ),
        ),
    };
    Phase0Discovery {
        evidence: Phase0CapabilityEvidence {
            codex_version,
            host_platform,
            capabilities,
        },
        control_plane_admission,
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn discover_phase0_evidence() -> Phase0CapabilityEvidence {
    discover_phase0(None).evidence
}

/// Evaluates the complete Phase 0 capability contract. The evaluator reports
/// all typed blockers found in one pass while still allowing support only when
/// no blocker exists.
#[must_use]
pub(crate) fn evaluate_phase0_support(evidence: Phase0CapabilityEvidence) -> Phase0SupportVerdict {
    if !evidence.host_platform.supports_native_computer_use() {
        return Phase0SupportVerdict::Blocked {
            blockers: vec![blocker_for(
                evidence,
                BlockerReason::UnsupportedHostPlatform,
                RequiredCapability::NativeReadiness,
            )],
        };
    }

    let mut blockers = Vec::new();

    let version_blocker = match evidence.codex_version {
        CodexVersionEvidence::Detected { version } if version == REQUIRED_CODEX_VERSION => None,
        CodexVersionEvidence::Detected { .. } => Some(BlockerReason::UnsupportedCodexVersion),
        CodexVersionEvidence::Missing => Some(BlockerReason::MissingCodexRuntime),
        CodexVersionEvidence::Malformed => Some(BlockerReason::MalformedCodexVersion),
        CodexVersionEvidence::Unavailable => Some(BlockerReason::CodexVersionUnavailable),
    };
    if let Some(reason) = version_blocker {
        blockers.push(blocker_for(evidence, reason, RequiredCapability::Handshake));
    }

    for capability in REQUIRED_CAPABILITIES {
        let observation = evidence.capabilities.evidence_for(capability);
        if observation.surface != EvidenceSurface::Stable {
            blockers.push(Phase0CapabilityBlocker {
                reason: surface_blocker_reason(evidence.capabilities, capability),
                capability,
                codex_version: evidence.codex_version,
                host_platform: evidence.host_platform,
                observed_surface: observation.surface,
                live_proof: observation.live_proof,
            });
        }

        if capability.requires_live_proof() && observation.live_proof != LiveProofStatus::Passed {
            blockers.push(Phase0CapabilityBlocker {
                reason: BlockerReason::IncompleteLiveProof,
                capability,
                codex_version: evidence.codex_version,
                host_platform: evidence.host_platform,
                observed_surface: observation.surface,
                live_proof: observation.live_proof,
            });
        }
    }

    if blockers.is_empty() {
        let CodexVersionEvidence::Detected { version } = evidence.codex_version else {
            unreachable!("a supported verdict requires a detected Codex version")
        };
        Phase0SupportVerdict::Supported {
            codex_version: version,
            host_platform: evidence.host_platform,
        }
    } else {
        Phase0SupportVerdict::Blocked { blockers }
    }
}

fn surface_blocker_reason(
    capabilities: CapabilityMatrix,
    capability: RequiredCapability,
) -> BlockerReason {
    let private_control_plane_proven = capabilities.handshake.surface == EvidenceSurface::Stable;
    if private_control_plane_proven
        && capabilities.evidence_for(capability).surface == EvidenceSurface::Absent
        && matches!(
            capability,
            RequiredCapability::NativeReadiness | RequiredCapability::NativeHarmlessAction
        )
    {
        BlockerReason::NativeExecutionPathUnavailable
    } else {
        BlockerReason::NonStableSurface
    }
}

fn blocker_for(
    evidence: Phase0CapabilityEvidence,
    reason: BlockerReason,
    capability: RequiredCapability,
) -> Phase0CapabilityBlocker {
    let observation = evidence.capabilities.evidence_for(capability);
    Phase0CapabilityBlocker {
        reason,
        capability,
        codex_version: evidence.codex_version,
        host_platform: evidence.host_platform,
        observed_surface: observation.surface,
        live_proof: observation.live_proof,
    }
}

fn probe_codex_version(timeout: Duration) -> CodexVersionEvidence {
    let mut command = Command::new("codex");
    command.arg("--version");
    probe_codex_version_command(command, timeout)
}

fn probe_codex_version_command(mut command: Command, timeout: Duration) -> CodexVersionEvidence {
    let deadline = Instant::now() + timeout;
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == ErrorKind::NotFound => return CodexVersionEvidence::Missing,
        Err(_) => return CodexVersionEvidence::Unavailable,
    };
    let Some(stdout) = child.inner().stdout.take() else {
        let _ = terminate_group(&mut child);
        return CodexVersionEvidence::Unavailable;
    };

    // Read at most one byte beyond the accepted limit. Dropping the pipe at
    // that point prevents an unexpected executable from filling memory with
    // arbitrary output. Stderr is discarded at the process boundary.
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let output = read_version_output(stdout, deadline);
        let _ = sender.send(output);
    });

    let status = wait_for_leader(&mut child, deadline);
    let group_stopped = terminate_group(&mut child);
    #[cfg(not(unix))]
    if !group_stopped && !reader.is_finished() {
        return CodexVersionEvidence::Unavailable;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let output = receiver.recv_timeout(remaining);
    let reader_stopped = reader.join().is_ok();
    let Ok(Ok(output)) = output else {
        return CodexVersionEvidence::Unavailable;
    };
    if !group_stopped || !reader_stopped {
        return CodexVersionEvidence::Unavailable;
    }

    let GroupWaitOutcome::Exited(status) = status else {
        return CodexVersionEvidence::Unavailable;
    };
    if !status.success() {
        return CodexVersionEvidence::Unavailable;
    }

    parse_codex_version_output(&output)
}

#[cfg(unix)]
fn read_version_output(
    stdout: std::process::ChildStdout,
    deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    set_nonblocking(&stdout)?;

    let mut output = Vec::with_capacity(VERSION_OUTPUT_LIMIT as usize);
    let mut bounded = stdout.take(VERSION_OUTPUT_LIMIT);
    loop {
        match bounded.read_to_end(&mut output) {
            Ok(_) => return Ok(output),
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(VERSION_PROBE_POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(unix))]
fn read_version_output(
    stdout: std::process::ChildStdout,
    _deadline: Instant,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(VERSION_OUTPUT_LIMIT as usize);
    stdout
        .take(VERSION_OUTPUT_LIMIT)
        .read_to_end(&mut output)
        .map(|_| output)
}

#[cfg(unix)]
pub(crate) fn set_nonblocking(fd: &impl std::os::fd::AsFd) -> std::io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    Ok(rustix::fs::fcntl_setfl(
        fd,
        flags | rustix::fs::OFlags::NONBLOCK,
    )?)
}

enum GroupWaitOutcome {
    Exited(std::process::ExitStatus),
    Deadline,
    Error,
}

fn wait_for_leader(child: &mut GroupChild, deadline: Instant) -> GroupWaitOutcome {
    loop {
        match child.inner().try_wait() {
            Ok(Some(status)) => return GroupWaitOutcome::Exited(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(VERSION_PROBE_POLL_INTERVAL),
            Ok(None) => return GroupWaitOutcome::Deadline,
            Err(_) => return GroupWaitOutcome::Error,
        }
    }
}

fn wait_for_group(child: &mut GroupChild, deadline: Instant) -> GroupWaitOutcome {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return GroupWaitOutcome::Exited(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(VERSION_PROBE_POLL_INTERVAL),
            Ok(None) => return GroupWaitOutcome::Deadline,
            Err(_) => return GroupWaitOutcome::Error,
        }
    }
}

pub(crate) fn terminate_group(child: &mut GroupChild) -> bool {
    let killed_or_gone = loop {
        match child.kill() {
            Ok(()) => break true,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => break group_is_gone(&error) || reap_proven_empty_group(child),
        }
    };
    if !killed_or_gone {
        return false;
    }

    // On Unix, kill() has already signaled the complete process group. Reap
    // the direct child by PID instead of asking command-group to wait by
    // negative process-group ID. Once the group disappears, macOS can report
    // that group wait as unavailable even though the leader is still ours to
    // reap, incorrectly turning successful containment into a failure.
    loop {
        #[cfg(unix)]
        let reaped = child.inner().wait();
        #[cfg(not(unix))]
        let reaped = child.wait();
        match reaped {
            Ok(_) => return true,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return group_is_reaped(&error),
        }
    }
}

#[cfg(unix)]
fn reap_proven_empty_group(child: &mut GroupChild) -> bool {
    let Some(group_id) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    if !matches!(child.inner().try_wait(), Ok(Some(_))) {
        return false;
    }
    matches!(
        rustix::process::test_kill_process_group(group_id),
        Err(error) if error == rustix::io::Errno::SRCH
    )
}

#[cfg(not(unix))]
fn reap_proven_empty_group(_child: &mut GroupChild) -> bool {
    false
}

fn group_is_gone(error: &std::io::Error) -> bool {
    if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::InvalidInput) {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error())
    }
    #[cfg(not(unix))]
    false
}

fn group_is_reaped(_error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        _error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error())
    }
    #[cfg(not(unix))]
    false
}

fn parse_codex_version_output(output: &[u8]) -> CodexVersionEvidence {
    // The expected line is under 32 bytes. The bound avoids retaining or
    // parsing an accidentally verbose response from an unexpected executable.
    if output.len() >= VERSION_OUTPUT_LIMIT as usize {
        return CodexVersionEvidence::Malformed;
    }

    let Ok(text) = std::str::from_utf8(output) else {
        return CodexVersionEvidence::Malformed;
    };
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let Some(version) = line.strip_prefix("codex-cli ") else {
        return CodexVersionEvidence::Malformed;
    };
    if version.is_empty()
        || version
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || byte == b'.'))
    {
        return CodexVersionEvidence::Malformed;
    }

    let mut fields = version.split('.');
    let parsed = fields
        .next()
        .and_then(parse_version_component)
        .zip(fields.next().and_then(parse_version_component))
        .zip(fields.next().and_then(parse_version_component));
    let Some(((major, minor), patch)) = parsed else {
        return CodexVersionEvidence::Malformed;
    };
    if fields.next().is_some() {
        return CodexVersionEvidence::Malformed;
    }

    CodexVersionEvidence::Detected {
        version: CodexVersion::new(major, minor, patch),
    }
}

fn parse_version_component(component: &str) -> Option<u16> {
    if component.len() > 1 && component.starts_with('0') {
        return None;
    }
    component.parse().ok()
}

#[cfg(test)]
#[path = "codex-capabilities-tests.rs"]
mod tests;
