use serde::Serialize;
use std::fmt;
use std::io::ErrorKind;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const VERSION_OUTPUT_LIMIT: u64 = 129;
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The only Codex release whose stable app-server contract is accepted by
/// Satelle Phase 0. A newer semver is not assumed to be compatible.
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

    const fn supports_native_computer_use(self) -> bool {
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
    /// Production discovery has not yet run the stable schema and native-host
    /// acceptance suite, so every capability remains explicitly unproven.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockerReason {
    MissingCodexRuntime,
    MalformedCodexVersion,
    CodexVersionUnavailable,
    UnsupportedCodexVersion,
    UnsupportedHostPlatform,
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
pub(crate) fn discover_phase0_evidence() -> Phase0CapabilityEvidence {
    Phase0CapabilityEvidence {
        codex_version: probe_codex_version(),
        host_platform: HostPlatform::current(),
        capabilities: CapabilityMatrix::unproven(),
    }
}

/// Evaluates the complete Phase 0 capability contract. The evaluator reports
/// all typed blockers found in one pass while still allowing support only when
/// no blocker exists.
#[must_use]
pub(crate) fn evaluate_phase0_support(evidence: Phase0CapabilityEvidence) -> Phase0SupportVerdict {
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

    if !evidence.host_platform.supports_native_computer_use() {
        blockers.push(blocker_for(
            evidence,
            BlockerReason::UnsupportedHostPlatform,
            RequiredCapability::NativeReadiness,
        ));
    }

    for capability in REQUIRED_CAPABILITIES {
        let observation = evidence.capabilities.evidence_for(capability);
        if observation.surface != EvidenceSurface::Stable {
            blockers.push(Phase0CapabilityBlocker {
                reason: BlockerReason::NonStableSurface,
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

fn probe_codex_version() -> CodexVersionEvidence {
    let mut command = Command::new("codex");
    command.arg("--version");
    probe_codex_version_command(command, VERSION_PROBE_TIMEOUT)
}

fn probe_codex_version_command(mut command: Command, timeout: Duration) -> CodexVersionEvidence {
    let deadline = Instant::now() + timeout;
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == ErrorKind::NotFound => return CodexVersionEvidence::Missing,
        Err(_) => return CodexVersionEvidence::Unavailable,
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return CodexVersionEvidence::Unavailable;
    };

    // Read at most one byte beyond the accepted limit. Dropping the pipe at
    // that point prevents an unexpected executable from filling memory with
    // arbitrary output. Stderr is discarded at the process boundary.
    let (sender, receiver) = mpsc::channel();
    let _reader = thread::spawn(move || {
        let mut output = Vec::with_capacity(VERSION_OUTPUT_LIMIT as usize);
        let output = stdout
            .take(VERSION_OUTPUT_LIMIT)
            .read_to_end(&mut output)
            .map(|_| output);
        let _ = sender.send(output);
    });

    let Some(status) = wait_for_child(&mut child, deadline) else {
        let _ = child.kill();
        let _ = child.wait();
        return CodexVersionEvidence::Unavailable;
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let Ok(Ok(output)) = receiver.recv_timeout(remaining) else {
        return CodexVersionEvidence::Unavailable;
    };

    if !status.success() {
        return CodexVersionEvidence::Unavailable;
    }

    parse_codex_version_output(&output)
}

fn wait_for_child(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(VERSION_PROBE_POLL_INTERVAL),
            Ok(None) | Err(_) => return None,
        }
    }
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
mod tests {
    use super::*;

    const INCOMPLETE_PROOF_STATES: [LiveProofStatus; 3] = [
        LiveProofStatus::NotRequired,
        LiveProofStatus::NotObserved,
        LiveProofStatus::Failed,
    ];
    const NON_STABLE_SURFACES: [EvidenceSurface; 3] = [
        EvidenceSurface::Experimental,
        EvidenceSurface::Undocumented,
        EvidenceSurface::Absent,
    ];

    #[test]
    fn exact_candidate_with_complete_proof_supports_macos_and_windows() {
        for platform in [HostPlatform::Macos, HostPlatform::Windows] {
            let verdict = evaluate_phase0_support(fully_proven_evidence(platform));

            assert_eq!(
                verdict,
                Phase0SupportVerdict::Supported {
                    codex_version: REQUIRED_CODEX_VERSION,
                    host_platform: platform,
                }
            );
        }
    }

    #[test]
    fn every_other_codex_version_is_blocked_at_the_handshake_gate() {
        for detected_version in [
            CodexVersion::new(0, 143, 9),
            CodexVersion::new(0, 144, 1),
            CodexVersion::new(0, 145, 0),
            CodexVersion::new(1, 0, 0),
        ] {
            let mut evidence = fully_proven_evidence(HostPlatform::Windows);
            evidence.codex_version = CodexVersionEvidence::Detected {
                version: detected_version,
            };

            assert_eq!(
                blockers(evaluate_phase0_support(evidence)),
                vec![Phase0CapabilityBlocker {
                    reason: BlockerReason::UnsupportedCodexVersion,
                    capability: RequiredCapability::Handshake,
                    codex_version: CodexVersionEvidence::Detected {
                        version: detected_version,
                    },
                    host_platform: HostPlatform::Windows,
                    observed_surface: EvidenceSurface::Stable,
                    live_proof: LiveProofStatus::NotRequired,
                }]
            );
        }
    }

    #[test]
    fn every_non_host_platform_is_blocked_at_native_readiness() {
        for platform in [HostPlatform::Linux, HostPlatform::Other] {
            let evidence = fully_proven_evidence(platform);

            assert_eq!(
                blockers(evaluate_phase0_support(evidence)),
                vec![Phase0CapabilityBlocker {
                    reason: BlockerReason::UnsupportedHostPlatform,
                    capability: RequiredCapability::NativeReadiness,
                    codex_version: CodexVersionEvidence::Detected {
                        version: REQUIRED_CODEX_VERSION,
                    },
                    host_platform: platform,
                    observed_surface: EvidenceSurface::Stable,
                    live_proof: LiveProofStatus::Passed,
                }]
            );
        }
    }

    #[test]
    fn every_required_capability_rejects_every_non_stable_surface() {
        for capability in REQUIRED_CAPABILITIES {
            for surface in NON_STABLE_SURFACES {
                let mut evidence = fully_proven_evidence(HostPlatform::Macos);
                evidence_mut(&mut evidence.capabilities, capability).surface = surface;

                assert_eq!(
                    blockers(evaluate_phase0_support(evidence)),
                    vec![Phase0CapabilityBlocker {
                        reason: BlockerReason::NonStableSurface,
                        capability,
                        codex_version: CodexVersionEvidence::Detected {
                            version: REQUIRED_CODEX_VERSION,
                        },
                        host_platform: HostPlatform::Macos,
                        observed_surface: surface,
                        live_proof: if capability.requires_live_proof() {
                            LiveProofStatus::Passed
                        } else {
                            LiveProofStatus::NotRequired
                        },
                    }],
                    "{capability:?} unexpectedly accepted {surface:?} evidence"
                );
            }
        }
    }

    #[test]
    fn every_live_proof_capability_rejects_every_incomplete_proof_state() {
        for capability in REQUIRED_CAPABILITIES
            .into_iter()
            .filter(|capability| capability.requires_live_proof())
        {
            for proof_status in INCOMPLETE_PROOF_STATES {
                let mut evidence = fully_proven_evidence(HostPlatform::Windows);
                evidence_mut(&mut evidence.capabilities, capability).live_proof = proof_status;

                assert_eq!(
                    blockers(evaluate_phase0_support(evidence)),
                    vec![Phase0CapabilityBlocker {
                        reason: BlockerReason::IncompleteLiveProof,
                        capability,
                        codex_version: CodexVersionEvidence::Detected {
                            version: REQUIRED_CODEX_VERSION,
                        },
                        host_platform: HostPlatform::Windows,
                        observed_surface: EvidenceSurface::Stable,
                        live_proof: proof_status,
                    }],
                    "{capability:?} unexpectedly accepted {proof_status:?} proof"
                );
            }
        }
    }

    #[test]
    fn all_blocker_classes_are_reported_together_without_claiming_support() {
        let mut evidence = fully_proven_evidence(HostPlatform::Linux);
        evidence.codex_version = CodexVersionEvidence::Detected {
            version: CodexVersion::new(0, 145, 0),
        };
        evidence.capabilities.approval_observation.surface = EvidenceSurface::Absent;
        evidence.capabilities.approval_observation.live_proof = LiveProofStatus::NotObserved;

        let blockers = blockers(evaluate_phase0_support(evidence));

        assert_eq!(blockers.len(), 4);
        assert!(
            blockers
                .iter()
                .any(|blocker| { blocker.reason == BlockerReason::UnsupportedCodexVersion })
        );
        assert!(
            blockers
                .iter()
                .any(|blocker| { blocker.reason == BlockerReason::UnsupportedHostPlatform })
        );
        assert!(
            blockers
                .iter()
                .any(|blocker| blocker.reason == BlockerReason::NonStableSurface)
        );
        assert!(
            blockers
                .iter()
                .any(|blocker| { blocker.reason == BlockerReason::IncompleteLiveProof })
        );
    }

    #[test]
    fn serialized_blockers_have_a_closed_diagnostic_shape() {
        let mut evidence = fully_proven_evidence(HostPlatform::Linux);
        evidence.capabilities.native_harmless_action.surface = EvidenceSurface::Undocumented;
        evidence.capabilities.native_harmless_action.live_proof = LiveProofStatus::Failed;

        let verdict = evaluate_phase0_support(evidence);
        let serialized = serde_json::to_string(&verdict).expect("verdict must serialize");

        assert!(!serialized.contains("terminal"));
        assert!(!serialized.contains("gui"));
        assert!(!serialized.contains("method"));

        let value = serde_json::to_value(&verdict).expect("verdict must serialize as JSON");
        assert_eq!(value["status"], "blocked");
        let blocker = value["blockers"][0]
            .as_object()
            .expect("blocked verdict must contain typed blocker objects");
        let mut keys: Vec<_> = blocker.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            vec![
                "capability",
                "codex_version",
                "host_platform",
                "live_proof",
                "observed_surface",
                "reason",
            ],
            keys
        );
    }

    fn fully_proven_evidence(host_platform: HostPlatform) -> Phase0CapabilityEvidence {
        let stable = CapabilityEvidence::new(EvidenceSurface::Stable, LiveProofStatus::NotRequired);
        let proven = CapabilityEvidence::new(EvidenceSurface::Stable, LiveProofStatus::Passed);

        Phase0CapabilityEvidence {
            codex_version: CodexVersionEvidence::Detected {
                version: REQUIRED_CODEX_VERSION,
            },
            host_platform,
            capabilities: CapabilityMatrix {
                handshake: stable,
                session_thread_creation: stable,
                turn_start: stable,
                lifecycle_events: stable,
                approval_observation: proven,
                native_readiness: proven,
                native_harmless_action: proven,
                recovery: proven,
                follow_up_turn: proven,
                detached_turn_ownership: proven,
                interrupt_request: stable,
                confirmed_stop: proven,
            },
        }
    }

    fn evidence_mut(
        matrix: &mut CapabilityMatrix,
        capability: RequiredCapability,
    ) -> &mut CapabilityEvidence {
        match capability {
            RequiredCapability::Handshake => &mut matrix.handshake,
            RequiredCapability::SessionThreadCreation => &mut matrix.session_thread_creation,
            RequiredCapability::TurnStart => &mut matrix.turn_start,
            RequiredCapability::LifecycleEvents => &mut matrix.lifecycle_events,
            RequiredCapability::ApprovalObservation => &mut matrix.approval_observation,
            RequiredCapability::NativeReadiness => &mut matrix.native_readiness,
            RequiredCapability::NativeHarmlessAction => &mut matrix.native_harmless_action,
            RequiredCapability::Recovery => &mut matrix.recovery,
            RequiredCapability::FollowUpTurn => &mut matrix.follow_up_turn,
            RequiredCapability::DetachedTurnOwnership => &mut matrix.detached_turn_ownership,
            RequiredCapability::InterruptRequest => &mut matrix.interrupt_request,
            RequiredCapability::ConfirmedStop => &mut matrix.confirmed_stop,
        }
    }

    fn blockers(verdict: Phase0SupportVerdict) -> Vec<Phase0CapabilityBlocker> {
        match verdict {
            Phase0SupportVerdict::Blocked { blockers } => blockers,
            Phase0SupportVerdict::Supported { .. } => {
                panic!("expected a blocked Phase 0 support verdict")
            }
        }
    }

    #[test]
    fn version_probe_parser_accepts_only_the_canonical_codex_cli_line() {
        let expected = CodexVersionEvidence::Detected {
            version: REQUIRED_CODEX_VERSION,
        };
        assert_eq!(parse_codex_version_output(b"codex-cli 0.144.0\n"), expected);
        assert_eq!(
            parse_codex_version_output(b"codex-cli 0.144.0\r\n"),
            expected
        );

        for malformed in [
            b"codex 0.144.0".as_slice(),
            b" codex-cli 0.144.0".as_slice(),
            b"codex-cli 0.144.0 ".as_slice(),
            b"codex-cli 0.144".as_slice(),
            b"codex-cli 00.144.0".as_slice(),
            b"codex-cli 0.0144.0".as_slice(),
            b"codex-cli 0.144.0-beta.1".as_slice(),
            b"codex-cli 0.144.0\nextra".as_slice(),
            b"codex-cli 0.144.0\n\n".as_slice(),
            b"\xff\xfe".as_slice(),
        ] {
            assert_eq!(
                parse_codex_version_output(malformed),
                CodexVersionEvidence::Malformed
            );
        }

        assert_eq!(
            parse_codex_version_output(&[b'x'; VERSION_OUTPUT_LIMIT as usize]),
            CodexVersionEvidence::Malformed
        );
    }

    #[test]
    fn missing_and_malformed_versions_have_distinct_typed_blockers() {
        for (version, expected_reason) in [
            (
                CodexVersionEvidence::Missing,
                BlockerReason::MissingCodexRuntime,
            ),
            (
                CodexVersionEvidence::Malformed,
                BlockerReason::MalformedCodexVersion,
            ),
            (
                CodexVersionEvidence::Unavailable,
                BlockerReason::CodexVersionUnavailable,
            ),
        ] {
            let mut evidence = fully_proven_evidence(HostPlatform::Windows);
            evidence.codex_version = version;

            let blockers = blockers(evaluate_phase0_support(evidence));
            assert_eq!(blockers.len(), 1);
            assert_eq!(blockers[0].reason, expected_reason);
            assert_eq!(blockers[0].codex_version, version);
        }
    }

    #[test]
    fn version_probe_times_out_and_terminates_a_slow_process() {
        let mut command = Command::new(
            std::env::current_exe().expect("the current test executable should be available"),
        );
        command
            .args([
                "--exact",
                "codex_capabilities::tests::slow_version_probe_child",
                "--nocapture",
            ])
            .env("SATELLE_VERSION_PROBE_TEST_CHILD", "slow");
        let started = Instant::now();

        let evidence = probe_codex_version_command(command, Duration::from_millis(50));

        assert_eq!(evidence, CodexVersionEvidence::Unavailable);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the bounded version probe exceeded its termination deadline"
        );
    }

    #[test]
    fn slow_version_probe_child() {
        if std::env::var_os("SATELLE_VERSION_PROBE_TEST_CHILD").as_deref()
            == Some(std::ffi::OsStr::new("slow"))
        {
            thread::sleep(Duration::from_secs(5));
        }
    }
}
