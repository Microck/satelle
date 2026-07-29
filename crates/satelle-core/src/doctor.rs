use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use thiserror::Error;

/// One Doctor command owns one scheduler for one target Host. Keeping the
/// bound here makes the default concurrency contract independent of output
/// order and of the executor used by the Host.
/// Closed blocker classes that Doctor may report when an authoritative probe
/// has observed the corresponding condition.
///
/// Defining a class here does not imply that every runtime can currently
/// detect it. Callers must omit a class when they lack a typed observation
/// from the subsystem that owns that condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorReadinessBlocker {
    CodexRuntimeMissing,
    ComputerUsePluginMissing,
    OsPermissionRequired,
    AppApprovalRequired,
    AuthenticationRequired,
    UnsupportedOperatingSystem,
    UnsupportedRegion,
}

impl DoctorReadinessBlocker {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodexRuntimeMissing => "codex-runtime-missing",
            Self::ComputerUsePluginMissing => "computer-use-plugin-missing",
            Self::OsPermissionRequired => "os-permission-required",
            Self::AppApprovalRequired => "app-approval-required",
            Self::AuthenticationRequired => "authentication-required",
            Self::UnsupportedOperatingSystem => "unsupported-operating-system",
            Self::UnsupportedRegion => "unsupported-region",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum DoctorScope {
    Codex,
    ComputerUse,
    Config,
    Provider,
    Transport,
}

impl DoctorScope {
    pub const ALL: [Self; 5] = [
        Self::Codex,
        Self::ComputerUse,
        Self::Config,
        Self::Provider,
        Self::Transport,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ComputerUse => "computer-use",
            Self::Config => "config",
            Self::Provider => "provider",
            Self::Transport => "transport",
        }
    }

    pub const fn supports_refresh(self) -> bool {
        matches!(self, Self::ComputerUse | Self::Provider)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorScopeSelectionError {
    UnsupportedScope(String),
    AllWithSpecificScopes(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorScopeSelection {
    scopes: Vec<DoctorScope>,
}

impl DoctorScopeSelection {
    pub fn parse(raw_scopes: &[String]) -> Result<Self, DoctorScopeSelectionError> {
        let mut includes_all = false;
        let mut specific_scopes = Vec::new();

        for raw_scope in raw_scopes {
            let scope = match raw_scope.as_str() {
                "all" => {
                    includes_all = true;
                    continue;
                }
                "codex" => DoctorScope::Codex,
                "computer-use" => DoctorScope::ComputerUse,
                "config" => DoctorScope::Config,
                "provider" => DoctorScope::Provider,
                "transport" => DoctorScope::Transport,
                unsupported => {
                    return Err(DoctorScopeSelectionError::UnsupportedScope(
                        unsupported.to_string(),
                    ));
                }
            };
            if !specific_scopes.contains(&scope) {
                specific_scopes.push(scope);
            }
        }

        if includes_all && !specific_scopes.is_empty() {
            return Err(DoctorScopeSelectionError::AllWithSpecificScopes(
                raw_scopes.to_vec(),
            ));
        }

        let scopes = if raw_scopes.is_empty() || includes_all {
            DoctorScope::ALL.to_vec()
        } else {
            DoctorScope::ALL
                .into_iter()
                .filter(|scope| specific_scopes.contains(scope))
                .collect()
        };
        Ok(Self { scopes })
    }

    pub fn scopes(&self) -> &[DoctorScope] {
        &self.scopes
    }

    pub fn contains(&self, scope: DoctorScope) -> bool {
        self.scopes.contains(&scope)
    }

    pub fn supports_refresh(&self) -> bool {
        self.scopes.iter().any(|scope| scope.supports_refresh())
    }
}

pub const DEFAULT_DOCTOR_PROBE_CONCURRENCY: usize = 4;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DoctorProbeResource {
    NativeComputerUse,
    VisibleDesktop,
    ProviderProbeSurface,
    ReadinessCacheWrite,
    RemoteServiceManager,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorProbeCachePolicy {
    Reuse,
    RefreshWhenRequested,
    Never,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorProbe {
    pub probe_id: String,
    pub scope: String,
    pub dependencies: Vec<String>,
    pub resource_locks: BTreeSet<DoctorProbeResource>,
    pub timeout: Duration,
    pub cache_policy: DoctorProbeCachePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorProbeStatus {
    Passed,
    Finding,
    Failed,
    TimedOut,
}

/// Probe status and dependency usefulness are separate. A failed or timed-out
/// prerequisite can still leave useful evidence for a dependent probe, while
/// an otherwise successful prerequisite can prove that the dependent has no
/// useful work to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorDependentEvidence {
    Useful,
    NotUseful,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoctorProbeCompletion {
    pub status: DoctorProbeStatus,
    pub dependent_evidence: DoctorDependentEvidence,
}

impl DoctorProbeCompletion {
    pub const fn new(
        status: DoctorProbeStatus,
        dependent_evidence: DoctorDependentEvidence,
    ) -> Self {
        Self {
            status,
            dependent_evidence,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DoctorProbeExecutionContext {
    deadline: Instant,
    cleanup_deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl DoctorProbeExecutionContext {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn cleanup_deadline(&self) -> Instant {
        self.cleanup_deadline
    }

    pub fn cleanup_remaining(&self) -> Duration {
        self.cleanup_deadline
            .saturating_duration_since(Instant::now())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorProbeExecutionRecord {
    pub probe_id: String,
    pub status: DoctorProbeStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorProbeScheduleEvent {
    Started { probe_id: String },
    Finished { probe_id: String },
}

impl DoctorProbeScheduleEvent {
    pub fn probe_id(&self) -> &str {
        match self {
            Self::Started { probe_id } | Self::Finished { probe_id } => probe_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DoctorProbeState {
    Pending,
    Running,
    Finished(DoctorProbeCompletion),
    SkippedDependency { blocking_probe_id: String },
}

#[derive(Clone, Debug)]
struct ScheduledProbe {
    definition: DoctorProbe,
    state: DoctorProbeState,
}

#[derive(Clone, Debug)]
pub struct DoctorProbeScheduler {
    probes: BTreeMap<String, ScheduledProbe>,
    max_concurrency: usize,
    completion_order: Vec<String>,
    schedule_events: Vec<DoctorProbeScheduleEvent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DoctorProbeLifecyclePhase {
    Running,
    Cancelling,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DoctorProbeLifecycleEvent {
    Running,
    BeginCancellation,
    TerminalAck(DoctorProbeCompletion),
}

/// Core-owned timing state for one concrete Doctor operation.
///
/// The lifecycle never calls caller-provided behavior. Host and CLI own their
/// resources and feed only nonblocking terminal observations into `poll`.
#[derive(Debug)]
pub struct DoctorProbeLifecycle {
    probe_id: String,
    deadline: Instant,
    cancel_at: Instant,
    context: DoctorProbeExecutionContext,
    phase: DoctorProbeLifecyclePhase,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DoctorProbeExecutionError {
    #[error("Doctor probe {probe_id} timeout cannot be represented as an absolute deadline")]
    DeadlineOverflow { probe_id: String },
    #[error("Doctor probe {probe_id} did not acknowledge terminal cleanup by its deadline")]
    CleanupDeadlineMissed { probe_id: String },
    #[error("Doctor probe {probe_id} already reached a terminal acknowledgment")]
    AlreadyTerminal { probe_id: String },
}

impl DoctorProbeLifecycle {
    pub fn start(
        probe_id: impl Into<String>,
        started_at: Instant,
        timeout: Duration,
        cleanup_reserve: Duration,
    ) -> Result<Self, DoctorProbeExecutionError> {
        let probe_id = probe_id.into();
        let deadline = started_at.checked_add(timeout).ok_or_else(|| {
            DoctorProbeExecutionError::DeadlineOverflow {
                probe_id: probe_id.clone(),
            }
        })?;
        let cleanup_reserve = cleanup_reserve.min(timeout);
        let cancel_at = deadline
            .checked_sub(cleanup_reserve)
            .expect("a reserve clamped to the timeout fits before its deadline");
        let cancelled = Arc::new(AtomicBool::new(false));
        Ok(Self {
            probe_id,
            deadline,
            cancel_at,
            context: DoctorProbeExecutionContext {
                // Useful work ends at cancel_at. The remaining interval is
                // reserved for task-owned cleanup before the hard deadline.
                deadline: cancel_at,
                cleanup_deadline: deadline,
                cancelled,
            },
            phase: DoctorProbeLifecyclePhase::Running,
        })
    }

    pub fn context(&self) -> DoctorProbeExecutionContext {
        self.context.clone()
    }

    pub fn cancel_at(&self) -> Instant {
        self.cancel_at
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn request_cancellation(&mut self) {
        if self.phase == DoctorProbeLifecyclePhase::Running {
            self.phase = DoctorProbeLifecyclePhase::Cancelling;
            self.context.cancelled.store(true, Ordering::Release);
        }
    }

    pub fn poll(
        &mut self,
        now: Instant,
        terminal_ack: Option<(Instant, DoctorProbeCompletion)>,
    ) -> Result<DoctorProbeLifecycleEvent, DoctorProbeExecutionError> {
        if self.phase == DoctorProbeLifecyclePhase::Terminal {
            return Err(DoctorProbeExecutionError::AlreadyTerminal {
                probe_id: self.probe_id.clone(),
            });
        }
        if let Some((completed_at, completion)) = terminal_ack {
            let completion = if completed_at >= self.cancel_at {
                DoctorProbeCompletion::new(
                    DoctorProbeStatus::TimedOut,
                    DoctorDependentEvidence::NotUseful,
                )
            } else {
                completion
            };
            self.phase = DoctorProbeLifecyclePhase::Terminal;
            return Ok(DoctorProbeLifecycleEvent::TerminalAck(completion));
        }

        match self.phase {
            DoctorProbeLifecyclePhase::Running if now >= self.deadline => {
                self.phase = DoctorProbeLifecyclePhase::Cancelling;
                self.context.cancelled.store(true, Ordering::Release);
                Err(DoctorProbeExecutionError::CleanupDeadlineMissed {
                    probe_id: self.probe_id.clone(),
                })
            }
            DoctorProbeLifecyclePhase::Running if now >= self.cancel_at => {
                self.phase = DoctorProbeLifecyclePhase::Cancelling;
                self.context.cancelled.store(true, Ordering::Release);
                Ok(DoctorProbeLifecycleEvent::BeginCancellation)
            }
            DoctorProbeLifecyclePhase::Cancelling if now >= self.deadline => {
                Err(DoctorProbeExecutionError::CleanupDeadlineMissed {
                    probe_id: self.probe_id.clone(),
                })
            }
            DoctorProbeLifecyclePhase::Running | DoctorProbeLifecyclePhase::Cancelling => {
                Ok(DoctorProbeLifecycleEvent::Running)
            }
            DoctorProbeLifecyclePhase::Terminal => unreachable!("terminal polls return above"),
        }
    }
}

impl DoctorProbeScheduler {
    pub fn new(probes: Vec<DoctorProbe>) -> Result<Self, DoctorProbeScheduleError> {
        Self::with_concurrency(probes, DEFAULT_DOCTOR_PROBE_CONCURRENCY)
    }

    pub fn serial(probes: Vec<DoctorProbe>) -> Result<Self, DoctorProbeScheduleError> {
        Self::with_concurrency(probes, 1)
    }

    fn with_concurrency(
        probes: Vec<DoctorProbe>,
        max_concurrency: usize,
    ) -> Result<Self, DoctorProbeScheduleError> {
        if !(1..=DEFAULT_DOCTOR_PROBE_CONCURRENCY).contains(&max_concurrency) {
            return Err(DoctorProbeScheduleError::InvalidConcurrency {
                value: max_concurrency,
            });
        }

        let mut scheduled = BTreeMap::new();
        for probe in probes {
            if probe.probe_id.is_empty() {
                return Err(DoctorProbeScheduleError::EmptyProbeId);
            }
            if probe.scope.is_empty() {
                return Err(DoctorProbeScheduleError::EmptyProbeScope {
                    probe_id: probe.probe_id,
                });
            }
            if probe.timeout.is_zero() {
                return Err(DoctorProbeScheduleError::ZeroTimeout {
                    probe_id: probe.probe_id,
                });
            }
            let probe_id = probe.probe_id.clone();
            if scheduled
                .insert(
                    probe_id.clone(),
                    ScheduledProbe {
                        definition: probe,
                        state: DoctorProbeState::Pending,
                    },
                )
                .is_some()
            {
                return Err(DoctorProbeScheduleError::DuplicateProbeId { probe_id });
            }
        }

        for scheduled_probe in scheduled.values() {
            let mut unique_dependencies = BTreeSet::new();
            for dependency in &scheduled_probe.definition.dependencies {
                if !unique_dependencies.insert(dependency) {
                    return Err(DoctorProbeScheduleError::DuplicateDependency {
                        probe_id: scheduled_probe.definition.probe_id.clone(),
                        dependency: dependency.clone(),
                    });
                }
                if !scheduled.contains_key(dependency) {
                    return Err(DoctorProbeScheduleError::UnknownDependency {
                        probe_id: scheduled_probe.definition.probe_id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        validate_acyclic(&scheduled)?;

        Ok(Self {
            probes: scheduled,
            max_concurrency,
            completion_order: Vec::new(),
            schedule_events: Vec::new(),
        })
    }

    /// Marks every currently runnable probe as running, up to the per-Host
    /// bound. The returned order is deterministic; callers may execute the
    /// returned probes concurrently and report completions in any order.
    pub fn start_ready(&mut self) -> Vec<DoctorProbe> {
        self.start_ready_with_external_occupancy(0, &BTreeSet::new())
    }

    pub fn start_ready_with_external_occupancy(
        &mut self,
        external_capacity: usize,
        external_resources: &BTreeSet<DoctorProbeResource>,
    ) -> Vec<DoctorProbe> {
        self.propagate_dependency_skips();

        let running = self
            .probes
            .values()
            .filter(|probe| probe.state == DoctorProbeState::Running)
            .count();
        let mut remaining_capacity = self
            .max_concurrency
            .saturating_sub(running.saturating_add(external_capacity));
        if remaining_capacity == 0 {
            return Vec::new();
        }

        let mut occupied_resources = external_resources.clone();
        occupied_resources.extend(
            self.probes
                .values()
                .filter(|probe| probe.state == DoctorProbeState::Running)
                .flat_map(|probe| probe.definition.resource_locks.iter().copied()),
        );

        let mut candidates = self
            .probes
            .values()
            .filter(|probe| probe.state == DoctorProbeState::Pending)
            .filter(|probe| {
                probe.definition.dependencies.iter().all(|dependency| {
                    matches!(
                        self.probes.get(dependency).map(|probe| &probe.state),
                        Some(DoctorProbeState::Finished(DoctorProbeCompletion {
                            dependent_evidence: DoctorDependentEvidence::Useful,
                            ..
                        }))
                    )
                })
            })
            .map(|probe| {
                (
                    probe.definition.scope.clone(),
                    probe.definition.probe_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        candidates.sort();

        let mut started = Vec::new();
        for (_, probe_id) in candidates {
            if remaining_capacity == 0 {
                break;
            }
            let definition = &self
                .probes
                .get(&probe_id)
                .expect("candidate probe must exist")
                .definition;
            if !definition.resource_locks.is_disjoint(&occupied_resources) {
                continue;
            }

            occupied_resources.extend(definition.resource_locks.iter().copied());
            let scheduled_probe = self
                .probes
                .get_mut(&probe_id)
                .expect("candidate probe must remain present");
            scheduled_probe.state = DoctorProbeState::Running;
            started.push(scheduled_probe.definition.clone());
            self.schedule_events
                .push(DoctorProbeScheduleEvent::Started { probe_id });
            remaining_capacity -= 1;
        }
        started
    }

    pub fn finish(
        &mut self,
        probe_id: &str,
        completion: DoctorProbeCompletion,
    ) -> Result<(), DoctorProbeScheduleError> {
        let probe = self.probes.get_mut(probe_id).ok_or_else(|| {
            DoctorProbeScheduleError::UnknownProbe {
                probe_id: probe_id.to_string(),
            }
        })?;
        if probe.state != DoctorProbeState::Running {
            return Err(DoctorProbeScheduleError::ProbeNotRunning {
                probe_id: probe_id.to_string(),
            });
        }
        probe.state = DoctorProbeState::Finished(completion);
        self.completion_order.push(probe_id.to_string());
        self.schedule_events
            .push(DoctorProbeScheduleEvent::Finished {
                probe_id: probe_id.to_string(),
            });
        Ok(())
    }

    pub fn state(&self, probe_id: &str) -> Option<&DoctorProbeState> {
        self.probes.get(probe_id).map(|probe| &probe.state)
    }

    pub fn completion_order(&self) -> &[String] {
        &self.completion_order
    }

    pub fn schedule_events(&self) -> &[DoctorProbeScheduleEvent] {
        &self.schedule_events
    }

    pub fn final_order(&self) -> Vec<String> {
        let mut probes = self
            .probes
            .values()
            .map(|probe| {
                (
                    probe.definition.scope.clone(),
                    probe.definition.probe_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        probes.sort();
        probes.into_iter().map(|(_, probe_id)| probe_id).collect()
    }

    pub fn is_complete(&self) -> bool {
        self.probes.values().all(|probe| {
            matches!(
                probe.state,
                DoctorProbeState::Finished(_) | DoctorProbeState::SkippedDependency { .. }
            )
        })
    }

    fn propagate_dependency_skips(&mut self) {
        loop {
            let skip = self
                .probes
                .values()
                .filter(|probe| probe.state == DoctorProbeState::Pending)
                .find_map(|probe| {
                    probe.definition.dependencies.iter().find_map(|dependency| {
                        let dependency_state = &self
                            .probes
                            .get(dependency)
                            .expect("dependencies are validated")
                            .state;
                        matches!(
                            dependency_state,
                            DoctorProbeState::Finished(DoctorProbeCompletion {
                                dependent_evidence: DoctorDependentEvidence::NotUseful,
                                ..
                            }) | DoctorProbeState::SkippedDependency { .. }
                        )
                        .then(|| (probe.definition.probe_id.clone(), dependency.clone()))
                    })
                });

            let Some((probe_id, blocking_probe_id)) = skip else {
                break;
            };
            self.probes
                .get_mut(&probe_id)
                .expect("pending probe must remain present")
                .state = DoctorProbeState::SkippedDependency { blocking_probe_id };
            self.completion_order.push(probe_id.clone());
            self.schedule_events
                .push(DoctorProbeScheduleEvent::Finished { probe_id });
        }
    }
}

fn validate_acyclic(
    probes: &BTreeMap<String, ScheduledProbe>,
) -> Result<(), DoctorProbeScheduleError> {
    let mut remaining_dependencies = probes
        .iter()
        .map(|(probe_id, probe)| (probe_id.clone(), probe.definition.dependencies.len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = remaining_dependencies
        .iter()
        .filter_map(|(probe_id, count)| (*count == 0).then_some(probe_id.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0;

    while let Some(completed) = ready.pop_front() {
        visited += 1;
        for (probe_id, probe) in probes {
            if !probe.definition.dependencies.contains(&completed) {
                continue;
            }
            let remaining = remaining_dependencies
                .get_mut(probe_id)
                .expect("every probe has an indegree");
            *remaining -= 1;
            if *remaining == 0 {
                ready.push_back(probe_id.clone());
            }
        }
    }

    if visited == probes.len() {
        Ok(())
    } else {
        Err(DoctorProbeScheduleError::DependencyCycle)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DoctorProbeScheduleError {
    #[error("doctor probe id must not be empty")]
    EmptyProbeId,
    #[error("doctor probe '{probe_id}' scope must not be empty")]
    EmptyProbeScope { probe_id: String },
    #[error("doctor probe '{probe_id}' timeout must be greater than zero")]
    ZeroTimeout { probe_id: String },
    #[error("doctor probe id '{probe_id}' is duplicated")]
    DuplicateProbeId { probe_id: String },
    #[error("doctor probe '{probe_id}' repeats dependency '{dependency}'")]
    DuplicateDependency {
        probe_id: String,
        dependency: String,
    },
    #[error("doctor probe '{probe_id}' depends on unknown probe '{dependency}'")]
    UnknownDependency {
        probe_id: String,
        dependency: String,
    },
    #[error("doctor probe dependency graph contains a cycle")]
    DependencyCycle,
    #[error("doctor probe concurrency must be between 1 and 4, got {value}")]
    InvalidConcurrency { value: usize },
    #[error("doctor probe '{probe_id}' is unknown")]
    UnknownProbe { probe_id: String },
    #[error("doctor probe '{probe_id}' is not running")]
    ProbeNotRunning { probe_id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_blocker_taxonomy_has_seven_distinct_closed_tokens() {
        let blockers = [
            DoctorReadinessBlocker::CodexRuntimeMissing,
            DoctorReadinessBlocker::ComputerUsePluginMissing,
            DoctorReadinessBlocker::OsPermissionRequired,
            DoctorReadinessBlocker::AppApprovalRequired,
            DoctorReadinessBlocker::AuthenticationRequired,
            DoctorReadinessBlocker::UnsupportedOperatingSystem,
            DoctorReadinessBlocker::UnsupportedRegion,
        ];

        assert_eq!(
            blockers.map(|blocker| serde_json::to_value(blocker).unwrap()),
            [
                serde_json::json!("codex-runtime-missing"),
                serde_json::json!("computer-use-plugin-missing"),
                serde_json::json!("os-permission-required"),
                serde_json::json!("app-approval-required"),
                serde_json::json!("authentication-required"),
                serde_json::json!("unsupported-operating-system"),
                serde_json::json!("unsupported-region"),
            ]
        );
    }

    #[test]
    fn omitted_and_explicit_all_scopes_select_the_same_deterministic_set() {
        let omitted = DoctorScopeSelection::parse(&[]).unwrap();
        let explicit = DoctorScopeSelection::parse(&["all".to_string()]).unwrap();

        assert_eq!(omitted, explicit);
        assert_eq!(omitted.scopes(), DoctorScope::ALL);
        assert!(omitted.supports_refresh());
    }

    #[test]
    fn specific_scopes_are_deduplicated_and_canonically_ordered() {
        let selection = DoctorScopeSelection::parse(&[
            "provider".to_string(),
            "codex".to_string(),
            "provider".to_string(),
        ])
        .unwrap();

        assert_eq!(
            selection.scopes(),
            [DoctorScope::Codex, DoctorScope::Provider]
        );
        assert!(selection.contains(DoctorScope::Provider));
    }

    #[test]
    fn all_with_a_specific_scope_is_a_typed_conflict() {
        let raw_scopes = vec!["provider".to_string(), "all".to_string()];

        assert_eq!(
            DoctorScopeSelection::parse(&raw_scopes),
            Err(DoctorScopeSelectionError::AllWithSpecificScopes(raw_scopes))
        );
    }

    #[test]
    fn unsupported_scope_remains_distinct_from_selection_conflict() {
        assert_eq!(
            DoctorScopeSelection::parse(&["database".to_string()]),
            Err(DoctorScopeSelectionError::UnsupportedScope(
                "database".to_string()
            ))
        );
    }

    fn probe(
        probe_id: &str,
        scope: &str,
        dependencies: &[&str],
        resources: &[DoctorProbeResource],
    ) -> DoctorProbe {
        DoctorProbe {
            probe_id: probe_id.to_string(),
            scope: scope.to_string(),
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).to_string())
                .collect(),
            resource_locks: resources.iter().copied().collect(),
            timeout: Duration::from_secs(1),
            cache_policy: DoctorProbeCachePolicy::Reuse,
        }
    }

    fn useful(status: DoctorProbeStatus) -> DoctorProbeCompletion {
        DoctorProbeCompletion::new(status, DoctorDependentEvidence::Useful)
    }

    #[test]
    fn default_scheduler_starts_at_most_four_independent_probes() {
        let probes = (0..5)
            .map(|index| probe(&format!("probe-{index}"), "config", &[], &[]))
            .collect();
        let mut scheduler = DoctorProbeScheduler::new(probes).expect("valid graph");

        let started = scheduler.start_ready();

        assert_eq!(started.len(), DEFAULT_DOCTOR_PROBE_CONCURRENCY);
        assert_eq!(
            started
                .iter()
                .map(|probe| probe.probe_id.as_str())
                .collect::<Vec<_>>(),
            ["probe-0", "probe-1", "probe-2", "probe-3"]
        );
    }

    #[test]
    fn dependencies_and_shared_resources_gate_probe_start() {
        let mut scheduler = DoctorProbeScheduler::new(vec![
            probe("transport", "transport", &[], &[]),
            probe(
                "native",
                "computer-use",
                &["transport"],
                &[DoctorProbeResource::NativeComputerUse],
            ),
            probe(
                "desktop",
                "computer-use",
                &["transport"],
                &[DoctorProbeResource::NativeComputerUse],
            ),
        ])
        .expect("valid graph");

        assert_eq!(scheduler.start_ready()[0].probe_id, "transport");
        assert!(scheduler.start_ready().is_empty());
        scheduler
            .finish("transport", useful(DoctorProbeStatus::Passed))
            .expect("transport is running");

        let first_locked = scheduler.start_ready();
        assert_eq!(first_locked.len(), 1);
        assert_eq!(first_locked[0].probe_id, "desktop");
        scheduler
            .finish("desktop", useful(DoctorProbeStatus::Passed))
            .expect("desktop is running");
        assert_eq!(scheduler.start_ready()[0].probe_id, "native");
    }

    #[test]
    fn unusable_dependency_skips_only_its_dependents() {
        let mut scheduler = DoctorProbeScheduler::new(vec![
            probe("prerequisite", "codex", &[], &[]),
            probe("dependent", "provider", &["prerequisite"], &[]),
            probe("independent", "config", &[], &[]),
        ])
        .expect("valid graph");

        let started = scheduler.start_ready();
        assert_eq!(
            started
                .iter()
                .map(|probe| probe.probe_id.as_str())
                .collect::<Vec<_>>(),
            ["prerequisite", "independent"]
        );
        scheduler
            .finish(
                "prerequisite",
                DoctorProbeCompletion::new(
                    DoctorProbeStatus::Finding,
                    DoctorDependentEvidence::NotUseful,
                ),
            )
            .expect("prerequisite is running");
        scheduler
            .finish("independent", useful(DoctorProbeStatus::TimedOut))
            .expect("independent probe is running");

        assert!(scheduler.start_ready().is_empty());
        assert_eq!(
            scheduler.state("dependent"),
            Some(&DoctorProbeState::SkippedDependency {
                blocking_probe_id: "prerequisite".to_string()
            })
        );
        assert!(scheduler.is_complete());
    }

    #[test]
    fn failures_and_timeouts_do_not_cancel_independent_work() {
        let mut scheduler = DoctorProbeScheduler::new(vec![
            probe("failed", "codex", &[], &[]),
            probe("timed-out", "provider", &[], &[]),
            probe("later", "transport", &[], &[]),
        ])
        .expect("valid graph");
        let started = scheduler.start_ready();
        assert_eq!(started.len(), 3);

        scheduler
            .finish("failed", useful(DoctorProbeStatus::Failed))
            .expect("failed probe is running");
        scheduler
            .finish("timed-out", useful(DoctorProbeStatus::TimedOut))
            .expect("timed-out probe is running");
        assert_eq!(scheduler.state("later"), Some(&DoctorProbeState::Running));
    }

    #[test]
    fn completion_order_does_not_change_deterministic_final_order() {
        let mut scheduler = DoctorProbeScheduler::new(vec![
            probe("z-probe", "transport", &[], &[]),
            probe("a-probe", "config", &[], &[]),
        ])
        .expect("valid graph");
        scheduler.start_ready();
        scheduler
            .finish("z-probe", useful(DoctorProbeStatus::Passed))
            .expect("z-probe is running");
        scheduler
            .finish("a-probe", useful(DoctorProbeStatus::Passed))
            .expect("a-probe is running");

        assert_eq!(scheduler.completion_order(), ["z-probe", "a-probe"]);
        assert_eq!(scheduler.final_order(), ["a-probe", "z-probe"]);
    }

    #[test]
    fn schedule_events_preserve_dependency_causality() {
        let mut scheduler = DoctorProbeScheduler::new(vec![
            probe("prerequisite", "config", &[], &[]),
            probe("dependent", "provider", &["prerequisite"], &[]),
        ])
        .expect("valid graph");

        scheduler.start_ready();
        scheduler
            .finish("prerequisite", useful(DoctorProbeStatus::Passed))
            .expect("prerequisite is running");
        scheduler.start_ready();
        scheduler
            .finish("dependent", useful(DoctorProbeStatus::Passed))
            .expect("dependent is running");

        assert_eq!(
            scheduler.schedule_events(),
            [
                DoctorProbeScheduleEvent::Started {
                    probe_id: "prerequisite".to_string()
                },
                DoctorProbeScheduleEvent::Finished {
                    probe_id: "prerequisite".to_string()
                },
                DoctorProbeScheduleEvent::Started {
                    probe_id: "dependent".to_string()
                },
                DoctorProbeScheduleEvent::Finished {
                    probe_id: "dependent".to_string()
                },
            ]
        );
    }

    #[test]
    fn invalid_dependency_graphs_are_rejected_at_the_boundary() {
        let unknown =
            DoctorProbeScheduler::new(vec![probe("provider", "provider", &["missing"], &[])]);
        assert_eq!(
            unknown.unwrap_err(),
            DoctorProbeScheduleError::UnknownDependency {
                probe_id: "provider".to_string(),
                dependency: "missing".to_string(),
            }
        );

        let cycle = DoctorProbeScheduler::new(vec![
            probe("first", "config", &["second"], &[]),
            probe("second", "codex", &["first"], &[]),
        ]);
        assert_eq!(
            cycle.unwrap_err(),
            DoctorProbeScheduleError::DependencyCycle
        );
    }

    #[test]
    fn lifecycle_classifies_terminal_ack_by_worker_completion_time() {
        let started = Instant::now();
        let mut lifecycle = DoctorProbeLifecycle::start(
            "probe",
            started,
            Duration::from_millis(10),
            Duration::from_millis(4),
        )
        .expect("representable deadline");
        let context = lifecycle.context();
        let event = lifecycle
            .poll(
                started + Duration::from_millis(6),
                Some((
                    started + Duration::from_millis(5),
                    DoctorProbeCompletion::new(
                        DoctorProbeStatus::Passed,
                        DoctorDependentEvidence::Useful,
                    ),
                )),
            )
            .expect("terminal acknowledgment is accepted");
        assert_eq!(
            event,
            DoctorProbeLifecycleEvent::TerminalAck(DoctorProbeCompletion::new(
                DoctorProbeStatus::Passed,
                DoctorDependentEvidence::Useful,
            ))
        );
        assert!(!context.is_cancelled());

        let mut delayed_publication = DoctorProbeLifecycle::start(
            "delayed-publication",
            started,
            Duration::from_millis(10),
            Duration::from_millis(4),
        )
        .expect("representable deadline");
        assert_eq!(
            delayed_publication
                .poll(started + Duration::from_millis(6), None)
                .expect("cancellation begins while publication waits"),
            DoctorProbeLifecycleEvent::BeginCancellation
        );
        assert_eq!(
            delayed_publication
                .poll(
                    started + Duration::from_millis(7),
                    Some((
                        started + Duration::from_millis(5),
                        DoctorProbeCompletion::new(
                            DoctorProbeStatus::Passed,
                            DoctorDependentEvidence::Useful,
                        ),
                    )),
                )
                .expect("completion time outranks publication delay"),
            DoctorProbeLifecycleEvent::TerminalAck(DoctorProbeCompletion::new(
                DoctorProbeStatus::Passed,
                DoctorDependentEvidence::Useful,
            ))
        );

        let mut at_deadline = DoctorProbeLifecycle::start(
            "at-deadline",
            started,
            Duration::from_millis(10),
            Duration::from_millis(4),
        )
        .expect("representable deadline");
        assert_eq!(
            at_deadline
                .poll(
                    started + Duration::from_millis(6),
                    Some((
                        started + Duration::from_millis(6),
                        DoctorProbeCompletion::new(
                            DoctorProbeStatus::Passed,
                            DoctorDependentEvidence::Useful,
                        ),
                    )),
                )
                .expect("deadline completion is a terminal acknowledgment"),
            DoctorProbeLifecycleEvent::TerminalAck(DoctorProbeCompletion::new(
                DoctorProbeStatus::TimedOut,
                DoctorDependentEvidence::NotUseful,
            ))
        );
    }

    #[test]
    fn lifecycle_cancellation_ack_releases_immediately_and_cleanup_miss_is_bounded() {
        let started = Instant::now();
        let mut acknowledged = DoctorProbeLifecycle::start(
            "acknowledged",
            started,
            Duration::from_millis(10),
            Duration::from_millis(4),
        )
        .expect("representable deadline");
        let context = acknowledged.context();
        assert_eq!(
            acknowledged
                .poll(started + Duration::from_millis(6), None)
                .expect("cancellation begins"),
            DoctorProbeLifecycleEvent::BeginCancellation
        );
        assert!(context.is_cancelled());
        assert_eq!(
            acknowledged
                .poll(
                    started + Duration::from_millis(7),
                    Some((
                        started + Duration::from_millis(7),
                        DoctorProbeCompletion::new(
                            DoctorProbeStatus::Passed,
                            DoctorDependentEvidence::Useful,
                        ),
                    )),
                )
                .expect("acknowledgment releases immediately"),
            DoctorProbeLifecycleEvent::TerminalAck(DoctorProbeCompletion::new(
                DoctorProbeStatus::TimedOut,
                DoctorDependentEvidence::NotUseful,
            ))
        );

        let mut missed = DoctorProbeLifecycle::start(
            "missed",
            started,
            Duration::from_millis(10),
            Duration::from_millis(4),
        )
        .expect("representable deadline");
        assert_eq!(
            missed
                .poll(started + Duration::from_millis(6), None)
                .expect("cancellation begins"),
            DoctorProbeLifecycleEvent::BeginCancellation
        );
        assert_eq!(
            missed
                .poll(started + Duration::from_millis(10), None)
                .expect_err("cleanup miss is a bounded typed failure"),
            DoctorProbeExecutionError::CleanupDeadlineMissed {
                probe_id: "missed".to_string(),
            }
        );

        let mut scheduler_delayed = DoctorProbeLifecycle::start(
            "scheduler-delayed",
            started,
            Duration::from_millis(10),
            Duration::from_millis(4),
        )
        .expect("representable deadline");
        assert_eq!(
            scheduler_delayed
                .poll(started + Duration::from_millis(10), None)
                .expect_err("the first late poll is already terminal"),
            DoctorProbeExecutionError::CleanupDeadlineMissed {
                probe_id: "scheduler-delayed".to_string(),
            }
        );
    }

    #[test]
    fn lifecycle_terminal_ack_is_immutable() {
        let started = Instant::now();
        let mut lifecycle = DoctorProbeLifecycle::start(
            "terminal",
            started,
            Duration::from_millis(10),
            Duration::from_millis(2),
        )
        .expect("representable deadline");
        let completion =
            DoctorProbeCompletion::new(DoctorProbeStatus::Passed, DoctorDependentEvidence::Useful);
        assert_eq!(
            lifecycle
                .poll(
                    started + Duration::from_millis(1),
                    Some((started + Duration::from_millis(1), completion)),
                )
                .expect("first terminal acknowledgment"),
            DoctorProbeLifecycleEvent::TerminalAck(completion)
        );

        assert_eq!(
            lifecycle
                .poll(started + Duration::from_millis(2), None)
                .expect_err("terminal lifecycle rejects later polls"),
            DoctorProbeExecutionError::AlreadyTerminal {
                probe_id: "terminal".to_string(),
            }
        );
        assert_eq!(
            lifecycle
                .poll(
                    started + Duration::from_millis(9),
                    Some((
                        started + Duration::from_millis(9),
                        DoctorProbeCompletion::new(
                            DoctorProbeStatus::TimedOut,
                            DoctorDependentEvidence::NotUseful,
                        ),
                    )),
                )
                .expect_err("terminal lifecycle rejects replacement acknowledgment"),
            DoctorProbeExecutionError::AlreadyTerminal {
                probe_id: "terminal".to_string(),
            }
        );
    }

    #[test]
    fn lifecycle_deadline_overflow_is_typed() {
        assert_eq!(
            DoctorProbeLifecycle::start("overflow", Instant::now(), Duration::MAX, Duration::ZERO,)
                .expect_err("overflow must not become an unbounded deadline"),
            DoctorProbeExecutionError::DeadlineOverflow {
                probe_id: "overflow".to_string(),
            }
        );
    }

    #[test]
    fn execution_completes_a_dependency_blocked_frontier_without_running_work() {
        let mut scheduler = DoctorProbeScheduler::new(vec![
            probe("failed", "codex", &[], &[]),
            probe("z-child", "computer-use", &["failed"], &[]),
            probe("a-grandchild", "provider", &["z-child"], &[]),
        ])
        .expect("valid graph");

        let started = scheduler.start_ready();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].probe_id, "failed");
        scheduler
            .finish(
                "failed",
                DoctorProbeCompletion::new(
                    DoctorProbeStatus::Failed,
                    DoctorDependentEvidence::NotUseful,
                ),
            )
            .expect("failed probe is running");
        assert!(scheduler.start_ready().is_empty());

        assert_eq!(
            scheduler.completion_order(),
            ["failed", "z-child", "a-grandchild"]
        );
        assert!(matches!(
            scheduler.state("z-child"),
            Some(DoctorProbeState::SkippedDependency { blocking_probe_id })
                if blocking_probe_id == "failed"
        ));
        assert!(matches!(
            scheduler.state("a-grandchild"),
            Some(DoctorProbeState::SkippedDependency { blocking_probe_id })
                if blocking_probe_id == "z-child"
        ));
        assert!(scheduler.is_complete());
    }

    #[test]
    fn duplicate_dependencies_are_rejected_at_the_scheduler_boundary() {
        assert_eq!(
            DoctorProbeScheduler::new(vec![
                probe("root", "codex", &[], &[]),
                probe("dependent", "computer-use", &["root", "root"], &[]),
            ])
            .unwrap_err(),
            DoctorProbeScheduleError::DuplicateDependency {
                probe_id: "dependent".to_string(),
                dependency: "root".to_string(),
            }
        );
    }
}
