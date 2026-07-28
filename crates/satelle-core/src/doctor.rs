use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

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
            for dependency in &scheduled_probe.definition.dependencies {
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
        })
    }

    /// Marks every currently runnable probe as running, up to the per-Host
    /// bound. The returned order is deterministic; callers may execute the
    /// returned probes concurrently and report completions in any order.
    pub fn start_ready(&mut self) -> Vec<DoctorProbe> {
        self.propagate_dependency_skips();

        let running = self
            .probes
            .values()
            .filter(|probe| probe.state == DoctorProbeState::Running)
            .count();
        let mut remaining_capacity = self.max_concurrency.saturating_sub(running);
        if remaining_capacity == 0 {
            return Vec::new();
        }

        let mut occupied_resources = self
            .probes
            .values()
            .filter(|probe| probe.state == DoctorProbeState::Running)
            .flat_map(|probe| probe.definition.resource_locks.iter().copied())
            .collect::<BTreeSet<_>>();

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
        Ok(())
    }

    pub fn state(&self, probe_id: &str) -> Option<&DoctorProbeState> {
        self.probes.get(probe_id).map(|probe| &probe.state)
    }

    pub fn completion_order(&self) -> &[String] {
        &self.completion_order
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
            self.completion_order.push(probe_id);
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
}
