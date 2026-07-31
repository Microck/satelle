use satelle_core::host_update::{
    CodexComponentOwnership, CodexUpdateEvidence, HostUpdateComponent, HostUpdateDisposition,
    HostUpdateMutation, HostUpdateReport, HostUpdateRestartImpact, HostUpdateTarget,
    HostUpdateTargetPlan, HostUpdateVersionSource, RepairCompatibilityReason, RepairUpgradeAction,
    RepairUpgradeDisposition, RepairUpgradeReport,
};
use std::collections::BTreeSet;
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostVersionRelation {
    Missing,
    OlderThanCli,
    MatchesCli,
    NewerThanCli,
    RequiresNewerCli,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostUpdateInspection {
    pub current_version: Option<String>,
    pub relation_to_cli: HostVersionRelation,
    pub remote_platform: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostUpdateServiceInspection {
    pub current_version: Option<String>,
    pub relation_to_cli: HostVersionRelation,
    pub destination: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedHostArtifact {
    pub version: String,
    pub remote_platform: String,
    pub daemon_destination: Option<String>,
}

/// T4 owns artifact discovery and target-matrix policy. T1 consumes only a
/// verified artifact for the exact invoking CLI version and remote platform.
pub trait VerifiedHostArtifactResolver {
    fn resolve_exact_cli_artifact(
        &self,
        cli_version: &str,
        remote_platform: &str,
    ) -> Result<Option<VerifiedHostArtifact>, HostUpdatePlanError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexUpdateInspection {
    pub target: HostUpdateTarget,
    pub ownership: CodexComponentOwnership,
    pub current_version: Option<String>,
    pub target_version: String,
    pub update_required: bool,
    pub restart_impact: HostUpdateRestartImpact,
    pub remote_mutations: Vec<HostUpdateMutation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairUpgradeInspection {
    pub target: HostUpdateTarget,
    pub current_version: Option<String>,
    pub target_version: String,
    pub compatibility_reason: Option<RepairCompatibilityReason>,
    pub version_source: HostUpdateVersionSource,
    pub automation_is_safe: bool,
    pub newer_compatible_version_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostUpdatePlanError {
    ComponentSelectionConflict,
    HostBinaryNewerThanCli {
        host_version: String,
        cli_version: String,
    },
    HostArtifactUnavailable {
        cli_version: String,
        remote_platform: String,
    },
    HostUpdateRequiresCliUpgrade {
        cli_version: String,
    },
    AmbiguousCodexComponentOwnership {
        target: HostUpdateTarget,
    },
    InvalidArtifact {
        expected_version: String,
        expected_platform: String,
    },
    InvalidCodexTarget {
        target: HostUpdateTarget,
    },
}

pub struct HostUpdatePlanRequest<'a> {
    pub host: &'a str,
    pub cli_version: &'a str,
    pub components: &'a [HostUpdateComponent],
    pub includes_all: bool,
    pub host_inspection: &'a HostUpdateInspection,
    pub service_inspection: Option<&'a HostUpdateServiceInspection>,
    pub codex_inspections: &'a [CodexUpdateInspection],
}

/// Builds a complete read-only plan. The function has no executor, ledger,
/// session, prompt, or filesystem handle, so it cannot cross the apply boundary.
pub fn build_host_update_plan(
    request: HostUpdatePlanRequest<'_>,
    artifacts: &dyn VerifiedHostArtifactResolver,
) -> Result<HostUpdateReport, HostUpdatePlanError> {
    let components = selected_components(request.components, request.includes_all)?;
    let mut targets = Vec::new();

    if components.contains(&HostUpdateComponent::Host) {
        targets.extend(plan_host_targets(&request, artifacts)?);
    }
    if components.contains(&HostUpdateComponent::Codex) {
        targets.extend(plan_codex_targets(request.codex_inspections)?);
    }

    Ok(HostUpdateReport::new(
        request.host,
        components.into_iter().collect(),
        targets,
    ))
}

fn selected_components(
    requested: &[HostUpdateComponent],
    includes_all: bool,
) -> Result<BTreeSet<HostUpdateComponent>, HostUpdatePlanError> {
    if includes_all && !requested.is_empty() {
        return Err(HostUpdatePlanError::ComponentSelectionConflict);
    }
    if includes_all || requested.is_empty() {
        return Ok(BTreeSet::from([
            HostUpdateComponent::Host,
            HostUpdateComponent::Codex,
        ]));
    }
    Ok(requested.iter().copied().collect())
}

fn plan_host_targets(
    request: &HostUpdatePlanRequest<'_>,
    artifacts: &dyn VerifiedHostArtifactResolver,
) -> Result<Vec<HostUpdateTargetPlan>, HostUpdatePlanError> {
    match request.host_inspection.relation_to_cli {
        HostVersionRelation::NewerThanCli => {
            return Err(HostUpdatePlanError::HostBinaryNewerThanCli {
                host_version: request
                    .host_inspection
                    .current_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                cli_version: request.cli_version.to_string(),
            });
        }
        HostVersionRelation::RequiresNewerCli => {
            return Err(HostUpdatePlanError::HostUpdateRequiresCliUpgrade {
                cli_version: request.cli_version.to_string(),
            });
        }
        HostVersionRelation::Missing
        | HostVersionRelation::OlderThanCli
        | HostVersionRelation::MatchesCli => {}
    }

    let disposition = match request.host_inspection.relation_to_cli {
        HostVersionRelation::Missing => HostUpdateDisposition::Install,
        HostVersionRelation::OlderThanCli => HostUpdateDisposition::Update,
        HostVersionRelation::MatchesCli => HostUpdateDisposition::Current,
        HostVersionRelation::NewerThanCli | HostVersionRelation::RequiresNewerCli => unreachable!(),
    };
    let service_disposition = request
        .service_inspection
        .map(|service| match service.relation_to_cli {
            HostVersionRelation::Missing => Ok(HostUpdateDisposition::Install),
            HostVersionRelation::OlderThanCli => Ok(HostUpdateDisposition::Update),
            HostVersionRelation::MatchesCli => Ok(HostUpdateDisposition::Current),
            HostVersionRelation::NewerThanCli => Err(HostUpdatePlanError::HostBinaryNewerThanCli {
                host_version: service
                    .current_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                cli_version: request.cli_version.to_string(),
            }),
            HostVersionRelation::RequiresNewerCli => {
                Err(HostUpdatePlanError::HostUpdateRequiresCliUpgrade {
                    cli_version: request.cli_version.to_string(),
                })
            }
        })
        .transpose()?;
    let artifact_required = disposition != HostUpdateDisposition::Current
        || service_disposition.is_some_and(|service| service != HostUpdateDisposition::Current);
    let artifact = if !artifact_required {
        None
    } else {
        let artifact = artifacts
            .resolve_exact_cli_artifact(
                request.cli_version,
                &request.host_inspection.remote_platform,
            )?
            .ok_or_else(|| HostUpdatePlanError::HostArtifactUnavailable {
                cli_version: request.cli_version.to_string(),
                remote_platform: request.host_inspection.remote_platform.clone(),
            })?;
        if artifact.version != request.cli_version
            || artifact.remote_platform != request.host_inspection.remote_platform
        {
            return Err(HostUpdatePlanError::InvalidArtifact {
                expected_version: request.cli_version.to_string(),
                expected_platform: request.host_inspection.remote_platform.clone(),
            });
        }
        Some(artifact)
    };
    let daemon_mutations = mutation_for(
        disposition,
        "replace_host_daemon",
        artifact.and_then(|artifact| artifact.daemon_destination),
    );
    let mut targets = vec![HostUpdateTargetPlan {
        target: HostUpdateTarget::HostDaemon,
        current_version: request.host_inspection.current_version.clone(),
        target_version: request.cli_version.to_string(),
        version_source: HostUpdateVersionSource::InvokingCliRelease,
        disposition,
        restart_impact: HostUpdateRestartImpact::HostDaemon,
        remote_mutations: daemon_mutations,
    }];
    if let Some((service, disposition)) = request.service_inspection.zip(service_disposition) {
        targets.push(HostUpdateTargetPlan {
            target: HostUpdateTarget::HostDaemonService,
            current_version: service.current_version.clone(),
            target_version: request.cli_version.to_string(),
            version_source: HostUpdateVersionSource::InvokingCliRelease,
            disposition,
            restart_impact: HostUpdateRestartImpact::HostDaemon,
            remote_mutations: mutation_for(
                disposition,
                "replace_host_daemon_service",
                Some(service.destination.clone()),
            ),
        });
    }

    Ok(targets)
}

fn mutation_for(
    disposition: HostUpdateDisposition,
    operation: &str,
    destination: Option<String>,
) -> Vec<HostUpdateMutation> {
    if disposition == HostUpdateDisposition::Current {
        Vec::new()
    } else {
        vec![HostUpdateMutation {
            operation: operation.to_string(),
            remote_path: destination,
        }]
    }
}

fn plan_codex_targets(
    inspections: &[CodexUpdateInspection],
) -> Result<Vec<HostUpdateTargetPlan>, HostUpdatePlanError> {
    inspections
        .iter()
        .map(|inspection| {
            if inspection.ownership == CodexComponentOwnership::Ambiguous {
                return Err(HostUpdatePlanError::AmbiguousCodexComponentOwnership {
                    target: inspection.target,
                });
            }
            if !matches!(
                inspection.target,
                HostUpdateTarget::CodexRuntime | HostUpdateTarget::CodexNativeComputerUse
            ) {
                return Err(HostUpdatePlanError::InvalidCodexTarget {
                    target: inspection.target,
                });
            }
            Ok(HostUpdateTargetPlan {
                target: inspection.target,
                current_version: inspection.current_version.clone(),
                target_version: inspection.target_version.clone(),
                version_source: HostUpdateVersionSource::CodexCompatibilityRequirement,
                disposition: if inspection.update_required {
                    if inspection.current_version.is_some() {
                        HostUpdateDisposition::Update
                    } else {
                        HostUpdateDisposition::Install
                    }
                } else {
                    HostUpdateDisposition::Current
                },
                restart_impact: inspection.restart_impact,
                remote_mutations: if inspection.update_required {
                    inspection.remote_mutations.clone()
                } else {
                    Vec::new()
                },
            })
        })
        .collect()
}

pub fn codex_inspections_from_evidence(
    evidence: &CodexUpdateEvidence,
) -> [CodexUpdateInspection; 2] {
    [
        CodexUpdateInspection {
            target: HostUpdateTarget::CodexRuntime,
            ownership: evidence.runtime_ownership,
            current_version: evidence.runtime_current_version.clone(),
            target_version: evidence.required_version.clone(),
            update_required: evidence.runtime_update_required,
            restart_impact: HostUpdateRestartImpact::CodexRuntime,
            remote_mutations: vec![HostUpdateMutation {
                operation: "replace_codex_runtime".to_string(),
                remote_path: None,
            }],
        },
        CodexUpdateInspection {
            target: HostUpdateTarget::CodexNativeComputerUse,
            ownership: evidence.native_component_ownership,
            current_version: evidence.native_component_current_version.clone(),
            target_version: evidence.required_version.clone(),
            update_required: evidence.native_update_required,
            restart_impact: HostUpdateRestartImpact::NativeComputerUse,
            remote_mutations: vec![HostUpdateMutation {
                operation: "replace_codex_native_computer_use".to_string(),
                remote_path: None,
            }],
        },
    ]
}

pub fn classify_repair_upgrade(
    blocking_reason: Option<RepairCompatibilityReason>,
    automation_is_safe: bool,
    newer_compatible_version_available: bool,
) -> RepairUpgradeDisposition {
    if blocking_reason.is_some() {
        if automation_is_safe {
            RepairUpgradeDisposition::Required
        } else {
            RepairUpgradeDisposition::ManualActionRequired
        }
    } else if newer_compatible_version_available {
        RepairUpgradeDisposition::RecommendHostUpdate
    } else {
        RepairUpgradeDisposition::NotNeeded
    }
}

pub fn build_repair_upgrade_plan(
    host: &str,
    inspections: &[RepairUpgradeInspection],
) -> RepairUpgradeReport {
    // This is read-only compatibility planning. It does not claim access to
    // the Host-owned setup action ledger. Any apply path must reconcile these
    // candidates through `SetupRepairPlan` before mutation.
    RepairUpgradeReport::new(
        host,
        inspections
            .iter()
            .map(|inspection| RepairUpgradeAction {
                target: inspection.target,
                current_version: inspection.current_version.clone(),
                target_version: inspection.target_version.clone(),
                compatibility_reason: inspection.compatibility_reason,
                version_source: inspection.version_source,
                disposition: classify_repair_upgrade(
                    inspection.compatibility_reason,
                    inspection.automation_is_safe,
                    inspection.newer_compatible_version_available,
                ),
            })
            .collect(),
    )
}

pub fn render_host_update_plan(report: &HostUpdateReport) -> String {
    let mut output = format!("Host update plan for {}\n", report.host);
    for target in &report.targets {
        let current = match (target.target, target.current_version.as_deref()) {
            (HostUpdateTarget::HostDaemonService, None)
                if target.disposition != HostUpdateDisposition::Install =>
            {
                "managed asset; version unavailable"
            }
            (_, Some(version)) => version,
            (_, None) => "not installed",
        };
        let _ = writeln!(
            output,
            "- {:?}: {} -> {} ({:?}, restart: {:?})",
            target.target,
            current,
            target.target_version,
            target.disposition,
            target.restart_impact
        );
        for mutation in &target.remote_mutations {
            let _ = writeln!(output, "  planned remote mutation: {}", mutation.operation);
        }
    }
    output
}

pub fn render_repair_upgrade_plan(
    report: &satelle_core::host_update::RepairUpgradeReport,
) -> String {
    let mut output = format!("Repair upgrade plan for {}\n", report.host);
    let _ = writeln!(
        output,
        "ledger: {:?}; plan source: {:?}",
        report.ledger_status, report.plan_source
    );
    for action in &report.actions {
        let current = action.current_version.as_deref().unwrap_or("not installed");
        let reason = action
            .compatibility_reason
            .map_or("none".to_string(), |reason| format!("{reason:?}"));
        let _ = writeln!(
            output,
            "- {:?}: {} -> {} ({:?}, reason: {}, source: {:?})",
            action.target,
            current,
            action.target_version,
            action.disposition,
            reason,
            action.version_source
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Artifact(Option<VerifiedHostArtifact>);

    impl VerifiedHostArtifactResolver for Artifact {
        fn resolve_exact_cli_artifact(
            &self,
            _cli_version: &str,
            _remote_platform: &str,
        ) -> Result<Option<VerifiedHostArtifact>, HostUpdatePlanError> {
            Ok(self.0.clone())
        }
    }

    fn artifact() -> Artifact {
        Artifact(Some(VerifiedHostArtifact {
            version: "1.2.3".to_string(),
            remote_platform: "linux-x64".to_string(),
            daemon_destination: Some("/opt/satelle/bin/satelle".to_string()),
        }))
    }

    fn host_inspection(relation_to_cli: HostVersionRelation) -> HostUpdateInspection {
        HostUpdateInspection {
            current_version: Some("1.2.2".to_string()),
            relation_to_cli,
            remote_platform: "linux-x64".to_string(),
        }
    }

    fn service_inspection() -> HostUpdateServiceInspection {
        HostUpdateServiceInspection {
            // The service asset is managed but does not embed its own version.
            current_version: None,
            relation_to_cli: HostVersionRelation::OlderThanCli,
            destination: "/home/operator/.config/systemd/user/satelle.service".to_string(),
        }
    }

    #[test]
    fn no_filter_checks_host_and_codex_and_keeps_codex_actions_separate() {
        let host = host_inspection(HostVersionRelation::OlderThanCli);
        let codex = [
            CodexUpdateInspection {
                target: HostUpdateTarget::CodexRuntime,
                ownership: CodexComponentOwnership::CodexOwned,
                current_version: Some("0.9.0".to_string()),
                target_version: "1.0.0".to_string(),
                update_required: true,
                restart_impact: HostUpdateRestartImpact::CodexRuntime,
                remote_mutations: vec![HostUpdateMutation {
                    operation: "replace_codex_runtime".to_string(),
                    remote_path: None,
                }],
            },
            CodexUpdateInspection {
                target: HostUpdateTarget::CodexNativeComputerUse,
                ownership: CodexComponentOwnership::CodexOwned,
                current_version: None,
                target_version: "1.0.0".to_string(),
                update_required: true,
                restart_impact: HostUpdateRestartImpact::NativeComputerUse,
                remote_mutations: vec![HostUpdateMutation {
                    operation: "install_codex_native_computer_use".to_string(),
                    remote_path: None,
                }],
            },
        ];
        let service = service_inspection();
        let report = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[],
                includes_all: false,
                host_inspection: &host,
                service_inspection: Some(&service),
                codex_inspections: &codex,
            },
            &artifact(),
        )
        .expect("build plan");

        assert_eq!(
            report.checked_components,
            [HostUpdateComponent::Host, HostUpdateComponent::Codex]
        );
        assert_eq!(report.targets.len(), 4);
        assert_eq!(report.targets[2].target, HostUpdateTarget::CodexRuntime);
        assert_eq!(
            report.targets[3].target,
            HostUpdateTarget::CodexNativeComputerUse
        );
        assert!(report.confirmation_required);
    }

    #[test]
    fn host_selection_targets_only_exact_cli_host_artifacts() {
        let host = host_inspection(HostVersionRelation::OlderThanCli);
        let service = service_inspection();
        let report = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: Some(&service),
                codex_inspections: &[],
            },
            &artifact(),
        )
        .expect("build host-only plan");

        assert_eq!(report.targets.len(), 2);
        assert!(report.targets.iter().all(|target| {
            matches!(
                target.target,
                HostUpdateTarget::HostDaemon | HostUpdateTarget::HostDaemonService
            ) && target.target_version == "1.2.3"
                && target.version_source == HostUpdateVersionSource::InvokingCliRelease
        }));
        assert_eq!(report.targets[1].current_version, None);
    }

    #[test]
    fn host_selection_omits_an_unobserved_service_asset() {
        let host = host_inspection(HostVersionRelation::OlderThanCli);
        let report = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: None,
                codex_inspections: &[],
            },
            &artifact(),
        )
        .expect("build host-only plan without service evidence");

        assert_eq!(report.targets.len(), 1);
        assert_eq!(report.targets[0].target, HostUpdateTarget::HostDaemon);
    }

    #[test]
    fn missing_service_asset_renders_as_not_installed() {
        let mut host = host_inspection(HostVersionRelation::MatchesCli);
        host.current_version = Some("1.2.3".to_string());
        let service = HostUpdateServiceInspection {
            current_version: None,
            relation_to_cli: HostVersionRelation::Missing,
            destination: "/home/operator/.config/systemd/user/satelle.service".to_string(),
        };
        let report = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: Some(&service),
                codex_inspections: &[],
            },
            &artifact(),
        )
        .expect("build plan with missing service asset");

        let rendered = render_host_update_plan(&report);
        assert!(
            rendered.contains(
                "HostDaemonService: not installed -> 1.2.3 (Install, restart: HostDaemon)"
            )
        );
        assert!(!rendered.contains("managed asset; version unavailable"));
    }

    #[test]
    fn current_host_does_not_resolve_an_update_artifact() {
        let mut host = host_inspection(HostVersionRelation::MatchesCli);
        host.current_version = Some("1.2.3".to_string());
        let report = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: None,
                codex_inspections: &[],
            },
            &Artifact(None),
        )
        .expect("a current Host does not need an update artifact");

        assert_eq!(report.targets.len(), 1);
        assert_eq!(
            report.targets[0].disposition,
            HostUpdateDisposition::Current
        );
        assert!(!report.confirmation_required);
    }

    #[test]
    fn current_daemon_with_outdated_service_still_requires_the_exact_release_artifact() {
        let mut host = host_inspection(HostVersionRelation::MatchesCli);
        host.current_version = Some("1.2.3".to_string());
        let service = service_inspection();

        let error = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: Some(&service),
                codex_inspections: &[],
            },
            &Artifact(None),
        )
        .expect_err("an outdated service needs the exact release artifact");

        assert_eq!(
            error,
            HostUpdatePlanError::HostArtifactUnavailable {
                cli_version: "1.2.3".to_string(),
                remote_platform: "linux-x64".to_string(),
            }
        );

        let report = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: Some(&service),
                codex_inspections: &[],
            },
            &artifact(),
        )
        .expect("the exact artifact makes the independent service update plannable");
        assert_eq!(
            report.targets[0].disposition,
            HostUpdateDisposition::Current
        );
        assert_eq!(
            report.targets[1].target,
            HostUpdateTarget::HostDaemonService
        );
        assert_eq!(report.targets[1].disposition, HostUpdateDisposition::Update);
    }

    #[test]
    fn unavailable_codex_evidence_blocks_default_but_not_host_only_planning() {
        let host = host_inspection(HostVersionRelation::OlderThanCli);
        let unavailable = codex_inspections_from_evidence(&CodexUpdateEvidence {
            runtime_ownership: CodexComponentOwnership::Ambiguous,
            native_component_ownership: CodexComponentOwnership::Ambiguous,
            runtime_current_version: None,
            native_component_current_version: None,
            required_version: "1.0.0".to_string(),
            runtime_update_required: true,
            native_update_required: true,
            runtime_compatibility_reason: None,
            native_component_compatibility_reason: None,
        });

        build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &host,
                service_inspection: None,
                codex_inspections: &unavailable,
            },
            &artifact(),
        )
        .expect("legacy Host evidence still supports a host-only update plan");

        let error = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[],
                includes_all: false,
                host_inspection: &host,
                service_inspection: None,
                codex_inspections: &unavailable,
            },
            &artifact(),
        )
        .expect_err("default planning must fail closed without Codex ownership evidence");
        assert!(matches!(
            error,
            HostUpdatePlanError::AmbiguousCodexComponentOwnership { .. }
        ));
    }

    #[test]
    fn newer_host_and_missing_artifact_fail_before_a_plan_exists() {
        let newer = host_inspection(HostVersionRelation::NewerThanCli);
        let newer_error = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &newer,
                service_inspection: None,
                codex_inspections: &[],
            },
            &artifact(),
        )
        .expect_err("newer daemon must not be downgraded");
        assert!(matches!(
            newer_error,
            HostUpdatePlanError::HostBinaryNewerThanCli { .. }
        ));

        let older = host_inspection(HostVersionRelation::OlderThanCli);
        let unavailable_error = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Host],
                includes_all: false,
                host_inspection: &older,
                service_inspection: None,
                codex_inspections: &[],
            },
            &Artifact(None),
        )
        .expect_err("missing verified artifact must block");
        assert!(matches!(
            unavailable_error,
            HostUpdatePlanError::HostArtifactUnavailable { .. }
        ));
    }

    #[test]
    fn ambiguous_codex_ownership_fails_closed() {
        let host = host_inspection(HostVersionRelation::MatchesCli);
        let ambiguous = [CodexUpdateInspection {
            target: HostUpdateTarget::CodexNativeComputerUse,
            ownership: CodexComponentOwnership::Ambiguous,
            current_version: None,
            target_version: "1.0.0".to_string(),
            update_required: true,
            restart_impact: HostUpdateRestartImpact::NativeComputerUse,
            remote_mutations: Vec::new(),
        }];
        let error = build_host_update_plan(
            HostUpdatePlanRequest {
                host: "office",
                cli_version: "1.2.3",
                components: &[HostUpdateComponent::Codex],
                includes_all: false,
                host_inspection: &host,
                service_inspection: None,
                codex_inspections: &ambiguous,
            },
            &artifact(),
        )
        .expect_err("ambiguous ownership must block");

        assert!(matches!(
            error,
            HostUpdatePlanError::AmbiguousCodexComponentOwnership { .. }
        ));
    }

    #[test]
    fn repair_upgrades_only_for_blocking_compatibility_or_readiness() {
        assert_eq!(
            classify_repair_upgrade(
                Some(RepairCompatibilityReason::ControlPlaneIncompatible),
                true,
                true,
            ),
            RepairUpgradeDisposition::Required
        );
        assert_eq!(
            classify_repair_upgrade(None, true, true),
            RepairUpgradeDisposition::RecommendHostUpdate
        );
        assert_eq!(
            classify_repair_upgrade(None, true, false),
            RepairUpgradeDisposition::NotNeeded
        );
        assert_eq!(
            classify_repair_upgrade(
                Some(RepairCompatibilityReason::NativeReadinessBlocked),
                false,
                false,
            ),
            RepairUpgradeDisposition::ManualActionRequired
        );
    }

    #[test]
    fn repair_plan_preserves_observed_reason_and_version_source() {
        let report = build_repair_upgrade_plan(
            "office",
            &[RepairUpgradeInspection {
                target: HostUpdateTarget::CodexRuntime,
                current_version: Some("0.9.0".to_string()),
                target_version: "1.0.0".to_string(),
                compatibility_reason: Some(RepairCompatibilityReason::ControlPlaneIncompatible),
                version_source: HostUpdateVersionSource::CodexCompatibilityRequirement,
                automation_is_safe: false,
                newer_compatible_version_available: false,
            }],
        );

        assert_eq!(report.host, "office");
        assert_eq!(report.actions.len(), 1);
        assert_eq!(
            report.actions[0],
            RepairUpgradeAction {
                target: HostUpdateTarget::CodexRuntime,
                current_version: Some("0.9.0".to_string()),
                target_version: "1.0.0".to_string(),
                compatibility_reason: Some(RepairCompatibilityReason::ControlPlaneIncompatible,),
                version_source: HostUpdateVersionSource::CodexCompatibilityRequirement,
                disposition: RepairUpgradeDisposition::ManualActionRequired,
            }
        );
    }
}
