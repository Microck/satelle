use super::*;
use crate::storage_migration::{BindingUpdate, argument};
use satelle_core::daemon_service::DaemonResolvedPathSet;
use satelle_host::{StorageMigrationPlan, StorageMigrationStage};

pub(crate) fn plan(
    host: &SelectedHost,
    destination: &Path,
) -> Result<StorageMigrationPlan, SatelleError> {
    if host.config.transport == TransportKind::Local {
        let (config, _, _) = effective_local_host_config(host)?;
        return HostService::plan_storage_migration(
            &HostService::resolved_daemon_paths_for_host(&config)?,
            destination,
        );
    }
    let remote = RemoteMigration::inspect(host)?;
    ssh_bootstrap::preview_storage_migration(
        remote.transport.binding.destination(),
        remote.target,
        remote.artifact.remote_path(),
        &remote.source,
        &destination.display().to_string(),
    )
    .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))
}

pub(crate) fn complete(host: &SelectedHost, operation_id: &str) -> Result<(), SatelleError> {
    let transport = match host.config.transport {
        TransportKind::Local => local_daemon_transport(host)?,
        TransportKind::Ssh => ssh_transport(host, SshDaemonLaunchPolicy::Never)?,
        TransportKind::Direct => direct_transport(host)?,
    };
    let paths = transport.host_paths()?;
    complete_verified(&transport.client, &host.alias, operation_id, &paths)
}

pub(crate) fn cleanup_source(
    host: &SelectedHost,
    operation_id: &str,
    apply: bool,
) -> Result<satelle_host::StorageMigrationCleanup, SatelleError> {
    let transport = match host.config.transport {
        TransportKind::Local => {
            let (config, root, _) = effective_local_host_config(host)?;
            let endpoint = read_local_daemon_endpoint(&root.join(LOCAL_DAEMON_ENDPOINT_FILE))?;
            let token = read_owner_only_secret_file(&root.join(LOCAL_DAEMON_TOKEN_FILE))
                .map_err(|_| SatelleError::host_unreachable(&host.alias))?;
            probe_local_daemon(host, &config, &endpoint, &token)?
                .ok_or_else(|| SatelleError::host_unreachable(&host.alias))?
        }
        TransportKind::Ssh => ssh_transport(host, SshDaemonLaunchPolicy::Never)?,
        TransportKind::Direct => direct_transport(host)?,
    };
    let response = if apply {
        transport
            .client
            .cleanup_storage_migration_source(operation_id)
    } else {
        transport
            .client
            .preview_storage_migration_source(operation_id)
    };
    response
        .map(|response| response.into_cleanup())
        .map_err(|error| direct_transport_error(&host.alias, error))
}

fn retry_once_after_transport_error<T>(
    mut request: impl FnMut() -> Result<T, DaemonClientError>,
) -> Result<T, DaemonClientError> {
    match request() {
        Err(DaemonClientError::Transport(_)) => request(),
        result => result,
    }
}

fn complete_verified(
    client: &DaemonClient,
    alias: &str,
    operation_id: &str,
    paths: &DaemonResolvedPathSet,
) -> Result<(), SatelleError> {
    // Completion can commit before a connection drops. Its idempotent replay
    // is safe after normal work resumes; switching back to the source is not.
    retry_once_after_transport_error(|| {
        client.complete_storage_migration(operation_id, paths.clone())
    })
    .map(|_| ())
    .map_err(|error| {
        let mut failure = direct_transport_error(alias, error);
        failure.code = ErrorCode::SetupPartiallyApplied;
        failure.message =
            "the destination is active, but migration completion could not be confirmed".into();
        failure.recovery_command = Some(format!(
            "satelle host storage complete --host {} --operation-id {} --yes",
            argument(alias),
            argument(operation_id),
        ));
        failure
            .details
            .insert("active_paths".into(), serde_json::json!(paths));
        failure
            .details
            .insert("operation_id".into(), serde_json::json!(operation_id));
        failure
    })
}

fn begin_request(
    client: &DaemonClient,
    operation_id: &str,
    paths: &DaemonResolvedPathSet,
) -> Result<(), DaemonClientError> {
    // A dropped reply may follow a committed maintenance lease. Replaying the
    // same operation confirms that lease before the coordinator stops a Host.
    retry_once_after_transport_error(|| client.begin_storage_migration(operation_id, paths.clone()))
        .map(|_| ())
}

fn begin_failure(
    mut error: SatelleError,
    plan: &StorageMigrationPlan,
    operation_id: &str,
    recovery_commands: Vec<String>,
) -> SatelleError {
    error
        .details
        .insert("operation_id".into(), serde_json::json!(operation_id));
    error
        .details
        .insert("source_paths".into(), serde_json::json!(plan.source));
    error.details.insert(
        "destination_paths".into(),
        serde_json::json!(plan.destination),
    );
    error.details.insert(
        "manual_recovery_commands".into(),
        serde_json::json!(recovery_commands),
    );
    error.details.insert("manual_recovery_requirement".into(), serde_json::json!("confirm this operation owns source maintenance before stopping the Host; an unconfirmed begin response does not authorize stopping active work"));
    error
}

fn require_paths(
    client: &DaemonClient,
    alias: &str,
    expected: &DaemonResolvedPathSet,
) -> Result<(), SatelleError> {
    let response = client
        .host_paths()
        .map_err(|error| direct_transport_error(alias, error))?;
    if response.paths() != expected {
        return Err(SatelleError::state_conflict());
    }
    Ok(())
}

fn selected_destination(host: &SelectedHost, paths: &DaemonResolvedPathSet) -> SelectedHost {
    let mut destination = host.clone();
    destination.config.daemon_state_dir = Some(PathBuf::from(&paths.state_root));
    destination.config.daemon_log_dir = Some(PathBuf::from(&paths.operator_log_root));
    destination
}

fn stop_local(
    host: &SelectedHost,
    transport: &DirectTransport,
    operation_id: &str,
) -> Result<(), SatelleError> {
    let (_, state_root, _) = effective_local_host_config(host)?;
    let endpoint_path = state_root.join(LOCAL_DAEMON_ENDPOINT_FILE);
    let endpoint = read_local_daemon_endpoint(&endpoint_path)?;
    transport
        .client
        .relaunch_local_daemon_if_idle(&format!("migration-stop-{operation_id}"))
        .map_err(|error| direct_transport_error(&host.alias, error))?;
    wait_for_local_daemon_endpoint_change(&endpoint_path, &endpoint.launch_id)
}

pub(crate) fn apply_local(
    host: &SelectedHost,
    destination_root: &Path,
    reviewed: &StorageMigrationPlan,
    operation_id: &str,
    binding: &BindingUpdate,
    config: &crate::ConfigContext<'_>,
) -> Result<StorageMigrationStage, SatelleError> {
    let source = local_daemon_transport(host)?;
    require_paths(&source.client, &host.alias, &reviewed.source)?;
    begin_request(&source.client, operation_id, &reviewed.source).map_err(|error| {
        begin_failure(
            direct_transport_error(&host.alias, error),
            reviewed,
            operation_id,
            local_recovery_commands(host, reviewed, operation_id, binding),
        )
    })?;
    let destination = selected_destination(host, &reviewed.destination);
    let mut destination_attempted = false;
    let activation = (|| {
        stop_local(host, &source, operation_id)?;
        let staged =
            HostService::stage_storage_migration(&reviewed.source, destination_root, operation_id)?;
        if staged.plan.destination != reviewed.destination {
            return Err(SatelleError::state_conflict());
        }
        destination_attempted = true;
        let active = local_daemon_transport(&destination)?;
        if active.host_identity != source.host_identity {
            return Err(SatelleError::state_conflict());
        }
        require_paths(&active.client, &host.alias, &reviewed.destination)?;
        binding.apply_for_host(config, host)?;
        Ok((staged, active))
    })();
    let (stage, active) = match activation {
        Ok(activation) => activation,
        Err(cause) => {
            let rollback = (|| {
                if destination_attempted {
                    // If launch failed before publishing an endpoint, the source
                    // cannot be reactivated until the destination is proven stopped.
                    let (_, root, _) = effective_local_host_config(&destination)?;
                    let endpoint =
                        optional_local_daemon_endpoint(&root.join(LOCAL_DAEMON_ENDPOINT_FILE))?
                            .ok_or_else(SatelleError::state_conflict)?;
                    let token = read_owner_only_secret_file(&root.join(LOCAL_DAEMON_TOKEN_FILE))
                        .map_err(|_| SatelleError::state_conflict())?;
                    if let Some(active) =
                        probe_local_daemon(&destination, &destination.config, &endpoint, &token)?
                    {
                        stop_local(&destination, &active, operation_id)?;
                    }
                } else {
                    let (_, root, _) = effective_local_host_config(host)?;
                    if let Some(endpoint) =
                        optional_local_daemon_endpoint(&root.join(LOCAL_DAEMON_ENDPOINT_FILE))?
                    {
                        let token =
                            read_owner_only_secret_file(&root.join(LOCAL_DAEMON_TOKEN_FILE))
                                .map_err(|_| SatelleError::state_conflict())?;
                        if let Some(active) =
                            probe_local_daemon(host, &host.config, &endpoint, &token)?
                        {
                            stop_local(host, &active, operation_id)?;
                        }
                    }
                }
                binding.rollback()?;
                HostService::rollback_storage_migration(
                    Path::new(&reviewed.source.state_root),
                    operation_id,
                )?;
                let restored = local_daemon_transport(host)?;
                require_paths(&restored.client, &host.alias, &reviewed.source)
            })();
            let mut error = migration_failure(cause, rollback, reviewed, operation_id, binding);
            error.details.insert(
                "manual_recovery_commands".into(),
                serde_json::json!(local_recovery_commands(
                    host,
                    reviewed,
                    operation_id,
                    binding
                )),
            );
            error.details.insert("manual_recovery_requirement".into(), serde_json::json!("verify both Host processes are stopped and cancel any pending destination launch before restoring the source"));
            return Err(error);
        }
    };
    complete_verified(
        &active.client,
        &host.alias,
        operation_id,
        &reviewed.destination,
    )?;
    Ok(stage)
}

fn migration_failure(
    mut cause: SatelleError,
    rollback: Result<(), SatelleError>,
    plan: &StorageMigrationPlan,
    operation_id: &str,
    binding: &BindingUpdate,
) -> SatelleError {
    cause
        .details
        .insert("source_paths".into(), serde_json::json!(plan.source));
    cause.details.insert(
        "destination_paths".into(),
        serde_json::json!(plan.destination),
    );
    cause
        .details
        .insert("operation_id".into(), serde_json::json!(operation_id));
    cause.details.insert(
        "binding_restore_command".into(),
        serde_json::json!(binding.restore_command()),
    );
    match rollback {
        Ok(()) => {
            cause.code = ErrorCode::SetupPartiallyApplied;
            cause
                .details
                .insert("service_state".into(), serde_json::json!("source_restored"));
        }
        Err(rollback) => {
            cause.code = ErrorCode::StorageMigrationRollbackFailed;
            cause.details.insert(
                "service_state".into(),
                serde_json::json!("recovery_required"),
            );
            cause
                .details
                .insert("rollback_error".into(), serde_json::json!(rollback));
        }
    }
    cause
}

fn local_recovery_commands(
    host: &SelectedHost,
    plan: &StorageMigrationPlan,
    operation_id: &str,
    binding: &BindingUpdate,
) -> Vec<String> {
    let release = |root: &str| {
        #[cfg(not(windows))]
        {
            format!(
                "SATELLE_STATE_DIR={} satelle host release-state",
                argument(root)
            )
        }
        #[cfg(windows)]
        {
            format!(
                "powershell -NoProfile -Command {}",
                argument(&format!(
                    "$env:SATELLE_STATE_DIR={}; satelle host release-state",
                    argument(root)
                ))
            )
        }
    };
    vec![
        release(&plan.destination.state_root),
        release(&plan.source.state_root),
        format!(
            "satelle host offline-storage-migration rollback --source-root {} --operation-id {} --yes",
            argument(&plan.source.state_root),
            argument(operation_id)
        ),
        binding.restore_command(),
        format!(
            "satelle doctor --host {} --scope all --json",
            argument(&host.alias)
        ),
    ]
}

struct RemoteMigration {
    transport: SshSetupTransport,
    target: ssh_bootstrap::RemoteTarget,
    directories: ssh_bootstrap::RemoteUserDirectories,
    overrides: DaemonPathOverrides,
    artifact: ssh_bootstrap::ManagedHostArtifact,
    source: DaemonResolvedPathSet,
}

impl RemoteMigration {
    fn inspect(host: &SelectedHost) -> Result<Self, SatelleError> {
        if host.config.transport != TransportKind::Ssh {
            return Err(SatelleError::invalid_usage(
                "storage migration requires a local or trusted SSH Host Binding",
            ));
        }
        let transport = SshSetupTransport::new(host)?;
        if transport.requires_first_trust {
            return Err(SatelleError::invalid_usage(
                "storage migration requires a trusted Host Identity",
            ));
        }
        let target = transport.remote_target()?;
        if target.service_platform() == DaemonServicePlatform::Linux {
            return Err(SatelleError::persistent_service_unsupported("linux"));
        }
        let directories = transport.remote_directories(target)?;
        let host_id = transport.binding.expected_host_identity().as_str();
        let overrides = directories
            .canonical_daemon_path_overrides(transport.binding.destination(), host_id)
            .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))?;
        let service_path = directories
            .persistent_service_asset_path(host_id)
            .ok_or_else(SatelleError::state_conflict)?;
        let executable = directories
            .probe_managed_service_executable(
                transport.binding.destination(),
                &service_path,
                host_id,
                ssh_bootstrap::ManagedServiceExpectation::new(
                    &overrides,
                    resolved_persistent_storage_policy(&host.config),
                    host.config.telemetry.as_ref(),
                    None,
                )
                .with_queue(&host.config.queue),
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(&host.alias, error))?
            .ok_or_else(SatelleError::state_conflict)?;
        let source = directories
            .resolved_path_set()
            .with_service_overrides(&overrides);
        Ok(Self {
            transport,
            target,
            directories,
            overrides,
            artifact: ssh_bootstrap::ManagedHostArtifact::from_installed(&executable),
            source,
        })
    }

    fn remote<'a>(
        &'a self,
        lock: &'a mut ssh_bootstrap::SshBootstrapLock,
    ) -> Result<ssh_bootstrap::PersistentServiceRemote<'a>, SatelleError> {
        ssh_bootstrap::PersistentServiceRemote::new(
            self.transport.binding.destination(),
            self.target,
            &self.directories,
            lock,
        )
        .map_err(|error| map_ssh_daemon_bootstrap_error(&self.transport.alias, error))
    }

    fn recovery_commands(
        &self,
        service: &PreparedPersistentService,
        binding: &BindingUpdate,
        operation_id: &str,
    ) -> Result<Vec<String>, SatelleError> {
        let (service_path, bytes, extension, stop, register, start) = match service {
            PreparedPersistentService::Windows { task, config } => (
                task.service_config_path.as_str(),
                serde_json::to_vec_pretty(config).map_err(|_| SatelleError::state_conflict())?,
                "json",
                ssh_bootstrap::windows_task_instance_command(task, "stop"),
                ssh_bootstrap::windows_task_register_command(task),
                ssh_bootstrap::windows_task_instance_command(task, "start"),
            ),
            PreparedPersistentService::Launchd(definition) => (
                definition.plist_path(),
                definition.contents().as_bytes().to_vec(),
                "plist",
                ssh_bootstrap::launchd_lifecycle_command("bootout"),
                ssh_bootstrap::launchd_register_command(definition.plist_path()),
                ssh_bootstrap::launchd_lifecycle_command("kickstart"),
            ),
        };
        let backup = binding
            .backup_path
            .with_file_name(format!("service-definition.{extension}"));
        persist_new_owner_only_config_file(&backup, &bytes).map_err(|_| {
            SatelleError::config_error(
                "could not preserve the original Host service definition",
                None,
            )
        })?;
        let destination = self.transport.binding.destination();
        let ssh = |command: &str| format!("ssh -- {} {}", argument(destination), argument(command));
        let rollback = ssh_bootstrap::storage_migration_command(
            self.target,
            self.artifact.remote_path(),
            "rollback",
            &[
                ("source-root", self.source.state_root.as_str()),
                ("operation-id", operation_id),
            ],
            true,
        );
        Ok(vec![
            ssh(&stop),
            format!(
                "scp -p -- {} {}",
                argument(&backup.display().to_string()),
                argument(&format!("{destination}:{service_path}"))
            ),
            ssh(&rollback),
            ssh(&register),
            ssh(&start),
            binding.restore_command(),
            format!(
                "satelle doctor --host {} --scope all --json",
                argument(&self.transport.alias)
            ),
        ])
    }

    fn activate(
        &self,
        service: &PreparedPersistentService,
        lock: &mut ssh_bootstrap::SshBootstrapLock,
    ) -> Result<(), SatelleError> {
        let alias = &self.transport.alias;
        {
            let mut remote = self.remote(lock)?;
            match service {
                PreparedPersistentService::Windows { task, config } => {
                    remote.publish_windows_service_config(task, config)
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.publish_launchd_definition(definition)
                }
            }
            .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
        }
        commit_verified_bootstrap_mutation(alias, lock)?;
        {
            let mut remote = self.remote(lock)?;
            match service {
                PreparedPersistentService::Windows { task, .. } => {
                    remote.register_windows_task(task)
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.register_launchd(definition)
                }
            }
            .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
            let observed = match service {
                PreparedPersistentService::Windows { task, .. } => {
                    remote.observe_windows_task(task)
                }
                PreparedPersistentService::Launchd(definition) => {
                    remote.observe_launchd(definition)
                }
            }
            .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
            if observed != ssh_bootstrap::PersistentServiceObservation::Matching {
                return Err(SatelleError::state_conflict());
            }
        }
        commit_verified_bootstrap_mutation(alias, lock)?;
        {
            let mut remote = self.remote(lock)?;
            match service {
                PreparedPersistentService::Windows { task, .. } => remote.start_windows_task(task),
                PreparedPersistentService::Launchd(_) => remote.kickstart_launchd(),
            }
            .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
            wait_for_service_observation(
                alias,
                || match service {
                    PreparedPersistentService::Windows { task, .. } => {
                        remote.observe_windows_task(task)
                    }
                    PreparedPersistentService::Launchd(_) => remote.observe_launchd_runtime(),
                },
                ssh_bootstrap::PersistentServiceObservation::Running,
            )?;
        }
        commit_verified_bootstrap_mutation(alias, lock)
    }
}

pub(crate) fn apply_remote(
    host: &SelectedHost,
    destination_root: &Path,
    reviewed: &StorageMigrationPlan,
    operation_id: &str,
    binding: &BindingUpdate,
    config: &crate::ConfigContext<'_>,
) -> Result<StorageMigrationStage, SatelleError> {
    let context = RemoteMigration::inspect(host)?;
    if context.source != reviewed.source {
        return Err(SatelleError::state_conflict());
    }
    let alias = &host.alias;
    let mut lock = acquire_bootstrap_lock_for_operation(
        alias,
        context.transport.binding.destination(),
        operation_id.to_string(),
        bootstrap_lock::OperationKind::StorageMaintenance,
    )?;
    let preparations = (|| {
        let remote = context.remote(&mut lock)?;
        let task = if context.target.service_platform() == DaemonServicePlatform::Windows {
            Some(
                remote
                    .registered_windows_task(
                        context.transport.binding.expected_host_identity().as_str(),
                    )
                    .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?,
            )
        } else {
            None
        };
        let previous = context.transport.prepare_persistent_service(
            context.target,
            &context.artifact,
            &context.overrides,
            &remote,
        )?;
        let mut overrides = context.overrides.clone();
        overrides.state_dir = Some(PathBuf::from(&reviewed.destination.state_root));
        overrides.log_dir = Some(PathBuf::from(&reviewed.destination.operator_log_root));
        let destination = context.transport.prepare_persistent_service(
            context.target,
            &context.artifact,
            &overrides,
            &remote,
        )?;
        let recovery_commands = context.recovery_commands(&previous, binding, operation_id)?;
        Ok((task, previous, destination, recovery_commands))
    })();
    let (task, previous, destination, recovery_commands) = match preparations {
        Ok(preparations) => preparations,
        Err(error) => {
            lock.release_unmodified()
                .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
            return Err(error);
        }
    };
    let (source_tunnel, source_client) = context.transport.durable_service_client()?;
    require_paths(&source_client, alias, &reviewed.source)?;
    lock.mark_mutation_started("maintenance_handoff_begin")
        .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
    reconcile_bootstrap_maintenance_response(
        alias,
        begin_request(&source_client, operation_id, &reviewed.source),
        &mut lock,
    )
    .map_err(|error| begin_failure(error, reviewed, operation_id, recovery_commands.clone()))?;
    commit_verified_bootstrap_mutation(alias, &mut lock)?;
    drop(source_client);
    drop(source_tunnel);
    let activation = (|| {
        verify_stopped_service_postconditions(
            &context.transport,
            context.target,
            &context.directories,
            &mut lock,
            task.as_ref(),
            true,
        )?;
        commit_verified_bootstrap_mutation(alias, &mut lock)?;
        let stage = context
            .remote(&mut lock)?
            .stage_storage_migration(
                &context.artifact,
                &reviewed.source,
                &destination_root.display().to_string(),
                operation_id,
            )
            .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
        if stage.plan.destination != reviewed.destination {
            return Err(SatelleError::state_conflict());
        }
        commit_verified_bootstrap_mutation(alias, &mut lock)?;
        context.activate(&destination, &mut lock)?;
        let (tunnel, client) = context.transport.durable_service_client()?;
        require_paths(&client, alias, &reviewed.destination)?;
        binding.apply_for_host(config, host)?;
        Ok((stage, tunnel, client))
    })();
    let (stage, _tunnel, client) = match activation {
        Ok(activation) => activation,
        Err(cause) => {
            let rollback = (|| {
                verify_stopped_service_postconditions(
                    &context.transport,
                    context.target,
                    &context.directories,
                    &mut lock,
                    task.as_ref(),
                    true,
                )?;
                commit_verified_bootstrap_mutation(alias, &mut lock)?;
                context
                    .remote(&mut lock)?
                    .rollback_storage_migration(
                        &context.artifact,
                        &reviewed.source.state_root,
                        operation_id,
                    )
                    .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
                commit_verified_bootstrap_mutation(alias, &mut lock)?;
                binding.rollback()?;
                context.activate(&previous, &mut lock)?;
                let (_tunnel, client) = context.transport.durable_service_client()?;
                require_paths(&client, alias, &reviewed.source)?;
                lock.release_committed_handoff()
                    .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))
            })();
            let mut error = migration_failure(cause, rollback, reviewed, operation_id, binding);
            error.details.insert(
                "manual_recovery_commands".into(),
                serde_json::json!(recovery_commands),
            );
            error.details.insert("manual_recovery_requirement".into(), serde_json::json!("verify the destination Host process is stopped before restoring and starting the source service"));
            return Err(error);
        }
    };
    lock.mark_mutation_started("maintenance_handoff_complete")
        .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
    complete_verified(&client, alias, operation_id, &reviewed.destination)?;
    commit_verified_bootstrap_mutation(alias, &mut lock)?;
    lock.release_committed_handoff()
        .map_err(|error| map_ssh_daemon_bootstrap_error(alias, error))?;
    Ok(stage)
}
