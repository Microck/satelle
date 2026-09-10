use satelle_core::daemon_service::DaemonResolvedPathSet;
use satelle_core::{ConfigSourceKind, ResolvedConfig, SatelleError};
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Table};

pub(super) fn argument(value: &str) -> String {
    #[cfg(windows)]
    {
        format!("'{}'", value.replace('\'', "''"))
    }
    #[cfg(not(windows))]
    {
        super::shell_argument(value)
    }
}

pub(super) fn run(
    command: super::HostStorageMigrateCommand,
    config: super::ConfigContext<'_>,
    format: super::OutputFormat,
) -> Result<(), super::CliFailure> {
    use super::{failure, transport};
    use std::io::IsTerminal as _;
    let alias = command.host.as_deref().ok_or_else(|| {
        failure(SatelleError::invalid_usage(
            "storage migration requires one explicit --host alias",
        ))
    })?;
    let host = config.resolve_host(Some(alias))?;
    if host.from_project {
        return Err(failure(SatelleError::invalid_usage(
            "storage migration requires a user-owned Host Binding",
        )));
    }
    let operation_id = format!("storage-migration-{}", uuid::Uuid::now_v7());
    let plan = transport::storage_migration::plan(&host, &command.to).map_err(failure)?;
    let binding = BindingUpdate::plan(config.load()?, alias, &plan.destination, &operation_id)
        .map_err(failure)?;
    let actions = vec![
        "back up the owning Host Binding configuration".to_string(),
        "acquire exclusive maintenance ownership and stop the Host service".to_string(),
        "copy and verify Host storage at the destination".to_string(),
        "activate the destination and update the Host Binding".to_string(),
    ];
    if command.dry_run {
        return print_report(
            &serde_json::json!({
                "schema_version": "satelle.storage-migration.v1", "host": alias,
                "dry_run": true, "operation_id": operation_id, "plan": plan,
                "service_restart_required": true, "planned_actions": actions,
                "binding_config": binding.path, "binding_backup": binding.backup_path,
                "binding_original_existed": binding.original.is_some(),
                "binding_restore_command": binding.restore_command(),
            }),
            format,
        );
    }
    let recovery_command = format!(
        "satelle host storage migrate --host {} --to {} --no-input --yes",
        argument(alias),
        argument(&command.to.display().to_string())
    );
    let trusted = super::trusted_profile_allows_mutation(
        config.load()?,
        alias,
        satelle_core::MutationCommandFamily::HostStorageMigrate,
        command.yes
            || (!command.no_input && !format.is_structured() && std::io::stdin().is_terminal()),
    )?;
    if !super::confirm_storage_maintenance(
        &actions,
        recovery_command,
        command.yes || trusted,
        command.no_input,
        format,
    )? {
        return super::print_storage_cancelled(alias, "migrate", format);
    }
    // Reject a changed effective binding before taking the backup or mutating
    // the Host. The writer separately checks its original file before replace.
    let fresh = config.fresh();
    if fresh.resolve_host(Some(alias))?.config != host.config {
        return Err(failure(SatelleError::state_conflict()));
    }
    binding.backup().map_err(failure)?;
    let stage = match host.config.transport {
        satelle_core::TransportKind::Local => transport::storage_migration::apply_local(
            &host,
            &command.to,
            &plan,
            &operation_id,
            &binding,
            &config,
        ),
        _ => transport::storage_migration::apply_remote(
            &host,
            &command.to,
            &plan,
            &operation_id,
            &binding,
            &config,
        ),
    }
    .map_err(failure)?;
    print_report(
        &serde_json::json!({
            "schema_version": "satelle.storage-migration.v1", "host": alias, "dry_run": false,
            "operation_id": operation_id, "status": "completed", "stage": stage,
            "binding_config": binding.path, "binding_backup": binding.backup_path,
            "binding_restore_command": binding.restore_command(), "source_preserved": true,
            "cleanup_command": format!("satelle host storage source cleanup --host {} --operation-id {} --yes",
                argument(alias), argument(&operation_id)),
        }),
        format,
    )
}

fn print_report(
    report: &serde_json::Value,
    format: super::OutputFormat,
) -> Result<(), super::CliFailure> {
    if format.is_structured() {
        format.print(report).map_err(super::failure)
    } else {
        // A migration report contains paths, checks, and recovery commands.
        // Preserve the complete reviewable record in the terminal too.
        super::print_json(report).map_err(super::failure)
    }
}

pub(super) fn cleanup(
    command: super::HostStorageSourceCleanupCommand,
    config: super::ConfigContext<'_>,
    format: super::OutputFormat,
) -> Result<(), super::CliFailure> {
    let host = config.resolve_host(Some(&command.host))?;
    let plan = (command.dry_run || !command.yes)
        .then(|| {
            super::transport::storage_migration::cleanup_source(&host, &command.operation_id, false)
        })
        .transpose()
        .map_err(super::failure)?;
    if command.dry_run {
        return print_report(
            &serde_json::json!({"schema_version": "satelle.storage-migration-cleanup.v1", "host": host.alias, "dry_run": true, "cleanup": plan.expect("dry-run loads the cleanup plan")}),
            format,
        );
    }
    let recovery = format!(
        "satelle host storage source cleanup --host {} --operation-id {} --no-input --yes",
        argument(&host.alias),
        argument(&command.operation_id)
    );
    let actions = plan
        .as_ref()
        .map(|plan| {
            vec![format!(
                "delete {} preserved source files",
                plan.files.len()
            )]
        })
        .unwrap_or_default();
    if !super::confirm_storage_maintenance(
        &actions,
        recovery,
        command.yes,
        command.no_input,
        format,
    )? {
        return super::print_storage_cancelled(&host.alias, "source-cleanup", format);
    }
    let cleanup =
        super::transport::storage_migration::cleanup_source(&host, &command.operation_id, true)
            .map_err(super::failure)?;
    print_report(
        &serde_json::json!({"schema_version": "satelle.storage-migration-cleanup.v1", "host": host.alias, "dry_run": false, "cleanup": cleanup}),
        format,
    )
}

#[derive(clap::Subcommand, Debug)]
pub(super) enum OfflineCommand {
    Plan {
        #[arg(long)]
        source_paths: String,
        #[arg(long)]
        to: PathBuf,
    },
    Stage {
        #[arg(long)]
        source_paths: String,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        yes: bool,
    },
    Rollback {
        #[arg(long)]
        source_root: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        yes: bool,
    },
}

pub(super) fn run_offline(command: OfflineCommand) -> Result<(), super::CliFailure> {
    let parse = |encoded: &str| {
        serde_json::from_str::<DaemonResolvedPathSet>(encoded)
            .map_err(|_| super::failure(SatelleError::invalid_usage("invalid source path set")))
    };
    let response = match command {
        OfflineCommand::Plan { source_paths, to } => {
            let plan =
                satelle_host::HostService::plan_storage_migration(&parse(&source_paths)?, &to)
                    .map_err(super::failure)?;
            serde_json::json!({"schema_version": "satelle.storage-migration.plan.v1", "plan": plan})
        }
        OfflineCommand::Stage {
            source_paths,
            to,
            operation_id,
            yes: true,
        } => {
            let stage = satelle_host::HostService::stage_storage_migration(
                &parse(&source_paths)?,
                &to,
                &operation_id,
            )
            .map_err(super::failure)?;
            serde_json::json!({"schema_version": "satelle.storage-migration.stage.v1", "stage": stage})
        }
        OfflineCommand::Rollback {
            source_root,
            operation_id,
            yes: true,
        } => {
            satelle_host::HostService::rollback_storage_migration(&source_root, &operation_id)
                .map_err(super::failure)?;
            serde_json::json!({"schema_version": "satelle.storage-migration.rollback.v1", "operation_id": operation_id, "source_root": source_root})
        }
        _ => {
            return Err(super::failure(SatelleError::invalid_usage(
                "offline storage mutation requires --yes",
            )));
        }
    };
    super::print_json(&response).map_err(super::failure)
}

/// The service and Controller binding must agree after a migration. Keep the
/// original bytes until both are verified so rollback preserves comments and
/// private references without copying effective project values into user config.
pub(crate) struct BindingUpdate {
    pub path: PathBuf,
    pub backup_path: PathBuf,
    original: Option<String>,
    updated: String,
}

impl BindingUpdate {
    pub fn plan(
        resolved: &ResolvedConfig,
        host_alias: &str,
        destination: &DaemonResolvedPathSet,
        operation_id: &str,
    ) -> Result<Self, SatelleError> {
        // Includes run before their parents. The last user file containing the
        // binding owns the whole object, including fields omitted by that file.
        let mut selected = None;
        for source in resolved.sources.files.iter().rev() {
            if source.source != ConfigSourceKind::UserConfig {
                continue;
            }
            let original = read_config(&source.path)?;
            let document = parse_config(&original)?;
            if document
                .get("hosts")
                .and_then(|hosts| hosts.get(host_alias))
                .is_some()
            {
                selected = Some((source.path.clone(), Some(original), document));
                break;
            }
        }
        let (path, original, mut document) = match selected {
            Some(selected) => selected,
            None if host_alias == satelle_core::LOCAL_DEMO_HOST => {
                let original = match std::fs::symlink_metadata(&resolved.user_config_path) {
                    Ok(_) => Some(read_config(&resolved.user_config_path)?),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(_) => return Err(config_error()),
                };
                let mut document = parse_config(original.as_deref().unwrap_or(""))?;
                let defaults = satelle_core::SatelleConfig::defaults();
                let binding = defaults.hosts.get(host_alias).expect("built-in local Host");
                let encoded = toml::to_string(binding).map_err(|_| config_error())?;
                let binding = parse_config(&encoded)?.as_table().clone();
                if !document.contains_key("hosts") {
                    document.insert("hosts", Item::Table(Table::new()));
                }
                document["hosts"][host_alias] = Item::Table(binding);
                (resolved.user_config_path.clone(), original, document)
            }
            None => {
                return Err(SatelleError::invalid_usage(
                    "storage migration requires a user-owned Host Binding",
                ));
            }
        };
        let binding = document
            .get_mut("hosts")
            .and_then(|hosts| hosts.get_mut(host_alias))
            .and_then(Item::as_table_like_mut)
            .ok_or_else(config_error)?;
        binding.insert(
            "daemon_state_dir",
            toml_edit::value(&destination.state_root),
        );
        binding.insert(
            "daemon_log_dir",
            toml_edit::value(&destination.operator_log_root),
        );
        let cwd = std::env::current_dir().map_err(|_| config_error())?;
        let backup_path = satelle_core::resolve_path_set(&cwd)?
            .state_root
            .join("storage-migration")
            .join(operation_id)
            .join("original.toml");
        Ok(Self {
            path,
            backup_path,
            original,
            updated: document.to_string(),
        })
    }

    pub fn backup(&self) -> Result<(), SatelleError> {
        self.require_original()?;
        super::host_trust::create_owner_only_directory_tree(
            self.backup_path
                .parent()
                .expect("migration backup has a parent"),
            &self.path,
            &self.restore_command(),
        )?;
        satelle_core::persist_new_owner_only_config_file(
            &self.backup_path,
            self.original.as_deref().unwrap_or("").as_bytes(),
        )
        .map_err(|_| config_error())
    }

    pub fn apply(&self) -> Result<(), SatelleError> {
        self.require_original()?;
        if self.original.is_some() {
            super::host_trust::persist_config(
                &self.path,
                self.updated.as_bytes(),
                Some(&self.restore_command()),
            )
        } else {
            super::host_trust::create_owner_only_directory_tree(
                self.path.parent().ok_or_else(config_error)?,
                &self.path,
                &self.restore_command(),
            )?;
            satelle_core::persist_new_owner_only_config_file(&self.path, self.updated.as_bytes())
                .map_err(|_| config_error())
        }
    }

    pub fn apply_for_host(
        &self,
        config: &super::ConfigContext<'_>,
        host: &super::SelectedHost,
    ) -> Result<(), SatelleError> {
        if config
            .fresh()
            .resolve_host(Some(&host.alias))
            .map_err(|failure| failure.error)?
            .config
            != host.config
        {
            return Err(SatelleError::state_conflict());
        }
        self.apply()
    }

    /// A failed write can leave either version, but never authorizes replacing
    /// a third version written by the operator while migration was running.
    pub fn rollback(&self) -> Result<(), SatelleError> {
        let current = self.current()?;
        if current == self.original {
            return Ok(());
        }
        if current.as_deref() != Some(self.updated.as_str()) {
            return Err(config_error());
        }
        if let Some(original) = &self.original {
            super::host_trust::persist_config(
                &self.path,
                original.as_bytes(),
                Some(&self.restore_command()),
            )
        } else {
            std::fs::remove_file(&self.path).map_err(|_| config_error())
        }
    }

    pub fn restore_command(&self) -> String {
        if self.original.is_some() {
            return super::config_repair::restore_command(&self.backup_path, &self.path);
        }
        #[cfg(windows)]
        return format!(
            "Remove-Item -LiteralPath '{}'",
            self.path.display().to_string().replace('\'', "''")
        );
        #[cfg(not(windows))]
        format!("rm -- {}", argument(&self.path.display().to_string()))
    }

    fn current(&self) -> Result<Option<String>, SatelleError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => read_config(&self.path).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(config_error()),
        }
    }

    fn require_original(&self) -> Result<(), SatelleError> {
        if self.current()? != self.original {
            return Err(config_error());
        }
        Ok(())
    }
}

fn read_config(path: &Path) -> Result<String, SatelleError> {
    satelle_core::read_owner_controlled_config_file(path).map_err(|_| config_error())
}

fn parse_config(contents: &str) -> Result<DocumentMut, SatelleError> {
    contents.parse().map_err(|_| config_error())
}

fn config_error() -> SatelleError {
    SatelleError::config_error(
        "storage migration cannot update the Host Binding; verify file ownership and review concurrent edits",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_update(root: &Path) -> BindingUpdate {
        BindingUpdate {
            path: root.join("config.toml"),
            backup_path: root.join("migration").join("original.toml"),
            original: Some("# retained comment\n[hosts.local-demo]\ntransport = 'local'\n".into()),
            updated: "# retained comment\n[hosts.local-demo]\ntransport = 'local'\ndaemon_state_dir = '/moved/state'\n".into(),
        }
    }

    #[test]
    fn binding_backup_and_rollback_preserve_exact_bytes_and_operator_edits() {
        let state = satelle_host::test_support::TestStateDir::new().unwrap();
        let update = binding_update(state.path());
        let original = update.original.as_ref().unwrap();
        satelle_core::persist_new_owner_only_config_file(&update.path, original.as_bytes())
            .unwrap();
        update.backup().unwrap();
        assert_eq!(read_config(&update.backup_path).unwrap(), *original);
        update.apply().unwrap();
        assert_eq!(read_config(&update.path).unwrap(), update.updated);
        update.rollback().unwrap();
        assert_eq!(read_config(&update.path).unwrap(), *original);
        update.apply().unwrap();
        let operator_edit = "# changed while migration was running\n";
        super::super::host_trust::persist_config(&update.path, operator_edit.as_bytes(), None)
            .unwrap();
        assert!(update.rollback().is_err());
        assert_eq!(read_config(&update.path).unwrap(), operator_edit);
        assert_eq!(read_config(&update.backup_path).unwrap(), *original);
    }

    #[test]
    fn concurrent_edit_blocks_backup_and_migration_created_config_can_roll_back() {
        let state = satelle_host::test_support::TestStateDir::new().unwrap();
        let mut update = binding_update(state.path());
        satelle_core::persist_new_owner_only_config_file(&update.path, b"# new user edit\n")
            .unwrap();
        assert!(update.backup().is_err());
        assert!(!update.backup_path.exists());
        std::fs::remove_file(&update.path).unwrap();
        update.original = None;
        update.backup().unwrap();
        update.apply().unwrap();
        update.rollback().unwrap();
        assert!(!update.path.exists());
        assert!(update.backup_path.exists());
    }
}
