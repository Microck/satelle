use super::output::{CONFIG_REPAIR_SCHEMA_VERSION, OutputArgs, OutputFormat};
use super::{CliFailure, failure};
use clap::Args;
use satelle_core::config_repair::{KeyRepair, RepairFile, RepairPlan, manual_action};
use satelle_core::{ConfigSourceKind, ErrorCode, MutationCommandFamily, SatelleError};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, TableLike};

#[derive(Args, Debug)]
pub(super) struct ConfigRepairCommand {
    /// Select one loaded local configuration file; project files require this flag.
    #[arg(long)]
    file: Option<PathBuf>,
    /// Scope Trusted Profile consent to edits inside this Host Binding.
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
    /// Accept the displayed local configuration edits and private backup.
    #[arg(long)]
    yes: bool,
    #[arg(long)]
    no_input: bool,
    #[command(flatten)]
    pub output_args: OutputArgs,
}

#[derive(Serialize)]
struct RepairReport {
    schema_version: &'static str,
    status: &'static str,
    dry_run: bool,
    changed: bool,
    files: Vec<FileReport>,
}

#[derive(Serialize)]
struct FileReport {
    path: PathBuf,
    source: ConfigSourceKind,
    addressed_diagnostics: Vec<KeyRepair>,
    planned_write: bool,
    backup_path: PathBuf,
    backup_created: bool,
    original_digest: String,
    repaired_digest: String,
    restore_command: String,
    diff: String,
}

pub(super) fn run(
    command: ConfigRepairCommand,
    flag_profile: Option<&str>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let cwd = std::env::current_dir().map_err(|_| {
        failure(SatelleError::config_error(
            "could not determine the local project directory",
            None,
        ))
    })?;
    let plan = satelle_core::config_repair::plan(&cwd, flag_profile, command.file.as_deref())
        .map_err(failure)?;
    let host = plan
        .resolved
        .resolve_host(command.host.as_deref())
        .map_err(failure)?;
    let host = super::SelectedHost::from(host);
    plan.resolved
        .config_check_contexts(command.host.as_deref(), false)
        .map_err(failure)?;
    let provider =
        super::resolve_provider_selection(&plan.resolved, &host, None, None, false, false)?;
    if provider.missing_auth_source_name().is_some() {
        return Err(failure(manual_action(
            &plan.resolved.user_config_path,
            ErrorCode::ModelProviderBindingMissing,
        )));
    }
    let mut report = RepairReport {
        schema_version: CONFIG_REPAIR_SCHEMA_VERSION,
        status: "unchanged",
        dry_run: command.dry_run,
        changed: false,
        files: Vec::new(),
    };
    let Some(file) = plan.file.as_ref().filter(|file| !file.repairs.is_empty()) else {
        return finish(&report, format);
    };
    // A local project file may be readable without being safe to replace.
    // Repair must never change its owner or relax its current writer policy.
    satelle_core::read_owner_controlled_config_file(&file.source.path)
        .map_err(|_| failure(manual_action(&file.source.path, ErrorCode::ConfigError)))?;
    let repaired = edit_document(file).map_err(failure)?;
    let backup_directory = satelle_core::resolve_path_set(&cwd)
        .map_err(failure)?
        .state_root
        .join("config-repair")
        .join(uuid::Uuid::now_v7().to_string());
    let backup_path = backup_directory.join("original.toml");
    let restore_command = restore_command(&backup_path, &file.source.path);
    report.status = "planned";
    report.files.push(FileReport {
        path: file.source.path.clone(),
        source: file.source.source,
        addressed_diagnostics: file.repairs.clone(),
        planned_write: true,
        backup_path,
        backup_created: false,
        original_digest: super::self_update::digest_hex(
            &Sha256::digest(file.original.as_bytes()).into(),
        ),
        repaired_digest: super::self_update::digest_hex(
            &Sha256::digest(repaired.as_bytes()).into(),
        ),
        restore_command: restore_command.clone(),
        diff: redacted_diff(file, &repaired).map_err(failure)?,
    });
    if command.dry_run {
        return finish(&report, format);
    }
    let host_scoped = command.host.as_deref().is_some_and(|host| {
        file.source.source == ConfigSourceKind::UserConfig
            && file.repairs.iter().all(|repair| {
                repair.path.len() >= 3 && repair.path[0] == "hosts" && repair.path[1] == host
            })
    });
    let interactive = !command.no_input && io::stdin().is_terminal();
    let trusted = host_scoped
        && super::trusted_profile_allows_mutation(
            &plan.resolved,
            &host.alias,
            MutationCommandFamily::ConfigRepair,
            command.yes || interactive,
        )?;
    if !command.yes && !trusted {
        if !interactive {
            let mut error = repair_error(
                ErrorCode::ConfigRepairConsentRequired,
                "local configuration repair needs explicit mutation consent",
                "review satelle config repair --dry-run, then repeat the same selection with --yes",
            );
            error.details.insert(
                "preview".into(),
                serde_json::to_value(&report).expect("the repair report is serializable"),
            );
            return Err(failure(error));
        }
        print_human(&report, &mut io::stderr()).map_err(|error| {
            failure(SatelleError::config_error(
                "could not display the config repair preview",
                Some(error.to_string()),
            ))
        })?;
        let confirmed = cliclack::confirm("Apply these local configuration edits?")
            .initial_value(false)
            .interact()
            .map_err(|error| {
                failure(SatelleError::config_error(
                    "could not read config repair confirmation",
                    Some(error.to_string()),
                ))
            })?;
        if !confirmed {
            report.status = "cancelled";
            return finish(&report, format);
        }
    }
    verify_inputs(&plan).map_err(failure)?;
    super::host_trust::create_owner_only_directory_tree(
        &backup_directory,
        &file.source.path,
        &restore_command,
    )
    .map_err(failure)?;
    let item = &mut report.files[0];
    satelle_core::persist_new_owner_only_config_file(&item.backup_path, file.original.as_bytes())
        .map_err(|_| failure(repair_error(
            ErrorCode::ConfigError,
            "could not create and verify the private configuration backup; configuration was not changed",
            "correct the local state directory access, then retry satelle config repair --dry-run",
        )))?;
    item.backup_created = true;
    // Consent and precedence depend on every loaded input, not just the file
    // being changed. Check the captured bytes again after creating the backup.
    let applied = verify_inputs(&plan).and_then(|()| {
        super::host_trust::persist_config(
            &file.source.path,
            repaired.as_bytes(),
            Some(&restore_command),
        )
    });
    if let Err(mut error) = applied {
        error.recovery_command = Some(restore_command);
        error
            .details
            .insert("backup_path".into(), json!(item.backup_path));
        return Err(failure(error));
    }
    report.changed = true;
    report.status = "applied";
    finish(&report, format)
}

fn edit_document(file: &RepairFile) -> Result<String, SatelleError> {
    let invalid = || manual_action(&file.source.path, ErrorCode::ConfigError);
    let mut document = file
        .original
        .parse::<DocumentMut>()
        .map_err(|_| invalid())?;
    for repair in &file.repairs {
        let mut table: &mut dyn TableLike = document.as_table_mut();
        for name in &repair.path[..repair.path.len() - 1] {
            table = table
                .get_mut(name)
                .and_then(Item::as_table_like_mut)
                .ok_or_else(invalid)?;
        }
        let old = repair.path.last().expect("a schema key has a path");
        let key = table.key(old).ok_or_else(invalid)?;
        let leaf = key.leaf_decor().clone();
        let dotted = key.dotted_decor().clone();
        let value = table.remove(old).ok_or_else(invalid)?;
        table.insert(&repair.corrected_key, value);
        let mut key = table
            .key_mut(&repair.corrected_key)
            .expect("the repaired key was inserted");
        *key.leaf_decor_mut() = leaf;
        *key.dotted_decor_mut() = dotted;
    }
    let repaired = document.to_string();
    let mut value: toml::Value = toml::from_str(&repaired).map_err(|_| invalid())?;
    value
        .as_table_mut()
        .expect("configuration is a TOML table")
        .remove("include");
    if value != file.repaired_value {
        return Err(invalid());
    }
    Ok(repaired)
}

fn redacted_diff(file: &RepairFile, repaired: &str) -> Result<String, SatelleError> {
    let invalid = || manual_action(&file.source.path, ErrorCode::ConfigError);
    let value: toml::Value = toml::from_str(repaired).map_err(|_| invalid())?;
    let mut after = serde_json::to_value(value).map_err(|_| invalid())?;
    super::redact_schema_marked_config_values(&mut after, &mut Vec::new(), false);
    // Start from the validated, redacted shape, then reverse only key names.
    // Raw comments and invalid raw fields never enter the preview.
    let mut before = after.clone();
    for repair in file.repairs.iter().rev() {
        let mut parent = &mut before;
        for name in &repair.path[..repair.path.len() - 1] {
            parent = parent.get_mut(name).ok_or_else(invalid)?;
        }
        let parent = parent.as_object_mut().ok_or_else(invalid)?;
        let value = parent.remove(&repair.corrected_key).ok_or_else(invalid)?;
        parent.insert(
            repair.path.last().expect("a schema key has a path").clone(),
            value,
        );
    }
    let before = serde_json::to_string_pretty(&before).expect("redacted JSON is serializable");
    let after = serde_json::to_string_pretty(&after).expect("redacted JSON is serializable");
    Ok(unified_diff(&before, &after, &file.source.path))
}

fn unified_diff(before: &str, after: &str, path: &Path) -> String {
    let before: Vec<_> = before.lines().collect();
    let after: Vec<_> = after.lines().collect();
    let prefix = before
        .iter()
        .zip(&after)
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = before[prefix..]
        .iter()
        .rev()
        .zip(after[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let start = prefix.saturating_sub(3);
    let before_end = (before.len() - suffix + 3).min(before.len());
    let after_end = (after.len() - suffix + 3).min(after.len());
    let mut diff = format!(
        "--- {}\n+++ {}\n@@ -{},{} +{},{} @@\n",
        path.display(),
        path.display(),
        start + 1,
        before_end - start,
        start + 1,
        after_end - start
    );
    for line in &before[start..prefix] {
        diff.push_str(&format!(" {line}\n"));
    }
    for line in &before[prefix..before.len() - suffix] {
        diff.push_str(&format!("-{line}\n"));
    }
    for line in &after[prefix..after.len() - suffix] {
        diff.push_str(&format!("+{line}\n"));
    }
    for line in &after[after.len() - suffix..after_end] {
        diff.push_str(&format!(" {line}\n"));
    }
    diff
}

fn verify_inputs(plan: &RepairPlan) -> Result<(), SatelleError> {
    for (source, original) in &plan.inputs {
        let current = match source.source {
            ConfigSourceKind::UserConfig => {
                satelle_core::read_owner_controlled_config_file(&source.path)
            }
            ConfigSourceKind::ProjectConfig => {
                satelle_core::read_bounded_regular_file_no_follow(&source.path, 1024 * 1024)
                    .and_then(|bytes| {
                        String::from_utf8(bytes).map_err(|_| satelle_core::SecureFileError::NotUtf8)
                    })
            }
        };
        if current.as_ref().ok() != Some(original) {
            return Err(repair_error(
                ErrorCode::ConfigRepairSourceChanged,
                "configuration changed after the repair preview; no repair was applied",
                "rerun satelle config repair --dry-run and review the current configuration",
            ));
        }
    }
    Ok(())
}

fn repair_error(code: ErrorCode, message: &str, recovery: &str) -> SatelleError {
    SatelleError {
        code,
        message: message.into(),
        recovery_command: Some(recovery.into()),
        source_detail: None,
        details: [("mutated".into(), json!(false))].into(),
    }
}

fn restore_command(backup: &Path, original: &Path) -> String {
    #[cfg(windows)]
    {
        let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "''"));
        format!(
            "Copy-Item -LiteralPath {} -Destination {} -Force",
            quote(backup),
            quote(original)
        )
    }
    #[cfg(not(windows))]
    {
        format!(
            "cp -- {} {}",
            super::shell_argument(&backup.display().to_string()),
            super::shell_argument(&original.display().to_string())
        )
    }
}

fn finish(report: &RepairReport, format: OutputFormat) -> Result<(), CliFailure> {
    if format.is_json() {
        super::print_json(report).map_err(failure)
    } else {
        print_human(report, &mut io::stdout()).map_err(|error| {
            failure(SatelleError::config_error(
                "could not write the config repair report",
                Some(error.to_string()),
            ))
        })
    }
}

fn print_human(report: &RepairReport, output: &mut impl Write) -> io::Result<()> {
    writeln!(output, "Config repair: {}", report.status)?;
    for file in &report.files {
        writeln!(output, "File: {}", file.path.display())?;
        writeln!(output, "Backup: {}", file.backup_path.display())?;
        writeln!(
            output,
            "SHA-256: {} -> {}",
            file.original_digest, file.repaired_digest
        )?;
        writeln!(output, "Restore: {}", file.restore_command)?;
        write!(output, "{}", file.diff)?;
    }
    Ok(())
}
