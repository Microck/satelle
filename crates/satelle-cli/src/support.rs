use super::output::OutputFormat;
use super::read;
use super::transport::transport_for;
use super::{
    CliFailure, ConfigContext, SelectedHost, SupportBundleCommand, SupportCommand, failure,
    print_json, redacted_config_json,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use satelle_core::{SatelleError, open_new_owner_only_file, utc_now};
use satelle_host::LogPageQuery;
use serde::Serialize;
use serde_json::{Value, json};
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

const SUPPORT_BUNDLE_SCHEMA_VERSION: &str = "satelle.support.bundle.v1";
const REDACTION_POLICY_VERSION: &str = "satelle.redaction.v1";
const MAX_LOG_ENTRIES: usize = 2000;

/// The manifest embedded in the exported archive. It describes the collection
/// only: the outer artifact path and byte size belong to the command result
/// because they are not known until the archive is written.
#[derive(Serialize)]
struct BundleManifest {
    schema_version: &'static str,
    status: &'static str,
    host: String,
    included: Vec<String>,
    not_collected: Vec<NotCollectedCategory>,
    redaction_policy_version: &'static str,
    created_at: String,
}

/// The command's final JSON contract. Field set is frozen by the support
/// bundle facts: status, source Host, output path, artifact byte size,
/// included and not_collected categories, redaction policy version, created_at.
#[derive(Serialize)]
struct SupportBundleReport {
    schema_version: &'static str,
    status: &'static str,
    host: String,
    output: String,
    artifact_byte_size: u64,
    included: Vec<String>,
    not_collected: Vec<NotCollectedCategory>,
    redaction_policy_version: &'static str,
    created_at: String,
}

#[derive(Clone, Serialize)]
struct NotCollectedCategory {
    category: String,
    reason: String,
}

struct ArchiveFile {
    name: String,
    body: Vec<u8>,
}

pub(super) fn run_support(
    command: SupportCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    match command {
        SupportCommand::Bundle(command) => export_bundle(command, config, format),
    }
}

fn export_bundle(
    command: SupportBundleCommand,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(), CliFailure> {
    let output = command.output.clone().ok_or_else(|| {
        failure(SatelleError::invalid_usage(
            "support bundle requires --output <path>",
        ))
    })?;
    if command.no_input && !command.yes {
        return Err(failure(SatelleError::input_required(
            "support bundle needs --yes when --no-input is used",
        )));
    }
    let resolved = config.load()?;
    let host = resolved
        .resolve_host_with_project_source(command.host.as_deref())
        .map(SelectedHost::from)
        .map_err(failure)?;

    let created_at = utc_now();
    let mut included = Vec::new();
    let mut not_collected = Vec::new();
    let mut files = Vec::new();
    let mut structured_errors = Vec::new();

    collect_file(
        "configuration",
        &mut included,
        &mut not_collected,
        &mut files,
        configuration_json(&host, &config),
    );
    collect_file(
        "version",
        &mut included,
        &mut not_collected,
        &mut files,
        Ok(version_json()),
    );

    match readiness_json(&host) {
        Ok((value, findings)) => {
            structured_errors.extend(findings);
            collect_file(
                "readiness",
                &mut included,
                &mut not_collected,
                &mut files,
                Ok(value),
            );
        }
        Err(reason) => {
            structured_errors.push(json!({
                "category": "readiness",
                "message": reason,
            }));
            not_collected.push(NotCollectedCategory {
                category: "readiness".to_string(),
                reason,
            });
        }
    }

    match logs_json(&host) {
        Ok(value) => collect_file(
            "logs",
            &mut included,
            &mut not_collected,
            &mut files,
            Ok(value),
        ),
        Err(reason) => {
            structured_errors.push(json!({
                "category": "logs",
                "message": reason,
            }));
            not_collected.push(NotCollectedCategory {
                category: "logs".to_string(),
                reason,
            });
        }
    }

    match transport_json(&host) {
        Ok(value) => collect_file(
            "transport",
            &mut included,
            &mut not_collected,
            &mut files,
            Ok(value),
        ),
        Err(reason) => {
            structured_errors.push(json!({
                "category": "transport",
                "message": reason,
            }));
            not_collected.push(NotCollectedCategory {
                category: "transport".to_string(),
                reason,
            });
        }
    }

    // The Host diagnostic APIs do not expose setup ledger summaries yet, so
    // the bundle reports the category as not_collected instead of guessing.
    not_collected.push(NotCollectedCategory {
        category: "setup_ledger".to_string(),
        reason: "setup ledger summaries are not exposed by the Host diagnostic APIs".to_string(),
    });

    collect_file(
        "errors",
        &mut included,
        &mut not_collected,
        &mut files,
        Ok(json!({ "errors": structured_errors })),
    );

    let status = if not_collected.is_empty() {
        "ok"
    } else if included.is_empty() {
        "failed"
    } else {
        "partial"
    };

    let manifest = BundleManifest {
        schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION,
        status,
        host: host.alias.clone(),
        included: included.clone(),
        not_collected: not_collected.clone(),
        redaction_policy_version: REDACTION_POLICY_VERSION,
        created_at: created_at.clone(),
    };
    let manifest_body = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        failure(SatelleError::config_error(
            "could not encode the support bundle manifest",
            Some(error.to_string()),
        ))
    })?;
    files.insert(
        0,
        ArchiveFile {
            name: "manifest.json".to_string(),
            body: manifest_body,
        },
    );

    let archive = write_tar_gz(&files).map_err(|reason| {
        failure(SatelleError::config_error(
            "could not encode the support bundle archive",
            Some(reason),
        ))
    })?;
    persist_owner_only_file(&output, &archive)?;

    let report = SupportBundleReport {
        schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION,
        status,
        host: host.alias.clone(),
        output: output.display().to_string(),
        artifact_byte_size: archive.len() as u64,
        included,
        not_collected,
        redaction_policy_version: REDACTION_POLICY_VERSION,
        created_at,
    };

    if format.is_json() {
        print_json(&report).map_err(failure)
    } else {
        println!("Status: {}", report.status);
        println!("Host: {}", report.host);
        println!("Output: {}", report.output);
        println!("Bytes: {}", report.artifact_byte_size);
        println!("Included: {}", report.included.join(", "));
        if !report.not_collected.is_empty() {
            println!(
                "Not collected: {}",
                report
                    .not_collected
                    .iter()
                    .map(|item| item.category.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(())
    }
}

fn collect_file(
    category: &str,
    included: &mut Vec<String>,
    not_collected: &mut Vec<NotCollectedCategory>,
    files: &mut Vec<ArchiveFile>,
    result: Result<Value, String>,
) {
    match result {
        Ok(value) => match serde_json::to_vec_pretty(&value) {
            Ok(body) => {
                included.push(category.to_string());
                files.push(ArchiveFile {
                    name: format!("{category}.json"),
                    body,
                });
            }
            Err(error) => not_collected.push(NotCollectedCategory {
                category: category.to_string(),
                reason: error.to_string(),
            }),
        },
        Err(reason) => not_collected.push(NotCollectedCategory {
            category: category.to_string(),
            reason,
        }),
    }
}

fn configuration_json(host: &SelectedHost, config: &ConfigContext<'_>) -> Result<Value, String> {
    let check = read::config_check_report(Some(host.alias.clone()), false, config.clone())
        .map_err(|failure| failure.error.message.clone())?;
    let resolved = config
        .load()
        .map_err(|failure| failure.error.message.clone())?;
    Ok(json!({
        "check": check,
        "redacted_config": redacted_config_json(&resolved.config, false),
    }))
}

fn version_json() -> Value {
    json!({
        "cli_version": env!("CARGO_PKG_VERSION"),
        "product": "satelle",
    })
}

fn readiness_json(host: &SelectedHost) -> Result<(Value, Vec<Value>), String> {
    let report = read::doctor_for_host(host, Some("all")).map_err(collection_error)?;
    let findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity != "info")
        .map(|finding| serde_json::to_value(finding).unwrap_or_else(|_| json!({})))
        .collect();
    let value = serde_json::to_value(&report).map_err(|error| error.to_string())?;
    Ok((value, findings))
}

fn logs_json(host: &SelectedHost) -> Result<Value, String> {
    let query = LogPageQuery::tail(MAX_LOG_ENTRIES).map_err(|error| error.to_string())?;
    let page = transport_for(host)
        .map_err(collection_error)?
        .logs(&query)
        .map_err(|error| error.message)?;
    serde_json::to_value(page.entries()).map_err(|error| error.to_string())
}

fn transport_json(host: &SelectedHost) -> Result<Value, String> {
    let status = read::host_status_for_host(host).map_err(collection_error)?;
    let paths = read::paths_report(Some(host)).map_err(collection_error)?;
    Ok(json!({
        "host_status": status,
        "paths": paths,
    }))
}

fn collection_error(failure: CliFailure) -> String {
    failure.error.message
}

fn write_tar_gz(files: &[ArchiveFile]) -> Result<Vec<u8>, String> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for file in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(file.body.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, &file.name, Cursor::new(file.body.as_slice()))
            .map_err(|error| error.to_string())?;
    }
    archive
        .into_inner()
        .map_err(|error| error.to_string())?
        .finish()
        .map_err(|error| error.to_string())
}

fn persist_owner_only_file(path: &Path, body: &[u8]) -> Result<(), CliFailure> {
    if path.file_name().is_none() {
        return Err(failure(SatelleError::invalid_usage(
            "--output must name a new destination file",
        )));
    }
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if path.try_exists().map_err(|error| {
        failure(SatelleError::config_error(
            format!(
                "could not inspect support bundle destination {}",
                path.display()
            ),
            Some(error.to_string()),
        ))
    })? {
        return Err(failure(SatelleError::invalid_usage(format!(
            "support bundle destination {} already exists",
            path.display()
        ))));
    }
    if !parent.as_os_str().is_empty() && parent != Path::new(".") {
        fs::create_dir_all(parent).map_err(|error| {
            failure(SatelleError::config_error(
                format!(
                    "could not create support bundle parent {}",
                    parent.display()
                ),
                Some(error.to_string()),
            ))
        })?;
    }
    let mut file = open_new_owner_only_file(path).map_err(|error| {
        failure(SatelleError::config_error(
            format!(
                "could not create owner-only support bundle {}",
                path.display()
            ),
            Some(error.to_string()),
        ))
    })?;
    file.write_all(body).map_err(|error| {
        failure(SatelleError::config_error(
            "could not write the support bundle archive",
            Some(error.to_string()),
        ))
    })?;
    file.flush().map_err(|error| {
        failure(SatelleError::config_error(
            "could not flush the support bundle archive",
            Some(error.to_string()),
        ))
    })?;
    file.sync_all().map_err(|error| {
        failure(SatelleError::config_error(
            "could not sync the support bundle archive",
            Some(error.to_string()),
        ))
    })?;
    Ok(())
}
