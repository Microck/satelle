use super::output::{OutputFormat, StatusReport};
use super::transport::transport_for;
use super::{
    CONFIG_CHECK_SCHEMA_VERSION, CONFIG_EXPLAIN_SCHEMA_VERSION, CliFailure, ConfigContext,
    HostSessionsReport, LOCAL_DEMO_HOST, PATHS_SCHEMA_VERSION, PublicSession, SessionId,
    apply_current_desktop_selection, daemon_path_overrides_json, env_source,
    experimental_provider_computer_use_json, failure, model_provider_config_json,
    redacted_config_json, resolve_path_set, yolo_config_json,
};
use satelle_core::{DoctorReport, SatelleError};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::str::FromStr;

pub(super) fn config_check_report(
    host: Option<String>,
    all: bool,
    config_context: ConfigContext<'_>,
    json_errors: bool,
) -> Result<Value, CliFailure> {
    let config = config_context.load(json_errors)?;
    let selected_profile = config
        .selected_profile
        .as_ref()
        .map(|profile| profile.name.as_str());
    let selected_profile_source = config
        .selected_profile
        .as_ref()
        .map_or("default", |profile| profile.source.as_str());
    let selected_host = config
        .resolve_host(host.as_deref())
        .map(|(alias, _)| alias)
        .map_err(|error| failure(error, json_errors))?;
    Ok(json!({
        "schema_version": CONFIG_CHECK_SCHEMA_VERSION,
        "status": "ok",
        "mode": if all { "all" } else { "selected" },
        "selected_host": selected_host,
        "selected_profile": selected_profile,
        "checked_files": [config.user_config_path, config.project_config_path],
        "checks": ["toml_parse", "host_resolution"],
        "checked_contexts": [{
            "host": selected_host,
            "profile": selected_profile,
            "source": selected_profile_source,
            "status": "ok",
            "checks": ["toml_parse", "host_resolution"],
            "errors": [],
            "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
        }],
        "errors": [],
        "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
        "recovery_commands": [],
    }))
}

pub(super) fn config_explain_report(
    host: Option<String>,
    show_secret_references: bool,
    config_context: ConfigContext<'_>,
    json_errors: bool,
) -> Result<Value, CliFailure> {
    let config = config_context.load(json_errors)?;
    let selected_profile = config
        .selected_profile
        .as_ref()
        .map(|profile| profile.name.as_str());
    let selected_profile_source = config
        .selected_profile
        .as_ref()
        .map(|profile| profile.source.as_str());
    let (selected_host, selected_host_config) = config
        .resolve_host(host.as_deref())
        .map_err(|error| failure(error, json_errors))?;
    let mut effective_config = config.config.clone();
    effective_config
        .hosts
        .insert(selected_host.clone(), selected_host_config.clone());
    let environment_sources = json!({
        "host": env_source("SATELLE_HOST"),
        "profile": env_source("SATELLE_PROFILE"),
        "paths": {
            "home": env_source("SATELLE_HOME"),
            "config_file": env_source("SATELLE_CONFIG_FILE"),
            "state_dir": env_source("SATELLE_STATE_DIR"),
            "cache_dir": env_source("SATELLE_CACHE_DIR"),
            "log_dir": env_source("SATELLE_LOG_DIR"),
        },
    });
    Ok(json!({
        "schema_version": CONFIG_EXPLAIN_SCHEMA_VERSION,
        "status": "ok",
        "selected_host": selected_host,
        "selected_profile": selected_profile,
        "checked_files": [config.user_config_path, config.project_config_path],
        "sources": {
            "defaults": true,
            "user_config": config.user_config_path,
            "project_config": config.project_config_path,
            "profile": selected_profile_source,
            "environment": environment_sources,
            "flags": ["--host", "--profile"],
        },
        "effective": redacted_config_json(&effective_config, show_secret_references),
        "values": {
            "default_host": config.config.default_host,
            "host_count": config.config.hosts.len(),
            "effective_timeouts": super::effective_timeouts_json(&selected_host_config),
            "daemon_path_overrides": daemon_path_overrides_json(&selected_host_config),
            "model_provider": model_provider_config_json(&config, &selected_host),
            "experimental_provider_computer_use": experimental_provider_computer_use_json(
                &config,
                &selected_host,
                &selected_host_config,
            ),
            "yolo": yolo_config_json(&config, &selected_host, &selected_host_config),
            "show_secret_references": show_secret_references,
        },
        "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
    }))
}

pub(super) fn paths_report(host: Option<String>, json_errors: bool) -> Result<Value, CliFailure> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let selected_host = host.unwrap_or_else(|| LOCAL_DEMO_HOST.to_string());
    let paths = resolve_path_set(&cwd).map_err(|error| failure(error, json_errors))?;
    Ok(json!({
        "schema_version": PATHS_SCHEMA_VERSION,
        "host": selected_host,
        "config_file": paths.config_file,
        "cache_root": paths.cache_root,
        "state_root": paths.state_root,
        "sqlite_store": paths.sqlite_store,
        "operator_log_root": paths.operator_log_root,
        "recording_root": paths.recording_root,
        "project_config_file": paths.project_config_file,
        "install_receipt": paths.install_receipt,
        "sources": paths.sources,
    }))
}

pub(super) fn doctor_for_host(
    host: &super::SelectedHost,
    scope: Option<&str>,
) -> Result<DoctorReport, CliFailure> {
    transport_for(host, OutputFormat::Json)?
        .doctor(scope, false)
        .map_err(|error| failure(error, true))
}

pub(super) fn host_status(
    host: Option<&str>,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<satelle_host::HostStatus, CliFailure> {
    let json_errors = format.is_json();
    let host = config.resolve_host(host, json_errors)?;
    host_status_for_host(&host, format)
}

pub(super) fn host_status_for_host(
    host: &super::SelectedHost,
    format: OutputFormat,
) -> Result<satelle_host::HostStatus, CliFailure> {
    let json_errors = format.is_json();
    transport_for(host, format)?
        .host_status()
        .map_err(|error| failure(error, json_errors))
}

pub(super) fn host_sessions(
    host: Option<&str>,
    no_bootstrap: bool,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<HostSessionsReport, CliFailure> {
    let json_errors = format.is_json();
    let host = config.resolve_host(host, json_errors)?;
    host_sessions_for_host(&host, no_bootstrap, format)
}

pub(super) fn host_sessions_for_host(
    host: &super::SelectedHost,
    no_bootstrap: bool,
    format: OutputFormat,
) -> Result<HostSessionsReport, CliFailure> {
    let json_errors = format.is_json();
    let mut report = transport_for(host, format)?
        .host_sessions(no_bootstrap)
        .map_err(|error| failure(error, json_errors))?;
    apply_current_desktop_selection(&mut report, &host.config);
    Ok(report)
}

pub(super) fn status(
    session_id: &str,
    host: Option<&str>,
    config: ConfigContext<'_>,
    format: OutputFormat,
) -> Result<(PublicSession, String), CliFailure> {
    let json_errors = format.is_json();
    let session_id =
        SessionId::from_str(session_id).map_err(|error| failure(error.into(), json_errors))?;
    let host = config.resolve_host(host, json_errors)?;
    status_for_host(&session_id, &host, format).map(|session| (session, host.alias))
}

pub(super) fn status_for_host(
    session_id: &SessionId,
    host: &super::SelectedHost,
    format: OutputFormat,
) -> Result<PublicSession, CliFailure> {
    let json_errors = format.is_json();
    let session = transport_for(host, format)?
        .status(session_id)
        .map_err(|error| failure(error, json_errors))?;
    Ok(session)
}

pub(super) fn status_value(session: &PublicSession, host: &str) -> Result<Value, SatelleError> {
    serde_json::to_value(StatusReport::new(session, host))
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))
}
