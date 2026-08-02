use super::output::StatusReport;
use super::transport::transport_for;
use super::{
    CONFIG_CHECK_SCHEMA_VERSION, CONFIG_EXPLAIN_SCHEMA_VERSION, CliFailure, ConfigContext,
    HostSessionsReport, LOCAL_DEMO_HOST, PATHS_SCHEMA_VERSION, PublicSession, SessionId,
    apply_current_desktop_selection, daemon_path_overrides_json, env_source,
    experimental_provider_computer_use_json, failure, model_provider_config_json,
    redacted_config_json, resolve_path_set, yolo_config_json,
};
use satelle_core::doctor::DoctorScopeSelection;
use satelle_core::{
    DoctorOptions, DoctorReport, MutationCommandFamily, ResolvedConfig, SatelleError,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

pub(super) fn config_check_report(
    host: Option<String>,
    all: bool,
    config_context: ConfigContext<'_>,
) -> Result<Value, CliFailure> {
    let config = config_context.load()?;
    let contexts = config
        .config_check_contexts(host.as_deref(), all)
        .map_err(failure)?;
    let selected = contexts
        .first()
        .expect("config check always validates at least the selected context");
    let checked_contexts = contexts
        .iter()
        .map(|context| -> Result<Value, CliFailure> {
            let context_config = context.profile.as_deref().map_or_else(
                ConfigContext::without_profile,
                |profile| {
                    context.profile_source.map_or_else(
                        || ConfigContext::new(Some(profile)),
                        |source| ConfigContext::for_profile(profile, source),
                    )
                },
            );
            let resolved = context_config.load()?;
            let provider_host = resolved
                .resolve_host(Some(&context.host))
                .map(super::SelectedHost::from)
                .map_err(failure)?;
            let provider_selection = super::resolve_provider_selection(
                resolved,
                &provider_host,
                None,
                None,
                false,
                false,
            )?;
            if let Some(auth_source_name) = provider_selection.missing_auth_source_name() {
                return Err(failure(SatelleError::config_error(
                    format!(
                        "Host Binding '{}' has provider authentication outcome missing_descriptor because provider_auth entry '{auth_source_name}' is absent",
                        provider_host.alias
                    ),
                    None,
                )));
            }
            Ok(json!({
                "host": context.host,
                "profile": context.profile,
                "source": context.source,
                "status": "ok",
                "checks": LOCAL_CONFIG_CHECKS,
                "errors": [],
                "not_checked": REMOTE_CONFIG_CHECKS,
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "schema_version": CONFIG_CHECK_SCHEMA_VERSION,
        "status": "ok",
        "mode": if all { "all" } else { "selected" },
        "selected_host": selected.host,
        "selected_profile": selected.profile,
        "checked_files": [config.user_config_path, config.project_config_path],
        "checks": LOCAL_CONFIG_CHECKS,
        "checked_contexts": checked_contexts,
        "errors": [],
        "not_checked": REMOTE_CONFIG_CHECKS,
        "recovery_commands": [],
    }))
}

const LOCAL_CONFIG_CHECKS: &[&str] = &[
    "toml_parse",
    "typed_schema",
    "unknown_keys",
    "unsupported_composition",
    "interpolation_syntax",
    "duration_units",
    "path_overrides",
    "merge_precedence",
    "profile_resolution",
    "host_resolution",
    "project_forbidden_keys",
];

const REMOTE_CONFIG_CHECKS: &[&str] = &["remote_host", "provider_auth", "native_computer_use"];

fn noninteractive_mutation_consent_json(config: &ResolvedConfig, host: &str) -> Value {
    let trusted_profile = config
        .trusted_profile_reference()
        .and_then(|reference| config.config.trusted_profiles.get(reference))
        .filter(|trusted| trusted.hosts.contains(host));
    let family = |command_family| {
        let active = trusted_profile
            .is_some_and(|trusted| trusted.command_families.contains(&command_family));
        json!({
            "active": active,
            "source": if active {
                "user_config_trusted_profile"
            } else {
                "absent"
            },
        })
    };

    json!({
        // Config explain has no mutating command flag. Report that source
        // explicitly so consumers do not mistake Trusted Profile consent for
        // a command-scoped --yes decision.
        "command_flag": {
            "active": false,
            "source": "absent",
        },
        "command_families": {
            "setup": family(MutationCommandFamily::Setup),
            "repair": family(MutationCommandFamily::Repair),
            "host_update": family(MutationCommandFamily::HostUpdate),
            "self_update_remotes": family(MutationCommandFamily::SelfUpdateRemotes),
            "doctor_fix": family(MutationCommandFamily::DoctorFix),
        },
    })
}

pub(super) fn config_explain_report(
    host: Option<String>,
    show_secret_references: bool,
    config_context: ConfigContext<'_>,
) -> Result<Value, CliFailure> {
    let config = config_context.load()?;
    let selected_profile = config
        .selected_profile
        .as_ref()
        .map(|profile| profile.name.as_str());
    let selected_profile_source = config
        .selected_profile
        .as_ref()
        .map(|profile| profile.source.as_str());
    let (selected_host, selected_host_config, host_from_project) = config
        .resolve_host_with_project_source(host.as_deref())
        .map_err(failure)?;
    let mut effective_config = config.config.clone();
    effective_config
        .hosts
        .insert(selected_host.clone(), selected_host_config.clone());
    let environment_sources = json!({
        "host": env_source("SATELLE_HOST"),
        "profile": env_source("SATELLE_PROFILE"),
        "command_history": env_source("SATELLE_COMMAND_HISTORY"),
        "log_verbosity": env_source("SATELLE_LOG"),
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
            "project_intent": {
                "host": host_from_project,
                "model": config.model_alias_from_project(),
                "provider": config.provider_alias_from_project(),
                "profile": selected_profile_source == Some("project_config"),
                "timeouts": config.timeout_intent_from_project(&selected_host),
                "transport": config.transport_intent_from_project(&selected_host),
                "output_format": config.output_format_from_project(),
            },
            "environment": environment_sources,
            "flags": ["--host", "--profile", "--log-verbosity"],
        },
        "effective": redacted_config_json(&effective_config, show_secret_references),
        "values": {
            "default_host": config.config.default_host,
            "output_format": config.config.output_format,
            "log_verbosity": config.config.log_verbosity,
            "host_count": config.config.hosts.len(),
            "effective_timeouts": super::effective_timeouts_json(
                &selected_host_config,
                super::configured_turn_execution_timeout_ms(&selected_host_config),
            ),
            "daemon_path_overrides": daemon_path_overrides_json(&selected_host_config),
            "model_provider": model_provider_config_json(
                config,
                &selected_host,
                &selected_host_config,
            ),
            "experimental_provider_computer_use": experimental_provider_computer_use_json(
                config,
                &selected_host,
                &selected_host_config,
            ),
            "yolo": yolo_config_json(config, &selected_host, &selected_host_config),
            "noninteractive_mutation_consent": noninteractive_mutation_consent_json(
                config,
                &selected_host,
            ),
            "show_secret_references": show_secret_references,
        },
        "not_checked": ["remote_host", "provider_auth", "native_computer_use"],
    }))
}

pub(super) fn paths_report(host: Option<&super::SelectedHost>) -> Result<Value, CliFailure> {
    let (selected_host, paths, observation_source) = if let Some(host) = host {
        (
            host.alias.clone(),
            super::transport::host_paths_for_inspection(host)?,
            Some(satelle_core::PathSource::HostReported),
        )
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let paths = resolve_path_set(&cwd).map_err(failure)?;
        (
            LOCAL_DEMO_HOST.to_string(),
            satelle_core::daemon_service::DaemonResolvedPathSet::from(&paths),
            None,
        )
    };
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
        "observation_source": observation_source,
    }))
}

pub(super) fn doctor_for_host(
    host: &super::SelectedHost,
    scope: Option<&str>,
) -> Result<DoctorReport, CliFailure> {
    let raw_scopes = scope.into_iter().map(str::to_string).collect::<Vec<_>>();
    let scope_selection =
        DoctorScopeSelection::parse(&raw_scopes).expect("read helpers use supported Doctor scopes");
    let options = DoctorOptions::default();
    let transport_probe = super::tailscale::transport_doctor_probe(&scope_selection, &host.config);
    if let Some(prepared) =
        super::tailscale::prepare_transport_only_doctor(&host.config, &scope_selection, options)
            .map_err(failure)?
    {
        return super::tailscale::execute_transport_only_doctor(
            &host.alias,
            &scope_selection,
            &transport_probe,
            prepared,
        )
        .map_err(failure);
    }
    transport_for(host)?
        .doctor(
            &scope_selection,
            Arc::new(transport_probe),
            options,
            &satelle_host::ProviderComputerUseIntent::host_default(),
        )
        .map_err(|failed| failure(failed.error))
}

pub(super) fn host_status(
    host: Option<&str>,
    config: ConfigContext<'_>,
) -> Result<satelle_host::HostStatus, CliFailure> {
    let host = config.resolve_host(host)?;
    host_status_for_host(&host)
}

pub(super) fn host_status_for_host(
    host: &super::SelectedHost,
) -> Result<satelle_host::HostStatus, CliFailure> {
    transport_for(host)?.host_status().map_err(failure)
}

pub(super) fn host_sessions(
    host: Option<&str>,
    no_bootstrap: bool,
    config: ConfigContext<'_>,
) -> Result<HostSessionsReport, CliFailure> {
    let host = config.resolve_host(host)?;
    host_sessions_for_host(&host, no_bootstrap)
}

pub(super) fn host_sessions_for_host(
    host: &super::SelectedHost,
    no_bootstrap: bool,
) -> Result<HostSessionsReport, CliFailure> {
    let mut report = super::transport::host_sessions_for_inspection(host, no_bootstrap)?;
    apply_current_desktop_selection(&mut report, &host.config);
    Ok(report)
}

pub(super) fn status(
    session_id: &str,
    host: Option<&str>,
    config: ConfigContext<'_>,
) -> Result<(PublicSession, String), CliFailure> {
    let session_id = SessionId::from_str(session_id).map_err(|error| failure(error.into()))?;
    let host = config.resolve_session_host(host, &session_id)?;
    status_for_host(&session_id, &host).map(|session| (session, host.alias))
}

pub(super) fn status_for_host(
    session_id: &SessionId,
    host: &super::SelectedHost,
) -> Result<PublicSession, CliFailure> {
    let session = transport_for(host)?.status(session_id).map_err(failure)?;
    Ok(session)
}

pub(super) fn status_value(session: &PublicSession, host: &str) -> Result<Value, SatelleError> {
    serde_json::to_value(StatusReport::new(session, host))
        .map_err(|error| SatelleError::invalid_usage(error.to_string()))
}
