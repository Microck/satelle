use clap::ValueEnum;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use toml_edit::{Array, DocumentMut, Item, Table, value};

const ALL_TARGETS: [InstallTarget; 12] = [
    InstallTarget::ClaudeCode,
    InstallTarget::ClaudeDesktop,
    InstallTarget::Codex,
    InstallTarget::Cursor,
    InstallTarget::VsCode,
    InstallTarget::Windsurf,
    InstallTarget::Gemini,
    InstallTarget::OpenCode,
    InstallTarget::Cline,
    InstallTarget::RooCode,
    InstallTarget::Droid,
    InstallTarget::Antigravity,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub(crate) enum InstallTarget {
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "claude-desktop")]
    ClaudeDesktop,
    Codex,
    Cursor,
    #[value(name = "vscode")]
    VsCode,
    Windsurf,
    Gemini,
    #[value(name = "opencode")]
    OpenCode,
    Cline,
    #[value(name = "roo-code")]
    RooCode,
    Droid,
    Antigravity,
}

#[derive(Debug, Clone)]
pub(crate) struct InstallRequest {
    pub targets: Vec<InstallTarget>,
    pub all: bool,
    pub server_name: String,
    pub satelle_path: Option<PathBuf>,
    pub profile: Option<String>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstallChange {
    pub target: InstallTarget,
    pub path: Option<PathBuf>,
    pub changed: bool,
    pub skipped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InstallReport {
    pub dry_run: bool,
    pub changes: Vec<InstallChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    MacOs,
    Windows,
}

#[derive(Debug, Clone)]
struct InstallEnvironment {
    platform: Platform,
    home: PathBuf,
    claude_config_dir: PathBuf,
    cline_mcp_settings_path: PathBuf,
    codex_home: PathBuf,
    config_home: PathBuf,
    app_data: Option<PathBuf>,
}

impl InstallEnvironment {
    fn detect() -> Result<Self, String> {
        let platform = match env::consts::OS {
            "windows" => Platform::Windows,
            "macos" => Platform::MacOs,
            _ => Platform::Linux,
        };
        let home = resolve_home(platform, env::var_os("HOME"), env::var_os("USERPROFILE"))?;
        let codex_home =
            nonempty_path(env::var_os("CODEX_HOME")).unwrap_or_else(|| home.join(".codex"));
        let claude_config_dir = env::var_os("CLAUDE_CONFIG_DIR")
            .and_then(absolute_path)
            .unwrap_or_else(|| home.clone());
        let cline_mcp_settings_path = resolve_cline_mcp_settings_path(
            &home,
            env::var_os("CLINE_MCP_SETTINGS_PATH"),
            env::var_os("CLINE_DATA_DIR"),
            env::var_os("CLINE_DIR"),
        );
        let config_home = env::var_os("XDG_CONFIG_HOME")
            .and_then(absolute_path)
            .unwrap_or_else(|| home.join(".config"));
        let app_data = env::var_os("APPDATA")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from);

        Ok(Self {
            platform,
            home,
            claude_config_dir,
            cline_mcp_settings_path,
            codex_home,
            config_home,
            app_data,
        })
    }
}

fn resolve_home(
    platform: Platform,
    home: Option<OsString>,
    user_profile: Option<OsString>,
) -> Result<PathBuf, String> {
    let resolved = match platform {
        Platform::Windows => nonempty_path(user_profile).or_else(|| nonempty_path(home)),
        Platform::Linux | Platform::MacOs => {
            nonempty_path(home).or_else(|| nonempty_path(user_profile))
        }
    };
    resolved.ok_or_else(|| "could not resolve the user home directory".to_string())
}

fn nonempty_path(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|path| !path.is_empty()).map(PathBuf::from)
}

fn nonempty_trimmed_path(value: Option<OsString>) -> Option<PathBuf> {
    let value = value?.into_string().ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| PathBuf::from(value))
}

fn resolve_cline_mcp_settings_path(
    home: &Path,
    explicit_settings: Option<OsString>,
    data_dir: Option<OsString>,
    cline_dir: Option<OsString>,
) -> PathBuf {
    if let Some(path) = nonempty_trimmed_path(explicit_settings) {
        return path;
    }
    if let Some(path) = nonempty_trimmed_path(data_dir) {
        return path.join("settings/cline_mcp_settings.json");
    }
    nonempty_trimmed_path(cline_dir)
        .unwrap_or_else(|| home.join(".cline"))
        .join("data/settings/cline_mcp_settings.json")
}

fn absolute_path(value: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    path.is_absolute().then_some(path)
}

struct PlannedWrite {
    target: InstallTarget,
    path: PathBuf,
    original: Option<String>,
    contents: String,
    changed: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallTestEvent {
    Planned(InstallTarget),
    GloballyRevalidated(InstallTarget),
    AcquiringClineLock,
}

#[cfg(test)]
thread_local! {
    static INSTALL_TEST_EVENTS: std::cell::RefCell<Vec<InstallTestEvent>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
fn record_install_test_event(event: InstallTestEvent) {
    INSTALL_TEST_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
fn take_install_test_events() -> Vec<InstallTestEvent> {
    INSTALL_TEST_EVENTS.with(|events| events.take())
}

pub(crate) fn install(request: InstallRequest) -> Result<InstallReport, super::CliFailure> {
    let environment = InstallEnvironment::detect().map_err(super::mcp_failure)?;
    install_with_environment(request, &environment).map_err(super::mcp_failure)
}

fn install_with_environment(
    request: InstallRequest,
    environment: &InstallEnvironment,
) -> Result<InstallReport, String> {
    validate_server_name(&request.server_name)?;
    let targets = selected_targets(&request)?;
    let satelle_args = mcp_serve_args(request.profile.as_deref());
    let satelle_path = match request.satelle_path {
        Some(path) if is_absolute_for_platform(&path, environment.platform) => path,
        Some(path) => env::current_dir()
            .map_err(|error| format!("could not resolve the current directory: {error}"))?
            .join(path),
        None => env::current_exe()
            .map_err(|error| format!("could not resolve the Satelle executable path: {error}"))?,
    };
    let satelle_command = satelle_path.to_str().ok_or_else(|| {
        format!(
            "Satelle executable path is not valid UTF-8: {}",
            satelle_path.display()
        )
    })?;

    // Build and validate the complete plan before making the first write. A
    // malformed later config must not leave earlier clients partially updated.
    let mut plans = Vec::new();
    let mut changes = Vec::new();
    for target in targets {
        let Some(path) = config_path(target, environment)? else {
            if request.all {
                changes.push(InstallChange {
                    target,
                    path: None,
                    changed: false,
                    skipped: true,
                });
                continue;
            }
            return Err(format!(
                "{} does not publish a Linux MCP configuration path",
                target.label()
            ));
        };
        let plan = plan_target(
            target,
            path.clone(),
            &request.server_name,
            satelle_command,
            &satelle_args,
        )?;
        changes.push(InstallChange {
            target,
            path: Some(path),
            changed: plan.changed,
            skipped: false,
        });
        #[cfg(test)]
        record_install_test_event(InstallTestEvent::Planned(target));
        plans.push(plan);
    }

    if !request.dry_run {
        // Revalidate the complete plan before the first replacement so an
        // intervening client edit cannot turn preservation into data loss.
        for plan in plans.iter().filter(|plan| plan.changed) {
            ensure_source_unchanged(plan)?;
            #[cfg(test)]
            record_install_test_event(InstallTestEvent::GloballyRevalidated(plan.target));
        }

        let changed_plans = plans
            .iter()
            .filter(|plan| plan.changed && plan.target != InstallTarget::Cline)
            .collect::<Vec<_>>();
        let mut applied = Vec::new();

        // Cline deliberately uses a ten-second stale threshold without a
        // heartbeat because its own lock covers only synchronous read, mutate,
        // and replace operations. Finish every unrelated plan and global
        // preflight first, then mirror that bounded critical section exactly.
        let replanned_cline = if let Some(initial_cline) = plans
            .iter()
            .find(|plan| plan.target == InstallTarget::Cline && plan.changed)
        {
            let _cline_lock = acquire_cline_settings_lock(&initial_cline.path)?;
            let cline_plan = plan_target(
                InstallTarget::Cline,
                initial_cline.path.clone(),
                &request.server_name,
                satelle_command,
                &satelle_args,
            )?;
            if let Some(change) = changes
                .iter_mut()
                .find(|change| change.target == InstallTarget::Cline)
            {
                change.changed = cline_plan.changed;
            }
            if cline_plan.changed {
                ensure_source_unchanged(&cline_plan)?;
                if let Err(error) = write_atomic(
                    &cline_plan.path,
                    &cline_plan.contents,
                    cline_plan.original.as_deref(),
                ) {
                    return Err(write_failure_error(
                        &cline_plan,
                        error,
                        &applied,
                        &changed_plans,
                    ));
                }
            }
            Some(cline_plan)
        } else {
            None
        };
        if let Some(cline_plan) = replanned_cline.as_ref().filter(|plan| plan.changed) {
            applied.push(cline_plan);
        }

        for (index, plan) in changed_plans.iter().enumerate() {
            // A client can still edit a later config while earlier targets are
            // being written, so check again at the last responsible moment.
            if let Err(error) = ensure_source_unchanged(plan) {
                return Err(partial_write_error(
                    error,
                    &applied,
                    &changed_plans[index..],
                ));
            }
            if let Err(error) = write_atomic(&plan.path, &plan.contents, plan.original.as_deref()) {
                return Err(write_failure_error(
                    plan,
                    error,
                    &applied,
                    &changed_plans[index + 1..],
                ));
            }
            applied.push(*plan);
        }
    }

    Ok(InstallReport {
        dry_run: request.dry_run,
        changes,
    })
}

fn is_absolute_for_platform(path: &Path, platform: Platform) -> bool {
    let bytes = path.as_os_str().to_string_lossy();
    let bytes = bytes.as_bytes();
    match platform {
        Platform::Windows => {
            matches!(bytes, [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
                || matches!(bytes, [b'\\' | b'/', b'\\' | b'/', ..])
        }
        Platform::Linux | Platform::MacOs => bytes.starts_with(b"/"),
    }
}

fn write_failure_error(
    plan: &PlannedWrite,
    error: AtomicWriteFailure,
    applied_before: &[&PlannedWrite],
    remaining_after: &[&PlannedWrite],
) -> String {
    #[cfg(unix)]
    let mut applied = applied_before.to_vec();
    #[cfg(not(unix))]
    let applied = applied_before.to_vec();
    let mut untouched = Vec::with_capacity(remaining_after.len() + 1);
    let cause = match error.outcome {
        AtomicWriteOutcome::NotCommitted => {
            untouched.push(plan);
            format!(
                "failed to write {} MCP config at {}: {error}",
                plan.target.label(),
                plan.path.display()
            )
        }
        #[cfg(unix)]
        AtomicWriteOutcome::Committed => {
            applied.push(plan);
            format!(
                "wrote {} MCP config at {}, but parent-directory durability could not be confirmed: {error}",
                plan.target.label(),
                plan.path.display()
            )
        }
        AtomicWriteOutcome::Unknown => format!(
            "the replacement outcome for {} MCP config at {} is unknown: {error}",
            plan.target.label(),
            plan.path.display()
        ),
    };
    untouched.extend_from_slice(remaining_after);
    partial_write_error(cause, &applied, &untouched)
}

fn partial_write_error(
    cause: String,
    applied: &[&PlannedWrite],
    untouched: &[&PlannedWrite],
) -> String {
    if applied.is_empty() {
        return cause;
    }
    let paths = |plans: &[&PlannedWrite]| {
        let paths = plans
            .iter()
            .map(|plan| plan.path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if paths.is_empty() {
            "none".to_string()
        } else {
            paths
        }
    };
    format!(
        "{cause}; already updated before the failure: {}; not updated: {}",
        paths(applied),
        paths(untouched)
    )
}

fn selected_targets(request: &InstallRequest) -> Result<Vec<InstallTarget>, String> {
    if request.all && !request.targets.is_empty() {
        return Err("--all cannot be combined with --target".to_string());
    }
    if request.all {
        return Ok(ALL_TARGETS.to_vec());
    }
    if request.targets.is_empty() {
        return Err("select at least one --target or use --all".to_string());
    }

    let mut seen = HashSet::new();
    Ok(request
        .targets
        .iter()
        .copied()
        .filter(|target| seen.insert(*target))
        .collect())
}

fn validate_server_name(server_name: &str) -> Result<(), String> {
    if server_name.is_empty()
        || !server_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(
            "--server-name must contain only ASCII letters, digits, hyphens, and underscores"
                .to_string(),
        );
    }
    Ok(())
}

impl InstallTarget {
    pub(crate) fn slug(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::ClaudeDesktop => "claude-desktop",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::VsCode => "vscode",
            Self::Windsurf => "windsurf",
            Self::Gemini => "gemini",
            Self::OpenCode => "opencode",
            Self::Cline => "cline",
            Self::RooCode => "roo-code",
            Self::Droid => "droid",
            Self::Antigravity => "antigravity",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::ClaudeDesktop => "Claude Desktop",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::VsCode => "VS Code",
            Self::Windsurf => "Windsurf",
            Self::Gemini => "Gemini",
            Self::OpenCode => "OpenCode",
            Self::Cline => "Cline",
            Self::RooCode => "Roo Code",
            Self::Droid => "Droid",
            Self::Antigravity => "Antigravity",
        }
    }
}

fn config_path(
    target: InstallTarget,
    environment: &InstallEnvironment,
) -> Result<Option<PathBuf>, String> {
    let home = &environment.home;
    let path = match target {
        InstallTarget::ClaudeCode => environment.claude_config_dir.join(".claude.json"),
        InstallTarget::ClaudeDesktop => match environment.platform {
            Platform::MacOs => {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            }
            Platform::Windows => environment
                .app_data
                .as_ref()
                .ok_or_else(|| "APPDATA is required for Claude Desktop".to_string())?
                .join("Claude/claude_desktop_config.json"),
            Platform::Linux => return Ok(None),
        },
        InstallTarget::Codex => environment.codex_home.join("config.toml"),
        InstallTarget::Cursor => home.join(".cursor/mcp.json"),
        InstallTarget::VsCode => editor_user_dir(environment, "Code")?.join("mcp.json"),
        InstallTarget::Windsurf => home.join(".codeium/windsurf/mcp_config.json"),
        InstallTarget::Gemini => home.join(".gemini/settings.json"),
        InstallTarget::OpenCode => environment.config_home.join("opencode/opencode.json"),
        InstallTarget::Cline => environment.cline_mcp_settings_path.clone(),
        InstallTarget::RooCode => editor_user_dir(environment, "Code")?
            .join("globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"),
        InstallTarget::Droid => home.join(".factory/mcp.json"),
        InstallTarget::Antigravity => home.join(".gemini/config/mcp_config.json"),
    };
    Ok(Some(path))
}

fn editor_user_dir(
    environment: &InstallEnvironment,
    application_name: &str,
) -> Result<PathBuf, String> {
    Ok(match environment.platform {
        Platform::Linux => environment.config_home.join(application_name).join("User"),
        Platform::MacOs => environment
            .home
            .join("Library/Application Support")
            .join(application_name)
            .join("User"),
        Platform::Windows => environment
            .app_data
            .as_ref()
            .ok_or_else(|| "APPDATA is required for VS Code configuration".to_string())?
            .join(application_name)
            .join("User"),
    })
}

fn plan_target(
    target: InstallTarget,
    path: PathBuf,
    server_name: &str,
    satelle_command: &str,
    satelle_args: &[String],
) -> Result<PlannedWrite, String> {
    let original = read_config_source(&path)?;
    let raw = original.as_deref().unwrap_or("");
    let contents = if target == InstallTarget::Codex {
        update_codex_config(raw, &path, server_name, satelle_command, satelle_args)?
    } else {
        update_json_config(
            raw,
            &path,
            target,
            server_name,
            satelle_command,
            satelle_args,
        )?
    };
    let changed = raw != contents;
    Ok(PlannedWrite {
        target,
        path,
        original,
        contents,
        changed,
    })
}

fn read_config_source(path: &Path) -> Result<Option<String>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "refusing to replace symlinked MCP config at {}",
                path.display()
            ));
        }
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(format!(
                "refusing to read non-regular MCP config at {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to inspect MCP config at {}: {error}",
                path.display()
            ));
        }
    }

    fs::read_to_string(path)
        .map(Some)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))
}

const CLINE_SETTINGS_LOCK_STALE_AFTER: Duration = Duration::from_secs(10);
const CLINE_SETTINGS_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const CLINE_SETTINGS_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(25);

struct ClineSettingsLock {
    lock_dir: PathBuf,
    owner_file: PathBuf,
}

impl Drop for ClineSettingsLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.owner_file);
        let _ = fs::remove_dir(&self.lock_dir);
    }
}

fn acquire_cline_settings_lock(config_path: &Path) -> Result<ClineSettingsLock, String> {
    #[cfg(test)]
    record_install_test_event(InstallTestEvent::AcquiringClineLock);

    acquire_cline_settings_lock_until(config_path, Instant::now() + CLINE_SETTINGS_LOCK_TIMEOUT)
}

fn acquire_cline_settings_lock_until(
    config_path: &Path,
    deadline: Instant,
) -> Result<ClineSettingsLock, String> {
    let lock_dir = path_with_suffix(config_path, ".lock");
    let parent = lock_dir.parent().ok_or_else(|| {
        format!(
            "Cline MCP settings lock has no parent: {}",
            lock_dir.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create Cline MCP settings directory at {}: {error}",
            parent.display()
        )
    })?;

    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Cline MCP settings lock at {} after 10 seconds",
                lock_dir.display()
            ));
        }
        let staging = tempfile::Builder::new()
            .prefix(".satelle-cline-lock-")
            .tempdir_in(parent)
            .map_err(|error| format!("failed to stage Cline MCP settings lock: {error}"))?;
        let owner_name = format!("owner.satelle.{}", std::process::id());
        fs::write(staging.path().join(&owner_name), owner_name.as_bytes())
            .map_err(|error| format!("failed to populate Cline MCP settings lock: {error}"))?;

        match fs::rename(staging.path(), &lock_dir) {
            Ok(()) => {
                return Ok(ClineSettingsLock {
                    owner_file: lock_dir.join(owner_name),
                    lock_dir,
                });
            }
            Err(error) if !lock_dir.exists() => {
                return Err(format!(
                    "failed to acquire Cline MCP settings lock at {}: {error}",
                    lock_dir.display()
                ));
            }
            Err(_) => {}
        }

        reclaim_stale_cline_lock(&lock_dir)?;
        std::thread::sleep(CLINE_SETTINGS_LOCK_POLL_INTERVAL);
    }
}

fn reclaim_stale_cline_lock(lock_dir: &Path) -> Result<(), String> {
    let metadata = match fs::metadata(lock_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "failed to inspect Cline MCP settings lock at {}: {error}",
                lock_dir.display()
            ));
        }
    };
    let age = SystemTime::now()
        .duration_since(metadata.modified().unwrap_or(SystemTime::now()))
        .unwrap_or_default();
    if age < CLINE_SETTINGS_LOCK_STALE_AFTER {
        return Ok(());
    }

    let token = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let stale_dir = path_with_suffix(lock_dir, &format!(".stale.{}.{token}", std::process::id()));
    match fs::rename(lock_dir, &stale_dir) {
        Ok(()) => fs::remove_dir_all(&stale_dir).map_err(|error| {
            format!(
                "failed to remove stale Cline MCP settings lock at {}: {error}",
                stale_dir.display()
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to reclaim stale Cline MCP settings lock at {}: {error}",
            lock_dir.display()
        )),
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn ensure_source_unchanged(plan: &PlannedWrite) -> Result<(), String> {
    let current = read_config_source(&plan.path).map_err(|error| {
        format!(
            "failed to re-read {} MCP config at {}: {error}",
            plan.target.label(),
            plan.path.display()
        )
    })?;
    if current != plan.original {
        return Err(format!(
            "{} MCP config changed while the install was being planned: {}",
            plan.target.label(),
            plan.path.display()
        ));
    }
    Ok(())
}

fn update_json_config(
    raw: &str,
    path: &Path,
    target: InstallTarget,
    server_name: &str,
    satelle_command: &str,
    satelle_args: &[String],
) -> Result<String, String> {
    let mut config = parse_json_object(raw, path)?;
    let (root_key, server) = json_server_entry(target, satelle_command, satelle_args);
    let servers = config
        .entry(root_key.to_string())
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            format!(
                "cannot update `{root_key}` in {} because it is not a JSON object",
                path.display()
            )
        })?;
    servers.insert(server_name.to_string(), server);
    serde_json::to_string_pretty(&Value::Object(config))
        .map(|json| format!("{json}\n"))
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))
}

fn mcp_serve_args(profile: Option<&str>) -> Vec<String> {
    let mut args = Vec::with_capacity(if profile.is_some() { 4 } else { 2 });
    if let Some(profile) = profile {
        args.push("--profile".to_string());
        args.push(profile.to_string());
    }
    args.push("mcp".to_string());
    args.push("serve".to_string());
    args
}

fn json_server_entry(
    target: InstallTarget,
    satelle_command: &str,
    satelle_args: &[String],
) -> (&'static str, Value) {
    let standard = || {
        json!({
            "command": satelle_command,
            "args": satelle_args
        })
    };
    match target {
        InstallTarget::ClaudeCode => (
            "mcpServers",
            json!({
                "type": "stdio",
                "command": satelle_command,
                "args": satelle_args
            }),
        ),
        InstallTarget::VsCode => (
            "servers",
            json!({
                "type": "stdio",
                "command": satelle_command,
                "args": satelle_args
            }),
        ),
        InstallTarget::OpenCode => (
            "mcp",
            json!({
                "type": "local",
                "command": std::iter::once(satelle_command)
                    .chain(satelle_args.iter().map(String::as_str))
                    .collect::<Vec<_>>()
            }),
        ),
        InstallTarget::Droid => (
            "mcpServers",
            json!({
                "type": "stdio",
                "command": satelle_command,
                "args": satelle_args
            }),
        ),
        InstallTarget::Cline => (
            "mcpServers",
            json!({
                "command": satelle_command,
                "args": satelle_args
            }),
        ),
        InstallTarget::Codex => unreachable!("Codex uses TOML"),
        InstallTarget::ClaudeDesktop
        | InstallTarget::Cursor
        | InstallTarget::Windsurf
        | InstallTarget::Gemini
        | InstallTarget::RooCode
        | InstallTarget::Antigravity => ("mcpServers", standard()),
    }
}

fn parse_json_object(raw: &str, path: &Path) -> Result<Map<String, Value>, String> {
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }
    let normalized = normalize_jsonc(raw).map_err(|error| {
        format!(
            "failed to parse JSONC config at {}: {error}",
            path.display()
        )
    })?;
    match serde_json::from_str::<Value>(&normalized)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?
    {
        Value::Object(object) => Ok(object),
        _ => Err(format!("{} must contain a JSON object", path.display())),
    }
}

fn normalize_jsonc(raw: &str) -> Result<String, String> {
    #[derive(Clone, Copy)]
    enum State {
        Normal,
        String,
        LineComment,
        BlockComment,
    }

    let mut state = State::Normal;
    let mut escaped = false;
    let mut chars = raw.chars().peekable();
    let mut without_comments = String::with_capacity(raw.len());
    while let Some(character) = chars.next() {
        match state {
            State::Normal => match (character, chars.peek().copied()) {
                ('"', _) => {
                    state = State::String;
                    without_comments.push(character);
                }
                ('/', Some('/')) => {
                    chars.next();
                    without_comments.push_str("  ");
                    state = State::LineComment;
                }
                ('/', Some('*')) => {
                    chars.next();
                    without_comments.push_str("  ");
                    state = State::BlockComment;
                }
                _ => without_comments.push(character),
            },
            State::String => {
                without_comments.push(character);
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    state = State::Normal;
                }
            }
            State::LineComment => {
                if character == '\n' || character == '\r' {
                    without_comments.push(character);
                    state = State::Normal;
                } else {
                    without_comments.push(' ');
                }
            }
            State::BlockComment => {
                if character == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    without_comments.push_str("  ");
                    state = State::Normal;
                } else if character == '\n' || character == '\r' {
                    without_comments.push(character);
                } else {
                    without_comments.push(' ');
                }
            }
        }
    }
    if matches!(state, State::BlockComment) {
        return Err("unterminated block comment".to_string());
    }

    let mut characters = without_comments.chars().collect::<Vec<_>>();
    let mut in_string = false;
    let mut escaped = false;
    for index in 0..characters.len() {
        let character = characters[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            continue;
        }
        if character != ',' {
            continue;
        }
        let next = characters[index + 1..]
            .iter()
            .copied()
            .find(|character| !character.is_whitespace());
        if matches!(next, Some('}') | Some(']')) {
            characters[index] = ' ';
        }
    }
    Ok(characters.into_iter().collect())
}

fn update_codex_config(
    raw: &str,
    path: &Path,
    server_name: &str,
    satelle_command: &str,
    satelle_args: &[String],
) -> Result<String, String> {
    let mut document = if raw.trim().is_empty() {
        DocumentMut::new()
    } else {
        raw.parse::<DocumentMut>()
            .map_err(|error| format!("failed to parse {}: {error}", path.display()))?
    };
    let servers = document
        .entry("mcp_servers")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| {
            format!(
                "cannot update `mcp_servers` in {} because it is not a TOML table",
                path.display()
            )
        })?;
    let mut server = Table::new();
    server.insert("command", value(satelle_command));
    let mut args = Array::new();
    for argument in satelle_args {
        args.push(argument.as_str());
    }
    server.insert("args", value(args));
    servers.insert(server_name, Item::Table(server));
    Ok(document.to_string())
}

#[derive(Debug)]
struct AtomicWriteFailure {
    error: io::Error,
    outcome: AtomicWriteOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicWriteOutcome {
    NotCommitted,
    #[cfg(unix)]
    Committed,
    Unknown,
}

impl From<io::Error> for AtomicWriteFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            outcome: AtomicWriteOutcome::NotCommitted,
        }
    }
}

impl fmt::Display for AtomicWriteFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct UnixSecurity {
    owner: u32,
    group: u32,
    mode: u32,
    xattrs: Vec<(std::ffi::CString, Vec<u8>)>,
    #[cfg(target_os = "macos")]
    acl: MacOsExtendedAcl,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UnixFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
struct UnixSource {
    // Keeping this descriptor open anchors the captured inode until persist.
    _descriptor: fs::File,
    identity: UnixFileIdentity,
    security: UnixSecurity,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq)]
enum MacOsExtendedAcl {
    None,
    Native(Vec<u8>),
}

#[cfg(target_os = "macos")]
mod macos_extended_acl {
    use super::MacOsExtendedAcl;
    use std::os::fd::{AsRawFd, RawFd};
    use std::{fs, io};

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const FILESEC_ACL: libc::c_int = 5;

    type Acl = *mut libc::c_void;
    type FileSec = *mut libc::c_void;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_size(acl: Acl) -> libc::ssize_t;
        fn acl_copy_ext_native(
            buffer: *mut libc::c_void,
            acl: Acl,
            size: libc::ssize_t,
        ) -> libc::ssize_t;
        fn acl_copy_int_native(buffer: *const libc::c_void) -> Acl;
        fn acl_valid(acl: Acl) -> libc::c_int;
        fn acl_set_fd_np(fd: libc::c_int, acl: Acl, acl_type: libc::c_int) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
        fn filesec_init() -> FileSec;
        fn filesec_set_property(
            filesec: FileSec,
            property: libc::c_int,
            value: *const libc::c_void,
        ) -> libc::c_int;
        fn fchmodx_np(fd: libc::c_int, filesec: FileSec) -> libc::c_int;
        fn filesec_free(filesec: FileSec);

    }

    struct OwnedAcl(Acl);

    impl Drop for OwnedAcl {
        fn drop(&mut self) {
            unsafe {
                let _ = acl_free(self.0);
            }
        }
    }

    struct OwnedFileSec(FileSec);

    impl Drop for OwnedFileSec {
        fn drop(&mut self) {
            unsafe { filesec_free(self.0) };
        }
    }

    pub(super) fn capture(file: &fs::File) -> io::Result<MacOsExtendedAcl> {
        let fd = file.as_raw_fd();
        let acl = unsafe {
            *libc::__error() = 0;
            acl_get_fd_np(fd, ACL_TYPE_EXTENDED)
        };
        if acl.is_null() {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(MacOsExtendedAcl::None)
            } else {
                Err(io::Error::last_os_error())
            };
        }
        let acl = OwnedAcl(acl);
        let size = unsafe { acl_size(acl.0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0_u8; size as usize];
        let copied = unsafe { acl_copy_ext_native(bytes.as_mut_ptr().cast(), acl.0, size) };
        if copied != size {
            return Err(io::Error::last_os_error());
        }
        Ok(MacOsExtendedAcl::Native(bytes))
    }

    pub(super) fn apply(file: &fs::File, acl: &MacOsExtendedAcl) -> io::Result<()> {
        let fd = file.as_raw_fd();
        match acl {
            MacOsExtendedAcl::None => remove(fd),
            MacOsExtendedAcl::Native(bytes) => set(fd, bytes),
        }
    }

    fn set(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
        let acl = unsafe {
            *libc::__error() = 0;
            acl_copy_int_native(bytes.as_ptr().cast())
        };
        if acl.is_null() {
            return Err(io::Error::last_os_error());
        }
        let acl = OwnedAcl(acl);
        // Apple's acl_valid_fd_np is an ENOTSUP stub. Validate the decoded ACL
        // itself, then apply it through the descriptor-based setter below.
        if unsafe { acl_valid(acl.0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { acl_set_fd_np(fd, acl.0, ACL_TYPE_EXTENDED) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn remove(fd: RawFd) -> io::Result<()> {
        let filesec = unsafe {
            *libc::__error() = 0;
            filesec_init()
        };
        if filesec.is_null() {
            return Err(io::Error::last_os_error());
        }
        let filesec = OwnedFileSec(filesec);
        let remove_acl = std::ptr::dangling::<libc::c_void>();
        if unsafe { filesec_set_property(filesec.0, FILESEC_ACL, remove_acl) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { fchmodx_np(fd, filesec.0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn unix_security(file: &fs::File) -> io::Result<UnixSecurity> {
    use rustix::buffer::spare_capacity;
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let mut empty = [0_u8; 0];
    let names_size = rustix::fs::flistxattr(file, &mut empty)?;
    let mut names = Vec::with_capacity(names_size);
    if names_size != 0 {
        rustix::fs::flistxattr(file, spare_capacity(&mut names))?;
    }

    let mut xattrs = Vec::new();
    for name in names.split_inclusive(|byte| *byte == 0) {
        let name = std::ffi::CStr::from_bytes_with_nul(name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .to_owned();
        let mut empty = [0_u8; 0];
        let value_size = rustix::fs::fgetxattr(file, &name, &mut empty)?;
        let mut value = Vec::with_capacity(value_size);
        if value_size != 0 {
            rustix::fs::fgetxattr(file, &name, spare_capacity(&mut value))?;
        }
        xattrs.push((name, value));
    }
    xattrs.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

    Ok(UnixSecurity {
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        xattrs,
        #[cfg(target_os = "macos")]
        acl: macos_extended_acl::capture(file)?,
    })
}

#[cfg(unix)]
fn unix_file_identity(file: &fs::File) -> io::Result<UnixFileIdentity> {
    let metadata = rustix::fs::fstat(file)?;
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the MCP config is not a regular file",
        ));
    }
    Ok(UnixFileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

#[cfg(unix)]
fn open_unix_source(path: &Path) -> io::Result<Option<UnixSource>> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => fs::File::from(descriptor),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let identity = unix_file_identity(&descriptor)?;
    let security = unix_security(&descriptor)?;
    Ok(Some(UnixSource {
        _descriptor: descriptor,
        identity,
        security,
    }))
}

#[cfg(unix)]
fn set_unix_security(file: &fs::File, security: &UnixSecurity) -> io::Result<()> {
    use rustix::fs::{Gid, Uid, XattrFlags};
    use std::os::unix::fs::PermissionsExt;

    rustix::fs::fchown(
        file,
        Some(Uid::from_raw(security.owner)),
        Some(Gid::from_raw(security.group)),
    )?;
    file.set_permissions(fs::Permissions::from_mode(security.mode))?;

    let current = unix_security(file)?;
    for (name, _) in &current.xattrs {
        if !security.xattrs.iter().any(|(wanted, _)| wanted == name) {
            rustix::fs::fremovexattr(file, name)?;
        }
    }
    for (name, value) in &security.xattrs {
        if current
            .xattrs
            .iter()
            .find(|(current_name, _)| current_name == name)
            .is_none_or(|(_, current_value)| current_value != value)
        {
            rustix::fs::fsetxattr(file, name, value, XattrFlags::empty())?;
        }
    }

    #[cfg(target_os = "macos")]
    macos_extended_acl::apply(file, &security.acl)?;

    if unix_security(file)? != *security {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the staging owner, group, mode, xattrs, or native ACL differ from the original MCP config",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn finalize_unix_staging(
    file: &fs::File,
    security: &UnixSecurity,
) -> Result<(), AtomicWriteFailure> {
    set_unix_security(file, security)?;
    Ok(())
}

fn ensure_expected_source(path: &Path, expected: Option<&str>) -> io::Result<()> {
    let current = read_config_source(path).map_err(io::Error::other)?;
    if current.as_deref() != expected {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "the MCP config changed inside the atomic replacement path",
        ));
    }
    Ok(())
}

fn write_atomic(
    path: &Path,
    contents: &str,
    expected_source: Option<&str>,
) -> Result<(), AtomicWriteFailure> {
    write_atomic_with_after_preflight_comparison(path, contents, expected_source, || {})
}

fn write_atomic_with_after_preflight_comparison<AfterPreflightComparison>(
    path: &Path,
    contents: &str,
    expected_source: Option<&str>,
    after_preflight_comparison: AfterPreflightComparison,
) -> Result<(), AtomicWriteFailure>
where
    AfterPreflightComparison: FnOnce(),
{
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("configuration path has no parent: {}", path.display()),
        )
    })?;
    fs::create_dir_all(parent)?;

    #[cfg(unix)]
    let parent_directory = fs::File::open(parent)?;

    // Replacing an existing Unix file with a new inode must not silently
    // reset its owner, group, mode, or extended ACL. NamedTempFile creates
    // new files privately, so only existing files need an explicit copy.
    #[cfg(unix)]
    let existing_source = open_unix_source(path)?;

    #[cfg(windows)]
    let existing_security = match fs::metadata(path) {
        Ok(_) => Some(mcp_windows_security(path)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };

    #[cfg(windows)]
    let mut temporary = match &existing_security {
        Some(security) => mcp_windows_staging_file(parent, security)?,
        None => tempfile::NamedTempFile::new_in(parent)?,
    };
    #[cfg(not(windows))]
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    if let Some(source) = &existing_source {
        finalize_unix_staging(temporary.as_file(), &source.security)?;
    }
    temporary.as_file_mut().sync_all()?;
    // This read is only a cheap preflight. Correctness comes from the platform compare-and-replace
    // boundary below, which validates the atomically displaced destination or refuses to clobber a
    // destination that appeared after an absence plan.
    ensure_expected_source(path, expected_source)?;
    after_preflight_comparison();

    #[cfg(unix)]
    persist_unix_compare_and_replace(temporary, path, expected_source, existing_source.as_ref())?;
    #[cfg(windows)]
    match existing_security {
        Some(security) => persist_mcp_windows_config(
            temporary,
            path,
            expected_source.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "an MCP config appeared after planning",
                )
            })?,
            &security,
        )?,
        None => {
            temporary
                .persist_noclobber(path)
                .map_err(|error| error.error)?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;

    // sync_all on the file does not make the directory entry replacement
    // durable. Sync the parent after the atomic rename on Unix.
    #[cfg(unix)]
    parent_directory
        .sync_all()
        .map_err(|error| AtomicWriteFailure {
            error,
            outcome: AtomicWriteOutcome::Committed,
        })?;
    Ok(())
}

#[cfg(unix)]
fn exchange_unix_paths(left: &Path, right: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};

    renameat_with(CWD, left, CWD, right, RenameFlags::EXCHANGE).map_err(Into::into)
}

#[cfg(unix)]
fn displaced_unix_source_matches(
    displaced_path: &Path,
    expected_contents: &str,
    expected_source: &UnixSource,
) -> io::Result<bool> {
    let displaced = open_unix_source(displaced_path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the displaced MCP config disappeared during atomic replacement",
        )
    })?;
    let contents = fs::read_to_string(displaced_path)?;
    Ok(contents == expected_contents
        && displaced.identity == expected_source.identity
        && displaced.security == expected_source.security)
}

#[cfg(unix)]
fn rollback_unix_exchange(
    mut displaced_path: tempfile::TempPath,
    config_path: &Path,
    validation_error: io::Error,
) -> AtomicWriteFailure {
    if let Err(restore_error) = exchange_unix_paths(&displaced_path, config_path) {
        let preserved_path = displaced_path.to_path_buf();
        displaced_path.disable_cleanup(true);
        return AtomicWriteFailure {
            error: io::Error::new(
                restore_error.kind(),
                format!(
                    "{validation_error}; restoring the displaced MCP config failed: {restore_error}; the original remains at {} and the destination outcome is unknown",
                    preserved_path.display()
                ),
            ),
            outcome: AtomicWriteOutcome::Unknown,
        };
    }
    AtomicWriteFailure {
        error: validation_error,
        outcome: AtomicWriteOutcome::NotCommitted,
    }
}

#[cfg(unix)]
fn persist_unix_compare_and_replace(
    temporary: tempfile::NamedTempFile,
    config_path: &Path,
    expected_contents: Option<&str>,
    expected_source: Option<&UnixSource>,
) -> Result<(), AtomicWriteFailure> {
    let Some(expected_source) = expected_source else {
        temporary
            .persist_noclobber(config_path)
            .map_err(|error| error.error)?;
        return Ok(());
    };
    let expected_contents = expected_contents.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an MCP config appeared after planning",
        )
    })?;

    // EXCHANGE/SWAP is the compare-and-replace boundary. The destination's exact previous inode
    // becomes the named displaced file atomically, so a same-inode edit in the preflight-to-swap
    // window is observable and can be restored without ever overwriting the edited inode.
    let displaced_path = temporary.into_temp_path();
    exchange_unix_paths(&displaced_path, config_path)?;
    match displaced_unix_source_matches(&displaced_path, expected_contents, expected_source) {
        Ok(true) => displaced_path.close().map_err(|error| AtomicWriteFailure {
            error,
            outcome: AtomicWriteOutcome::Committed,
        }),
        Ok(false) => Err(rollback_unix_exchange(
            displaced_path,
            config_path,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the displaced MCP config differs from the source used for planning",
            ),
        )),
        Err(error) => Err(rollback_unix_exchange(displaced_path, config_path, error)),
    }
}

#[cfg(windows)]
fn persist_mcp_windows_config(
    temporary: tempfile::NamedTempFile,
    config_path: &Path,
    expected_contents: &str,
    original_security: &McpWindowsSecurity,
) -> Result<(), AtomicWriteFailure> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        ERROR_UNABLE_TO_MOVE_REPLACEMENT, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2,
    };
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let mut replacement_path = temporary.into_temp_path();
    // CreateFileW can merge inheritable ACEs even when it receives the
    // destination's complete descriptor. Reapply the captured fields after
    // creation, then prove the closed staging file is byte-for-byte ready
    // before ReplaceFileW can move the original configuration.
    set_mcp_windows_security(&replacement_path, original_security)?;
    if mcp_windows_security(&replacement_path)? != *original_security {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the staging owner, DACL, or DACL protection differs from the original MCP config",
        )
        .into());
    }
    // A named backup makes both documented partial ReplaceFileW outcomes
    // recoverable instead of leaving the client config in an unknown state.
    let mut backup_path = tempfile::NamedTempFile::new_in(
        config_path
            .parent()
            .expect("validated configuration path has a parent"),
    )?
    .into_temp_path();
    fs::remove_file(&backup_path)?;
    let replaced = config_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replacement = replacement_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let backup = backup_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            backup.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        let replace_error = io::Error::last_os_error();
        match replace_error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT) => {}
            Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) => {
                if let Err(restore_error) =
                    move_mcp_windows_file_replacing(&backup_path, config_path)
                {
                    let preserved_path = replacement_path.to_path_buf();
                    let preserved_backup_path = backup_path.to_path_buf();
                    replacement_path.disable_cleanup(true);
                    backup_path.disable_cleanup(true);
                    return Err(AtomicWriteFailure {
                        error: io::Error::new(
                            restore_error.kind(),
                            format!(
                                "{replace_error}; restoring the original MCP config failed: {restore_error}; the replacement remains at {} and the original remains at {}; the destination outcome is unknown",
                                preserved_path.display(),
                                preserved_backup_path.display()
                            ),
                        ),
                        outcome: AtomicWriteOutcome::Unknown,
                    });
                }
            }
            _ => {}
        }
        return Err(replace_error.into());
    }

    // ReplaceFileW moves the exact displaced destination to the named backup in the same
    // operation that publishes the replacement. Validate that displaced file, not a racy read of
    // the live path, and restore it before reporting NotCommitted on any mismatch.
    let displaced_validation = ensure_expected_source(&backup_path, Some(expected_contents))
        .and_then(|()| mcp_windows_security(&backup_path))
        .and_then(|displaced_security| {
            if displaced_security == *original_security {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the displaced MCP config security differs from the source used for planning",
                ))
            }
        });
    if let Err(validation_error) = displaced_validation {
        return Err(rollback_mcp_windows_replacement(
            &mut backup_path,
            config_path,
            validation_error,
            move_mcp_windows_file_replacing,
        ));
    }

    finalize_mcp_windows_replacement(
        &mut backup_path,
        config_path,
        original_security,
        set_mcp_windows_security,
        mcp_windows_security,
        move_mcp_windows_file_replacing,
    )
}

#[cfg(windows)]
fn finalize_mcp_windows_replacement<ApplySecurity, QuerySecurity, RestoreBackup>(
    backup_path: &mut tempfile::TempPath,
    config_path: &Path,
    original_security: &McpWindowsSecurity,
    apply_security: ApplySecurity,
    query_security: QuerySecurity,
    restore_backup: RestoreBackup,
) -> Result<(), AtomicWriteFailure>
where
    ApplySecurity: FnOnce(&Path, &McpWindowsSecurity) -> io::Result<()>,
    QuerySecurity: FnOnce(&Path) -> io::Result<McpWindowsSecurity>,
    RestoreBackup: FnOnce(&Path, &Path) -> io::Result<()>,
{
    // ReplaceFileW can merge destination metadata into the replacement even
    // after staging was exact. Reapply the captured fields on the live path;
    // every error from this point must restore the named original backup.
    let validation = apply_security(config_path, original_security)
        .and_then(|()| query_security(config_path))
        .and_then(|replacement_security| {
            if replacement_security == *original_security {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the replacement owner, DACL, or DACL protection differs from the original MCP config",
                ))
            }
        });
    if let Err(validation_error) = validation {
        return Err(rollback_mcp_windows_replacement(
            backup_path,
            config_path,
            validation_error,
            restore_backup,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn move_mcp_windows_file_replacing(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn rollback_mcp_windows_replacement<RestoreBackup>(
    backup_path: &mut tempfile::TempPath,
    config_path: &Path,
    validation_error: io::Error,
    restore_backup: RestoreBackup,
) -> AtomicWriteFailure
where
    RestoreBackup: FnOnce(&Path, &Path) -> io::Result<()>,
{
    if let Err(restore_error) = restore_backup(backup_path, config_path) {
        let preserved_backup_path = backup_path.to_path_buf();
        backup_path.disable_cleanup(true);
        return AtomicWriteFailure {
            error: io::Error::new(
                restore_error.kind(),
                format!(
                    "{validation_error}; restoring the original MCP config failed: {restore_error}; the original remains at {}; the destination outcome is unknown",
                    preserved_backup_path.display()
                ),
            ),
            outcome: AtomicWriteOutcome::Unknown,
        };
    }
    AtomicWriteFailure {
        error: validation_error,
        outcome: AtomicWriteOutcome::NotCommitted,
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct McpWindowsSecurity {
    owner: Vec<u8>,
    dacl: Vec<u8>,
    dacl_protected: bool,
    descriptor: Box<[usize]>,
}

#[cfg(windows)]
impl PartialEq for McpWindowsSecurity {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.dacl == other.dacl
            && self.dacl_protected == other.dacl_protected
    }
}

#[cfg(windows)]
impl Eq for McpWindowsSecurity {}

#[cfg(windows)]
impl McpWindowsSecurity {
    fn descriptor(&self) -> *mut std::ffi::c_void {
        self.descriptor.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
fn mcp_windows_security(path: &Path) -> io::Result<McpWindowsSecurity> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorLength, IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED,
    };

    struct LocalSecurityDescriptor(*mut std::ffi::c_void);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the MCP config has no valid owner or DACL",
        ));
    }
    let owner_size = unsafe { GetLengthSid(owner) } as usize;
    let dacl_size = usize::from(unsafe { &*dacl }.AclSize);
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor_size = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if descriptor_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the MCP config has no valid security descriptor",
        ));
    }
    let mut descriptor_copy =
        vec![0_usize; descriptor_size.div_ceil(std::mem::size_of::<usize>())].into_boxed_slice();
    unsafe {
        std::ptr::copy_nonoverlapping(
            descriptor.cast::<u8>(),
            descriptor_copy.as_mut_ptr().cast::<u8>(),
            descriptor_size,
        );
    }
    Ok(McpWindowsSecurity {
        owner: unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_size) }.to_vec(),
        dacl: unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), dacl_size) }.to_vec(),
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        descriptor: descriptor_copy,
    })
}

#[cfg(windows)]
fn set_mcp_windows_security(path: &Path, security: &McpWindowsSecurity) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let protection = if security.dacl_protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | protection,
            security.owner.as_ptr().cast_mut().cast(),
            std::ptr::null_mut(),
            security.dacl.as_ptr().cast::<ACL>(),
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(windows)]
fn mcp_windows_staging_file(
    parent: &Path,
    security: &McpWindowsSecurity,
) -> io::Result<tempfile::NamedTempFile> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.descriptor(),
        bInheritHandle: 0,
    };
    tempfile::Builder::new().make_in(parent, |path| {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_handle(raw) })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum;
    use serde_json::{Value, json};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn request(targets: Vec<InstallTarget>, all: bool, dry_run: bool) -> InstallRequest {
        InstallRequest {
            targets,
            all,
            server_name: "satelle".to_string(),
            satelle_path: Some(PathBuf::from("/opt/satelle/bin/satelle")),
            profile: None,
            dry_run,
        }
    }

    fn environment(root: &Path, platform: Platform) -> InstallEnvironment {
        let home = root.join("home");
        InstallEnvironment {
            platform,
            claude_config_dir: home.clone(),
            cline_mcp_settings_path: home.join(".cline/data/settings/cline_mcp_settings.json"),
            codex_home: home.join(".codex"),
            home,
            config_home: root.join("xdg-config"),
            app_data: Some(root.join("app-data")),
        }
    }

    fn read_json(path: impl AsRef<Path>) -> Value {
        serde_json::from_str(&fs::read_to_string(path).expect("config should be readable"))
            .expect("installer output should be JSON")
    }

    #[cfg(target_os = "macos")]
    fn install_native_macos_test_acl(path: &Path) {
        let output = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read")
            .arg(path)
            .output()
            .expect("run the native macOS ACL editor");
        assert!(
            output.status.success(),
            "install a real macOS ACL at {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn exposes_every_named_install_target() {
        let names = InstallTarget::value_variants()
            .iter()
            .map(|target| target.to_possible_value().unwrap().get_name().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            [
                "claude-code",
                "claude-desktop",
                "codex",
                "cursor",
                "vscode",
                "windsurf",
                "gemini",
                "opencode",
                "cline",
                "roo-code",
                "droid",
                "antigravity",
            ]
        );
    }

    #[test]
    fn relative_xdg_config_home_is_ignored() {
        let absolute = std::env::current_dir().unwrap().join("config");
        assert_eq!(absolute_path(OsString::new()), None);
        assert_eq!(absolute_path(OsString::from("relative/config")), None);
        assert_eq!(
            absolute_path(absolute.clone().into_os_string()),
            Some(absolute)
        );
    }

    #[test]
    fn cline_cli_path_and_lock_follow_upstream_environment_precedence() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("home");
        let explicit = fixture.path().join("explicit/cline.json");
        let data = fixture.path().join("data");
        let cline = fixture.path().join("cline");

        assert_eq!(
            resolve_cline_mcp_settings_path(
                &home,
                Some(explicit.clone().into_os_string()),
                Some(data.clone().into_os_string()),
                Some(cline.clone().into_os_string()),
            ),
            explicit
        );
        assert_eq!(
            resolve_cline_mcp_settings_path(
                &home,
                Some(OsString::from("  ")),
                Some(data.clone().into_os_string()),
                Some(cline.clone().into_os_string()),
            ),
            data.join("settings/cline_mcp_settings.json")
        );
        assert_eq!(
            resolve_cline_mcp_settings_path(
                &home,
                None,
                None,
                Some(cline.clone().into_os_string()),
            ),
            cline.join("data/settings/cline_mcp_settings.json")
        );
        assert_eq!(
            resolve_cline_mcp_settings_path(&home, None, None, None),
            home.join(".cline/data/settings/cline_mcp_settings.json")
        );

        let mut environment = environment(fixture.path(), Platform::Linux);
        environment.cline_mcp_settings_path = data.join("settings/cline_mcp_settings.json");
        let report = install_with_environment(
            request(vec![InstallTarget::Cline], false, false),
            &environment,
        )
        .expect("install Cline at the upstream-resolved path");
        assert_eq!(
            report.changes[0].path.as_deref(),
            Some(environment.cline_mcp_settings_path.as_path())
        );
        assert!(environment.cline_mcp_settings_path.exists());
        assert!(!path_with_suffix(&environment.cline_mcp_settings_path, ".lock").exists());
    }

    #[test]
    fn installer_paths_are_stable_across_client_working_directories() {
        let fixture = tempfile::tempdir().unwrap();
        let mut environment = environment(fixture.path(), Platform::Linux);
        environment.claude_config_dir = fixture.path().join("claude-config");
        let mut install_request = request(vec![InstallTarget::ClaudeCode], false, false);
        install_request.satelle_path = Some(PathBuf::from("relative/satelle"));

        let report = install_with_environment(install_request, &environment).unwrap();
        let config_path = environment.claude_config_dir.join(".claude.json");
        let expected_command = std::env::current_dir()
            .unwrap()
            .join("relative/satelle")
            .to_string_lossy()
            .into_owned();

        assert_eq!(
            report.changes[0].path.as_deref(),
            Some(config_path.as_path())
        );
        assert_eq!(
            read_json(config_path)["mcpServers"]["satelle"]["command"],
            expected_command
        );
    }

    #[test]
    fn installs_every_target_at_its_authoritative_global_path() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::MacOs);

        let report = install_with_environment(request(Vec::new(), true, false), &environment)
            .expect("all targets should install");

        assert_eq!(report.changes.len(), 12);
        assert!(report.changes.iter().all(|change| !change.skipped));

        let home = &environment.home;
        let config_home = &environment.config_home;
        let application_support = home.join("Library/Application Support");
        let expected = [
            home.join(".claude.json"),
            application_support.join("Claude/claude_desktop_config.json"),
            home.join(".codex/config.toml"),
            home.join(".cursor/mcp.json"),
            application_support.join("Code/User/mcp.json"),
            home.join(".codeium/windsurf/mcp_config.json"),
            home.join(".gemini/settings.json"),
            config_home.join("opencode/opencode.json"),
            home.join(".cline/data/settings/cline_mcp_settings.json"),
            application_support.join(
                "Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
            ),
            home.join(".factory/mcp.json"),
            home.join(".gemini/config/mcp_config.json"),
        ];
        assert_eq!(
            report
                .changes
                .iter()
                .map(|change| change.path.clone().unwrap())
                .collect::<Vec<_>>(),
            expected
        );

        assert_eq!(
            read_json(home.join(".claude.json"))["mcpServers"]["satelle"],
            json!({
                "type": "stdio",
                "command": "/opt/satelle/bin/satelle",
                "args": ["mcp", "serve"]
            })
        );
        assert_eq!(
            read_json(application_support.join("Code/User/mcp.json"))["servers"]["satelle"],
            json!({
                "type": "stdio",
                "command": "/opt/satelle/bin/satelle",
                "args": ["mcp", "serve"]
            })
        );
        assert_eq!(
            read_json(config_home.join("opencode/opencode.json"))["mcp"]["satelle"],
            json!({
                "type": "local",
                "command": ["/opt/satelle/bin/satelle", "mcp", "serve"]
            })
        );
        assert_eq!(
            read_json(home.join(".cline/data/settings/cline_mcp_settings.json"))["mcpServers"]["satelle"],
            json!({
                "command": "/opt/satelle/bin/satelle",
                "args": ["mcp", "serve"]
            })
        );
        assert!(
            !path_with_suffix(
                &home.join(".cline/data/settings/cline_mcp_settings.json"),
                ".lock"
            )
            .exists(),
            "Cline settings lock must be released after installation"
        );

        let codex = fs::read_to_string(home.join(".codex/config.toml")).unwrap();
        let codex = codex.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(
            codex["mcp_servers"]["satelle"]["command"].as_str(),
            Some("/opt/satelle/bin/satelle")
        );
        assert_eq!(
            codex["mcp_servers"]["satelle"]["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>(),
            ["mcp", "serve"]
        );
    }

    #[test]
    fn explicit_profile_is_preserved_in_every_installed_launch_command() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::MacOs);
        let mut install_request = request(Vec::new(), true, false);
        install_request.profile = Some("work".to_string());

        let report = install_with_environment(install_request, &environment)
            .expect("all targets should preserve the selected profile");
        let expected_args = json!(["--profile", "work", "mcp", "serve"]);

        for change in report.changes {
            let path = change.path.expect("macOS publishes every target path");
            match change.target {
                InstallTarget::Codex => {
                    let codex = fs::read_to_string(path)
                        .unwrap()
                        .parse::<toml_edit::DocumentMut>()
                        .unwrap();
                    assert_eq!(
                        codex["mcp_servers"]["satelle"]["args"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|value| value.as_str().unwrap())
                            .collect::<Vec<_>>(),
                        ["--profile", "work", "mcp", "serve"]
                    );
                }
                InstallTarget::OpenCode => {
                    assert_eq!(
                        read_json(path)["mcp"]["satelle"]["command"],
                        json!([
                            "/opt/satelle/bin/satelle",
                            "--profile",
                            "work",
                            "mcp",
                            "serve"
                        ])
                    );
                }
                target => {
                    let root_key = if target == InstallTarget::VsCode {
                        "servers"
                    } else {
                        "mcpServers"
                    };
                    assert_eq!(
                        read_json(path)[root_key]["satelle"]["args"],
                        expected_args,
                        "{} discarded the explicit profile",
                        target.label()
                    );
                }
            }
        }
    }

    #[test]
    fn installs_every_target_at_its_windows_global_path_and_format() {
        const SATELLE_COMMAND: &str = r"C:\Program Files\Satelle\satelle.exe";

        let fixture = tempfile::tempdir().unwrap();
        let unix_home = fixture.path().join("unix-home");
        let windows_home = fixture.path().join("windows-home");
        assert_eq!(
            resolve_home(
                Platform::Windows,
                Some(unix_home.clone().into_os_string()),
                Some(windows_home.clone().into_os_string()),
            )
            .unwrap(),
            windows_home
        );
        assert_eq!(
            resolve_home(
                Platform::Linux,
                Some(unix_home.clone().into_os_string()),
                Some(windows_home.into_os_string()),
            )
            .unwrap(),
            unix_home
        );

        let mut environment = environment(fixture.path(), Platform::Windows);
        environment.codex_home = fixture.path().join("custom-codex-home");
        let mut install_request = request(Vec::new(), true, false);
        install_request.satelle_path = Some(PathBuf::from(SATELLE_COMMAND));

        #[cfg(windows)]
        let cursor_security = {
            let cursor = environment.home.join(".cursor/mcp.json");
            fs::create_dir_all(cursor.parent().unwrap()).unwrap();
            fs::write(&cursor, "{\"mcpServers\":{}}\n").unwrap();
            let user = current_windows_user_sid();
            set_windows_owner(&cursor, &user);
            set_windows_acl(
                &cursor,
                &[
                    format!("*{user}:(F)"),
                    "*S-1-5-18:(F)".to_string(),
                    "*S-1-5-32-544:(F)".to_string(),
                ],
            );
            let security = mcp_windows_security(&cursor).expect("read explicit Cursor config DACL");
            assert!(
                security.dacl_protected,
                "the explicit fixture DACL must be protected from inheritance"
            );
            security
        };

        let report = install_with_environment(install_request, &environment)
            .expect("all targets should install for Windows");

        assert_eq!(report.changes.len(), 12);
        assert!(report.changes.iter().all(|change| !change.skipped));

        let home = &environment.home;
        let config_home = &environment.config_home;
        let app_data = environment.app_data.as_ref().unwrap();
        let expected_paths = [
            home.join(".claude.json"),
            app_data.join("Claude/claude_desktop_config.json"),
            environment.codex_home.join("config.toml"),
            home.join(".cursor/mcp.json"),
            app_data.join("Code/User/mcp.json"),
            home.join(".codeium/windsurf/mcp_config.json"),
            home.join(".gemini/settings.json"),
            config_home.join("opencode/opencode.json"),
            home.join(".cline/data/settings/cline_mcp_settings.json"),
            app_data.join(
                "Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
            ),
            home.join(".factory/mcp.json"),
            home.join(".gemini/config/mcp_config.json"),
        ];
        assert_eq!(
            report
                .changes
                .iter()
                .map(|change| change.path.clone().unwrap())
                .collect::<Vec<_>>(),
            expected_paths
        );

        let standard = json!({
            "command": SATELLE_COMMAND,
            "args": ["mcp", "serve"]
        });
        let typed_stdio = json!({
            "type": "stdio",
            "command": SATELLE_COMMAND,
            "args": ["mcp", "serve"]
        });
        let json_expectations = [
            (home.join(".claude.json"), "mcpServers", typed_stdio.clone()),
            (
                app_data.join("Claude/claude_desktop_config.json"),
                "mcpServers",
                standard.clone(),
            ),
            (
                home.join(".cursor/mcp.json"),
                "mcpServers",
                standard.clone(),
            ),
            (
                app_data.join("Code/User/mcp.json"),
                "servers",
                typed_stdio.clone(),
            ),
            (
                home.join(".codeium/windsurf/mcp_config.json"),
                "mcpServers",
                standard.clone(),
            ),
            (
                home.join(".gemini/settings.json"),
                "mcpServers",
                standard.clone(),
            ),
            (
                config_home.join("opencode/opencode.json"),
                "mcp",
                json!({
                    "type": "local",
                    "command": [SATELLE_COMMAND, "mcp", "serve"]
                }),
            ),
            (
                home.join(".cline/data/settings/cline_mcp_settings.json"),
                "mcpServers",
                json!({
                    "command": SATELLE_COMMAND,
                    "args": ["mcp", "serve"]
                }),
            ),
            (
                app_data.join(
                    "Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
                ),
                "mcpServers",
                standard.clone(),
            ),
            (home.join(".factory/mcp.json"), "mcpServers", typed_stdio),
            (
                home.join(".gemini/config/mcp_config.json"),
                "mcpServers",
                standard,
            ),
        ];
        for (path, root_key, expected) in json_expectations {
            assert_eq!(
                read_json(path)[root_key]["satelle"],
                expected,
                "unexpected Windows MCP format at {root_key}"
            );
        }

        let codex = fs::read_to_string(environment.codex_home.join("config.toml")).unwrap();
        let codex = codex.parse::<toml_edit::DocumentMut>().unwrap();
        assert_eq!(
            codex["mcp_servers"]["satelle"]["command"].as_str(),
            Some(SATELLE_COMMAND)
        );
        assert_eq!(
            codex["mcp_servers"]["satelle"]["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>(),
            ["mcp", "serve"]
        );
        assert!(!environment.home.join(".codex").exists());
        #[cfg(windows)]
        {
            let replacement_security =
                mcp_windows_security(&environment.home.join(".cursor/mcp.json"))
                    .expect("read replaced Cursor config DACL");
            assert!(
                replacement_security.dacl_protected,
                "Windows replacement must preserve DACL protection"
            );
            assert_eq!(
                replacement_security, cursor_security,
                "Windows replacement must preserve the explicit owner, DACL, and protection"
            );
        }
    }

    #[test]
    fn dry_run_reports_changes_without_creating_or_modifying_files() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        let cursor = environment.home.join(".cursor/mcp.json");
        fs::create_dir_all(cursor.parent().unwrap()).unwrap();
        let original = b"{\n  \"mcpServers\": {\"other\": {\"command\": \"other\"}}\n}\n";
        fs::write(&cursor, original).unwrap();

        let report = install_with_environment(
            request(
                vec![
                    InstallTarget::Cursor,
                    InstallTarget::Codex,
                    InstallTarget::OpenCode,
                    InstallTarget::Cline,
                ],
                false,
                true,
            ),
            &environment,
        )
        .expect("dry-run should plan valid configs");

        assert!(report.dry_run);
        assert_eq!(report.changes.len(), 4);
        assert!(report.changes.iter().all(|change| change.changed));
        assert_eq!(fs::read(&cursor).unwrap(), original);
        assert!(!environment.home.join(".codex").exists());
        assert!(!environment.config_home.exists());
        assert!(
            !path_with_suffix(&environment.cline_mcp_settings_path, ".lock").exists(),
            "dry-run must not acquire the client settings lock"
        );
    }

    #[test]
    fn preserves_unrelated_json_jsonc_and_toml_configuration() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        let cursor = environment.home.join(".cursor/mcp.json");
        let opencode = environment.config_home.join("opencode/opencode.json");
        let codex = environment.home.join(".codex/config.toml");
        for path in [&cursor, &opencode, &codex] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        fs::write(
            &cursor,
            r#"{
  "theme": "dark",
  "mcpServers": {"other": {"command": "other", "args": ["one"]}}
}
"#,
        )
        .unwrap();
        fs::write(
            &opencode,
            r#"{
  // OpenCode accepts JSONC in its canonical config file.
  "model": "provider/model",
  "mcp": {
    "other": {"type": "local", "command": ["other"],},
  },
}
"#,
        )
        .unwrap();
        fs::write(
            &codex,
            r#"# keep this comment
model = "gpt-example"

[mcp_servers.other]
command = "other"
args = ["one"]
"#,
        )
        .unwrap();

        install_with_environment(
            request(
                vec![
                    InstallTarget::Cursor,
                    InstallTarget::OpenCode,
                    InstallTarget::Codex,
                ],
                false,
                false,
            ),
            &environment,
        )
        .unwrap();

        let cursor = read_json(cursor);
        assert_eq!(cursor["theme"], "dark");
        assert_eq!(cursor["mcpServers"]["other"]["command"], "other");
        let opencode = read_json(opencode);
        assert_eq!(opencode["model"], "provider/model");
        assert_eq!(opencode["mcp"]["other"]["command"], json!(["other"]));
        let codex = fs::read_to_string(codex).unwrap();
        assert!(codex.contains("# keep this comment"));
        assert!(codex.contains("model = \"gpt-example\""));
        assert!(codex.contains("[mcp_servers.other]"));
    }

    #[test]
    fn reinstall_is_idempotent() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::MacOs);

        let first = install_with_environment(request(Vec::new(), true, false), &environment)
            .expect("first install should create every config");
        let before = first
            .changes
            .iter()
            .map(|change| {
                let path = change.path.as_ref().unwrap();
                (path.clone(), fs::read(path).unwrap())
            })
            .collect::<Vec<_>>();

        let second = install_with_environment(request(Vec::new(), true, false), &environment)
            .expect("reinstall should accept its own output");

        assert!(first.changes.iter().all(|change| change.changed));
        assert!(second.changes.iter().all(|change| !change.changed));
        for (path, contents) in before {
            assert_eq!(fs::read(path).unwrap(), contents);
        }
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_preserves_unix_permissions_and_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        let cursor = environment.home.join(".cursor/mcp.json");
        fs::create_dir_all(cursor.parent().unwrap()).unwrap();
        fs::write(&cursor, "{}\n").unwrap();
        fs::set_permissions(&cursor, fs::Permissions::from_mode(0o640)).unwrap();

        install_with_environment(
            request(vec![InstallTarget::Cursor], false, false),
            &environment,
        )
        .unwrap();

        assert_eq!(
            fs::metadata(&cursor).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let managed_config = fixture.path().join("managed-cursor.json");
        fs::write(&managed_config, "{\"mcpServers\":{}}\n").unwrap();
        fs::remove_file(&cursor).unwrap();
        symlink(&managed_config, &cursor).unwrap();

        let error = install_with_environment(
            request(vec![InstallTarget::Cursor], false, false),
            &environment,
        )
        .expect_err("atomic replacement must not destroy a managed symlink");

        assert!(error.contains("symlinked MCP config"));
        assert!(
            fs::symlink_metadata(&cursor)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(managed_config).unwrap(),
            "{\"mcpServers\":{}}\n"
        );

        fs::remove_file(&cursor).unwrap();
        let _socket = UnixListener::bind(&cursor).unwrap();
        let error = install_with_environment(
            request(vec![InstallTarget::Cursor], false, false),
            &environment,
        )
        .expect_err("special filesystem nodes are not configuration files");
        assert!(error.contains("non-regular MCP config"));
    }

    #[test]
    fn preflight_failure_prevents_partial_writes() {
        let fixture = tempfile::tempdir().unwrap();
        let install_environment = environment(fixture.path(), Platform::Linux);
        let cursor = install_environment.home.join(".cursor/mcp.json");
        let codex = install_environment.home.join(".codex/config.toml");
        for path in [&cursor, &codex] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        let original_cursor = b"{\"mcpServers\":{\"other\":{\"command\":\"other\"}}}\n";
        fs::write(&cursor, original_cursor).unwrap();
        fs::write(&codex, "this is not valid = [toml\n").unwrap();

        let error = install_with_environment(
            request(
                vec![InstallTarget::Cursor, InstallTarget::Codex],
                false,
                false,
            ),
            &install_environment,
        )
        .expect_err("invalid later config should fail the complete plan");

        assert!(error.contains("config.toml"));
        assert_eq!(fs::read(&cursor).unwrap(), original_cursor);

        let plan = plan_target(
            InstallTarget::Cursor,
            cursor.clone(),
            "satelle",
            "/opt/satelle/bin/satelle",
            &mcp_serve_args(None),
        )
        .unwrap();

        let client_edit = "{\"mcpServers\":{\"client-added\":{\"command\":\"other\"}}}\n";
        fs::write(&cursor, client_edit).unwrap();

        let error = ensure_source_unchanged(&plan).expect_err("stale plan must be rejected");
        assert!(error.contains("changed while the install was being planned"));
        assert_eq!(fs::read_to_string(cursor).unwrap(), client_edit);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let fixture = tempfile::tempdir().unwrap();
            let environment = environment(fixture.path(), Platform::Linux);
            let cursor = environment.home.join(".cursor/mcp.json");
            let codex = environment.home.join(".codex/config.toml");
            let codex_parent = codex.parent().unwrap();
            fs::create_dir_all(codex_parent).unwrap();
            fs::write(&codex, "model = \"gpt-example\"\n").unwrap();
            fs::set_permissions(codex_parent, fs::Permissions::from_mode(0o500)).unwrap();

            let error = install_with_environment(
                request(
                    vec![InstallTarget::Cursor, InstallTarget::Codex],
                    false,
                    false,
                ),
                &environment,
            )
            .expect_err("a later unwritable config should report the earlier write");

            fs::set_permissions(codex_parent, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(error.contains("already updated before the failure"));
            assert!(error.contains(&cursor.display().to_string()));
            assert!(error.contains("not updated"));
            assert!(error.contains(&codex.display().to_string()));
            assert!(cursor.exists());
            assert_eq!(
                fs::read_to_string(codex).unwrap(),
                "model = \"gpt-example\"\n"
            );
        }
    }

    #[test]
    fn every_plan_and_global_revalidation_finishes_before_cline_lock_acquisition() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        take_install_test_events();

        install_with_environment(
            request(
                vec![
                    InstallTarget::Cursor,
                    InstallTarget::Cline,
                    InstallTarget::RooCode,
                ],
                false,
                false,
            ),
            &environment,
        )
        .expect("the ordered install fixture should succeed");

        assert_eq!(
            take_install_test_events(),
            [
                InstallTestEvent::Planned(InstallTarget::Cursor),
                InstallTestEvent::Planned(InstallTarget::Cline),
                InstallTestEvent::Planned(InstallTarget::RooCode),
                InstallTestEvent::GloballyRevalidated(InstallTarget::Cursor),
                InstallTestEvent::GloballyRevalidated(InstallTarget::Cline),
                InstallTestEvent::GloballyRevalidated(InstallTarget::RooCode),
                InstallTestEvent::AcquiringClineLock,
            ],
            "moving any global source revalidation under Cline's compatible lock must change this order"
        );
    }

    #[test]
    fn unchanged_cline_config_does_not_acquire_its_write_lock() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        let cline = environment.cline_mcp_settings_path.clone();
        install_with_environment(
            request(vec![InstallTarget::Cline], false, false),
            &environment,
        )
        .expect("seed the already-current Cline config");
        let lock = path_with_suffix(&cline, ".lock");
        fs::create_dir_all(&lock).unwrap();

        let report = install_with_environment(
            request(
                vec![InstallTarget::Cline, InstallTarget::Cursor],
                false,
                false,
            ),
            &environment,
        )
        .expect("an unchanged Cline target must not inspect its held write lock");

        assert!(!report.changes[0].changed);
        assert!(report.changes[1].changed);
        assert!(environment.home.join(".cursor/mcp.json").exists());
        assert!(lock.exists(), "the unrelated Cline lock must be untouched");
    }

    #[test]
    fn cline_lock_respects_an_expired_monotonic_deadline() {
        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("cline_mcp_settings.json");

        let error = match acquire_cline_settings_lock_until(&config, Instant::now()) {
            Ok(_) => panic!("an expired monotonic acquisition must not attempt the lock"),
            Err(error) => error,
        };

        assert!(error.contains("timed out waiting for Cline MCP settings lock"));
        assert!(!path_with_suffix(&config, ".lock").exists());
    }

    #[cfg(windows)]
    #[test]
    fn post_replace_finalization_rolls_back_validation_failures_and_reports_unknown_restoration() {
        let original_security = McpWindowsSecurity {
            owner: vec![1],
            dacl: vec![2],
            dacl_protected: true,
            descriptor: Vec::new().into_boxed_slice(),
        };
        let validation_failures = [
            (
                "query error",
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "security query failed",
                )),
            ),
            (
                "owner mismatch",
                Ok(McpWindowsSecurity {
                    owner: vec![3],
                    dacl: vec![2],
                    dacl_protected: true,
                    descriptor: Vec::new().into_boxed_slice(),
                }),
            ),
            (
                "DACL byte mismatch",
                Ok(McpWindowsSecurity {
                    owner: vec![1],
                    dacl: vec![3],
                    dacl_protected: true,
                    descriptor: Vec::new().into_boxed_slice(),
                }),
            ),
            (
                "DACL protection mismatch",
                Ok(McpWindowsSecurity {
                    owner: vec![1],
                    dacl: vec![2],
                    dacl_protected: false,
                    descriptor: Vec::new().into_boxed_slice(),
                }),
            ),
        ];

        for (case, validation) in validation_failures {
            let fixture = tempfile::tempdir().unwrap();
            let config = fixture.path().join("mcp.json");
            fs::write(&config, b"replacement").unwrap();
            let mut backup = tempfile::NamedTempFile::new_in(fixture.path())
                .unwrap()
                .into_temp_path();
            fs::write(&backup, b"original").unwrap();

            let failure = finalize_mcp_windows_replacement(
                &mut backup,
                &config,
                &original_security,
                |_, _| Ok(()),
                |_| validation,
                move_mcp_windows_file_replacing,
            )
            .expect_err(case);

            assert_eq!(failure.outcome, AtomicWriteOutcome::NotCommitted, "{case}");
            assert_eq!(fs::read(&config).unwrap(), b"original", "{case}");
        }

        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"replacement").unwrap();
        let mut backup = tempfile::NamedTempFile::new_in(fixture.path())
            .unwrap()
            .into_temp_path();
        fs::write(&backup, b"original").unwrap();
        let reported_backup = backup.to_path_buf();

        let failure = finalize_mcp_windows_replacement(
            &mut backup,
            &config,
            &original_security,
            |_, _| Ok(()),
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "security query failed",
                ))
            },
            |_, _| Err(io::Error::other("restoration failed")),
        )
        .expect_err("a restoration failure must make the replacement outcome unknown");

        assert_eq!(failure.outcome, AtomicWriteOutcome::Unknown);
        assert!(
            failure
                .to_string()
                .contains(&reported_backup.display().to_string())
        );
        assert_eq!(fs::read(&reported_backup).unwrap(), b"original");
        assert_eq!(fs::read(&config).unwrap(), b"replacement");

        let applied = PlannedWrite {
            target: InstallTarget::Cursor,
            path: fixture.path().join("applied.json"),
            original: None,
            contents: String::new(),
            changed: true,
        };
        let unknown = PlannedWrite {
            target: InstallTarget::Cline,
            path: config,
            original: None,
            contents: String::new(),
            changed: true,
        };
        let untouched = PlannedWrite {
            target: InstallTarget::RooCode,
            path: fixture.path().join("untouched.json"),
            original: None,
            contents: String::new(),
            changed: true,
        };
        let unknown_path = unknown.path.display().to_string();
        let error = write_failure_error(&unknown, failure, &[&applied], &[&untouched]);

        assert!(error.contains(&applied.path.display().to_string()));
        assert!(error.contains(&untouched.path.display().to_string()));
        assert_eq!(
            error.matches(&unknown_path).count(),
            1,
            "an unknown replacement must appear only in the cause, not in the applied or untouched lists"
        );
    }

    #[cfg(windows)]
    #[test]
    fn post_replace_security_apply_error_rolls_back_before_querying() {
        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"replacement").unwrap();
        let mut backup = tempfile::NamedTempFile::new_in(fixture.path())
            .unwrap()
            .into_temp_path();
        fs::write(&backup, b"original").unwrap();
        let original_security = McpWindowsSecurity {
            owner: vec![1],
            dacl: vec![2],
            dacl_protected: true,
            descriptor: Vec::new().into_boxed_slice(),
        };

        let failure = finalize_mcp_windows_replacement(
            &mut backup,
            &config,
            &original_security,
            |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "apply failed",
                ))
            },
            |_| panic!("security query must not run after an apply error"),
            move_mcp_windows_file_replacing,
        )
        .expect_err("a post-replacement security apply error must roll back");

        assert_eq!(failure.outcome, AtomicWriteOutcome::NotCommitted);
        assert_eq!(fs::read(&config).unwrap(), b"original");
    }

    #[cfg(windows)]
    #[test]
    fn atomic_replacement_preserves_an_unprotected_inherited_dacl_exactly() {
        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"original").unwrap();
        run_icacls(
            &config,
            &["/inheritance:e"],
            "enable fixture ACL inheritance",
        );

        let original_security = mcp_windows_security(&config).unwrap();
        assert!(
            !original_security.dacl_protected,
            "the regression must exercise an inherited, unprotected DACL"
        );

        write_atomic(&config, "replacement", Some("original"))
            .expect("replace the real Windows fixture");

        let replacement_security = mcp_windows_security(&config).unwrap();
        assert_eq!(replacement_security.owner, original_security.owner);
        assert_eq!(replacement_security.dacl, original_security.dacl);
        assert_eq!(
            replacement_security.dacl_protected,
            original_security.dacl_protected
        );
        assert_eq!(fs::read(&config).unwrap(), b"replacement");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_replacement_preserves_unix_owner_group_mode_and_posix_acl() {
        use rustix::fs::XattrFlags;
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"original").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();

        // Linux stores extended POSIX ACLs in this xattr. The named-user ACE
        // keeps the ACL distinct from the three mode-bit entries.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (0x01_u16, 0x06_u16, u32::MAX),
            (0x02, 0x04, 65_534),
            (0x04, 0x00, u32::MAX),
            (0x10, 0x04, u32::MAX),
            (0x20, 0x00, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permissions.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let original = fs::File::options()
            .read(true)
            .write(true)
            .open(&config)
            .unwrap();
        rustix::fs::fsetxattr(
            &original,
            c"system.posix_acl_access",
            &acl,
            XattrFlags::empty(),
        )
        .unwrap();
        rustix::fs::fsetxattr(
            &original,
            c"user.satelle-test",
            b"preserve this xattr",
            XattrFlags::empty(),
        )
        .unwrap();
        // Apply this after the ACL fixture so the snapshot contains both the
        // exact ACL and a set-ID bit that a later content write would clear.
        original
            .set_permissions(fs::Permissions::from_mode(0o4640))
            .unwrap();
        let original_security = unix_security(&original).unwrap();
        let original_identity = unix_file_identity(&original).unwrap();
        assert_ne!(original_security.mode & 0o4000, 0);
        drop(original);

        write_atomic(&config, "replacement", Some("original"))
            .expect("replace the real Unix fixture");

        let replacement = fs::File::open(&config).unwrap();
        assert_eq!(unix_security(&replacement).unwrap(), original_security);
        assert_ne!(unix_file_identity(&replacement).unwrap(), original_identity);
        assert_eq!(fs::read(&config).unwrap(), b"replacement");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_security_apply_failure_is_not_committed_and_preserves_the_destination() {
        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"original").unwrap();
        let original = fs::File::open(&config).unwrap();
        let original_identity = unix_file_identity(&original).unwrap();
        let original_security = unix_security(&original).unwrap();
        assert_ne!(
            original_security.owner, 0,
            "this regression requires a non-root runner"
        );

        let staged = tempfile::NamedTempFile::new_in(fixture.path()).unwrap();
        fs::write(staged.path(), b"replacement").unwrap();
        let mut unauthorized = original_security.clone();
        unauthorized.owner = if unauthorized.owner == u32::MAX - 1 {
            unauthorized.owner - 1
        } else {
            unauthorized.owner + 1
        };

        let failure = finalize_unix_staging(staged.as_file(), &unauthorized)
            .expect_err("an unauthorized real fchown must fail closed");

        assert_eq!(failure.outcome, AtomicWriteOutcome::NotCommitted);
        assert_eq!(fs::read(&config).unwrap(), b"original");
        let unchanged = fs::File::open(&config).unwrap();
        assert_eq!(unix_file_identity(&unchanged).unwrap(), original_identity);
        assert_eq!(unix_security(&unchanged).unwrap(), original_security);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unix_security_finalizer_removes_staged_xattrs_absent_from_source() {
        use rustix::fs::XattrFlags;

        let fixture = tempfile::tempdir().unwrap();
        let source_path = fixture.path().join("source.json");
        fs::write(&source_path, b"original").unwrap();
        let source = fs::File::open(&source_path).unwrap();
        let source_security = unix_security(&source).unwrap();

        let staged = tempfile::NamedTempFile::new_in(fixture.path()).unwrap();
        rustix::fs::fsetxattr(
            staged.as_file(),
            c"user.satelle-extra",
            b"must be removed",
            XattrFlags::empty(),
        )
        .unwrap();

        finalize_unix_staging(staged.as_file(), &source_security).unwrap();

        assert_eq!(unix_security(staged.as_file()).unwrap(), source_security);
    }

    #[test]
    fn atomic_writer_restores_a_substituted_destination_after_preflight_comparison() {
        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"original").unwrap();
        let replacement = fixture.path().join("replacement.json");
        fs::write(&replacement, b"external replacement").unwrap();

        let failure = write_atomic_with_after_preflight_comparison(
            &config,
            "stale planned replacement",
            Some("original"),
            || {
                fs::remove_file(&config).unwrap();
                fs::rename(&replacement, &config).unwrap();
            },
        )
        .expect_err("a substituted destination must be restored after the atomic exchange");

        assert_eq!(failure.outcome, AtomicWriteOutcome::NotCommitted);
        assert_eq!(fs::read(&config).unwrap(), b"external replacement");
    }

    #[test]
    fn atomic_writer_restores_an_edit_after_preflight_comparison() {
        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"original").unwrap();
        #[cfg(unix)]
        let original_identity = unix_file_identity(&fs::File::open(&config).unwrap()).unwrap();

        let failure = write_atomic_with_after_preflight_comparison(
            &config,
            "stale planned replacement",
            Some("original"),
            || fs::write(&config, b"client edit").unwrap(),
        )
        .expect_err("a post-comparison same-inode edit must be atomically displaced and restored");

        assert_eq!(failure.outcome, AtomicWriteOutcome::NotCommitted);
        assert_eq!(fs::read(&config).unwrap(), b"client edit");
        #[cfg(unix)]
        assert_eq!(
            unix_file_identity(&fs::File::open(&config).unwrap()).unwrap(),
            original_identity,
            "rollback must restore the exact client-edited inode"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn atomic_replacement_preserves_native_macos_acl_and_xattrs() {
        use rustix::fs::{XattrFlags, fsetxattr};

        let fixture = tempfile::tempdir().unwrap();
        let config = fixture.path().join("mcp.json");
        fs::write(&config, b"original").unwrap();
        let original = fs::File::options()
            .read(true)
            .write(true)
            .open(&config)
            .unwrap();
        install_native_macos_test_acl(&config);
        fsetxattr(
            &original,
            c"com.satelle.test",
            b"preserve this xattr",
            XattrFlags::empty(),
        )
        .unwrap();
        let original_security = unix_security(&original).unwrap();
        let original_identity = unix_file_identity(&original).unwrap();
        assert!(matches!(original_security.acl, MacOsExtendedAcl::Native(_)));
        drop(original);

        write_atomic(&config, "replacement", Some("original"))
            .expect("replace the real macOS fixture");

        let replacement = fs::File::open(&config).unwrap();
        assert_eq!(unix_security(&replacement).unwrap(), original_security);
        assert_ne!(unix_file_identity(&replacement).unwrap(), original_identity);
        assert_eq!(fs::read(&config).unwrap(), b"replacement");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_finalizer_removes_a_staged_acl_when_source_has_none() {
        let fixture = tempfile::tempdir().unwrap();
        let source_path = fixture.path().join("source.json");
        fs::write(&source_path, b"original").unwrap();
        let source = fs::File::open(&source_path).unwrap();
        let source_security = unix_security(&source).unwrap();
        assert_eq!(source_security.acl, MacOsExtendedAcl::None);

        let staged = tempfile::NamedTempFile::new_in(fixture.path()).unwrap();
        install_native_macos_test_acl(staged.path());
        assert!(matches!(
            unix_security(staged.as_file()).unwrap().acl,
            MacOsExtendedAcl::Native(_)
        ));

        finalize_unix_staging(staged.as_file(), &source_security).unwrap();

        assert_eq!(unix_security(staged.as_file()).unwrap(), source_security);
    }

    #[test]
    fn custom_name_and_path_apply_only_to_selected_targets() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        let mut request = request(vec![InstallTarget::Cursor], false, false);
        request.server_name = "satelle_tools".to_string();
        request.satelle_path = Some(PathBuf::from("/custom/bin/satelle"));

        let report = install_with_environment(request, &environment).unwrap();

        assert_eq!(report.changes.len(), 1);
        let cursor = read_json(environment.home.join(".cursor/mcp.json"));
        assert_eq!(
            cursor["mcpServers"]["satelle_tools"],
            json!({
                "command": "/custom/bin/satelle",
                "args": ["mcp", "serve"]
            })
        );
        assert!(cursor["mcpServers"].get("satelle").is_none());
        assert!(!environment.home.join(".codex").exists());
    }

    #[test]
    fn rejects_ambiguous_or_invalid_install_requests_without_writes() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);

        let no_target = install_with_environment(request(Vec::new(), false, false), &environment)
            .expect_err("an install needs an explicit selection");
        assert!(no_target.contains("--target"));

        let both = install_with_environment(
            request(vec![InstallTarget::Cursor], true, false),
            &environment,
        )
        .expect_err("--all and --target must conflict");
        assert!(both.contains("cannot be combined"));

        let mut invalid_name = request(vec![InstallTarget::Cursor], false, false);
        invalid_name.server_name = "not portable".to_string();
        let invalid_name = install_with_environment(invalid_name, &environment)
            .expect_err("server names must work in every client");
        assert!(invalid_name.contains("--server-name"));

        let desktop = install_with_environment(
            request(vec![InstallTarget::ClaudeDesktop], false, false),
            &environment,
        )
        .expect_err("Claude Desktop has no documented Linux path");
        assert!(desktop.contains("does not publish a Linux"));
        assert!(!environment.home.exists());
    }

    #[test]
    fn generated_entries_contain_only_process_launch_metadata() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::MacOs);
        install_with_environment(request(Vec::new(), true, false), &environment).unwrap();

        let forbidden = [
            "credential",
            "token",
            "bearer",
            "prompt",
            "transcript",
            "screenshot",
            "recording",
            "env",
            "headers",
        ];
        for target in InstallTarget::value_variants() {
            let path = config_path(*target, &environment)
                .unwrap()
                .expect("macOS supports every target");
            let raw = fs::read_to_string(path).unwrap().to_ascii_lowercase();
            for forbidden in forbidden {
                assert!(
                    !raw.contains(forbidden),
                    "{target:?} config contains forbidden install metadata: {forbidden}"
                );
            }
        }
    }

    #[test]
    fn all_skips_undocumented_claude_desktop_on_linux() {
        let fixture = tempfile::tempdir().unwrap();
        let environment = environment(fixture.path(), Platform::Linux);
        let report =
            install_with_environment(request(Vec::new(), true, true), &environment).unwrap();

        let desktop = report
            .changes
            .iter()
            .find(|change| change.target == InstallTarget::ClaudeDesktop)
            .unwrap();
        assert!(desktop.skipped);
        assert!(desktop.path.is_none());
        assert_eq!(
            report
                .changes
                .iter()
                .filter(|change| !change.skipped)
                .count(),
            11
        );
    }

    #[cfg(windows)]
    fn current_windows_user_sid() -> String {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
            ])
            .output()
            .expect("query current Windows user SID");
        assert!(output.status.success(), "PowerShell SID query failed");
        String::from_utf8(output.stdout)
            .expect("SID output should be UTF-8")
            .trim()
            .to_string()
    }

    #[cfg(windows)]
    fn set_windows_acl(path: &Path, entries: &[String]) {
        run_icacls(path, &["/inheritance:r"], "disable ACL inheritance");
        let mut grants = vec!["/grant:r".to_string()];
        grants.extend(entries.iter().cloned());
        run_icacls(
            path,
            &grants.iter().map(String::as_str).collect::<Vec<_>>(),
            "install the requested ACL grants",
        );
    }

    #[cfg(windows)]
    fn set_windows_owner(path: &Path, user: &str) {
        let owner = format!("*{user}");
        run_icacls(path, &["/setowner", &owner], "set fixture owner");
    }

    #[cfg(windows)]
    fn run_icacls(path: &Path, arguments: &[&str], operation: &str) {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(arguments)
            .output()
            .expect(operation);
        assert!(
            output.status.success(),
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
