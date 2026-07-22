use crate::{DaemonPathOverrides, SetupMode};
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use thiserror::Error;

pub const WINDOWS_SERVICE_CONFIG_SCHEMA: &str = "satelle.host-service.v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupModeSource {
    SetupFlag,
    UserConfig,
    Default,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupModeSelection {
    pub mode: SetupMode,
    pub source: SetupModeSource,
}

impl SetupModeSelection {
    pub const fn new(mode: SetupMode, source: SetupModeSource) -> Self {
        Self { mode, source }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonServicePlatform {
    Macos,
    Windows,
    Linux,
}

impl DaemonServicePlatform {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonServiceManager {
    OnDemand,
    Launchd,
    WindowsTaskScheduler,
}

impl DaemonServiceManager {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnDemand => "on_demand",
            Self::Launchd => "launchd",
            Self::WindowsTaskScheduler => "windows_task_scheduler",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistentServiceDecision {
    pub setup_mode: SetupMode,
    pub service_persistent: bool,
    pub service_scope: String,
    pub service_manager: DaemonServiceManager,
    pub privileged: bool,
    pub service_account: String,
    pub desktop_session_impact: String,
    pub fallback_reason: Option<String>,
    pub explicit_persistent_unsupported: bool,
}

impl PersistentServiceDecision {
    pub fn resolve(selection: SetupModeSelection, platform: DaemonServicePlatform) -> Self {
        if selection.mode == SetupMode::OnDemand {
            return Self::on_demand(None);
        }

        match platform {
            DaemonServicePlatform::Macos => Self::persistent(
                DaemonServiceManager::Launchd,
                "login_session",
                "authenticated_user",
                "the daemon runs only in the authenticated user's signed-in launchd session",
            ),
            DaemonServicePlatform::Windows => Self::persistent(
                DaemonServiceManager::WindowsTaskScheduler,
                "login_session",
                "authenticated_bootstrap_user",
                "the daemon runs only while the authenticated bootstrap user has an interactive logon session",
            ),
            DaemonServicePlatform::Linux if selection.source == SetupModeSource::SetupFlag => {
                Self {
                    setup_mode: SetupMode::Persistent,
                    service_persistent: false,
                    service_scope: "unsupported".to_string(),
                    service_manager: DaemonServiceManager::OnDemand,
                    privileged: false,
                    service_account: "authenticated_user".to_string(),
                    desktop_session_impact:
                        "Linux is not an MVP native Computer Use Host platform".to_string(),
                    fallback_reason: None,
                    explicit_persistent_unsupported: true,
                }
            }
            DaemonServicePlatform::Linux => Self::on_demand(Some(
                "user-level persistent mode is unsupported on Linux in the MVP; planned on_demand instead"
                    .to_string(),
            )),
        }
    }

    fn on_demand(fallback_reason: Option<String>) -> Self {
        Self {
            setup_mode: SetupMode::OnDemand,
            service_persistent: false,
            service_scope: "on_demand".to_string(),
            service_manager: DaemonServiceManager::OnDemand,
            privileged: false,
            service_account: "authenticated_user".to_string(),
            desktop_session_impact:
                "the daemon runs only for the authenticated user's on-demand process".to_string(),
            fallback_reason,
            explicit_persistent_unsupported: false,
        }
    }

    fn persistent(
        service_manager: DaemonServiceManager,
        service_scope: &str,
        service_account: &str,
        desktop_session_impact: &str,
    ) -> Self {
        Self {
            setup_mode: SetupMode::Persistent,
            service_persistent: true,
            service_scope: service_scope.to_string(),
            service_manager,
            privileged: false,
            service_account: service_account.to_string(),
            desktop_session_impact: desktop_session_impact.to_string(),
            fallback_reason: None,
            explicit_persistent_unsupported: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonResolvedPathSet {
    pub config_file: String,
    pub cache_root: String,
    pub state_root: String,
    pub sqlite_store: String,
    pub operator_log_root: String,
    pub recording_root: String,
    pub install_receipt: String,
}

impl DaemonResolvedPathSet {
    pub fn with_service_overrides(&self, overrides: &DaemonPathOverrides) -> Self {
        let mut planned = self.clone();
        if let Some(home) = overrides.home.as_ref() {
            let home = home.display().to_string();
            planned.config_file = join_remote_path(&home, "config/config.toml");
            planned.cache_root = join_remote_path(&home, "cache");
            planned.state_root = join_remote_path(&home, "state");
            planned.operator_log_root = join_remote_path(&home, "logs");
        }
        if let Some(path) = overrides.config_file.as_ref() {
            planned.config_file = path.display().to_string();
        }
        if let Some(path) = overrides.cache_dir.as_ref() {
            planned.cache_root = path.display().to_string();
        }
        if let Some(path) = overrides.state_dir.as_ref() {
            planned.state_root = path.display().to_string();
        }
        if let Some(path) = overrides.log_dir.as_ref() {
            planned.operator_log_root = path.display().to_string();
        }
        planned.sqlite_store = join_remote_path(&planned.state_root, "satelle.sqlite3");
        planned.recording_root = join_remote_path(&planned.state_root, "recordings");
        planned.install_receipt = join_remote_path(&planned.state_root, "install-receipt.json");
        planned
    }

    pub fn required_directories(&self) -> Vec<String> {
        let mut directories = vec![
            remote_parent(&self.config_file).unwrap_or_else(|| ".".to_string()),
            self.cache_root.clone(),
            self.state_root.clone(),
            self.operator_log_root.clone(),
            self.recording_root.clone(),
        ];
        directories.sort();
        directories.dedup();
        directories
    }
}

impl From<&crate::SatellePathSet> for DaemonResolvedPathSet {
    fn from(paths: &crate::SatellePathSet) -> Self {
        Self {
            config_file: paths.config_file.display().to_string(),
            cache_root: paths.cache_root.display().to_string(),
            state_root: paths.state_root.display().to_string(),
            sqlite_store: paths.sqlite_store.display().to_string(),
            operator_log_root: paths.operator_log_root.display().to_string(),
            recording_root: paths.recording_root.display().to_string(),
            install_receipt: paths.install_receipt.display().to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaemonArtifactAction {
    Install,
    ReuseCurrent,
    UpdateOlder,
    UpdateProtocolIncompatible,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonArtifactPlan {
    pub current_version: Option<String>,
    pub target_version: String,
    pub target_platform: String,
    pub artifact_digest: String,
    pub install_path: String,
    pub restart_impact: String,
    pub action: DaemonArtifactAction,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DaemonArtifactPlanError {
    #[error("the Host version is not a stable numeric release")]
    InvalidVersion,
    #[error("the installed Host is newer than the invoking CLI")]
    NewerHostVersion,
    #[error("the Host artifact metadata is invalid")]
    InvalidArtifactMetadata,
}

impl DaemonArtifactPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_version: Option<&str>,
        protocol_compatible: bool,
        target_version: &str,
        target_platform: &str,
        artifact_digest: &str,
        install_path: String,
        persistent_service: bool,
    ) -> Result<Self, DaemonArtifactPlanError> {
        let target = parse_release_version(target_version)?;
        let current = current_version.map(parse_release_version).transpose()?;
        if current.is_some_and(|current| current > target) {
            return Err(DaemonArtifactPlanError::NewerHostVersion);
        }
        if target_platform.is_empty()
            || !is_sha256_hex(artifact_digest)
            || !is_safe_install_path(&install_path)
        {
            return Err(DaemonArtifactPlanError::InvalidArtifactMetadata);
        }
        let action = match current {
            None => DaemonArtifactAction::Install,
            Some(current) if current < target => DaemonArtifactAction::UpdateOlder,
            Some(_) if !protocol_compatible => DaemonArtifactAction::UpdateProtocolIncompatible,
            Some(_) => DaemonArtifactAction::ReuseCurrent,
        };
        let restart_impact = match (action, persistent_service) {
            (_, true) => "restart the persistent Host Daemon after service reconciliation",
            (DaemonArtifactAction::ReuseCurrent, false) => "no Host Daemon restart required",
            (_, false) => "replace the on-demand Host Daemon before the next connection",
        };
        Ok(Self {
            current_version: current_version.map(str::to_string),
            target_version: target_version.to_string(),
            target_platform: target_platform.to_string(),
            artifact_digest: artifact_digest.to_string(),
            install_path,
            restart_impact: restart_impact.to_string(),
            action,
        })
    }
}

fn parse_release_version(value: &str) -> Result<(u64, u64, u64), DaemonArtifactPlanError> {
    let mut parts = value.split('.');
    let version = (
        parts
            .next()
            .and_then(|part| part.parse().ok())
            .ok_or(DaemonArtifactPlanError::InvalidVersion)?,
        parts
            .next()
            .and_then(|part| part.parse().ok())
            .ok_or(DaemonArtifactPlanError::InvalidVersion)?,
        parts
            .next()
            .and_then(|part| part.parse().ok())
            .ok_or(DaemonArtifactPlanError::InvalidVersion)?,
    );
    if parts.next().is_some() {
        return Err(DaemonArtifactPlanError::InvalidVersion);
    }
    Ok(version)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_safe_install_path(value: &str) -> bool {
    !value.is_empty()
        && !value
            .replace('\\', "/")
            .split('/')
            .any(|component| component == "..")
}

fn join_remote_path(base: &str, child: &str) -> String {
    let separator = if is_absolute_windows_path(base) {
        '\\'
    } else {
        '/'
    };
    let base = base.trim_end_matches(['/', '\\']);
    let child = child.trim_start_matches(['/', '\\']);
    let child = if separator == '\\' {
        child.replace('/', "\\")
    } else {
        child.replace('\\', "/")
    };
    format!("{base}{separator}{child}")
}

fn remote_parent(path: &str) -> Option<String> {
    path.rfind(['/', '\\'])
        .map(|separator| path[..separator].to_string())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonServicePlan {
    pub manager: DaemonServiceManager,
    pub scope: String,
    pub privileged: bool,
    pub service_account: String,
    pub desktop_session_impact: String,
    pub configuration_surface: String,
}

impl DaemonServicePlan {
    pub fn from_decision(decision: &PersistentServiceDecision) -> Self {
        let configuration_surface = match decision.service_manager {
            DaemonServiceManager::OnDemand => "process_environment",
            DaemonServiceManager::Launchd => "launchd_environment_variables",
            DaemonServiceManager::WindowsTaskScheduler => "satelle_owned_service_config",
        };
        Self {
            manager: decision.service_manager,
            scope: decision.service_scope.clone(),
            privileged: decision.privileged,
            service_account: decision.service_account.clone(),
            desktop_session_impact: decision.desktop_session_impact.clone(),
            configuration_surface: configuration_surface.to_string(),
        }
    }
}

pub fn render_launchd_user_plist(
    binary: &Path,
    bind: &str,
    overrides: &DaemonPathOverrides,
) -> Result<String, WindowsServiceDefinitionError> {
    let bind = bind
        .parse::<SocketAddr>()
        .map_err(|_| WindowsServiceDefinitionError::InvalidServiceConfig)?;
    if !binary.is_absolute() || !bind.ip().is_loopback() {
        return Err(WindowsServiceDefinitionError::InvalidServiceConfig);
    }
    let mut environment = String::new();
    for entry in overrides.entries() {
        let path = Path::new(&entry.value);
        if !path.is_absolute() {
            return Err(WindowsServiceDefinitionError::InvalidServiceConfig);
        }
        write!(
            environment,
            "<key>{}</key><string>{}</string>",
            xml_escape(&entry.environment_variable),
            xml_escape(&entry.value)
        )
        .expect("writing to a String cannot fail");
    }
    Ok(format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
            "<plist version=\"1.0\"><dict>",
            "<key>Label</key><string>dev.microck.satelle.host</string>",
            "<key>ProgramArguments</key><array>",
            "<string>{}</string><string>host</string><string>start</string>",
            "<string>--foreground</string><string>--bind</string><string>{}</string>",
            "</array><key>EnvironmentVariables</key><dict>{}</dict>",
            "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>",
            "</dict></plist>"
        ),
        xml_escape(&binary.display().to_string()),
        xml_escape(&bind.to_string()),
        environment
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WindowsServiceDefinitionError {
    #[error("host identity is not safe for a Task Scheduler path")]
    InvalidHostId,
    #[error("bootstrap account SID is required")]
    MissingPrincipalSid,
    #[error("bootstrap account SID observation is invalid")]
    InvalidPrincipalSid,
    #[error("bootstrap account observation does not match the authenticated account")]
    AccountObservationMismatch,
    #[error("Satelle executable must be an absolute Windows path")]
    InvalidExecutablePath,
    #[error("Satelle executable observation is not verified")]
    UnverifiedExecutable,
    #[error("Satelle executable digest observation is invalid")]
    InvalidExecutableDigest,
    #[error("Windows service configuration is invalid")]
    InvalidServiceConfig,
    #[error("LOCALAPPDATA must be an absolute Windows path")]
    InvalidLocalAppDataPath,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WindowsServiceConfigV1 {
    schema: String,
    daemon_arguments: Vec<String>,
    environment: BTreeMap<String, String>,
}

impl WindowsServiceConfigV1 {
    pub fn new(
        bind: &str,
        overrides: &DaemonPathOverrides,
    ) -> Result<Self, WindowsServiceDefinitionError> {
        let mut environment = BTreeMap::new();
        insert_path_override(&mut environment, "SATELLE_HOME", overrides.home.as_ref());
        insert_path_override(
            &mut environment,
            "SATELLE_CONFIG_FILE",
            overrides.config_file.as_ref(),
        );
        insert_path_override(
            &mut environment,
            "SATELLE_STATE_DIR",
            overrides.state_dir.as_ref(),
        );
        insert_path_override(
            &mut environment,
            "SATELLE_CACHE_DIR",
            overrides.cache_dir.as_ref(),
        );
        insert_path_override(
            &mut environment,
            "SATELLE_LOG_DIR",
            overrides.log_dir.as_ref(),
        );

        let config = Self {
            schema: WINDOWS_SERVICE_CONFIG_SCHEMA.to_string(),
            daemon_arguments: vec![
                "host".to_string(),
                "start".to_string(),
                "--foreground".to_string(),
                "--bind".to_string(),
                bind.to_string(),
            ],
            environment,
        };
        config
            .validate()
            .map_err(|_| WindowsServiceDefinitionError::InvalidServiceConfig)?;
        Ok(config)
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn daemon_arguments(&self) -> &[String] {
        &self.daemon_arguments
    }

    pub fn bind(&self) -> &str {
        // Deserialization validates the closed five-argument shape before a
        // service config reaches this accessor.
        &self.daemon_arguments[4]
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.schema != WINDOWS_SERVICE_CONFIG_SCHEMA
            || self.daemon_arguments.len() != 5
            || self.daemon_arguments[0..4] != ["host", "start", "--foreground", "--bind"]
        {
            return Err("invalid daemon arguments");
        }
        let bind = self.daemon_arguments[4]
            .parse::<SocketAddr>()
            .map_err(|_| "invalid daemon bind")?;
        if !bind.ip().is_loopback() {
            return Err("daemon bind is not loopback");
        }
        const ALLOWED_OVERRIDES: [&str; 5] = [
            "SATELLE_HOME",
            "SATELLE_CONFIG_FILE",
            "SATELLE_STATE_DIR",
            "SATELLE_CACHE_DIR",
            "SATELLE_LOG_DIR",
        ];
        if self.environment.iter().any(|(key, value)| {
            !ALLOWED_OVERRIDES.contains(&key.as_str())
                || value.is_empty()
                || !is_absolute_windows_path(value)
                || has_parent_component(value)
        }) {
            return Err("invalid daemon environment");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for WindowsServiceConfigV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireConfig {
            schema: String,
            daemon_arguments: Vec<String>,
            environment: BTreeMap<String, String>,
        }

        let wire = WireConfig::deserialize(deserializer)?;
        let config = Self {
            schema: wire.schema,
            daemon_arguments: wire.daemon_arguments,
            environment: wire.environment,
        };
        config.validate().map_err(D::Error::custom)?;
        Ok(config)
    }
}

fn insert_path_override(
    environment: &mut BTreeMap<String, String>,
    key: &str,
    value: Option<&std::path::PathBuf>,
) {
    if let Some(value) = value {
        environment.insert(key.to_string(), value.display().to_string());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsTaskDefinition {
    pub task_path: String,
    pub principal_sid: String,
    pub logon_type: String,
    pub run_level: String,
    pub trigger_user_sid: String,
    pub stores_password: bool,
    pub multiple_instances_policy: String,
    pub executable: String,
    pub arguments: Vec<String>,
    pub service_config_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedWindowsAccount {
    principal_sid: String,
    local_app_data: String,
}

impl AuthenticatedWindowsAccount {
    pub fn from_observation(
        requested_sid: &str,
        observed_sid: &str,
        requested_local_app_data: &str,
        observed_local_app_data: &str,
    ) -> Result<Self, WindowsServiceDefinitionError> {
        if requested_sid.is_empty() {
            return Err(WindowsServiceDefinitionError::MissingPrincipalSid);
        }
        if !is_valid_windows_sid(requested_sid) || !is_valid_windows_sid(observed_sid) {
            return Err(WindowsServiceDefinitionError::InvalidPrincipalSid);
        }
        if requested_sid != observed_sid
            || !same_windows_path(requested_local_app_data, observed_local_app_data)
        {
            return Err(WindowsServiceDefinitionError::AccountObservationMismatch);
        }
        if !is_absolute_windows_path(observed_local_app_data)
            || has_parent_component(observed_local_app_data)
        {
            return Err(WindowsServiceDefinitionError::InvalidLocalAppDataPath);
        }
        Ok(Self {
            principal_sid: observed_sid.to_string(),
            local_app_data: normalize_windows_path_for_storage(observed_local_app_data),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsObservedPathKind {
    Missing,
    Directory,
    ReparsePoint,
    RegularFile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedWindowsExecutable {
    canonical_path: String,
    digest: String,
}

impl VerifiedWindowsExecutable {
    pub fn from_observation(
        requested_path: &str,
        canonical_path: &str,
        observed_kind: WindowsObservedPathKind,
        expected_release_digest: &str,
        observed_digest: &str,
    ) -> Result<Self, WindowsServiceDefinitionError> {
        if !is_absolute_windows_path(requested_path) || has_parent_component(requested_path) {
            return Err(WindowsServiceDefinitionError::InvalidExecutablePath);
        }
        if observed_kind != WindowsObservedPathKind::RegularFile
            || !same_windows_path(requested_path, canonical_path)
        {
            return Err(WindowsServiceDefinitionError::UnverifiedExecutable);
        }
        if !is_sha256_hex(expected_release_digest)
            || !is_sha256_hex(observed_digest)
            || expected_release_digest != observed_digest
        {
            return Err(WindowsServiceDefinitionError::InvalidExecutableDigest);
        }
        Ok(Self {
            canonical_path: canonical_path.to_string(),
            digest: observed_digest.to_string(),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl WindowsTaskDefinition {
    pub fn for_host(
        host_id: &str,
        account: &AuthenticatedWindowsAccount,
        executable: &VerifiedWindowsExecutable,
    ) -> Result<Self, WindowsServiceDefinitionError> {
        if host_id.is_empty()
            || !host_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(WindowsServiceDefinitionError::InvalidHostId);
        }
        let service_config_path = format!(
            r"{}\Satelle\service\{host_id}.json",
            account.local_app_data.trim_end_matches(['\\', '/'])
        );

        Ok(Self {
            task_path: format!(r"\Satelle\Host-{host_id}"),
            principal_sid: account.principal_sid.clone(),
            logon_type: "InteractiveToken".to_string(),
            run_level: "LeastPrivilege".to_string(),
            trigger_user_sid: account.principal_sid.clone(),
            stores_password: false,
            multiple_instances_policy: "IgnoreNew".to_string(),
            executable: executable.canonical_path.clone(),
            arguments: vec![
                "host".to_string(),
                "start".to_string(),
                "--service-config".to_string(),
                service_config_path.clone(),
            ],
            service_config_path,
        })
    }

    pub fn matches_observation(&self, observation: &WindowsTaskObservation) -> bool {
        observation == self
    }
}

pub type WindowsTaskObservation = WindowsTaskDefinition;

fn is_absolute_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    let unc_absolute = value.starts_with(r"\\") && value[2..].contains(['\\', '/']);
    drive_absolute || unc_absolute
}

fn has_parent_component(value: &str) -> bool {
    value
        .replace('/', "\\")
        .split('\\')
        .any(|part| part == "..")
}

fn same_windows_path(left: &str, right: &str) -> bool {
    normalize_windows_path(left) == normalize_windows_path(right)
}

fn normalize_windows_path(value: &str) -> String {
    let normalized = value.replace('/', "\\");
    let normalized = normalized
        .strip_prefix(r"\\?\UNC\")
        .map(|path| format!(r"\\{path}"))
        .or_else(|| normalized.strip_prefix(r"\\?\").map(str::to_string))
        .unwrap_or(normalized);
    normalized.trim_end_matches('\\').to_ascii_lowercase()
}

fn normalize_windows_path_for_storage(value: &str) -> String {
    value.replace('/', "\\").trim_end_matches('\\').to_string()
}

fn is_valid_windows_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    parts.next() == Some("S")
        && parts.clone().count() >= 3
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const HOST_ID: &str = "host-123";
    const SID: &str = "S-1-5-21-1000-1001-1002-1003";
    const EXECUTABLE: &str = r"C:\Program Files\Satelle\satelle.exe";
    const LOCAL_APP_DATA: &str = r"C:\Users\operator\AppData\Local";

    fn windows_definition() -> WindowsTaskDefinition {
        WindowsTaskDefinition::for_host(HOST_ID, &account_observation(), &executable_observation())
            .expect("valid task definition")
    }

    fn account_observation() -> AuthenticatedWindowsAccount {
        AuthenticatedWindowsAccount::from_observation(SID, SID, LOCAL_APP_DATA, LOCAL_APP_DATA)
            .expect("verified authenticated Windows account")
    }

    fn executable_observation() -> VerifiedWindowsExecutable {
        VerifiedWindowsExecutable::from_observation(
            EXECUTABLE,
            r"\\?\C:\Program Files\Satelle\satelle.exe",
            WindowsObservedPathKind::RegularFile,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("verified Windows executable")
    }

    #[test]
    fn windows_task_definition_matches_gap_020_exactly() {
        let definition = windows_definition();
        assert_eq!(definition.task_path, r"\Satelle\Host-host-123");
        assert_eq!(definition.principal_sid, SID);
        assert_eq!(definition.logon_type, "InteractiveToken");
        assert_eq!(definition.run_level, "LeastPrivilege");
        assert_eq!(definition.trigger_user_sid, SID);
        assert!(!definition.stores_password);
        assert_eq!(definition.multiple_instances_policy, "IgnoreNew");
        assert_eq!(
            definition.executable,
            r"\\?\C:\Program Files\Satelle\satelle.exe"
        );
        assert_eq!(
            definition.service_config_path,
            r"C:\Users\operator\AppData\Local\Satelle\service\host-123.json"
        );
    }

    #[test]
    fn windows_task_definition_comparison_detects_every_authoritative_field() {
        let definition = windows_definition();
        assert!(definition.matches_observation(&definition.clone()));

        macro_rules! mismatch {
            ($field:ident, $value:expr) => {{
                let mut observation = definition.clone();
                observation.$field = $value;
                assert!(!definition.matches_observation(&observation));
            }};
        }
        mismatch!(task_path, r"\Satelle\Host-other".to_string());
        mismatch!(principal_sid, "S-1-5-21-other".to_string());
        mismatch!(logon_type, "Password".to_string());
        mismatch!(run_level, "HighestAvailable".to_string());
        mismatch!(trigger_user_sid, "S-1-5-21-other".to_string());
        mismatch!(stores_password, true);
        mismatch!(multiple_instances_policy, "Parallel".to_string());
        mismatch!(executable, r"C:\other\satelle.exe".to_string());
        mismatch!(arguments, vec!["host".to_string(), "start".to_string()]);
        mismatch!(service_config_path, r"C:\other\config.json".to_string());
    }

    #[test]
    fn windows_service_config_contains_only_launch_arguments_and_five_path_overrides() {
        let overrides = DaemonPathOverrides {
            home: Some(PathBuf::from(r"C:\Satelle")),
            config_file: Some(PathBuf::from(r"C:\Satelle\config.toml")),
            state_dir: Some(PathBuf::from(r"C:\Satelle\state")),
            cache_dir: Some(PathBuf::from(r"C:\Satelle\cache")),
            log_dir: Some(PathBuf::from(r"C:\Satelle\logs")),
            ..DaemonPathOverrides::default()
        };
        let config = WindowsServiceConfigV1::new("127.0.0.1:3001", &overrides)
            .expect("valid service config");
        assert_eq!(config.schema(), WINDOWS_SERVICE_CONFIG_SCHEMA);
        assert_eq!(
            config.daemon_arguments(),
            ["host", "start", "--foreground", "--bind", "127.0.0.1:3001"]
        );
        assert_eq!(config.environment().len(), 5);
        assert_eq!(
            config.environment().keys().cloned().collect::<Vec<_>>(),
            [
                "SATELLE_CACHE_DIR",
                "SATELLE_CONFIG_FILE",
                "SATELLE_HOME",
                "SATELLE_LOG_DIR",
                "SATELLE_STATE_DIR",
            ]
        );

        let encoded = serde_json::to_value(config).expect("serialize service config");
        assert_eq!(
            encoded
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["daemon_arguments", "environment", "schema"]
        );
    }

    #[test]
    fn windows_service_config_rejects_arbitrary_arguments_and_environment_keys() {
        let invalid_arguments = serde_json::json!({
            "schema": WINDOWS_SERVICE_CONFIG_SCHEMA,
            "daemon_arguments": ["host", "start", "--foreground", "--bind", "0.0.0.0:3001"],
            "environment": {}
        });
        assert!(serde_json::from_value::<WindowsServiceConfigV1>(invalid_arguments).is_err());

        let invalid_environment = serde_json::json!({
            "schema": WINDOWS_SERVICE_CONFIG_SCHEMA,
            "daemon_arguments": ["host", "start", "--foreground", "--bind", "127.0.0.1:3001"],
            "environment": {"PATH": "C:\\attacker"}
        });
        assert!(serde_json::from_value::<WindowsServiceConfigV1>(invalid_environment).is_err());
    }

    #[test]
    fn windows_task_definition_requires_authenticated_account_and_verified_executable() {
        assert!(
            AuthenticatedWindowsAccount::from_observation(
                SID,
                "S-1-5-21-9-9-9-9",
                LOCAL_APP_DATA,
                LOCAL_APP_DATA,
            )
            .is_err()
        );

        assert!(
            VerifiedWindowsExecutable::from_observation(
                EXECUTABLE,
                EXECUTABLE,
                WindowsObservedPathKind::RegularFile,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .is_err()
        );

        assert!(
            VerifiedWindowsExecutable::from_observation(
                r"C:\Satelle\..\attacker.exe",
                r"C:\attacker.exe",
                WindowsObservedPathKind::RegularFile,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .is_err()
        );
    }

    #[test]
    fn windows_persistent_decision_reports_login_session_and_never_system_scope() {
        let decision = PersistentServiceDecision::resolve(
            SetupModeSelection::new(SetupMode::Persistent, SetupModeSource::SetupFlag),
            DaemonServicePlatform::Windows,
        );
        assert!(decision.service_persistent);
        assert_eq!(decision.service_scope, "login_session");
        assert_eq!(
            decision.service_manager,
            DaemonServiceManager::WindowsTaskScheduler
        );
        assert!(!decision.privileged);
        assert_ne!(decision.service_scope, "system");
    }

    #[test]
    fn windows_task_definition_passes_the_absolute_service_config_argument() {
        let definition = windows_definition();
        assert_eq!(
            definition.arguments,
            [
                "host",
                "start",
                "--service-config",
                r"C:\Users\operator\AppData\Local\Satelle\service\host-123.json",
            ]
        );

        let mut observed = definition.clone();
        observed.arguments[3] = r"C:\attacker\service.json".to_string();
        assert!(!definition.matches_observation(&observed));
    }

    #[test]
    fn verified_windows_inputs_reject_observation_or_digest_drift() {
        assert!(
            AuthenticatedWindowsAccount::from_observation(
                SID,
                "S-1-5-21-9-9-9-9",
                LOCAL_APP_DATA,
                LOCAL_APP_DATA,
            )
            .is_err()
        );
        assert!(
            VerifiedWindowsExecutable::from_observation(
                EXECUTABLE,
                EXECUTABLE,
                WindowsObservedPathKind::RegularFile,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .is_err()
        );
        assert!(
            VerifiedWindowsExecutable::from_observation(
                EXECUTABLE,
                EXECUTABLE,
                WindowsObservedPathKind::ReparsePoint,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .is_err()
        );
    }

    #[test]
    fn daemon_artifact_plan_updates_only_missing_older_or_incompatible_hosts() {
        let missing = DaemonArtifactPlan::new(
            None,
            true,
            "0.1.0",
            "darwin-arm64",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/Users/operator/Library/Caches/Satelle/host/v0.1.0/satelle".to_string(),
            true,
        )
        .expect("missing host is installable");
        assert_eq!(missing.action, DaemonArtifactAction::Install);

        let older = DaemonArtifactPlan::new(
            Some("0.0.9"),
            true,
            "0.1.0",
            "darwin-arm64",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/Users/operator/Library/Caches/Satelle/host/v0.1.0/satelle".to_string(),
            true,
        )
        .expect("older host is updateable");
        assert_eq!(older.action, DaemonArtifactAction::UpdateOlder);

        let incompatible = DaemonArtifactPlan::new(
            Some("0.1.0"),
            false,
            "0.1.0",
            "darwin-arm64",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/Users/operator/Library/Caches/Satelle/host/v0.1.0/satelle".to_string(),
            true,
        )
        .expect("protocol-incompatible host is replaceable");
        assert_eq!(
            incompatible.action,
            DaemonArtifactAction::UpdateProtocolIncompatible
        );

        let reused_persistent = DaemonArtifactPlan::new(
            Some("0.1.0"),
            true,
            "0.1.0",
            "darwin-arm64",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "/Users/operator/Library/Caches/Satelle/host/v0.1.0/satelle".to_string(),
            true,
        )
        .expect("matching persistent host is reusable");
        assert_eq!(reused_persistent.action, DaemonArtifactAction::ReuseCurrent);
        assert_eq!(
            reused_persistent.restart_impact,
            "restart the persistent Host Daemon after service reconciliation"
        );

        assert!(matches!(
            DaemonArtifactPlan::new(
                Some("0.2.0"),
                true,
                "0.1.0",
                "darwin-arm64",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "/Users/operator/Library/Caches/Satelle/host/v0.1.0/satelle".to_string(),
                true,
            ),
            Err(DaemonArtifactPlanError::NewerHostVersion)
        ));
    }

    #[test]
    fn daemon_path_plan_derives_all_owned_paths_and_restart_directories() {
        let current = DaemonResolvedPathSet {
            config_file: "/old/config.toml".to_string(),
            cache_root: "/old/cache".to_string(),
            state_root: "/old/state".to_string(),
            sqlite_store: "/old/state/satelle.sqlite3".to_string(),
            operator_log_root: "/old/logs".to_string(),
            recording_root: "/old/state/recordings".to_string(),
            install_receipt: "/old/state/install-receipt.json".to_string(),
        };
        let planned = current.with_service_overrides(&DaemonPathOverrides {
            home: Some(PathBuf::from("/new/home")),
            log_dir: Some(PathBuf::from("/new/operator-logs")),
            ..DaemonPathOverrides::default()
        });
        assert_eq!(planned.state_root, "/new/home/state");
        assert_eq!(planned.sqlite_store, "/new/home/state/satelle.sqlite3");
        assert_eq!(planned.recording_root, "/new/home/state/recordings");
        assert_eq!(planned.operator_log_root, "/new/operator-logs");
        assert!(planned.required_directories().contains(&planned.state_root));
    }

    #[test]
    fn launchd_definition_is_user_scoped_loopback_and_satelle_owned() {
        let plist = render_launchd_user_plist(
            Path::new("/Users/operator/Library/Caches/Satelle/host/v0.1.0/satelle"),
            "127.0.0.1:3001",
            &DaemonPathOverrides {
                home: Some(PathBuf::from("/Users/operator/Satelle & Host")),
                ..DaemonPathOverrides::default()
            },
        )
        .expect("valid launchd definition");
        assert!(plist.contains("<key>EnvironmentVariables</key>"));
        assert!(plist.contains("<key>SATELLE_HOME</key>"));
        assert!(plist.contains("Satelle &amp; Host"));
        assert!(plist.contains("127.0.0.1:3001"));
        assert!(!plist.contains("0.0.0.0"));
        assert!(!plist.contains("UserName"));
    }
}
