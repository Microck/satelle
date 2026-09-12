use crate::secure_file::{
    SecureFileError, open_existing_private_file, open_or_create_owner_only_directory,
    persist_new_owner_only_config_file, read_owner_only_secret_file, sync_owner_only_directory,
};
use crate::{ErrorCode, SatelleError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const TELEMETRY_QUEUE_MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const TELEMETRY_QUEUE_RETENTION: Duration = Duration::hours(24);
pub const TELEMETRY_STATUS_SCHEMA_VERSION: &str = "satelle.telemetry.status.v1";
const MAX_TELEMETRY_RECORD_BYTES: usize = 16 * 1024;
const MAX_DEPLOYMENT_LABEL_BYTES: usize = 64;

pub const TELEMETRY_EXCLUSIONS: [&str; 17] = [
    "host_alias_or_id",
    "principal",
    "session_id",
    "turn_id",
    "user_or_machine_identity",
    "network_address",
    "arguments",
    "request_or_response_bodies",
    "prompts",
    "transcripts",
    "desktop_content",
    "file_paths",
    "secret_descriptors_or_values",
    "artifacts",
    "project_or_profile_names",
    "model_or_provider_names",
    "prompt_derived_identifiers",
];

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otlp_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<TelemetrySecretSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_label: Option<String>,
}

impl TelemetryConfig {
    pub fn endpoint(&self) -> Result<Option<TelemetryEndpoint>, SatelleError> {
        if let Some(label) = self.deployment_label.as_deref()
            && (label.is_empty()
                || label.len() > MAX_DEPLOYMENT_LABEL_BYTES
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        {
            return Err(SatelleError::config_error(
                "telemetry.deployment_label must be 1 to 64 ASCII letters, digits, dots, dashes, or underscores",
                None,
            ));
        }
        if let Some(source) = self.authorization.as_ref() {
            source.validate()?;
        }
        if !self.enabled {
            return Ok(None);
        }
        let raw = self.otlp_endpoint.as_deref().ok_or_else(|| {
            SatelleError::config_error(
                "telemetry.enabled requires telemetry.otlp_endpoint on the emitting machine",
                None,
            )
        })?;
        let endpoint = TelemetryEndpoint::parse(raw)?;
        Ok(Some(endpoint))
    }

    pub fn resolve_authorization(&self) -> Result<Option<Zeroizing<String>>, SatelleError> {
        self.authorization
            .as_ref()
            .map(TelemetrySecretSource::resolve)
            .transpose()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TelemetrySecretSource {
    Environment { variable: String },
    File { path: PathBuf },
}

impl TelemetrySecretSource {
    fn validate(&self) -> Result<(), SatelleError> {
        match self {
            Self::Environment { variable } if valid_environment_name(variable) => Ok(()),
            Self::File { path } if path.is_absolute() && !path.starts_with("~") => Ok(()),
            Self::Environment { .. } => Err(SatelleError::config_error(
                "telemetry authorization environment variable must be a non-empty environment name",
                None,
            )),
            Self::File { .. } => Err(SatelleError::config_error(
                "telemetry authorization file path must be absolute",
                None,
            )),
        }
    }

    fn resolve(&self) -> Result<Zeroizing<String>, SatelleError> {
        self.validate()?;
        match self {
            Self::Environment { variable } if !variable.trim().is_empty() => {
                std::env::var(variable)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(Zeroizing::new)
                    .ok_or_else(|| telemetry_secret_unavailable("environment"))
            }
            Self::File { path } if path.is_absolute() => read_owner_only_secret_file(path)
                .map_err(|_| telemetry_secret_unavailable("owner-only file")),
            Self::Environment { .. } | Self::File { .. } => unreachable!("validated descriptor"),
        }
    }
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn telemetry_secret_unavailable(kind: &str) -> SatelleError {
    SatelleError::config_error(
        format!("telemetry authorization could not be resolved from its {kind} Secret Source"),
        None,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryEndpoint {
    base: Url,
}

impl TelemetryEndpoint {
    fn parse(raw: &str) -> Result<Self, SatelleError> {
        let base = Url::parse(raw).map_err(|_| {
            SatelleError::config_error("telemetry.otlp_endpoint must be an absolute URL", None)
        })?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !matches!(base.path(), "" | "/")
        {
            return Err(SatelleError::config_error(
                "telemetry.otlp_endpoint must contain only an origin; credentials, query, fragment, and path are not allowed",
                None,
            ));
        }
        let loopback = base.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
            return Err(SatelleError::config_error(
                "telemetry.otlp_endpoint must use HTTPS, except for loopback HTTP",
                None,
            ));
        }
        Ok(Self { base })
    }

    pub fn origin(&self) -> String {
        self.base.origin().ascii_serialization()
    }

    pub fn traces_url(&self) -> Url {
        self.base
            .join("/v1/traces")
            .expect("a validated HTTP origin accepts the OTLP traces path")
    }

    pub fn metrics_url(&self) -> Url {
        self.base
            .join("/v1/metrics")
            .expect("a validated HTTP origin accepts the OTLP metrics path")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryComponent {
    Controller,
    Host,
}

impl TelemetryComponent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Host => "host",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryOutcome {
    Success,
    Failure,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryRecord {
    #[serde(with = "time::serde::rfc3339")]
    recorded_at: OffsetDateTime,
    duration_ms: u64,
    outcome: TelemetryOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<ErrorCode>,
    retry_count: u32,
    queue_depth: u64,
    resource_usage: TelemetryResourceUsage,
}

impl TelemetryRecord {
    pub fn new(
        duration: std::time::Duration,
        outcome: TelemetryOutcome,
        error_code: Option<ErrorCode>,
        retry_count: u32,
        resource_usage: TelemetryResourceUsage,
    ) -> Self {
        Self {
            recorded_at: OffsetDateTime::now_utc(),
            duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            outcome,
            error_code,
            retry_count,
            queue_depth: 0,
            resource_usage,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryResourceUsage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,
}

impl TelemetryResourceUsage {
    pub fn current() -> Self {
        #[cfg(unix)]
        {
            return unix_resource_usage();
        }
        #[cfg(windows)]
        {
            return windows_resource_usage();
        }
        #[allow(unreachable_code)]
        Self::default()
    }
}

#[cfg(unix)]
fn unix_resource_usage() -> TelemetryResourceUsage {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // getrusage writes the complete structure when it reports success.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return TelemetryResourceUsage::default();
    }
    // The successful call above initialized every field.
    let usage = unsafe { usage.assume_init() };
    let timeval_ms = |value: libc::timeval| {
        u64::try_from(value.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1_000)
            .saturating_add(u64::try_from(value.tv_usec).unwrap_or(0) / 1_000)
    };
    let peak_memory = u64::try_from(usage.ru_maxrss).ok().map(|value| {
        if cfg!(target_os = "macos") {
            value
        } else {
            value.saturating_mul(1_024)
        }
    });
    TelemetryResourceUsage {
        cpu_ms: Some(timeval_ms(usage.ru_utime).saturating_add(timeval_ms(usage.ru_stime))),
        peak_memory_bytes: peak_memory,
    }
}

#[cfg(windows)]
fn windows_resource_usage() -> TelemetryResourceUsage {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let process = unsafe { GetCurrentProcess() };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let cpu_ms =
        (unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            != 0)
            .then(|| {
                let ticks = |value: FILETIME| {
                    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
                };
                ticks(kernel).saturating_add(ticks(user)) / 10_000
            });
    let mut memory = PROCESS_MEMORY_COUNTERS {
        cb: u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>())
            .expect("Windows process counters fit in u32"),
        ..PROCESS_MEMORY_COUNTERS::default()
    };
    let peak_memory_bytes = (unsafe { GetProcessMemoryInfo(process, &mut memory, memory.cb) } != 0)
        .then(|| u64::try_from(memory.PeakWorkingSetSize).unwrap_or(u64::MAX));
    TelemetryResourceUsage {
        cpu_ms,
        peak_memory_bytes,
    }
}

#[derive(Clone, Debug)]
pub struct TelemetryQueue {
    root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct QueuedTelemetry {
    pub file_name: String,
    pub record: TelemetryRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryDelivery {
    #[serde(with = "time::serde::rfc3339")]
    pub delivered_at: OffsetDateTime,
    pub outcome: TelemetryOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryStatus {
    pub schema_version: String,
    pub component: TelemetryComponent,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_origin: Option<String>,
    pub buffered_record_count: usize,
    pub buffered_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_record_age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_delivery: Option<TelemetryDelivery>,
    pub excluded_data_categories: Vec<String>,
}

impl TelemetryStatus {
    pub fn disabled(component: TelemetryComponent) -> Self {
        Self {
            schema_version: TELEMETRY_STATUS_SCHEMA_VERSION.to_string(),
            component,
            enabled: false,
            endpoint_origin: None,
            buffered_record_count: 0,
            buffered_bytes: 0,
            oldest_record_age_ms: None,
            last_delivery: None,
            excluded_data_categories: TELEMETRY_EXCLUSIONS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }
}

impl TelemetryQueue {
    pub fn new(state_root: &Path, component: TelemetryComponent) -> Self {
        Self {
            root: state_root.join("telemetry").join(component.as_str()),
        }
    }

    pub fn enqueue(&self, mut record: TelemetryRecord) -> Result<(), TelemetryQueueError> {
        self.ensure_root()?;
        let existing = self.records()?;
        record.queue_depth = u64::try_from(existing.len()).unwrap_or(u64::MAX);
        let file_name = format!("record-{}.json", Uuid::now_v7().simple());
        let bytes = serde_json::to_vec(&record).map_err(|_| TelemetryQueueError::InvalidRecord)?;
        persist_new_owner_only_config_file(&self.root.join(file_name), &bytes)?;
        self.prune()?;
        Ok(())
    }

    /// Drains queued records with OTLP/HTTP. Callers run this outside their
    /// control path; this method owns delivery ordering and acknowledgement.
    pub fn deliver(
        &self,
        config: &TelemetryConfig,
        component: TelemetryComponent,
    ) -> Result<(), TelemetryQueueError> {
        if !config.enabled {
            return self.clear();
        }
        let endpoint = config
            .endpoint()
            .map_err(|_| {
                let _ =
                    self.record_delivery(TelemetryOutcome::Failure, Some("configuration_invalid"));
                TelemetryQueueError::DeliveryFailed
            })?
            .ok_or(TelemetryQueueError::DeliveryFailed)?;
        let authorization = config.resolve_authorization().map_err(|_| {
            let _ =
                self.record_delivery(TelemetryOutcome::Failure, Some("authorization_unresolved"));
            TelemetryQueueError::DeliveryFailed
        })?;
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| TelemetryQueueError::DeliveryFailed)?;
        for queued in self.pending()? {
            let (traces, metrics) = otlp_payloads(
                component,
                config.deployment_label.as_deref(),
                &queued.record,
            );
            let send = |url: Url, body: &Value| {
                let request = client.post(url).json(body);
                let request = if let Some(secret) = authorization.as_ref() {
                    request.bearer_auth(secret.as_str())
                } else {
                    request
                };
                request
                    .send()
                    .ok()
                    .filter(|response| response.status().is_success())
            };
            let delivered = send(endpoint.traces_url(), &traces).is_some()
                && send(endpoint.metrics_url(), &metrics).is_some();
            if !delivered {
                self.record_delivery(TelemetryOutcome::Failure, Some("otlp_delivery_failed"))?;
                return Err(TelemetryQueueError::DeliveryFailed);
            }
            self.acknowledge(&queued.file_name)?;
            self.record_delivery(TelemetryOutcome::Success, None)?;
        }
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<QueuedTelemetry>, TelemetryQueueError> {
        self.prune()?;
        self.records()
    }

    pub fn acknowledge(&self, file_name: &str) -> Result<(), TelemetryQueueError> {
        if !is_queue_file_name(file_name, "record-") {
            return Err(TelemetryQueueError::InvalidRecord);
        }
        match fs::remove_file(self.root.join(file_name)) {
            Ok(()) => self.sync(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(TelemetryQueueError::Unavailable),
        }
    }

    pub fn record_delivery(
        &self,
        outcome: TelemetryOutcome,
        error_code: Option<&str>,
    ) -> Result<(), TelemetryQueueError> {
        self.ensure_root()?;
        let delivery = TelemetryDelivery {
            delivered_at: OffsetDateTime::now_utc(),
            outcome,
            error_code: error_code.map(str::to_string),
        };
        let file_name = format!("delivery-{}.json", Uuid::now_v7().simple());
        let bytes =
            serde_json::to_vec(&delivery).map_err(|_| TelemetryQueueError::InvalidRecord)?;
        persist_new_owner_only_config_file(&self.root.join(file_name), &bytes)?;
        let mut delivery_files = self.files_with_prefix("delivery-")?;
        delivery_files.sort();
        for (_, path) in delivery_files.into_iter().rev().skip(1) {
            fs::remove_file(path).map_err(|_| TelemetryQueueError::Unavailable)?;
        }
        self.sync()
    }

    pub fn status(
        &self,
        component: TelemetryComponent,
        enabled: bool,
        endpoint_origin: Option<String>,
    ) -> Result<TelemetryStatus, TelemetryQueueError> {
        if !enabled {
            self.clear()?;
        }
        let records = if enabled { self.pending()? } else { Vec::new() };
        let mut buffered_record_count = 0_usize;
        let mut buffered_bytes = 0_u64;
        let mut oldest = None;
        for queued in &records {
            let size = match fs::metadata(self.root.join(&queued.file_name)) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(TelemetryQueueError::Unavailable),
            };
            buffered_record_count += 1;
            buffered_bytes = buffered_bytes.saturating_add(size);
            oldest = Some(
                oldest.map_or(queued.record.recorded_at, |value: OffsetDateTime| {
                    value.min(queued.record.recorded_at)
                }),
            );
        }
        let oldest_record_age_ms = oldest.map(|recorded_at| {
            let age = OffsetDateTime::now_utc() - recorded_at;
            u64::try_from(age.whole_milliseconds().max(0)).unwrap_or(u64::MAX)
        });
        Ok(TelemetryStatus {
            schema_version: TELEMETRY_STATUS_SCHEMA_VERSION.to_string(),
            component,
            enabled,
            endpoint_origin,
            buffered_record_count,
            buffered_bytes,
            oldest_record_age_ms,
            last_delivery: enabled.then(|| self.last_delivery()).transpose()?.flatten(),
            excluded_data_categories: TELEMETRY_EXCLUSIONS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        })
    }

    pub fn clear(&self) -> Result<(), TelemetryQueueError> {
        if !self.root.exists() {
            return Ok(());
        }
        let directory = open_or_create_owner_only_directory(&self.root)?;
        for entry in fs::read_dir(&self.root).map_err(|_| TelemetryQueueError::Unavailable)? {
            let entry = entry.map_err(|_| TelemetryQueueError::Unavailable)?;
            if !entry
                .file_type()
                .map_err(|_| TelemetryQueueError::Unavailable)?
                .is_file()
            {
                return Err(TelemetryQueueError::Unavailable);
            }
            fs::remove_file(entry.path()).map_err(|_| TelemetryQueueError::Unavailable)?;
        }
        sync_owner_only_directory(&self.root, &directory)?;
        drop(directory);
        fs::remove_dir(&self.root).map_err(|_| TelemetryQueueError::Unavailable)
    }

    fn records(&self) -> Result<Vec<QueuedTelemetry>, TelemetryQueueError> {
        let mut files = self.files_with_prefix("record-")?;
        files.sort();
        let mut records = Vec::with_capacity(files.len());
        for (file_name, path) in files {
            match read_json(&path) {
                Ok(record) => records.push(QueuedTelemetry { file_name, record }),
                Err(_) if !path.exists() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(records)
    }

    fn files_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, PathBuf)>, TelemetryQueueError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let _directory = open_or_create_owner_only_directory(&self.root)?;
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| TelemetryQueueError::Unavailable)? {
            let entry = entry.map_err(|_| TelemetryQueueError::Unavailable)?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| TelemetryQueueError::InvalidRecord)?;
            if file_name.starts_with(prefix) {
                if !entry
                    .file_type()
                    .map_err(|_| TelemetryQueueError::Unavailable)?
                    .is_file()
                    || !is_queue_file_name(&file_name, prefix)
                {
                    return Err(TelemetryQueueError::InvalidRecord);
                }
                files.push((file_name, entry.path()));
            }
        }
        Ok(files)
    }

    fn prune(&self) -> Result<(), TelemetryQueueError> {
        self.prune_with_limits(
            OffsetDateTime::now_utc(),
            TELEMETRY_QUEUE_MAX_BYTES,
            TELEMETRY_QUEUE_RETENTION,
        )
    }

    fn prune_with_limits(
        &self,
        now: OffsetDateTime,
        max_bytes: u64,
        retention: Duration,
    ) -> Result<(), TelemetryQueueError> {
        let mut records = self.records_without_prune()?;
        let mut retained = Vec::new();
        for (name, path, record, bytes) in records.drain(..) {
            if now - record.recorded_at >= retention {
                fs::remove_file(path).map_err(|_| TelemetryQueueError::Unavailable)?;
            } else {
                retained.push((name, path, bytes));
            }
        }
        retained.sort_by(|left, right| left.0.cmp(&right.0));
        let mut total = retained
            .iter()
            .fold(0_u64, |total, (_, _, bytes)| total.saturating_add(*bytes));
        for (_, path, bytes) in retained {
            if total <= max_bytes {
                break;
            }
            fs::remove_file(path).map_err(|_| TelemetryQueueError::Unavailable)?;
            total = total.saturating_sub(bytes);
        }
        if self.root.exists() {
            self.sync()?;
        }
        Ok(())
    }

    fn records_without_prune(
        &self,
    ) -> Result<Vec<(String, PathBuf, TelemetryRecord, u64)>, TelemetryQueueError> {
        let mut records = Vec::new();
        for (name, path) in self.files_with_prefix("record-")? {
            let bytes = match fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(TelemetryQueueError::Unavailable),
            };
            match read_json(&path) {
                Ok(record) => records.push((name, path, record, bytes)),
                Err(_) if !path.exists() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(records)
    }

    fn last_delivery(&self) -> Result<Option<TelemetryDelivery>, TelemetryQueueError> {
        let mut files = self.files_with_prefix("delivery-")?;
        files.sort();
        for (_, path) in files.into_iter().rev() {
            match read_json(&path) {
                Ok(delivery) => return Ok(Some(delivery)),
                Err(_) if !path.exists() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn sync(&self) -> Result<(), TelemetryQueueError> {
        let directory = open_or_create_owner_only_directory(&self.root)?;
        sync_owner_only_directory(&self.root, &directory)?;
        Ok(())
    }

    fn ensure_root(&self) -> Result<(), TelemetryQueueError> {
        let parent = self.root.parent().ok_or(TelemetryQueueError::Unavailable)?;
        let state_root = parent.parent().ok_or(TelemetryQueueError::Unavailable)?;
        drop(open_or_create_owner_only_directory(state_root)?);
        drop(open_or_create_owner_only_directory(parent)?);
        drop(open_or_create_owner_only_directory(&self.root)?);
        Ok(())
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, TelemetryQueueError> {
    let mut file = open_existing_private_file(path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_TELEMETRY_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| TelemetryQueueError::Unavailable)?;
    if bytes.len() > MAX_TELEMETRY_RECORD_BYTES {
        return Err(TelemetryQueueError::InvalidRecord);
    }
    serde_json::from_slice(&bytes).map_err(|_| TelemetryQueueError::InvalidRecord)
}

fn is_queue_file_name(file_name: &str, prefix: &str) -> bool {
    file_name
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(".json"))
        .is_some_and(|value| {
            value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TelemetryQueueError {
    #[error("the private telemetry queue failed its owner security policy: {0}")]
    Secure(#[from] SecureFileError),
    #[error("the private telemetry queue is unavailable")]
    Unavailable,
    #[error("the private telemetry queue contains an invalid record")]
    InvalidRecord,
    #[error("the OTLP telemetry delivery failed")]
    DeliveryFailed,
}

pub fn otlp_payloads(
    component: TelemetryComponent,
    deployment_label: Option<&str>,
    record: &TelemetryRecord,
) -> (Value, Value) {
    let trace_id = Uuid::now_v7().simple().to_string();
    let span_id = trace_id[16..].to_string();
    let end_nanos = record.recorded_at.unix_timestamp_nanos();
    let duration_nanos = i128::from(record.duration_ms) * 1_000_000;
    let start_nanos = end_nanos.saturating_sub(duration_nanos);
    let resource = resource_attributes(component, deployment_label);
    let status = match record.outcome {
        TelemetryOutcome::Success => json!({"code": 1}),
        TelemetryOutcome::Failure => json!({
            "code": 2,
            "message": record.error_code.map(|code| serde_json::to_value(code).expect("error code serializes")).unwrap_or_else(|| json!("unknown")),
        }),
    };
    let traces = json!({
        "resourceSpans": [{
            "resource": {"attributes": resource},
            "scopeSpans": [{
                "scope": {"name": "satelle", "version": env!("CARGO_PKG_VERSION")},
                "spans": [{
                    "traceId": trace_id,
                    "spanId": span_id,
                    "name": "satelle.operation",
                    "kind": 1,
                    "startTimeUnixNano": start_nanos.to_string(),
                    "endTimeUnixNano": end_nanos.to_string(),
                    "status": status
                }]
            }]
        }]
    });
    let mut metrics = vec![
        gauge(
            "satelle.operation.duration",
            record.duration_ms as f64,
            end_nanos,
        ),
        gauge(
            "satelle.operation.outcome",
            matches!(record.outcome, TelemetryOutcome::Success) as u8 as f64,
            end_nanos,
        ),
        gauge(
            "satelle.operation.retry_count",
            record.retry_count as f64,
            end_nanos,
        ),
        gauge(
            "satelle.telemetry.queue_depth",
            record.queue_depth as f64,
            end_nanos,
        ),
    ];
    if let Some(cpu_ms) = record.resource_usage.cpu_ms {
        metrics.push(gauge("satelle.process.cpu", cpu_ms as f64, end_nanos));
    }
    if let Some(bytes) = record.resource_usage.peak_memory_bytes {
        metrics.push(gauge(
            "satelle.process.peak_memory",
            bytes as f64,
            end_nanos,
        ));
    }
    let metrics = json!({
        "resourceMetrics": [{
            "resource": {"attributes": resource_attributes(component, deployment_label)},
            "scopeMetrics": [{
                "scope": {"name": "satelle", "version": env!("CARGO_PKG_VERSION")},
                "metrics": metrics
            }]
        }]
    });
    (traces, metrics)
}

fn resource_attributes(
    component: TelemetryComponent,
    deployment_label: Option<&str>,
) -> Vec<Value> {
    let mut attributes = vec![
        string_attribute("service.version", env!("CARGO_PKG_VERSION")),
        string_attribute("satelle.component", component.as_str()),
        string_attribute("os.type", std::env::consts::OS),
    ];
    if let Some(label) = deployment_label {
        attributes.push(string_attribute("deployment.environment.name", label));
    }
    attributes
}

fn string_attribute(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

fn gauge(name: &str, value: f64, timestamp: i128) -> Value {
    json!({
        "name": name,
        "gauge": {"dataPoints": [{"timeUnixNano": timestamp.to_string(), "asDouble": value}]}
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    struct PrivateState {
        _temporary: tempfile::TempDir,
        root: PathBuf,
    }

    impl PrivateState {
        fn path(&self) -> &Path {
            &self.root
        }
    }

    fn private_state() -> PrivateState {
        let temporary = tempfile::tempdir().expect("temporary state");
        let root = temporary.path().join("state");
        drop(
            open_or_create_owner_only_directory(&root)
                .expect("create owner-only test state directory"),
        );
        PrivateState {
            _temporary: temporary,
            root,
        }
    }

    fn success_record(duration_ms: u64) -> TelemetryRecord {
        TelemetryRecord::new(
            std::time::Duration::from_millis(duration_ms),
            TelemetryOutcome::Success,
            None,
            0,
            TelemetryResourceUsage::default(),
        )
    }

    #[test]
    fn endpoint_requires_https_except_for_loopback_http() {
        assert!(TelemetryEndpoint::parse("https://collector.example").is_ok());
        assert!(TelemetryEndpoint::parse("http://127.0.0.1:4318").is_ok());
        assert!(TelemetryEndpoint::parse("http://collector.example").is_err());
        assert!(TelemetryEndpoint::parse("https://user:secret@collector.example").is_err());
        assert!(TelemetryEndpoint::parse("https://collector.example/private").is_err());
    }

    #[test]
    fn disabled_status_deletes_buffered_records() {
        let state = private_state();
        let queue = TelemetryQueue::new(state.path(), TelemetryComponent::Controller);
        queue.enqueue(success_record(42)).expect("queue record");

        let status = queue
            .status(TelemetryComponent::Controller, false, None)
            .expect("disabled status");

        assert_eq!(status.buffered_record_count, 0);
        assert!(!state.path().join("telemetry/controller").exists());
    }

    #[test]
    fn disabled_delivery_clears_without_resolving_or_contacting_configuration() {
        let state = private_state();
        let queue = TelemetryQueue::new(state.path(), TelemetryComponent::Controller);
        queue.enqueue(success_record(42)).expect("queue record");
        let disabled = TelemetryConfig {
            enabled: false,
            otlp_endpoint: Some("https://unreachable.invalid".to_string()),
            authorization: Some(TelemetrySecretSource::Environment {
                variable: "SATELLE_TEST_MISSING_TELEMETRY_SECRET".to_string(),
            }),
            deployment_label: None,
        };

        queue
            .deliver(&disabled, TelemetryComponent::Controller)
            .expect("disable clears without delivery");

        assert!(!state.path().join("telemetry/controller").exists());
    }

    #[test]
    fn queue_drops_expired_and_oldest_over_limit_records() {
        let state = private_state();
        let queue = TelemetryQueue::new(state.path(), TelemetryComponent::Controller);
        queue
            .enqueue(success_record(1))
            .expect("queue oldest record");
        queue
            .enqueue(success_record(2))
            .expect("queue middle record");
        queue
            .enqueue(success_record(3))
            .expect("queue newest record");
        let records = queue.records().expect("read queued records");

        let mut expired = records[0].record.clone();
        expired.recorded_at = OffsetDateTime::now_utc() - Duration::hours(25);
        fs::write(
            queue.root.join(&records[0].file_name),
            serde_json::to_vec(&expired).unwrap(),
        )
        .expect("age the oldest record");
        let newest_size = fs::metadata(queue.root.join(&records[2].file_name))
            .expect("measure newest record")
            .len();

        queue
            .prune_with_limits(
                OffsetDateTime::now_utc(),
                newest_size,
                TELEMETRY_QUEUE_RETENTION,
            )
            .expect("apply retention and byte limit");

        let retained = queue.records().expect("read retained records");
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].record.duration_ms, 3);
    }

    #[test]
    fn delivery_uses_otlp_http_and_acknowledges_only_after_both_payloads() {
        let state = private_state();
        let secret_path = state.path().join("collector-token");
        persist_new_owner_only_config_file(&secret_path, b"test-token")
            .expect("write authorization Secret Source");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test collector");
        listener
            .set_nonblocking(true)
            .expect("bound collector accept timeout");
        let address = listener.local_addr().expect("collector address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let collector = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while captured.lock().unwrap().len() < 2 && std::time::Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .expect("collector read timeout");
                let mut request = Vec::new();
                let header_end = loop {
                    let mut buffer = [0_u8; 1024];
                    let read = stream.read(&mut buffer).expect("read OTLP request");
                    assert_ne!(read, 0, "OTLP request ended before its headers");
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(position) =
                        request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| {
                        value
                            .trim()
                            .parse::<usize>()
                            .expect("numeric content length")
                    })
                    .expect("OTLP request content length");
                while request.len() - header_end < content_length {
                    let mut buffer = [0_u8; 1024];
                    let read = stream.read(&mut buffer).expect("read OTLP body");
                    assert_ne!(read, 0, "OTLP body ended early");
                    request.extend_from_slice(&buffer[..read]);
                }
                captured.lock().unwrap().push(request);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .expect("reply to OTLP request");
            }
        });
        let config = TelemetryConfig {
            enabled: true,
            otlp_endpoint: Some(format!("http://{address}")),
            authorization: Some(TelemetrySecretSource::File { path: secret_path }),
            deployment_label: Some("test".to_string()),
        };
        let queue = TelemetryQueue::new(state.path(), TelemetryComponent::Controller);
        queue.enqueue(success_record(42)).expect("queue telemetry");

        queue
            .deliver(&config, TelemetryComponent::Controller)
            .expect("deliver telemetry");
        collector.join().expect("join test collector");

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let encoded = requests
            .iter()
            .map(|request| String::from_utf8_lossy(request))
            .collect::<Vec<_>>();
        assert!(
            encoded
                .iter()
                .any(|request| request.starts_with("POST /v1/traces "))
        );
        assert!(
            encoded
                .iter()
                .any(|request| request.starts_with("POST /v1/metrics "))
        );
        assert!(
            encoded
                .iter()
                .all(|request| request.contains("authorization: Bearer test-token"))
        );
        assert!(queue.pending().expect("read drained queue").is_empty());
        let status = queue
            .status(
                TelemetryComponent::Controller,
                true,
                Some(config.endpoint().unwrap().unwrap().origin()),
            )
            .expect("read telemetry status");
        assert_eq!(
            status.last_delivery.unwrap().outcome,
            TelemetryOutcome::Success
        );
    }

    #[test]
    fn payload_uses_only_the_public_resource_attributes() {
        let record = TelemetryRecord::new(
            std::time::Duration::from_millis(42),
            TelemetryOutcome::Failure,
            Some(ErrorCode::HostUnreachable),
            2,
            TelemetryResourceUsage::default(),
        );
        let (traces, metrics) =
            otlp_payloads(TelemetryComponent::Host, Some("production"), &record);
        let encoded = format!("{traces}{metrics}");

        for allowed in [
            "service.version",
            "satelle.component",
            "os.type",
            "deployment.environment.name",
        ] {
            assert!(encoded.contains(allowed));
        }
        for excluded in TELEMETRY_EXCLUSIONS {
            assert!(!encoded.contains(excluded));
        }
    }

    #[test]
    #[cfg(any(unix, windows))]
    fn process_resource_usage_is_available_on_supported_emitters() {
        let usage = TelemetryResourceUsage::current();
        assert!(usage.cpu_ms.is_some());
        assert!(usage.peak_memory_bytes.is_some());
    }
}
