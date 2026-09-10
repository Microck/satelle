use crate::storage::Storage;
use satelle_core::sensitive_diagnostics::{
    DiagnosticRedactor, MAX_PENDING_RAW_EXPORTS, MAX_RAW_PROTOCOL_BYTES, ProtocolDirection,
    RAW_DIAGNOSTICS_SCHEMA_VERSION, RAW_EXPORT_RETENTION_SECONDS, RawDiagnosticExportOutcome,
    RawDiagnosticFailure, RawDiagnosticManifest, RawProtocolArtifact, RawProtocolRecord,
};
use satelle_core::{SatelleError, TurnId, utc_now};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex};
use time::OffsetDateTime;

#[derive(Clone)]
pub(crate) struct RawProtocolCapture {
    inner: Arc<Mutex<CaptureState>>,
}

struct CaptureState {
    manifest: RawDiagnosticManifest,
    redactor: DiagnosticRedactor,
    records: Vec<RawProtocolRecord>,
    captured_bytes: usize,
    failure: Option<RawDiagnosticFailure>,
    finished: bool,
}

impl RawProtocolCapture {
    fn new(manifest: RawDiagnosticManifest) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CaptureState {
                manifest,
                redactor: DiagnosticRedactor::default(),
                records: Vec::new(),
                captured_bytes: 0,
                failure: None,
                finished: false,
            })),
        }
    }

    fn failed(manifest: RawDiagnosticManifest, failure: RawDiagnosticFailure) -> Self {
        let capture = Self::new(manifest);
        capture.fail(failure);
        capture
    }

    pub(crate) fn add_known_secret(&self, secret: &str) {
        if let Ok(mut state) = self.inner.lock()
            && state.failure.is_none()
            && !state.finished
        {
            state.redactor.add_known_secret(secret);
        }
    }

    /// Capture failures are contained here. Protocol execution never observes
    /// them, and a failed capture retains no partial protocol record list.
    pub(crate) fn record(&self, direction: ProtocolDirection, bytes: &[u8]) {
        let message = match serde_json::from_slice(bytes) {
            Ok(message) => message,
            Err(_) => {
                self.fail(RawDiagnosticFailure::RedactionFailed);
                return;
            }
        };
        self.record_message(direction, message, bytes.len());
    }

    pub(crate) fn record_message(
        &self,
        direction: ProtocolDirection,
        message: serde_json::Value,
        wire_len: usize,
    ) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        if state.failure.is_some() || state.finished {
            return;
        }
        let Some(captured_bytes) = state.captured_bytes.checked_add(wire_len) else {
            state.set_failure(RawDiagnosticFailure::RedactionFailed);
            return;
        };
        if captured_bytes > MAX_RAW_PROTOCOL_BYTES {
            state.set_failure(RawDiagnosticFailure::RedactionFailed);
            return;
        }
        let message = match state.redactor.redact_message(message, wire_len) {
            Ok(message) => message,
            Err(_) => {
                state.set_failure(RawDiagnosticFailure::RedactionFailed);
                return;
            }
        };
        state.captured_bytes = captured_bytes;
        state.records.push(RawProtocolRecord {
            direction,
            captured_at: utc_now(),
            message,
        });
    }

    fn fail(&self, failure: RawDiagnosticFailure) {
        if let Ok(mut state) = self.inner.lock() {
            state.set_failure(failure);
        }
    }

    fn finish(&self) -> (RawExportState, Option<usize>) {
        let Ok(mut state) = self.inner.lock() else {
            return (
                RawExportState::Failed(RawDiagnosticFailure::StagingFailed),
                None,
            );
        };
        state.finished = true;
        if let Some(failure) = state.failure {
            return (RawExportState::Failed(failure), None);
        }
        let artifact = RawProtocolArtifact {
            schema_version: RAW_DIAGNOSTICS_SCHEMA_VERSION.to_string(),
            manifest: state.manifest.clone(),
            records: std::mem::take(&mut state.records),
        };
        let mut serialized_size = SerializedSize::default();
        let size = match serde_json::to_writer(&mut serialized_size, &artifact) {
            Ok(()) if serialized_size.0 <= MAX_RAW_PROTOCOL_BYTES => serialized_size.0,
            _ => {
                state.set_failure(RawDiagnosticFailure::RedactionFailed);
                return (
                    RawExportState::Failed(RawDiagnosticFailure::RedactionFailed),
                    None,
                );
            }
        };
        (RawExportState::Ready(Box::new(artifact)), Some(size))
    }
}

#[derive(Default)]
struct SerializedSize(usize);

impl Write for SerializedSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_size = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized diagnostic size overflow"))?;
        if next_size > MAX_RAW_PROTOCOL_BYTES {
            return Err(io::Error::other("serialized diagnostic exceeds its limit"));
        }
        self.0 = next_size;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CaptureState {
    fn set_failure(&mut self, failure: RawDiagnosticFailure) {
        self.failure.get_or_insert(failure);
        self.records.clear();
        self.captured_bytes = 0;
    }
}

struct RawExportEntry {
    principal_ref: String,
    state: RawExportState,
    expires_at: Option<OffsetDateTime>,
}

enum RawExportState {
    Capturing(RawProtocolCapture),
    Ready(Box<RawProtocolArtifact>),
    Failed(RawDiagnosticFailure),
}

#[derive(Default)]
struct RawExportRegistry {
    entries: HashMap<TurnId, RawExportEntry>,
    expiry_worker_running: bool,
    generation: u64,
}

#[derive(Clone, Default)]
pub(crate) struct RawDiagnosticExports {
    registry: Arc<(Mutex<RawExportRegistry>, Condvar)>,
}

impl RawDiagnosticExports {
    pub(crate) fn begin(
        &self,
        storage: &Storage,
        principal_ref: &str,
        manifest: RawDiagnosticManifest,
        created_at: OffsetDateTime,
    ) -> RawProtocolCapture {
        let turn_id = manifest.turn_id.clone();
        let mut registry = match self.registry.0.lock() {
            Ok(registry) => registry,
            Err(_) => {
                return RawProtocolCapture::failed(manifest, RawDiagnosticFailure::StagingFailed);
            }
        };
        if registry.entries.len() >= MAX_PENDING_RAW_EXPORTS {
            let capture =
                RawProtocolCapture::failed(manifest.clone(), RawDiagnosticFailure::StagingFailed);
            if storage
                .begin_raw_diagnostic_export(principal_ref, &manifest, created_at)
                .is_ok()
            {
                let _ = storage.finish_raw_diagnostic_export(
                    principal_ref,
                    &turn_id,
                    RawDiagnosticExportOutcome::Failed,
                    created_at,
                );
            }
            return capture;
        }
        let capture = RawProtocolCapture::new(manifest.clone());
        if storage
            .begin_raw_diagnostic_export(principal_ref, &manifest, created_at)
            .is_err()
        {
            capture.fail(RawDiagnosticFailure::StagingFailed);
        }
        registry.entries.insert(
            turn_id,
            RawExportEntry {
                principal_ref: principal_ref.to_string(),
                state: RawExportState::Capturing(capture.clone()),
                expires_at: None,
            },
        );
        capture
    }

    pub(crate) fn complete(
        &self,
        storage: Arc<Mutex<Storage>>,
        turn_id: &TurnId,
        completed_at: OffsetDateTime,
    ) {
        let capturing_entry = self.registry.0.lock().ok().and_then(|registry| {
            match &registry.entries.get(turn_id)?.state {
                RawExportState::Capturing(capture) => Some((
                    capture.clone(),
                    registry.entries[turn_id].principal_ref.clone(),
                )),
                RawExportState::Ready(_) | RawExportState::Failed(_) => None,
            }
        });
        let Some((capture, principal_ref)) = capturing_entry else {
            return;
        };
        let (mut export, size) = capture.finish();
        let Ok(storage_guard) = storage.lock() else {
            return;
        };
        if let Some(size) = size
            && storage_guard
                .prepare_raw_diagnostic_export(turn_id, size)
                .is_err()
        {
            export = RawExportState::Failed(RawDiagnosticFailure::StagingFailed);
        }
        if matches!(export, RawExportState::Failed(_)) {
            let _ = storage_guard.finish_raw_diagnostic_export(
                &principal_ref,
                turn_id,
                RawDiagnosticExportOutcome::Failed,
                completed_at,
            );
        }
        drop(storage_guard);

        let expires_at =
            completed_at + time::Duration::seconds(RAW_EXPORT_RETENTION_SECONDS as i64);
        let should_start_worker = {
            let Ok(mut registry) = self.registry.0.lock() else {
                return;
            };
            let Some(entry) = registry.entries.get_mut(turn_id) else {
                return;
            };
            entry.state = export;
            entry.expires_at = Some(expires_at);
            registry.generation = registry.generation.wrapping_add(1);
            let should_start = !registry.expiry_worker_running;
            registry.expiry_worker_running = true;
            self.registry.1.notify_one();
            should_start
        };
        if !should_start_worker {
            return;
        }
        let expiry_registry = Arc::clone(&self.registry);
        let expiry_storage = Arc::clone(&storage);
        let expiry_thread = std::thread::Builder::new()
            .name("satelle-raw-diagnostic-expiry".to_string())
            .spawn(move || run_expiry_worker(&expiry_registry, &expiry_storage));
        if expiry_thread.is_err() {
            self.expire_all_completed_exports(&storage, completed_at);
        }
    }

    pub(crate) fn download(
        &self,
        storage: &Storage,
        principal_ref: &str,
        turn_id: &TurnId,
        observed_at: OffsetDateTime,
    ) -> Result<RawProtocolArtifact, SatelleError> {
        self.expire(storage, observed_at);
        let registry = self.registry.0.lock().map_err(|_| {
            SatelleError::raw_diagnostics_failure(
                RawDiagnosticFailure::ExportFailed,
                "the raw diagnostic export registry is unavailable",
            )
        })?;
        let entry = registry
            .entries
            .get(turn_id)
            .filter(|entry| entry.principal_ref == principal_ref)
            .ok_or_else(raw_export_unavailable)?;
        match &entry.state {
            RawExportState::Ready(artifact) => Ok(artifact.as_ref().clone()),
            RawExportState::Failed(failure) => Err(SatelleError::raw_diagnostics_failure(
                *failure,
                "the Host could not prepare this raw protocol export",
            )),
            RawExportState::Capturing(_) => Err(SatelleError::raw_diagnostics_failure(
                RawDiagnosticFailure::ExportFailed,
                "the selected Turn has not finished raw protocol capture",
            )),
        }
    }

    pub(crate) fn acknowledge(
        &self,
        storage: &Storage,
        principal_ref: &str,
        turn_id: &TurnId,
        outcome: RawDiagnosticExportOutcome,
        completed_at: OffsetDateTime,
    ) -> Result<(), SatelleError> {
        let mut registry = self
            .registry
            .0
            .lock()
            .map_err(|_| raw_export_unavailable())?;
        let entry = registry
            .entries
            .get(turn_id)
            .filter(|entry| entry.principal_ref == principal_ref)
            .ok_or_else(raw_export_unavailable)?;
        if !matches!(entry.state, RawExportState::Ready(_)) {
            return Err(raw_export_unavailable());
        }
        storage
            .finish_raw_diagnostic_export(principal_ref, turn_id, outcome, completed_at)
            .map_err(crate::runtime::storage_failure)?;
        registry.entries.remove(turn_id);
        registry.generation = registry.generation.wrapping_add(1);
        self.registry.1.notify_one();
        Ok(())
    }

    fn expire(&self, storage: &Storage, observed_at: OffsetDateTime) {
        let Ok(mut registry) = self.registry.0.lock() else {
            return;
        };
        let expired: Vec<(TurnId, String)> = registry
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at.is_some_and(|expiry| expiry <= observed_at))
            .map(|(turn_id, entry)| (turn_id.clone(), entry.principal_ref.clone()))
            .collect();
        for (turn_id, principal_ref) in expired {
            let _ = storage.finish_raw_diagnostic_export(
                &principal_ref,
                &turn_id,
                RawDiagnosticExportOutcome::Failed,
                observed_at,
            );
            registry.entries.remove(&turn_id);
        }
        registry.generation = registry.generation.wrapping_add(1);
        self.registry.1.notify_one();
    }

    fn expire_all_completed_exports(&self, storage: &Mutex<Storage>, observed_at: OffsetDateTime) {
        let expired = self.registry.0.lock().ok().map(|mut registry| {
            let completed_ids = registry
                .entries
                .iter()
                .filter(|(_, entry)| entry.expires_at.is_some())
                .map(|(turn_id, _)| turn_id.clone())
                .collect::<Vec<_>>();
            let expired = completed_ids
                .into_iter()
                .filter_map(|turn_id| {
                    registry
                        .entries
                        .remove(&turn_id)
                        .map(|entry| (turn_id, entry.principal_ref))
                })
                .collect::<Vec<_>>();
            registry.expiry_worker_running = false;
            registry.generation = registry.generation.wrapping_add(1);
            expired
        });
        if let Some(expired) = expired
            && let Ok(storage) = storage.lock()
        {
            for (turn_id, principal_ref) in expired {
                let _ = storage.finish_raw_diagnostic_export(
                    &principal_ref,
                    &turn_id,
                    RawDiagnosticExportOutcome::Failed,
                    observed_at,
                );
            }
        }
    }
}

fn run_expiry_worker(registry: &(Mutex<RawExportRegistry>, Condvar), storage: &Mutex<Storage>) {
    loop {
        let now = OffsetDateTime::now_utc();
        let (expired, next_expiry, generation) = {
            let Ok(mut state) = registry.0.lock() else {
                return;
            };
            let expired_ids: Vec<TurnId> = state
                .entries
                .iter()
                .filter(|(_, entry)| entry.expires_at.is_some_and(|expiry| expiry <= now))
                .map(|(turn_id, _)| turn_id.clone())
                .collect();
            let expired = expired_ids
                .into_iter()
                .filter_map(|turn_id| {
                    state
                        .entries
                        .remove(&turn_id)
                        .map(|entry| (turn_id, entry.principal_ref))
                })
                .collect::<Vec<_>>();
            let next_expiry = state
                .entries
                .values()
                .filter_map(|entry| entry.expires_at)
                .min();
            if next_expiry.is_none() {
                state.expiry_worker_running = false;
            }
            (expired, next_expiry, state.generation)
        };

        if !expired.is_empty()
            && let Ok(storage) = storage.lock()
        {
            for (turn_id, principal_ref) in expired {
                let _ = storage.finish_raw_diagnostic_export(
                    &principal_ref,
                    &turn_id,
                    RawDiagnosticExportOutcome::Failed,
                    now,
                );
            }
        }
        let Some(next_expiry) = next_expiry else {
            return;
        };
        let wait_for = (next_expiry - OffsetDateTime::now_utc())
            .try_into()
            .unwrap_or(std::time::Duration::ZERO);
        let Ok(state) = registry.0.lock() else {
            return;
        };
        if state.generation != generation {
            continue;
        }
        let _ = registry
            .1
            .wait_timeout_while(state, wait_for, |state| state.generation == generation);
    }
}

fn raw_export_unavailable() -> SatelleError {
    SatelleError::raw_diagnostics_failure(
        RawDiagnosticFailure::ExportFailed,
        "the raw protocol export is unavailable for this Principal and Turn",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use satelle_core::SessionId;
    use satelle_core::sensitive_diagnostics::RawDiagnosticCommand;
    use serde_json::json;

    #[test]
    fn export_is_redacted_creator_bound_and_removed_after_acknowledgement() {
        const SECRET: &str = "PRIVATE_RAW_PROTOCOL_SECRET";
        let state = crate::TestStateDir::new().unwrap();
        let (storage, _) = Storage::open(state.path()).unwrap();
        let storage = Arc::new(Mutex::new(storage));
        let exports = RawDiagnosticExports::default();
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let now = OffsetDateTime::now_utc();

        let capture = exports.begin(
            &storage.lock().unwrap(),
            "creator",
            RawDiagnosticManifest::new(
                "remote-demo",
                "host-test",
                RawDiagnosticCommand::Run,
                session_id.clone(),
                turn_id.clone(),
            ),
            now,
        );
        capture.add_known_secret(SECRET);
        capture.record(
            ProtocolDirection::ToCodex,
            &serde_json::to_vec(&json!({
                "method": "turn/start",
                "prompt": format!("inspect {SECRET}"),
                "headers": {"Authorization": "Bearer TOKEN_CANARY"}
            }))
            .unwrap(),
        );
        capture.record(
            ProtocolDirection::FromCodex,
            br#"{"result":{"message":"completed"}}"#,
        );
        exports.complete(Arc::clone(&storage), &turn_id, now);

        let artifact = exports
            .download(&storage.lock().unwrap(), "creator", &turn_id, now)
            .unwrap();
        assert_eq!(artifact.schema_version, RAW_DIAGNOSTICS_SCHEMA_VERSION);
        assert_eq!(artifact.manifest.session_id, session_id);
        assert_eq!(artifact.manifest.turn_id, turn_id);
        assert_eq!(artifact.records.len(), 2);
        let bytes = serde_json::to_vec(&artifact).unwrap();
        assert!(
            !bytes
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );
        assert!(!bytes.windows(12).any(|window| window == b"TOKEN_CANARY"));
        assert!(
            exports
                .download(&storage.lock().unwrap(), "other", &turn_id, now)
                .is_err()
        );

        exports
            .acknowledge(
                &storage.lock().unwrap(),
                "creator",
                &turn_id,
                RawDiagnosticExportOutcome::Exported,
                now,
            )
            .unwrap();
        assert!(
            exports
                .download(&storage.lock().unwrap(), "creator", &turn_id, now)
                .is_err()
        );
    }

    #[test]
    fn pending_export_registry_stays_within_its_hard_limit() {
        let state = crate::TestStateDir::new().unwrap();
        let (storage, _) = Storage::open(state.path()).unwrap();
        let exports = RawDiagnosticExports::default();
        let now = OffsetDateTime::now_utc();
        for _ in 0..MAX_PENDING_RAW_EXPORTS {
            exports.begin(
                &storage,
                "creator",
                RawDiagnosticManifest::new(
                    "local-demo",
                    "host-test",
                    RawDiagnosticCommand::Run,
                    SessionId::new(),
                    TurnId::new(),
                ),
                now,
            );
        }

        let rejected = exports.begin(
            &storage,
            "creator",
            RawDiagnosticManifest::new(
                "local-demo",
                "host-test",
                RawDiagnosticCommand::Run,
                SessionId::new(),
                TurnId::new(),
            ),
            now,
        );
        assert_eq!(
            exports.registry.0.lock().unwrap().entries.len(),
            MAX_PENDING_RAW_EXPORTS
        );
        assert!(matches!(
            rejected.finish().0,
            RawExportState::Failed(RawDiagnosticFailure::StagingFailed)
        ));
    }

    #[test]
    fn redaction_failure_discards_all_protocol_records_without_affecting_capture_callers() {
        let state = crate::TestStateDir::new().unwrap();
        let (storage, _) = Storage::open(state.path()).unwrap();
        let storage = Arc::new(Mutex::new(storage));
        let exports = RawDiagnosticExports::default();
        let turn_id = TurnId::new();
        let now = OffsetDateTime::now_utc();
        let capture = exports.begin(
            &storage.lock().unwrap(),
            "creator",
            RawDiagnosticManifest::new(
                "local-demo",
                "host-test",
                RawDiagnosticCommand::Steer,
                SessionId::new(),
                turn_id.clone(),
            ),
            now,
        );

        capture.record(ProtocolDirection::ToCodex, br#"{"method":"turn/start"}"#);
        capture.record(ProtocolDirection::FromCodex, b"not-json");
        capture.record(
            ProtocolDirection::FromCodex,
            br#"{"result":{"message":"must not survive"}}"#,
        );
        exports.complete(Arc::clone(&storage), &turn_id, now);

        let error = match exports.download(&storage.lock().unwrap(), "creator", &turn_id, now) {
            Ok(_) => panic!("failed capture must not return protocol records"),
            Err(error) => error,
        };
        assert_eq!(
            error.code,
            satelle_core::ErrorCode::RawDiagnosticsRedactionFailed
        );
    }
}
