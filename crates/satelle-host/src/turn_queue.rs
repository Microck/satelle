use crate::attachment::AttachmentInput;
use crate::storage::TurnQueueOperation;
use crate::{ApiPrincipal, ApiScopes, HostService, MutationAuthority, TurnIntent};
use satelle_core::queue::{QueueCancelResult, QueueFailure, QueueRequestStatus, QueueStatus};
use satelle_core::session::TurnExecutionMode;
use satelle_core::{ErrorCode, QueueRequestId, SatelleError, SessionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use time::OffsetDateTime;

pub(crate) const QUEUE_PAYLOAD_SCHEMA_VERSION: &str = "satelle.queue.payload.v1";
const MAX_QUEUE_PAYLOAD_BYTES: usize = 16 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QueuedOperation {
    Run,
    Steer,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedPrincipal {
    token_id: String,
    principal_ref: String,
    credential_revision: u64,
    scopes: u8,
    #[serde(with = "time::serde::rfc3339::option")]
    expires_at: Option<OffsetDateTime>,
}

impl QueuedPrincipal {
    fn capture(principal: &ApiPrincipal) -> Result<Self, SatelleError> {
        if principal.is_ssh_bootstrap()
            || principal.is_durable_setup_pending()
            || !principal.scopes().allows(ApiScopes::CONTROL)
        {
            return Err(queue_error(
                ErrorCode::QueuedPrincipalNoLongerAuthorized,
                "the current API Principal cannot own a durable queued Turn",
                None,
            ));
        }
        Ok(Self {
            token_id: principal.token_id().to_string(),
            principal_ref: principal.principal_ref().to_string(),
            credential_revision: principal.credential_revision(),
            scopes: principal.scopes().bits(),
            expires_at: principal.expires_at(),
        })
    }

    pub(crate) fn restore(&self) -> Result<ApiPrincipal, SatelleError> {
        let scopes = ApiScopes::from_bits(self.scopes).map_err(|_| {
            queue_error(
                ErrorCode::StorageIntegrityFailed,
                "the queued API Principal scope set is invalid",
                None,
            )
        })?;
        Ok(ApiPrincipal {
            token_id: self.token_id.clone(),
            principal_ref: self.principal_ref.clone(),
            credential_revision: self.credential_revision,
            scopes,
            expires_at: self.expires_at,
            process_local_ssh_bootstrap: false,
            durable_setup_pending: false,
            durable_setup_active: true,
        })
    }

    pub(crate) fn token_id(&self) -> &str {
        &self.token_id
    }

    pub(crate) const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedTurnPayload {
    schema_version: String,
    operation: QueuedOperation,
    explicit_queue: bool,
    session_id: Option<SessionId>,
    principal: QueuedPrincipal,
    idempotency_key: String,
    prompt: String,
    execution_mode: TurnExecutionMode,
    model: Option<String>,
    provider: Option<String>,
    model_from_project: bool,
    provider_from_project: bool,
    refresh_provider_smoke_test: bool,
    experimental_provider_computer_use: bool,
    turn_execution_timeout_ms: Option<u64>,
    attachments: Vec<AttachmentInput>,
    raw_protocol_source_host: Option<String>,
    recording: Option<satelle_core::recording::RecordingRequest>,
}

impl QueuedTurnPayload {
    pub(crate) fn capture(
        operation: QueuedOperation,
        session_id: Option<SessionId>,
        intent: &TurnIntent,
        authority: &MutationAuthority,
        explicit_queue: bool,
    ) -> Result<Self, SatelleError> {
        Ok(Self {
            schema_version: QUEUE_PAYLOAD_SCHEMA_VERSION.to_string(),
            operation,
            explicit_queue,
            session_id,
            principal: QueuedPrincipal::capture(authority.principal())?,
            idempotency_key: authority.idempotency_key().to_string(),
            prompt: intent.prompt().to_string(),
            execution_mode: intent.execution_mode(),
            model: intent
                .provider_intent()
                .model()
                .map(|model| model.as_str().to_string()),
            provider: intent
                .provider_intent()
                .provider()
                .map(|provider| provider.as_str().to_string()),
            model_from_project: intent.provider_intent().model_from_project(),
            provider_from_project: intent.provider_intent().provider_from_project(),
            refresh_provider_smoke_test: intent.provider_intent().refresh(),
            experimental_provider_computer_use: intent
                .provider_intent()
                .experimental_provider_computer_use(),
            turn_execution_timeout_ms: intent
                .turn_execution_timeout()
                .map(|timeout| u64::from(timeout.seconds()) * 1_000),
            attachments: intent
                .attachments()
                .iter()
                .map(crate::attachment::AcceptedImageAttachment::durable_input)
                .collect(),
            raw_protocol_source_host: intent.raw_protocol_source_host().map(str::to_string),
            recording: intent.recording().cloned(),
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, SatelleError> {
        serde_json::to_vec(self).map_err(|_| queue_storage_error("encode the queued Turn"))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, SatelleError> {
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|_| queue_storage_error("decode the queued Turn"))?;
        if payload.schema_version != QUEUE_PAYLOAD_SCHEMA_VERSION {
            return Err(queue_storage_error("decode the queued Turn schema"));
        }
        Ok(payload)
    }

    pub(crate) const fn operation(&self) -> QueuedOperation {
        self.operation
    }

    pub(crate) const fn explicit_queue(&self) -> bool {
        self.explicit_queue
    }

    pub(crate) const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub(crate) fn principal(&self) -> &QueuedPrincipal {
        &self.principal
    }

    pub(crate) fn into_admission(
        self,
    ) -> Result<(TurnIntent, MutationAuthority, Option<SessionId>), SatelleError> {
        let intent = TurnIntent::new(self.prompt, self.execution_mode)
            .and_then(|intent| {
                intent.with_provider_intent(
                    self.model,
                    self.provider,
                    self.refresh_provider_smoke_test,
                )
            })
            .map(|intent| {
                intent.with_project_selection_provenance(
                    self.model_from_project,
                    self.provider_from_project,
                )
            })
            .map(|intent| {
                intent.with_experimental_provider_computer_use(
                    self.experimental_provider_computer_use,
                )
            })
            .and_then(|intent| {
                intent.with_turn_execution_timeout_ms(self.turn_execution_timeout_ms)
            })
            .and_then(|intent| intent.with_attachments(self.attachments))
            .and_then(|intent| intent.with_raw_protocol_capture(self.raw_protocol_source_host))
            .and_then(|intent| intent.with_recording(self.recording))
            .map_err(|_| queue_storage_error("validate the queued Turn"))?;
        let authority = MutationAuthority::new(self.principal.restore()?, self.idempotency_key)
            .map_err(|_| queue_storage_error("validate the queued idempotency identity"))?;
        Ok((intent, authority, self.session_id))
    }
}

pub(crate) struct QueuePayloadStore {
    root: PathBuf,
}

impl QueuePayloadStore {
    pub(crate) fn open(root: PathBuf) -> Result<Self, SatelleError> {
        satelle_core::open_or_create_owner_only_directory(&root)
            .map_err(|_| queue_storage_error("open the private queue payload directory"))?;
        Ok(Self { root })
    }

    pub(crate) fn write(
        &self,
        queue_request_id: &QueueRequestId,
        payload: &[u8],
    ) -> Result<(String, String), SatelleError> {
        if payload.len() > MAX_QUEUE_PAYLOAD_BYTES {
            return Err(queue_error(
                ErrorCode::InvalidUsage,
                "the queued Turn exceeds the private payload byte limit",
                None,
            ));
        }
        let file_name = format!("{}.json", queue_request_id.as_str());
        let path = self.root.join(&file_name);
        let mut file = satelle_core::open_new_owner_only_file(&path)
            .map_err(|_| queue_storage_error("create the private queue payload"))?;
        if file
            .write_all(payload)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(queue_storage_error("persist the private queue payload"));
        }
        let digest = Sha256::digest(payload)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok((file_name, digest))
    }

    pub(crate) fn read(
        &self,
        file_name: &str,
        expected_sha256: &str,
    ) -> Result<QueuedTurnPayload, SatelleError> {
        validate_file_name(file_name)?;
        let bytes = satelle_core::read_bounded_regular_file_no_follow(
            &self.root.join(file_name),
            MAX_QUEUE_PAYLOAD_BYTES,
        )
        .map_err(|_| queue_storage_error("read the private queue payload"))?;
        let digest = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if digest != expected_sha256 {
            return Err(queue_storage_error("verify the private queue payload"));
        }
        QueuedTurnPayload::decode(&bytes)
    }

    pub(crate) fn delete(&self, file_name: &str) -> Result<(), SatelleError> {
        validate_file_name(file_name)?;
        match fs::remove_file(self.root.join(file_name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(queue_storage_error("delete the private queue payload")),
        }
    }

    pub(crate) fn retain_only(&self, retained: &BTreeSet<String>) -> Result<(), SatelleError> {
        for entry in fs::read_dir(&self.root)
            .map_err(|_| queue_storage_error("inspect the private queue payload directory"))?
        {
            let entry = entry
                .map_err(|_| queue_storage_error("inspect the private queue payload directory"))?;
            let file_name = entry
                .file_name()
                .into_string()
                .map_err(|_| queue_storage_error("validate a private queue payload name"))?;
            validate_file_name(&file_name)?;
            if !retained.contains(&file_name) {
                self.delete(&file_name)?;
            }
        }
        Ok(())
    }
}

pub(crate) fn queue_failure(error: &SatelleError) -> QueueFailure {
    QueueFailure {
        code: error.code.as_str().to_string(),
        message: error.message.clone(),
    }
}

impl HostService {
    pub fn queue_enabled(&self) -> Result<bool, SatelleError> {
        self.runtime.queue_config().map(|config| config.enabled())
    }

    pub fn enqueue_run(
        &self,
        intent: &TurnIntent,
        authority: &MutationAuthority,
        explicit_queue: bool,
    ) -> Result<QueueStatus, SatelleError> {
        self.enqueue_turn(
            QueuedOperation::Run,
            None,
            intent,
            authority,
            explicit_queue,
        )
    }

    pub fn enqueue_steer(
        &self,
        session_id: &SessionId,
        intent: &TurnIntent,
        authority: &MutationAuthority,
        explicit_queue: bool,
    ) -> Result<QueueStatus, SatelleError> {
        self.enqueue_turn(
            QueuedOperation::Steer,
            Some(session_id.clone()),
            intent,
            authority,
            explicit_queue,
        )
    }

    fn enqueue_turn(
        &self,
        operation: QueuedOperation,
        session_id: Option<SessionId>,
        intent: &TurnIntent,
        authority: &MutationAuthority,
        explicit_queue: bool,
    ) -> Result<QueueStatus, SatelleError> {
        let config = self.runtime.queue_config()?;
        if !explicit_queue && !config.enabled() {
            return Err(queue_error(
                ErrorCode::QueueDisabled,
                "the durable Turn queue is not enabled for this Host",
                Some(
                    "pass --queue or enable hosts.<alias>.queue.enabled in user config".to_string(),
                ),
            ));
        }
        let payload = QueuedTurnPayload::capture(
            operation,
            session_id.clone(),
            intent,
            authority,
            explicit_queue,
        )?;
        let encoded = payload.encode()?;
        let now = OffsetDateTime::now_utc();
        self.runtime.expire_turn_queue(now)?;
        let queue_request_id = QueueRequestId::new();
        let desktop_binding = self.runtime.queue_desktop_binding()?;
        let lease_key = self.runtime.queue_lease_key(&desktop_binding)?;
        let expires_at = now
            .checked_add(time::Duration::milliseconds(
                i64::try_from(config.ttl_ms()).expect("queue TTL fits i64"),
            ))
            .ok_or_else(|| queue_storage_error("calculate the queued Turn expiry"))?;
        let record = self
            .runtime
            .enqueue_turn_queue(
                &queue_request_id,
                &lease_key,
                payload.principal().token_id(),
                payload.principal().credential_revision(),
                authority.principal().principal_ref(),
                match operation {
                    QueuedOperation::Run => TurnQueueOperation::Run,
                    QueuedOperation::Steer => TurnQueueOperation::Steer,
                },
                authority.idempotency_key(),
                session_id.as_ref(),
                &encoded,
                now,
                expires_at,
                config.max_depth(),
            )?
            .ok_or_else(|| {
                queue_error(
                    ErrorCode::QueueFull,
                    format!(
                        "the durable Turn queue reached its {} request limit",
                        config.max_depth()
                    ),
                    Some(
                        "wait for a queued Turn to finish or cancel one queue request".to_string(),
                    ),
                )
            })?;
        let status = record.status.clone();
        self.start_queue_worker();
        Ok(status)
    }

    pub fn queued_turn_status(
        &self,
        principal_ref: &str,
        queue_request_id: &QueueRequestId,
    ) -> Result<QueueStatus, SatelleError> {
        self.runtime.expire_turn_queue(OffsetDateTime::now_utc())?;
        let status = self
            .runtime
            .queued_turn_status(principal_ref, queue_request_id)?
            .ok_or_else(queue_not_found)?
            .status;
        self.start_queue_worker();
        Ok(status)
    }

    pub fn cancel_queued_turn(
        &self,
        principal_ref: &str,
        queue_request_id: &QueueRequestId,
    ) -> Result<QueueCancelResult, SatelleError> {
        self.runtime.expire_turn_queue(OffsetDateTime::now_utc())?;
        let before = self
            .runtime
            .queued_turn_status(principal_ref, queue_request_id)?
            .ok_or_else(queue_not_found)?;
        if before.status.status == QueueRequestStatus::Admitted {
            let session_id = before
                .status
                .session_id
                .as_ref()
                .ok_or_else(|| queue_storage_error("read the admitted queue Session"))?;
            let mut error = queue_error(
                ErrorCode::QueueAlreadyAdmitted,
                "the queued Turn has already been admitted",
                Some(format!("satelle stop {session_id}")),
            );
            error.details.insert(
                "session_id".to_string(),
                serde_json::Value::String(session_id.to_string()),
            );
            if let Some(turn_id) = before.status.turn_id.as_ref() {
                error.details.insert(
                    "turn_id".to_string(),
                    serde_json::Value::String(turn_id.to_string()),
                );
            }
            return Err(error);
        }
        let after = self
            .runtime
            .cancel_queued_turn(principal_ref, queue_request_id)?
            .ok_or_else(queue_not_found)?;
        self.start_queue_worker();
        if before.status.status == QueueRequestStatus::Queued
            && after.status.status == QueueRequestStatus::Cancelled
        {
            Ok(QueueCancelResult::cancelled(queue_request_id.clone()))
        } else {
            Ok(QueueCancelResult::already_terminal(&after.status))
        }
    }

    pub fn start_queue_worker(&self) {
        if !self.runtime.try_start_queue_worker() {
            return;
        }
        let service = self.clone();
        if std::thread::Builder::new()
            .name("satelle-turn-queue".to_string())
            .spawn(move || {
                service.drain_turn_queue();
                service.runtime.finish_queue_worker();
                // Close the insertion/exit race: an enqueue that observed the
                // old worker as running is visible before this recheck.
                if service
                    .runtime
                    .queue_desktop_binding()
                    .and_then(|binding| service.runtime.queue_lease_key(&binding))
                    .and_then(|lease| service.runtime.next_queued_turn(&lease))
                    .is_ok_and(|next| next.is_some())
                {
                    service.start_queue_worker();
                }
            })
            .is_err()
        {
            self.runtime.finish_queue_worker();
        }
    }

    fn drain_turn_queue(&self) {
        loop {
            let now = OffsetDateTime::now_utc();
            if self.runtime.expire_turn_queue(now).is_err() {
                return;
            }
            // Queue admission must wait for both live Turn/control work and
            // runtime-owned maintenance. The latter is tracked outside
            // OperationCapacity, so use the combined daemon snapshot.
            let idle = self
                .daemon_activity_snapshot()
                .map(|snapshot| snapshot.is_idle())
                .unwrap_or(false);
            if !idle {
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            let record = match self
                .runtime
                .queue_desktop_binding()
                .and_then(|binding| self.runtime.queue_lease_key(&binding))
                .and_then(|lease| self.runtime.next_queued_turn(&lease))
            {
                Ok(Some(record)) => record,
                Ok(None) | Err(_) => return,
            };
            let payload = match self.runtime.read_queued_turn(&record) {
                Ok(payload) => payload,
                Err(error) => {
                    let _ = self
                        .runtime
                        .finish_queued_turn_failed(&record, &queue_failure(&error));
                    continue;
                }
            };
            if !queue_record_matches_payload(&record, &payload) {
                let error = queue_storage_error("match the queued Turn metadata and payload");
                let _ = self
                    .runtime
                    .finish_queued_turn_failed(&record, &queue_failure(&error));
                continue;
            }
            let config = match self.runtime.queue_config() {
                Ok(config) => config,
                Err(_) => return,
            };
            if !payload.explicit_queue() && !config.enabled() {
                let error = queue_error(
                    ErrorCode::QueueDisabled,
                    "the Host queue policy no longer allows this queued Turn",
                    None,
                );
                let _ = self
                    .runtime
                    .finish_queued_turn_failed(&record, &queue_failure(&error));
                continue;
            }
            let principal = match payload.principal().restore() {
                Ok(principal) => principal,
                Err(error) => {
                    let _ = self
                        .runtime
                        .finish_queued_turn_failed(&record, &queue_failure(&error));
                    continue;
                }
            };
            if !self.api_principal_is_active(&principal).unwrap_or(false)
                || !principal.scopes().allows(ApiScopes::CONTROL)
            {
                let error = queue_error(
                    ErrorCode::QueuedPrincipalNoLongerAuthorized,
                    "the queued API Principal is no longer authorized",
                    None,
                );
                let _ = self
                    .runtime
                    .finish_queued_turn_failed(&record, &queue_failure(&error));
                continue;
            }
            let operation = payload.operation();
            let (intent, authority, session_id) = match payload.into_admission() {
                Ok(admission) => admission,
                Err(error) => {
                    let _ = self
                        .runtime
                        .finish_queued_turn_failed(&record, &queue_failure(&error));
                    continue;
                }
            };
            let admitted = match operation {
                QueuedOperation::Run => self.admit_run(&intent, &authority),
                QueuedOperation::Steer => match session_id {
                    Some(session_id) => self.admit_steer(&session_id, &intent, &authority),
                    None => Err(queue_storage_error("read the queued steer Session")),
                },
            };
            match admitted {
                Ok(session) => {
                    let turn_id = session
                        .turns()
                        .last()
                        .expect("an admitted queued request contains its target Turn")
                        .turn_id()
                        .clone();
                    if self
                        .runtime
                        .finish_queued_turn_admitted(&record, session.session_id(), &turn_id)
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.code == ErrorCode::CapacityExceeded => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Err(error) => {
                    if self
                        .runtime
                        .finish_queued_turn_failed(&record, &queue_failure(&error))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
}

fn queue_record_matches_payload(
    record: &crate::storage::StoredQueueRecord,
    payload: &QueuedTurnPayload,
) -> bool {
    matches!(
        (record.operation, payload.operation()),
        (TurnQueueOperation::Run, QueuedOperation::Run)
            | (TurnQueueOperation::Steer, QueuedOperation::Steer)
    ) && record.status.session_id.as_ref() == payload.session_id()
}

fn queue_not_found() -> SatelleError {
    queue_error(
        ErrorCode::QueueRequestNotFound,
        "the queue request was not found for this API Principal",
        None,
    )
}

pub(crate) fn queue_error(
    code: ErrorCode,
    message: impl Into<String>,
    recovery_command: Option<String>,
) -> SatelleError {
    SatelleError {
        code,
        message: message.into(),
        recovery_command,
        source_detail: None,
        details: Default::default(),
    }
}

fn queue_storage_error(action: &str) -> SatelleError {
    queue_error(
        ErrorCode::StorageIntegrityFailed,
        format!("the Host could not {action}"),
        Some("inspect the Host storage and retry the queue operation".to_string()),
    )
}

fn validate_file_name(file_name: &str) -> Result<(), SatelleError> {
    let Some(id) = file_name.strip_suffix(".json") else {
        return Err(queue_storage_error("validate a private queue payload name"));
    };
    QueueRequestId::parse(id)
        .map(|_| ())
        .map_err(|_| queue_storage_error("validate a private queue payload name"))
}
