use satelle_core::recording::{
    RecordingArtifactMetadata, RecordingManifest, RecordingMode, RecordingRequest, format_timestamp,
};
use satelle_core::sensitive_diagnostics::{DiagnosticRedactor, MAX_RAW_PROTOCOL_BYTES};
use satelle_core::{SatelleError, SatelleEvent, SessionId, TurnId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;

const VIDEO_FRAME_INTERVAL: Duration = Duration::from_secs(1);
const MAX_TEXT_RECORDING_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct RecordingCapture {
    inner: Arc<Mutex<CaptureState>>,
}

struct CaptureState {
    recording_id: String,
    mode: RecordingMode,
    session_id: SessionId,
    turn_id: TurnId,
    source_host: String,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    directory: PathBuf,
    prompt: String,
    transcript_items: Vec<Value>,
    transcript_bytes: usize,
    redactor: DiagnosticRedactor,
    screenshot_paths: Vec<PathBuf>,
    failure: Option<SatelleError>,
    video: Option<VideoCapture>,
    finished: Option<RecordingManifest>,
}

struct VideoCapture {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<Result<Vec<PathBuf>, SatelleError>>>,
    staging_root: PathBuf,
}

impl RecordingCapture {
    pub(crate) fn begin(
        recording_root: &Path,
        request: &RecordingRequest,
        session_id: SessionId,
        turn_id: TurnId,
        prompt: &str,
        created_at: OffsetDateTime,
    ) -> Result<Self, SatelleError> {
        let recording_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let directory = recording_root.join(&recording_id);
        satelle_core::open_or_create_owner_only_directory(&directory).map_err(|_| {
            recording_error(
                "recording_root_unavailable",
                "the private recording directory could not be created",
            )
        })?;
        let expires_at = created_at
            + time::Duration::milliseconds(i64::try_from(request.retention_ms).map_err(|_| {
                recording_error(
                    "retention_unrepresentable",
                    "the recording retention could not be represented",
                )
            })?);
        let capture = Self {
            inner: Arc::new(Mutex::new(CaptureState {
                recording_id,
                mode: request.mode,
                session_id,
                turn_id,
                source_host: request.source_host.clone(),
                created_at,
                expires_at,
                directory,
                prompt: prompt.to_string(),
                transcript_items: Vec::new(),
                transcript_bytes: prompt.len(),
                redactor: DiagnosticRedactor::default(),
                screenshot_paths: Vec::new(),
                failure: None,
                video: None,
                finished: None,
            })),
        };
        Ok(capture)
    }

    /// Starts sensitive capture only after the Host has committed its audit row.
    pub(crate) fn start(&self) -> Result<(), SatelleError> {
        let mode = self
            .inner
            .lock()
            .map_err(|_| {
                recording_error(
                    "capture_state_unavailable",
                    "recording capture state is unavailable",
                )
            })?
            .mode;
        match mode {
            RecordingMode::Screenshots => {
                self.capture_screenshot();
                if let Some(error) = self
                    .inner
                    .lock()
                    .map_err(|_| {
                        recording_error(
                            "capture_state_unavailable",
                            "recording capture state is unavailable",
                        )
                    })?
                    .failure
                    .clone()
                {
                    return Err(error);
                }
            }
            RecordingMode::Video => {
                let directory = self.directory()?;
                let video = start_video_capture(&directory)?;
                self.inner
                    .lock()
                    .map_err(|_| {
                        recording_error(
                            "capture_state_unavailable",
                            "recording capture state is unavailable",
                        )
                    })?
                    .video = Some(video);
            }
            RecordingMode::Events | RecordingMode::Transcript => {}
        }
        Ok(())
    }

    pub(crate) fn recording_id(&self) -> Result<String, SatelleError> {
        self.inner
            .lock()
            .map(|state| state.recording_id.clone())
            .map_err(|_| {
                recording_error(
                    "capture_state_unavailable",
                    "recording capture state is unavailable",
                )
            })
    }

    pub(crate) fn directory(&self) -> Result<PathBuf, SatelleError> {
        self.inner
            .lock()
            .map(|state| state.directory.clone())
            .map_err(|_| {
                recording_error(
                    "capture_state_unavailable",
                    "recording capture state is unavailable",
                )
            })
    }

    pub(crate) fn expires_at(&self) -> Result<OffsetDateTime, SatelleError> {
        self.inner
            .lock()
            .map(|state| state.expires_at)
            .map_err(|_| {
                recording_error(
                    "capture_state_unavailable",
                    "recording capture state is unavailable",
                )
            })
    }

    pub(crate) fn add_known_secret(&self, secret: &str) {
        if let Ok(mut state) = self.inner.lock() {
            state.redactor.add_known_secret(secret);
        }
    }

    pub(crate) fn record_protocol_item(&self, method: &str, item: &Value) {
        let mut capture_screenshot = false;
        if let Ok(mut state) = self.inner.lock() {
            if state.failure.is_some() || method != "item/completed" {
                return;
            }
            match state.mode {
                RecordingMode::Transcript => {
                    let item_bytes = serde_json::to_vec(item)
                        .map_or(MAX_TEXT_RECORDING_BYTES + 1, |bytes| bytes.len());
                    state.transcript_bytes = state.transcript_bytes.saturating_add(item_bytes);
                    if state.transcript_bytes > MAX_TEXT_RECORDING_BYTES {
                        state.failure = Some(recording_error(
                            "transcript_too_large",
                            "the recording transcript exceeded its 32 MiB capture limit",
                        ));
                    } else {
                        state.transcript_items.push(item.clone());
                    }
                }
                RecordingMode::Screenshots => capture_screenshot = true,
                RecordingMode::Events | RecordingMode::Video => {}
            }
        }
        if capture_screenshot {
            self.capture_screenshot();
        }
    }

    fn capture_screenshot(&self) {
        let png = match crate::desktop_snapshot::capture_current_desktop_png() {
            Ok(png) => png,
            Err(error) => {
                if let Ok(mut state) = self.inner.lock() {
                    state.failure.get_or_insert(error);
                }
                return;
            }
        };
        if let Ok(mut state) = self.inner.lock() {
            if state.failure.is_some() || state.mode != RecordingMode::Screenshots {
                return;
            }
            let path = state.directory.join(format!(
                "screenshot-{:06}.png",
                state.screenshot_paths.len() + 1
            ));
            let staging = state
                .directory
                .join(format!(".screenshot-{}.tmp", uuid::Uuid::now_v7().simple()));
            match satelle_core::persist_new_owner_only_desktop_snapshot(&path, &staging, &png) {
                Ok(()) => state.screenshot_paths.push(path),
                Err(_) => {
                    state.failure = Some(recording_error(
                        "screenshot_write_failed",
                        "a private recording screenshot could not be written",
                    ));
                }
            }
        }
    }

    pub(crate) fn finish(
        &self,
        events: &[SatelleEvent],
    ) -> Result<RecordingManifest, SatelleError> {
        let mut state = self.inner.lock().map_err(|_| {
            recording_error(
                "capture_state_unavailable",
                "recording capture state is unavailable",
            )
        })?;
        if let Some(manifest) = &state.finished {
            return Ok(manifest.clone());
        }
        let mut artifacts = match state.mode {
            RecordingMode::Events => write_events(&state, events)?,
            RecordingMode::Transcript => write_transcript(&state)?,
            RecordingMode::Screenshots => state
                .screenshot_paths
                .iter()
                .map(|path| artifact_metadata(path, "image/png", state.created_at))
                .collect::<Result<Vec<_>, _>>()?,
            RecordingMode::Video => finish_video(&mut state)?,
        };
        if let Some(error) = state.failure.take() {
            return Err(error);
        }
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest_path = state.directory.join("manifest.json");
        let manifest = RecordingManifest::new(
            state.recording_id.clone(),
            state.mode,
            state.session_id.clone(),
            state.turn_id.clone(),
            state.source_host.clone(),
            state.created_at,
            state.expires_at,
            manifest_path.display().to_string(),
            artifacts,
            cleanup_command(&state.directory),
        );
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| {
            recording_error(
                "manifest_serialization_failed",
                "the recording manifest could not be serialized",
            )
        })?;
        let staging = state.directory.join(".manifest.tmp");
        satelle_core::persist_new_owner_only_diagnostic_file(&manifest_path, &staging, &bytes)
            .map_err(|_| {
                recording_error(
                    "manifest_write_failed",
                    "the private recording manifest could not be written",
                )
            })?;
        state.finished = Some(manifest.clone());
        Ok(manifest)
    }

    pub(crate) fn abort(&self) -> Result<(), SatelleError> {
        let mut state = self.inner.lock().map_err(|_| {
            recording_error(
                "capture_state_unavailable",
                "recording capture state is unavailable",
            )
        })?;
        if let Some(mut video) = state.video.take() {
            let _ = video.stop.send(());
            video
                .worker
                .take()
                .expect("video worker exists until abort")
                .join()
                .map_err(|_| {
                    recording_error(
                        "video_worker_failed",
                        "the desktop video capture worker stopped unexpectedly",
                    )
                })??;
        }
        Ok(())
    }
}

fn write_events(
    state: &CaptureState,
    events: &[SatelleEvent],
) -> Result<Vec<RecordingArtifactMetadata>, SatelleError> {
    let mut records = Vec::new();
    for event in events {
        let bytes = serde_json::to_vec(event).map_err(|_| {
            recording_error(
                "event_serialization_failed",
                "a Satelle Event could not be serialized",
            )
        })?;
        let redacted = state.redactor.redact_json(&bytes).map_err(|_| {
            recording_error(
                "event_redaction_failed",
                "a Satelle Event could not be redacted",
            )
        })?;
        serde_json::to_writer(&mut records, &redacted).map_err(|_| {
            recording_error(
                "event_serialization_failed",
                "a redacted Satelle Event could not be serialized",
            )
        })?;
        records.push(b'\n');
    }
    persist_text_artifact(state, "events.ndjson", "application/x-ndjson", &records)
}

fn write_transcript(state: &CaptureState) -> Result<Vec<RecordingArtifactMetadata>, SatelleError> {
    if state.transcript_bytes > MAX_TEXT_RECORDING_BYTES {
        return Err(recording_error(
            "transcript_too_large",
            "the recording transcript exceeded its 32 MiB capture limit",
        ));
    }
    let prompt = state
        .redactor
        .redact_text(state.prompt.as_bytes())
        .map_err(|_| {
            recording_error(
                "transcript_redaction_failed",
                "the recording prompt could not be redacted",
            )
        })?;
    let mut records = Vec::new();
    serde_json::to_writer(
        &mut records,
        &json!({"kind": "prompt", "captured_at": format_timestamp(state.created_at), "text": prompt}),
    )
    .map_err(|_| recording_error("transcript_serialization_failed", "the recording prompt could not be serialized"))?;
    records.push(b'\n');
    for item in &state.transcript_items {
        let wire_len =
            serde_json::to_vec(item).map_or(MAX_RAW_PROTOCOL_BYTES + 1, |bytes| bytes.len());
        let redacted = state
            .redactor
            .redact_message(item.clone(), wire_len)
            .map_err(|_| {
                recording_error(
                    "transcript_redaction_failed",
                    "a transcript item could not be redacted",
                )
            })?;
        serde_json::to_writer(&mut records, &json!({"kind": "item", "item": redacted})).map_err(
            |_| {
                recording_error(
                    "transcript_serialization_failed",
                    "a transcript item could not be serialized",
                )
            },
        )?;
        records.push(b'\n');
    }
    persist_text_artifact(state, "transcript.ndjson", "application/x-ndjson", &records)
}

fn persist_text_artifact(
    state: &CaptureState,
    file_name: &str,
    artifact_type: &str,
    bytes: &[u8],
) -> Result<Vec<RecordingArtifactMetadata>, SatelleError> {
    let path = state.directory.join(file_name);
    let staging = state.directory.join(format!(".{file_name}.tmp"));
    satelle_core::persist_new_owner_only_diagnostic_file(&path, &staging, bytes).map_err(|_| {
        recording_error(
            "artifact_write_failed",
            "a private recording artifact could not be written",
        )
    })?;
    Ok(vec![artifact_metadata(
        &path,
        artifact_type,
        state.created_at,
    )?])
}

fn start_video_capture(directory: &Path) -> Result<VideoCapture, SatelleError> {
    let staging_root = directory.join(".video-frames");
    satelle_core::open_or_create_owner_only_directory(&staging_root).map_err(|_| {
        recording_error(
            "video_staging_unavailable",
            "the private video staging directory could not be created",
        )
    })?;
    let worker_root = staging_root.clone();
    let (stop, stopped) = mpsc::channel();
    let worker = thread::Builder::new()
        .name("satelle-recording-video".to_string())
        .spawn(move || {
            let mut frames = Vec::new();
            loop {
                let png = crate::desktop_snapshot::capture_current_desktop_png()?;
                let path = worker_root.join(format!("frame-{:08}.png", frames.len() + 1));
                write_private_new(&path, &png)?;
                frames.push(path);
                match stopped.recv_timeout(VIDEO_FRAME_INTERVAL) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(frames),
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        })
        .map_err(|_| {
            recording_error(
                "video_worker_unavailable",
                "the desktop video capture worker could not start",
            )
        })?;
    Ok(VideoCapture {
        stop,
        worker: Some(worker),
        staging_root,
    })
}

fn finish_video(state: &mut CaptureState) -> Result<Vec<RecordingArtifactMetadata>, SatelleError> {
    let mut video = state.video.take().ok_or_else(|| {
        recording_error(
            "video_state_unavailable",
            "the desktop video capture state is unavailable",
        )
    })?;
    let _ = video.stop.send(());
    let frames = video
        .worker
        .take()
        .expect("video worker exists until finalization")
        .join()
        .map_err(|_| {
            recording_error(
                "video_worker_failed",
                "the desktop video capture worker stopped unexpectedly",
            )
        })??;
    if frames.is_empty() {
        return Err(recording_error(
            "video_empty",
            "the desktop video recording produced no frames",
        ));
    }
    let path = state.directory.join("desktop-video.avi");
    write_mpng_avi(&path, &frames)?;
    fs::remove_dir_all(&video.staging_root).map_err(|_| {
        recording_error(
            "video_staging_cleanup_failed",
            "desktop video staging files could not be removed",
        )
    })?;
    Ok(vec![artifact_metadata(
        &path,
        "video/x-motion-png",
        state.created_at,
    )?])
}

fn write_mpng_avi(path: &Path, frames: &[PathBuf]) -> Result<(), SatelleError> {
    let first = fs::read(&frames[0]).map_err(|_| {
        recording_error(
            "video_frame_unavailable",
            "a desktop video frame could not be read",
        )
    })?;
    let (width, height) = png_dimensions(&first).ok_or_else(|| {
        recording_error(
            "video_frame_invalid",
            "a desktop video frame was not a valid PNG",
        )
    })?;
    let mut file = private_file(path)?;
    let mut header = avi_header(width, height, frames.len() as u32, 0, 0);
    file.write_all(&header).map_err(|_| {
        recording_error(
            "video_write_failed",
            "the desktop video artifact could not be written",
        )
    })?;
    let movi_data_start = header.len() as u64;
    let mut index = Vec::with_capacity(frames.len());
    for frame_path in frames {
        let frame = fs::read(frame_path).map_err(|_| {
            recording_error(
                "video_frame_unavailable",
                "a desktop video frame could not be read",
            )
        })?;
        if png_dimensions(&frame) != Some((width, height)) {
            return Err(recording_error(
                "video_frame_size_changed",
                "the visible desktop size changed during video recording",
            ));
        }
        let offset = file.stream_position().map_err(|_| {
            recording_error(
                "video_write_failed",
                "the desktop video artifact could not be written",
            )
        })?;
        file.write_all(b"00dc")
            .and_then(|()| file.write_all(&(frame.len() as u32).to_le_bytes()))
            .and_then(|()| file.write_all(&frame))
            .map_err(|_| {
                recording_error(
                    "video_write_failed",
                    "the desktop video artifact could not be written",
                )
            })?;
        if frame.len() % 2 == 1 {
            file.write_all(&[0]).map_err(|_| {
                recording_error(
                    "video_write_failed",
                    "the desktop video artifact could not be written",
                )
            })?;
        }
        index.push((
            u32::try_from(offset - movi_data_start).map_err(|_| {
                recording_error(
                    "video_too_large",
                    "the desktop video exceeded the AVI size limit",
                )
            })?,
            frame.len() as u32,
        ));
    }
    let index_start = file.stream_position().map_err(|_| {
        recording_error(
            "video_write_failed",
            "the desktop video artifact could not be written",
        )
    })?;
    file.write_all(b"idx1")
        .and_then(|()| file.write_all(&(index.len() as u32 * 16).to_le_bytes()))
        .map_err(|_| {
            recording_error(
                "video_write_failed",
                "the desktop video index could not be written",
            )
        })?;
    for (offset, size) in &index {
        file.write_all(b"00dc")
            .and_then(|()| file.write_all(&0x10_u32.to_le_bytes()))
            .and_then(|()| file.write_all(&offset.to_le_bytes()))
            .and_then(|()| file.write_all(&size.to_le_bytes()))
            .map_err(|_| {
                recording_error(
                    "video_write_failed",
                    "the desktop video index could not be written",
                )
            })?;
    }
    let end = file.stream_position().map_err(|_| {
        recording_error(
            "video_write_failed",
            "the desktop video artifact could not be written",
        )
    })?;
    let movi_size = u32::try_from(index_start - movi_data_start + 4).map_err(|_| {
        recording_error(
            "video_too_large",
            "the desktop video exceeded the AVI size limit",
        )
    })?;
    let riff_size = u32::try_from(end - 8).map_err(|_| {
        recording_error(
            "video_too_large",
            "the desktop video exceeded the AVI size limit",
        )
    })?;
    header = avi_header(width, height, frames.len() as u32, movi_size, riff_size);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&header))
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            recording_error(
                "video_write_failed",
                "the desktop video artifact could not be finalized",
            )
        })?;
    Ok(())
}

fn avi_header(width: u32, height: u32, frames: u32, movi_size: u32, riff_size: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(224);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&riff_size.to_le_bytes());
    out.extend_from_slice(b"AVI ");
    let mut hdrl = Vec::new();
    write_chunk(&mut hdrl, b"avih", &avi_main_header(width, height, frames));
    let mut strl = Vec::new();
    write_chunk(&mut strl, b"strh", &avi_stream_header(frames));
    write_chunk(&mut strl, b"strf", &avi_bitmap_header(width, height));
    write_list(&mut hdrl, b"strl", &strl);
    write_list(&mut out, b"hdrl", &hdrl);
    out.extend_from_slice(b"LIST");
    out.extend_from_slice(&movi_size.to_le_bytes());
    out.extend_from_slice(b"movi");
    out
}

fn avi_main_header(width: u32, height: u32, frames: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    for value in [
        1_000_000, 0, 0, 0x10, frames, 0, 1, 0, width, height, 0, 0, 0, 0,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn avi_stream_header(frames: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(56);
    out.extend_from_slice(b"vidsMPNG");
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    for value in [0_u32, 1, 1, 0, frames, 0, u32::MAX, 0] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&[0_u8; 8]);
    out
}

fn avi_bitmap_header(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(&40_u32.to_le_bytes());
    out.extend_from_slice(&(width as i32).to_le_bytes());
    out.extend_from_slice(&(height as i32).to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&24_u16.to_le_bytes());
    out.extend_from_slice(b"MPNG");
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&[0_u8; 16]);
    out
}

fn write_chunk(out: &mut Vec<u8>, id: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(id);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    if body.len() % 2 == 1 {
        out.push(0);
    }
}

fn write_list(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(b"LIST");
    out.extend_from_slice(&((body.len() + 4) as u32).to_le_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
}

fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    (bytes.len() >= 24 && &bytes[..8] == b"\x89PNG\r\n\x1a\n" && &bytes[12..16] == b"IHDR").then(
        || {
            (
                u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
                u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
            )
        },
    )
}

fn artifact_metadata(
    path: &Path,
    artifact_type: &str,
    created_at: OffsetDateTime,
) -> Result<RecordingArtifactMetadata, SatelleError> {
    let mut file = File::open(path).map_err(|_| {
        recording_error(
            "artifact_unavailable",
            "a recording artifact could not be read",
        )
    })?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            recording_error(
                "artifact_unavailable",
                "a recording artifact could not be read",
            )
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes = bytes.saturating_add(read as u64);
    }
    Ok(RecordingArtifactMetadata {
        path: path.display().to_string(),
        artifact_type: artifact_type.to_string(),
        created_at: format_timestamp(created_at),
        sha256: digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        byte_size: bytes,
        retention_state: "retained".to_string(),
    })
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), SatelleError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| {
        recording_error(
            "artifact_write_failed",
            "a private recording artifact could not be created",
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            recording_error(
                "artifact_write_failed",
                "a private recording artifact could not be written",
            )
        })
}

fn private_file(path: &Path) -> Result<File, SatelleError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| {
        recording_error(
            "artifact_write_failed",
            "a private recording artifact could not be created",
        )
    })
}

fn cleanup_command(path: &Path) -> String {
    #[cfg(windows)]
    {
        format!(
            "Remove-Item -Recurse -LiteralPath '{}'",
            path.to_string_lossy().replace('\'', "''")
        )
    }
    #[cfg(not(windows))]
    {
        format!(
            "rm -rf -- '{}'",
            path.to_string_lossy().replace('\'', "'\"'\"'")
        )
    }
}

fn recording_error(reason: &'static str, message: &'static str) -> SatelleError {
    let mut error = SatelleError::config_error(message, None);
    error
        .details
        .insert("recording_reason".to_string(), json!(reason));
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_recording_redacts_before_writing_manifested_artifact() {
        use satelle_core::{EventSource, EventType, SatelleEventBody};

        let state = crate::test_support::TestStateDir::new().unwrap();
        let session_id = SessionId::new();
        let turn_id = TurnId::new();
        let capture = RecordingCapture::begin(
            state.path(),
            &RecordingRequest::new(RecordingMode::Events, 60_000, "remote-demo"),
            session_id.clone(),
            turn_id.clone(),
            "private prompt",
            OffsetDateTime::now_utc(),
        )
        .unwrap();
        capture.start().unwrap();
        capture.add_known_secret("private-token");
        let event = SatelleEventBody::new(
            EventType::TurnProgress,
            EventSource::CodexAdapter,
            OffsetDateTime::now_utc(),
            "remote-demo",
            Some(satelle_core::EventSubject::TurnIdentity {
                session_id,
                turn_id,
            }),
            "progress",
            json!({"authorization": "private-token"}),
        )
        .unwrap()
        .with_seq(1)
        .unwrap();

        let manifest = capture.finish(&[event]).unwrap();
        assert_eq!(manifest.artifacts.len(), 1);
        assert!(Path::new(&manifest.manifest_path).is_file());
        let event_bytes = fs::read(&manifest.artifacts[0].path).unwrap();
        assert!(
            !event_bytes
                .windows(13)
                .any(|bytes| bytes == b"private-token")
        );
        assert_eq!(
            manifest.expires_at,
            format_timestamp(capture.expires_at().unwrap())
        );
    }

    #[test]
    fn motion_png_avi_has_one_indexed_png_frame() {
        let state = crate::test_support::TestStateDir::new().unwrap();
        let frame = state.path().join("frame.png");
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&2_u32.to_be_bytes());
        png.extend_from_slice(&3_u32.to_be_bytes());
        png.extend_from_slice(b"test-frame-body");
        write_private_new(&frame, &png).unwrap();
        let video = state.path().join("video.avi");
        write_mpng_avi(&video, &[frame]).unwrap();
        let bytes = fs::read(video).unwrap();
        assert_eq!(&bytes[..4], b"RIFF");
        assert!(bytes.windows(4).any(|window| window == b"MPNG"));
        assert!(bytes.windows(4).any(|window| window == b"idx1"));
    }
}
