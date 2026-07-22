use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_ATTACHMENTS: usize = 4;
const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 10 * 1024 * 1024;
const MAX_STALE_FILES_PER_START: usize = 1024;
const FILE_PREFIX: &str = "satelle-image-";

#[derive(Clone)]
pub struct AttachmentUpload {
    media_type: String,
    size_bytes: u64,
    sha256: String,
    data_base64: String,
}

impl AttachmentUpload {
    pub fn new(
        media_type: impl Into<String>,
        size_bytes: u64,
        sha256: impl Into<String>,
        data_base64: impl Into<String>,
    ) -> Self {
        Self {
            media_type: media_type.into(),
            size_bytes,
            sha256: sha256.into(),
            data_base64: data_base64.into(),
        }
    }
}

impl fmt::Debug for AttachmentUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachmentUpload")
            .field("media_type", &self.media_type)
            .field("size_bytes", &self.size_bytes)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct VerifiedImageAttachment {
    media_type: &'static str,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl fmt::Debug for VerifiedImageAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedImageAttachment")
            .field("media_type", &self.media_type)
            .field("size_bytes", &self.bytes.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

pub(crate) fn verify_uploads(
    uploads: Vec<AttachmentUpload>,
) -> Result<Vec<VerifiedImageAttachment>, ()> {
    if uploads.len() > MAX_ATTACHMENTS {
        return Err(());
    }
    let mut total = 0_usize;
    uploads
        .into_iter()
        .map(|upload| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(upload.data_base64.as_bytes())
                .map_err(|_| ())?;
            if bytes.len() > MAX_ATTACHMENT_BYTES
                || u64::try_from(bytes.len()).map_err(|_| ())? != upload.size_bytes
            {
                return Err(());
            }
            total = total.checked_add(bytes.len()).ok_or(())?;
            if total > MAX_TOTAL_BYTES {
                return Err(());
            }
            let media_type = sniff_media_type(&bytes).ok_or(())?;
            if media_type != upload.media_type {
                return Err(());
            }
            let digest = Sha256::digest(&bytes);
            if !constant_time_hex_eq(&upload.sha256, digest.as_slice()) {
                return Err(());
            }
            Ok(VerifiedImageAttachment {
                media_type,
                bytes,
                sha256: digest.into(),
            })
        })
        .collect()
}

impl VerifiedImageAttachment {
    pub(crate) const fn media_type(&self) -> &'static str {
        self.media_type
    }

    pub(crate) fn size_bytes(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn sniff_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

fn constant_time_hex_eq(declared: &str, actual: &[u8]) -> bool {
    if declared.len() != actual.len() * 2 || !declared.is_ascii() {
        return false;
    }
    let expected = actual.iter().flat_map(|byte| {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]]
    });
    declared
        .bytes()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(crate) struct AttachmentStore {
    root: PathBuf,
    next_name: AtomicU64,
}

impl AttachmentStore {
    pub(crate) fn open(root: PathBuf) -> Result<Self, satelle_core::SatelleError> {
        satelle_core::open_or_create_owner_only_directory(&root)
            .map_err(|_| attachment_failure("attachment staging is unavailable"))?;
        cleanup_stale_files(&root)?;
        Ok(Self {
            root,
            next_name: AtomicU64::new(1),
        })
    }

    pub(crate) fn stage(
        &self,
        attachments: Vec<VerifiedImageAttachment>,
    ) -> Result<StagedAttachments, satelle_core::SatelleError> {
        let transaction = self.next_name.fetch_add(1, Ordering::Relaxed);
        let mut images = Vec::with_capacity(attachments.len());
        for (index, attachment) in attachments.into_iter().enumerate() {
            let extension = extension_for(attachment.media_type);
            let path = self.root.join(format!(
                "{FILE_PREFIX}{}-{transaction}-{index}.{extension}",
                std::process::id()
            ));
            let mut file = match satelle_core::open_new_owner_only_file(&path) {
                Ok(file) => file,
                Err(_) => {
                    cleanup_paths(&images);
                    return Err(attachment_failure("attachment staging failed"));
                }
            };
            let persisted = file
                .write_all(&attachment.bytes)
                .and_then(|()| file.sync_all());
            drop(file);
            if persisted.is_err() {
                images.push(StagedImage {
                    path,
                    media_type: attachment.media_type,
                    bytes: attachment.bytes,
                });
                cleanup_paths(&images);
                return Err(attachment_failure("attachment staging failed"));
            }
            images.push(StagedImage {
                path,
                media_type: attachment.media_type,
                bytes: attachment.bytes,
            });
        }
        Ok(StagedAttachments { images })
    }
}

fn cleanup_stale_files(root: &Path) -> Result<(), satelle_core::SatelleError> {
    let mut processed = 0_usize;
    for entry in fs::read_dir(root).map_err(|_| attachment_failure("attachment cleanup failed"))? {
        let entry = entry.map_err(|_| attachment_failure("attachment cleanup failed"))?;
        processed += 1;
        if processed > MAX_STALE_FILES_PER_START {
            return Err(attachment_failure("attachment cleanup is incomplete"));
        }
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| attachment_failure("attachment cleanup failed"))?;
        if !name.to_string_lossy().starts_with(FILE_PREFIX) || !metadata.file_type().is_file() {
            return Err(attachment_failure(
                "attachment staging contains an unsafe entry",
            ));
        }
        fs::remove_file(entry.path())
            .map_err(|_| attachment_failure("attachment cleanup failed"))?;
    }
    Ok(())
}

fn extension_for(media_type: &str) -> &'static str {
    match media_type {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        _ => unreachable!("verified media type"),
    }
}

fn attachment_failure(message: &'static str) -> satelle_core::SatelleError {
    satelle_core::SatelleError::invalid_usage(message)
}

pub(crate) struct StagedImage {
    path: PathBuf,
    media_type: &'static str,
    bytes: Vec<u8>,
}

impl StagedImage {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn media_type(&self) -> &'static str {
        self.media_type
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf, media_type: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            path,
            media_type,
            bytes,
        }
    }
}

#[derive(Default)]
pub(crate) struct StagedAttachments {
    images: Vec<StagedImage>,
}

impl StagedAttachments {
    pub(crate) fn images(&self) -> &[StagedImage] {
        &self.images
    }
}

impl Drop for StagedAttachments {
    fn drop(&mut self) {
        let failed = self
            .images
            .iter()
            .filter(|image| fs::remove_file(&image.path).is_err())
            .count();
        if failed != 0 {
            tracing::warn!(
                attachment_count = self.images.len(),
                "attachment cleanup failed"
            );
        }
    }
}

fn cleanup_paths(images: &[StagedImage]) {
    let failed = images
        .iter()
        .filter(|image| fs::remove_file(&image.path).is_err())
        .count();
    if failed != 0 {
        tracing::warn!(attachment_count = images.len(), "attachment cleanup failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn upload(bytes: &[u8], media_type: &str, digest: Option<String>) -> AttachmentUpload {
        AttachmentUpload::new(
            media_type,
            bytes.len() as u64,
            digest.unwrap_or_else(|| {
                Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            }),
            base64::engine::general_purpose::STANDARD.encode(bytes),
        )
    }

    #[test]
    fn verification_rejects_declared_integrity_and_media_mismatches() {
        let png = b"\x89PNG\r\n\x1a\nfixture";
        assert!(verify_uploads(vec![upload(png, "image/jpeg", None)]).is_err());
        assert!(verify_uploads(vec![upload(png, "image/png", Some("00".repeat(32)))]).is_err());
    }

    #[test]
    fn staging_uses_generated_private_names_and_drop_deletes_files() {
        let state = tempfile::tempdir().expect("state directory");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = state.path().join("attachments");
        let store = AttachmentStore::open(root.clone()).expect("attachment store");
        let verified = verify_uploads(vec![upload(b"\x89PNG\r\n\x1a\nfixture", "image/png", None)])
            .expect("verified image");
        let staged = store.stage(verified).expect("stage image");
        let path = staged.images()[0].path().to_path_buf();
        assert!(path.starts_with(&root));
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(FILE_PREFIX)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(staged);
        assert!(!path.exists());
    }

    #[test]
    fn startup_cleanup_removes_only_generated_staging_files() {
        let state = tempfile::tempdir().expect("state directory");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = state.path().join("attachments");
        satelle_core::open_or_create_owner_only_directory(&root).unwrap();
        let stale = root.join(format!("{FILE_PREFIX}stale.png"));
        satelle_core::open_new_owner_only_file(&stale).unwrap();
        AttachmentStore::open(root.clone()).expect("cleanup stale staging");
        assert!(!stale.exists());
    }

    fn private_staging_root() -> (tempfile::TempDir, PathBuf) {
        let state = tempfile::tempdir().expect("state directory");
        #[cfg(unix)]
        fs::set_permissions(
            state.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let root = state.path().join("attachments");
        satelle_core::open_or_create_owner_only_directory(&root).unwrap();
        (state, root)
    }

    fn populate_stale_files(root: &Path, count: usize) {
        for index in 0..count {
            let path = root.join(format!("{FILE_PREFIX}bound-{index}.png"));
            drop(satelle_core::open_new_owner_only_file(&path).unwrap());
        }
    }

    #[test]
    fn startup_cleanup_accepts_exactly_the_1024_file_budget() {
        let (_state, root) = private_staging_root();
        populate_stale_files(&root, MAX_STALE_FILES_PER_START);

        AttachmentStore::open(root.clone()).expect("clean the exact startup budget");

        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn startup_cleanup_rejects_the_1025th_file_and_leaves_the_residual() {
        let (_state, root) = private_staging_root();
        populate_stale_files(&root, MAX_STALE_FILES_PER_START + 1);

        let error = match AttachmentStore::open(root.clone()) {
            Ok(_) => panic!("accepting excess stale files violates the startup bound"),
            Err(error) => error,
        };

        assert_eq!(error.message, "attachment cleanup is incomplete");
        assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    }

    struct CleanupCapture {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for CleanupCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = CleanupVisitor(String::new());
            event.record(&mut visitor);
            self.events.lock().unwrap().push(visitor.0);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    struct CleanupVisitor(String);

    impl tracing::field::Visit for CleanupVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?};", field.name());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value};", field.name());
        }
    }

    #[test]
    fn cleanup_failures_emit_only_a_static_message_and_count() {
        let state = tempfile::tempdir().expect("state directory");
        let path = state.path().join("PRIVATE_ATTACHMENT_PATH_CANARY");
        let events = Arc::new(Mutex::new(Vec::new()));
        let dispatch = tracing::Dispatch::new(CleanupCapture {
            events: Arc::clone(&events),
        });
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let images = vec![StagedImage::for_test(
            path,
            "image/png",
            b"PRIVATE_ATTACHMENT_BYTES_CANARY".to_vec(),
        )];

        cleanup_paths(&images);
        drop(StagedAttachments { images });

        let captured = events.lock().unwrap().join("\n");
        assert_eq!(captured.matches("attachment cleanup failed").count(), 2);
        assert_eq!(captured.matches("attachment_count=1").count(), 2);
        assert!(!captured.contains("PRIVATE_ATTACHMENT_PATH_CANARY"));
        assert!(!captured.contains("PRIVATE_ATTACHMENT_BYTES_CANARY"));
    }
}
