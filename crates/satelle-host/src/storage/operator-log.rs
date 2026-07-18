use crate::{DaemonLogEntry, LogSubject};
use satelle_core::{
    OwnerOnlyDirectory, open_or_create_owner_only_directory, open_or_create_owner_only_file,
};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;

const OPERATOR_LOG_FILE_NAME: &str = "satelle-host.log";
const DEFAULT_ROTATION_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_RETAINED_FILES: usize = 5;

/// File policy after another layer has resolved the OS-native log root.
///
/// Path precedence deliberately does not live here. Host construction owns
/// path resolution and injects its one canonical result into this sink.
pub(crate) struct OperatorLogPolicy {
    root: PathBuf,
    rotation_bytes: u64,
    retained_files: usize,
}

impl OperatorLogPolicy {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root,
            rotation_bytes: DEFAULT_ROTATION_BYTES,
            retained_files: DEFAULT_RETAINED_FILES,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: PathBuf, rotation_bytes: u64, retained_files: usize) -> Self {
        assert!(rotation_bytes > 0);
        assert!(retained_files > 0);
        Self {
            root,
            rotation_bytes,
            retained_files,
        }
    }

    #[cfg(test)]
    pub(crate) const fn rotation_bytes_for_test(&self) -> u64 {
        self.rotation_bytes
    }

    #[cfg(test)]
    pub(crate) const fn retained_files_for_test(&self) -> usize {
        self.retained_files
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperatorLogFailureKind {
    BoundaryUnavailable,
    FormatFailed,
    RotationFailed,
    WriteFailed,
}

#[derive(Debug)]
pub(crate) enum OperatorLogWriteOutcome {
    Written,
    Failure(OperatorLogFailureKind),
    FailureCoalesced,
}

impl OperatorLogWriteOutcome {
    pub(crate) fn failure_kind(&self) -> Option<OperatorLogFailureKind> {
        match self {
            Self::Failure(kind) => Some(*kind),
            Self::Written | Self::FailureCoalesced => None,
        }
    }
}

/// A write-only, best-effort mirror of committed SQLite log records.
///
/// The sink intentionally exposes no read API. The authoritative log query
/// path remains SQLite through the Host Daemon API.
pub(crate) struct OperatorLogSink {
    policy: OperatorLogPolicy,
    // The write handle must close before its pinned directory boundary.
    file: Option<File>,
    directory: Option<OwnerOnlyDirectory>,
    failure_active: bool,
}

impl OperatorLogSink {
    pub(crate) fn new(policy: OperatorLogPolicy) -> Self {
        Self {
            policy,
            file: None,
            directory: None,
            failure_active: false,
        }
    }

    /// Mirrors the authoritative entry loaded after its SQLite commit.
    /// A sink failure is returned as data and must never become a recursive log
    /// entry or change the authoritative commit result.
    pub(crate) fn write_committed(&mut self, entry: &DaemonLogEntry) -> OperatorLogWriteOutcome {
        match self.try_write_committed(entry) {
            Ok(()) => {
                self.failure_active = false;
                OperatorLogWriteOutcome::Written
            }
            Err(kind) => {
                // Reopen from the pinned owner-only boundary on the next
                // record. Only the first failure in one uninterrupted outage
                // is surfaced for conversion into the existing Doctor model.
                self.file = None;
                if self.failure_active {
                    OperatorLogWriteOutcome::FailureCoalesced
                } else {
                    self.failure_active = true;
                    OperatorLogWriteOutcome::Failure(kind)
                }
            }
        }
    }

    fn try_write_committed(
        &mut self,
        entry: &DaemonLogEntry,
    ) -> Result<(), OperatorLogFailureKind> {
        let line = format_entry(entry)?;
        self.ensure_open()?;

        let current_bytes = self
            .file
            .as_ref()
            .expect("ensure_open establishes the write handle")
            .metadata()
            .map_err(|_| OperatorLogFailureKind::WriteFailed)?
            .len();
        if current_bytes > 0
            && current_bytes.saturating_add(line.len() as u64) > self.policy.rotation_bytes
        {
            self.rotate()?;
        }

        self.file
            .as_mut()
            .expect("ensure_open establishes the write handle")
            .write_all(line.as_bytes())
            .map_err(|_| OperatorLogFailureKind::WriteFailed)
    }

    fn ensure_open(&mut self) -> Result<(), OperatorLogFailureKind> {
        if self.directory.is_none() {
            self.directory = Some(
                open_or_create_owner_only_directory(&self.policy.root)
                    .map_err(|_| OperatorLogFailureKind::BoundaryUnavailable)?,
            );
        }
        if self.file.is_none() {
            let mut file = open_or_create_owner_only_file(&self.current_path())
                .map_err(|_| OperatorLogFailureKind::BoundaryUnavailable)?;
            file.seek(SeekFrom::End(0))
                .map_err(|_| OperatorLogFailureKind::WriteFailed)?;
            self.file = Some(file);
        }
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), OperatorLogFailureKind> {
        self.file = None;
        let rotate = || -> std::io::Result<()> {
            if self.policy.retained_files == 1 {
                remove_if_present(&self.current_path())?;
                return Ok(());
            }

            remove_if_present(&self.rotated_path(self.policy.retained_files - 1))?;
            for generation in (1..self.policy.retained_files).rev() {
                let source = if generation == 1 {
                    self.current_path()
                } else {
                    self.rotated_path(generation - 1)
                };
                rename_if_present(&source, &self.rotated_path(generation))?;
            }
            Ok(())
        };
        rotate().map_err(|_| OperatorLogFailureKind::RotationFailed)?;
        self.ensure_open()
    }

    fn current_path(&self) -> PathBuf {
        self.policy.root.join(OPERATOR_LOG_FILE_NAME)
    }

    fn rotated_path(&self, generation: usize) -> PathBuf {
        self.policy
            .root
            .join(format!("{OPERATOR_LOG_FILE_NAME}.{generation}"))
    }

    #[cfg(test)]
    pub(crate) fn release_handles_for_test(&mut self) {
        self.file = None;
        self.directory = None;
    }
}

fn format_entry(entry: &DaemonLogEntry) -> Result<String, OperatorLogFailureKind> {
    let timestamp = entry
        .timestamp()
        .format(&Rfc3339)
        .map_err(|_| OperatorLogFailureKind::FormatFailed)?;
    let subject = match entry.subject() {
        LogSubject::Host => "subject=host".to_string(),
        LogSubject::Turn {
            session_id,
            turn_id,
            session_state_revision,
            turn_state_revision,
        } => format!(
            "subject=turn session={} turn={} session_revision={} turn_revision={}",
            session_id.as_str(),
            turn_id.as_str(),
            session_state_revision,
            turn_state_revision,
        ),
    };
    Ok(format!(
        "{timestamp} level={} source={} event={} {subject} cursor={} message=\"{}\"\n",
        entry.severity().as_str(),
        entry.source().as_str(),
        entry.event().as_str(),
        entry.cursor(),
        entry.event().message(),
    ))
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn rename_if_present(source: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::rename(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
