use super::super::{StorageError, StorageErrorKind};
use rusqlite::ffi;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};

const PINNED_PATH_PREFIX: &[u8] = b"/.satelle-fd/";

static REGISTERED_DIRECTORIES: OnceLock<Mutex<BTreeMap<RawFd, RegisteredDirectory>>> =
    OnceLock::new();

type OpenCallback = unsafe extern "C" fn(
    *mut ffi::sqlite3_vfs,
    ffi::sqlite3_filename,
    *mut ffi::sqlite3_file,
    c_int,
    *mut c_int,
) -> c_int;

pub(in crate::storage::open) struct DirectoryRegistration {
    directory_fd: RawFd,
}

impl Drop for DirectoryRegistration {
    fn drop(&mut self) {
        let mut registry = registered_directories()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.remove(&self.directory_fd);
    }
}

pub(in crate::storage::open) fn register_directory(
    directory: &File,
) -> Result<DirectoryRegistration, StorageError> {
    let directory_fd = directory.as_raw_fd();
    let retained_directory = directory
        .try_clone()
        .map_err(|_| StorageError::new(StorageErrorKind::OpenFailed))?;
    let mut registry = registered_directories()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match registry.entry(directory_fd) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(RegisteredDirectory {
                directory: Arc::new(retained_directory),
                files: Vec::new(),
            });
        }
        std::collections::btree_map::Entry::Occupied(_) => {
            return Err(StorageError::new(StorageErrorKind::OpenFailed));
        }
    }
    Ok(DirectoryRegistration { directory_fd })
}

pub(super) fn is_pinned_path(path: &[u8]) -> bool {
    pinned_path(path).is_some()
}

pub(super) unsafe fn open_pinned(
    delegate: *mut ffi::sqlite3_vfs,
    callback: OpenCallback,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    output_flags: *mut c_int,
) -> Option<c_int> {
    if name.is_null() {
        return None;
    }
    // SAFETY: SQLite supplies xOpen with a NUL-terminated filename.
    let path = unsafe { CStr::from_ptr(name) }.to_bytes();
    let Some((directory_fd, leaf)) = pinned_path(path) else {
        return path
            .starts_with(PINNED_PATH_PREFIX)
            .then_some(ffi::SQLITE_CANTOPEN);
    };
    let opened = match open_pinned_file(directory_fd, leaf, flags) {
        Ok(opened) => opened,
        Err(code) => return Some(code),
    };
    let stable_path = stable_descriptor_path(&opened);
    let delegated_flags = flags & !ffi::SQLITE_OPEN_EXCLUSIVE;
    // SAFETY: stable_path is double-NUL terminated. On success, both it and
    // opened move into the directory registry and outlive sqlite3_file.
    let code = unsafe {
        callback(
            delegate,
            stable_path.as_ptr().cast(),
            file,
            delegated_flags,
            output_flags,
        )
    };
    if code != ffi::SQLITE_OK {
        return Some(code);
    }
    if let Err((_opened, _stable_path)) = retain_file(directory_fd, opened, stable_path) {
        // SAFETY: The successful callback initialized this file, while both
        // retained allocations remain alive through the close call.
        unsafe { close_delegated_file(file) };
        return Some(ffi::SQLITE_IOERR);
    }
    if !output_flags.is_null() {
        // SAFETY: SQLite supplied writable output storage. Restore the
        // exclusive-create fact already enforced by openat.
        unsafe { *output_flags |= flags & ffi::SQLITE_OPEN_EXCLUSIVE };
    }
    Some(ffi::SQLITE_OK)
}

pub(super) unsafe fn delete_pinned(name: *const c_char, sync_directory: c_int) -> Option<c_int> {
    if name.is_null() {
        return None;
    }
    // SAFETY: SQLite supplies xDelete with a NUL-terminated filename.
    let path = unsafe { CStr::from_ptr(name) }.to_bytes();
    let Some((directory_fd, leaf)) = pinned_path(path) else {
        return path
            .starts_with(PINNED_PATH_PREFIX)
            .then_some(ffi::SQLITE_IOERR_DELETE);
    };
    Some(delete_pinned_file(directory_fd, leaf, sync_directory))
}

pub(super) unsafe fn access_pinned(
    name: *const c_char,
    flags: c_int,
    output: *mut c_int,
) -> Option<c_int> {
    if name.is_null() {
        return None;
    }
    // SAFETY: SQLite supplies xAccess with a NUL-terminated filename.
    let path = unsafe { CStr::from_ptr(name) }.to_bytes();
    let Some((directory_fd, leaf)) = pinned_path(path) else {
        return path
            .starts_with(PINNED_PATH_PREFIX)
            .then_some(ffi::SQLITE_IOERR_ACCESS);
    };
    if output.is_null() {
        return Some(ffi::SQLITE_IOERR_ACCESS);
    }
    let metadata = match pinned_metadata(directory_fd, leaf) {
        Ok(metadata) => metadata,
        Err(code) => return Some(code),
    };
    let accessible = match metadata {
        None => false,
        Some(metadata)
            if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
                || metadata.st_uid != rustix::process::geteuid().as_raw()
                || metadata.st_nlink != 1 =>
        {
            return Some(ffi::SQLITE_IOERR_ACCESS);
        }
        Some(metadata) if flags == ffi::SQLITE_ACCESS_EXISTS => metadata.st_size > 0,
        Some(metadata) if flags == ffi::SQLITE_ACCESS_READWRITE => {
            let mode = Mode::from_raw_mode(metadata.st_mode);
            mode.contains(Mode::RUSR | Mode::WUSR)
        }
        Some(_) => return Some(ffi::SQLITE_IOERR_ACCESS),
    };
    // SAFETY: The null check above proves SQLite supplied writable storage.
    unsafe { *output = c_int::from(accessible) };
    Some(ffi::SQLITE_OK)
}

struct RetainedFile {
    _file: OwnedFd,
    _path: Box<[u8]>,
}

struct RegisteredDirectory {
    directory: Arc<File>,
    files: Vec<RetainedFile>,
}

fn registered_directories() -> &'static Mutex<BTreeMap<RawFd, RegisteredDirectory>> {
    REGISTERED_DIRECTORIES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn pinned_path(path: &[u8]) -> Option<(RawFd, &[u8])> {
    let relative = path.strip_prefix(PINNED_PATH_PREFIX)?;
    let separator = relative.iter().position(|byte| *byte == b'/')?;
    let descriptor = std::str::from_utf8(&relative[..separator])
        .ok()?
        .parse::<RawFd>()
        .ok()?;
    let leaf = &relative[separator + 1..];
    (descriptor >= 0 && super::is_protected_leaf(leaf)).then_some((descriptor, leaf))
}

fn registered_directory(directory_fd: RawFd) -> Option<Arc<File>> {
    registered_directories()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&directory_fd)
        .map(|registration| Arc::clone(&registration.directory))
}

fn retain_file(
    directory_fd: RawFd,
    file: OwnedFd,
    path: Box<[u8]>,
) -> Result<(), (OwnedFd, Box<[u8]>)> {
    let mut registry = registered_directories()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(registration) = registry.get_mut(&directory_fd) else {
        return Err((file, path));
    };
    registration.files.push(RetainedFile {
        _file: file,
        _path: path,
    });
    Ok(())
}

fn open_pinned_file(
    directory_fd: RawFd,
    leaf: &[u8],
    sqlite_flags: c_int,
) -> Result<OwnedFd, c_int> {
    let Some(directory) = registered_directory(directory_fd) else {
        return Err(ffi::SQLITE_CANTOPEN);
    };
    if sqlite_flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0 {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    let leaf = CString::new(leaf).map_err(|_| ffi::SQLITE_CANTOPEN)?;
    let mut flags = OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if sqlite_flags & ffi::SQLITE_OPEN_READWRITE != 0 {
        flags |= OFlags::RDWR;
    } else if sqlite_flags & ffi::SQLITE_OPEN_READONLY != 0 {
        flags |= OFlags::RDONLY;
    } else {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    if sqlite_flags & ffi::SQLITE_OPEN_CREATE != 0 {
        flags |= OFlags::CREATE;
    }
    if sqlite_flags & ffi::SQLITE_OPEN_EXCLUSIVE != 0 {
        flags |= OFlags::EXCL;
    }

    // The callback's Arc pins a cloned directory descriptor even if the
    // registration is concurrently removed while this operation is running.
    let file = rustix::fs::openat(
        directory.as_ref(),
        leaf.as_c_str(),
        flags,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| ffi::SQLITE_CANTOPEN)?;
    let metadata = rustix::fs::fstat(&file).map_err(|_| ffi::SQLITE_IOERR_FSTAT)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
    {
        return Err(ffi::SQLITE_CANTOPEN);
    }
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| ffi::SQLITE_IOERR_ACCESS)?;
    if sqlite_flags & ffi::SQLITE_OPEN_CREATE != 0 {
        rustix::fs::fsync(directory.as_ref()).map_err(|_| ffi::SQLITE_IOERR_DIR_FSYNC)?;
    }
    Ok(file)
}

fn stable_descriptor_path(file: &OwnedFd) -> Box<[u8]> {
    let mut path = format!("/dev/fd/{}", file.as_raw_fd()).into_bytes();
    // unixOpen requires database names to be double-NUL terminated when the
    // URI flag is absent, and retains this pointer until delegated xClose.
    path.extend_from_slice(&[0, 0]);
    path.into_boxed_slice()
}

unsafe fn close_delegated_file(file: *mut ffi::sqlite3_file) {
    if file.is_null() {
        return;
    }
    // SAFETY: A successful delegated xOpen initializes pMethods and transfers
    // one live sqlite3_file to the caller.
    let methods = unsafe { (*file).pMethods };
    if methods.is_null() {
        return;
    }
    // SAFETY: pMethods belongs to the delegated unix-excl implementation.
    if let Some(close) = unsafe { (*methods).xClose } {
        let _ = unsafe { close(file) };
    }
}

fn pinned_metadata(directory_fd: RawFd, leaf: &[u8]) -> Result<Option<rustix::fs::Stat>, c_int> {
    let Some(directory) = registered_directory(directory_fd) else {
        return Err(ffi::SQLITE_IOERR_ACCESS);
    };
    let leaf = CString::new(leaf).map_err(|_| ffi::SQLITE_IOERR_ACCESS)?;
    match rustix::fs::statat(
        directory.as_ref(),
        leaf.as_c_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(ffi::SQLITE_IOERR_ACCESS),
    }
}

fn delete_pinned_file(directory_fd: RawFd, leaf: &[u8], sync_directory: c_int) -> c_int {
    let Some(directory) = registered_directory(directory_fd) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    let Ok(leaf) = CString::new(leaf) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    match rustix::fs::unlinkat(directory.as_ref(), leaf.as_c_str(), AtFlags::empty()) {
        Ok(()) => {}
        Err(rustix::io::Errno::NOENT) => return ffi::SQLITE_IOERR_DELETE_NOENT,
        Err(_) => return ffi::SQLITE_IOERR_DELETE,
    }
    if sync_directory & 1 != 0 && rustix::fs::fsync(directory.as_ref()).is_err() {
        return ffi::SQLITE_IOERR_DIR_FSYNC;
    }
    ffi::SQLITE_OK
}
