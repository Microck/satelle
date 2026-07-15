use super::{StorageError, StorageErrorKind};
use rusqlite::ffi;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fmt;
use std::ptr;
use std::sync::OnceLock;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(super) use macos::{DirectoryRegistration, register_directory};

const VFS_NAME: &CStr = c"satelle-unix-excl";
const DELEGATE_NAME: &CStr = c"unix-excl";
#[cfg(target_os = "linux")]
const PINNED_PATH_PREFIX: &[u8] = b"/proc/self/fd/";

static REGISTRATION: OnceLock<Result<(), RegistrationFailure>> = OnceLock::new();

/// Registers the descriptor-anchored VFS once and returns its stable name.
///
/// The caller must supply SQLite with a validated directory descriptor and
/// leaf. Linux uses `/proc/self/fd/<directory-fd>/<leaf>`. macOS uses an
/// internal `/.satelle-fd/<directory-fd>/<leaf>` name whose VFS callbacks
/// resolve the leaf with `openat`. The custom `xFullPathname` preserves the
/// anchor instead of resolving it to a replaceable path.
pub(super) fn name() -> Result<&'static CStr, StorageError> {
    match REGISTRATION.get_or_init(register) {
        Ok(()) => Ok(VFS_NAME),
        Err(failure) => Err(StorageError::with_source(
            StorageErrorKind::OpenFailed,
            *failure,
        )),
    }
}

#[derive(Clone, Copy, Debug)]
enum RegistrationFailure {
    Initialize(c_int),
    DelegateUnavailable,
    InvalidDelegate(&'static str),
    NameInUse,
    Register(c_int),
}

impl fmt::Display for RegistrationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialize(code) => {
                write!(formatter, "SQLite initialization failed with code {code}")
            }
            Self::DelegateUnavailable => {
                formatter.write_str("SQLite's unix-excl VFS is unavailable")
            }
            Self::InvalidDelegate(reason) => {
                write!(formatter, "SQLite's unix-excl VFS is invalid: {reason}")
            }
            Self::NameInUse => {
                formatter.write_str("the Satelle SQLite VFS name is already registered")
            }
            Self::Register(code) => {
                write!(formatter, "SQLite VFS registration failed with code {code}")
            }
        }
    }
}

impl std::error::Error for RegistrationFailure {}

fn register() -> Result<(), RegistrationFailure> {
    // SAFETY: SQLite documents sqlite3_initialize as process-global and
    // thread-safe. OnceLock additionally serializes this registration path.
    let initialize_code = unsafe { ffi::sqlite3_initialize() };
    if initialize_code != ffi::SQLITE_OK {
        return Err(RegistrationFailure::Initialize(initialize_code));
    }

    // SAFETY: Both names are static NUL-terminated strings. SQLite owns all
    // pointers returned by sqlite3_vfs_find for the process lifetime.
    let name_collision = unsafe { ffi::sqlite3_vfs_find(VFS_NAME.as_ptr()) };
    if !name_collision.is_null() {
        return Err(RegistrationFailure::NameInUse);
    }
    // SAFETY: DELEGATE_NAME is a static NUL-terminated string.
    let delegate = unsafe { ffi::sqlite3_vfs_find(DELEGATE_NAME.as_ptr()) };
    if delegate.is_null() {
        return Err(RegistrationFailure::DelegateUnavailable);
    }

    // SAFETY: sqlite3_vfs_find returned a live SQLite-owned VFS. Copying the
    // value snapshots its immutable callback table; pNext is intentionally
    // ignored because only SQLite may use it.
    let template = unsafe { delegate.read() };
    validate_delegate(&template)?;

    let wrapper = Box::new(ffi::sqlite3_vfs {
        iVersion: template.iVersion,
        szOsFile: template.szOsFile,
        mxPathname: template.mxPathname,
        pNext: ptr::null_mut(),
        zName: VFS_NAME.as_ptr(),
        pAppData: delegate.cast(),
        xOpen: Some(forward_open),
        xDelete: Some(forward_delete),
        xAccess: Some(forward_access),
        xFullPathname: Some(preserve_full_pathname),
        xDlOpen: template.xDlOpen.map(|_| forward_dl_open as _),
        xDlError: template.xDlError.map(|_| forward_dl_error as _),
        xDlSym: template.xDlSym.map(|_| forward_dl_sym as _),
        xDlClose: template.xDlClose.map(|_| forward_dl_close as _),
        xRandomness: Some(forward_randomness),
        xSleep: Some(forward_sleep),
        xCurrentTime: Some(forward_current_time),
        xGetLastError: template.xGetLastError.map(|_| forward_get_last_error as _),
        xCurrentTimeInt64: (template.iVersion >= 2)
            .then_some(template.xCurrentTimeInt64)
            .flatten()
            .map(|_| forward_current_time_int64 as _),
        xSetSystemCall: (template.iVersion >= 3)
            .then_some(template.xSetSystemCall)
            .flatten()
            .map(|_| forward_set_system_call as _),
        xGetSystemCall: (template.iVersion >= 3)
            .then_some(template.xGetSystemCall)
            .flatten()
            .map(|_| forward_get_system_call as _),
        xNextSystemCall: (template.iVersion >= 3)
            .then_some(template.xNextSystemCall)
            .flatten()
            .map(|_| forward_next_system_call as _),
    });
    let wrapper = Box::into_raw(wrapper);

    // SAFETY: wrapper points to a fully initialized VFS whose name, app data,
    // callback functions, and delegated VFS all have process lifetime. It is
    // not made the default VFS.
    let registration_code = unsafe { ffi::sqlite3_vfs_register(wrapper, 0) };
    if registration_code != ffi::SQLITE_OK {
        // SAFETY: Registration failed, so SQLite did not retain this VFS and
        // ownership remains with this function.
        unsafe { drop(Box::from_raw(wrapper)) };
        return Err(RegistrationFailure::Register(registration_code));
    }

    // SAFETY: VFS lookup is thread-safe and VFS_NAME is static. A mismatched
    // pointer means another component registered the same name concurrently;
    // using whichever implementation happens to win would not fail closed.
    let selected = unsafe { ffi::sqlite3_vfs_find(VFS_NAME.as_ptr()) };
    if selected != wrapper {
        // SAFETY: wrapper was registered successfully above. Unregistering it
        // removes only this pointer, even if a different VFS reused its name.
        let _ = unsafe { ffi::sqlite3_vfs_unregister(wrapper) };
        // Do not reclaim a successfully registered VFS. Another thread could
        // have found it during the brief registration window, and SQLite may
        // retain that pointer for the lifetime of an open connection.
        return Err(RegistrationFailure::NameInUse);
    }

    // SQLite requires registered VFS storage to remain valid until it is
    // unregistered. Satelle never unregisters this process-global shim, so
    // the allocation is intentionally retained for the process lifetime.
    Ok(())
}

fn validate_delegate(delegate: &ffi::sqlite3_vfs) -> Result<(), RegistrationFailure> {
    if !(1..=3).contains(&delegate.iVersion) {
        return Err(RegistrationFailure::InvalidDelegate(
            "unsupported sqlite3_vfs version",
        ));
    }
    if delegate.szOsFile <= 0 {
        return Err(RegistrationFailure::InvalidDelegate(
            "non-positive sqlite3_file size",
        ));
    }
    if delegate.mxPathname <= 0 {
        return Err(RegistrationFailure::InvalidDelegate(
            "non-positive maximum pathname length",
        ));
    }
    if delegate.zName.is_null() {
        return Err(RegistrationFailure::InvalidDelegate("missing name"));
    }
    if delegate.xOpen.is_none()
        || delegate.xDelete.is_none()
        || delegate.xAccess.is_none()
        || delegate.xFullPathname.is_none()
        || delegate.xRandomness.is_none()
        || delegate.xSleep.is_none()
        || delegate.xCurrentTime.is_none()
    {
        return Err(RegistrationFailure::InvalidDelegate(
            "missing required version 1 callback",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_pinned_path(path: &[u8]) -> bool {
    let Some(relative) = path.strip_prefix(PINNED_PATH_PREFIX) else {
        return false;
    };
    let Some(separator) = relative.iter().position(|byte| *byte == b'/') else {
        return false;
    };
    let descriptor = &relative[..separator];
    let leaf = &relative[separator + 1..];
    !descriptor.is_empty() && descriptor.iter().all(u8::is_ascii_digit) && is_protected_leaf(leaf)
}

fn is_protected_leaf(leaf: &[u8]) -> bool {
    super::PROTECTED_FILE_NAMES
        .iter()
        .any(|file_name| file_name.as_bytes() == leaf)
        || is_migration_backup_leaf(leaf)
}

fn is_migration_backup_leaf(leaf: &[u8]) -> bool {
    let Ok(file_name) = std::str::from_utf8(leaf) else {
        return false;
    };
    let Some(remainder) = file_name.strip_prefix("satelle.sqlite3.migration-v") else {
        return false;
    };
    let stem = remainder
        .strip_suffix(".backup.json")
        .or_else(|| remainder.strip_suffix(".backup"));
    let Some((schema_version, backup_id)) = stem.and_then(|stem| stem.split_once('-')) else {
        return false;
    };
    !schema_version.is_empty()
        && schema_version.bytes().all(|byte| byte.is_ascii_digit())
        && uuid::Uuid::parse_str(backup_id).is_ok()
}

#[cfg(target_os = "macos")]
fn is_pinned_path(path: &[u8]) -> bool {
    macos::is_pinned_path(path)
}

unsafe fn delegate_from(wrapper: *mut ffi::sqlite3_vfs) -> Option<*mut ffi::sqlite3_vfs> {
    if wrapper.is_null() {
        return None;
    }
    // SAFETY: SQLite invokes a VFS callback with the registered VFS pointer.
    // The null check above makes reading its immutable pAppData field valid.
    let delegate = unsafe { (*wrapper).pAppData.cast::<ffi::sqlite3_vfs>() };
    (!delegate.is_null()).then_some(delegate)
}

unsafe extern "C" fn forward_open(
    wrapper: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    output_flags: *mut c_int,
) -> c_int {
    if file.is_null() {
        return ffi::SQLITE_IOERR;
    }
    // SQLite requires pMethods to be null whenever xOpen reports an error.
    // Initialize it before any wrapper-specific validation can fail.
    unsafe { (*file).pMethods = ptr::null() };
    // Passing the actual unix-excl VFS pointer is essential: unixOpen checks
    // that pointer's zName before enabling UNIXFILE_EXCL and heap WAL-index
    // behavior.
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegate is the process-lifetime VFS found during registration.
    let Some(callback) = (unsafe { (*delegate).xOpen }) else {
        return ffi::SQLITE_IOERR;
    };
    #[cfg(target_os = "macos")]
    // SAFETY: macos validates the callback inputs before handling only its
    // internal pinned-path namespace.
    if let Some(code) =
        unsafe { macos::open_pinned(delegate, callback, name, file, flags, output_flags) }
    {
        return code;
    }
    // SAFETY: SQLite supplied the remaining arguments according to xOpen's
    // callback contract; the delegate callback receives its own VFS pointer.
    unsafe { callback(delegate, name, file, flags, output_flags) }
}

unsafe extern "C" fn forward_delete(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_directory: c_int,
) -> c_int {
    #[cfg(target_os = "macos")]
    // SAFETY: macos validates the callback filename before resolving it.
    if let Some(code) = unsafe { macos::delete_pinned(name, sync_directory) } {
        return code;
    }
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegate was validated during registration.
    let Some(callback) = (unsafe { (*delegate).xDelete }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite supplied a valid xDelete argument set.
    unsafe { callback(delegate, name, sync_directory) }
}

unsafe extern "C" fn forward_access(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    output: *mut c_int,
) -> c_int {
    #[cfg(target_os = "macos")]
    // SAFETY: macos validates the callback filename and output pointer.
    if let Some(code) = unsafe { macos::access_pinned(name, flags, output) } {
        return code;
    }
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegate was validated during registration.
    let Some(callback) = (unsafe { (*delegate).xAccess }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite supplied a valid xAccess argument set.
    unsafe { callback(delegate, name, flags, output) }
}

unsafe extern "C" fn preserve_full_pathname(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    output_length: c_int,
    output: *mut c_char,
) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    };
    if name.is_null() || output.is_null() || output_length <= 0 {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    }
    // SAFETY: delegate is the process-lifetime VFS found during registration.
    let maximum_length = unsafe { (*delegate).mxPathname };
    let Ok(maximum_length) = usize::try_from(maximum_length) else {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    };
    let Ok(output_length) = usize::try_from(output_length) else {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    };

    let Some(scan_length) = maximum_length.checked_add(1) else {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    };
    let mut path_length = 0;
    while path_length < scan_length {
        // SAFETY: SQLite guarantees name is NUL-terminated. The explicit
        // maximum prevents an unbounded scan if that contract is violated.
        let byte = unsafe { name.cast::<u8>().add(path_length).read() };
        if byte == 0 {
            break;
        }
        path_length += 1;
    }
    if path_length == scan_length || path_length + 1 > output_length {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    }

    // SAFETY: The bounded scan found a NUL at path_length, so these bytes are
    // readable as one path. The earlier null check covers the empty slice too.
    let path = unsafe { std::slice::from_raw_parts(name.cast::<u8>(), path_length) };
    if !is_pinned_path(path) {
        return ffi::SQLITE_CANTOPEN_FULLPATH;
    }

    // SAFETY: output has output_length writable bytes by SQLite's callback
    // contract, and the check above proves the path plus NUL fits. SQLite
    // may supply overlapping buffers, so use the overlap-safe copy operation.
    unsafe { ptr::copy(name, output, path_length + 1) };
    ffi::SQLITE_OK
}

unsafe extern "C" fn forward_dl_open(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *mut c_void {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ptr::null_mut();
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xDlOpen }) else {
        return ptr::null_mut();
    };
    // SAFETY: SQLite supplied a valid xDlOpen argument set.
    unsafe { callback(delegate, name) }
}

unsafe extern "C" fn forward_dl_error(
    wrapper: *mut ffi::sqlite3_vfs,
    length: c_int,
    message: *mut c_char,
) {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return;
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xDlError }) else {
        return;
    };
    // SAFETY: SQLite supplied a valid xDlError argument set.
    unsafe { callback(delegate, length, message) };
}

unsafe extern "C" fn forward_dl_sym(
    wrapper: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    symbol: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    let delegate = (unsafe { delegate_from(wrapper) })?;
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let callback = (unsafe { (*delegate).xDlSym })?;
    // SAFETY: SQLite supplied a valid xDlSym argument set.
    unsafe { callback(delegate, handle, symbol) }
}

unsafe extern "C" fn forward_dl_close(wrapper: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return;
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xDlClose }) else {
        return;
    };
    // SAFETY: SQLite supplied a valid xDlClose argument set.
    unsafe { callback(delegate, handle) };
}

unsafe extern "C" fn forward_randomness(
    wrapper: *mut ffi::sqlite3_vfs,
    length: c_int,
    output: *mut c_char,
) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return 0;
    };
    // SAFETY: delegate was validated during registration.
    let Some(callback) = (unsafe { (*delegate).xRandomness }) else {
        return 0;
    };
    // SAFETY: SQLite supplied a valid xRandomness argument set.
    unsafe { callback(delegate, length, output) }
}

unsafe extern "C" fn forward_sleep(wrapper: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return 0;
    };
    // SAFETY: delegate was validated during registration.
    let Some(callback) = (unsafe { (*delegate).xSleep }) else {
        return 0;
    };
    // SAFETY: SQLite supplied a valid xSleep argument set.
    unsafe { callback(delegate, microseconds) }
}

unsafe extern "C" fn forward_current_time(
    wrapper: *mut ffi::sqlite3_vfs,
    output: *mut f64,
) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: delegate was validated during registration.
    let Some(callback) = (unsafe { (*delegate).xCurrentTime }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite supplied a valid xCurrentTime argument set.
    unsafe { callback(delegate, output) }
}

unsafe extern "C" fn forward_get_last_error(
    wrapper: *mut ffi::sqlite3_vfs,
    length: c_int,
    output: *mut c_char,
) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return 0;
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xGetLastError }) else {
        return 0;
    };
    // SAFETY: SQLite supplied a valid xGetLastError argument set.
    unsafe { callback(delegate, length, output) }
}

unsafe extern "C" fn forward_current_time_int64(
    wrapper: *mut ffi::sqlite3_vfs,
    output: *mut ffi::sqlite3_int64,
) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xCurrentTimeInt64 }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: SQLite supplied a valid xCurrentTimeInt64 argument set.
    unsafe { callback(delegate, output) }
}

unsafe extern "C" fn forward_set_system_call(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    function: ffi::sqlite3_syscall_ptr,
) -> c_int {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xSetSystemCall }) else {
        return ffi::SQLITE_NOTFOUND;
    };
    // SAFETY: SQLite supplied a valid xSetSystemCall argument set.
    unsafe { callback(delegate, name, function) }
}

unsafe extern "C" fn forward_get_system_call(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    let delegate = (unsafe { delegate_from(wrapper) })?;
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let callback = (unsafe { (*delegate).xGetSystemCall })?;
    // SAFETY: SQLite supplied a valid xGetSystemCall argument set.
    unsafe { callback(delegate, name) }
}

unsafe extern "C" fn forward_next_system_call(
    wrapper: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *const c_char {
    let Some(delegate) = (unsafe { delegate_from(wrapper) }) else {
        return ptr::null();
    };
    // SAFETY: The wrapper installs this callback only when the delegate has it.
    let Some(callback) = (unsafe { (*delegate).xNextSystemCall }) else {
        return ptr::null();
    };
    // SAFETY: SQLite supplied a valid xNextSystemCall argument set.
    unsafe { callback(delegate, name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;

    #[test]
    fn failed_open_clears_methods() {
        let mut file = ffi::sqlite3_file {
            pMethods: NonNull::<ffi::sqlite3_io_methods>::dangling().as_ptr(),
        };

        // SAFETY: This intentionally supplies a missing wrapper VFS to drive
        // the error path while providing writable sqlite3_file storage.
        let code =
            unsafe { forward_open(ptr::null_mut(), ptr::null(), &mut file, 0, ptr::null_mut()) };

        assert_eq!(ffi::SQLITE_IOERR, code);
        assert!(file.pMethods.is_null());
    }
}
