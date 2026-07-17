use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_SECRET_FILE_BYTES: usize = 1024;
const MAX_CONFIG_FILE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SecureFileError {
    #[error("the file is unavailable or does not satisfy the required owner security policy")]
    UnsafeOrUnavailable,
    #[error("the file exceeds the maximum supported size")]
    TooLarge,
    #[error("the file is not valid UTF-8")]
    NotUtf8,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SecurityPolicy {
    OwnerOnly,
    OwnerPrivate,
    OwnerControlled,
    UserOrAdministratorControlled,
}

pub fn read_owner_only_secret_file(path: &Path) -> Result<Zeroizing<String>, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerOnly, MAX_SECRET_FILE_BYTES)?;
    let value = std::str::from_utf8(bytes.as_slice()).map_err(|_| SecureFileError::NotUtf8)?;
    Ok(Zeroizing::new(value.trim_ascii().to_string()))
}

/// Reads larger secret configuration material such as a PEM private key while
/// retaining the regular-file, ownership, link, and ACL requirements of
/// ordinary token files and allowing owner-read-only key material.
pub fn read_owner_only_secret_config_file(
    path: &Path,
) -> Result<Zeroizing<String>, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerPrivate, MAX_CONFIG_FILE_BYTES)?;
    let value = std::str::from_utf8(bytes.as_slice()).map_err(|_| SecureFileError::NotUtf8)?;
    Ok(Zeroizing::new(value.to_string()))
}

pub fn read_owner_controlled_config_file(path: &Path) -> Result<String, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerControlled, MAX_CONFIG_FILE_BYTES)?;
    std::str::from_utf8(bytes.as_slice())
        .map(str::to_string)
        .map_err(|_| SecureFileError::NotUtf8)
}

pub fn read_trusted_ca_bundle_file(path: &Path) -> Result<String, SecureFileError> {
    let bytes = read_secure_file(
        path,
        SecurityPolicy::UserOrAdministratorControlled,
        MAX_CONFIG_FILE_BYTES,
    )?;
    std::str::from_utf8(bytes.as_slice())
        .map(str::to_string)
        .map_err(|_| SecureFileError::NotUtf8)
}

/// Creates a regular file with Satelle's owner-only policy, or opens an
/// existing file only when it already satisfies that policy.
#[cfg(unix)]
pub fn open_or_create_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
    use rustix::fs::{FileType, Mode, OFlags};

    require_macos_parent_without_extended_acl(path)?;
    let create_flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (descriptor, created) = match rustix::fs::open(path, create_flags, Mode::RUSR | Mode::WUSR)
    {
        Ok(descriptor) => (descriptor, true),
        Err(rustix::io::Errno::EXIST) => (
            rustix::fs::open(
                path,
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?,
            false,
        ),
        Err(_) => return Err(SecureFileError::UnsafeOrUnavailable),
    };
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || (!created && metadata.st_mode & 0o777 != 0o600)
    {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    require_no_macos_extended_acl(&descriptor)?;
    if created {
        rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR)
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    }
    Ok(File::from(descriptor))
}

/// Opens or creates an owner-only directory. Keeping the returned handle alive
/// pins the directory against replacement on platforms that support that
/// guarantee.
#[cfg(unix)]
pub fn open_or_create_owner_only_directory(path: &Path) -> Result<File, SecureFileError> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    require_macos_parent_without_extended_acl(path)?;
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => return Err(SecureFileError::UnsafeOrUnavailable),
    };
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || (!created && metadata.st_mode & 0o777 != 0o700)
    {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    require_no_macos_extended_acl(&descriptor)?;
    if created {
        rustix::fs::fchmod(&descriptor, Mode::RWXU)
            .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    }
    Ok(File::from(descriptor))
}

#[cfg(target_os = "macos")]
fn require_macos_parent_without_extended_acl(path: &Path) -> Result<(), SecureFileError> {
    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or(SecureFileError::UnsafeOrUnavailable)?;
    let descriptor = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    require_no_macos_extended_acl(&descriptor)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_macos_parent_without_extended_acl(_path: &Path) -> Result<(), SecureFileError> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_no_macos_extended_acl(
    descriptor: &impl std::os::fd::AsFd,
) -> Result<(), SecureFileError> {
    use std::os::fd::AsRawFd;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // acl_get_fd_np returns NULL with ENOENT when no extended ACL exists.
    // Any allocated ACL is non-canonical for Satelle's owner-only policy,
    // regardless of its allow/deny ordering.
    unsafe {
        *libc::__error() = 0;
        let acl = acl_get_fd_np(descriptor.as_fd().as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            return (*libc::__error() == libc::ENOENT)
                .then_some(())
                .ok_or(SecureFileError::UnsafeOrUnavailable);
        }
        let _ = acl_free(acl);
    }
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_no_macos_extended_acl(
    _descriptor: &impl std::os::fd::AsFd,
) -> Result<(), SecureFileError> {
    Ok(())
}

#[cfg(windows)]
pub fn open_or_create_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
    windows::open_or_create_owner_only_file(path)
}

#[cfg(windows)]
pub fn open_or_create_owner_only_directory(path: &Path) -> Result<File, SecureFileError> {
    windows::open_or_create_owner_only_directory(path)
}

#[cfg(not(any(unix, windows)))]
pub fn open_or_create_owner_only_file(_path: &Path) -> Result<File, SecureFileError> {
    // Satelle cannot claim owner-only persistence on a platform without an
    // implemented file-security policy.
    Err(SecureFileError::UnsafeOrUnavailable)
}

#[cfg(not(any(unix, windows)))]
pub fn open_or_create_owner_only_directory(_path: &Path) -> Result<File, SecureFileError> {
    Err(SecureFileError::UnsafeOrUnavailable)
}

fn read_secure_file(
    path: &Path,
    policy: SecurityPolicy,
    maximum_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, SecureFileError> {
    let mut file = open_secure_file(path, policy)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(maximum_bytes.min(4096)));
    file.by_ref()
        .take((maximum_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    if bytes.len() > maximum_bytes {
        return Err(SecureFileError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_secure_file(path: &Path, policy: SecurityPolicy) -> Result<File, SecureFileError> {
    use rustix::fs::{FileType, Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let metadata =
        rustix::fs::fstat(&descriptor).map_err(|_| SecureFileError::UnsafeOrUnavailable)?;
    let mode = metadata.st_mode & 0o777;
    let permissions_are_safe = match policy {
        SecurityPolicy::OwnerOnly => mode == 0o600,
        SecurityPolicy::OwnerPrivate => matches!(mode, 0o400 | 0o600),
        SecurityPolicy::OwnerControlled | SecurityPolicy::UserOrAdministratorControlled => {
            mode & 0o022 == 0
        }
    };
    let owner_is_trusted = metadata.st_uid == rustix::process::geteuid().as_raw()
        || (policy == SecurityPolicy::UserOrAdministratorControlled && metadata.st_uid == 0);
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || !owner_is_trusted
        || metadata.st_nlink != 1
        || !permissions_are_safe
    {
        return Err(SecureFileError::UnsafeOrUnavailable);
    }
    if matches!(
        policy,
        SecurityPolicy::OwnerOnly | SecurityPolicy::OwnerPrivate
    ) {
        require_no_macos_extended_acl(&descriptor)?;
    }
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_secure_file(path: &Path, policy: SecurityPolicy) -> Result<File, SecureFileError> {
    windows::open_secure_file(path, policy)
}

#[cfg(windows)]
mod windows {
    use super::{SecureFileError, SecurityPolicy};
    use std::ffi::c_void;
    use std::fs::File;
    use std::marker::PhantomData;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE,
        GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, CopySid,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl,
        GetTokenInformation, IsValidAcl, IsValidSid, IsWellKnownSid, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, FileAttributeTagInfo,
        GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
        GetVolumeInformationByHandleW, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
        WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, FILE_PERSISTENT_ACLS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const DANGEROUS_WRITE_MASK: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;

    pub(super) fn open_or_create_owner_only_file(path: &Path) -> Result<File, SecureFileError> {
        let process_sid = current_user_sid()?;
        let descriptor = PrivateDescriptor::new(&process_sid, "")?;
        let attributes = descriptor.security_attributes();
        let wide = wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        require_persistent_acls(&handle)?;
        require_regular_single_link(&handle)?;

        // SECURITY_ATTRIBUTES applies the policy atomically on creation.
        // Existing files are verified as-is so an earlier broad ACL and any
        // already-open handles can never be normalized into apparent safety.
        verify_security(&handle, &process_sid, SecurityPolicy::OwnerOnly)?;
        Ok(File::from(handle))
    }

    pub(super) fn open_or_create_owner_only_directory(
        path: &Path,
    ) -> Result<File, SecureFileError> {
        let process_sid = current_user_sid()?;
        let descriptor = PrivateDescriptor::new(&process_sid, "OICI")?;
        let attributes = descriptor.security_attributes();
        let wide = wide_path(path)?;
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
        if created == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        require_persistent_acls(&handle)?;
        require_directory(&handle)?;
        // CreateDirectoryW applies the protected DACL only to a new directory.
        // Existing namespaces must already satisfy it before they are used.
        verify_owner_only_security(
            &handle,
            &process_sid,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )?;
        Ok(File::from(handle))
    }

    pub(super) fn open_secure_file(
        path: &Path,
        policy: SecurityPolicy,
    ) -> Result<File, SecureFileError> {
        let wide = wide_path(path)?;
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        require_persistent_acls(&handle)?;
        require_regular_single_link(&handle)?;
        let process_sid = current_user_sid()?;
        verify_security(&handle, &process_sid, policy)?;
        Ok(File::from(handle))
    }

    fn require_regular_single_link(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        if unsafe { GetFileType(raw_handle(handle)) } != FILE_TYPE_DISK {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let loaded = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(handle),
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if loaded == 0
            || attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(raw_handle(handle), &mut information) } == 0
            || information.nNumberOfLinks != 1
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn require_directory(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        if unsafe { GetFileType(raw_handle(handle)) } != FILE_TYPE_DISK {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let loaded = unsafe {
            GetFileInformationByHandleEx(
                raw_handle(handle),
                FileAttributeTagInfo,
                (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if loaded == 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn require_persistent_acls(handle: &OwnedHandle) -> Result<(), SecureFileError> {
        let mut flags = 0_u32;
        let loaded = unsafe {
            GetVolumeInformationByHandleW(
                raw_handle(handle),
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut flags,
                null_mut(),
                0,
            )
        };
        if loaded == 0 || flags & FILE_PERSISTENT_ACLS == 0 {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(())
    }

    fn verify_security(
        handle: &OwnedHandle,
        process_sid: &ProcessSid,
        policy: SecurityPolicy,
    ) -> Result<(), SecureFileError> {
        let security = read_security(handle)?;
        let owner_is_trusted = !security.owner.is_null()
            && (unsafe { EqualSid(security.owner, process_sid.as_psid()) } != 0
                || (policy == SecurityPolicy::UserOrAdministratorControlled
                    && unsafe {
                        IsWellKnownSid(security.owner, WinLocalSystemSid) != 0
                            || IsWellKnownSid(security.owner, WinBuiltinAdministratorsSid) != 0
                    }));
        if !owner_is_trusted || security.dacl.is_null() || unsafe { IsValidAcl(security.dacl) } == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        match policy {
            SecurityPolicy::OwnerOnly => {
                verify_owner_only_dacl(&security, process_sid, 0, OwnerAccess::Full)
            }
            SecurityPolicy::OwnerPrivate => {
                verify_owner_only_dacl(&security, process_sid, 0, OwnerAccess::ReadOrFull)
            }
            SecurityPolicy::OwnerControlled | SecurityPolicy::UserOrAdministratorControlled => {
                verify_owner_controlled_dacl(&security, process_sid)
            }
        }
    }

    #[derive(Clone, Copy)]
    enum OwnerAccess {
        Full,
        ReadOrFull,
    }

    impl OwnerAccess {
        const fn permits(self, access: u32) -> bool {
            match self {
                Self::Full => access == FILE_ALL_ACCESS,
                Self::ReadOrFull => access & FILE_GENERIC_READ == FILE_GENERIC_READ,
            }
        }
    }

    fn verify_owner_only_dacl(
        security: &SecurityView,
        process_sid: &ProcessSid,
        expected_ace_flags: u8,
        owner_access: OwnerAccess,
    ) -> Result<(), SecureFileError> {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe {
            GetSecurityDescriptorControl(security.allocation.as_ptr(), &mut control, &mut revision)
        } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let dacl = unsafe { &*security.dacl };
        let mut owner_allow_seen = false;
        for index in 0..dacl.AceCount {
            match ace_entry(security, u32::from(index))? {
                // A deny ACE cannot grant access to another principal. Accept
                // it without making the owner-only invariant depend on one
                // serialized DACL shape.
                AceEntry::Denied => {}
                AceEntry::Allowed(ace) => {
                    if owner_allow_seen
                        || ace.flags != expected_ace_flags
                        || !owner_access.permits(normalized_file_access_mask(ace.mask))
                        || !ace_matches(&ace, process_sid)
                    {
                        return Err(SecureFileError::UnsafeOrUnavailable);
                    }
                    owner_allow_seen = true;
                }
                AceEntry::Unsupported => return Err(SecureFileError::UnsafeOrUnavailable),
            }
        }
        owner_allow_seen
            .then_some(())
            .ok_or(SecureFileError::UnsafeOrUnavailable)
    }

    fn verify_owner_only_security(
        handle: &OwnedHandle,
        process_sid: &ProcessSid,
        expected_ace_flags: u8,
    ) -> Result<(), SecureFileError> {
        let security = read_security(handle)?;
        if security.owner.is_null()
            || unsafe { EqualSid(security.owner, process_sid.as_psid()) } == 0
            || security.dacl.is_null()
            || unsafe { IsValidAcl(security.dacl) } == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        verify_owner_only_dacl(
            &security,
            process_sid,
            expected_ace_flags,
            OwnerAccess::Full,
        )
    }

    fn normalized_file_access_mask(mask: u32) -> u32 {
        let mut normalized = mask & !(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE);
        if mask & GENERIC_ALL != 0 {
            normalized |= FILE_ALL_ACCESS;
        }
        if mask & GENERIC_READ != 0 {
            normalized |= FILE_GENERIC_READ;
        }
        if mask & GENERIC_WRITE != 0 {
            normalized |= FILE_GENERIC_WRITE;
        }
        if mask & GENERIC_EXECUTE != 0 {
            normalized |= FILE_GENERIC_EXECUTE;
        }
        normalized
    }

    fn verify_owner_controlled_dacl(
        security: &SecurityView,
        process_sid: &ProcessSid,
    ) -> Result<(), SecureFileError> {
        let dacl = unsafe { &*security.dacl };
        for index in 0..dacl.AceCount {
            match ace_entry(security, u32::from(index))? {
                AceEntry::Denied => {}
                AceEntry::Allowed(ace) => {
                    if !trusted_config_writer(&ace, process_sid)
                        && ace.mask & DANGEROUS_WRITE_MASK != 0
                    {
                        return Err(SecureFileError::UnsafeOrUnavailable);
                    }
                }
                AceEntry::Unsupported => return Err(SecureFileError::UnsafeOrUnavailable),
            }
        }
        Ok(())
    }

    enum AceEntry<'security> {
        Allowed(ValidatedAllowedAce<'security>),
        Denied,
        Unsupported,
    }

    struct ValidatedAllowedAce<'security> {
        mask: u32,
        flags: u8,
        sid: PSID,
        _security: PhantomData<&'security SecurityView>,
    }

    fn ace_entry<'security>(
        security: &'security SecurityView,
        index: u32,
    ) -> Result<AceEntry<'security>, SecureFileError> {
        let mut raw_ace = null_mut();
        if unsafe { GetAce(security.dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let acl_start = security.dacl as usize;
        let ace_start = raw_ace as usize;
        let ace_offset = ace_start
            .checked_sub(acl_start)
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let acl_size = usize::from(unsafe { &*security.dacl }.AclSize);
        if ace_offset
            .checked_add(size_of::<ACE_HEADER>())
            .is_none_or(|end| end > acl_size)
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let header = unsafe { raw_ace.cast::<ACE_HEADER>().read_unaligned() };
        if ace_offset
            .checked_add(usize::from(header.AceSize))
            .is_none_or(|end| end > acl_size)
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                validated_allowed_ace(security, raw_ace.cast(), header).map(AceEntry::Allowed)
            }
            ACCESS_DENIED_ACE_TYPE => Ok(AceEntry::Denied),
            _ => Ok(AceEntry::Unsupported),
        }
    }

    fn validated_allowed_ace<'security>(
        _security: &'security SecurityView,
        raw_ace: *const u8,
        header: ACE_HEADER,
    ) -> Result<ValidatedAllowedAce<'security>, SecureFileError> {
        const SID_HEADER_BYTES: usize = 8;
        let ace_size = usize::from(header.AceSize);
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if ace_size < sid_offset + SID_HEADER_BYTES {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let sid_bytes =
            unsafe { std::slice::from_raw_parts(raw_ace.add(sid_offset), ace_size - sid_offset) };
        let subauthority_bytes = usize::from(sid_bytes[1])
            .checked_mul(size_of::<u32>())
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        let sid_length = SID_HEADER_BYTES
            .checked_add(subauthority_bytes)
            .ok_or(SecureFileError::UnsafeOrUnavailable)?;
        if sid_length > sid_bytes.len() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let sid = unsafe { raw_ace.add(sid_offset) }.cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize != sid_length {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mask = unsafe {
            raw_ace
                .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                .cast::<u32>()
                .read_unaligned()
        };
        Ok(ValidatedAllowedAce {
            mask,
            flags: header.AceFlags,
            sid,
            _security: PhantomData,
        })
    }

    fn ace_matches(ace: &ValidatedAllowedAce<'_>, process_sid: &ProcessSid) -> bool {
        (unsafe { EqualSid(ace.sid, process_sid.as_psid()) }) != 0
    }

    fn trusted_config_writer(ace: &ValidatedAllowedAce<'_>, process_sid: &ProcessSid) -> bool {
        unsafe {
            EqualSid(ace.sid, process_sid.as_psid()) != 0
                || IsWellKnownSid(ace.sid, WinLocalSystemSid) != 0
                || IsWellKnownSid(ace.sid, WinBuiltinAdministratorsSid) != 0
        }
    }

    fn current_user_sid() -> Result<ProcessSid, SecureFileError> {
        let mut raw_token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let information = token_information(&token, TokenUser, size_of::<TOKEN_USER>())?;
        let token_user = unsafe { &*information.as_ptr().cast::<TOKEN_USER>() };
        ProcessSid::copy_from(token_user.User.Sid)
    }

    fn token_information(
        token: &OwnedHandle,
        class: TOKEN_INFORMATION_CLASS,
        minimum: usize,
    ) -> Result<Vec<usize>, SecureFileError> {
        let mut required = 0_u32;
        unsafe { GetTokenInformation(raw_handle(token), class, null_mut(), 0, &mut required) };
        if (required as usize) < minimum {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        let mut words = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                raw_handle(token),
                class,
                words.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(words)
    }

    struct ProcessSid(Box<[usize]>);

    impl ProcessSid {
        fn copy_from(sid: PSID) -> Result<Self, SecureFileError> {
            if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            let length = unsafe { GetLengthSid(sid) };
            let mut words =
                vec![0_usize; (length as usize).div_ceil(size_of::<usize>())].into_boxed_slice();
            if unsafe { CopySid(length, words.as_mut_ptr().cast(), sid) } == 0 {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            Ok(Self(words))
        }

        fn as_psid(&self) -> PSID {
            self.0.as_ptr().cast_mut().cast()
        }

        fn sddl(&self) -> Result<String, SecureFileError> {
            let mut raw = null_mut();
            if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut raw) } == 0 || raw.is_null() {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            let allocation = LocalWideString(raw);
            allocation.to_string()
        }
    }

    struct PrivateDescriptor(LocalMemory);

    impl PrivateDescriptor {
        fn new(process_sid: &ProcessSid, ace_flags: &str) -> Result<Self, SecureFileError> {
            let sid = process_sid.sddl()?;
            let sddl = format!("O:{sid}D:P(A;{ace_flags};FA;;;{sid})");
            let wide = wide_string(&sddl)?;
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
                || descriptor.is_null()
            {
                return Err(SecureFileError::UnsafeOrUnavailable);
            }
            Ok(Self(LocalMemory(descriptor)))
        }

        fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0.as_ptr(),
                bInheritHandle: 0,
            }
        }
    }

    struct SecurityView {
        allocation: LocalMemory,
        owner: PSID,
        dacl: *mut ACL,
    }

    fn read_security(handle: &OwnedHandle) -> Result<SecurityView, SecureFileError> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                raw_handle(handle),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || descriptor.is_null() {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        Ok(SecurityView {
            allocation: LocalMemory(descriptor),
            owner,
            dacl,
        })
    }

    struct LocalMemory(PSECURITY_DESCRIPTOR);

    impl LocalMemory {
        fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }
    }

    impl Drop for LocalMemory {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }

    struct LocalWideString(*mut u16);

    impl LocalWideString {
        fn to_string(&self) -> Result<String, SecureFileError> {
            const MAX_SID_STRING_UNITS: usize = 1024;

            let length = (0..MAX_SID_STRING_UNITS)
                .find(|index| unsafe { *self.0.add(*index) } == 0)
                .ok_or(SecureFileError::UnsafeOrUnavailable)?;
            String::from_utf16(unsafe { std::slice::from_raw_parts(self.0, length) })
                .map_err(|_| SecureFileError::UnsafeOrUnavailable)
        }
    }

    impl Drop for LocalWideString {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast::<c_void>() as HLOCAL) };
        }
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, SecureFileError> {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.is_empty() || wide.contains(&0) {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        wide.push(0);
        Ok(wide)
    }

    fn wide_string(value: &str) -> Result<Vec<u16>, SecureFileError> {
        let mut wide = value.encode_utf16().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(SecureFileError::UnsafeOrUnavailable);
        }
        wide.push(0);
        Ok(wide)
    }

    fn raw_handle(handle: &OwnedHandle) -> HANDLE {
        use std::os::windows::io::AsRawHandle;
        handle.as_raw_handle()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn generic_access_masks_normalize_without_hiding_extra_rights() {
            const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

            assert_eq!(normalized_file_access_mask(GENERIC_ALL), FILE_ALL_ACCESS);
            assert_eq!(
                normalized_file_access_mask(FILE_ALL_ACCESS),
                FILE_ALL_ACCESS
            );
            assert_ne!(
                normalized_file_access_mask(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE),
                FILE_ALL_ACCESS
            );
            assert_eq!(
                normalized_file_access_mask(GENERIC_ALL | ACCESS_SYSTEM_SECURITY),
                FILE_ALL_ACCESS | ACCESS_SYSTEM_SECURITY
            );
            assert!(OwnerAccess::Full.permits(FILE_ALL_ACCESS));
            assert!(!OwnerAccess::Full.permits(FILE_GENERIC_READ));
            assert!(OwnerAccess::ReadOrFull.permits(FILE_GENERIC_READ));
            assert!(OwnerAccess::ReadOrFull.permits(FILE_ALL_ACCESS));
            assert!(
                OwnerAccess::ReadOrFull
                    .permits(normalized_file_access_mask(GENERIC_READ | GENERIC_WRITE))
            );
            assert!(!OwnerAccess::ReadOrFull.permits(FILE_GENERIC_WRITE));
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::*;
    #[cfg(any(unix, windows))]
    use std::fs;
    #[cfg(any(unix, windows))]
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[cfg(any(unix, windows))]
    #[test]
    fn owner_only_files_are_private_before_callers_write() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let fresh = directory.path().join("fresh-owner-only");
        let mut file = open_or_create_owner_only_file(&fresh).expect("create owner-only file");
        file.write_all(b"fresh-secret")
            .expect("write newly private file");
        drop(file);
        assert_eq!(
            read_owner_only_secret_file(&fresh)
                .expect("read newly private file")
                .as_str(),
            "fresh-secret"
        );

        let existing = directory.path().join("existing-owner-only");
        let mut existing_file =
            open_or_create_owner_only_file(&existing).expect("create existing private file");
        existing_file
            .write_all(b"existing-secret")
            .expect("write existing private file");
        drop(existing_file);
        drop(open_or_create_owner_only_file(&existing).expect("reopen existing private file"));
        assert_eq!(
            read_owner_only_secret_file(&existing)
                .expect("read existing private file")
                .as_str(),
            "existing-secret"
        );

        #[cfg(unix)]
        {
            fs::set_permissions(&existing, fs::Permissions::from_mode(0o644))
                .expect("make existing file broadly readable");
            assert!(matches!(
                open_or_create_owner_only_file(&existing),
                Err(SecureFileError::UnsafeOrUnavailable)
            ));
        }

        let private_directory = directory.path().join("owner-only-directory");
        let _directory_guard = open_or_create_owner_only_directory(&private_directory)
            .expect("create owner-only directory");
        let nested = private_directory.join("nested-owner-only");
        let mut nested_file =
            open_or_create_owner_only_file(&nested).expect("create file in owner-only directory");
        nested_file
            .write_all(b"nested-secret")
            .expect("write nested owner-only file");
        drop(nested_file);
        assert_eq!(
            read_owner_only_secret_file(&nested)
                .expect("read nested owner-only file")
                .as_str(),
            "nested-secret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn permissive_existing_directory_with_a_sidecar_is_rejected() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let history = directory.path().join("command-history");
        fs::create_dir(&history).expect("create permissive history directory");
        let sidecar = history.join("command-history.sqlite3-journal");
        fs::write(&sidecar, b"planted-sidecar").expect("plant SQLite sidecar");
        fs::set_permissions(&history, fs::Permissions::from_mode(0o770))
            .expect("make history directory group writable");

        assert!(matches!(
            open_or_create_owner_only_directory(&history),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert_eq!(
            fs::read(&sidecar).expect("read rejected sidecar"),
            b"planted-sidecar"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_extended_and_inherited_acls_are_rejected() {
        fn add_acl(path: &Path, entry: &str) {
            let status = std::process::Command::new("chmod")
                .arg("+a")
                .arg(entry)
                .arg(path)
                .status()
                .expect("run macOS chmod ACL command");
            assert!(status.success(), "macOS chmod must add the test ACL");
        }

        let directory = tempfile::tempdir().expect("create temporary directory");
        let existing = directory.path().join("existing-owner-only");
        fs::write(&existing, b"existing-secret").expect("write existing private file");
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o600))
            .expect("set owner-only mode");
        add_acl(&existing, "everyone allow read");
        assert!(matches!(
            open_or_create_owner_only_file(&existing),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert_eq!(
            read_owner_only_secret_config_file(&existing),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        let inheriting_parent = directory.path().join("inheriting-parent");
        fs::create_dir(&inheriting_parent).expect("create ACL inheritance parent");
        fs::set_permissions(&inheriting_parent, fs::Permissions::from_mode(0o700))
            .expect("set owner-only parent mode");
        add_acl(
            &inheriting_parent,
            "everyone allow read,file_inherit,directory_inherit",
        );
        let child = inheriting_parent.join("new-owner-only");
        assert!(matches!(
            open_or_create_owner_only_file(&child),
            Err(SecureFileError::UnsafeOrUnavailable)
        ));
        assert!(
            !child.exists(),
            "ACL-bearing parents must be rejected before creation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_require_regular_owner_only_single_link_files() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let token = directory.path().join("satelle.token");
        fs::write(&token, "secret-value\n").expect("write token file");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("restrict token file");
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read private token")
                .as_str(),
            "secret-value"
        );

        fs::set_permissions(&token, fs::Permissions::from_mode(0o640))
            .expect("make token file unsafe");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("restore token permissions");
        let link = directory.path().join("token-link");
        symlink(&token, &link).expect("create token symlink");
        assert_eq!(
            read_owner_only_secret_file(&link),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        let private_key = directory.path().join("host-private-key.pem");
        let pem = "x".repeat(MAX_SECRET_FILE_BYTES + 1);
        fs::write(&private_key, &pem).expect("write larger private key fixture");
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
            .expect("restrict private key file");
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read larger owner-only secret configuration")
                .as_str(),
            pem
        );

        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o400))
            .expect("make private key owner-readable");
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read owner-private configuration without write access")
                .as_str(),
            pem
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_secret_paths_fail_without_blocking() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let fifo = directory.path().join("satelle.token");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success());
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600))
            .expect("restrict FIFO permissions");

        let started = std::time::Instant::now();
        assert_eq!(
            read_owner_only_secret_file(&fifo),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn owner_controlled_config_rejects_unrelated_write_access() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let config = directory.path().join("config.toml");
        fs::write(&config, "default_host = \"local-demo\"\n").expect("write config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))
            .expect("set normal user config permissions");
        assert!(read_owner_controlled_config_file(&config).is_ok());
        assert!(read_trusted_ca_bundle_file(&config).is_ok());

        fs::set_permissions(&config, fs::Permissions::from_mode(0o664))
            .expect("make config group-writable");
        assert_eq!(
            read_owner_controlled_config_file(&config),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_reads_are_bounded_and_require_utf8() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let token = directory.path().join("satelle.token");
        fs::write(&token, vec![b'x'; MAX_SECRET_FILE_BYTES + 1]).expect("write large token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("restrict token file");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::TooLarge)
        );

        fs::write(&token, [0xff, 0xfe]).expect("write non-UTF-8 token");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::NotUtf8)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_secret_files_require_an_owner_only_acl_and_a_single_real_file() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let token = directory.path().join("satelle.token");
        fs::write(&token, "secret-value\n").expect("write token file");
        let user = current_windows_user_sid();
        set_windows_owner(&token, &user);
        set_windows_acl(&token, &[format!("*{user}:(F)")]);
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read private token")
                .as_str(),
            "secret-value"
        );

        set_windows_acl(&token, &[format!("*{user}:(R)")]);
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        set_windows_acl(&token, &[format!("*{user}:(F)")]);

        let private_key = directory.path().join("host-private-key.pem");
        let pem = "x".repeat(MAX_SECRET_FILE_BYTES + 1);
        fs::write(&private_key, &pem).expect("write larger private key fixture");
        set_windows_owner(&private_key, &user);
        set_windows_acl(&private_key, &[format!("*{user}:(R)")]);
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read owner-read-only private key")
                .as_str(),
            pem
        );
        set_windows_acl(&private_key, &[format!("*{user}:(M)")]);
        assert_eq!(
            read_owner_only_secret_config_file(&private_key)
                .expect("read owner-read-write private key")
                .as_str(),
            pem
        );

        add_windows_deny(&token, "*S-1-5-7:(R)");
        assert_eq!(
            read_owner_only_secret_file(&token)
                .expect("read token with an unrelated deny ACE")
                .as_str(),
            "secret-value"
        );

        set_windows_acl(
            &token,
            &[format!("*{user}:(F)"), "*S-1-1-0:(R)".to_string()],
        );
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );

        set_windows_acl(&token, &[format!("*{user}:(F)")]);
        let hard_link = directory.path().join("satelle-hard-link.token");
        fs::hard_link(&token, &hard_link).expect("create token hard link");
        assert_eq!(
            read_owner_only_secret_file(&token),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        fs::remove_file(hard_link).expect("remove token hard link");

        let symbolic_link = directory.path().join("satelle-symbolic-link.token");
        std::os::windows::fs::symlink_file(&token, &symbolic_link)
            .expect("create token symbolic link");
        assert_eq!(
            read_owner_only_secret_file(&symbolic_link),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_owner_controlled_config_allows_only_trusted_writers() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let config = directory.path().join("config.toml");
        fs::write(&config, "default_host = \"local-demo\"\n").expect("write config");
        let user = current_windows_user_sid();
        set_windows_owner(&config, &user);
        let trusted_acl = [
            format!("*{user}:(F)"),
            "*S-1-5-18:(F)".to_string(),
            "*S-1-5-32-544:(F)".to_string(),
            "*S-1-1-0:(R)".to_string(),
        ];
        set_windows_acl(&config, &trusted_acl);
        assert!(read_owner_controlled_config_file(&config).is_ok());
        assert!(read_trusted_ca_bundle_file(&config).is_ok());

        set_windows_owner(&config, "S-1-5-32-544");
        assert_eq!(
            read_owner_controlled_config_file(&config),
            Err(SecureFileError::UnsafeOrUnavailable)
        );
        assert!(read_trusted_ca_bundle_file(&config).is_ok());
        set_windows_owner(&config, &user);

        let unsafe_acl = [
            format!("*{user}:(F)"),
            "*S-1-5-18:(F)".to_string(),
            "*S-1-5-32-544:(F)".to_string(),
            "*S-1-1-0:(M)".to_string(),
        ];
        set_windows_acl(&config, &unsafe_acl);
        assert_eq!(
            read_owner_controlled_config_file(&config),
            Err(SecureFileError::UnsafeOrUnavailable)
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
    fn set_windows_acl(path: &std::path::Path, entries: &[String]) {
        run_icacls(path, &["/inheritance:r"], "disable ACL inheritance");

        let mut principals = vec![
            "*S-1-5-18".to_string(),
            "*S-1-5-32-544".to_string(),
            "*S-1-1-0".to_string(),
        ];
        principals.extend(entries.iter().filter_map(|entry| {
            entry
                .split_once(":(")
                .map(|(principal, _)| principal.to_string())
        }));
        let mut remove_arguments = vec!["/remove:g".to_string()];
        remove_arguments.extend(principals);
        run_icacls(
            path,
            &remove_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "remove existing ACL grants",
        );

        let mut grant_arguments = vec!["/grant:r".to_string()];
        grant_arguments.extend(entries.iter().cloned());
        run_icacls(
            path,
            &grant_arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            "install requested ACL grants",
        );
    }

    #[cfg(windows)]
    fn run_icacls(path: &std::path::Path, arguments: &[&str], operation: &str) {
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

    #[cfg(windows)]
    fn set_windows_owner(path: &std::path::Path, sid: &str) {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/setowner", &format!("*{sid}")])
            .output()
            .expect("set Windows file owner");
        assert!(
            output.status.success(),
            "icacls owner update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    fn add_windows_deny(path: &std::path::Path, entry: &str) {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .args(["/deny", entry])
            .output()
            .expect("add Windows deny ACE");
        assert!(
            output.status.success(),
            "icacls deny update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
