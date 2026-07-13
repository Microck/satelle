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
    OwnerControlled,
    UserOrAdministratorControlled,
}

pub fn read_owner_only_secret_file(path: &Path) -> Result<Zeroizing<String>, SecureFileError> {
    let bytes = read_secure_file(path, SecurityPolicy::OwnerOnly, MAX_SECRET_FILE_BYTES)?;
    let value = std::str::from_utf8(bytes.as_slice()).map_err(|_| SecureFileError::NotUtf8)?;
    Ok(Zeroizing::new(value.trim_ascii().to_string()))
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
        GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CopySid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl, IsValidSid,
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        FileAttributeTagInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFileType, GetVolumeInformationByHandleW, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
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
            SecurityPolicy::OwnerOnly => verify_owner_only_dacl(&security, process_sid),
            SecurityPolicy::OwnerControlled | SecurityPolicy::UserOrAdministratorControlled => {
                verify_owner_controlled_dacl(&security, process_sid)
            }
        }
    }

    fn verify_owner_only_dacl(
        security: &SecurityView,
        process_sid: &ProcessSid,
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
                        || ace.flags != 0
                        || normalized_file_access_mask(ace.mask) != FILE_ALL_ACCESS
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

    fn wide_path(path: &Path) -> Result<Vec<u16>, SecureFileError> {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.is_empty() || wide.contains(&0) {
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
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::*;
    #[cfg(any(unix, windows))]
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

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
