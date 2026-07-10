use super::{StorageError, StorageErrorKind};
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{addr_of, null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS, GetLastError,
    HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, CONTAINER_INHERIT_ACE, CopySid, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetTokenInformation, IsValidAcl, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetVolumeInformationByHandleW, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, ReOpenFile, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const MAX_SID_STRING_UNITS: usize = 1024;

/// Pins every state-path component and owns the daemon account SID used for
/// all protected leaves. Omitting FILE_SHARE_DELETE on directory handles
/// prevents a checked path component from being renamed or deleted while the
/// SQLite connection is alive.
pub(super) struct SecureStateDirectory {
    root: PathBuf,
    _pinned_directories: Vec<OwnedHandle>,
    process_identity: ProcessIdentity,
}

impl SecureStateDirectory {
    pub(super) fn prepare(state_root: &Path) -> Result<Self, StorageError> {
        if !state_root.is_absolute() || state_root.parent().is_none() {
            return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
        }

        let prefixes = directory_prefixes(state_root)?;
        let drive_root = prefixes
            .first()
            .ok_or_else(|| StorageError::new(StorageErrorKind::UnsafeStatePath))?;
        require_fixed_drive(drive_root)?;

        let process_identity = ProcessIdentity::current()?;
        let directory_descriptor =
            PrivateDescriptor::new(&process_identity.user, ObjectKind::Directory)?;
        let mut pinned_directories = Vec::with_capacity(prefixes.len());

        for (index, path) in prefixes.iter().enumerate() {
            let is_drive_root = index == 0;
            let is_state_root = index + 1 == prefixes.len();
            let desired_access = if is_state_root {
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC
            } else {
                FILE_READ_ATTRIBUTES
            };
            let mut handle = open_directory(path, desired_access)?;
            if handle.is_none() && !is_drive_root {
                create_directory(path, &directory_descriptor)?;
                handle = open_directory(path, desired_access)?;
            }
            let handle = handle
                .ok_or_else(|| StorageError::new(StorageErrorKind::StateDirectoryUnavailable))?;
            require_directory_handle(&handle)?;

            if is_state_root {
                require_persistent_acls(&handle)?;
                require_owner(&handle, &process_identity.user)?;
                set_private_dacl(&handle, &directory_descriptor)?;
                verify_private_security(&handle, &process_identity.user, ObjectKind::Directory)?;
            }
            pinned_directories.push(handle);
        }

        Ok(Self {
            root: state_root.to_path_buf(),
            _pinned_directories: pinned_directories,
            process_identity,
        })
    }

    pub(super) fn open_private_leaf(
        &self,
        file_name: &str,
        create: bool,
        fallback: StorageErrorKind,
    ) -> Result<Option<File>, StorageError> {
        if file_name.is_empty()
            || file_name
                .chars()
                .any(|character| matches!(character, '/' | '\\' | ':'))
            || file_name == "."
            || file_name == ".."
        {
            return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
        }

        let path = self.root.join(file_name);
        let descriptor = PrivateDescriptor::new(&self.process_identity.user, ObjectKind::File)?;
        let security_attributes = descriptor.security_attributes();
        let wide = wide_path(&path)?;
        let disposition = if create { OPEN_ALWAYS } else { OPEN_EXISTING };
        let raw = unsafe {
            // FILE_FLAG_OPEN_REPARSE_POINT makes this the handle to a link or
            // junction itself. Every decision below is made from that handle.
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &security_attributes,
                disposition,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            let code = unsafe { GetLastError() };
            if !create && matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                return Ok(None);
            }
            return Err(win32_error(fallback, code));
        }
        let security_handle = unsafe {
            // CreateFileW returned unique ownership of this non-pseudo handle.
            OwnedHandle::from_raw_handle(raw)
        };

        require_regular_single_link(&security_handle)?;
        require_initial_leaf_owner(&security_handle, &self.process_identity)?;
        set_private_owner_and_dacl(&security_handle, &descriptor, &self.process_identity.user)?;
        verify_private_security(
            &security_handle,
            &self.process_identity.user,
            ObjectKind::File,
        )?;

        let reopened = unsafe {
            // ReOpenFile is handle-relative, so there is no second pathname
            // lookup between validation and obtaining the data handle. Its
            // final argument accepts file flags, not CreateFile attributes;
            // zero requests no additional flags.
            ReOpenFile(
                raw_handle(&security_handle),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                0,
            )
        };
        if reopened == INVALID_HANDLE_VALUE {
            return Err(last_error(fallback));
        }
        let data_handle = unsafe {
            // ReOpenFile returned a second uniquely owned handle.
            OwnedHandle::from_raw_handle(reopened)
        };
        require_regular_single_link(&data_handle)?;
        Ok(Some(File::from(data_handle)))
    }
}

#[derive(Clone, Copy)]
enum ObjectKind {
    Directory,
    File,
}

impl ObjectKind {
    fn sddl_flags(self) -> &'static str {
        match self {
            Self::Directory => "OICI",
            Self::File => "",
        }
    }

    fn ace_flags(self) -> u8 {
        match self {
            Self::Directory => (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
            Self::File => 0,
        }
    }
}

struct ProcessIdentity {
    user: ProcessSid,
    default_owner: ProcessSid,
}

impl ProcessIdentity {
    fn current() -> Result<Self, StorageError> {
        let mut token = null_mut();
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
        }
        let token = unsafe {
            // OpenProcessToken returned unique ownership of a real handle.
            OwnedHandle::from_raw_handle(token)
        };

        let user_information = token_information(&token, TokenUser, size_of::<TOKEN_USER>())?;
        let token_user = unsafe {
            // token_information returns an aligned buffer at least TOKEN_USER bytes long.
            &*user_information.as_ptr().cast::<TOKEN_USER>()
        };
        let user = ProcessSid::copy_from(token_user.User.Sid)?;

        let owner_information = token_information(&token, TokenOwner, size_of::<TOKEN_OWNER>())?;
        let token_owner = unsafe {
            // token_information returns an aligned buffer at least TOKEN_OWNER bytes long.
            &*owner_information.as_ptr().cast::<TOKEN_OWNER>()
        };
        let default_owner = ProcessSid::copy_from(token_owner.Owner)?;

        Ok(Self {
            user,
            default_owner,
        })
    }
}

struct ProcessSid {
    words: Box<[usize]>,
    sddl: String,
}

impl ProcessSid {
    fn copy_from(sid: PSID) -> Result<Self, StorageError> {
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
        }
        let sid_bytes = unsafe { GetLengthSid(sid) };
        if sid_bytes == 0 {
            return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
        }
        let mut words =
            vec![0_usize; (sid_bytes as usize).div_ceil(size_of::<usize>())].into_boxed_slice();
        let copied = unsafe { CopySid(sid_bytes, words.as_mut_ptr().cast(), sid) };
        if copied == 0 {
            return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
        }
        let sddl = sid_to_string(words.as_ptr().cast_mut().cast())?;
        Ok(Self { words, sddl })
    }

    fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }
}

fn token_information(
    token: &OwnedHandle,
    information_class: TOKEN_INFORMATION_CLASS,
    minimum_size: usize,
) -> Result<Box<[usize]>, StorageError> {
    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(
            raw_handle(token),
            information_class,
            null_mut(),
            0,
            &mut required,
        );
    }
    if required < minimum_size as u32 {
        return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
    }
    let buffer_bytes = required;
    let word_count = (buffer_bytes as usize).div_ceil(size_of::<usize>());
    let mut words = vec![0_usize; word_count].into_boxed_slice();
    let loaded = unsafe {
        GetTokenInformation(
            raw_handle(token),
            information_class,
            words.as_mut_ptr().cast(),
            buffer_bytes,
            &mut required,
        )
    };
    if loaded == 0 || required < minimum_size as u32 || required > buffer_bytes {
        return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
    }
    Ok(words)
}

struct PrivateDescriptor(LocalMemory);

impl PrivateDescriptor {
    fn new(process_sid: &ProcessSid, kind: ObjectKind) -> Result<Self, StorageError> {
        let sddl = format!(
            "O:{}D:P(A;{};FA;;;{})",
            process_sid.sddl,
            kind.sddl_flags(),
            process_sid.sddl
        );
        let wide = wide_string(&sddl)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
        }
        LocalMemory::new(descriptor).map(Self)
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0.as_ptr()
    }

    fn dacl(&self) -> Result<*mut ACL, StorageError> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        let loaded = unsafe {
            GetSecurityDescriptorDacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted)
        };
        if loaded == 0 || present == 0 || dacl.is_null() {
            return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
        }
        Ok(dacl)
    }

    fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.as_ptr(),
            bInheritHandle: 0,
        }
    }
}

struct LocalMemory(*mut c_void);

impl LocalMemory {
    fn new(pointer: *mut c_void) -> Result<Self, StorageError> {
        if pointer.is_null() {
            return Err(StorageError::new(
                StorageErrorKind::StateDirectoryUnavailable,
            ));
        }
        Ok(Self(pointer))
    }

    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            // All LocalMemory values originate from APIs documented to use
            // LocalAlloc and are released exactly once here.
            LocalFree(self.0 as HLOCAL);
        }
    }
}

fn directory_prefixes(path: &Path) -> Result<Vec<PathBuf>, StorageError> {
    let mut current = PathBuf::new();
    let mut prefixes = Vec::new();
    let mut saw_disk = false;
    let mut saw_root = false;

    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                if saw_disk || !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                    return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
                }
                saw_disk = true;
                current.push(prefix.as_os_str());
            }
            component @ Component::RootDir => {
                if !saw_disk || saw_root {
                    return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
                }
                saw_root = true;
                current.push(component.as_os_str());
                prefixes.push(current.clone());
            }
            Component::Normal(part) if saw_root => {
                current.push(part);
                prefixes.push(current.clone());
            }
            Component::CurDir | Component::ParentDir | Component::Normal(_) => {
                return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
            }
        }
    }

    if !saw_disk || !saw_root || prefixes.len() < 2 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(prefixes)
}

fn require_fixed_drive(drive_root: &Path) -> Result<(), StorageError> {
    let wide = wide_path(drive_root)?;
    let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
    if drive_type != DRIVE_FIXED {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

fn open_directory(path: &Path, desired_access: u32) -> Result<Option<OwnedHandle>, StorageError> {
    let wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        if matches!(code, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(None);
        }
        return Err(win32_error(
            StorageErrorKind::StateDirectoryUnavailable,
            code,
        ));
    }
    Ok(Some(unsafe {
        // CreateFileW returned unique ownership of this non-pseudo handle.
        OwnedHandle::from_raw_handle(raw)
    }))
}

fn create_directory(path: &Path, descriptor: &PrivateDescriptor) -> Result<(), StorageError> {
    let wide = wide_path(path)?;
    let attributes = descriptor.security_attributes();
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
    if created != 0 {
        return Ok(());
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_ALREADY_EXISTS {
        return Ok(());
    }
    Err(win32_error(
        StorageErrorKind::StateDirectoryUnavailable,
        code,
    ))
}

fn require_directory_handle(handle: &OwnedHandle) -> Result<(), StorageError> {
    let attributes = handle_attributes(handle)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

fn require_regular_single_link(handle: &OwnedHandle) -> Result<(), StorageError> {
    let attributes = handle_attributes(handle)?;
    if attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let loaded = unsafe { GetFileInformationByHandle(raw_handle(handle), &mut information) };
    if loaded == 0 {
        return Err(last_error(StorageErrorKind::OpenFailed));
    }
    if information.nNumberOfLinks != 1 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

fn handle_attributes(handle: &OwnedHandle) -> Result<FILE_ATTRIBUTE_TAG_INFO, StorageError> {
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    let loaded = unsafe {
        GetFileInformationByHandleEx(
            raw_handle(handle),
            FileAttributeTagInfo,
            (&mut information as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if loaded == 0 {
        return Err(last_error(StorageErrorKind::UnsafeStatePath));
    }
    Ok(information)
}

fn require_persistent_acls(handle: &OwnedHandle) -> Result<(), StorageError> {
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
    if loaded == 0 {
        return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

fn require_owner(handle: &OwnedHandle, process_sid: &ProcessSid) -> Result<(), StorageError> {
    let security = read_security(handle, OWNER_SECURITY_INFORMATION)?;
    if security.owner.is_null() || unsafe { EqualSid(security.owner, process_sid.as_psid()) } == 0 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

fn require_initial_leaf_owner(
    handle: &OwnedHandle,
    process_identity: &ProcessIdentity,
) -> Result<(), StorageError> {
    let security = read_security(handle, OWNER_SECURITY_INFORMATION)?;
    if security.owner.is_null()
        || (unsafe { EqualSid(security.owner, process_identity.user.as_psid()) } == 0
            && unsafe { EqualSid(security.owner, process_identity.default_owner.as_psid()) } == 0)
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

fn set_private_dacl(
    handle: &OwnedHandle,
    descriptor: &PrivateDescriptor,
) -> Result<(), StorageError> {
    let dacl = descriptor.dacl()?;
    let status = unsafe {
        SetSecurityInfo(
            raw_handle(handle),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(StorageErrorKind::UnsafeStatePath, status));
    }
    Ok(())
}

fn set_private_owner_and_dacl(
    handle: &OwnedHandle,
    descriptor: &PrivateDescriptor,
    process_sid: &ProcessSid,
) -> Result<(), StorageError> {
    let dacl = descriptor.dacl()?;
    let status = unsafe {
        SetSecurityInfo(
            raw_handle(handle),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            process_sid.as_psid(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(StorageErrorKind::UnsafeStatePath, status));
    }
    Ok(())
}

fn verify_private_security(
    handle: &OwnedHandle,
    process_sid: &ProcessSid,
    kind: ObjectKind,
) -> Result<(), StorageError> {
    let security = read_security(
        handle,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
    )?;
    if security.owner.is_null()
        || unsafe { EqualSid(security.owner, process_sid.as_psid()) } == 0
        || security.dacl.is_null()
        || unsafe { IsValidAcl(security.dacl) } == 0
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    let control_loaded = unsafe {
        GetSecurityDescriptorControl(security.allocation.as_ptr(), &mut control, &mut revision)
    };
    if control_loaded == 0 || control & SE_DACL_PROTECTED == 0 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }

    let dacl = unsafe { &*security.dacl };
    if dacl.AceCount != 1 {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    let mut raw_ace = null_mut();
    let loaded = unsafe { GetAce(security.dacl, 0, &mut raw_ace) };
    if loaded == 0 || raw_ace.is_null() {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || ace.Header.AceFlags != kind.ace_flags()
        || ace.Mask != FILE_ALL_ACCESS
        || usize::from(ace.Header.AceSize)
            < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + size_of::<u32>()
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    let ace_sid = addr_of!(ace.SidStart).cast_mut().cast();
    if unsafe { IsValidSid(ace_sid) } == 0
        || unsafe { EqualSid(ace_sid, process_sid.as_psid()) } == 0
    {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    let sid_bytes = unsafe { GetLengthSid(ace_sid) } as usize;
    if offset_of!(ACCESS_ALLOWED_ACE, SidStart) + sid_bytes > usize::from(ace.Header.AceSize) {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    Ok(())
}

struct SecurityView {
    allocation: LocalMemory,
    owner: PSID,
    dacl: *mut ACL,
}

fn read_security(handle: &OwnedHandle, information: u32) -> Result<SecurityView, StorageError> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            raw_handle(handle),
            SE_FILE_OBJECT,
            information,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(StorageErrorKind::UnsafeStatePath, status));
    }
    let allocation = LocalMemory::new(descriptor)?;
    Ok(SecurityView {
        allocation,
        owner,
        dacl,
    })
}

fn sid_to_string(sid: PSID) -> Result<String, StorageError> {
    let mut pointer = null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut pointer) };
    if converted == 0 {
        return Err(last_error(StorageErrorKind::StateDirectoryUnavailable));
    }
    let allocation = LocalMemory::new(pointer.cast())?;
    let mut length = 0;
    while length < MAX_SID_STRING_UNITS && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == MAX_SID_STRING_UNITS {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    let units = unsafe { std::slice::from_raw_parts(pointer, length) };
    let string = String::from_utf16(units)
        .map_err(|source| StorageError::with_source(StorageErrorKind::UnsafeStatePath, source))?;
    drop(allocation);
    Ok(string)
}

fn wide_path(path: &Path) -> Result<Vec<u16>, StorageError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    wide.push(0);
    Ok(wide)
}

fn wide_string(value: &str) -> Result<Vec<u16>, StorageError> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    if wide.contains(&0) {
        return Err(StorageError::new(StorageErrorKind::UnsafeStatePath));
    }
    wide.push(0);
    Ok(wide)
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}

fn last_error(kind: StorageErrorKind) -> StorageError {
    let code = unsafe { GetLastError() };
    win32_error(kind, code)
}

fn win32_error(kind: StorageErrorKind, code: u32) -> StorageError {
    StorageError::with_source(kind, io::Error::from_raw_os_error(code as i32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_leaf(state: &SecureStateDirectory, file_name: &str, create: bool) -> File {
        match state.open_private_leaf(file_name, create, StorageErrorKind::OpenFailed) {
            Ok(Some(file)) => file,
            Ok(None) => panic!("the test leaf should exist"),
            Err(error) => panic!(
                "secure leaf open failed: {error}; source={:?}",
                std::error::Error::source(&error).map(ToString::to_string)
            ),
        }
    }

    #[test]
    fn token_default_owner_leaf_is_canonicalized_to_process_user() {
        let temporary_parent = tempfile::tempdir().expect("create temporary parent");
        let state_root = temporary_parent.path().join("state");
        let state = SecureStateDirectory::prepare(&state_root).expect("prepare state root");
        std::fs::write(state_root.join("owner-probe.sqlite3"), b"owner probe")
            .expect("create a leaf with the token's default owner");

        let file = open_test_leaf(&state, "owner-probe.sqlite3", false);
        file.try_lock()
            .expect("the canonical data handle should support ownership locking");
    }

    #[test]
    fn newly_created_private_leaf_supports_ownership_locking() {
        let temporary_parent = tempfile::tempdir().expect("create temporary parent");
        let state_root = temporary_parent.path().join("state");
        let state = SecureStateDirectory::prepare(&state_root).expect("prepare state root");

        let file = open_test_leaf(&state, "satelle.sqlite3.lock", true);
        file.try_lock()
            .expect("the newly created data handle should support ownership locking");
    }
}
