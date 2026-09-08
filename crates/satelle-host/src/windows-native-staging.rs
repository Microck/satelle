use satelle_core::{OwnerOnlyDirectory, open_or_create_owner_only_directory};
use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_NAME, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

/// The bundled bridge writes its kernel assets before launching them under
/// CodexSandboxUsers. Keep those assets readable without admitting TEMP as a
/// writable root or changing permissions on the user's shared temp directory.
pub(super) struct WindowsNativeStaging {
    path: PathBuf,
    directory: Option<OwnerOnlyDirectory>,
}

impl WindowsNativeStaging {
    pub(super) fn create() -> io::Result<Self> {
        // Qualify the local group so a missing sandbox setup cannot resolve
        // an unrelated domain group with the same name.
        let mut computer = [0_u16; 16];
        let mut length = computer.len() as u32;
        if unsafe { GetComputerNameW(computer.as_mut_ptr(), &mut length) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let computer =
            String::from_utf16(&computer[..length as usize]).map_err(io::Error::other)?;
        Self::create_for_reader(&format!("{computer}\\CodexSandboxUsers"))
    }

    fn create_for_reader(reader: &str) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!("satelle-native-{}", uuid::Uuid::now_v7()));
        // The core directory guard creates a protected owner-only DACL
        // atomically and pins the directory and its ancestors against replacement.
        let directory = open_or_create_owner_only_directory(&path).map_err(io::Error::other)?;
        let staging = Self {
            path,
            directory: Some(directory),
        };
        grant_read_execute(&staging.path, reader)?;
        Ok(staging)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WindowsNativeStaging {
    fn drop(&mut self) {
        // The app-server owner outlives its process group. Release the pinned
        // Windows handles before removing the directory, including failed starts.
        drop(self.directory.take());
        if let Err(error) = fs::remove_dir_all(&self.path) {
            tracing::warn!(%error, "Could not remove Windows native staging directory");
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn grant_read_execute(path: &Path, reader: &str) -> io::Result<()> {
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut reader: Vec<u16> = reader.encode_utf16().chain(Some(0)).collect();
    let mut old_acl = null_mut();
    let mut descriptor = null_mut();
    // Both ACL APIs allocate with LocalAlloc. Keep the original descriptor
    // alive until the new ACL has been built and applied to the pinned directory.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old_acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalAllocation(descriptor);
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_NAME,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: reader.as_mut_ptr(),
        },
    };
    let mut new_acl = null_mut();
    let status = unsafe { SetEntriesInAclW(1, &access, old_acl, &mut new_acl) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _acl = LocalAllocation(new_acl.cast());
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            new_acl,
            null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{size_of, size_of_val};
    use windows_sys::Win32::Security::Authorization::GetEffectiveRightsFromAclW;
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, LookupAccountSidW, SECURITY_MAX_SID_SIZE, WinBuiltinUsersSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };

    #[test]
    fn staging_grants_only_read_execute_and_cleans_up() {
        // Resolve the built-in Users group by SID so the test also works on
        // localized Windows installations, without installing Codex users.
        let mut sid = [0_u32; SECURITY_MAX_SID_SIZE as usize / size_of::<u32>()];
        let mut sid_bytes = size_of_val(&sid) as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinBuiltinUsersSid,
                    null_mut(),
                    sid.as_mut_ptr().cast(),
                    &mut sid_bytes,
                )
            },
            0
        );
        let mut name = [0_u16; 256];
        let mut domain = [0_u16; 256];
        let mut name_length = name.len() as u32;
        let mut domain_length = domain.len() as u32;
        let mut sid_use = 0;
        assert_ne!(
            unsafe {
                LookupAccountSidW(
                    std::ptr::null(),
                    sid.as_mut_ptr().cast(),
                    name.as_mut_ptr(),
                    &mut name_length,
                    domain.as_mut_ptr(),
                    &mut domain_length,
                    &mut sid_use,
                )
            },
            0
        );
        let reader = format!(
            "{}\\{}",
            String::from_utf16(&domain[..domain_length as usize]).unwrap(),
            String::from_utf16(&name[..name_length as usize]).unwrap(),
        );
        let staging =
            WindowsNativeStaging::create_for_reader(&reader).expect("create native staging");
        let path = staging.path().to_path_buf();
        let script = path.join("kernel.js");
        fs::write(&script, "console.log(2)").expect("the Host can stage its script");
        let wide: Vec<u16> = script.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        assert_eq!(
            unsafe {
                GetNamedSecurityInfoW(
                    wide.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    &mut acl,
                    null_mut(),
                    &mut descriptor,
                )
            },
            ERROR_SUCCESS
        );
        let _descriptor = LocalAllocation(descriptor);
        let mut reader: Vec<u16> = reader.encode_utf16().chain(Some(0)).collect();
        let trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_NAME,
            TrusteeType: TRUSTEE_IS_GROUP,
            ptstrName: reader.as_mut_ptr(),
        };
        let mut rights = 0;
        assert_eq!(
            unsafe { GetEffectiveRightsFromAclW(acl, &trustee, &mut rights) },
            ERROR_SUCCESS
        );
        let readable = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
        assert_eq!(rights & readable, readable);
        assert_eq!(
            rights
                & (FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | FILE_DELETE_CHILD
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER),
            0
        );
        drop(staging);
        assert!(!path.exists(), "session-owned staging must be removed");
    }
}
