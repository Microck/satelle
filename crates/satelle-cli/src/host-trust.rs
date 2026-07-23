use satelle_core::{
    DesktopSessionPreference, ErrorCode, SatelleError, read_owner_controlled_config_file,
};
use serde::Serialize;
use std::fs;
#[cfg(unix)]
use std::fs::Permissions;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
#[cfg(windows)]
use tempfile::{Builder as TempFileBuilder, TempPath};
use toml_edit::{DocumentMut, value};

#[derive(Debug, Serialize)]
pub(crate) struct HostTrustReport {
    schema_version: &'static str,
    host: String,
    endpoint: String,
    observed_host_identity: String,
    previous_expected_host_identity: Option<String>,
    changed: bool,
}

impl HostTrustReport {
    pub(crate) fn new(
        host: impl Into<String>,
        endpoint: impl Into<String>,
        observed_host_identity: impl Into<String>,
        previous_expected_host_identity: Option<String>,
        changed: bool,
    ) -> Self {
        Self {
            schema_version: "satelle.host.trust.v1",
            host: host.into(),
            endpoint: endpoint.into(),
            observed_host_identity: observed_host_identity.into(),
            previous_expected_host_identity,
            changed,
        }
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn observed_host_identity(&self) -> &str {
        &self.observed_host_identity
    }

    pub(crate) fn previous_expected_host_identity(&self) -> Option<&str> {
        self.previous_expected_host_identity.as_deref()
    }

    pub(crate) const fn changed(&self) -> bool {
        self.changed
    }
}

pub(crate) fn persist_host_identity(
    config_path: &Path,
    host_alias: &str,
    observed_identity: &str,
) -> Result<bool, SatelleError> {
    let original = read_owner_controlled_config_file(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not read the user configuration securely",
            Some(error.to_string()),
        )
    })?;
    let mut document = original.parse::<DocumentMut>().map_err(|error| {
        trust_config_error(
            config_path,
            "could not parse the user configuration for Host trust",
            Some(error.to_string()),
        )
    })?;
    let hosts = document
        .get_mut("hosts")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                "the user configuration does not contain a hosts table",
                None,
            )
        })?;
    let host = hosts
        .get_mut(host_alias)
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                &format!("the user configuration does not contain Host Binding {host_alias}"),
                None,
            )
        })?;
    if host
        .get("expected_host_id")
        .and_then(toml_edit::Item::as_str)
        == Some(observed_identity)
    {
        return Ok(false);
    }
    host.insert("expected_host_id", value(observed_identity));
    persist_config(config_path, document.to_string().as_bytes())?;
    Ok(true)
}

pub(crate) fn persist_desktop_selection(
    config_path: &Path,
    host_alias: &str,
    desktop_user: &str,
    preference: Option<&DesktopSessionPreference>,
) -> Result<bool, SatelleError> {
    let original = read_owner_controlled_config_file(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not read the user configuration securely",
            Some(error.to_string()),
        )
    })?;
    let mut document = original.parse::<DocumentMut>().map_err(|error| {
        trust_config_error(
            config_path,
            "could not parse the user configuration for desktop selection",
            Some(error.to_string()),
        )
    })?;
    let hosts = document
        .get_mut("hosts")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                "the user configuration does not contain a hosts table",
                None,
            )
        })?;
    let host = hosts
        .get_mut(host_alias)
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                &format!("the user configuration does not contain Host Binding {host_alias}"),
                None,
            )
        })?;
    let preference = preference.map(|value| match value {
        DesktopSessionPreference::Only => "only",
        DesktopSessionPreference::Console => "console",
    });
    let unchanged = host.get("desktop_user").and_then(toml_edit::Item::as_str)
        == Some(desktop_user)
        && host
            .get("desktop_session_preference")
            .and_then(toml_edit::Item::as_str)
            == preference
        && host.get("desktop_session_native_selector").is_none();
    if unchanged {
        return Ok(false);
    }

    host.insert("desktop_user", value(desktop_user));
    if let Some(preference) = preference {
        host.insert("desktop_session_preference", value(preference));
    } else {
        host.remove("desktop_session_preference");
    }
    host.remove("desktop_session_native_selector");
    persist_config(config_path, document.to_string().as_bytes())?;
    Ok(true)
}

fn persist_config(config_path: &Path, contents: &[u8]) -> Result<(), SatelleError> {
    let metadata = fs::symlink_metadata(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not inspect the user configuration",
            Some(error.to_string()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(trust_config_error(
            config_path,
            "the user configuration is not a regular file",
            None,
        ));
    }
    #[cfg(windows)]
    let original_security = windows_security(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not preserve the user configuration owner and DACL",
            Some(error.to_string()),
        )
    })?;
    let parent = config_path.parent().ok_or_else(|| {
        trust_config_error(
            config_path,
            "the user configuration has no parent directory",
            None,
        )
    })?;
    #[cfg(windows)]
    let mut temporary = windows_staging_file(parent, &original_security).map_err(|error| {
        trust_config_error(
            config_path,
            "could not create a restricted temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    #[cfg(not(windows))]
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        trust_config_error(
            config_path,
            "could not create a temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    temporary.write_all(contents).map_err(|error| {
        trust_config_error(
            config_path,
            "could not write the temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    #[cfg(unix)]
    preserve_permissions(temporary.as_file(), metadata.permissions()).map_err(|error| {
        trust_config_error(
            config_path,
            "could not preserve user configuration permissions",
            Some(error.to_string()),
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        trust_config_error(
            config_path,
            "could not synchronize the temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    #[cfg(unix)]
    temporary.persist(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not atomically replace the user configuration",
            Some(error.error.to_string()),
        )
    })?;
    #[cfg(windows)]
    persist_windows_config(temporary, config_path, &original_security).map_err(|error| {
        trust_config_error(
            config_path,
            "could not atomically replace the user configuration while preserving its owner and DACL",
            Some(error.to_string()),
        )
    })?;
    #[cfg(not(any(unix, windows)))]
    temporary.persist(config_path).map_err(|error| {
        trust_config_error(
            config_path,
            "could not atomically replace the user configuration",
            Some(error.error.to_string()),
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn preserve_permissions(file: &fs::File, permissions: Permissions) -> std::io::Result<()> {
    file.set_permissions(permissions)
}

#[cfg(windows)]
fn persist_windows_config(
    temporary: NamedTempFile,
    config_path: &Path,
    original_security: &WindowsSecurity,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        ERROR_UNABLE_TO_MOVE_REPLACEMENT, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2,
    };
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let mut replacement_path = temporary.into_temp_path();
    // Supplying a named backup makes every documented partial ReplaceFileW
    // outcome recoverable: the original either remains at config_path or is
    // moved to this exact path.
    let mut backup_path = NamedTempFile::new_in(
        config_path
            .parent()
            .expect("validated configuration path has a parent"),
    )?
    .into_temp_path();
    fs::remove_file(&backup_path)?;
    let replaced = config_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replacement = replacement_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let backup = backup_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            backup.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        let replace_error = std::io::Error::last_os_error();
        match replace_error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT) => {
                // With lpBackupFileName supplied, both inputs retain their
                // original names and the existing configuration remains live.
            }
            Some(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2) => {
                // Windows moved the original to the requested backup name but
                // could not move the replacement. Restore the known-good file
                // before the temporary replacement is cleaned up.
                if let Err(restore_error) = move_windows_file_replacing(&backup_path, config_path) {
                    let preserved_path = replacement_path.to_path_buf();
                    let preserved_backup_path = backup_path.to_path_buf();
                    replacement_path.disable_cleanup(true);
                    backup_path.disable_cleanup(true);
                    return Err(std::io::Error::new(
                        restore_error.kind(),
                        format!(
                            "{replace_error}; restoring the original configuration failed: {restore_error}; the replacement remains at {} and the original remains at {}",
                            preserved_path.display(),
                            preserved_backup_path.display()
                        ),
                    ));
                }
            }
            _ => {}
        }
        return Err(replace_error);
    }

    let validation = (|| {
        let replacement_security = windows_security(config_path)?;
        if replacement_security != *original_security {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the replacement owner or DACL differs from the original user configuration",
            ));
        }
        read_owner_controlled_config_file(config_path)
            .map(|_| ())
            .map_err(std::io::Error::other)
    })();
    if let Err(validation_error) = validation {
        return Err(rollback_windows_replacement(
            &mut backup_path,
            config_path,
            validation_error,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn move_windows_file_replacing(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn rollback_windows_replacement(
    backup_path: &mut TempPath,
    config_path: &Path,
    validation_error: std::io::Error,
) -> std::io::Error {
    if let Err(restore_error) = move_windows_file_replacing(backup_path, config_path) {
        let preserved_backup_path = backup_path.to_path_buf();
        backup_path.disable_cleanup(true);
        return std::io::Error::new(
            restore_error.kind(),
            format!(
                "{validation_error}; restoring the original configuration failed: {restore_error}; the original remains at {}",
                preserved_backup_path.display()
            ),
        );
    }
    validation_error
}

#[cfg(windows)]
struct WindowsSecurity {
    owner: Vec<u8>,
    dacl: Vec<u8>,
    descriptor: Box<[usize]>,
}

#[cfg(windows)]
impl PartialEq for WindowsSecurity {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.dacl == other.dacl
    }
}

#[cfg(windows)]
impl Eq for WindowsSecurity {}

#[cfg(windows)]
impl WindowsSecurity {
    fn descriptor(&self) -> *mut std::ffi::c_void {
        self.descriptor.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
fn windows_security(path: &Path) -> std::io::Result<WindowsSecurity> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetLengthSid, GetSecurityDescriptorLength, IsValidAcl,
        IsValidSid, OWNER_SECURITY_INFORMATION,
    };

    struct LocalSecurityDescriptor(*mut std::ffi::c_void);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the user configuration has no valid owner or DACL",
        ));
    }
    let owner_size = unsafe { GetLengthSid(owner) } as usize;
    let dacl_size = usize::from(unsafe { &*dacl }.AclSize);
    let descriptor_size = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if descriptor_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the user configuration has no valid security descriptor",
        ));
    }
    // SECURITY_ATTRIBUTES requires the complete security descriptor, not
    // separate owner and DACL pointers. usize storage preserves its alignment.
    let mut descriptor_copy =
        vec![0_usize; descriptor_size.div_ceil(std::mem::size_of::<usize>())].into_boxed_slice();
    unsafe {
        std::ptr::copy_nonoverlapping(
            descriptor.cast::<u8>(),
            descriptor_copy.as_mut_ptr().cast::<u8>(),
            descriptor_size,
        );
    }
    Ok(WindowsSecurity {
        owner: unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_size) }.to_vec(),
        dacl: unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), dacl_size) }.to_vec(),
        descriptor: descriptor_copy,
    })
}

#[cfg(windows)]
fn windows_staging_file(
    parent: &Path,
    security: &WindowsSecurity,
) -> std::io::Result<NamedTempFile> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.descriptor(),
        bInheritHandle: 0,
    };
    TempFileBuilder::new().make_in(parent, |path| {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // CreateFileW returned one uniquely owned, non-pseudo file handle.
        Ok(unsafe { fs::File::from_raw_handle(raw) })
    })
}

fn trust_config_error(
    config_path: &Path,
    message: &str,
    source_detail: Option<String>,
) -> SatelleError {
    SatelleError {
        code: ErrorCode::ConfigError,
        message: format!("{message}: {}", config_path.display()),
        recovery_command: Some(
            "repair the user-level Host Binding and retry satelle host trust".to_string(),
        ),
        source_detail,
        details: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use satelle_core::open_or_create_owner_only_directory;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn secure_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let parent = tempfile::tempdir().expect("create temporary config parent");
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("chmod")
                .arg("-N")
                .arg(parent.path())
                .status()
                .expect("remove inherited macOS ACLs from the config fixture");
            assert!(status.success(), "macOS chmod must remove inherited ACLs");
        }
        #[cfg(unix)]
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure temporary config parent");
        let directory = parent.path().join("config");
        #[cfg(unix)]
        drop(
            open_or_create_owner_only_directory(&directory)
                .expect("create owner-only config directory"),
        );
        #[cfg(windows)]
        {
            fs::create_dir(&directory).expect("create Windows config directory");
            let user = current_windows_user_sid();
            set_windows_acl(
                &directory,
                &[
                    format!("*{user}:(OI)(CI)(F)"),
                    "*S-1-5-18:(OI)(CI)(F)".to_string(),
                    "*S-1-5-32-544:(OI)(CI)(F)".to_string(),
                    "*S-1-1-0:(OI)(CI)(M)".to_string(),
                ],
            );
        }
        let path = directory.join("config.toml");
        fs::write(&path, contents).expect("write user configuration");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("secure user configuration");
        #[cfg(windows)]
        {
            let user = current_windows_user_sid();
            set_windows_owner(&path, &user);
            set_windows_acl(
                &path,
                &[
                    format!("*{user}:(F)"),
                    "*S-1-5-18:(F)".to_string(),
                    "*S-1-5-32-544:(F)".to_string(),
                ],
            );
        }
        (parent, path)
    }

    #[test]
    fn host_identity_update_preserves_unrelated_toml_and_is_idempotent() {
        let original = concat!(
            "# keep this comment\n",
            "default_host = \"remote\"\n\n",
            "[hosts.remote]\n",
            "transport = \"direct\" # keep inline comment\n",
            "adapter = \"codex\"\n",
            "address = \"https://host.example.test\"\n",
        );
        let (_directory, config) = secure_config(original);
        #[cfg(windows)]
        let original_acl = windows_acl_listing(&config);

        assert!(persist_host_identity(&config, "remote", "host-observed").unwrap());
        let updated = fs::read_to_string(&config).unwrap();
        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("transport = \"direct\" # keep inline comment"));
        assert!(updated.contains("expected_host_id = \"host-observed\""));
        assert!(!persist_host_identity(&config, "remote", "host-observed").unwrap());
        assert_eq!(fs::read_to_string(&config).unwrap(), updated);
        #[cfg(windows)]
        {
            assert_eq!(windows_acl_listing(&config), original_acl);
            assert!(read_owner_controlled_config_file(&config).is_ok());
        }
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_staging_file_is_restricted_before_contents_are_written() {
        let (_directory, config) =
            secure_config("[hosts.remote]\ntransport = \"direct\"\nadapter = \"codex\"\n");
        let original_security = windows_security(&config).expect("read original security");

        let staging = windows_staging_file(
            config.parent().expect("configuration has a parent"),
            &original_security,
        )
        .expect("create restricted staging file");

        assert_eq!(
            fs::metadata(staging.path())
                .expect("read staging metadata")
                .len(),
            0,
            "security must be installed before configuration contents are written"
        );
        assert!(
            windows_security(staging.path()).expect("read staging security") == original_security,
            "the staging file must not retain the broadly writable parent DACL"
        );
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open(staging.path())
                .is_err(),
            "no second writer may open the staging file while its contents are prepared"
        );
    }

    #[test]
    fn host_identity_update_requires_an_existing_user_binding() {
        let contents = "[hosts.other]\ntransport = \"local\"\nadapter = \"fake\"\n";
        let (_directory, config) = secure_config(contents);

        let error = persist_host_identity(&config, "remote", "host-observed").unwrap_err();
        assert_eq!(error.code, ErrorCode::ConfigError);
        assert_eq!(fs::read_to_string(&config).unwrap(), contents);
    }

    #[cfg(windows)]
    #[test]
    fn failed_replacement_validation_restores_the_original_config() {
        let directory = tempfile::tempdir().expect("create replacement test directory");
        let config = directory.path().join("config.toml");
        fs::write(&config, "replacement").expect("write invalid replacement");
        let mut backup = NamedTempFile::new_in(directory.path()).expect("create original backup");
        backup
            .write_all(b"original")
            .expect("write original backup");
        let mut backup = backup.into_temp_path();

        let validation_error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "replacement validation failed",
        );
        let returned = rollback_windows_replacement(&mut backup, &config, validation_error);

        assert_eq!(returned.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::read_to_string(&config).expect("read restored config"),
            "original"
        );
        assert!(!backup.exists(), "the original moved back to its live path");
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
    fn set_windows_acl(path: &Path, entries: &[String]) {
        run_icacls(path, &["/inheritance:r"], "disable ACL inheritance");
        let mut grants = vec!["/grant:r".to_string()];
        grants.extend(entries.iter().cloned());
        run_icacls(
            path,
            &grants.iter().map(String::as_str).collect::<Vec<_>>(),
            "install the requested ACL grants",
        );
    }

    #[cfg(windows)]
    fn set_windows_owner(path: &Path, user: &str) {
        let owner = format!("*{user}");
        run_icacls(
            path,
            &["/setowner", &owner],
            "set the Windows fixture owner",
        );
    }

    #[cfg(windows)]
    fn run_icacls(path: &Path, arguments: &[&str], operation: &str) {
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
    fn windows_acl_listing(path: &Path) -> String {
        let output = std::process::Command::new("icacls.exe")
            .arg(path)
            .output()
            .expect("read Windows ACL");
        assert!(
            output.status.success(),
            "icacls ACL read failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("icacls output should be UTF-8")
    }
}
