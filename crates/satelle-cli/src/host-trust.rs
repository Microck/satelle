use satelle_core::{
    DesktopSessionPreference, ErrorCode, LOCAL_DEMO_HOST, ProviderSecretSource, SatelleConfig,
    SatelleError, open_or_create_owner_only_directory, persist_new_owner_only_config_file,
    read_owner_controlled_config_file,
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
use toml_edit::{DocumentMut, Item, Table, value};

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
    persist_config(config_path, document.to_string().as_bytes(), None)?;
    Ok(true)
}

pub(crate) fn persist_desktop_selection(
    config_path: &Path,
    host_alias: &str,
    desktop_user: &str,
    preference: Option<&DesktopSessionPreference>,
    recovery_command: &str,
) -> Result<bool, SatelleError> {
    let (original, new_config) = match read_owner_controlled_config_file(config_path) {
        Ok(original) => (original, false),
        Err(_)
            if host_alias == LOCAL_DEMO_HOST
                && matches!(fs::symlink_metadata(config_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound) =>
        {
            (String::new(), true)
        }
        Err(error) => {
            return Err(config_error_with_recovery(
                config_path,
                "could not read the user configuration securely",
                Some(error.to_string()),
                recovery_command,
            ));
        }
    };
    let mut document = if new_config {
        default_user_document(config_path, recovery_command)?
    } else {
        original.parse::<DocumentMut>().map_err(|error| {
            config_error_with_recovery(
                config_path,
                "could not parse the user configuration for desktop selection",
                Some(error.to_string()),
                recovery_command,
            )
        })?
    };
    if host_alias == LOCAL_DEMO_HOST && document.get("hosts").is_none() {
        let defaults = default_user_document(config_path, recovery_command)?;
        document.insert("hosts", defaults["hosts"].clone());
    }
    let hosts = document
        .get_mut("hosts")
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            config_error_with_recovery(
                config_path,
                "the user configuration does not contain a hosts table",
                None,
                recovery_command,
            )
        })?;
    if host_alias == LOCAL_DEMO_HOST && hosts.get(host_alias).is_none() {
        let defaults = default_user_document(config_path, recovery_command)?;
        let local = defaults["hosts"][LOCAL_DEMO_HOST].clone();
        hosts.insert(host_alias, local);
    }
    let host = hosts
        .get_mut(host_alias)
        .and_then(toml_edit::Item::as_table_like_mut)
        .ok_or_else(|| {
            config_error_with_recovery(
                config_path,
                &format!("the user configuration does not contain Host Binding {host_alias}"),
                None,
                recovery_command,
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
    let contents = document.to_string();
    if new_config {
        persist_new_config(config_path, contents.as_bytes(), recovery_command)?;
    } else {
        persist_config(config_path, contents.as_bytes(), Some(recovery_command))?;
    }
    Ok(true)
}

fn default_user_document(
    config_path: &Path,
    recovery_command: &str,
) -> Result<DocumentMut, SatelleError> {
    let encoded = toml::to_string(&SatelleConfig::defaults()).map_err(|error| {
        config_error_with_recovery(
            config_path,
            "could not serialize the built-in local Host Binding",
            Some(error.to_string()),
            recovery_command,
        )
    })?;
    encoded.parse::<DocumentMut>().map_err(|error| {
        config_error_with_recovery(
            config_path,
            "could not prepare the built-in local Host Binding",
            Some(error.to_string()),
            recovery_command,
        )
    })
}

fn persist_new_config(
    config_path: &Path,
    contents: &[u8],
    recovery_command: &str,
) -> Result<(), SatelleError> {
    let parent = config_path.parent().ok_or_else(|| {
        config_error_with_recovery(
            config_path,
            "the user configuration has no parent directory",
            None,
            recovery_command,
        )
    })?;
    create_owner_only_directory_tree(parent, config_path, recovery_command)?;
    persist_new_owner_only_config_file(config_path, contents).map_err(|error| {
        config_error_with_recovery(
            config_path,
            "could not atomically create the owner-only user configuration",
            Some(error.to_string()),
            recovery_command,
        )
    })
}

fn create_owner_only_directory_tree(
    directory: &Path,
    config_path: &Path,
    recovery_command: &str,
) -> Result<(), SatelleError> {
    let mut missing = Vec::new();
    let mut current = directory;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current);
                current = current.parent().ok_or_else(|| {
                    config_error_with_recovery(
                        config_path,
                        "the user configuration directory has no existing ancestor",
                        None,
                        recovery_command,
                    )
                })?;
            }
            Err(error) => {
                return Err(config_error_with_recovery(
                    config_path,
                    "could not inspect the user configuration directory",
                    Some(error.to_string()),
                    recovery_command,
                ));
            }
        }
    }
    for path in missing.into_iter().rev() {
        drop(open_or_create_owner_only_directory(path).map_err(|error| {
            config_error_with_recovery(
                config_path,
                "could not create the owner-only user configuration directory",
                Some(error.to_string()),
                recovery_command,
            )
        })?);
    }
    drop(
        open_or_create_owner_only_directory(directory).map_err(|error| {
            config_error_with_recovery(
                config_path,
                "could not open the owner-only user configuration directory",
                Some(error.to_string()),
                recovery_command,
            )
        })?,
    );
    Ok(())
}

pub(crate) fn persist_provider_auth_descriptor(
    config_path: &Path,
    host_alias: &str,
    auth_source_name: &str,
    descriptor: &ProviderSecretSource,
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
            "could not parse the user configuration for provider authentication",
            Some(error.to_string()),
        )
    })?;
    let hosts = document
        .get_mut("hosts")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                "the user configuration does not contain a hosts table",
                None,
            )
        })?;
    let host = hosts
        .get_mut(host_alias)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                &format!("the user configuration does not contain Host Binding {host_alias}"),
                None,
            )
        })?;
    if host.get("provider_auth").is_none() {
        host.insert("provider_auth", Item::Table(Table::new()));
    }
    let provider_auth = host
        .get_mut("provider_auth")
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| {
            trust_config_error(
                config_path,
                "the Host Binding provider_auth value is not a table",
                None,
            )
        })?;
    let descriptor = provider_secret_source_item(descriptor);
    if provider_auth.get(auth_source_name).is_some_and(|existing| {
        provider_secret_source_item_matches(
            existing,
            descriptor
                .as_table()
                .expect("provider secret descriptors are tables"),
        )
    }) {
        return Ok(false);
    }
    provider_auth.insert(auth_source_name, descriptor);
    persist_config(config_path, document.to_string().as_bytes(), None)?;
    Ok(true)
}

fn provider_secret_source_item_matches(existing: &Item, expected: &Table) -> bool {
    let Some(existing) = existing.as_table_like() else {
        return false;
    };
    existing.len() == expected.len()
        && expected
            .iter()
            .all(|(key, value)| existing.get(key).and_then(Item::as_str) == value.as_str())
}

fn provider_secret_source_item(descriptor: &ProviderSecretSource) -> Item {
    let mut table = Table::new();
    match descriptor {
        ProviderSecretSource::Environment { variable } => {
            table.insert("kind", value("environment"));
            table.insert("variable", value(variable));
        }
        ProviderSecretSource::File { path } => {
            table.insert("kind", value("file"));
            table.insert("path", value(path.to_string_lossy().as_ref()));
        }
        ProviderSecretSource::CredentialStore { service, account } => {
            table.insert("kind", value("credential-store"));
            table.insert("service", value(service));
            table.insert("account", value(account));
        }
        ProviderSecretSource::HostStore { name } => {
            table.insert("kind", value("host-store"));
            table.insert("name", value(name));
        }
    }
    Item::Table(table)
}

fn persist_config(
    config_path: &Path,
    contents: &[u8],
    recovery_command: Option<&str>,
) -> Result<(), SatelleError> {
    let config_error = |message: &str, source_detail: Option<String>| {
        config_error_with_recovery(
            config_path,
            message,
            source_detail,
            recovery_command
                .unwrap_or("repair the user-level Host Binding and retry satelle host trust"),
        )
    };
    let metadata = fs::symlink_metadata(config_path).map_err(|error| {
        config_error(
            "could not inspect the user configuration",
            Some(error.to_string()),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(config_error(
            "the user configuration is not a regular file",
            None,
        ));
    }
    #[cfg(windows)]
    let original_security = windows_security(config_path).map_err(|error| {
        config_error(
            "could not preserve the user configuration owner and DACL",
            Some(error.to_string()),
        )
    })?;
    let parent = config_path
        .parent()
        .ok_or_else(|| config_error("the user configuration has no parent directory", None))?;
    #[cfg(windows)]
    let mut temporary = windows_staging_file(parent, &original_security).map_err(|error| {
        config_error(
            "could not create a restricted temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    #[cfg(not(windows))]
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
        config_error(
            "could not create a temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    temporary.write_all(contents).map_err(|error| {
        config_error(
            "could not write the temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    #[cfg(unix)]
    preserve_permissions(temporary.as_file(), metadata.permissions()).map_err(|error| {
        config_error(
            "could not preserve user configuration permissions",
            Some(error.to_string()),
        )
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        config_error(
            "could not synchronize the temporary user configuration",
            Some(error.to_string()),
        )
    })?;
    #[cfg(unix)]
    temporary.persist(config_path).map_err(|error| {
        config_error(
            "could not atomically replace the user configuration",
            Some(error.error.to_string()),
        )
    })?;
    #[cfg(windows)]
    persist_windows_config(temporary, config_path, &original_security).map_err(|error| {
        config_error(
            "could not atomically replace the user configuration while preserving its owner and DACL",
            Some(error.to_string()),
        )
    })?;
    #[cfg(not(any(unix, windows)))]
    temporary.persist(config_path).map_err(|error| {
        config_error(
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
    config_error_with_recovery(
        config_path,
        message,
        source_detail,
        "repair the user-level Host Binding and retry satelle host trust",
    )
}

fn config_error_with_recovery(
    config_path: &Path,
    message: &str,
    source_detail: Option<String>,
    recovery_command: &str,
) -> SatelleError {
    SatelleError {
        code: ErrorCode::ConfigError,
        message: format!("{message}: {}", config_path.display()),
        recovery_command: Some(recovery_command.to_string()),
        source_detail,
        details: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use satelle_core::open_or_create_owner_only_directory;
    use satelle_core::{open_owner_only_directory, read_owner_only_secret_config_file};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    const SETUP_RECOVERY: &str = "satelle setup --host local-demo --on-demand --component computer-use --no-input --json --yes";

    fn secure_temporary_parent() -> tempfile::TempDir {
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
        parent
    }

    fn secure_config(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let parent = secure_temporary_parent();
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

    fn missing_config_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let parent = secure_temporary_parent();
        let path = parent
            .path()
            .join("Microck")
            .join("Satelle")
            .join("config")
            .join("config.toml");
        (parent, path)
    }

    #[test]
    fn desktop_selection_materializes_the_builtin_local_host_config() {
        let (_directory, config) = missing_config_path();

        assert!(
            persist_desktop_selection(
                &config,
                LOCAL_DEMO_HOST,
                "desktop-user",
                Some(&DesktopSessionPreference::Console),
                SETUP_RECOVERY,
            )
            .unwrap()
        );
        let persisted = read_owner_controlled_config_file(&config)
            .expect("read the materialized owner-controlled config");
        let parsed = toml::from_str::<SatelleConfig>(&persisted)
            .expect("load the materialized config through the typed contract");
        let local = &parsed.hosts[LOCAL_DEMO_HOST];
        let default_local = &SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST];
        assert_eq!(local.transport, default_local.transport);
        assert_eq!(local.adapter, default_local.adapter);
        assert_eq!(local.desktop_user.as_deref(), Some("desktop-user"));
        assert_eq!(
            local.desktop_session_preference,
            Some(DesktopSessionPreference::Console)
        );
        assert!(local.desktop_session_native_selector.is_none());
        read_owner_only_secret_config_file(&config)
            .expect("materialized config must be owner-only");
        drop(
            open_owner_only_directory(config.parent().expect("config has a parent"))
                .expect("materialized config directory must be owner-only"),
        );
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&config).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(config.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert!(
            !persist_desktop_selection(
                &config,
                LOCAL_DEMO_HOST,
                "desktop-user",
                Some(&DesktopSessionPreference::Console),
                SETUP_RECOVERY,
            )
            .unwrap()
        );
    }

    #[test]
    fn desktop_selection_does_not_materialize_a_remote_host_config() {
        let (_directory, config) = missing_config_path();

        let error = persist_desktop_selection(
            &config,
            "remote",
            "desktop-user",
            Some(&DesktopSessionPreference::Console),
            SETUP_RECOVERY,
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigError);
        assert_eq!(error.recovery_command.as_deref(), Some(SETUP_RECOVERY));
        assert!(!config.exists());
    }

    #[test]
    fn desktop_selection_adds_the_builtin_local_host_to_an_existing_config() {
        let (_directory, config) = secure_config("command_history = false\n");

        assert!(
            persist_desktop_selection(
                &config,
                LOCAL_DEMO_HOST,
                "desktop-user",
                Some(&DesktopSessionPreference::Only),
                SETUP_RECOVERY,
            )
            .unwrap()
        );
        let persisted = read_owner_controlled_config_file(&config)
            .expect("read the updated owner-controlled config");
        let parsed = toml::from_str::<SatelleConfig>(&persisted)
            .expect("load the updated config through the typed contract");
        let local = &parsed.hosts[LOCAL_DEMO_HOST];
        let default_local = &SatelleConfig::defaults().hosts[LOCAL_DEMO_HOST];
        assert_eq!(parsed.command_history, Some(false));
        assert_eq!(local.transport, default_local.transport);
        assert_eq!(local.adapter, default_local.adapter);
        assert_eq!(local.desktop_user.as_deref(), Some("desktop-user"));
        assert_eq!(
            local.desktop_session_preference,
            Some(DesktopSessionPreference::Only)
        );
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

    #[test]
    fn provider_auth_update_persists_only_the_descriptor_reference() {
        let original = concat!(
            "default_host = \"remote\"\n\n",
            "[hosts.remote]\n",
            "transport = \"direct\"\n",
            "adapter = \"codex\"\n",
            "address = \"https://host.example.test\"\n",
        );
        let (_directory, config) = secure_config(original);
        let descriptor = ProviderSecretSource::Environment {
            variable: "SATELLE_PROVIDER_TOKEN".to_string(),
        };

        assert!(
            persist_provider_auth_descriptor(&config, "remote", "openai", &descriptor).unwrap()
        );
        let updated = fs::read_to_string(&config).unwrap();
        assert!(updated.contains("[hosts.remote.provider_auth.openai]"));
        assert!(updated.contains("kind = \"environment\""));
        assert!(updated.contains("variable = \"SATELLE_PROVIDER_TOKEN\""));
        assert!(!updated.contains("secret"));
        assert!(
            !persist_provider_auth_descriptor(&config, "remote", "openai", &descriptor).unwrap()
        );
        assert_eq!(fs::read_to_string(&config).unwrap(), updated);
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
