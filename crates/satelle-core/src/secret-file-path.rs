use crate::{ErrorCode, SatelleError};
use serde_json::json;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SecretFilePathError {
    #[error("the provider secret file path must be absolute for the resolving Host")]
    NotAbsolute,
    #[error("the provider secret file path uses unsupported home or shell syntax")]
    TildeFormUnsupported,
    #[error("the resolving Host account has no available absolute home directory")]
    HomeUnavailable,
}

impl SecretFilePathError {
    /// Source locations can be unknown for Host-owned registry bindings. Keep
    /// the diagnostic shape stable without inventing a config path or alias.
    pub fn diagnostic(
        self,
        config_file: Option<&Path>,
        toml_path: Option<&str>,
        host: Option<&str>,
        resolver_os: Option<&str>,
    ) -> SatelleError {
        let supported_forms: &[&str] = match resolver_os {
            Some("windows") | None => &["~", "~/", "~\\"],
            Some(_) => &["~", "~/"],
        };
        SatelleError {
            code: match self {
                Self::NotAbsolute => ErrorCode::SecretFilePathNotAbsolute,
                Self::TildeFormUnsupported => ErrorCode::SecretFileTildeFormUnsupported,
                Self::HomeUnavailable => ErrorCode::SecretFileHomeUnavailable,
            },
            message: self.to_string(),
            recovery_command: Some(
                "configure an absolute provider secret file path on the target Host".to_string(),
            ),
            source_detail: None,
            details: [
                ("config_file".to_string(), json!(config_file)),
                ("toml_path".to_string(), json!(toml_path)),
                ("host".to_string(), json!(host)),
                ("secret_source_kind".to_string(), json!("file")),
                ("resolver_os".to_string(), json!(resolver_os)),
                ("supported_forms".to_string(), json!(supported_forms)),
            ]
            .into(),
        }
    }
}

/// Validates the closed detail envelope at either side of the Host transport.
pub fn secret_file_error_details(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    let fields = value.as_object()?;
    if fields.len() != 6 || fields.get("secret_source_kind")?.as_str()? != "file" {
        return None;
    }
    for key in ["config_file", "toml_path", "host"] {
        let field = fields.get(key)?;
        if !field.is_null() && !field.is_string() {
            return None;
        }
    }
    let supported: &[&str] = match fields.get("resolver_os")? {
        serde_json::Value::Null => &["~", "~/", "~\\"],
        serde_json::Value::String(os) if os == "windows" => &["~", "~/", "~\\"],
        serde_json::Value::String(os) if matches!(os.as_str(), "linux" | "macos") => &["~", "~/"],
        _ => return None,
    };
    let forms = fields.get("supported_forms")?.as_array()?;
    (forms.len() == supported.len()
        && forms
            .iter()
            .zip(supported)
            .all(|(form, expected)| form.as_str() == Some(*expected)))
    .then_some(fields)
}

/// Checks input grammar without finding a home or opening the secret file.
/// Controllers pass None until the resolving Host's platform is known.
pub fn validate_secret_file_path(
    path: &Path,
    windows: Option<bool>,
) -> Result<(), SecretFilePathError> {
    let path = path.to_str().ok_or(SecretFilePathError::NotAbsolute)?;
    if path.contains('\0') || path.is_empty() {
        return Err(SecretFilePathError::NotAbsolute);
    }
    if crate::interpolation_syntax(path).is_some() || path.contains("$(") || path.contains('`') {
        return Err(SecretFilePathError::TildeFormUnsupported);
    }
    if let Some(suffix) = path.strip_prefix('~') {
        let tail = suffix.get(1..).unwrap_or_default();
        // A Windows drive prefix would make Path::join replace the account
        // home instead of resolving a path beneath that home.
        let drive_prefixed_tail = windows == Some(true)
            && tail.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && tail.as_bytes().get(1) == Some(&b':');
        if misplaced_home_component(suffix, windows)
            || !(suffix.is_empty()
                || suffix.starts_with('/')
                || (windows != Some(false) && suffix.starts_with('\\')))
            || tail.starts_with(['/', '\\'])
            || drive_prefixed_tail
        {
            return Err(SecretFilePathError::TildeFormUnsupported);
        }
        return Ok(());
    }
    if misplaced_home_component(path, windows) {
        return Err(SecretFilePathError::TildeFormUnsupported);
    }
    let valid = match windows {
        Some(true) => absolute_windows_path(path),
        Some(false) => path.starts_with('/'),
        None => path.starts_with('/') || absolute_windows_path(path),
    };
    valid.then_some(()).ok_or(SecretFilePathError::NotAbsolute)
}

fn misplaced_home_component(path: &str, windows: Option<bool>) -> bool {
    // Tildes inside filenames are literal, including Windows short names.
    // Only a component beginning with ~ resembles unsupported home syntax.
    path.split(|character| character == '/' || (windows != Some(false) && character == '\\'))
        .any(|component| component.starts_with('~'))
}

fn absolute_windows_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
    {
        return true;
    }
    let Some(rest) = path.strip_prefix(r"\\").or_else(|| path.strip_prefix("//")) else {
        return false;
    };
    let mut components = rest.split(['/', '\\']).filter(|part| !part.is_empty());
    matches!(
        (components.next(), components.next()),
        (Some(server), Some(share))
            if !matches!(server, "." | ".." | "?") && !matches!(share, "." | "..")
    )
}

/// Produces the effective native absolute path. This is lexical expansion;
/// file existence, ownership, and contents remain the secret reader's job.
pub fn expand_secret_file_path(
    path: &Path,
    home: Option<&Path>,
) -> Result<PathBuf, SecretFilePathError> {
    validate_secret_file_path(path, Some(cfg!(windows)))?;
    let text = path
        .to_str()
        .expect("validated secret file paths are UTF-8");
    let expanded = if let Some(suffix) = text.strip_prefix('~') {
        let home = home
            .filter(|home| home.is_absolute())
            .ok_or(SecretFilePathError::HomeUnavailable)?;
        home.join(suffix.get(1..).unwrap_or_default())
    } else {
        path.to_path_buf()
    };
    // Normalize . and .. without following symlinks or reading the filesystem.
    let mut normalized = PathBuf::new();
    for component in expanded.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

/// The OS account running this process owns provider resolution. Environment
/// overrides and desktop/SSH account selections must not redirect its home.
#[cfg(unix)]
pub fn resolver_account_home() -> Option<PathBuf> {
    use std::ffi::{CStr, OsString};
    use std::os::unix::ffi::OsStringExt;

    // Account backends can need a larger buffer than a local passwd entry.
    // Grow only on ERANGE, with a finite cap on account lookup allocation.
    let mut buffer = vec![0_u8; 4096];
    loop {
        let mut account = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: all output pointers have the documented writable capacity.
        // Returned strings live in buffer and are copied before it is dropped.
        let status = unsafe {
            libc::getpwuid_r(
                libc::geteuid(),
                account.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer.len() < 64 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        if status != 0 || found.is_null() {
            return None;
        }
        // SAFETY: a successful lookup with a non-null result initialized the
        // passwd structure and its NUL-terminated home pointer.
        let home = unsafe {
            let account = account.assume_init();
            if account.pw_dir.is_null() {
                return None;
            }
            CStr::from_ptr(account.pw_dir).to_bytes()
        };
        let home = PathBuf::from(OsString::from_vec(home.to_vec()));
        return home.is_absolute().then_some(home);
    }
}

#[cfg(windows)]
pub fn resolver_account_home() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

    let mut token = std::ptr::null_mut();
    // SAFETY: token is writable. A successful call transfers an owned handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    // SAFETY: OpenProcessToken returned a valid owned handle, closed by RAII.
    let token = unsafe { OwnedHandle::from_raw_handle(token.cast()) };
    let mut length = 0;
    // SAFETY: a null buffer requests the required UTF-16 capacity, including
    // the terminator. The account token avoids environment-based redirection.
    unsafe {
        GetUserProfileDirectoryW(
            token.as_raw_handle().cast(),
            std::ptr::null_mut(),
            &mut length,
        )
    };
    if !(2..=32_768).contains(&length) {
        return None;
    }
    let mut home = vec![0_u16; length as usize];
    // SAFETY: home has the capacity requested by the API and token stays live.
    if unsafe {
        GetUserProfileDirectoryW(token.as_raw_handle().cast(), home.as_mut_ptr(), &mut length)
    } == 0
    {
        return None;
    }
    let home = PathBuf::from(OsString::from_wide(&home[..length as usize - 1]));
    home.is_absolute().then_some(home)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_file_home_syntax_follows_the_resolving_platform() {
        for value in ["~", "~/token"] {
            for windows in [None, Some(false), Some(true)] {
                assert_eq!(validate_secret_file_path(Path::new(value), windows), Ok(()));
            }
        }
        assert_eq!(
            validate_secret_file_path(Path::new(r"~\token"), Some(true)),
            Ok(())
        );
        assert_eq!(
            validate_secret_file_path(Path::new(r"~\token"), Some(false)),
            Err(SecretFilePathError::TildeFormUnsupported)
        );
        for value in ["~/C:/token", r"~\C:\token", "~/C:token"] {
            assert_eq!(
                validate_secret_file_path(Path::new(value), Some(true)),
                Err(SecretFilePathError::TildeFormUnsupported)
            );
        }
        for value in [
            "~other/token",
            r"~domain\user",
            "~~/token",
            "/x/~/token",
            "~/~",
            "~//token",
            "~/$TOKEN",
            "~/%TOKEN%",
            "~/$(helper)",
            "~/`helper`",
        ] {
            assert_eq!(
                validate_secret_file_path(Path::new(value), None),
                Err(SecretFilePathError::TildeFormUnsupported),
                "{value}"
            );
        }
        assert_eq!(
            validate_secret_file_path(Path::new("relative/token"), None),
            Err(SecretFilePathError::NotAbsolute)
        );
        for (value, windows) in [
            (r"C:\Users\RUNNER~1\token", Some(true)),
            (r"C:\Users\RUNNER~1\token", None),
            ("/home/account~backup/token", Some(false)),
            ("~/account~backup/token", None),
        ] {
            assert_eq!(validate_secret_file_path(Path::new(value), windows), Ok(()));
        }
    }

    #[test]
    fn secret_file_home_expansion_is_lexical_and_requires_a_home_only_for_shorthand() {
        let home = if cfg!(windows) {
            Path::new(r"C:\Users\daemon")
        } else {
            Path::new("/home/daemon")
        };
        assert_eq!(
            expand_secret_file_path(Path::new("~/a/../token"), Some(home)).unwrap(),
            home.join("token")
        );
        assert_eq!(
            expand_secret_file_path(Path::new("~"), Some(home)).unwrap(),
            home
        );
        assert_eq!(
            expand_secret_file_path(Path::new("~/token"), None),
            Err(SecretFilePathError::HomeUnavailable)
        );
        assert_eq!(
            expand_secret_file_path(&home.join("token"), None).unwrap(),
            home.join("token")
        );
        let error = SecretFilePathError::HomeUnavailable.diagnostic(
            None,
            None,
            Some("remote"),
            Some(std::env::consts::OS),
        );
        assert_eq!(error.details.len(), 6);
        assert_eq!(error.details["host"], json!("remote"));
        assert_eq!(error.details["config_file"], json!(null));
    }

    #[test]
    fn secret_file_resolver_uses_the_real_process_account_home() {
        let home = resolver_account_home().expect("test runner has an OS account home");
        assert!(home.is_absolute());
        assert_eq!(
            expand_secret_file_path(Path::new("~"), Some(&home)).unwrap(),
            home
        );
    }
}
