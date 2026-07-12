use satelle_core::DesktopSessionRecord;

pub(super) fn discover() -> Result<Vec<DesktopSessionRecord>, satelle_core::SatelleError> {
    platform::observe().map(|observation| observation.and_then(record).into_iter().collect())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DesktopObservation {
    platform_name: &'static str,
    native_selector: String,
    desktop_user: String,
    active: bool,
    is_console: bool,
    is_remote: bool,
}

fn record(observation: DesktopObservation) -> Option<DesktopSessionRecord> {
    if !observation.active || observation.desktop_user.is_empty() {
        return None;
    }
    let (connection, is_console, is_remote) = match (observation.is_console, observation.is_remote)
    {
        (true, false) => ("console", true, false),
        (false, true) => ("remote", false, true),
        _ => return None,
    };
    let native_selector = observation.native_selector;
    let portable_selectors = vec!["active".to_string(), connection.to_string()];
    Some(DesktopSessionRecord {
        session_id: native_selector.clone(),
        display_summary: format!(
            "{} {connection} session for {}",
            observation.platform_name, observation.desktop_user
        ),
        desktop_user: observation.desktop_user,
        state: "active".to_string(),
        session_kind: "visible_desktop".to_string(),
        is_console,
        is_remote,
        portable_selectors,
        native_selectors: vec![native_selector],
        // The Controller applies its resolved HostConfig after discovery.
        selected_by_current_config: false,
    })
}

#[cfg(windows)]
mod platform {
    use super::DesktopObservation;
    use satelle_core::{ErrorCode, SatelleError};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::ptr;
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTSActive, WTSClientProtocolType,
        WTSConnectState, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
        WTSUserName,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;

    pub(super) fn observe() -> Result<Option<DesktopObservation>, SatelleError> {
        let mut session_id = 0_u32;
        // SAFETY: `session_id` is a valid writable u32 and the current process
        // identifier remains valid for the duration of this call.
        if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) } == 0 {
            return Err(discovery_error(
                "Windows could not resolve the daemon WTS session",
                Some(io::Error::last_os_error().to_string()),
            ));
        }
        let desktop_user = query_string(session_id, WTSUserName)?;
        let state = query_value::<i32>(session_id, WTSConnectState)?;
        let protocol = query_value::<u16>(session_id, WTSClientProtocolType)?;
        // SAFETY: this function takes no pointers and returns an identifier.
        let console_session = unsafe { WTSGetActiveConsoleSessionId() };
        let is_console = session_id == console_session && protocol == 0;
        Ok(Some(DesktopObservation {
            platform_name: "Windows",
            native_selector: format!("windows:wts-session:{session_id}"),
            desktop_user,
            active: session_id != 0 && state == WTSActive,
            is_console,
            is_remote: protocol != 0,
        }))
    }

    struct WtsMemory(*mut u16);

    impl Drop for WtsMemory {
        fn drop(&mut self) {
            // SAFETY: WTS allocated this buffer and ownership remains with the
            // guard until this single matching free.
            unsafe { WTSFreeMemory(self.0.cast::<c_void>()) };
        }
    }

    fn query(session_id: u32, information: i32) -> Result<(WtsMemory, u32), SatelleError> {
        let mut buffer = ptr::null_mut();
        let mut bytes = 0_u32;
        // SAFETY: output pointers are valid, and WTS owns the returned buffer
        // until it is wrapped by `WtsMemory` and released exactly once.
        let succeeded = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                information,
                &mut buffer,
                &mut bytes,
            )
        };
        if succeeded == 0 || buffer.is_null() {
            return Err(discovery_error(
                "Windows could not read WTS session metadata",
                Some(io::Error::last_os_error().to_string()),
            ));
        }
        Ok((WtsMemory(buffer), bytes))
    }

    fn query_string(session_id: u32, information: i32) -> Result<String, SatelleError> {
        let (buffer, bytes) = query(session_id, information)?;
        let bytes = usize::try_from(bytes)
            .map_err(|_| discovery_error("Windows returned invalid WTS string metadata", None))?;
        if bytes % size_of::<u16>() != 0 {
            return Err(discovery_error(
                "Windows returned invalid WTS string metadata",
                None,
            ));
        }
        let units = bytes / size_of::<u16>();
        // SAFETY: WTS reported `bytes` bytes for this UTF-16 buffer and the
        // guard keeps it alive for the complete slice conversion.
        let values = unsafe { std::slice::from_raw_parts(buffer.0, units) };
        let end = values
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(values.len());
        String::from_utf16(&values[..end])
            .map_err(|_| discovery_error("Windows returned malformed WTS user metadata", None))
    }

    fn query_value<T: Copy>(session_id: u32, information: i32) -> Result<T, SatelleError> {
        let (buffer, bytes) = query(session_id, information)?;
        if usize::try_from(bytes)
            .ok()
            .is_none_or(|bytes| bytes < size_of::<T>())
        {
            return Err(discovery_error(
                "Windows returned incomplete WTS session metadata",
                None,
            ));
        }
        // SAFETY: the preceding length check proves the WTS buffer contains a
        // complete value; unaligned reads avoid assuming WTS allocation alignment.
        Ok(unsafe { ptr::read_unaligned(buffer.0.cast::<T>()) })
    }

    fn discovery_error(message: &'static str, source_detail: Option<String>) -> SatelleError {
        SatelleError {
            code: ErrorCode::ComputerUseNotReady,
            message: message.to_string(),
            recovery_command: Some(
                "satelle doctor --scope computer-use --refresh --json".to_string(),
            ),
            source_detail,
            details: BTreeMap::new(),
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::DesktopObservation;
    use satelle_core::{ErrorCode, SatelleError};
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    pub(super) fn observe() -> Result<Option<DesktopObservation>, SatelleError> {
        let effective_user = rustix::process::geteuid().as_raw();
        let console = std::fs::symlink_metadata("/dev/console")
            .map_err(|error| discovery_error("macOS could not inspect /dev/console", error))?;
        let output = Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .map_err(|error| discovery_error("macOS could not resolve the daemon user", error))?;
        if !output.status.success() {
            return Err(discovery_error(
                "macOS could not resolve the daemon user",
                std::io::Error::other(format!("/usr/bin/id exited with {}", output.status)),
            ));
        }
        let desktop_user = String::from_utf8(output.stdout)
            .map_err(|error| discovery_error("macOS returned a non-UTF-8 daemon user", error))?
            .trim()
            .to_string();
        Ok(Some(DesktopObservation {
            platform_name: "macOS",
            native_selector: format!("macos:console-uid:{effective_user}"),
            desktop_user,
            active: console.uid() == effective_user,
            is_console: true,
            is_remote: false,
        }))
    }

    fn discovery_error(message: &'static str, source: impl std::fmt::Display) -> SatelleError {
        SatelleError {
            code: ErrorCode::ComputerUseNotReady,
            message: message.to_string(),
            recovery_command: Some(
                "satelle doctor --scope computer-use --refresh --json".to_string(),
            ),
            source_detail: Some(source.to_string()),
            details: BTreeMap::new(),
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use super::DesktopObservation;

    pub(super) fn observe() -> Result<Option<DesktopObservation>, satelle_core::SatelleError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_console_and_remote_sessions_have_closed_selector_shapes() {
        let console = record(DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:3".to_string(),
            desktop_user: "operator".to_string(),
            active: true,
            is_console: true,
            is_remote: false,
        })
        .expect("active console session");
        assert_eq!(console.session_id, "windows:wts-session:3");
        assert_eq!(console.portable_selectors, ["active", "console"]);
        assert_eq!(console.native_selectors, ["windows:wts-session:3"]);

        let remote = record(DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:7".to_string(),
            desktop_user: "operator".to_string(),
            active: true,
            is_console: false,
            is_remote: true,
        })
        .expect("active remote session");
        assert_eq!(remote.portable_selectors, ["active", "remote"]);
        assert_eq!(remote.native_selectors, ["windows:wts-session:7"]);
    }

    #[test]
    fn macos_console_session_uses_the_daemon_user_identity() {
        let record = record(DesktopObservation {
            platform_name: "macOS",
            native_selector: "macos:console-uid:501".to_string(),
            desktop_user: "operator".to_string(),
            active: true,
            is_console: true,
            is_remote: false,
        })
        .expect("active macOS console session");
        assert_eq!(record.session_id, "macos:console-uid:501");
        assert_eq!(record.portable_selectors, ["active", "console"]);
        assert_eq!(record.native_selectors, ["macos:console-uid:501"]);
    }

    #[test]
    fn inactive_or_ownerless_observations_are_not_compatible_desktops() {
        for observation in [
            DesktopObservation {
                platform_name: "Windows",
                native_selector: "windows:wts-session:0".to_string(),
                desktop_user: "SYSTEM".to_string(),
                active: false,
                is_console: true,
                is_remote: false,
            },
            DesktopObservation {
                platform_name: "Windows",
                native_selector: "windows:wts-session:4".to_string(),
                desktop_user: String::new(),
                active: true,
                is_console: false,
                is_remote: true,
            },
        ] {
            assert!(record(observation).is_none());
        }
    }

    #[test]
    fn contradictory_connection_classification_is_not_published() {
        let observation = DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:3".to_string(),
            desktop_user: "operator".to_string(),
            active: true,
            is_console: true,
            is_remote: true,
        };
        assert!(record(observation).is_none());
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn unsupported_platforms_do_not_claim_a_native_desktop_session() {
        assert_eq!(discover().expect("unsupported platform discovery"), []);
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_discovery_returns_at_most_the_daemon_process_session() {
        let sessions = discover().expect("Windows WTS discovery");
        assert!(sessions.len() <= 1);
        for session in sessions {
            assert!(session.session_id.starts_with("windows:wts-session:"));
            assert_eq!(session.native_selectors.len(), 1);
            assert_eq!(session.native_selectors[0], session.session_id);
            assert_eq!(session.state, "active");
            assert_ne!(session.is_console, session.is_remote);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_discovery_obeys_console_ownership() {
        use std::os::unix::fs::MetadataExt;

        let sessions = discover().expect("macOS console discovery");
        let effective_user = rustix::process::geteuid().as_raw();
        let console_user = std::fs::symlink_metadata("/dev/console")
            .expect("macOS console metadata")
            .uid();
        if console_user == effective_user {
            assert_eq!(sessions.len(), 1);
            assert_eq!(
                sessions[0].session_id,
                format!("macos:console-uid:{effective_user}")
            );
            assert!(sessions[0].is_console);
            assert!(!sessions[0].is_remote);
        } else {
            assert!(sessions.is_empty());
        }
    }
}
