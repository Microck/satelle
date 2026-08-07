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

#[cfg(any(test, target_os = "macos"))]
fn macos_console_observation(
    daemon_uid: u32,
    daemon_user: &str,
    console_uid: u32,
    console_user: &str,
) -> DesktopObservation {
    DesktopObservation {
        platform_name: "macOS",
        native_selector: format!("macos:console-uid:{console_uid}"),
        desktop_user: console_user.to_string(),
        active: daemon_uid == console_uid && daemon_user == console_user,
        is_console: true,
        is_remote: false,
    }
}

fn compatible_connection(observation: &DesktopObservation) -> Option<(&'static str, bool, bool)> {
    if !observation.active || observation.desktop_user.is_empty() {
        return None;
    }
    Some(match (observation.is_console, observation.is_remote) {
        (true, false) => ("console", true, false),
        (false, true) => ("remote", false, true),
        _ => return None,
    })
}

#[cfg(any(test, windows))]
fn prefer_windows_observation(
    daemon_session: DesktopObservation,
    active_console: Option<DesktopObservation>,
) -> DesktopObservation {
    if compatible_connection(&daemon_session).is_some() {
        daemon_session
    } else {
        active_console.unwrap_or(daemon_session)
    }
}

fn record(observation: DesktopObservation) -> Option<DesktopSessionRecord> {
    let (connection, is_console, is_remote) = compatible_connection(&observation)?;
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
        // SAFETY: this function takes no pointers and returns an identifier.
        let console_session = unsafe { WTSGetActiveConsoleSessionId() };
        let daemon_observation = observe_session(session_id, console_session);

        // Task Scheduler and SSH can host the daemon outside the interactive
        // window station even while a real console user is active. Preserve a
        // compatible daemon-owned remote session, but otherwise query the
        // live console instead of publishing an empty background session.
        let console_observation = (console_session != u32::MAX
            && console_session != session_id
            && !daemon_observation
                .as_ref()
                .is_ok_and(|observation| super::compatible_connection(observation).is_some()))
        .then(|| observe_session(console_session, console_session))
        .transpose()?;

        match daemon_observation {
            Ok(observation) => Ok(Some(super::prefer_windows_observation(
                observation,
                console_observation,
            ))),
            Err(error) => console_observation.map(Some).ok_or(error),
        }
    }

    fn observe_session(
        session_id: u32,
        console_session: u32,
    ) -> Result<DesktopObservation, SatelleError> {
        let desktop_user = query_string(session_id, WTSUserName)?;
        let state = query_value::<i32>(session_id, WTSConnectState)?;
        let protocol = query_value::<u16>(session_id, WTSClientProtocolType)?;
        let is_console = session_id == console_session && protocol == 0;
        Ok(DesktopObservation {
            platform_name: "Windows",
            native_selector: format!("windows:wts-session:{session_id}"),
            desktop_user,
            active: session_id != 0 && state == WTSActive,
            is_console,
            is_remote: protocol != 0,
        })
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
    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    use satelle_core::{ErrorCode, SatelleError};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::process::Command;
    use std::ptr;

    #[link(name = "SystemConfiguration", kind = "framework")]
    unsafe extern "C" {
        fn SCDynamicStoreCopyConsoleUser(
            store: *const c_void,
            uid: *mut libc::uid_t,
            gid: *mut libc::gid_t,
        ) -> CFStringRef;
    }

    pub(super) fn observe() -> Result<Option<DesktopObservation>, SatelleError> {
        let effective_user = rustix::process::geteuid().as_raw();
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
        let (console_user, console_uid) = live_console_user()?;
        Ok(Some(super::macos_console_observation(
            effective_user,
            &desktop_user,
            console_uid,
            &console_user,
        )))
    }

    pub(super) fn live_console_user() -> Result<(String, u32), SatelleError> {
        let mut uid = 0;
        let mut gid = 0;
        // SAFETY: a null store asks SystemConfiguration for its current global
        // dynamic store. The writable UID/GID pointers remain valid for the
        // complete call, and the returned create-rule CFString is owned here.
        let raw_user = unsafe { SCDynamicStoreCopyConsoleUser(ptr::null(), &mut uid, &mut gid) };
        if raw_user.is_null() {
            return Err(discovery_error(
                "macOS could not resolve the active console user",
                "SystemConfiguration returned no console user",
            ));
        }
        // SAFETY: SCDynamicStoreCopyConsoleUser returned a non-null CFString
        // under the Core Foundation create rule, so this wrapper owns one
        // matching release.
        let user = unsafe { CFString::wrap_under_create_rule(raw_user) }.to_string();
        Ok((user, uid))
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
    fn windows_background_host_falls_back_to_the_active_console_session() {
        let background = DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:0".to_string(),
            desktop_user: String::new(),
            active: false,
            is_console: false,
            is_remote: false,
        };
        let console = DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:2".to_string(),
            desktop_user: "Administrator".to_string(),
            active: true,
            is_console: true,
            is_remote: false,
        };

        let session = record(prefer_windows_observation(background, Some(console)))
            .expect("the active console is the compatible visible desktop");

        assert_eq!(session.session_id, "windows:wts-session:2");
        assert_eq!(session.desktop_user, "Administrator");
        assert_eq!(session.portable_selectors, ["active", "console"]);
    }

    #[test]
    fn windows_active_remote_host_remains_selected_over_the_console_session() {
        let remote = DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:4".to_string(),
            desktop_user: "remote-user".to_string(),
            active: true,
            is_console: false,
            is_remote: true,
        };
        let console = DesktopObservation {
            platform_name: "Windows",
            native_selector: "windows:wts-session:2".to_string(),
            desktop_user: "console-user".to_string(),
            active: true,
            is_console: true,
            is_remote: false,
        };

        let session = record(prefer_windows_observation(remote, Some(console)))
            .expect("an active remote daemon session remains the compatible desktop");

        assert_eq!(session.session_id, "windows:wts-session:4");
        assert_eq!(session.desktop_user, "remote-user");
        assert_eq!(session.portable_selectors, ["active", "remote"]);
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
    fn macos_console_session_uses_live_console_identity_instead_of_device_ownership() {
        let observation = macos_console_observation(501, "operator", 501, "operator");

        let record = record(observation)
            .expect("a live matching console remains valid when /dev/console ownership is stale");
        assert_eq!(record.desktop_user, "operator");
        assert_eq!(record.session_id, "macos:console-uid:501");
    }

    #[test]
    fn macos_console_session_rejects_a_different_live_console_identity() {
        assert!(record(macos_console_observation(501, "operator", 502, "operator")).is_none());
        assert!(record(macos_console_observation(501, "operator", 501, "other")).is_none());
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
    fn macos_native_discovery_obeys_live_console_identity() {
        let sessions = discover().expect("macOS console discovery");
        let effective_user = rustix::process::geteuid().as_raw();
        let daemon_user = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .expect("daemon user query");
        let daemon_user = String::from_utf8(daemon_user.stdout)
            .expect("UTF-8 daemon user")
            .trim()
            .to_string();
        let (console_user, console_uid) = platform::live_console_user().expect("live console user");
        if console_uid == effective_user && console_user == daemon_user {
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
