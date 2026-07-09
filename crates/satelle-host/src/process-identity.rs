//! Native daemon identity used to distinguish a live process from a reused PID.
//!
//! Every component comes from an operating-system lifetime boundary. There is
//! deliberately no random or synthesized fallback: an unavailable identity must
//! prevent lease acquisition instead of weakening stale-owner detection.

use std::error::Error;
use std::fmt;
use std::io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessIdentity {
    process_id: u32,
    process_start_ref: String,
    boot_identity_ref: String,
}

impl ProcessIdentity {
    pub(crate) fn current() -> Result<Self, ProcessIdentityError> {
        platform::capture()
    }

    pub(crate) fn process_id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn process_start_ref(&self) -> &str {
        &self.process_start_ref
    }

    pub(crate) fn boot_identity_ref(&self) -> &str {
        &self.boot_identity_ref
    }
}

#[derive(Debug)]
pub(crate) enum ProcessIdentityError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidData {
        resource: &'static str,
        reason: &'static str,
    },
    #[cfg(windows)]
    NativeStatus {
        operation: &'static str,
        status: u32,
    },
}

impl fmt::Display for ProcessIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, .. } => write!(formatter, "{operation} failed"),
            Self::InvalidData { resource, reason } => {
                write!(formatter, "{resource} is invalid: {reason}")
            }
            #[cfg(windows)]
            Self::NativeStatus { operation, status } => {
                write!(
                    formatter,
                    "{operation} failed with native status {status:#010x}"
                )
            }
        }
    }
}

impl Error for ProcessIdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidData { .. } => None,
            #[cfg(windows)]
            Self::NativeStatus { .. } => None,
        }
    }
}

#[cfg(any(target_os = "macos", windows))]
fn io_failure(operation: &'static str) -> ProcessIdentityError {
    ProcessIdentityError::Io {
        operation,
        source: io::Error::last_os_error(),
    }
}

fn invalid(resource: &'static str, reason: &'static str) -> ProcessIdentityError {
    ProcessIdentityError::InvalidData { resource, reason }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{ProcessIdentity, ProcessIdentityError, invalid};
    use std::fs;

    const PROCESS_STAT: &str = "/proc/self/stat";
    const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

    pub(super) fn capture() -> Result<ProcessIdentity, ProcessIdentityError> {
        let expected_pid = std::process::id();
        let stat = fs::read_to_string(PROCESS_STAT).map_err(|source| ProcessIdentityError::Io {
            operation: "read /proc/self/stat",
            source,
        })?;
        let (observed_pid, start_ticks) = parse_proc_stat(&stat)?;
        if observed_pid != expected_pid {
            return Err(invalid(
                "Linux process identity",
                "/proc/self/stat PID does not match the current process",
            ));
        }

        let raw_boot_id =
            fs::read_to_string(BOOT_ID).map_err(|source| ProcessIdentityError::Io {
                operation: "read Linux boot ID",
                source,
            })?;
        let boot_id = canonical_boot_id(&raw_boot_id)?;

        Ok(ProcessIdentity {
            process_id: expected_pid,
            process_start_ref: format!("linux-start-ticks:{start_ticks}"),
            boot_identity_ref: format!("linux-boot:{boot_id}"),
        })
    }

    fn parse_proc_stat(stat: &str) -> Result<(u32, u64), ProcessIdentityError> {
        // `comm` may contain spaces and right parentheses. The kernel wraps it
        // in the first `(` and final `)`, so only those outer delimiters are
        // structurally meaningful.
        let comm_start = stat
            .find('(')
            .ok_or_else(|| invalid("/proc/self/stat", "missing command start"))?;
        let comm_end = stat
            .rfind(')')
            .filter(|end| *end > comm_start)
            .ok_or_else(|| invalid("/proc/self/stat", "missing command end"))?;

        let pid = stat[..comm_start]
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid("/proc/self/stat", "invalid PID field"))?;
        if pid == 0 {
            return Err(invalid("/proc/self/stat", "PID must be nonzero"));
        }

        let mut fields = stat[comm_end + 1..].split_ascii_whitespace();
        let state = fields
            .next()
            .ok_or_else(|| invalid("/proc/self/stat", "missing process state"))?;
        if state.len() != 1 || !state.as_bytes()[0].is_ascii_alphabetic() {
            return Err(invalid("/proc/self/stat", "invalid process state"));
        }

        // After consuming field 3 (`state`), field 22 (`starttime`) is the
        // nineteenth remaining field, or zero-based index 18.
        let start_ticks = fields
            .nth(18)
            .ok_or_else(|| invalid("/proc/self/stat", "missing starttime field"))?
            .parse::<u64>()
            .map_err(|_| invalid("/proc/self/stat", "invalid starttime field"))?;
        if start_ticks == 0 {
            return Err(invalid("/proc/self/stat", "starttime must be nonzero"));
        }

        Ok((pid, start_ticks))
    }

    fn canonical_boot_id(raw: &str) -> Result<String, ProcessIdentityError> {
        let value = raw.trim();
        let bytes = value.as_bytes();
        if bytes.len() != 36 {
            return Err(invalid("Linux boot ID", "expected a canonical UUID"));
        }

        for (index, byte) in bytes.iter().copied().enumerate() {
            let is_separator = matches!(index, 8 | 13 | 18 | 23);
            if (is_separator && byte != b'-') || (!is_separator && !byte.is_ascii_hexdigit()) {
                return Err(invalid("Linux boot ID", "expected a canonical UUID"));
            }
        }
        if bytes
            .iter()
            .copied()
            .filter(|byte| *byte != b'-')
            .all(|byte| byte == b'0')
        {
            return Err(invalid("Linux boot ID", "UUID must be nonzero"));
        }

        Ok(value.to_ascii_lowercase())
    }

    #[cfg(test)]
    mod tests {
        use super::{canonical_boot_id, parse_proc_stat};

        #[test]
        fn proc_stat_parser_handles_spaces_and_parentheses_in_comm() {
            let stat = "4321 (worker (blue) ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";

            assert_eq!(parse_proc_stat(stat).unwrap(), (4321, 987654));
        }

        #[test]
        fn proc_stat_parser_rejects_a_missing_starttime() {
            let stat = "4321 (worker) S 1 2 3";

            assert!(parse_proc_stat(stat).is_err());
        }

        #[test]
        fn boot_id_parser_canonicalizes_hex_case() {
            assert_eq!(
                canonical_boot_id("4D36E967-E325-11CE-BFC1-08002BE10318\n").unwrap(),
                "4d36e967-e325-11ce-bfc1-08002be10318"
            );
        }

        #[test]
        fn boot_id_parser_rejects_nil_and_malformed_values() {
            assert!(canonical_boot_id("00000000-0000-0000-0000-000000000000").is_err());
            assert!(canonical_boot_id("not-a-boot-id").is_err());
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{ProcessIdentity, ProcessIdentityError, invalid, io_failure};
    use std::ffi::{c_char, c_int, c_long, c_void};
    use std::mem::{offset_of, size_of};
    use std::ptr;

    const PROC_PIDTBSDINFO: c_int = 3;

    #[repr(C)]
    #[derive(Default)]
    struct ProcBsdInfo {
        _flags_status_xstatus: [u32; 3],
        pid: u32,
        _ppid_through_nice: [u8; 104],
        start_seconds: u64,
        start_microseconds: u64,
    }

    const _: () = assert!(size_of::<ProcBsdInfo>() == 136);
    const _: () = assert!(offset_of!(ProcBsdInfo, pid) == 12);
    const _: () = assert!(offset_of!(ProcBsdInfo, start_seconds) == 120);

    #[repr(C)]
    #[derive(Default)]
    struct Timeval {
        seconds: c_long,
        microseconds: c_int,
    }

    const _: () = assert!(size_of::<Timeval>() == 16);

    unsafe extern "C" {
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffer_size: c_int,
        ) -> c_int;

        fn sysctlbyname(
            name: *const c_char,
            old_value: *mut c_void,
            old_len: *mut usize,
            new_value: *mut c_void,
            new_len: usize,
        ) -> c_int;
    }

    pub(super) fn capture() -> Result<ProcessIdentity, ProcessIdentityError> {
        let process_id = std::process::id();
        let native_pid = c_int::try_from(process_id)
            .map_err(|_| invalid("macOS process identity", "PID is out of range"))?;

        let mut process_info = ProcBsdInfo::default();
        let process_info_size = size_of::<ProcBsdInfo>();
        // SAFETY: `process_info` is a writable, correctly sized C-layout
        // buffer, and all other arguments are plain values required by
        // PROC_PIDTBSDINFO.
        let bytes_written = unsafe {
            proc_pidinfo(
                native_pid,
                PROC_PIDTBSDINFO,
                0,
                ptr::from_mut(&mut process_info).cast(),
                process_info_size as c_int,
            )
        };
        if bytes_written <= 0 {
            return Err(io_failure("query macOS process start time"));
        }
        if bytes_written as usize != process_info_size {
            return Err(invalid(
                "macOS process identity",
                "proc_pidinfo returned a partial record",
            ));
        }
        if process_info.pid != process_id {
            return Err(invalid(
                "macOS process identity",
                "proc_pidinfo PID does not match the current process",
            ));
        }
        let process_start_ref = timestamp_ref(
            "macos-start",
            process_info.start_seconds,
            process_info.start_microseconds,
        )?;

        let mut boot_time = Timeval::default();
        let mut boot_time_size = size_of::<Timeval>();
        // SAFETY: the name is a static NUL-terminated C string and
        // `boot_time`/`boot_time_size` describe a writable timeval buffer.
        let status = unsafe {
            sysctlbyname(
                c"kern.boottime".as_ptr(),
                ptr::from_mut(&mut boot_time).cast(),
                &mut boot_time_size,
                ptr::null_mut(),
                0,
            )
        };
        if status != 0 {
            return Err(io_failure("query macOS boot time"));
        }
        if boot_time_size != size_of::<Timeval>() {
            return Err(invalid(
                "macOS boot identity",
                "kern.boottime returned an unexpected record size",
            ));
        }
        let boot_seconds = u64::try_from(boot_time.seconds)
            .map_err(|_| invalid("macOS boot identity", "boot time is negative"))?;
        let boot_microseconds = u64::try_from(boot_time.microseconds)
            .map_err(|_| invalid("macOS boot identity", "boot time is negative"))?;

        Ok(ProcessIdentity {
            process_id,
            process_start_ref,
            boot_identity_ref: timestamp_ref("macos-boot", boot_seconds, boot_microseconds)?,
        })
    }

    fn timestamp_ref(
        prefix: &'static str,
        seconds: u64,
        microseconds: u64,
    ) -> Result<String, ProcessIdentityError> {
        if seconds == 0 {
            return Err(invalid("macOS native timestamp", "seconds must be nonzero"));
        }
        if microseconds >= 1_000_000 {
            return Err(invalid(
                "macOS native timestamp",
                "microseconds are out of range",
            ));
        }
        Ok(format!("{prefix}:{seconds}:{microseconds}"))
    }

    #[cfg(test)]
    mod tests {
        use super::timestamp_ref;

        #[test]
        fn timestamp_ref_is_stable_and_validated() {
            assert_eq!(
                timestamp_ref("macos-start", 1_700_000_000, 42).unwrap(),
                "macos-start:1700000000:42"
            );
            assert!(timestamp_ref("macos-start", 0, 42).is_err());
            assert!(timestamp_ref("macos-start", 1, 1_000_000).is_err());
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{ProcessIdentity, ProcessIdentityError, invalid, io_failure};
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::ptr;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    const SYSTEM_BOOT_ENVIRONMENT_INFORMATION: u32 = 90;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct NativeGuid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    #[derive(Default)]
    struct BootEnvironmentInformation {
        boot_identifier: NativeGuid,
        _firmware_type: u32,
        _alignment: u32,
        _boot_flags: u64,
    }

    const _: () = assert!(size_of::<BootEnvironmentInformation>() == 32);
    const _: () = assert!(offset_of!(BootEnvironmentInformation, _boot_flags) == 24);

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            information_class: u32,
            information: *mut c_void,
            information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    pub(super) fn capture() -> Result<ProcessIdentity, ProcessIdentityError> {
        let process_id = std::process::id();
        let creation_time = process_creation_time()?;
        if creation_time == 0 {
            return Err(invalid(
                "Windows process identity",
                "creation FILETIME must be nonzero",
            ));
        }

        let boot_identifier = boot_identifier()?;
        Ok(ProcessIdentity {
            process_id,
            process_start_ref: format!("windows-start-filetime:{creation_time}"),
            boot_identity_ref: format!("windows-boot:{}", format_guid(boot_identifier)?),
        })
    }

    fn process_creation_time() -> Result<u64, ProcessIdentityError> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: GetCurrentProcess returns a process pseudo-handle that must
        // not be closed. Every FILETIME pointer refers to live writable data.
        let succeeded = unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        };
        if succeeded == 0 {
            return Err(io_failure("query Windows process creation time"));
        }

        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    fn boot_identifier() -> Result<NativeGuid, ProcessIdentityError> {
        let mut information = BootEnvironmentInformation::default();
        // SAFETY: `information` has the exact C layout and size required by
        // SystemBootEnvironmentInformation. The return-length output is
        // optional for this fixed-size query.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_BOOT_ENVIRONMENT_INFORMATION,
                ptr::from_mut(&mut information).cast(),
                size_of::<BootEnvironmentInformation>() as u32,
                ptr::null_mut(),
            )
        };
        if status < 0 {
            return Err(ProcessIdentityError::NativeStatus {
                operation: "query Windows boot environment",
                status: status as u32,
            });
        }
        Ok(information.boot_identifier)
    }

    fn format_guid(guid: NativeGuid) -> Result<String, ProcessIdentityError> {
        if guid.data1 == 0
            && guid.data2 == 0
            && guid.data3 == 0
            && guid.data4.iter().all(|byte| *byte == 0)
        {
            return Err(invalid(
                "Windows boot identity",
                "boot GUID must be nonzero",
            ));
        }

        Ok(format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::{NativeGuid, format_guid};

        #[test]
        fn guid_formatter_uses_canonical_field_order() {
            let guid = NativeGuid {
                data1: 0x4d36_e967,
                data2: 0xe325,
                data3: 0x11ce,
                data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
            };

            assert_eq!(
                format_guid(guid).unwrap(),
                "4d36e967-e325-11ce-bfc1-08002be10318"
            );
            assert!(format_guid(NativeGuid::default()).is_err());
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("Satelle process identity supports only Linux, macOS, and Windows");

#[cfg(test)]
mod tests {
    use super::ProcessIdentity;

    #[test]
    fn current_identity_is_stable_and_storage_safe() {
        let first = ProcessIdentity::current().unwrap();
        let second = ProcessIdentity::current().unwrap();

        assert_eq!(first, second);
        assert_ne!(first.process_id(), 0);
        for value in [first.process_start_ref(), first.boot_identity_ref()] {
            assert!(!value.is_empty());
            assert!(value.len() <= 256);
            assert!(value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            }));
        }
    }
}
