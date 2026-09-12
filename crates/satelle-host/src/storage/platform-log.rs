use crate::LogSeverity;
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformLogFailureKind {
    FormatFailed,
    SinkUnavailable,
    WriteFailed,
}

impl PlatformLogFailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FormatFailed => "format_failed",
            Self::SinkUnavailable => "sink_unavailable",
            Self::WriteFailed => "write_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformLogSinkHealth {
    Disabled,
    Healthy,
    Degraded(PlatformLogFailureKind),
}

pub(crate) trait PlatformLogWriter {
    fn write(&mut self, line: &str, severity: LogSeverity) -> io::Result<()>;
}

pub(crate) struct PlatformLogSink<W = NativePlatformLogWriter> {
    writer: Option<W>,
    active_failure: Option<PlatformLogFailureKind>,
}

impl PlatformLogSink<NativePlatformLogWriter> {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            writer: enabled.then(NativePlatformLogWriter::new),
            active_failure: None,
        }
    }
}

impl<W: PlatformLogWriter> PlatformLogSink<W> {
    #[cfg(test)]
    pub(super) fn with_writer(writer: W) -> Self {
        Self {
            writer: Some(writer),
            active_failure: None,
        }
    }

    pub(crate) fn write_formatted(&mut self, line: &str, severity: LogSeverity) {
        let Some(writer) = self.writer.as_mut() else {
            return;
        };
        match writer.write(line, severity) {
            Ok(()) => self.active_failure = None,
            Err(error) => {
                self.active_failure = Some(classify_io_failure(&error));
            }
        }
    }

    pub(crate) fn record_format_failure(&mut self) {
        if self.writer.is_some() {
            self.active_failure = Some(PlatformLogFailureKind::FormatFailed);
        }
    }

    pub(crate) const fn health(&self) -> PlatformLogSinkHealth {
        if self.writer.is_none() {
            PlatformLogSinkHealth::Disabled
        } else if let Some(kind) = self.active_failure {
            PlatformLogSinkHealth::Degraded(kind)
        } else {
            PlatformLogSinkHealth::Healthy
        }
    }
}

fn classify_io_failure(error: &io::Error) -> PlatformLogFailureKind {
    match error.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::WouldBlock => PlatformLogFailureKind::SinkUnavailable,
        _ => PlatformLogFailureKind::WriteFailed,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct NativePlatformLogWriter {
    socket: Option<std::os::unix::net::UnixDatagram>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl NativePlatformLogWriter {
    fn new() -> Self {
        Self { socket: None }
    }

    fn socket(&mut self) -> io::Result<&std::os::unix::net::UnixDatagram> {
        if self.socket.is_none() {
            let socket = std::os::unix::net::UnixDatagram::unbound()?;
            socket.set_nonblocking(true)?;
            socket.connect(PLATFORM_LOG_SOCKET)?;
            self.socket = Some(socket);
        }
        Ok(self
            .socket
            .as_ref()
            .expect("platform log socket was initialized"))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PlatformLogWriter for NativePlatformLogWriter {
    fn write(&mut self, line: &str, severity: LogSeverity) -> io::Result<()> {
        let socket = self.socket()?;
        let payload = format_platform_log_payload(line, severity);
        if let Err(error) = socket.send(payload.as_bytes()) {
            self.socket = None;
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
const PLATFORM_LOG_SOCKET: &str = "/var/run/syslog";

#[cfg(target_os = "linux")]
const PLATFORM_LOG_SOCKET: &str = "/run/systemd/journal/socket";

#[cfg(target_os = "linux")]
fn format_platform_log_payload(line: &str, severity: LogSeverity) -> String {
    let priority = syslog_priority(severity);
    format!(
        "PRIORITY={priority}\nSYSLOG_IDENTIFIER=satelle-host\nMESSAGE={}",
        line.trim_end_matches('\n')
    )
}

#[cfg(target_os = "macos")]
fn format_platform_log_payload(line: &str, severity: LogSeverity) -> String {
    format!(
        "<{}>satelle-host: {}",
        syslog_priority(severity),
        line.trim_end_matches('\n')
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const fn syslog_priority(severity: LogSeverity) -> u8 {
    match severity {
        LogSeverity::Info => 6,
        LogSeverity::Warning => 4,
        LogSeverity::Error => 3,
    }
}

#[cfg(windows)]
pub(crate) struct NativePlatformLogWriter {
    // Event Log handles are process handles that may cross threads. Store the
    // address as an integer so the mutex-owned runtime mirror remains Send.
    handle: isize,
}

#[cfg(windows)]
impl NativePlatformLogWriter {
    fn new() -> Self {
        Self { handle: 0 }
    }

    fn handle(&mut self) -> io::Result<windows_sys::Win32::Foundation::HANDLE> {
        use windows_sys::Win32::System::EventLog::RegisterEventSourceW;

        if self.handle == 0 {
            let source = "Satelle Host\0".encode_utf16().collect::<Vec<_>>();
            // SAFETY: The source buffer is NUL terminated and remains alive for the
            // call. A null server selects the local Windows Event Log.
            let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            self.handle = handle as isize;
        }
        Ok(self.handle as windows_sys::Win32::Foundation::HANDLE)
    }
}

#[cfg(windows)]
impl PlatformLogWriter for NativePlatformLogWriter {
    fn write(&mut self, line: &str, severity: LogSeverity) -> io::Result<()> {
        use windows_sys::Win32::System::EventLog::{
            EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, ReportEventW,
        };

        let handle = self.handle()?;
        let event_type = match severity {
            LogSeverity::Info => EVENTLOG_INFORMATION_TYPE,
            LogSeverity::Warning => EVENTLOG_WARNING_TYPE,
            LogSeverity::Error => EVENTLOG_ERROR_TYPE,
        };
        let message = line
            .trim_end_matches('\n')
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let strings = [message.as_ptr()];
        // SAFETY: The message and pointer array remain alive for this synchronous
        // call. No user SID or raw binary payload is supplied.
        let written = unsafe {
            ReportEventW(
                handle,
                event_type,
                0,
                0x1000,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            )
        };
        if written == 0 {
            // SAFETY: The handle came from RegisterEventSourceW and this path
            // discards its sole owner before the next entry can register again.
            unsafe {
                windows_sys::Win32::System::EventLog::DeregisterEventSource(handle);
            }
            self.handle = 0;
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for NativePlatformLogWriter {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: The handle came from RegisterEventSourceW and has one owner.
            unsafe {
                windows_sys::Win32::System::EventLog::DeregisterEventSource(
                    self.handle as windows_sys::Win32::Foundation::HANDLE,
                );
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) struct NativePlatformLogWriter;

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl NativePlatformLogWriter {
    fn new() -> Self {
        Self
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl PlatformLogWriter for NativePlatformLogWriter {
    fn write(&mut self, _line: &str, _severity: LogSeverity) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the current platform has no native log sink",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct RecordingWriter {
        lines: Arc<Mutex<Vec<String>>>,
        failure: Option<io::ErrorKind>,
    }

    impl PlatformLogWriter for RecordingWriter {
        fn write(&mut self, line: &str, _severity: LogSeverity) -> io::Result<()> {
            if let Some(kind) = self.failure.take() {
                return Err(io::Error::from(kind));
            }
            self.lines.lock().unwrap().push(line.to_string());
            Ok(())
        }
    }

    #[test]
    fn disabled_sink_does_no_io() {
        let mut sink = PlatformLogSink::new(false);
        sink.write_formatted("ignored", LogSeverity::Info);
        assert_eq!(sink.health(), PlatformLogSinkHealth::Disabled);
    }

    #[test]
    fn sink_recovers_after_a_typed_write_failure() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let mut sink = PlatformLogSink::with_writer(RecordingWriter {
            lines: Arc::clone(&lines),
            failure: Some(io::ErrorKind::NotFound),
        });
        sink.write_formatted("first", LogSeverity::Warning);
        assert_eq!(
            sink.health(),
            PlatformLogSinkHealth::Degraded(PlatformLogFailureKind::SinkUnavailable)
        );
        sink.write_formatted("second", LogSeverity::Warning);
        assert_eq!(sink.health(), PlatformLogSinkHealth::Healthy);
        assert_eq!(&*lines.lock().unwrap(), &["second"]);
    }
}
