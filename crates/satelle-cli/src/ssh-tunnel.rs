use std::ffi::OsString;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;

const REMOTE_DAEMON_PORT: u16 = 3001;
const READY_POLL_INTERVAL: Duration = Duration::from_millis(20);
const HOST_KEY_FAILURE_MARKERS: [&[u8]; 2] = [
    b"Host key verification failed.",
    b"REMOTE HOST IDENTIFICATION HAS CHANGED!",
];

pub(super) struct SshTunnel {
    child: Child,
    local_addr: SocketAddr,
    stderr_reader: Option<JoinHandle<SshStderrClassification>>,
}

impl SshTunnel {
    pub(super) fn open(destination: &str) -> Result<Self, SshTunnelError> {
        let reservation =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(SshTunnelError::PortAllocation)?;
        let local_addr = reservation
            .local_addr()
            .map_err(SshTunnelError::PortAllocation)?;
        drop(reservation);

        let mut command = Command::new("ssh");
        command
            .args(ssh_arguments(destination, local_addr.port()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // OpenSSH owns authentication and host-key interaction. Satelle
            // drains stderr only into a streaming classifier and never keeps
            // or reproduces potentially remote-controlled text.
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(SshTunnelError::Spawn)?;
        let stderr = child
            .stderr
            .take()
            .expect("OpenSSH stderr was configured as piped");
        let stderr_reader = match spawn_stderr_reader(stderr) {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let mut tunnel = Self {
            child,
            local_addr,
            stderr_reader: Some(stderr_reader),
        };
        tunnel.wait_until_listening()?;
        Ok(tunnel)
    }

    pub(super) const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn wait_until_listening(&mut self) -> Result<(), SshTunnelError> {
        loop {
            if self
                .child
                .try_wait()
                .map_err(SshTunnelError::Inspect)?
                .is_some()
            {
                return Err(self.exited_before_ready());
            }
            if let Ok(connection) = TcpStream::connect(self.local_addr) {
                drop(connection);
                if self
                    .child
                    .try_wait()
                    .map_err(SshTunnelError::Inspect)?
                    .is_none()
                {
                    return Ok(());
                }
                return Err(self.exited_before_ready());
            }
            thread::sleep(READY_POLL_INTERVAL);
        }
    }

    fn exited_before_ready(&mut self) -> SshTunnelError {
        if self.finish_stderr_reader().host_key_verification_failed {
            SshTunnelError::HostKeyVerificationRequired
        } else {
            SshTunnelError::ExitedBeforeReady
        }
    }

    fn finish_stderr_reader(&mut self) -> SshStderrClassification {
        self.stderr_reader
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.finish_stderr_reader();
    }
}

fn spawn_stderr_reader(
    stderr: ChildStderr,
) -> Result<JoinHandle<SshStderrClassification>, SshTunnelError> {
    thread::Builder::new()
        .name("satelle-ssh-stderr".to_string())
        .spawn(move || classify_stderr(stderr))
        .map_err(SshTunnelError::StderrReader)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct SshStderrClassification {
    host_key_verification_failed: bool,
}

impl SshStderrClassification {
    pub(super) const fn host_key_verification_failed(self) -> bool {
        self.host_key_verification_failed
    }
}

pub(super) fn classify_stderr(mut stderr: impl Read) -> SshStderrClassification {
    let mut classification = SshStderrClassification::default();
    let mut marker_offsets = [0_usize; HOST_KEY_FAILURE_MARKERS.len()];
    let mut buffer = [0_u8; 4096];
    loop {
        let count = match stderr.read(&mut buffer) {
            Ok(0) | Err(_) => return classification,
            Ok(count) => count,
        };
        for byte in &buffer[..count] {
            for (marker, offset) in HOST_KEY_FAILURE_MARKERS
                .iter()
                .zip(marker_offsets.iter_mut())
            {
                if *byte == marker[*offset] {
                    *offset += 1;
                    if *offset == marker.len() {
                        classification.host_key_verification_failed = true;
                        *offset = 0;
                    }
                } else {
                    *offset = usize::from(*byte == marker[0]);
                }
            }
        }
    }
}

fn ssh_arguments(destination: &str, local_port: u16) -> Vec<OsString> {
    vec![
        OsString::from("-N"),
        OsString::from("-T"),
        OsString::from("-o"),
        OsString::from("ExitOnForwardFailure=yes"),
        OsString::from("-L"),
        OsString::from(format!(
            "127.0.0.1:{local_port}:127.0.0.1:{REMOTE_DAEMON_PORT}"
        )),
        OsString::from(destination),
    ]
}

#[derive(Debug, Error)]
pub(super) enum SshTunnelError {
    #[error("could not allocate a loopback port for the SSH tunnel")]
    PortAllocation(#[source] io::Error),
    #[error("could not start system OpenSSH")]
    Spawn(#[source] io::Error),
    #[error("could not start the system OpenSSH diagnostic reader")]
    StderrReader(#[source] io::Error),
    #[error("could not inspect the system OpenSSH process")]
    Inspect(#[source] io::Error),
    #[error("system OpenSSH requires Host-key verification")]
    HostKeyVerificationRequired,
    #[error("system OpenSSH exited before the tunnel became ready")]
    ExitedBeforeReady,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_loopback_only_and_contains_no_remote_command_or_host_key_bypass() {
        assert_eq!(
            ssh_arguments("operator@example", 43123),
            [
                "-N",
                "-T",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
                "127.0.0.1:43123:127.0.0.1:3001",
                "operator@example",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn stderr_classifier_recognizes_only_host_key_failures() {
        for diagnostic in HOST_KEY_FAILURE_MARKERS {
            assert!(classify_stderr(diagnostic).host_key_verification_failed);
        }
        assert_eq!(
            classify_stderr(&b"connection refused by the configured host"[..]),
            SshStderrClassification::default()
        );
    }
}
