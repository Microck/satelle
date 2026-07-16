use std::ffi::OsString;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use thiserror::Error;

const REMOTE_DAEMON_PORT: u16 = 3001;
const READY_POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(super) struct SshTunnel {
    child: Child,
    local_addr: SocketAddr,
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
            // never captures or reproduces potentially remote-controlled text.
            .stderr(Stdio::null());
        let child = command.spawn().map_err(SshTunnelError::Spawn)?;
        let mut tunnel = Self { child, local_addr };
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
                return Err(SshTunnelError::ExitedBeforeReady);
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
                return Err(SshTunnelError::ExitedBeforeReady);
            }
            thread::sleep(READY_POLL_INTERVAL);
        }
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) | Err(_) => {}
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
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
    #[error("could not inspect the system OpenSSH process")]
    Inspect(#[source] io::Error),
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
}
