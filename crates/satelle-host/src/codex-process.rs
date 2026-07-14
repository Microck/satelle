use super::{CodexSessionError, CodexSessionFailure};
use command_group::CommandGroup;
use serde_json::Value;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const INBOUND_LINE_LIMIT: usize = 2 * 1024 * 1024;
const INBOUND_QUEUE_CAPACITY: usize = 8;
const READER_POLL_INTERVAL: Duration = Duration::from_millis(5);

pub(super) trait CodexExchange {
    type Output;

    fn run(
        &mut self,
        writer: &ProtocolWriter,
        receiver: &mpsc::Receiver<ReadEvent>,
    ) -> Result<Self::Output, CodexSessionError>;

    fn turn_dispatch_attempted(&self) -> bool {
        false
    }
}

pub(super) fn run_exchange<E: CodexExchange>(
    mut command: Command,
    working_directory: &Path,
    deadline: Instant,
    exchange: &mut E,
) -> Result<E::Output, CodexSessionFailure> {
    let mut child = command
        .current_dir(working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
        .map_err(|_| CodexSessionFailure::before_turn_dispatch(CodexSessionError::Spawn))?;
    let stdin = child.inner().stdin.take();
    let stdout = child.inner().stdout.take();
    let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
        let _ = crate::codex_capabilities::terminate_group(&mut child);
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Spawn,
        ));
    };

    #[cfg(unix)]
    if crate::codex_capabilities::set_nonblocking(&stdout).is_err() {
        let _ = crate::codex_capabilities::terminate_group(&mut child);
        return Err(CodexSessionFailure::before_turn_dispatch(
            CodexSessionError::Spawn,
        ));
    }

    let (sender, receiver) = mpsc::sync_channel(INBOUND_QUEUE_CAPACITY);
    let reader = match thread::Builder::new()
        .name("satelle-codex-reader".to_string())
        .spawn(move || {
            let mut stdout = stdout;
            read_messages(&mut stdout, deadline, sender);
            // Returning the pipe keeps it owned by the JoinHandle until the
            // parent has attempted process-group termination and joins us.
            stdout
        }) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = crate::codex_capabilities::terminate_group(&mut child);
            return Err(CodexSessionFailure::before_turn_dispatch(
                CodexSessionError::Spawn,
            ));
        }
    };
    let (write_sender, write_receiver) = mpsc::channel();
    let writer = ProtocolWriter {
        sender: write_sender,
        deadline,
    };
    let writer_thread = match thread::Builder::new()
        .name("satelle-codex-writer".to_string())
        .spawn(move || write_messages(stdin, write_receiver))
    {
        Ok(writer_thread) => writer_thread,
        Err(_) => {
            drop(writer);
            let _ = crate::codex_capabilities::terminate_group(&mut child);
            drop(receiver);
            let _ = reader.join();
            return Err(CodexSessionFailure::before_turn_dispatch(
                CodexSessionError::Spawn,
            ));
        }
    };
    let exchange_result = exchange.run(&writer, &receiver);
    let turn_dispatch_attempted = exchange.turn_dispatch_attempted();

    // Keep both pipe-owning threads connected until the process group is
    // signaled and reaped. Closing stdout first can make a backpressured child
    // exit while group termination is starting, leaving macOS unable to prove
    // that the group is contained.
    let group_stopped = crate::codex_capabilities::terminate_group(&mut child);
    // Release a reader blocked on the bounded queue before joining either pipe
    // owner. A completed reader retains stdout in its JoinHandle until join.
    drop(receiver);
    drop(writer);
    let reader_stopped = reader.join().is_ok();
    let writer_stopped = writer_thread.join().is_ok();
    if !group_stopped || !reader_stopped || !writer_stopped {
        return Err(CodexSessionFailure::after_exchange(
            CodexSessionError::Containment,
            turn_dispatch_attempted,
        ));
    }
    match exchange_result {
        Ok(output) => Ok(output),
        Err(error) => Err(CodexSessionFailure::after_exchange(
            error,
            turn_dispatch_attempted,
        )),
    }
}

pub(super) struct ProtocolWriter {
    sender: mpsc::Sender<WriteCommand>,
    deadline: Instant,
}

struct WriteCommand {
    bytes: Vec<u8>,
    completed: mpsc::Sender<Result<(), ()>>,
}

impl ProtocolWriter {
    #[cfg(test)]
    pub(super) fn expired_for_test() -> Self {
        let (sender, _receiver) = mpsc::channel();
        Self {
            sender,
            deadline: Instant::now(),
        }
    }

    pub(super) fn write(&self, value: &Value) -> Result<(), CodexSessionError> {
        self.write_after_queue(value, || {})
    }

    pub(super) fn write_after_queue(
        &self,
        value: &Value,
        after_queue: impl FnOnce(),
    ) -> Result<(), CodexSessionError> {
        if Instant::now() >= self.deadline {
            return Err(CodexSessionError::Timeout);
        }
        let mut bytes = serde_json::to_vec(value).map_err(|_| CodexSessionError::Write)?;
        bytes.push(b'\n');
        if Instant::now() >= self.deadline {
            return Err(CodexSessionError::Timeout);
        }
        let (completed, completion) = mpsc::channel();
        self.sender
            .send(WriteCommand { bytes, completed })
            .map_err(|_| CodexSessionError::Write)?;
        after_queue();
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(CodexSessionError::Timeout)?;
        match completion.recv_timeout(remaining) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(())) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(CodexSessionError::Write)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(CodexSessionError::Timeout),
        }
    }
}

fn write_messages(mut stdin: std::process::ChildStdin, receiver: mpsc::Receiver<WriteCommand>) {
    while let Ok(command) = receiver.recv() {
        let result = stdin
            .write_all(&command.bytes)
            .and_then(|()| stdin.flush())
            .map_err(|_| ());
        let failed = result.is_err();
        let _ = command.completed.send(result);
        if failed {
            return;
        }
    }
}

pub(super) enum ReadEvent {
    Line(Vec<u8>),
    Oversized,
    Eof,
    Io,
    Timeout,
}

fn read_messages<R: Read>(stdout: &mut R, deadline: Instant, sender: mpsc::SyncSender<ReadEvent>) {
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = Vec::new();
        let mut bounded = (&mut reader).take((INBOUND_LINE_LIMIT + 1) as u64);
        loop {
            match bounded.read_until(b'\n', &mut line) {
                Ok(0) if line.is_empty() => {
                    let _ = sender.send(ReadEvent::Eof);
                    return;
                }
                // App-server messages are JSON Lines. A final fragment is not
                // a message even when its bytes happen to form valid JSON.
                Ok(0) => {
                    let _ = sender.send(ReadEvent::Io);
                    return;
                }
                Ok(_) if line.last() == Some(&b'\n') => break,
                Ok(_) if line.len() > INBOUND_LINE_LIMIT => {
                    let _ = sender.send(ReadEvent::Oversized);
                    return;
                }
                Ok(_) => {}
                Err(error)
                    if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(READER_POLL_INTERVAL);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    let _ = sender.send(ReadEvent::Timeout);
                    return;
                }
                Err(_) => {
                    let _ = sender.send(ReadEvent::Io);
                    return;
                }
            }
        }
        if line.len() > INBOUND_LINE_LIMIT {
            let _ = sender.send(ReadEvent::Oversized);
            return;
        }
        if sender.send(ReadEvent::Line(line)).is_err() {
            return;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{ReadEvent, read_messages};
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn completed_reader_retains_pipe_until_join() {
        let (mut writer, reader_stream) = UnixStream::pair().expect("create stream pair");
        reader_stream
            .set_nonblocking(true)
            .expect("make reader nonblocking");
        let (sender, receiver) = mpsc::sync_channel(1);
        let (finished_sender, finished_receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut reader_stream = reader_stream;
            read_messages(&mut reader_stream, Instant::now(), sender);
            finished_sender.send(()).expect("report reader completion");
            reader_stream
        });

        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)),
            Ok(ReadEvent::Timeout)
        ));
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("reader must finish after its timeout");

        writer
            .write_all(b"pipe remains owned")
            .expect("completed reader must retain its pipe");
        let retained_pipe = reader.join().expect("reader thread must stop cleanly");
        drop(retained_pipe);
        assert!(writer.write_all(b"pipe is now closed").is_err());
    }
}
