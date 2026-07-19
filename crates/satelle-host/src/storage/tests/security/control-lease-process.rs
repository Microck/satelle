use super::*;

const PROBE_PREFIX: &str = "SATELLE_CONTROL_LEASE:";
const DEADLOCK_GUARD_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy)]
enum DrainStream {
    Stdout,
    Stderr,
}

type DrainCompletion = (DrainStream, Result<String, String>);

#[derive(Default)]
struct CapturedOutput {
    stdout: Option<String>,
    stderr: Option<String>,
    errors: Vec<String>,
}

impl CapturedOutput {
    fn record(&mut self, (stream, captured): DrainCompletion) -> Result<(), String> {
        let (name, destination) = match stream {
            DrainStream::Stdout => ("stdout", &mut self.stdout),
            DrainStream::Stderr => ("stderr", &mut self.stderr),
        };
        let captured = captured.map_err(|error| format!("failed to drain {name}: {error}"))?;
        if destination.replace(captured).is_some() {
            return Err(format!("{name} reported drain completion twice"));
        }
        Ok(())
    }

    fn keep(&mut self, completion: DrainCompletion) {
        if let Err(error) = self.record(completion) {
            self.errors.push(error);
        }
    }

    fn diagnostics(&self) -> (String, String) {
        let stdout = self.stdout.as_deref().unwrap_or("<stdout unavailable>");
        let stderr = self.stderr.as_deref().unwrap_or("<stderr unavailable>");
        let drain_errors = if self.errors.is_empty() {
            String::new()
        } else {
            format!("\ndrain errors: {}", self.errors.join("; "))
        };
        (stdout.to_owned(), format!("{stderr}{drain_errors}"))
    }
}

struct Probe {
    role: String,
    child: Option<std::process::Child>,
    commands: Option<std::process::ChildStdin>,
    events: std::sync::mpsc::Receiver<String>,
    drain_completions: std::sync::mpsc::Receiver<DrainCompletion>,
    stdout_drain: Option<std::thread::JoinHandle<()>>,
    stderr_drain: Option<std::thread::JoinHandle<()>>,
}

impl Probe {
    fn spawn(role: &str, state: &std::path::Path) -> Self {
        use std::process::Stdio;

        let mut child = std::process::Command::new(
            std::env::current_exe().expect("locate the current test binary"),
        )
        .args([
            "--exact",
            "storage::tests::security::control_lease_process::probe_child",
            "--nocapture",
        ])
        .env("SATELLE_CONTROL_LEASE_PROBE", role)
        .env("SATELLE_CONTROL_LEASE_STATE", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the Control Lease probe");
        let commands = child.stdin.take().expect("capture probe stdin");
        let stdout = child.stdout.take().expect("capture probe stdout");
        let stderr = child.stderr.take().expect("capture probe stderr");
        let (event_sender, events) = std::sync::mpsc::channel();
        let (drain_sender, drain_completions) = std::sync::mpsc::channel();
        let stdout_drain_sender = drain_sender.clone();
        let stdout_drain = std::thread::spawn(move || {
            let captured = drain_stdout(stdout, event_sender).map_err(|error| error.to_string());
            let _ = stdout_drain_sender.send((DrainStream::Stdout, captured));
        });
        let stderr_drain = std::thread::spawn(move || {
            let captured = drain_stderr(stderr).map_err(|error| error.to_string());
            let _ = drain_sender.send((DrainStream::Stderr, captured));
        });
        Self {
            role: role.to_owned(),
            child: Some(child),
            commands: Some(commands),
            events,
            drain_completions,
            stdout_drain: Some(stdout_drain),
            stderr_drain: Some(stderr_drain),
        }
    }

    fn send(&mut self, command: &str) {
        use std::io::Write;

        let result = {
            let commands = self.commands.as_mut().expect("probe stdin is open");
            writeln!(commands, "{command}").and_then(|()| commands.flush())
        };
        if let Err(error) = result {
            self.fail(format!("failed to send {command}: {error}"));
        }
    }

    fn expect_event(&mut self, expected: &str) {
        match self.events.recv_timeout(DEADLOCK_GUARD_LIMIT) {
            Ok(event) if event == expected => {}
            Ok(event) => self.fail(format!("expected event {expected}, received {event}")),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.fail(format!(
                "cleanup-only deadlock guard expired while waiting for {expected}"
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                self.fail(format!("probe exited before reporting {expected}"));
            }
        }
    }

    fn finish(mut self) {
        self.send("EXIT");
        self.expect_event("DONE");
        drop(self.commands.take());

        // This deadline bounds cleanup only. Passing the test never depends
        // on how quickly either child stream closes within the guard window.
        let deadline = std::time::Instant::now() + DEADLOCK_GUARD_LIMIT;
        let mut captured = CapturedOutput::default();
        for _ in 0..2 {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                self.fail_with_output(
                    "cleanup-only deadlock guard expired while draining child output".to_owned(),
                    captured,
                );
            };
            match self.drain_completions.recv_timeout(remaining) {
                Ok(completion) => {
                    if let Err(error) = captured.record(completion) {
                        self.fail_with_output(error, captured);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.fail_with_output(
                    "cleanup-only deadlock guard expired while draining child output".to_owned(),
                    captured,
                ),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => self.fail_with_output(
                    "child output drain disconnected before both streams closed".to_owned(),
                    captured,
                ),
            }
        }

        self.join_drains(&mut captured);
        let status = self.reap(false);
        let (stdout, stderr) = captured.diagnostics();
        assert!(
            status.is_some_and(|status| status.success()),
            "{} probe failed with status {status:?}:\nstdout:\n{stdout}\nstderr:\n{stderr}",
            self.role,
        );
    }

    fn fail(&mut self, reason: String) -> ! {
        self.fail_with_output(reason, CapturedOutput::default())
    }

    fn fail_with_output(&mut self, reason: String, mut captured: CapturedOutput) -> ! {
        drop(self.commands.take());
        let status = self.reap(true);
        self.join_drains(&mut captured);
        for completion in self.drain_completions.try_iter() {
            captured.keep(completion);
        }
        let (stdout, stderr) = captured.diagnostics();
        panic!(
            "{} probe {reason}; status {status:?}:\nstdout:\n{stdout}\nstderr:\n{stderr}",
            self.role,
        );
    }

    fn reap(&mut self, terminate: bool) -> Option<std::process::ExitStatus> {
        self.child.take().and_then(|mut child| {
            if terminate {
                match child.try_wait() {
                    Ok(Some(status)) => return Some(status),
                    Ok(None) | Err(_) => {
                        let _ = child.kill();
                    }
                }
            }
            child.wait().ok()
        })
    }

    fn join_drains(&mut self, captured: &mut CapturedOutput) {
        for (stream, drain) in [
            ("stdout", self.stdout_drain.take()),
            ("stderr", self.stderr_drain.take()),
        ] {
            if drain.is_some_and(|drain| drain.join().is_err()) {
                captured
                    .errors
                    .push(format!("{stream} drain thread panicked"));
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        drop(self.commands.take());
        let _ = self.reap(true);
        let mut captured = CapturedOutput::default();
        self.join_drains(&mut captured);
        for completion in self.drain_completions.try_iter() {
            captured.keep(completion);
        }
    }
}

fn drain_stdout(
    stdout: std::process::ChildStdout,
    events: std::sync::mpsc::Sender<String>,
) -> std::io::Result<String> {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(stdout);
    let mut captured = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(captured);
        }
        captured.push_str(&line);
        if let Some(event) = probe_event(&line) {
            let _ = events.send(event.to_owned());
        }
    }
}

fn probe_event(line: &str) -> Option<&str> {
    line.split_whitespace()
        .last()?
        .strip_prefix(PROBE_PREFIX)
        .filter(|event| !event.is_empty())
}

#[test]
fn probe_event_accepts_a_libtest_prefixed_marker_without_near_matches() {
    assert_eq!(
        Some("READY"),
        probe_event(
            "test storage::tests::security::control_lease_process::probe_child ... \
             SATELLE_CONTROL_LEASE:READY\n"
        )
    );
    assert_eq!(
        None,
        probe_event("test probe_child ... SATELLE_CONTROL_LEASED:READY\n")
    );
    assert_eq!(
        None,
        probe_event("test probe_child ... XSATELLE_CONTROL_LEASE:READY\n")
    );
    assert_eq!(
        None,
        probe_event("test probe_child ... SATELLE_CONTROL_LEASE:\n")
    );
    assert_eq!(
        None,
        probe_event("test probe_child ... SATELLE_CONTROL_LEASE:READY trailing\n")
    );
}

fn drain_stderr(mut stderr: std::process::ChildStderr) -> std::io::Result<String> {
    use std::io::Read;

    let mut captured = String::new();
    stderr.read_to_string(&mut captured)?;
    Ok(captured)
}

#[test]
fn cross_process_control_lease_blocks_competing_turn_after_owner_handoff() {
    let state = TempDir::new().expect("temporary state directory");
    let mut owner = Probe::spawn("owner", state.path());
    let mut lock_contender = Probe::spawn("lock-contender", state.path());
    let mut handoff_contender = Probe::spawn("handoff-contender", state.path());

    // All processes are alive before any phase command. Each contender makes
    // exactly one open attempt in its assigned phase, so ownership exclusion
    // and durable lease exclusion remain separate observable contracts.
    owner.expect_event("READY");
    lock_contender.expect_event("READY");
    handoff_contender.expect_event("READY");
    lock_contender.send("OPEN");
    lock_contender.expect_event("STORE_IN_USE");
    owner.send("RELEASE");
    owner.expect_event("RELEASED");
    handoff_contender.send("ADMIT");
    handoff_contender.expect_event("LEASE_CONFLICT");

    owner.finish();
    lock_contender.finish();
    handoff_contender.finish();
}

fn emit_event(event: &str) {
    use std::io::Write;

    println!("{PROBE_PREFIX}{event}");
    std::io::stdout().flush().expect("flush a probe event");
}

fn read_command() -> String {
    use std::io::BufRead;

    let mut command = String::new();
    let bytes = std::io::stdin()
        .lock()
        .read_line(&mut command)
        .expect("read a probe command");
    assert_ne!(bytes, 0, "probe command pipe closed unexpectedly");
    command.trim().to_owned()
}

#[test]
fn probe_child() {
    let Ok(role) = std::env::var("SATELLE_CONTROL_LEASE_PROBE") else {
        return;
    };
    let state = std::path::PathBuf::from(
        std::env::var_os("SATELLE_CONTROL_LEASE_STATE").expect("probe state directory"),
    );

    match role.as_str() {
        "owner" => {
            let (mut storage, recovery) = Storage::open(&state).expect("owner opens Storage");
            assert!(recovery.is_empty());
            let session = initial_session(&storage, SESSION_1, TURN_1, at(0));
            assert!(matches!(
                storage
                    .begin_session(
                        &session,
                        &admission(
                            IdempotentOperation::Run,
                            "cross-process-owner",
                            "request-cross-process-owner",
                            at(0),
                        ),
                    )
                    .expect("owner admits the first Turn"),
                AdmissionOutcome::Execute { .. }
            ));
            emit_event("READY");
            assert_eq!("RELEASE", read_command());
            drop(storage);
            emit_event("RELEASED");
        }
        "lock-contender" => {
            emit_event("READY");
            assert_eq!("OPEN", read_command());
            let error = match Storage::open(&state) {
                Ok(_) => panic!("the owner process must retain exclusive Storage ownership"),
                Err(error) => error,
            };
            assert_eq!(StorageErrorKind::StoreInUse, error.kind());
            emit_event("STORE_IN_USE");
        }
        "handoff-contender" => {
            emit_event("READY");
            assert_eq!("ADMIT", read_command());
            let (mut storage, recovery) =
                Storage::open(&state).expect("handoff contender opens Storage");
            assert_eq!(1, recovery.len());
            assert_eq!(&session_id(SESSION_1), recovery[0].session_id());
            let competing = initial_session(&storage, SESSION_2, TURN_2, at(1));
            let error = storage
                .begin_session(
                    &competing,
                    &admission(
                        IdempotentOperation::Run,
                        "cross-process-contender",
                        "request-cross-process-contender",
                        at(1),
                    ),
                )
                .expect_err("persisted Control Lease blocks the competing Turn");
            assert_eq!(StorageErrorKind::LeaseConflict, error.kind());
            assert_eq!(Some(&session_id(SESSION_1)), error.conflicting_session_id());
            let durable_counts: (i64, i64, i64, i64, i64) = storage
                .connection_for_test()
                .query_row(
                    "SELECT \
                       (SELECT count(*) FROM sessions), \
                       (SELECT count(*) FROM turns), \
                       (SELECT count(*) FROM control_leases), \
                       (SELECT count(*) FROM idempotency_records), \
                       (SELECT count(*) FROM turns WHERE state IN ('starting', 'running', 'recovery_pending'))",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .expect("count durable admission rows");
            assert_eq!((1, 1, 1, 1, 1), durable_counts);
            emit_event("LEASE_CONFLICT");
        }
        unexpected => panic!("unexpected Control Lease probe role {unexpected}"),
    }

    assert_eq!("EXIT", read_command());
    emit_event("DONE");
}
