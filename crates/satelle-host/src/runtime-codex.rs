use command_group::CommandGroup;
use satelle_core::{
    ControlPlaneCapability, ControlPlaneCapabilitySet, ControlPlaneFailureReason,
    ControlPlaneOperation, IncompatibleControlPlaneDetails, SatelleError,
};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SCHEMA_FILE_LIMIT: u64 = 2 * 1024 * 1024;
const HANDSHAKE_LINE_LIMIT: u64 = 64 * 1024;
const HANDSHAKE_MESSAGE_LIMIT: usize = 64;
const HANDSHAKE_SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
static SCHEMA_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const REQUIRED_LIFECYCLE_NOTIFICATIONS: [&str; 5] = [
    "thread/started",
    "turn/started",
    "item/started",
    "item/completed",
    "turn/completed",
];
/// Sanitized result of schema discovery plus a live initialize/initialized
/// exchange over a private stdio child process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControlPlaneProbe {
    operations: ControlPlaneCapabilitySet,
    schema_available: bool,
    handshake_completed: bool,
    goal_set: bool,
    image_input: CodexImageInputMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexImageInputMode {
    Unsupported,
    Inline,
    Local,
}

impl ControlPlaneProbe {
    const fn unavailable() -> Self {
        Self {
            operations: ControlPlaneCapabilitySet::EMPTY,
            schema_available: false,
            handshake_completed: false,
            goal_set: false,
            image_input: CodexImageInputMode::Unsupported,
        }
    }

    pub(super) const fn supports(self, capability: ControlPlaneCapability) -> bool {
        self.schema_available && self.handshake_completed && self.operations.contains(capability)
    }

    pub(super) const fn handshake_completed(self) -> bool {
        self.handshake_completed
    }
}

/// Sanitized admission evidence retained by the production adapter. It stores
/// only closed failure reasons and capability bits, never upstream method
/// names, schema bytes, process output, or app-server messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlPlaneAdmission {
    NotApplicable,
    Unavailable(ControlPlaneFailureReason),
    Probed(ControlPlaneProbe),
}

impl ControlPlaneAdmission {
    pub(crate) const fn not_applicable() -> Self {
        Self::NotApplicable
    }

    pub(crate) const fn unavailable(reason: ControlPlaneFailureReason) -> Self {
        Self::Unavailable(reason)
    }

    pub(crate) const fn from_probe(probe: ControlPlaneProbe) -> Self {
        Self::Probed(probe)
    }

    pub(crate) const fn goal_set(self) -> bool {
        matches!(self, Self::Probed(probe) if probe.goal_set)
    }

    pub(crate) const fn image_input(self) -> CodexImageInputMode {
        match self {
            Self::Probed(probe) => probe.image_input,
            Self::NotApplicable | Self::Unavailable(_) => CodexImageInputMode::Unsupported,
        }
    }

    pub(crate) fn admit(self, operation: ControlPlaneOperation) -> Result<(), SatelleError> {
        let required = operation.required_capabilities();
        let (reason, missing) = match self {
            Self::NotApplicable => return Ok(()),
            Self::Unavailable(reason) => (reason, Vec::new()),
            Self::Probed(probe) if !probe.schema_available => {
                (ControlPlaneFailureReason::SchemaUnavailable, Vec::new())
            }
            Self::Probed(probe) if !probe.handshake_completed => {
                (ControlPlaneFailureReason::HandshakeUnavailable, Vec::new())
            }
            Self::Probed(probe) => {
                let missing = required
                    .iter()
                    .copied()
                    .filter(|capability| !probe.operations.contains(*capability))
                    .collect::<Vec<_>>();
                if missing.is_empty() {
                    return Ok(());
                }
                (
                    ControlPlaneFailureReason::RequiredCapabilityMissing,
                    missing,
                )
            }
        };
        let details = IncompatibleControlPlaneDetails::new(operation, reason, &missing)
            .expect("the closed operation capability matrix is internally consistent");
        Err(SatelleError::incompatible_control_plane(details))
    }
}

impl super::CapabilityMatrix {
    pub(super) fn from_control_plane(probe: ControlPlaneProbe) -> Self {
        let unobserved = super::CapabilityEvidence::new(
            super::EvidenceSurface::Absent,
            super::LiveProofStatus::NotObserved,
        );
        let stable = |capability| {
            super::CapabilityEvidence::new(
                if probe.supports(capability) {
                    super::EvidenceSurface::Stable
                } else {
                    super::EvidenceSurface::Absent
                },
                super::LiveProofStatus::NotRequired,
            )
        };
        let stable_unobserved = |capability| {
            super::CapabilityEvidence::new(
                stable(capability).surface,
                super::LiveProofStatus::NotObserved,
            )
        };
        let handshake = super::CapabilityEvidence::new(
            if probe.handshake_completed() {
                super::EvidenceSurface::Stable
            } else {
                super::EvidenceSurface::Absent
            },
            super::LiveProofStatus::NotRequired,
        );

        Self {
            handshake,
            session_thread_creation: stable(ControlPlaneCapability::SessionCreation),
            turn_start: stable(ControlPlaneCapability::TurnStart),
            lifecycle_events: stable(ControlPlaneCapability::EventObservation),
            approval_observation: unobserved,
            native_readiness: unobserved,
            native_harmless_action: unobserved,
            recovery: if probe.supports(ControlPlaneCapability::Status)
                && probe.supports(ControlPlaneCapability::Steering)
            {
                super::CapabilityEvidence::new(
                    super::EvidenceSurface::Stable,
                    super::LiveProofStatus::NotObserved,
                )
            } else {
                unobserved
            },
            follow_up_turn: stable_unobserved(ControlPlaneCapability::Steering),
            // Detached ownership is a Host Daemon behavior, not a method in
            // the upstream schema. It remains unproven until the live journey.
            detached_turn_ownership: unobserved,
            interrupt_request: stable(ControlPlaneCapability::Cancellation),
            confirmed_stop: if probe.supports(ControlPlaneCapability::Cancellation)
                && probe.supports(ControlPlaneCapability::EventObservation)
            {
                super::CapabilityEvidence::new(
                    super::EvidenceSurface::Stable,
                    super::LiveProofStatus::NotObserved,
                )
            } else {
                unobserved
            },
        }
    }
}

pub(super) fn probe_installed_control_plane(
    runtime: &crate::codex_install::VerifiedCodexRuntime,
    timeout: Option<Duration>,
) -> ControlPlaneProbe {
    let Ok(mut schema_command) = runtime.command() else {
        return ControlPlaneProbe::unavailable();
    };
    let schema_command = move |schema_dir: &Path| {
        schema_command
            .args(["app-server", "generate-json-schema", "--out"])
            .arg(schema_dir);
        schema_command
    };
    let Ok(mut app_server_command) = runtime.command() else {
        return ControlPlaneProbe::unavailable();
    };
    app_server_command.args(["app-server", "--listen", "stdio://"]);
    probe_control_plane_with(
        schema_command,
        app_server_command,
        timeout.unwrap_or(PROBE_TIMEOUT),
    )
}

pub(crate) fn installed_app_server_command() -> Result<Command, SatelleError> {
    let runtime = crate::codex_install::admit_managed_codex_for_current_process()?;
    Ok(configure_app_server_command(runtime.command()?))
}

pub(crate) fn configure_app_server_command(mut command: Command) -> Command {
    // The Host owns this process through private pipes. No socket or public
    // listener exists at the upstream protocol seam.
    command.args(["app-server", "--listen", "stdio://"]);
    command
}

pub(super) fn probe_control_plane_with<F>(
    schema_command: F,
    app_server_command: Command,
    timeout: Duration,
) -> ControlPlaneProbe
where
    F: FnOnce(&Path) -> Command,
{
    probe_control_plane_with_handshake(schema_command, timeout, |schema_dir, deadline| {
        perform_handshake(app_server_command, schema_dir, deadline)
    })
}

fn probe_control_plane_with_handshake<F, H>(
    schema_command: F,
    timeout: Duration,
    handshake: H,
) -> ControlPlaneProbe
where
    F: FnOnce(&Path) -> Command,
    H: FnOnce(&Path, Instant) -> bool,
{
    let deadline = Instant::now() + timeout;
    let Some(schema_dir) = SchemaDirectory::create() else {
        return ControlPlaneProbe::unavailable();
    };
    let mut command = schema_command(schema_dir.path());
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !run_to_completion(&mut command, deadline) {
        return ControlPlaneProbe::unavailable();
    }

    let Some(schema) = StableProtocolSchema::read(schema_dir.path()) else {
        return ControlPlaneProbe::unavailable();
    };
    let operations = schema.operation_capabilities();
    let goal_set = schema.client_requests.declares("thread/goal/set");
    let image_input = if schema.client_requests.declares_user_input("localImage") {
        CodexImageInputMode::Local
    } else if schema.client_requests.declares_user_input("image") {
        CodexImageInputMode::Inline
    } else {
        CodexImageInputMode::Unsupported
    };
    let handshake_declared = schema.client_requests.declares("initialize")
        && schema.client_notifications.declares("initialized");
    let handshake_completed = handshake_declared && handshake(schema_dir.path(), deadline);

    ControlPlaneProbe {
        operations,
        schema_available: true,
        handshake_completed,
        goal_set,
        image_input,
    }
}

struct StableProtocolSchema {
    client_requests: MethodSchema,
    client_notifications: MethodSchema,
    server_notifications: MethodSchema,
}

impl StableProtocolSchema {
    fn read(schema_dir: &Path) -> Option<Self> {
        Some(Self {
            client_requests: MethodSchema::read(&schema_dir.join("ClientRequest.json"))?,
            client_notifications: MethodSchema::read(&schema_dir.join("ClientNotification.json"))?,
            server_notifications: MethodSchema::read(&schema_dir.join("ServerNotification.json"))?,
        })
    }

    fn operation_capabilities(&self) -> ControlPlaneCapabilitySet {
        ControlPlaneCapability::ALL
            .into_iter()
            .filter(|capability| match capability {
                ControlPlaneCapability::SessionCreation => {
                    self.client_requests.declares("thread/start")
                }
                ControlPlaneCapability::TurnStart => self.client_requests.declares("turn/start"),
                ControlPlaneCapability::EventObservation => REQUIRED_LIFECYCLE_NOTIFICATIONS
                    .iter()
                    .all(|method| self.server_notifications.declares(method)),
                // Public Satelle steering starts a follow-up Turn on the same
                // thread. It does not map to upstream in-flight turn/steer.
                ControlPlaneCapability::Steering => {
                    self.client_requests.declares("turn/start")
                        && self.client_requests.declares("thread/resume")
                }
                ControlPlaneCapability::Status => self.client_requests.declares("thread/read"),
                ControlPlaneCapability::Cancellation => {
                    self.client_requests.declares("turn/interrupt")
                }
            })
            .collect()
    }
}

struct MethodSchema(Value);

impl MethodSchema {
    fn read(path: &Path) -> Option<Self> {
        let file = File::open(path).ok()?;
        let mut bytes = Vec::new();
        file.take(SCHEMA_FILE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > SCHEMA_FILE_LIMIT as usize {
            return None;
        }
        serde_json::from_slice(&bytes).ok().map(Self)
    }

    fn declares(&self, expected: &str) -> bool {
        declares_method(&self.0, expected)
    }

    fn declares_user_input(&self, expected: &str) -> bool {
        let Some(request) = request_variant(&self.0, "turn/start") else {
            return false;
        };
        let Some(params) = resolve_schema(&self.0, request.pointer("/properties/params")) else {
            return false;
        };
        let Some(input) = resolve_schema(&self.0, params.pointer("/properties/input/items")) else {
            return false;
        };
        input
            .get("oneOf")
            .and_then(Value::as_array)
            .is_some_and(|variants| {
                variants.iter().any(|variant| {
                    resolve_schema(&self.0, Some(variant))
                        .and_then(|variant| variant.pointer("/properties/type"))
                        .is_some_and(|kind| schema_string_value(kind, expected))
                })
            })
    }
}

fn request_variant<'a>(root: &'a Value, method: &str) -> Option<&'a Value> {
    root.get("oneOf")?.as_array()?.iter().find(|variant| {
        variant
            .pointer("/properties/method")
            .is_some_and(|kind| schema_string_value(kind, method))
    })
}

fn resolve_schema<'a>(root: &'a Value, value: Option<&'a Value>) -> Option<&'a Value> {
    let value = value?;
    match value.get("$ref").and_then(Value::as_str) {
        Some(reference) => root.pointer(reference.strip_prefix('#')?),
        None => Some(value),
    }
}

fn schema_string_value(value: &Value, expected: &str) -> bool {
    value.get("const").and_then(Value::as_str) == Some(expected)
        || value
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn declares_method(value: &Value, expected: &str) -> bool {
    value
        .get("oneOf")
        .and_then(Value::as_array)
        .is_some_and(|variants| {
            variants.iter().any(|variant| {
                variant
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get("method"))
                    .and_then(Value::as_object)
                    .and_then(|method| method.get("enum"))
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        values.iter().any(|value| value.as_str() == Some(expected))
                    })
            })
        })
}

fn perform_handshake(mut command: Command, working_dir: &Path, deadline: Instant) -> bool {
    if Instant::now() >= deadline {
        return false;
    }
    let mut child = match command
        .current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
    {
        Ok(child) => child,
        Err(_) => return false,
    };
    let Some(mut stdin) = child.inner().stdin.take() else {
        let _ = super::terminate_group(&mut child);
        return false;
    };
    let Some(stdout) = child.inner().stdout.take() else {
        let _ = super::terminate_group(&mut child);
        return false;
    };

    if !write_initialize_request(&mut stdin) {
        let _ = super::terminate_group(&mut child);
        return false;
    }

    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let result = read_initialize_response(stdout, deadline);
        let _ = sender.send(result);
    });
    let remaining = deadline.saturating_duration_since(Instant::now());
    let accepted = receiver.recv_timeout(remaining).unwrap_or(false);

    let initialized_sent = accepted && write_initialized_notification(&mut stdin);

    let shutdown_deadline = Instant::now()
        + deadline
            .saturating_duration_since(Instant::now())
            .min(HANDSHAKE_SHUTDOWN_GRACE);
    let status = super::wait_for_group(&mut child, shutdown_deadline);
    // The app-server is expected to remain alive after initialization. Always
    // terminate the complete process group or Windows job, including when the
    // leader exited after spawning descendants.
    let group_stopped = super::terminate_group(&mut child);
    drop(stdin);
    // A healthy app-server remains alive while its stdin is open. A status
    // query failure must not be confused with reaching the observation
    // deadline, and an early exit is incompatible even when its status is 0.
    let process_accepted_initialization =
        matches!(status, super::GroupWaitOutcome::Deadline) && group_stopped;
    // Unix readers are nonblocking and enforce the same absolute deadline, so
    // even a group-escaping descendant cannot hold this join open. Windows job
    // containment closes every inherited pipe before a reader is joined.
    #[cfg(unix)]
    let reader_stopped = reader.join().is_ok();
    #[cfg(not(unix))]
    let reader_stopped = group_stopped && reader.join().is_ok();
    initialized_sent && process_accepted_initialization && reader_stopped
}

fn write_initialize_request(writer: &mut impl Write) -> bool {
    write_json_line(
        writer,
        &json!({
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "satelle-host",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "capabilities": {"experimentalApi": false}
            }
        }),
    )
}

fn write_initialized_notification(writer: &mut impl Write) -> bool {
    write_json_line(writer, &json!({"method": "initialized"}))
}

fn write_json_line(writer: &mut impl Write, value: &Value) -> bool {
    serde_json::to_writer(&mut *writer, value).is_ok()
        && writer.write_all(b"\n").is_ok()
        && writer.flush().is_ok()
}

fn read_initialize_response(stdout: std::process::ChildStdout, _deadline: Instant) -> bool {
    #[cfg(unix)]
    if super::set_nonblocking(&stdout).is_err() {
        return false;
    }
    let mut reader = BufReader::new(stdout);

    for _ in 0..HANDSHAKE_MESSAGE_LIMIT {
        let mut line = Vec::new();
        let mut bounded = (&mut reader).take(HANDSHAKE_LINE_LIMIT + 1);
        loop {
            match bounded.read_until(b'\n', &mut line) {
                Ok(0) => return false,
                Ok(_) if line.last() == Some(&b'\n') => break,
                Ok(_) if line.len() > HANDSHAKE_LINE_LIMIT as usize => return false,
                // A nonblocking pipe may yield a valid prefix before the
                // delimiter arrives. Keep accumulating the same bounded line
                // instead of attempting to parse a partial JSON object.
                Ok(_) => {}
                #[cfg(unix)]
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < _deadline =>
                {
                    if line.len() > HANDSHAKE_LINE_LIMIT as usize {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return false,
            }
        }
        if line.len() > HANDSHAKE_LINE_LIMIT as usize {
            return false;
        }
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            return false;
        };
        let Some(object) = message.as_object() else {
            return false;
        };

        if object.get("id").and_then(Value::as_u64) == Some(1) {
            return object
                .get("result")
                .and_then(Value::as_object)
                .is_some_and(|result| {
                    ["userAgent", "codexHome", "platformFamily", "platformOs"]
                        .iter()
                        .all(|field| result.get(*field).and_then(Value::as_str).is_some())
                });
        }
        // Notifications have no request id. Unknown methods are deliberately
        // normalized to this branch and discarded without side effects.
        if object.get("id").is_none() && object.get("method").and_then(Value::as_str).is_some() {
            continue;
        }
        return false;
    }
    false
}

fn run_to_completion(command: &mut Command, deadline: Instant) -> bool {
    if Instant::now() >= deadline {
        return false;
    }
    let Ok(mut child) = command.group_spawn() else {
        return false;
    };
    let status = super::wait_for_group(&mut child, deadline);
    let group_stopped = super::terminate_group(&mut child);
    matches!(status, super::GroupWaitOutcome::Exited(status) if status.success()) && group_stopped
}

struct SchemaDirectory(PathBuf);

impl SchemaDirectory {
    fn create() -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let sequence = SCHEMA_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "satelle-codex-schema-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;

            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        builder.create(&path).ok()?;
        Some(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for SchemaDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
