use super::arguments::{
    HostLifecycleInput, HostUpdateInput, RepairInput, RunInput, SetupInput, SteerInput, StopInput,
};
use super::result::structured;
use command_group::{CommandGroup as _, GroupChild};
use rmcp::ErrorData as McpError;
use rmcp::model::CallToolResult;
use serde_json::Value;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(20);
// Direct Host requests have a 30-second deadline. Leave enough time for the
// CLI's Ctrl-C path to stop an admitted Turn and drain its terminal evidence
// before using the force-kill fallback.
const GRACEFUL_INTERRUPT_TIMEOUT: Duration = Duration::from_secs(35);

pub(super) async fn run(
    executable: Arc<PathBuf>,
    mut input: RunInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    args.push("run".to_string());
    let prompt = std::mem::take(&mut input.prompt);
    prompt_args(&mut args, PromptOptions::from_run(input));
    args.extend([
        "--events".to_string(),
        "none".to_string(),
        "--quiet".to_string(),
        "--json".to_string(),
        "-".to_string(),
    ]);
    execute(
        executable,
        args,
        Some(prompt),
        cancellation,
        CancellationMode::GracefulInterrupt,
    )
    .await
}

pub(super) async fn steer(
    executable: Arc<PathBuf>,
    mut input: SteerInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    let session_id = std::mem::take(&mut input.session_id);
    let prompt = std::mem::take(&mut input.prompt);
    args.extend(["steer".to_string(), session_id]);
    prompt_args(&mut args, PromptOptions::from_steer(input));
    args.extend([
        "--events".to_string(),
        "none".to_string(),
        "--quiet".to_string(),
        "--json".to_string(),
        "-".to_string(),
    ]);
    execute(
        executable,
        args,
        Some(prompt),
        cancellation,
        CancellationMode::GracefulInterrupt,
    )
    .await
}

pub(super) async fn stop(
    executable: Arc<PathBuf>,
    input: StopInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    args.extend(["stop".to_string(), input.session_id]);
    optional(&mut args, "--host", input.host);
    args.push("--json".to_string());
    execute(
        executable,
        args,
        None,
        cancellation,
        CancellationMode::ForceKill,
    )
    .await
}

pub(super) async fn setup(
    executable: Arc<PathBuf>,
    input: SetupInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    args.push("setup".to_string());
    optional(&mut args, "--host", input.host);
    flag(&mut args, "--dry-run", input.dry_run);
    flag(&mut args, "--verify", input.verify);
    flag(&mut args, "--on-demand", input.on_demand);
    flag(&mut args, "--persistent", input.persistent);
    repeated(&mut args, "--component", input.components);
    flag(&mut args, "--yes", input.yes);
    flag(&mut args, "--no-input", input.no_input);
    optional(&mut args, "--expected-host-id", input.expected_host_id);
    args.push("--json".to_string());
    execute(
        executable,
        args,
        None,
        cancellation,
        CancellationMode::ForceKill,
    )
    .await
}

pub(super) async fn repair(
    executable: Arc<PathBuf>,
    input: RepairInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    args.push("repair".to_string());
    optional(&mut args, "--host", input.host);
    optional(&mut args, "--run", input.run);
    flag(&mut args, "--dry-run", input.dry_run);
    flag(&mut args, "--yes", input.yes);
    flag(&mut args, "--no-input", input.no_input);
    args.push("--json".to_string());
    execute(
        executable,
        args,
        None,
        cancellation,
        CancellationMode::ForceKill,
    )
    .await
}

pub(super) async fn host_update(
    executable: Arc<PathBuf>,
    input: HostUpdateInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    args.extend(["host".to_string(), "update".to_string()]);
    optional(&mut args, "--host", input.host);
    repeated(&mut args, "--component", input.components);
    flag(&mut args, "--dry-run", input.dry_run);
    flag(&mut args, "--yes", input.yes);
    flag(&mut args, "--no-input", input.no_input);
    args.extend(["--quiet".to_string(), "--json".to_string()]);
    execute(
        executable,
        args,
        None,
        cancellation,
        CancellationMode::ForceKill,
    )
    .await
}

pub(super) async fn host_lifecycle(
    executable: Arc<PathBuf>,
    input: HostLifecycleInput,
    profile: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
) -> Result<CallToolResult, McpError> {
    let mut args = base_args(profile.as_deref());
    args.extend(["host".to_string(), input.action.as_str().to_string()]);
    optional(&mut args, "--host", input.host);
    flag(&mut args, "--yes", input.yes);
    flag(&mut args, "--no-input", input.no_input);
    args.push("--json".to_string());
    execute(
        executable,
        args,
        None,
        cancellation,
        CancellationMode::ForceKill,
    )
    .await
}

struct PromptOptions {
    host: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    detach: bool,
    yolo: bool,
    no_yolo: bool,
    experimental_provider_computer_use: bool,
    refresh_provider_smoke_test: bool,
    timeout: Option<String>,
    images: Vec<String>,
}

impl PromptOptions {
    fn from_run(input: RunInput) -> Self {
        Self {
            host: input.host,
            model: input.model,
            provider: input.provider,
            detach: input.detach,
            yolo: input.yolo,
            no_yolo: input.no_yolo,
            experimental_provider_computer_use: input.experimental_provider_computer_use,
            refresh_provider_smoke_test: input.refresh_provider_smoke_test,
            timeout: input.timeout,
            images: input.images,
        }
    }

    fn from_steer(input: SteerInput) -> Self {
        Self {
            host: input.host,
            model: input.model,
            provider: input.provider,
            detach: input.detach,
            yolo: input.yolo,
            no_yolo: input.no_yolo,
            experimental_provider_computer_use: input.experimental_provider_computer_use,
            refresh_provider_smoke_test: input.refresh_provider_smoke_test,
            timeout: input.timeout,
            images: input.images,
        }
    }
}

fn prompt_args(args: &mut Vec<String>, options: PromptOptions) {
    optional(args, "--host", options.host);
    optional(args, "--model", options.model);
    optional(args, "--provider", options.provider);
    flag(args, "--detach", options.detach);
    flag(args, "--yolo", options.yolo);
    flag(args, "--no-yolo", options.no_yolo);
    flag(
        args,
        "--experimental-provider-computer-use",
        options.experimental_provider_computer_use,
    );
    flag(
        args,
        "--refresh-provider-smoke-test",
        options.refresh_provider_smoke_test,
    );
    optional(args, "--timeout", options.timeout);
    repeated(args, "--image", options.images);
}

fn base_args(profile: Option<&str>) -> Vec<String> {
    let mut args = vec!["--error-format".to_string(), "json".to_string()];
    if let Some(profile) = profile {
        args.extend(["--profile".to_string(), profile.to_string()]);
    }
    args
}

fn optional(args: &mut Vec<String>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        args.extend([name.to_string(), value]);
    }
}

fn repeated(args: &mut Vec<String>, name: &str, values: Vec<String>) {
    for value in values {
        args.extend([name.to_string(), value]);
    }
}

fn flag(args: &mut Vec<String>, name: &str, enabled: bool) {
    if enabled {
        args.push(name.to_string());
    }
}

async fn execute(
    executable: Arc<PathBuf>,
    args: Vec<String>,
    stdin: Option<String>,
    cancellation: impl Future<Output = ()> + Send,
    cancellation_mode: CancellationMode,
) -> Result<CallToolResult, McpError> {
    let (cancel, cancelled) = mpsc::channel();
    let mut task = tokio::task::spawn_blocking(move || {
        execute_blocking(
            executable.as_path(),
            args,
            stdin,
            cancelled,
            cancellation_mode,
        )
    });
    tokio::pin!(cancellation);
    let outcome = tokio::select! {
        biased;
        _ = &mut cancellation => {
            let _ = cancel.send(());
            task.await
        }
        outcome = &mut task => outcome,
    }
    .map_err(|error| {
        McpError::internal_error(format!("Satelle CLI task failed: {error}"), None)
    })??;
    match outcome {
        ProcessOutcome::Completed(output) => tool_result(output),
        ProcessOutcome::Cancelled => Err(McpError::internal_error(
            "MCP tool request was cancelled",
            None,
        )),
    }
}

fn execute_blocking(
    executable: &Path,
    args: Vec<String>,
    stdin: Option<String>,
    cancelled: mpsc::Receiver<()>,
    cancellation_mode: CancellationMode,
) -> Result<ProcessOutcome, McpError> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_group(&mut command).map_err(|error| {
        McpError::internal_error(format!("could not start Satelle command: {error}"), None)
    })?;
    // Drain both output pipes before writing stdin. A child is allowed to emit output before it
    // consumes the prompt, so delaying these readers can deadlock both sides on full pipe buffers.
    let output = OutputReaders::start(&mut child);
    if let Some(stdin) = stdin {
        let mut child_stdin = child
            .inner()
            .stdin
            .take()
            .expect("piped Satelle command stdin");
        if let Err(error) = child_stdin.write_all(stdin.as_bytes()) {
            // A child can reject its arguments and close stdin before a large prompt is fully
            // written. Preserve that completed command's canonical stderr instead of replacing
            // its typed CLI failure with an MCP transport error.
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                drop(child_stdin);
                return wait_for_output(child, output, cancelled, cancellation_mode);
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = output.join();
            return Err(McpError::internal_error(
                format!("could not write Satelle prompt: {error}"),
                None,
            ));
        }
    }
    wait_for_output(child, output, cancelled, cancellation_mode)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationMode {
    GracefulInterrupt,
    ForceKill,
}

struct SpawnedChild {
    child: GroupChild,
    #[cfg(windows)]
    interrupt: WindowsInterruptEvent,
}

impl std::ops::Deref for SpawnedChild {
    type Target = GroupChild;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl std::ops::DerefMut for SpawnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

#[cfg(not(windows))]
fn spawn_group(command: &mut Command) -> std::io::Result<SpawnedChild> {
    command.group_spawn().map(|child| SpawnedChild { child })
}

#[cfg(windows)]
struct WindowsInterruptEvent(std::os::windows::io::OwnedHandle);

#[cfg(windows)]
impl WindowsInterruptEvent {
    fn create(command: &mut Command) -> std::io::Result<Self> {
        use std::os::windows::io::{FromRawHandle as _, RawHandle};
        use windows_sys::Win32::System::Threading::CreateEventW;

        let name = format!("Local\\SatelleMcpInterrupt-{}", uuid::Uuid::now_v7());
        let wide_name = name.encode_utf16().chain([0]).collect::<Vec<_>>();
        // SAFETY: the security descriptor is null, booleans are valid, and wide_name is
        // NUL-terminated for the duration of the call.
        let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, wide_name.as_ptr()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        command.env(crate::transport::MCP_INTERRUPT_EVENT_ENV, name);
        // SAFETY: CreateEventW returned a new owned HANDLE that this wrapper closes once.
        Ok(Self(unsafe {
            std::os::windows::io::OwnedHandle::from_raw_handle(handle as RawHandle)
        }))
    }

    fn signal(&self) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::Threading::SetEvent;

        // SAFETY: the owned handle remains valid for this call and names an event object.
        if unsafe { SetEvent(self.0.as_raw_handle()) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
fn spawn_group(command: &mut Command) -> std::io::Result<SpawnedChild> {
    let interrupt = WindowsInterruptEvent::create(command)?;
    let child = command.group_spawn()?;
    Ok(SpawnedChild { child, interrupt })
}

struct OutputReaders {
    stdout: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
}

impl OutputReaders {
    fn start(child: &mut SpawnedChild) -> Self {
        let stdout = child
            .inner()
            .stdout
            .take()
            .expect("piped Satelle command stdout");
        let stderr = child
            .inner()
            .stderr
            .take()
            .expect("piped Satelle command stderr");
        Self {
            stdout: std::thread::spawn(move || read_output(stdout)),
            stderr: std::thread::spawn(move || read_output(stderr)),
        }
    }

    fn join(self) -> Result<(Vec<u8>, Vec<u8>), McpError> {
        Ok((
            join_output(self.stdout, "stdout")?,
            join_output(self.stderr, "stderr")?,
        ))
    }
}

#[derive(Debug)]
enum ProcessOutcome {
    Completed(Output),
    Cancelled,
}

fn wait_for_output(
    mut child: SpawnedChild,
    output: OutputReaders,
    cancelled: mpsc::Receiver<()>,
    cancellation_mode: CancellationMode,
) -> Result<ProcessOutcome, McpError> {
    loop {
        if let Some(status) = child.try_wait().map_err(wait_error)? {
            return completed_process(status, output).map(ProcessOutcome::Completed);
        }
        match cancelled.recv_timeout(PROCESS_POLL_INTERVAL) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(status) = child.try_wait().map_err(wait_error)? {
                    return completed_process(status, output).map(ProcessOutcome::Completed);
                }
                terminate_cancelled_child(child, output, cancellation_mode)?;
                return Ok(ProcessOutcome::Cancelled);
            }
        }
    }
}

fn terminate_cancelled_child(
    mut child: SpawnedChild,
    output: OutputReaders,
    cancellation_mode: CancellationMode,
) -> Result<(), McpError> {
    if cancellation_mode == CancellationMode::GracefulInterrupt
        && send_graceful_interrupt(&child).is_ok()
    {
        let deadline = Instant::now() + GRACEFUL_INTERRUPT_TIMEOUT;
        while Instant::now() < deadline {
            if child.try_wait().map_err(wait_error)?.is_some() {
                output.join()?;
                return Ok(());
            }
            std::thread::sleep(PROCESS_POLL_INTERVAL);
        }
    }

    if let Err(error) = child.kill() {
        if child.try_wait().map_err(wait_error)?.is_some() {
            output.join()?;
            return Ok(());
        }
        return Err(McpError::internal_error(
            format!("could not terminate cancelled Satelle command: {error}"),
            None,
        ));
    }
    child.wait().map_err(wait_error)?;
    output.join()?;
    Ok(())
}

#[cfg(unix)]
fn send_graceful_interrupt(child: &SpawnedChild) -> std::io::Result<()> {
    use command_group::{Signal, UnixChildExt as _};

    child.child.signal(Signal::SIGINT)
}

#[cfg(windows)]
fn send_graceful_interrupt(child: &SpawnedChild) -> std::io::Result<()> {
    child.interrupt.signal()
}

fn completed_process(status: ExitStatus, output: OutputReaders) -> Result<Output, McpError> {
    let (stdout, stderr) = output.join()?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_output(mut stream: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_output(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> Result<Vec<u8>, McpError> {
    reader
        .join()
        .map_err(|_| McpError::internal_error(format!("Satelle {stream} reader panicked"), None))?
        .map_err(|error| {
            McpError::internal_error(format!("could not read Satelle {stream}: {error}"), None)
        })
}

fn wait_error(error: std::io::Error) -> McpError {
    McpError::internal_error(format!("could not wait for Satelle command: {error}"), None)
}

fn tool_result(output: Output) -> Result<CallToolResult, McpError> {
    let bytes = if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    };
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        McpError::internal_error(
            format!("Satelle command did not return canonical JSON: {error}"),
            None,
        )
    })?;
    if output.status.success() {
        Ok(structured(value, false))
    } else if value.get("schema_version").and_then(Value::as_str) == Some("satelle.error.v1") {
        Ok(structured(value, true))
    } else {
        Err(McpError::internal_error(
            "Satelle command returned a non-canonical error",
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    #[test]
    fn cancellation_terminates_and_reaps_the_child() {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--exact",
                "mcp::mutation::tests::cancellation_helper_waits",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_group(&mut command).expect("start cancellation helper");
        let mut child = child;
        let output = OutputReaders::start(&mut child);
        let (cancel, cancelled) = mpsc::channel();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            wait_for_output(child, output, cancelled, CancellationMode::ForceKill)
        });
        std::thread::sleep(Duration::from_millis(50));
        cancel.send(()).expect("cancel helper child");

        assert!(matches!(
            waiter.join().expect("join cancellation waiter"),
            Ok(ProcessOutcome::Cancelled)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cancellation_allows_attached_cleanup_before_force_kill() {
        let directory = tempfile::tempdir().expect("temporary cancellation proof");
        let marker = directory.path().join("graceful-cleanup-complete");
        let armed_marker = marker.with_extension("armed");
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--exact",
                "mcp::mutation::tests::graceful_cancellation_helper_waits_for_interrupt",
                "--ignored",
            ])
            .env("SATELLE_TEST_CANCELLATION_MARKER", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = spawn_group(&mut command).expect("start graceful cancellation helper");
        let mut child = child;
        let output = OutputReaders::start(&mut child);
        let (cancel, cancelled) = mpsc::channel();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            wait_for_output(
                child,
                output,
                cancelled,
                CancellationMode::GracefulInterrupt,
            )
        });

        // Do not race the signal against helper startup. The helper records this marker only
        // after the OS signal future has been polled once and registered its listener.
        let arm_deadline = Instant::now() + Duration::from_secs(5);
        while !armed_marker.exists() && Instant::now() < arm_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !armed_marker.exists() {
            // Keep a failed proof bounded as well. This reaches the same graceful deadline and
            // force-kill fallback instead of leaving the helper alive after the test panics.
            cancel.send(()).expect("cancel unarmed helper child");
            let _ = waiter.join();
            panic!("graceful signal listener was not armed");
        }
        cancel.send(()).expect("cancel helper child");

        assert!(matches!(
            waiter.join().expect("join graceful cancellation waiter"),
            Ok(ProcessOutcome::Cancelled)
        ));
        assert_eq!(
            std::fs::read(marker).expect("graceful cleanup marker"),
            b"graceful cleanup complete\n"
        );
        assert!(
            started.elapsed() < GRACEFUL_INTERRUPT_TIMEOUT,
            "graceful cleanup must finish before the force-kill fallback"
        );
    }

    #[test]
    fn drains_child_output_before_writing_the_prompt() {
        let prompt = "p".repeat(1024 * 1024);
        let args = vec![
            "--exact".to_string(),
            "mcp::mutation::tests::output_before_stdin_helper".to_string(),
            "--ignored".to_string(),
            "--nocapture".to_string(),
        ];
        let (_cancel, cancelled) = mpsc::channel();
        let (finished, completion) = mpsc::channel();
        std::thread::spawn(move || {
            let executable = std::env::current_exe().expect("current test executable");
            let outcome = execute_blocking(
                &executable,
                args,
                Some(prompt),
                cancelled,
                CancellationMode::ForceKill,
            );
            let _ = finished.send(outcome);
        });

        let outcome = completion
            .recv_timeout(Duration::from_secs(5))
            .expect("subprocess output and prompt pipes must not deadlock")
            .expect("execute helper process");
        assert!(matches!(outcome, ProcessOutcome::Completed(output) if output.status.success()));
    }

    #[test]
    fn closed_prompt_pipe_preserves_the_canonical_child_error() {
        let prompt = "p".repeat(1024 * 1024);
        let args = vec![
            "--exact".to_string(),
            "mcp::mutation::tests::canonical_error_before_stdin_helper".to_string(),
            "--ignored".to_string(),
            "--nocapture".to_string(),
        ];
        let (_cancel, cancelled) = mpsc::channel();
        let executable = std::env::current_exe().expect("current test executable");
        let outcome = execute_blocking(
            &executable,
            args,
            Some(prompt),
            cancelled,
            CancellationMode::ForceKill,
        )
        .expect("preserve completed child output");
        let ProcessOutcome::Completed(output) = outcome else {
            panic!("child completed before cancellation");
        };

        let result = tool_result(output).expect("return the canonical CLI error as a tool result");
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    #[ignore = "helper process for cancellation_terminates_and_reaps_the_child"]
    fn cancellation_helper_waits() {
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "helper process for drains_child_output_before_writing_the_prompt"]
    fn output_before_stdin_helper() {
        use std::io::{Read as _, Write as _};

        std::io::stdout()
            .write_all(&vec![b'o'; 1024 * 1024])
            .expect("write helper output");
        let mut prompt = Vec::new();
        std::io::stdin()
            .read_to_end(&mut prompt)
            .expect("read helper prompt");
        assert_eq!(prompt.len(), 1024 * 1024);
    }

    #[test]
    #[ignore = "helper process for closed_prompt_pipe_preserves_the_canonical_child_error"]
    fn canonical_error_before_stdin_helper() {
        eprint!(
            r#"{{"schema_version":"satelle.error.v1","code":"invalid-usage","message":"conflicting flags"}}"#
        );
        std::process::exit(2);
    }

    #[test]
    #[ignore = "helper process for cancellation_allows_attached_cleanup_before_force_kill"]
    fn graceful_cancellation_helper_waits_for_interrupt() {
        let marker = std::env::var_os("SATELLE_TEST_CANCELLATION_MARKER")
            .expect("graceful cancellation marker path");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("signal runtime");
        runtime
            .block_on(async {
                let mut signal = Box::pin(crate::transport::process_interrupt_signal());
                let first_poll =
                    std::future::poll_fn(|context| match signal.as_mut().poll(context) {
                        std::task::Poll::Ready(result) => std::task::Poll::Ready(Some(result)),
                        std::task::Poll::Pending => std::task::Poll::Ready(None),
                    })
                    .await;
                std::fs::write(
                    std::path::PathBuf::from(&marker).with_extension("armed"),
                    b"armed\n",
                )
                .expect("write graceful signal armed marker");
                match first_poll {
                    Some(result) => result,
                    None => signal.await,
                }
            })
            .expect("receive graceful interrupt");
        std::fs::write(marker, b"graceful cleanup complete\n")
            .expect("write graceful cleanup marker");
    }
}
