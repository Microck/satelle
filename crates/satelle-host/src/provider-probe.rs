use base64::Engine;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CONNECTION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CONNECTION_TIMEOUT: Duration = Duration::from_millis(250);
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const CLICK_OBSERVED: u8 = 1;
const DRAG_OBSERVED: u8 = 2;
const NATIVE_ACTION_RECEIPT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(crate) struct NativeActionEvidence {
    state: Arc<(Mutex<NativeActionState>, Condvar)>,
}

#[derive(Default)]
struct NativeActionState {
    expected_script: Option<String>,
    expected_app_id: Option<String>,
    active_item: Option<String>,
    active_item_completed: bool,
    observed_actions: u8,
    invalidated: bool,
}

impl NativeActionEvidence {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(NativeActionState::default()), Condvar::new())),
        }
    }

    fn reset(&self) {
        let (state, _) = &*self.state;
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.expected_script = None;
        state.expected_app_id = None;
        state.active_item = None;
        state.active_item_completed = false;
        state.observed_actions = 0;
        state.invalidated = false;
    }

    #[cfg(test)]
    pub(crate) fn expect_script(&self, script: &str) {
        self.expect_script_for_app(script, "test-app");
    }

    pub(crate) fn expect_script_for_app(&self, script: &str, app_id: &str) {
        let (state, _) = &*self.state;
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.expected_script = Some(script.to_string());
        state.expected_app_id = Some(app_id.to_string());
    }

    pub(crate) fn expected_authorization(&self) -> Option<(String, String)> {
        let (state, _) = &*self.state;
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .expected_script
            .clone()
            .zip(state.expected_app_id.clone())
    }

    pub(crate) fn invalidated(&self) -> bool {
        let (state, _) = &*self.state;
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .invalidated
    }

    fn wait_for(&self, action: NativeAction) -> bool {
        let required = match action {
            NativeAction::Click => CLICK_OBSERVED,
            NativeAction::Drag => DRAG_OBSERVED,
        };
        let (state, changed) = &*self.state;
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mut state, _) = changed
            .wait_timeout_while(state, NATIVE_ACTION_RECEIPT_TIMEOUT, |state| {
                state.active_item.is_none() && !state.invalidated
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.invalidated || state.active_item.is_none() {
            return false;
        }
        state.observed_actions |= required;
        true
    }

    pub(crate) fn observe_app_server_item(&self, method: &str, item: &serde_json::Value) {
        let Some(item) = item.as_object() else {
            return;
        };
        let Some(id) = item.get("id").and_then(serde_json::Value::as_str) else {
            return;
        };
        let script = item
            .get("arguments")
            .and_then(serde_json::Value::as_object)
            .and_then(|arguments| arguments.get("code"))
            .and_then(serde_json::Value::as_str);
        let (state, changed) = &*self.state;
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_mcp_tool_call =
            item.get("type").and_then(serde_json::Value::as_str) == Some("mcpToolCall");
        let trusted_call = is_mcp_tool_call
            && item.get("server").and_then(serde_json::Value::as_str) == Some("node_repl")
            && item.get("tool").and_then(serde_json::Value::as_str) == Some("js")
            && script == state.expected_script.as_deref();
        match method {
            "item/started"
                if trusted_call
                    && item.get("status").and_then(serde_json::Value::as_str)
                        == Some("inProgress")
                    && state.active_item.is_none()
                    && !state.invalidated =>
            {
                state.active_item = Some(id.to_string());
                state.active_item_completed = false;
                changed.notify_all();
            }
            "item/completed"
                if trusted_call
                    && state.active_item.as_deref() == Some(id)
                    && item.get("status").and_then(serde_json::Value::as_str)
                        == Some("completed") =>
            {
                // Callback receipts can arrive before the MCP item terminal.
                // Do not stop the turn until Codex has also recorded the exact
                // trusted tool call as successful.
                state.active_item_completed = true;
                changed.notify_all();
            }
            "item/started" | "item/completed" if is_mcp_tool_call => {
                // Native readiness permits one exact tool call. Any other MCP
                // item can stage effects that make later callbacks untrustworthy.
                state.invalidated = true;
                state.active_item = None;
                state.active_item_completed = false;
                state.observed_actions = 0;
                changed.notify_all();
            }
            _ => {}
        }
    }

    pub(crate) fn completed(&self) -> bool {
        let (state, _) = &*self.state;
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.invalidated
            && state.active_item.is_some()
            && state.active_item_completed
            && state.observed_actions & (CLICK_OBSERVED | DRAG_OBSERVED)
                == CLICK_OBSERVED | DRAG_OBSERVED
    }

    #[cfg(test)]
    pub(crate) fn observe_click_for_test(&self) -> bool {
        self.wait_for(NativeAction::Click)
    }

    #[cfg(test)]
    pub(crate) fn observe_drag_for_test(&self) -> bool {
        self.wait_for(NativeAction::Drag)
    }
}

/// Owns one loopback-only provider capability probe. Dropping the owner
/// cancels and joins the server thread, so no probe listener can survive its
/// Codex execution attempt.
pub(crate) struct ProviderProbeSurface {
    page_url: String,
    #[cfg(windows)]
    _native_window: Option<crate::windows_native_probe::WindowsNativeProbeWindow>,
    deadline: Instant,
    shutdown: Arc<AtomicBool>,
    observed_actions: Arc<AtomicU8>,
    requirements: ProbeRequirements,
    cancellation: Option<crate::runtime::AdmissionCancellation>,
    completion: mpsc::Receiver<Result<(), ProviderProbeError>>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Clone, Copy)]
enum ProbeRequirements {
    #[cfg(test)]
    DragOnly,
    ClickAndDrag,
}

struct ProbeServerControl<'a> {
    deadline: Instant,
    shutdown: &'a AtomicBool,
    observed_actions: &'a AtomicU8,
    cancellation: Option<&'a crate::runtime::AdmissionCancellation>,
    requirements: ProbeRequirements,
    native_gesture_evidence: NativeGestureEvidence,
}

enum NativeGestureEvidence {
    #[cfg(test)]
    NotRequired,
    Native {
        evidence: NativeActionEvidence,
        #[cfg(windows)]
        previous_input_tick: Option<u32>,
    },
    Unavailable,
}

#[derive(Clone, Copy)]
enum NativeAction {
    Click,
    Drag,
}

impl NativeGestureEvidence {
    fn new(_requirements: ProbeRequirements, evidence: Option<NativeActionEvidence>) -> Self {
        #[cfg(test)]
        if matches!(_requirements, ProbeRequirements::DragOnly) {
            return Self::NotRequired;
        }
        match evidence {
            Some(evidence) => Self::Native {
                evidence,
                #[cfg(windows)]
                previous_input_tick: windows_last_input_tick(),
            },
            None => Self::Unavailable,
        }
    }

    fn accept(&mut self, action: NativeAction) -> bool {
        match self {
            #[cfg(test)]
            Self::NotRequired => true,
            Self::Native {
                evidence,
                #[cfg(windows)]
                previous_input_tick,
            } => {
                if !evidence.wait_for(action) {
                    return false;
                }
                #[cfg(windows)]
                let Some(previous_tick) = *previous_input_tick else {
                    return false;
                };
                #[cfg(windows)]
                let Some(current) = windows_last_input_tick() else {
                    return false;
                };
                #[cfg(windows)]
                let accepted = counter_changed(previous_tick, current);
                #[cfg(windows)]
                if accepted {
                    *previous_input_tick = Some(current);
                }
                #[cfg(windows)]
                {
                    accepted
                }
                #[cfg(not(windows))]
                {
                    true
                }
            }
            Self::Unavailable => false,
        }
    }
}

#[cfg(any(windows, test))]
fn counter_changed(previous: u32, current: u32) -> bool {
    // GetLastInputInfo is session-local evidence, but Windows does not promise
    // a monotonic tick. SendInput may supply a tick older than the prior event.
    current != previous
}

#[cfg(windows)]
fn windows_last_input_tick() -> Option<u32> {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    let mut info = LASTINPUTINFO {
        cbSize: u32::try_from(std::mem::size_of::<LASTINPUTINFO>()).ok()?,
        dwTime: 0,
    };
    (unsafe { GetLastInputInfo(&mut info) } != 0).then_some(info.dwTime)
}

#[derive(Debug, Error)]
pub(crate) enum ProviderProbeError {
    #[error("the provider probe could not bind an IPv4 loopback listener")]
    Bind(#[source] std::io::Error),
    #[error("the provider probe could not generate its one-time capability")]
    Random(#[source] getrandom::Error),
    #[error("the provider probe request was invalid")]
    InvalidRequest,
    #[error("the provider probe timed out")]
    TimedOut,
    #[error("the native click callback was not observed")]
    NativeClickNotObserved,
    #[error("the native drag callback was not observed")]
    NativeDragNotObserved,
    #[error("the provider probe was cancelled")]
    Cancelled,
    #[error("the provider probe listener failed")]
    Io(#[source] std::io::Error),
    #[error("the provider probe worker could not start")]
    WorkerSpawn(#[source] std::io::Error),
    #[cfg(windows)]
    #[error("the native provider probe window could not start")]
    NativeWindow(#[source] std::io::Error),
    #[error("the provider probe worker stopped unexpectedly")]
    WorkerStopped,
}

impl ProviderProbeSurface {
    #[cfg(test)]
    pub(crate) fn start(timeout: Duration) -> Result<Self, ProviderProbeError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ProviderProbeError::TimedOut)?;
        Self::start_with_control(deadline, None)
    }

    /// Starts the listener with the caller's absolute execution deadline.
    /// Doctor passes its scheduler-owned cancellation capability unchanged;
    /// the private shutdown flag exists only to make RAII teardown joinable.
    #[cfg(test)]
    pub(crate) fn start_with_control(
        deadline: Instant,
        cancellation: Option<crate::runtime::AdmissionCancellation>,
    ) -> Result<Self, ProviderProbeError> {
        Self::start_with_requirements(
            deadline,
            cancellation,
            ProbeRequirements::DragOnly,
            None,
            None,
        )
    }

    /// Starts the independent native action proof. The same private loopback
    /// capability is used, but completion requires both a click and a drag.
    #[cfg(test)]
    pub(crate) fn start_native_with_control(
        deadline: Instant,
        cancellation: Option<crate::runtime::AdmissionCancellation>,
    ) -> Result<Self, ProviderProbeError> {
        Self::start_with_requirements(
            deadline,
            cancellation,
            ProbeRequirements::ClickAndDrag,
            None,
            None,
        )
    }

    pub(crate) fn start_native_with_evidence(
        deadline: Instant,
        cancellation: Option<crate::runtime::AdmissionCancellation>,
        evidence: NativeActionEvidence,
        desktop_session_id: &str,
    ) -> Result<Self, ProviderProbeError> {
        Self::start_with_requirements(
            deadline,
            cancellation,
            ProbeRequirements::ClickAndDrag,
            Some(evidence),
            Some(desktop_session_id),
        )
    }

    fn start_with_requirements(
        deadline: Instant,
        cancellation: Option<crate::runtime::AdmissionCancellation>,
        requirements: ProbeRequirements,
        native_action_evidence: Option<NativeActionEvidence>,
        desktop_session_id: Option<&str>,
    ) -> Result<Self, ProviderProbeError> {
        #[cfg(not(windows))]
        let _ = desktop_session_id;
        if Instant::now() >= deadline {
            return Err(ProviderProbeError::TimedOut);
        }
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(ProviderProbeError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(ProviderProbeError::Bind)?;
        let address = listener.local_addr().map_err(ProviderProbeError::Bind)?;
        let SocketAddr::V4(address) = address else {
            return Err(ProviderProbeError::Bind(std::io::Error::other(
                "provider probe listener was not IPv4",
            )));
        };
        if !address.ip().is_loopback() {
            return Err(ProviderProbeError::Bind(std::io::Error::other(
                "provider probe listener was not loopback",
            )));
        }
        let port = address.port();
        let nonce = random_token(32)?;
        if let Some(evidence) = native_action_evidence.as_ref() {
            evidence.reset();
        }
        let capability = random_token(32)?;
        let page_url = format!("http://127.0.0.1:{port}/probe/{capability}");
        #[cfg(windows)]
        let native_window = native_action_evidence
            .as_ref()
            .map(|_| {
                crate::windows_native_probe::WindowsNativeProbeWindow::spawn(
                    address,
                    &capability,
                    &nonce,
                    desktop_session_id.expect("native Windows probes bind an exact desktop"),
                )
            })
            .transpose()
            .map_err(ProviderProbeError::NativeWindow)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let observed_actions = Arc::new(AtomicU8::new(0));
        let worker_observed_actions = Arc::clone(&observed_actions);
        let worker_cancellation = cancellation.clone();
        let native_gesture_evidence =
            NativeGestureEvidence::new(requirements, native_action_evidence);
        let (sender, completion) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("satelle-provider-probe".to_string())
            .spawn(move || {
                let outcome = serve_probe(
                    listener,
                    nonce,
                    capability,
                    ProbeServerControl {
                        deadline,
                        shutdown: &worker_shutdown,
                        observed_actions: &worker_observed_actions,
                        cancellation: worker_cancellation.as_ref(),
                        requirements,
                        native_gesture_evidence,
                    },
                );
                let _ = sender.send(outcome);
            })
            .map_err(ProviderProbeError::WorkerSpawn)?;

        Ok(Self {
            page_url,
            #[cfg(windows)]
            _native_window: native_window,
            deadline,
            shutdown,
            observed_actions,
            requirements,
            cancellation,
            completion,
            worker: Some(worker),
        })
    }

    pub(crate) fn page_url(&self) -> &str {
        &self.page_url
    }

    /// Success is based only on the exact daemon-observed callback. Codex's
    /// terminal text or process exit status cannot satisfy this check.
    pub(crate) fn wait_for_completion(mut self) -> Result<(), ProviderProbeError> {
        let outcome = loop {
            if probe_requirements_satisfied(
                self.requirements,
                self.observed_actions.load(Ordering::Acquire),
            ) {
                break Ok(());
            }
            // A callback that completed before cancellation is durable proof.
            // Consume it first so session timeout cleanup cannot overwrite an
            // already-observed click-and-drag success.
            match self.completion.try_recv() {
                Ok(outcome) => break outcome,
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    break Err(ProviderProbeError::WorkerStopped);
                }
            }
            if self
                .cancellation
                .as_ref()
                .is_some_and(crate::runtime::AdmissionCancellation::is_requested_or_expired)
            {
                break Err(ProviderProbeError::Cancelled);
            }
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break Err(probe_timeout_error(
                    self.requirements,
                    self.observed_actions.load(Ordering::Acquire),
                ));
            }
            match self.completion.recv_timeout(POLL_INTERVAL.min(remaining)) {
                Ok(outcome) => break outcome,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(ProviderProbeError::WorkerStopped);
                }
            }
        };
        self.shutdown.store(true, Ordering::Release);
        self.join_worker()?;
        outcome
    }

    fn join_worker(&mut self) -> Result<(), ProviderProbeError> {
        self.worker.take().map_or(Ok(()), |worker| {
            worker.join().map_err(|_| ProviderProbeError::WorkerStopped)
        })
    }
}

impl Drop for ProviderProbeSurface {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.join_worker();
    }
}

fn serve_probe(
    listener: TcpListener,
    nonce: String,
    capability: String,
    control: ProbeServerControl<'_>,
) -> Result<(), ProviderProbeError> {
    let ProbeServerControl {
        deadline,
        shutdown,
        observed_actions,
        cancellation,
        requirements,
        mut native_gesture_evidence,
    } = control;
    let page_target = format!("/probe/{capability}");
    let completion_target = format!("/complete/{capability}");
    let click_body = format!("nonce={nonce}&action=click");
    let drag_body = format!("nonce={nonce}&action=drag");
    let expected_host = listener
        .local_addr()
        .map_err(ProviderProbeError::Io)?
        .to_string();
    let expected_origin = format!("http://{expected_host}");

    loop {
        if probe_stopped(shutdown, cancellation) {
            return Err(ProviderProbeError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(probe_timeout_error(
                requirements,
                observed_actions.load(Ordering::Acquire),
            ));
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                // One stalled or reset loopback client must not monopolize the
                // single-use surface until the probe-wide deadline. The exact
                // browser request can still arrive after this connection is
                // rejected without receiving a new probe budget.
                let connection_deadline = Instant::now()
                    .checked_add(CONNECTION_TIMEOUT)
                    .map_or(deadline, |connection_deadline| {
                        connection_deadline.min(deadline)
                    });
                let request =
                    match read_request(&mut stream, connection_deadline, shutdown, cancellation) {
                        Ok(request) => request,
                        Err(error) => {
                            if probe_stopped(shutdown, cancellation) {
                                return Err(ProviderProbeError::Cancelled);
                            }
                            if Instant::now() >= deadline {
                                return Err(probe_timeout_error(
                                    requirements,
                                    observed_actions.load(Ordering::Acquire),
                                ));
                            }
                            let _ = write_response(
                                &mut stream,
                                "400 Bad Request",
                                "text/plain; charset=utf-8",
                                "bad request\n",
                            );
                            match error {
                                ProviderProbeError::InvalidRequest
                                | ProviderProbeError::TimedOut
                                | ProviderProbeError::Io(_) => continue,
                                error => return Err(error),
                            }
                        }
                    };
                if request.method == "GET"
                    && request.target == page_target
                    && request.body.is_empty()
                    && request.headers_valid
                    && request.host.as_deref() == Some(expected_host.as_str())
                    && request.origin.is_none()
                {
                    write_page(&mut stream, &nonce, &completion_target, requirements)?;
                } else if request.method == "POST"
                    && request.target == completion_target
                    && request.headers_valid
                    && !request.has_sensitive_headers
                    && request.host.as_deref() == Some(expected_host.as_str())
                    && request.origin.as_deref() == Some(expected_origin.as_str())
                    && request.content_type.as_deref() == Some(FORM_CONTENT_TYPE)
                    && request.content_length == Some(request.body.len())
                    && match requirements {
                        #[cfg(test)]
                        ProbeRequirements::DragOnly => request.body == drag_body.as_bytes(),
                        ProbeRequirements::ClickAndDrag => {
                            request.body == click_body.as_bytes()
                                || request.body == drag_body.as_bytes()
                        }
                    }
                    && native_gesture_evidence.accept(if request.body == click_body.as_bytes() {
                        NativeAction::Click
                    } else {
                        NativeAction::Drag
                    })
                {
                    if request.body == click_body.as_bytes() {
                        observed_actions.fetch_or(CLICK_OBSERVED, Ordering::AcqRel);
                    } else {
                        observed_actions.fetch_or(DRAG_OBSERVED, Ordering::AcqRel);
                    }
                    let completed = probe_requirements_satisfied(
                        requirements,
                        observed_actions.load(Ordering::Acquire),
                    );
                    // A 204 acknowledges a callback only after its observation
                    // is durable, so later cancellation cannot overtake it.
                    // The native callback reads only the 204 status line. On
                    // Windows it can then close with an abortive reset while
                    // this side is still writing headers. The action and its
                    // exact tool receipt are already durable, so a failed
                    // acknowledgement must not erase that proof or prevent
                    // the second action from arriving.
                    let _ = write_response(&mut stream, "204 No Content", "text/plain", "");
                    if completed {
                        return Ok(());
                    }
                } else if request.target == completion_target {
                    let _ = write_response(
                        &mut stream,
                        "404 Not Found",
                        "text/plain; charset=utf-8",
                        "not found\n",
                    );
                    return Err(ProviderProbeError::InvalidRequest);
                } else {
                    let _ = write_response(
                        &mut stream,
                        "404 Not Found",
                        "text/plain; charset=utf-8",
                        "not found\n",
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(
                    POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(ProviderProbeError::Io(error)),
        }
    }
}

fn probe_requirements_satisfied(requirements: ProbeRequirements, observed_actions: u8) -> bool {
    match requirements {
        #[cfg(test)]
        ProbeRequirements::DragOnly => observed_actions & DRAG_OBSERVED != 0,
        ProbeRequirements::ClickAndDrag => {
            observed_actions & (CLICK_OBSERVED | DRAG_OBSERVED) == (CLICK_OBSERVED | DRAG_OBSERVED)
        }
    }
}

fn probe_timeout_error(
    requirements: ProbeRequirements,
    observed_actions: u8,
) -> ProviderProbeError {
    match (requirements, observed_actions) {
        (ProbeRequirements::ClickAndDrag, CLICK_OBSERVED) => {
            ProviderProbeError::NativeDragNotObserved
        }
        (ProbeRequirements::ClickAndDrag, DRAG_OBSERVED) => {
            ProviderProbeError::NativeClickNotObserved
        }
        _ => ProviderProbeError::TimedOut,
    }
}

fn random_token(byte_count: usize) -> Result<String, ProviderProbeError> {
    let mut bytes = vec![0_u8; byte_count];
    getrandom::fill(&mut bytes).map_err(ProviderProbeError::Random)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

struct ProbeRequest {
    method: String,
    target: String,
    host: Option<String>,
    origin: Option<String>,
    content_type: Option<String>,
    content_length: Option<usize>,
    headers_valid: bool,
    has_sensitive_headers: bool,
    body: Vec<u8>,
}

fn read_request(
    stream: &mut TcpStream,
    connection_deadline: Instant,
    shutdown: &AtomicBool,
    cancellation: Option<&crate::runtime::AdmissionCancellation>,
) -> Result<ProbeRequest, ProviderProbeError> {
    let mut request = Vec::with_capacity(512);
    let header_end = loop {
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        read_more(
            stream,
            &mut request,
            connection_deadline,
            shutdown,
            cancellation,
        )?;
    };
    let header = std::str::from_utf8(&request[..header_end])
        .map_err(|_| ProviderProbeError::InvalidRequest)?;
    let mut lines = header.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or(ProviderProbeError::InvalidRequest)?
        .split_ascii_whitespace();
    let (method, target) = match (
        request_line.next(),
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) {
        (Some(method @ ("GET" | "POST")), Some(target), Some("HTTP/1.1" | "HTTP/1.0"), None)
            if target.starts_with('/') && !target.contains('?') =>
        {
            (method.to_string(), target.to_string())
        }
        _ => return Err(ProviderProbeError::InvalidRequest),
    };

    let mut header_names = HashSet::new();
    let mut host = None;
    let mut origin = None;
    let mut content_length = None;
    let mut content_type = None;
    let mut headers_valid = true;
    let mut has_sensitive_headers = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(ProviderProbeError::InvalidRequest)?;
        if name != name.trim()
            || name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProviderProbeError::InvalidRequest);
        }
        let name = name.to_ascii_lowercase();
        if !header_names.insert(name.clone()) {
            headers_valid = false;
            continue;
        }
        match name.as_str() {
            "host" => host = Some(value.trim().to_string()),
            "origin" => origin = Some(value.trim().to_string()),
            "content-length" => {
                content_length = Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| ProviderProbeError::InvalidRequest)?,
                );
            }
            "content-type" => content_type = Some(value.trim().to_string()),
            "transfer-encoding" => return Err(ProviderProbeError::InvalidRequest),
            // Browsers may send host-scoped credentials on the initial page
            // navigation. The page never reads or reflects them, while the
            // completion callback must remain explicitly credential-free.
            "authorization" | "cookie" | "proxy-authorization" => {
                has_sensitive_headers = true;
            }
            _ => {}
        }
    }
    let body_length = content_length.unwrap_or(0);
    let request_length = header_end
        .checked_add(body_length)
        .ok_or(ProviderProbeError::InvalidRequest)?;
    if request_length > MAX_REQUEST_BYTES {
        return Err(ProviderProbeError::InvalidRequest);
    }
    while request.len() < request_length {
        read_more(
            stream,
            &mut request,
            connection_deadline,
            shutdown,
            cancellation,
        )?;
    }
    if request.len() != request_length {
        return Err(ProviderProbeError::InvalidRequest);
    }

    Ok(ProbeRequest {
        method,
        target,
        host,
        origin,
        content_type,
        content_length,
        headers_valid,
        has_sensitive_headers,
        body: request[header_end..].to_vec(),
    })
}

fn read_more(
    stream: &mut TcpStream,
    request: &mut Vec<u8>,
    connection_deadline: Instant,
    shutdown: &AtomicBool,
    cancellation: Option<&crate::runtime::AdmissionCancellation>,
) -> Result<(), ProviderProbeError> {
    loop {
        if request.len() >= MAX_REQUEST_BYTES {
            return Err(ProviderProbeError::InvalidRequest);
        }
        if probe_stopped(shutdown, cancellation) {
            return Err(ProviderProbeError::Cancelled);
        }
        let now = Instant::now();
        if now >= connection_deadline {
            return Err(ProviderProbeError::TimedOut);
        }
        stream
            .set_read_timeout(Some(
                CONNECTION_POLL_INTERVAL.min(connection_deadline.duration_since(now)),
            ))
            .map_err(ProviderProbeError::Io)?;
        let mut buffer = [0_u8; 512];
        match stream.read(&mut buffer) {
            Ok(0) => return Err(ProviderProbeError::InvalidRequest),
            Ok(read) if request.len() + read <= MAX_REQUEST_BYTES => {
                request.extend_from_slice(&buffer[..read]);
                return Ok(());
            }
            Ok(_) => return Err(ProviderProbeError::InvalidRequest),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(ProviderProbeError::Io(error)),
        }
    }
}

fn probe_stopped(
    shutdown: &AtomicBool,
    cancellation: Option<&crate::runtime::AdmissionCancellation>,
) -> bool {
    shutdown.load(Ordering::Acquire)
        || cancellation.is_some_and(crate::runtime::AdmissionCancellation::is_requested_or_expired)
}

fn write_page(
    stream: &mut TcpStream,
    nonce: &str,
    completion_target: &str,
    requirements: ProbeRequirements,
) -> Result<(), ProviderProbeError> {
    let click_control = match requirements {
        #[cfg(test)]
        ProbeRequirements::DragOnly => String::new(),
        ProbeRequirements::ClickAndDrag => format!(
            "<button id=confirm type=button>Click to confirm</button><script>document.querySelector('#confirm').addEventListener('click',event=>{{if(!event.isTrusted)return;event.currentTarget.textContent='Click event observed';fetch('{completion_target}',{{method:'POST',headers:{{'Content-Type':'{FORM_CONTENT_TYPE}'}},credentials:'omit',cache:'no-store',keepalive:true,body:'nonce={nonce}&action=click'}});}});</script>"
        ),
    };
    let title = match requirements {
        #[cfg(test)]
        ProbeRequirements::DragOnly => "Satelle provider probe",
        ProbeRequirements::ClickAndDrag => "Satelle native readiness probe",
    };
    // The macOS Window API drags at app-window coordinates. A range control
    // turns real pointer travel into a trusted, observable value change. This
    // avoids HTML drag-and-drop semantics, which Safari may not emit for the
    // Computer Use service's synthesized mouse gesture.
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><link rel=icon href=data:,><title>{title}</title><style>main{{font:24px sans-serif;padding:40px}}button{{display:block;box-sizing:border-box;width:320px;min-height:80px;margin:24px 0;padding:24px;border:3px solid #222;background:#fff;color:#111;text-align:center}}#source{{position:fixed;left:48px;top:228px;width:740px;height:80px;margin:0;cursor:grab}}#target{{position:fixed;left:48px;top:332px}}</style><main><p>Nonce: <strong>{nonce}</strong></p>{click_control}<label id=target for=source>Drag the control</label><input id=source type=range min=0 max=100 value=0></main><script>const source=document.querySelector('#source');const target=document.querySelector('#target');let dragSent=false;const completeDrag=event=>{{if(!event.isTrusted||Number(event.currentTarget.value)<50||dragSent)return;dragSent=true;target.textContent='Drag event observed';fetch('{completion_target}',{{method:'POST',headers:{{'Content-Type':'{FORM_CONTENT_TYPE}'}},credentials:'omit',cache:'no-store',keepalive:true,body:'nonce={nonce}&action=drag'}});}};source.addEventListener('input',completeDrag);</script>"
    );
    write_response(stream, "200 OK", "text/html; charset=utf-8", &body)
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), ProviderProbeError> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; img-src data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(ProviderProbeError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_receipts_require_the_exact_successful_tool_call() {
        let evidence = NativeActionEvidence::new();
        evidence.reset();
        evidence.expect_script("probe-nonce exact script");
        let started = serde_json::json!({
            "id": "item-1",
            "type": "mcpToolCall",
            "server": "node_repl",
            "tool": "js",
            "arguments": {"code": "probe-nonce exact script"},
            "status": "inProgress"
        });
        evidence.observe_app_server_item("item/started", &started);

        assert!(evidence.wait_for(NativeAction::Click));
        assert!(evidence.wait_for(NativeAction::Drag));
        assert!(!evidence.completed());

        let completed = serde_json::json!({
            "id": "item-1",
            "type": "mcpToolCall",
            "server": "node_repl",
            "tool": "js",
            "arguments": {"code": "probe-nonce exact script"},
            "status": "completed",
            "result": {"content": [{"type": "text", "text": "ok"}]},
            "error": null
        });
        evidence.observe_app_server_item("item/completed", &completed);
        assert!(evidence.completed());
    }

    #[test]
    fn native_receipts_reject_changed_tool_calls() {
        let evidence = NativeActionEvidence::new();
        evidence.reset();
        evidence.expect_script("probe-nonce exact script");
        evidence.observe_app_server_item(
            "item/started",
            &serde_json::json!({
                "id": "item-1",
                "type": "mcpToolCall",
                "server": "node_repl",
                "tool": "js",
                "arguments": {"code": "probe-nonce exact script; void import(\"node:\" + \"http\")"},
                "status": "inProgress"
            }),
        );
        assert!(!evidence.wait_for(NativeAction::Click));
        assert!(!evidence.completed());
    }

    #[test]
    fn native_receipts_reject_a_failed_exact_tool_call() {
        let evidence = NativeActionEvidence::new();
        evidence.reset();
        evidence.expect_script("probe-nonce exact script");
        let started = serde_json::json!({
            "id": "item-1",
            "type": "mcpToolCall",
            "server": "node_repl",
            "tool": "js",
            "arguments": {"code": "probe-nonce exact script"},
            "status": "inProgress"
        });
        evidence.observe_app_server_item("item/started", &started);
        assert!(evidence.wait_for(NativeAction::Click));
        assert!(evidence.wait_for(NativeAction::Drag));

        let failed = serde_json::json!({
            "id": "item-1",
            "type": "mcpToolCall",
            "server": "node_repl",
            "tool": "js",
            "arguments": {"code": "probe-nonce exact script"},
            "status": "failed",
            "error": null
        });
        evidence.observe_app_server_item("item/completed", &failed);

        assert!(!evidence.completed());
    }

    #[test]
    fn native_receipts_reject_an_exact_call_after_a_changed_tool_call() {
        let evidence = NativeActionEvidence::new();
        evidence.reset();
        evidence.expect_script("probe-nonce exact script");
        evidence.observe_app_server_item(
            "item/started",
            &serde_json::json!({
                "id": "item-untrusted",
                "type": "mcpToolCall",
                "server": "node_repl",
                "tool": "js",
                "arguments": {"code": "schedule forged callbacks"},
                "status": "inProgress"
            }),
        );
        evidence.observe_app_server_item(
            "item/started",
            &serde_json::json!({
                "id": "item-exact",
                "type": "mcpToolCall",
                "server": "node_repl",
                "tool": "js",
                "arguments": {"code": "probe-nonce exact script"},
                "status": "inProgress"
            }),
        );

        assert!(!evidence.wait_for(NativeAction::Click));
        assert!(!evidence.completed());
    }

    #[derive(Clone, Copy, Debug)]
    enum InvalidCallbackCase {
        WrongMethod,
        WrongHost,
        WrongOrigin,
        WrongContentType,
        CaseVariantContentType,
        WrongNonce,
        WrongAction,
        DuplicateHost,
        DuplicateOrigin,
        DuplicateContentType,
        DuplicateContentLength,
        Cookie,
        Authorization,
        ProxyAuthorization,
    }

    impl InvalidCallbackCase {
        fn request(self, address: &str, target: &str, nonce: &str) -> String {
            let body = match self {
                Self::WrongNonce => "nonce=wrong&action=drag".to_string(),
                Self::WrongAction => format!("nonce={nonce}&action=click"),
                _ => format!("nonce={nonce}&action=drag"),
            };
            let method = if matches!(self, Self::WrongMethod) {
                "GET"
            } else {
                "POST"
            };
            let host = if matches!(self, Self::WrongHost) {
                "127.0.0.1:1"
            } else {
                address
            };
            let origin = if matches!(self, Self::WrongOrigin) {
                "http://127.0.0.1:1".to_string()
            } else {
                format!("http://{address}")
            };
            let content_type = match self {
                Self::WrongContentType => "text/plain",
                Self::CaseVariantContentType => "APPLICATION/X-WWW-FORM-URLENCODED",
                _ => FORM_CONTENT_TYPE,
            };
            let duplicate_host = matches!(self, Self::DuplicateHost)
                .then(|| format!("Host: {address}\r\n"))
                .unwrap_or_default();
            let duplicate_origin = matches!(self, Self::DuplicateOrigin)
                .then(|| format!("Origin: http://{address}\r\n"))
                .unwrap_or_default();
            let duplicate_content_type = matches!(self, Self::DuplicateContentType)
                .then(|| format!("Content-Type: {FORM_CONTENT_TYPE}\r\n"))
                .unwrap_or_default();
            let duplicate_content_length = matches!(self, Self::DuplicateContentLength)
                .then(|| format!("Content-Length: {}\r\n", body.len()))
                .unwrap_or_default();
            let sensitive_header = match self {
                Self::Cookie => "Cookie: private=value\r\n",
                Self::Authorization => "Authorization: Bearer private\r\n",
                Self::ProxyAuthorization => "Proxy-Authorization: Basic private\r\n",
                _ => "",
            };
            format!(
                "{method} {target} HTTP/1.1\r\nHost: {host}\r\n{duplicate_host}Origin: {origin}\r\n{duplicate_origin}Content-Type: {content_type}\r\n{duplicate_content_type}Content-Length: {}\r\n{duplicate_content_length}{sensitive_header}\r\n{body}",
                body.len()
            )
        }
    }

    #[test]
    fn exact_page_and_callback_complete_once_without_external_state() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let page_url = probe.page_url().to_string();
        let (address, page_target) = split_local_url(&page_url);
        let page = exchange(
            &address,
            &format!(
                "GET {page_target} HTTP/1.1\r\nHost: {address}\r\nCookie: unrelated=local-development\r\n\r\n"
            ),
        );
        assert!(page.contains("Satelle provider probe"));
        assert!(!page.contains("local-development"));
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let body = format!("nonce={nonce}&action=drag");
        let callback = exchange(
            &address,
            &format!(
                "POST {completion_target} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nContent-Type: {FORM_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(callback.starts_with("HTTP/1.1 204 No Content"));
        probe.wait_for_completion().unwrap();
        assert!(TcpStream::connect(address).is_err());
    }

    #[test]
    fn native_page_rejects_direct_callbacks_without_os_input_evidence() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let probe = ProviderProbeSurface::start_native_with_control(deadline, None).unwrap();
        let page_url = probe.page_url().to_string();
        let (address, page_target) = split_local_url(&page_url);
        let page = get_page(&address, &page_target);

        assert!(page.contains("Satelle native readiness probe"));
        assert!(page.contains("<button id=confirm type=button>Click to confirm</button>"));
        assert!(page.contains("<input id=source type=range min=0 max=100 value=0>"));
        assert!(page.contains("#source{position:fixed;left:48px;top:228px"));
        assert!(page.contains("width:740px;height:80px"));
        assert!(page.contains("source.addEventListener('input',completeDrag)"));
        assert!(page.contains("Number(event.currentTarget.value)<50"));
        assert!(page.contains("Click event observed"));
        assert!(page.contains("Drag event observed"));
        assert_eq!(page.matches("keepalive:true").count(), 2);
        assert!(page.contains("if(!event.isTrusted)return"));

        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let callback = |action| {
            let body = format!("nonce={nonce}&action={action}");
            exchange(
                &address,
                &format!(
                    "POST {completion_target} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nContent-Type: {FORM_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                ),
            )
        };

        assert!(callback("click").starts_with("HTTP/1.1 404 Not Found"));
        assert!(matches!(
            probe.wait_for_completion(),
            Err(ProviderProbeError::InvalidRequest)
        ));
        assert!(TcpStream::connect(address).is_err());
    }

    #[cfg(windows)]
    fn send_test_mouse_input(delta_x: i32) {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
            INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_MOVE, MOUSEINPUT, SendInput,
        };

        // The production callback requires a fresh session-local Windows input
        // tick. Exercise that boundary with real injected mouse movement in the
        // VM instead of weakening the probe for this regression.
        std::thread::sleep(Duration::from_millis(20));
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: delta_x,
                    dy: 0,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        assert_eq!(
            unsafe {
                SendInput(
                    1,
                    &input,
                    i32::try_from(std::mem::size_of::<INPUT>()).unwrap(),
                )
            },
            1,
            "Windows did not accept the native test input"
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_status_line_client_close_preserves_click_and_drag_proof() {
        let evidence = NativeActionEvidence::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        let desktop_session_id = crate::windows_native_probe::current_process_desktop_session_id();
        let probe = ProviderProbeSurface::start_with_requirements(
            deadline,
            None,
            ProbeRequirements::ClickAndDrag,
            Some(evidence.clone()),
            Some(&desktop_session_id),
        )
        .unwrap();
        // Starting a probe clears evidence from any prior Codex attempt. Feed
        // the exact active item only after the new probe owns that clean state.
        evidence.expect_script("exact native callback test");
        evidence.observe_app_server_item(
            "item/started",
            &serde_json::json!({
                "id": "item-1",
                "type": "mcpToolCall",
                "server": "node_repl",
                "tool": "js",
                "arguments": {"code": "exact native callback test"},
                "status": "inProgress"
            }),
        );
        let (address, page_target) = split_local_url(probe.page_url());
        let page = get_page(&address, &page_target);
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");

        for (action, delta_x) in [("click", 1), ("drag", -1)] {
            send_test_mouse_input(delta_x);
            let body = format!("nonce={nonce}&action={action}");
            let request = format!(
                "POST {completion_target} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nContent-Type: {FORM_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let mut stream = TcpStream::connect(&address).unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            let mut status_line = [0_u8; b"HTTP/1.1 204 No Content".len()];
            stream.read_exact(&mut status_line).unwrap();
            assert_eq!(&status_line, b"HTTP/1.1 204 No Content");
            drop(stream);
        }

        probe.wait_for_completion().unwrap();
        evidence.observe_app_server_item(
            "item/completed",
            &serde_json::json!({
                "id": "item-1",
                "type": "mcpToolCall",
                "server": "node_repl",
                "tool": "js",
                "arguments": {"code": "exact native callback test"},
                "status": "completed",
                "result": {"content": [{"type": "text", "text": "ok"}]},
                "error": null
            }),
        );
        assert!(evidence.completed());
    }

    #[test]
    fn native_timeout_identifies_the_missing_drag_callback() {
        assert!(matches!(
            probe_timeout_error(ProbeRequirements::ClickAndDrag, CLICK_OBSERVED),
            ProviderProbeError::NativeDragNotObserved
        ));
    }

    #[test]
    fn native_cancellation_reports_cancellation() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let cancellation = crate::runtime::AdmissionCancellation::with_deadline(deadline);
        let probe =
            ProviderProbeSurface::start_native_with_control(deadline, Some(cancellation.clone()))
                .unwrap();
        cancellation.request();
        assert!(matches!(
            probe.wait_for_completion(),
            Err(ProviderProbeError::Cancelled)
        ));
    }

    #[test]
    fn input_counter_comparison_accepts_non_monotonic_windows_ticks() {
        assert!(counter_changed(u32::MAX - 1, 1));
        assert!(!counter_changed(42, 42));
        assert!(counter_changed(42, 41));
    }

    #[test]
    fn unrelated_loopback_requests_do_not_terminate_the_probe() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let page_url = probe.page_url().to_string();
        let (address, page_target) = split_local_url(&page_url);

        let unrelated = exchange(
            &address,
            "GET /unrelated HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(unrelated.starts_with("HTTP/1.1 404 Not Found"));

        let page = exchange(
            &address,
            &format!("GET {page_target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
        );
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let body = format!("nonce={nonce}&action=drag");
        let callback = exchange(
            &address,
            &format!(
                "POST {completion_target} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nContent-Type: {FORM_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(callback.starts_with("HTTP/1.1 204 No Content"));
        probe.wait_for_completion().unwrap();
    }

    #[test]
    fn callback_rejects_a_wrong_host_and_origin() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let (address, page_target) = split_local_url(probe.page_url());
        let page = exchange(
            &address,
            &format!("GET {page_target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
        );
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let body = format!("nonce={nonce}&action=drag");

        let response = exchange(
            &address,
            &format!(
                "POST {completion_target} HTTP/1.1\r\nHost: 127.0.0.1:1\r\nOrigin: http://127.0.0.1:1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        assert!(matches!(
            probe.wait_for_completion(),
            Err(ProviderProbeError::InvalidRequest)
        ));
    }

    #[test]
    fn every_attempt_uses_ipv4_loopback_and_fresh_256_bit_secrets() {
        let first = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let second = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let (first_address, first_target) = split_local_url(first.page_url());
        let (second_address, second_target) = split_local_url(second.page_url());

        for address in [&first_address, &second_address] {
            let parsed: SocketAddr = address.parse().unwrap();
            assert!(matches!(parsed, SocketAddr::V4(value) if value.ip().is_loopback()));
        }
        assert_ne!(first_target, second_target);
        for capability in [
            first_target.strip_prefix("/probe/").unwrap(),
            second_target.strip_prefix("/probe/").unwrap(),
        ] {
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(capability)
                    .unwrap()
                    .len(),
                32
            );
        }

        let first_page = get_page(&first_address, &first_target);
        let second_page = get_page(&second_address, &second_target);
        let first_nonce = between(&first_page, "Nonce: <strong>", "</strong>");
        let second_nonce = between(&second_page, "Nonce: <strong>", "</strong>");
        assert_ne!(first_nonce, second_nonce);
        for nonce in [first_nonce, second_nonce] {
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(nonce)
                    .unwrap()
                    .len(),
                32
            );
        }
    }

    #[test]
    fn callback_rejects_wrong_duplicate_or_sensitive_protocol_inputs() {
        for case in [
            InvalidCallbackCase::WrongMethod,
            InvalidCallbackCase::WrongHost,
            InvalidCallbackCase::WrongOrigin,
            InvalidCallbackCase::WrongContentType,
            InvalidCallbackCase::CaseVariantContentType,
            InvalidCallbackCase::WrongNonce,
            InvalidCallbackCase::WrongAction,
            InvalidCallbackCase::DuplicateHost,
            InvalidCallbackCase::DuplicateOrigin,
            InvalidCallbackCase::DuplicateContentType,
            InvalidCallbackCase::DuplicateContentLength,
            InvalidCallbackCase::Cookie,
            InvalidCallbackCase::Authorization,
            InvalidCallbackCase::ProxyAuthorization,
        ] {
            let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
            let (address, page_target) = split_local_url(probe.page_url());
            let page = get_page(&address, &page_target);
            let nonce = between(&page, "Nonce: <strong>", "</strong>");
            let completion_target = between(&page, "fetch('", "'");
            let response = exchange(&address, &case.request(&address, completion_target, nonce));
            assert!(
                response.starts_with("HTTP/1.1 400 Bad Request")
                    || response.starts_with("HTTP/1.1 404 Not Found"),
                "unexpected response for {case:?}: {response}"
            );
            assert!(
                matches!(
                    probe.wait_for_completion(),
                    Err(ProviderProbeError::InvalidRequest)
                ),
                "invalid callback was accepted for {case:?}"
            );
        }
    }

    #[test]
    fn stalled_unrelated_connection_is_rejected_before_exact_success() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let (address, page_target) = split_local_url(probe.page_url());
        let mut stalled = TcpStream::connect(&address).unwrap();
        stalled
            .write_all(b"GET /unrelated HTTP/1.1\r\nHost: ")
            .unwrap();

        let page = get_page(&address, &page_target);
        complete_probe(probe, &address, &page);
    }

    #[test]
    fn query_oversized_and_wrong_capability_requests_never_complete() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let (address, page_target) = split_local_url(probe.page_url());

        for request in [
            format!("GET {page_target}?query=1 HTTP/1.1\r\nHost: {address}\r\n\r\n"),
            format!("GET /probe/wrong HTTP/1.1\r\nHost: {address}\r\n\r\n"),
            format!("GET http://example.invalid{page_target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
            format!(
                "GET {page_target} HTTP/1.1\r\nHost: {address}\r\nX-Oversized: {}\r\n\r\n",
                "x".repeat(MAX_REQUEST_BYTES)
            ),
        ] {
            let response = exchange(&address, &request);
            assert!(!response.starts_with("HTTP/1.1 200 OK"));
            assert!(!response.starts_with("HTTP/1.1 204 No Content"));
        }

        let page = get_page(&address, &page_target);
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let query_callback = exchange(
            &address,
            &valid_callback_request(&address, &format!("{completion_target}?query=1"), nonce),
        );
        assert!(query_callback.starts_with("HTTP/1.1 400 Bad Request"));
        let wrong_capability = exchange(
            &address,
            &valid_callback_request(&address, "/complete/wrong", nonce),
        );
        assert!(wrong_capability.starts_with("HTTP/1.1 404 Not Found"));

        complete_probe(probe, &address, &page);
        assert!(TcpStream::connect(&address).is_err());
    }

    #[test]
    fn page_response_exposes_only_closed_local_probe_state() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let (address, page_target) = split_local_url(probe.page_url());
        let page = exchange(
            &address,
            &format!("GET {page_target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
        );
        let lowercase = page.to_ascii_lowercase();

        assert!(lowercase.contains("cache-control: no-store\r\n"));
        assert!(lowercase.contains("content-security-policy: default-src 'none';"));
        assert!(lowercase.contains("referrer-policy: no-referrer\r\n"));
        assert!(!lowercase.contains("set-cookie:"));
        assert!(!lowercase.contains("document.cookie"));
        assert!(!lowercase.contains("credentials:'include'"));
        assert!(!lowercase.contains("file:"));
        assert!(!lowercase.contains("session"));
        assert!(!lowercase.contains("proxy"));
        assert!(!page.contains(&address));
    }

    #[test]
    fn timeout_cancellation_and_caller_completion_never_leave_a_listener() {
        let timed_out = ProviderProbeSurface::start(Duration::from_millis(40)).unwrap();
        let (timeout_address, _) = split_local_url(timed_out.page_url());
        let mut timeout_stream = TcpStream::connect(&timeout_address).unwrap();
        timeout_stream.write_all(b"GET /stalled").unwrap();
        assert!(matches!(
            timed_out.wait_for_completion(),
            Err(ProviderProbeError::TimedOut)
        ));
        assert!(TcpStream::connect(timeout_address).is_err());

        let cancelled = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let (cancelled_address, _) = split_local_url(cancelled.page_url());
        let mut cancelled_stream = TcpStream::connect(&cancelled_address).unwrap();
        cancelled_stream.write_all(b"GET /stalled").unwrap();
        drop(cancelled);
        assert!(TcpStream::connect(cancelled_address).is_err());

        let deadline = Instant::now() + Duration::from_secs(2);
        let external_cancellation = crate::runtime::AdmissionCancellation::with_deadline(deadline);
        let externally_cancelled =
            ProviderProbeSurface::start_with_control(deadline, Some(external_cancellation.clone()))
                .unwrap();
        let (external_address, _) = split_local_url(externally_cancelled.page_url());
        let mut external_stream = TcpStream::connect(&external_address).unwrap();
        external_stream.write_all(b"GET /stalled").unwrap();
        external_cancellation.request();
        assert!(matches!(
            externally_cancelled.wait_for_completion(),
            Err(ProviderProbeError::Cancelled)
        ));
        assert!(TcpStream::connect(external_address).is_err());

        let no_callback = ProviderProbeSurface::start(Duration::from_millis(40)).unwrap();
        assert!(matches!(
            no_callback.wait_for_completion(),
            Err(ProviderProbeError::TimedOut)
        ));
    }

    fn split_local_url(url: &str) -> (String, String) {
        let remainder = url.strip_prefix("http://").unwrap();
        let (address, path) = remainder.split_once('/').unwrap();
        (address.to_string(), format!("/{path}"))
    }

    fn exchange(address: &str, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        if let Err(error) = stream.read_to_string(&mut response) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset,
                "provider probe response read failed unexpectedly"
            );
        }
        response
    }

    fn get_page(address: &str, target: &str) -> String {
        exchange(
            address,
            &format!("GET {target} HTTP/1.1\r\nHost: {address}\r\n\r\n"),
        )
    }

    fn valid_callback_request(address: &str, target: &str, nonce: &str) -> String {
        let body = format!("nonce={nonce}&action=drag");
        format!(
            "POST {target} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nContent-Type: {FORM_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn complete_probe(probe: ProviderProbeSurface, address: &str, page: &str) {
        let nonce = between(page, "Nonce: <strong>", "</strong>");
        let completion_target = between(page, "fetch('", "'");
        let callback = exchange(
            address,
            &valid_callback_request(address, completion_target, nonce),
        );
        assert!(callback.starts_with("HTTP/1.1 204 No Content"));
        probe.wait_for_completion().unwrap();
    }

    fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let text = text.split_once(start).unwrap().1;
        text.split_once(end).unwrap().0
    }
}
