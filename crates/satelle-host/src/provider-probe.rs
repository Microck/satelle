use base64::Engine;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CONNECTION_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Owns one loopback-only provider capability probe. Dropping the owner
/// cancels and joins the server thread, so no probe listener can survive its
/// Codex execution attempt.
pub(crate) struct ProviderProbeSurface {
    page_url: String,
    deadline: Instant,
    cancel: Arc<AtomicBool>,
    completion: mpsc::Receiver<Result<(), ProviderProbeError>>,
    worker: Option<JoinHandle<()>>,
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
    #[error("the provider probe was cancelled")]
    Cancelled,
    #[error("the provider probe listener failed")]
    Io(#[source] std::io::Error),
    #[error("the provider probe worker could not start")]
    WorkerSpawn(#[source] std::io::Error),
    #[error("the provider probe worker stopped unexpectedly")]
    WorkerStopped,
}

impl ProviderProbeSurface {
    pub(crate) fn start(timeout: Duration) -> Result<Self, ProviderProbeError> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(ProviderProbeError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(ProviderProbeError::Bind)?;
        let port = listener
            .local_addr()
            .map_err(ProviderProbeError::Bind)?
            .port();
        let nonce = random_token(32)?;
        let capability = random_token(32)?;
        let page_url = format!("http://127.0.0.1:{port}/probe/{capability}");
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ProviderProbeError::TimedOut)?;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (sender, completion) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("satelle-provider-probe".to_string())
            .spawn(move || {
                let outcome = serve_probe(listener, nonce, capability, deadline, &worker_cancel);
                let _ = sender.send(outcome);
            })
            .map_err(ProviderProbeError::WorkerSpawn)?;

        Ok(Self {
            page_url,
            deadline,
            cancel,
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
        let outcome = self
            .completion
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(Err(ProviderProbeError::TimedOut));
        self.cancel.store(true, Ordering::Release);
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
        self.cancel.store(true, Ordering::Release);
        let _ = self.join_worker();
    }
}

fn serve_probe(
    listener: TcpListener,
    nonce: String,
    capability: String,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), ProviderProbeError> {
    let page_target = format!("/probe/{capability}");
    let completion_target = format!("/complete/{capability}");
    let completion_body = format!("nonce={nonce}&action=drag");

    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(ProviderProbeError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(ProviderProbeError::TimedOut);
        }

        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(CONNECTION_POLL_INTERVAL))
                    .map_err(ProviderProbeError::Io)?;
                let request = match read_request(&mut stream, deadline, cancel) {
                    Ok(request) => request,
                    Err(ProviderProbeError::InvalidRequest) => {
                        let _ = write_response(
                            &mut stream,
                            "400 Bad Request",
                            "text/plain; charset=utf-8",
                            "bad request\n",
                        );
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if request.method == "GET"
                    && request.target == page_target
                    && request.body.is_empty()
                {
                    write_page(&mut stream, &nonce, &completion_target)?;
                } else if request.method == "POST"
                    && request.target == completion_target
                    && request.content_type.as_deref() == Some("application/x-www-form-urlencoded")
                    && request.body == completion_body.as_bytes()
                {
                    write_response(&mut stream, "204 No Content", "text/plain", "")?;
                    return Ok(());
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

fn random_token(byte_count: usize) -> Result<String, ProviderProbeError> {
    let mut bytes = vec![0_u8; byte_count];
    getrandom::fill(&mut bytes).map_err(ProviderProbeError::Random)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

struct ProbeRequest {
    method: String,
    target: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn read_request(
    stream: &mut TcpStream,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<ProbeRequest, ProviderProbeError> {
    let mut request = Vec::with_capacity(512);
    let header_end = loop {
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        read_more(stream, &mut request, deadline, cancel)?;
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

    let mut content_length = 0_usize;
    let mut content_type = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(ProviderProbeError::InvalidRequest)?;
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| ProviderProbeError::InvalidRequest)?;
            }
            "content-type" => content_type = Some(value.trim().to_ascii_lowercase()),
            "transfer-encoding" => return Err(ProviderProbeError::InvalidRequest),
            _ => {}
        }
    }
    if header_end + content_length > MAX_REQUEST_BYTES {
        return Err(ProviderProbeError::InvalidRequest);
    }
    while request.len() < header_end + content_length {
        read_more(stream, &mut request, deadline, cancel)?;
    }
    if request.len() != header_end + content_length {
        return Err(ProviderProbeError::InvalidRequest);
    }

    Ok(ProbeRequest {
        method,
        target,
        content_type,
        body: request[header_end..].to_vec(),
    })
}

fn read_more(
    stream: &mut TcpStream,
    request: &mut Vec<u8>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<(), ProviderProbeError> {
    loop {
        if request.len() >= MAX_REQUEST_BYTES {
            return Err(ProviderProbeError::InvalidRequest);
        }
        if cancel.load(Ordering::Acquire) {
            return Err(ProviderProbeError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(ProviderProbeError::TimedOut);
        }
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

fn write_page(
    stream: &mut TcpStream,
    nonce: &str,
    completion_target: &str,
) -> Result<(), ProviderProbeError> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><link rel=icon href=data:,><title>Satelle provider probe</title><main><p>Nonce: <strong>{nonce}</strong></p><div id=source draggable=true>Drag this marker</div><div id=target>Drop here</div></main><script>const source=document.querySelector('#source');const target=document.querySelector('#target');source.addEventListener('dragstart',event=>event.dataTransfer.setData('text/plain','satelle'));target.addEventListener('dragover',event=>event.preventDefault());target.addEventListener('drop',event=>{{event.preventDefault();if(event.dataTransfer.getData('text/plain')==='satelle')fetch('{completion_target}',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},credentials:'omit',cache:'no-store',body:'nonce={nonce}&action=drag'}});}});</script>"
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
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(ProviderProbeError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_page_and_callback_complete_once_without_external_state() {
        let probe = ProviderProbeSurface::start(Duration::from_secs(2)).unwrap();
        let page_url = probe.page_url().to_string();
        let (address, page_target) = split_local_url(&page_url);
        let page = exchange(
            &address,
            &format!("GET {page_target} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        );
        assert!(page.contains("Satelle provider probe"));
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let body = format!("nonce={nonce}&action=drag");
        let callback = exchange(
            &address,
            &format!(
                "POST {completion_target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(callback.starts_with("HTTP/1.1 204 No Content"));
        probe.wait_for_completion().unwrap();
        assert!(TcpStream::connect(address).is_err());
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
            &format!("GET {page_target} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        );
        let nonce = between(&page, "Nonce: <strong>", "</strong>");
        let completion_target = between(&page, "fetch('", "'");
        let body = format!("nonce={nonce}&action=drag");
        let callback = exchange(
            &address,
            &format!(
                "POST {completion_target} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(callback.starts_with("HTTP/1.1 204 No Content"));
        probe.wait_for_completion().unwrap();
    }

    fn split_local_url(url: &str) -> (String, String) {
        let remainder = url.strip_prefix("http://").unwrap();
        let (address, path) = remainder.split_once('/').unwrap();
        (address.to_string(), format!("/{path}"))
    }

    fn exchange(address: &str, request: &str) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let text = text.split_once(start).unwrap().1;
        text.split_once(end).unwrap().0
    }
}
