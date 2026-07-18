use base64::Engine;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CONNECTION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CONNECTION_TIMEOUT: Duration = Duration::from_millis(250);
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

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
        // Startup, request handling, completion, and shutdown all consume one
        // caller-owned budget. A slow bind or entropy source must not grant the
        // probe surface a fresh timeout after startup work has already elapsed.
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ProviderProbeError::TimedOut)?;
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
        let capability = random_token(32)?;
        let page_url = format!("http://127.0.0.1:{port}/probe/{capability}");
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
    let expected_host = listener
        .local_addr()
        .map_err(ProviderProbeError::Io)?
        .to_string();
    let expected_origin = format!("http://{expected_host}");

    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(ProviderProbeError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(ProviderProbeError::TimedOut);
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
                let request = match read_request(&mut stream, connection_deadline, cancel) {
                    Ok(request) => request,
                    Err(error) => {
                        if cancel.load(Ordering::Acquire) {
                            return Err(ProviderProbeError::Cancelled);
                        }
                        if Instant::now() >= deadline {
                            return Err(ProviderProbeError::TimedOut);
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
                    write_page(&mut stream, &nonce, &completion_target)?;
                } else if request.method == "POST"
                    && request.target == completion_target
                    && request.headers_valid
                    && !request.has_sensitive_headers
                    && request.host.as_deref() == Some(expected_host.as_str())
                    && request.origin.as_deref() == Some(expected_origin.as_str())
                    && request.content_type.as_deref() == Some(FORM_CONTENT_TYPE)
                    && request.content_length == Some(request.body.len())
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
    cancel: &AtomicBool,
) -> Result<ProbeRequest, ProviderProbeError> {
    let mut request = Vec::with_capacity(512);
    let header_end = loop {
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        read_more(stream, &mut request, connection_deadline, cancel)?;
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
        read_more(stream, &mut request, connection_deadline, cancel)?;
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
    cancel: &AtomicBool,
) -> Result<(), ProviderProbeError> {
    loop {
        if request.len() >= MAX_REQUEST_BYTES {
            return Err(ProviderProbeError::InvalidRequest);
        }
        if cancel.load(Ordering::Acquire) {
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

fn write_page(
    stream: &mut TcpStream,
    nonce: &str,
    completion_target: &str,
) -> Result<(), ProviderProbeError> {
    let body = format!(
        "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><link rel=icon href=data:,><title>Satelle provider probe</title><main><p>Nonce: <strong>{nonce}</strong></p><div id=source draggable=true>Drag this marker</div><div id=target>Drop here</div></main><script>const source=document.querySelector('#source');const target=document.querySelector('#target');source.addEventListener('dragstart',event=>event.dataTransfer.setData('text/plain','satelle'));target.addEventListener('dragover',event=>event.preventDefault());target.addEventListener('drop',event=>{{event.preventDefault();if(event.dataTransfer.getData('text/plain')==='satelle')fetch('{completion_target}',{{method:'POST',headers:{{'Content-Type':'{FORM_CONTENT_TYPE}'}},credentials:'omit',cache:'no-store',body:'nonce={nonce}&action=drag'}});}});</script>"
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
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; img-src data:; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .map_err(ProviderProbeError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

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
